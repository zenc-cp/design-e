"""
Design E RPC Endpoint Implementation (FastAPI)

Scout↔ZenOps dispatch via Entra-authenticated Azure RPC.
Implements 3 methods: hermes_ask, dispatch_specialist, record_event.

Reference: design-e-rpc-spec.md (§1–7)
"""

import os
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from pathlib import Path

import jwt
from fastapi import FastAPI, HTTPException, Header, Depends, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field, ValidationError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request

# ============================================================================
# CONFIG
# ============================================================================

# Entra Auth
AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID", "test-tenant-id")
ENTRA_AUDIENCE = "https://zenops-cloud-dispatch"
ENTRA_JWKS_URL = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/discovery/v2.0/keys"

# For testing: use HS256 with hardcoded secret
JWT_SECRET = os.getenv("JWT_SECRET", "test-secret")
JWT_ALGORITHM = "HS256"

# File-based message bus (Brain inbox)
BRAIN_INBOX_PATH = Path(os.getenv("BRAIN_INBOX_PATH", "/tmp/brain-inbox"))
BRAIN_INBOX_PATH.mkdir(exist_ok=True, parents=True)

# Audit log path
AUDIT_LOG_PATH = Path(os.getenv("AUDIT_LOG_PATH", "/tmp/audit-logs"))
AUDIT_LOG_PATH.mkdir(exist_ok=True, parents=True)

# Results path (L2 task status retrieval)
RESULTS_PATH = Path(os.getenv("RESULTS_PATH", "/var/lib/design-e/results"))

# Valid specialists
VALID_SPECIALISTS = {"Scout", "Hunter", "Sentinel", "Trader", "Scribe", "Ops"}

# Valid event types
VALID_EVENT_TYPES = {"dispatch_created", "dispatch_completed", "dispatch_failed", "lease_acquired", "heartbeat"}

# Rate limiting (in-memory; resets on app restart)
RATE_LIMIT_PER_CALLER = {"Scout": 100, "Copilot-CLI": 50}
RATE_LIMIT_WINDOW_SEC = 60
caller_request_log: Dict[str, List[float]] = {}

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# EXCEPTIONS
# ============================================================================

class AuthError(Exception):
    """JWT validation failed."""
    pass


class SpecialistNotFoundError(Exception):
    """Specialist not recognized."""
    pass


class RateLimitError(Exception):
    """Rate limit exceeded."""
    pass


# ============================================================================
# REQUEST/RESPONSE MODELS
# ============================================================================

class Context(BaseModel):
    session_id: str
    user_id: str
    caller: str = "Scout"
    timestamp: Optional[str] = None


class Task(BaseModel):
    id: Optional[str] = None
    role: str
    payload: Dict[str, Any]
    priority: str = "normal"
    ttl_sec: int = 3600


class DispatchSpecialistRequest(BaseModel):
    specialist: str
    task: Task
    context: Context


class DispatchSpecialistResponse(BaseModel):
    status: str
    data: Dict[str, str]


class HermesAskRequest(BaseModel):
    query: str = Field(..., max_length=2000)
    context: Context
    timeout_sec: int = 30


class HermesAskResponse(BaseModel):
    status: str
    data: Optional[Dict[str, Any]] = None
    error: Optional[Dict[str, str]] = None


class RecordEventRequest(BaseModel):
    event_type: str
    task_id: str
    details: Dict[str, Any]
    context: Context


class HealthResponse(BaseModel):
    status: str


class ErrorResponse(BaseModel):
    status: str
    error: Dict[str, str]


# ============================================================================
# AUTH MIDDLEWARE
# ============================================================================

def validate_entra_token(authorization: str = Header(None)) -> Dict[str, Any]:
    """
    Validate Entra JWT token from Authorization header.
    
    Raises:
        AuthError: If token is missing, invalid, expired, or has wrong audience
    """
    if not authorization:
        raise AuthError("Missing Authorization header")
    
    if not authorization.startswith("Bearer "):
        raise AuthError("Invalid Authorization header format")
    
    token = authorization[len("Bearer "):]
    
    try:
        # Decode and validate JWT
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            audience=ENTRA_AUDIENCE,
            issuer=f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/v2.0",
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise AuthError("Token expired")
    except jwt.InvalidAudienceError:
        raise AuthError("Invalid audience")
    except jwt.InvalidSignatureError:
        raise AuthError("Invalid token signature")
    except jwt.DecodeError as e:
        raise AuthError(f"Invalid token: {e}")


def check_rate_limit(token_payload: Dict[str, Any]) -> None:
    """
    Check rate limit for caller (based on UPN or default Scout).
    
    Raises:
        RateLimitError: If caller exceeds quota
    """
    caller = token_payload.get("upn", "Scout").split("@")[0]
    quota = RATE_LIMIT_PER_CALLER.get(caller, 100)
    
    now = datetime.now(timezone.utc).timestamp()
    cutoff = now - RATE_LIMIT_WINDOW_SEC
    
    if caller not in caller_request_log:
        caller_request_log[caller] = []
    
    # Prune old requests
    caller_request_log[caller] = [t for t in caller_request_log[caller] if t > cutoff]
    
    # Check quota
    if len(caller_request_log[caller]) >= quota:
        raise RateLimitError(f"Rate limit exceeded ({quota} req/min)")
    
    # Log this request
    caller_request_log[caller].append(now)


# ============================================================================
# APP
# ============================================================================

app = FastAPI(title="Design E RPC Endpoint", version="1.0.0")


# ============================================================================
# EXCEPTION HANDLERS
# ============================================================================

@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    """
    Parse JSON-string details from HTTPException and return as properly formatted response.
    This ensures JSON string details are deserialized before returning to client.
    Preserves headers (e.g., X-RateLimit-Reset).
    """
    if isinstance(exc.detail, str):
        try:
            detail = json.loads(exc.detail)
        except (json.JSONDecodeError, TypeError):
            detail = {"status": "error", "error": {"message": exc.detail}}
    else:
        detail = exc.detail
    
    # Use JSONResponse to preserve headers
    response = JSONResponse(status_code=exc.status_code, content=detail)
    if exc.headers:
        for key, value in exc.headers.items():
            response.headers[key] = value
    return response


@app.exception_handler(RequestValidationError)
async def custom_validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Convert Pydantic validation errors (422) to 400 BAD_REQUEST for RPC compliance.
    """
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content=json.dumps({
            "status": "error",
            "error": {
                "code": "BAD_REQUEST",
                "message": "Request validation failed",
                "details": str(exc.errors())
            }
        }),
    )


# ============================================================================
# ROUTES
# ============================================================================

@app.get("/rpc/v1/health", response_model=HealthResponse)
async def health():
    """Health check endpoint."""
    return {"status": "ok"}


@app.post("/rpc/v1/dispatch_specialist", status_code=202, response_model=DispatchSpecialistResponse)
async def dispatch_specialist(
    request: DispatchSpecialistRequest,
    authorization: str = Header(None),
) -> DispatchSpecialistResponse:
    """
    Enqueue task for a ZenOps specialist.
    
    Request:  {"specialist": "Scout", "task": {...}, "context": {...}}
    Response: 202 Accepted, {"status": "ok", "data": {"task_id": "uuid"}}
    
    Raises:
        401: Invalid token
        403: Wrong audience
        400: Invalid specialist or payload
        503: Hermes unavailable
    """
    try:
        # Auth
        token_payload = validate_entra_token(authorization)
        check_rate_limit(token_payload)
        
        # Validate specialist
        if request.specialist not in VALID_SPECIALISTS:
            raise SpecialistNotFoundError(f"unknown specialist: {request.specialist}")
        
        # Generate task ID if not provided
        task_id = request.task.id or str(uuid.uuid4())
        
        # Write to Brain inbox
        task_envelope = {
            "specialist": request.specialist,
            "task": {
                "id": task_id,
                "role": request.task.role,
                "payload": request.task.payload,
                "priority": request.task.priority,
                "ttl_sec": request.task.ttl_sec,
            },
            "context": request.context.dict(),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        
        # Write to Brain inbox FS
        inbox_file = BRAIN_INBOX_PATH / f"{task_id}.json"
        with open(inbox_file, "w") as f:
            json.dump(task_envelope, f, indent=2)
        
        logger.info(f"Enqueued task {task_id} for specialist {request.specialist}")
        
        # Log event
        _record_event_internal(
            event_type="dispatch_created",
            task_id=task_id,
            details={"outcome": "success", "latency_ms": 10},
            context=request.context,
        )
        
        return DispatchSpecialistResponse(
            status="ok",
            data={"task_id": task_id, "status": "pending"},
        )
    
    except SpecialistNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=json.dumps({"status": "error", "error": {"code": "BAD_REQUEST", "message": str(e)}}),
        )
    except AuthError as e:
        error_msg = str(e)
        if "audience" in error_msg.lower():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=json.dumps({"status": "error", "error": {"code": "FORBIDDEN", "message": "audience mismatch"}}),
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=json.dumps({"status": "error", "error": {"code": "UNAUTHORIZED", "message": error_msg}}),
        )
    except RateLimitError:
        reset_time = int((datetime.now(timezone.utc) + timedelta(seconds=RATE_LIMIT_WINDOW_SEC)).timestamp())
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=json.dumps({"status": "error", "error": {"code": "RATE_LIMIT", "message": "quota exceeded"}}),
            headers={"X-RateLimit-Reset": str(reset_time)},
        )
    except Exception as e:
        logger.error(f"dispatch_specialist failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=json.dumps({"status": "error", "error": {"code": "INTERNAL_ERROR", "message": str(e)}}),
        )


@app.post("/rpc/v1/hermes_ask", response_model=HermesAskResponse)
async def hermes_ask(
    request: HermesAskRequest,
    authorization: str = Header(None),
) -> HermesAskResponse:
    """
    Query Hermes reasoning engine.
    
    Request:  {"query": "...", "context": {...}, "timeout_sec": 30}
    Response: 200 or 202, {"status": "ok" or "pending", "data": {...}}
    
    Raises:
        401: Invalid token
        400: Query too long
        503: Hermes unavailable
    """
    try:
        # Auth
        token_payload = validate_entra_token(authorization)
        check_rate_limit(token_payload)
        
        # Validate query length (already enforced by Pydantic, but explicit for clarity)
        if len(request.query) > 2000:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=json.dumps({"status": "error", "error": {"code": "BAD_REQUEST", "message": "query exceeds 2000 char limit"}}),
            )
        
        # For now, return mock response (Hermes integration is future work)
        return HermesAskResponse(
            status="ok",
            data={
                "answer": "This is a mock answer from Hermes.",
                "confidence": 0.75,
                "sources": ["source_1", "source_2"],
                "trace_id": str(uuid.uuid4()),
            },
        )
    
    except AuthError as e:
        error_msg = str(e)
        if "audience" in error_msg.lower():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=json.dumps({"status": "error", "error": {"code": "FORBIDDEN", "message": "audience mismatch"}}),
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=json.dumps({"status": "error", "error": {"code": "UNAUTHORIZED", "message": error_msg}}),
        )
    except RateLimitError:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=json.dumps({"status": "error", "error": {"code": "RATE_LIMIT", "message": "quota exceeded"}}),
        )
    except Exception as e:
        logger.error(f"hermes_ask failed: {e}")
        # Simulate Hermes unavailable if any error
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=json.dumps({"status": "error", "error": {"code": "SERVICE_UNAVAILABLE", "message": "Hermes unavailable"}}),
        )


@app.post("/rpc/v1/record_event", status_code=204)
async def record_event(
    request: RecordEventRequest,
    authorization: str = Header(None),
) -> None:
    """
    Record audit event.
    
    Request:  {"event_type": "dispatch_created", "task_id": "...", "details": {...}}
    Response: 204 NO CONTENT
    
    Raises:
        401: Invalid token
        400: Invalid event type
    """
    try:
        # Auth
        token_payload = validate_entra_token(authorization)
        check_rate_limit(token_payload)
        
        # Validate event type
        if request.event_type not in VALID_EVENT_TYPES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=json.dumps({"status": "error", "error": {"code": "BAD_REQUEST", "message": f"invalid event_type: {request.event_type}"}}),
            )
        
        # Write to audit log
        _record_event_internal(
            event_type=request.event_type,
            task_id=request.task_id,
            details=request.details,
            context=request.context,
        )
        
        return None
    
    except AuthError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=json.dumps({"status": "error", "error": {"code": "UNAUTHORIZED", "message": str(e)}}),
        )
    except RateLimitError:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=json.dumps({"status": "error", "error": {"code": "RATE_LIMIT", "message": "quota exceeded"}}),
        )


@app.get("/rpc/v1/results/{task_id}")
async def get_results(task_id: str, authorization: str = Header(None)) -> dict:
    """
    Retrieve L2 task results by task_id.
    
    Request:  GET /rpc/v1/results/{task_id}
    Response: 200, {task result JSON}
    
    Raises:
        401: Invalid token
        404: Task not found
    """
    try:
        # Auth
        validate_entra_token(authorization)
        
        # Re-read module attribute each call to honor monkeypatch in tests
        from design_e_endpoint import RESULTS_PATH as _rp
        f = _rp / f"{task_id}.json"
        
        if not f.exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=json.dumps({"status": "error", "error": {"code": "NOT_FOUND", "message": f"task {task_id} not found"}}),
            )
        
        return json.loads(f.read_text(encoding="utf-8"))
    
    except AuthError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=json.dumps({"status": "error", "error": {"code": "UNAUTHORIZED", "message": str(e)}}),
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"get_results failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=json.dumps({"status": "error", "error": {"code": "INTERNAL_ERROR", "message": str(e)}}),
        )


# ============================================================================
# INTERNAL HELPERS
# ============================================================================

def _record_event_internal(
    event_type: str,
    task_id: str,
    details: Dict[str, Any],
    context: Context,
) -> None:
    """Write audit log entry."""
    log_entry = {
        "event_type": event_type,
        "task_id": task_id,
        "details": details,
        "context": context.dict(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    
    log_file = AUDIT_LOG_PATH / f"audit-{datetime.now(timezone.utc).strftime('%Y%m%d')}.log"
    with open(log_file, "a") as f:
        f.write(json.dumps(log_entry) + "\n")
    
    logger.info(f"Recorded event {event_type} for task {task_id}")


# Stub for hermes_client (for testing mocking)
class HermesClient:
    def health_check(self):
        return {"status": "ok"}


hermes_client = HermesClient()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7890)
