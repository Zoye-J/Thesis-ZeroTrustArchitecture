"""
ZTA Flow Middleware for logging the complete flow
User → Server1 → OPA → API Server → Server1 → User
"""

from app.logs.zta_event_logger import zta_logger
from datetime import datetime
import uuid


def log_zta_flow_start(user_claims, resource, action, request_id=None):
    """Log the start of ZTA flow: User → Server1"""
    if not request_id:
        request_id = str(uuid.uuid4())

    zta_logger.log_event(
        "ZTA_FLOW_START",
        {
            "step": "user_to_server1",
            "user": {
                "id": user_claims.get("sub"),
                "username": user_claims.get("username"),
                "role": user_claims.get("user_class"),
                "clearance": user_claims.get("clearance_level"),
            },
            "resource": resource,
            "action": action,
            "timestamp": datetime.utcnow().isoformat(),
        },
        user_id=user_claims.get("sub"),
        request_id=request_id,
    )
    return request_id


def log_opa_to_api_server(request_id, opa_result):
    """Log OPA → API Server communication"""
    zta_logger.log_event(
        "ZTA_FLOW_STEP",
        {
            "step": "opa_to_api_server",
            "direction": "forward",
            "opa_decision": opa_result.get("allow", False),
            "opa_reason": opa_result.get("reason", "No reason provided"),
            "timestamp": datetime.utcnow().isoformat(),
        },
        request_id=request_id,
    )


def log_api_to_server1(request_id, success=True):
    """Log API Server → Server1 response"""
    zta_logger.log_event(
        "ZTA_FLOW_STEP",
        {
            "step": "api_to_server1",
            "direction": "backward",
            "success": success,
            "timestamp": datetime.utcnow().isoformat(),
        },
        request_id=request_id,
    )


def log_server1_to_user(request_id, allowed=True):
    """Log Server1 → User response"""
    zta_logger.log_event(
        "ZTA_FLOW_STEP",
        {
            "step": "server1_to_user",
            "direction": "forward",
            "access_allowed": allowed,
            "timestamp": datetime.utcnow().isoformat(),
        },
        request_id=request_id,
    )


def log_zta_flow_complete(request_id, success=True):
    """Log completion of the entire ZTA flow"""
    zta_logger.log_event(
        "ZTA_FLOW_COMPLETE",
        {
            "step": "flow_complete",
            "success": success,
            "total_steps_completed": 5,  # User→S1→OPA→API→S1→User
            "timestamp": datetime.utcnow().isoformat(),
            "flow_diagram": "User → Server1 → OPA → API Server → Server1 → User",
        },
        request_id=request_id,
    )


def log_service_token_validation(request_id, service_name, token_valid):
    """Log service token validation"""
    zta_logger.log_event(
        "SERVICE_TOKEN_VALIDATION",
        {
            "service": service_name,
            "token_valid": token_valid,
            "step": "service_auth",
            "timestamp": datetime.utcnow().isoformat(),
        },
        request_id=request_id,
    )


def log_mtls_handshake_step(request_id, client_info):
    """Log mTLS handshake step"""
    zta_logger.log_event(
        "MTLS_HANDSHAKE_STEP",
        {
            "step": "mtls_handshake",
            "client": client_info.get("client_id", "unknown"),
            "certificate_fingerprint": client_info.get("fingerprint", "")[:16] + "...",
            "timestamp": datetime.utcnow().isoformat(),
        },
        request_id=request_id,
    )
