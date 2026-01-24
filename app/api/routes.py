from flask import Blueprint, request, jsonify, current_app, g
from app.mTLS.middleware import require_authentication, require_mtls
from app.logs.zta_event_logger import event_logger, EventType, Severity
from datetime import datetime
import uuid
import hashlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from app import db

api_bp = Blueprint("api", __name__)


# KEEP: Simple ZTA test endpoint (for gateway)
@api_bp.route("/zta-test", methods=["GET"])
def simple_zta_test():
    """
    Simple ZTA test endpoint - no authentication required
    Just checks if certificate is present (gateway functionality)
    """
    request_id = str(uuid.uuid4())

    # Check for certificate
    cert_pem = request.environ.get("SSL_CLIENT_CERT")

    if cert_pem:
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            fingerprint = cert.fingerprint(hashlib.sha256()).hex()

            # Extract info
            email = None
            for attr in cert.subject:
                if attr.oid._name == "emailAddress":
                    email = attr.value
                    break
                elif attr.oid._name == "commonName" and "@" in attr.value:
                    email = attr.value

            # Log mTLS certificate detection
            event_logger.log_event(
                event_type=EventType.MTLS_HANDSHAKE,
                source_component="gateway",
                action="mTLS certificate validated",
                source_ip=request.remote_addr or "127.0.0.1",
                details={
                    "certificate_present": True,
                    "email": email,
                    "fingerprint_short": fingerprint[:16] + "...",
                    "test_endpoint": True,
                },
                trace_id=request_id,
                severity=Severity.INFO,
            )

            return (
                jsonify(
                    {
                        "status": "success",
                        "message": "mTLS certificate detected",
                        "certificate": {
                            "present": True,
                            "email": email,
                            "fingerprint_short": fingerprint[:16] + "...",
                            "subject": {
                                attr.oid._name: attr.value for attr in cert.subject
                            },
                        },
                        "zta_info": {
                            "authentication_method": "mTLS",
                            "layer": "Transport security",
                        },
                    }
                ),
                200,
            )
        except Exception as e:
            event_logger.log_event(
                event_type=EventType.CLIENT_CERT_INVALID,
                source_component="gateway",
                action="Certificate error",
                source_ip=request.remote_addr or "127.0.0.1",
                details={
                    "error": str(e),
                    "certificate_present": True,
                },
                trace_id=request_id,
                severity=Severity.HIGH,
            )
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": f"Certificate error: {str(e)}",
                        "certificate": {"present": True, "valid": False},
                    }
                ),
                400,
            )

    # No certificate
    event_logger.log_event(
        event_type=EventType.CLIENT_CERT_INVALID,
        source_component="gateway",
        action="No client certificate provided",
        source_ip=request.remote_addr or "127.0.0.1",
        details={
            "reason": "No client certificate provided",
            "test_endpoint": True,
        },
        trace_id=request_id,
        severity=Severity.MEDIUM,
    )

    return (
        jsonify(
            {
                "status": "info",
                "message": "No client certificate provided",
                "certificate": {"present": False},
                "hint": "Connect with: curl --cert ./certs/clients/1/client.crt --key ./certs/clients/1/client.key --cacert ./certs/ca.crt https://localhost:8443/api/zta-test",
            }
        ),
        200,
    )


# KEEP: Test authentication endpoint (for gateway)
@api_bp.route("/zta/test", methods=["GET"])
@require_authentication
def test_zta_auth():
    """Test Zero Trust Authentication (JWT + mTLS) - Gateway test"""
    try:
        request_id = getattr(g, "request_id", str(uuid.uuid4()))

        # Get auth method from g object (set by middleware)
        auth_method = getattr(g, "auth_method", "unknown")
        user_id = getattr(g, "jwt_identity", None)

        if auth_method == "mtls":
            cert_info = getattr(g, "client_certificate", {})
            email = cert_info.get("subject", {}).get("emailAddress", "Unknown")

            return (
                jsonify(
                    {
                        "status": "success",
                        "message": "Zero Trust Authentication successful",
                        "authentication_layers": {
                            "layer1_mtls": "✓ Client certificate validated",
                            "layer2_jwt": "✗ JWT token not required (mTLS only)",
                        },
                        "certificate_info": {
                            "fingerprint": cert_info.get("fingerprint", "")[:16]
                            + "...",
                            "subject": cert_info.get("subject", {}),
                        },
                        "auth_method": "mTLS",
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                ),
                200,
            )

        elif auth_method == "jwt":
            return (
                jsonify(
                    {
                        "status": "success",
                        "message": "JWT Authentication successful",
                        "authentication_layers": {
                            "layer1_mtls": "✗ Client certificate not present",
                            "layer2_jwt": "✓ JWT token validated",
                        },
                        "auth_method": "JWT",
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                ),
                200,
            )

        else:
            return jsonify({"error": "Authentication required"}), 401

    except Exception as e:
        event_logger.log_event(
            event_type=EventType.ERROR,
            source_component="gateway",
            action="ZTA test error",
            details={
                "error": str(e),
                "test_endpoint": True,
            },
            trace_id=getattr(g, "request_id", str(uuid.uuid4())),
            severity=Severity.MEDIUM,
        )
        return jsonify({"error": "ZTA test failed", "message": str(e)}), 500


# KEEP: Service health endpoint (for gateway)
@api_bp.route("/service/health", methods=["GET"])
@require_mtls  # Services only need mTLS
def service_health():
    """Service health check - mTLS only (service-to-service)"""
    request_id = str(uuid.uuid4())
    auth_method = getattr(g, "auth_method", "unknown")

    return jsonify(
        {
            "status": "healthy",
            "service": "ZTA Gateway Server",
            "auth_method": auth_method,
            "timestamp": datetime.utcnow().isoformat(),
            "zta_enabled": True,
            "features": ["JWT", "mTLS", "OPA", "Certificate Validation", "RBAC"],
            "access_restriction": "mTLS certificate required for services",
            "request_id": request_id,
        }
    )


# KEEP: Certificate verification logging endpoint (for gateway)
@api_bp.route("/certificate/verify", methods=["POST"])
@require_mtls  # Requires mTLS certificate
def verify_certificate():
    """Endpoint to verify and log certificate details (gateway functionality)"""
    try:
        request_id = getattr(g, "request_id", str(uuid.uuid4()))

        # Get certificate from g object
        if not hasattr(g, "client_certificate"):
            return jsonify({"error": "No certificate provided"}), 400

        cert_info = g.client_certificate

        return (
            jsonify(
                {
                    "status": "success",
                    "certificate_valid": True,
                    "certificate_details": cert_info,
                    "zta_context": {
                        "verification_method": "mTLS_certificate",
                        "request_id": request_id,
                        "timestamp": datetime.utcnow().isoformat(),
                    },
                }
            ),
            200,
        )

    except Exception as e:
        event_logger.log_event(
            event_type=EventType.ERROR,
            source_component="gateway",
            action="Certificate verification error",
            source_ip=request.remote_addr or "127.0.0.1",
            details={
                "error": str(e),
            },
            trace_id=getattr(g, "request_id", str(uuid.uuid4())),
            severity=Severity.HIGH,
        )
        return (
            jsonify({"error": "Certificate verification failed", "message": str(e)}),
            500,
        )
