"""
Gateway-specific API routes
These are lightweight endpoints that run on the Gateway server
"""

from flask import Blueprint, request, jsonify, current_app, g
from app.mTLS.middleware import require_authentication, require_mtls
from app.logs.zta_event_logger import zta_logger, EVENT_TYPES
from datetime import datetime
import uuid
import hashlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import requests

gateway_bp = Blueprint("gateway", __name__)


@gateway_bp.route("/fter/", methods=["POST"])
@gateway_bp.route("/register", methods=["POST"])
def handle_registration():
    """Handle registration by forwarding to API Server"""
    print(f"\n🔀 Registration request received at Gateway")

    try:
        data = request.get_json()
        print(f"Registration data: {data}")

        # Get API Server URL from config
        api_server_url = current_app.config.get(
            "API_SERVER_URL", "https://localhost:5001"
        )
        print(f"Forwarding to: {api_server_url}/api/register/")

        # Forward to API Server
        response = requests.post(
            f"{api_server_url}/api/register/",
            json=data,
            headers={
                "Content-Type": "application/json",
                "X-Service-Token": current_app.config.get(
                    "GATEWAY_SERVICE_TOKEN", "gateway-token-2024"
                ),
                "X-Request-ID": str(uuid.uuid4()),
            },
            timeout=10,
            verify=False,  # Important: Disable SSL verification for self-signed certs
        )

        print(f"API Server response status: {response.status_code}")

        # Return the API Server's response
        return jsonify(response.json()), response.status_code

    except requests.exceptions.RequestException as e:
        print(f"❌ API Server connection error: {e}")
        return (
            jsonify(
                {
                    "error": "Registration service unavailable",
                    "message": "Cannot connect to registration server",
                }
            ),
            503,
        )
    except Exception as e:
        print(f"❌ Registration error: {e}")
        return jsonify({"error": "Registration failed", "message": str(e)}), 500


@gateway_bp.route("/zta-test", methods=["GET"])
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
            zta_logger.log_event(
                EVENT_TYPES["MTLS_CERT_VALIDATED"],
                {
                    "certificate_present": True,
                    "email": email,
                    "fingerprint_short": fingerprint[:16] + "...",
                    "test_endpoint": True,
                },
                request_id=request_id,
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
            zta_logger.log_event(
                "CERTIFICATE_ERROR",
                {"error": str(e), "certificate_present": True},
                request_id=request_id,
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
    zta_logger.log_event(
        EVENT_TYPES["MTLS_CERT_REJECTED"],
        {"reason": "No client certificate provided", "test_endpoint": True},
        request_id=request_id,
    )

    return (
        jsonify(
            {
                "status": "info",
                "message": "No client certificate provided",
                "certificate": {"present": False},
                "hint": "Connect with mTLS certificate to test",
            }
        ),
        200,
    )


@gateway_bp.route("/zta/test", methods=["GET"])
@require_authentication
def test_zta_auth():
    """Test Zero Trust Authentication (JWT + mTLS) - Gateway test"""
    try:
        request_id = getattr(g, "request_id", str(uuid.uuid4()))
        auth_method = getattr(g, "auth_method", "unknown")

        if auth_method == "mtls":
            cert_info = getattr(g, "client_certificate", {})
            return (
                jsonify(
                    {
                        "status": "success",
                        "message": "mTLS authentication successful",
                        "auth_method": "mTLS",
                        "certificate_info": {
                            "fingerprint": cert_info.get("fingerprint", "")[:16]
                            + "...",
                            "subject": cert_info.get("subject", {}),
                        },
                    }
                ),
                200,
            )
        elif auth_method == "jwt":
            return (
                jsonify(
                    {
                        "status": "success",
                        "message": "JWT authentication successful",
                        "auth_method": "JWT",
                    }
                ),
                200,
            )
        else:
            return jsonify({"error": "Authentication failed"}), 401

    except Exception as e:
        return jsonify({"error": "ZTA test failed", "message": str(e)}), 500


@gateway_bp.route("/service/health", methods=["GET"])
@require_mtls
def service_health():
    """Service health check - mTLS only (service-to-service)"""
    return jsonify(
        {
            "status": "healthy",
            "service": "ZTA Gateway Server",
            "timestamp": datetime.utcnow().isoformat(),
        }
    )
