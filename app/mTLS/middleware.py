"""
mTLS Middleware for Flask with JWT fallback
Supports both mTLS and JWT authentication
CLEANED VERSION - Removed fake flow logging
"""

from flask import request, jsonify, current_app, g
from functools import wraps
import base64
from datetime import datetime
from app.logs.zta_event_logger import zta_logger, EVENT_TYPES
import uuid
from cryptography.hazmat.backends import default_backend
from cryptography import x509


def extract_client_certificate():
    """Extract client certificate from request"""
    cert_pem = None

    # Method 1: From SSL environment variable (for direct mTLS)
    if "SSL_CLIENT_CERT" in request.environ:
        cert_pem = request.environ["SSL_CLIENT_CERT"]

    # Method 2: From header (for proxy setups)
    elif "X-SSL-Client-Cert" in request.headers:
        cert_pem = request.headers["X-SSL-Client-Cert"]

    # Method 3: From custom header
    elif "X-Client-Certificate" in request.headers:
        cert_b64 = request.headers["X-Client-Certificate"]
        try:
            cert_pem = base64.b64decode(cert_b64).decode("utf-8")
        except:
            pass

    return cert_pem


def require_authentication(f):
    """
    Decorator that accepts EITHER mTLS OR JWT authentication
    This is the main decorator for your API endpoints
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if mTLS is enabled in config
        mtls_enabled = current_app.config.get("MTLS_ENABLED", True)

        # Try mTLS authentication first if enabled
        if mtls_enabled:
            cert_pem = extract_client_certificate()

            if cert_pem:
                # Import here to avoid circular imports
                from app.mTLS.cert_manager import cert_manager

                # Validate certificate
                is_valid, result = cert_manager.validate_certificate(cert_pem)

                if is_valid:
                    # Certificate is valid
                    cert_info = result

                    # Check if revoked
                    if cert_manager.is_certificate_revoked(
                        cert_info.get("serial_number", "")
                    ):
                        return (
                            jsonify(
                                {
                                    "error": "Certificate has been revoked",
                                    "code": "CERTIFICATE_REVOKED",
                                }
                            ),
                            401,
                        )

                    # Add certificate info to Flask's g object for global access
                    g.client_certificate = cert_info
                    g.auth_method = "mtls"

                    # Try to find user in database
                    try:
                        from app.models.user import User

                        user = User.find_by_certificate_fingerprint(
                            cert_info.get("fingerprint")
                        )
                        if user:
                            g.current_user = user
                            user.last_certificate_auth = datetime.utcnow()
                    except:
                        pass  # Database might not be available

                    current_app.logger.info(
                        f"Authenticated via mTLS: {cert_info.get('subject', {}).get('emailAddress', 'Unknown')}"
                    )
                    return f(*args, **kwargs)

        # If mTLS failed or not enabled, try JWT
        try:
            from flask_jwt_extended import (
                verify_jwt_in_request,
                get_jwt_identity,
            )

            verify_jwt_in_request(optional=True)
            user_identity = get_jwt_identity()

            if user_identity:
                # JWT authentication successful
                g.auth_method = "jwt"
                g.jwt_identity = user_identity

                # Try to load user from database
                try:
                    from app.models.user import User

                    user = User.query.get(user_identity)
                    if user:
                        g.current_user = user
                except:
                    pass

                current_app.logger.info(f"Authenticated via JWT: {user_identity}")
                return f(*args, **kwargs)
        except:
            pass  # JWT verification failed

        # Neither mTLS nor JWT succeeded
        if mtls_enabled:
            return (
                jsonify(
                    {
                        "error": "Authentication required",
                        "methods": ["mTLS (client certificate)", "JWT Bearer token"],
                        "mtls_required": True,
                    }
                ),
                401,
            )
        else:
            return (
                jsonify(
                    {
                        "error": "Authentication required",
                        "methods": ["JWT Bearer token"],
                    }
                ),
                401,
            )

    return decorated_function


def require_mtls(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Generate request ID
        request_id = str(uuid.uuid4())
        g.request_id = request_id

        cert_pem = extract_client_certificate()

        if not cert_pem:
            # Log certificate missing
            zta_logger.log_event(
                EVENT_TYPES["MTLS_CERT_REJECTED"],
                {
                    "reason": "No client certificate provided",
                    "endpoint": request.path,
                    "required": True,
                },
                request_id=request_id,
            )
            return (
                jsonify(
                    {
                        "error": "Client certificate required",
                        "code": "CERTIFICATE_REQUIRED",
                    }
                ),
                401,
            )

        # Use enhanced logging
        is_valid, cert_info_or_error = log_mtls_handshake(cert_pem, request_id)

        if not is_valid:
            return (
                jsonify(
                    {
                        "error": "Invalid client certificate",
                        "details": str(cert_info_or_error),
                        "code": "INVALID_CERTIFICATE",
                    }
                ),
                401,
            )

        # Certificate is valid
        cert_info = cert_info_or_error

        # Check if revoked
        from app.mTLS.cert_manager import cert_manager

        if cert_manager.is_certificate_revoked(cert_info.get("serial_number", "")):
            zta_logger.log_event(
                "CERTIFICATE_REVOKED",
                {
                    "serial": cert_info.get("serial_number"),
                    "fingerprint": cert_info.get("fingerprint", "")[:16] + "...",
                    "action": "access_denied",
                },
                request_id=request_id,
            )
            return (
                jsonify(
                    {
                        "error": "Certificate has been revoked",
                        "code": "CERTIFICATE_REVOKED",
                    }
                ),
                401,
            )

        # Log successful mTLS authentication
        zta_logger.log_event(
            EVENT_TYPES["MTLS_CERT_VALIDATED"],
            {
                "fingerprint": cert_info.get("fingerprint", "")[:16] + "...",
                "subject": cert_info.get("subject", {}),
                "issuer": cert_info.get("issuer", {}),
                "valid_from": cert_info.get("not_valid_before"),
                "valid_to": cert_info.get("not_valid_after"),
                "validation_steps": [
                    "certificate_present",
                    "format_valid",
                    "not_expired",
                    "trusted_issuer",
                    "not_revoked",
                ],
            },
            request_id=request_id,
        )

        # Add certificate info to Flask's g object
        g.client_certificate = cert_info
        g.auth_method = "mtls"

        return f(*args, **kwargs)

    return decorated_function


def require_jwt(f):
    """
    Decorator that requires JWT authentication (no mTLS fallback)
    Use for legacy endpoints or when mTLS isn't available
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity

            verify_jwt_in_request()
            user_identity = get_jwt_identity()

            g.auth_method = "jwt"
            g.jwt_identity = user_identity

            current_app.logger.info(
                f"JWT authentication required for user {user_identity}"
            )

            return f(*args, **kwargs)
        except Exception as e:
            return (
                jsonify({"error": "JWT token required or invalid", "details": str(e)}),
                401,
            )

    return decorated_function


def log_mtls_handshake(cert_pem, request_id=None):
    """Enhanced mTLS handshake logging with certificate details"""
    if not request_id:
        request_id = str(uuid.uuid4())

    try:
        from app.mTLS.cert_manager import cert_manager

        # Get client IP
        client_ip = None
        if request and hasattr(request, "remote_addr"):
            client_ip = request.remote_addr

        # Use enhanced validation with detailed logging
        is_valid, cert_info, validation_checks = (
            cert_manager.validate_certificate_with_detailed_logging(
                cert_pem, request_id, client_ip
            )
        )

        if is_valid:
            # Log certificate verification summary
            cert_manager.log_certificate_verification_summary(
                cert_pem, request_id, client_ip
            )

            # Extract subject for logging
            subject_email = cert_info.get("subject", {}).get("emailAddress", "Unknown")

            # Log successful handshake
            zta_logger.log_event(
                EVENT_TYPES["MTLS_HANDSHAKE_START"],
                {
                    "client": subject_email,
                    "client_ip": client_ip,
                    "certificate_fingerprint": cert_info.get("fingerprint", "")[:16]
                    + "...",
                    "validation_checks": validation_checks,
                },
                request_id=request_id,
            )

        else:
            # Log failed handshake with detailed reason
            failed_checks = [k for k, v in validation_checks.items() if not v]
            zta_logger.log_event(
                EVENT_TYPES["MTLS_CERT_REJECTED"],
                {
                    "certificate_present": bool(cert_pem),
                    "failed_validation_checks": failed_checks,
                    "client_ip": client_ip,
                    "rejection_reason": "certificate_validation_failed",
                    "details": (
                        cert_info if isinstance(cert_info, str) else "multiple_failures"
                    ),
                },
                request_id=request_id,
            )

        return is_valid, cert_info if is_valid else None

    except Exception as e:
        zta_logger.log_event(
            "MTLS_HANDSHAKE_ERROR",
            {
                "error": str(e),
                "certificate_present": bool(cert_pem),
                "client_ip": client_ip,
            },
            request_id=request_id,
        )
        return False, str(e)
