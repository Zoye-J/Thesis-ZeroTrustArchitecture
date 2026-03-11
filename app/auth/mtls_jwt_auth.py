"""
Unified Authentication: JWT + mTLS + OPA
For Zero Trust Architecture
"""

from flask import request, jsonify, current_app
from functools import wraps
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
import hashlib
from cryptography import x509
from datetime import datetime
from cryptography.hazmat.backends import default_backend
import json


class ZeroTrustAuthenticator:
    """Handles JWT + mTLS + OPA authentication"""

    def __init__(self, app=None):
        self.app = app
        if app:
            self.init_app(app)

    def init_app(self, app):
        """Initialize with Flask app"""
        self.app = app

    def extract_certificate(self):
        """Extract and validate client certificate"""
        cert_pem = request.environ.get("SSL_CLIENT_CERT")

        if not cert_pem:
            return None

        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            fingerprint = cert.fingerprint(hashlib.sha256()).hex()

            # Extract identity info
            identity = {
                "fingerprint": fingerprint,
                "serial": format(cert.serial_number, "X"),
                "subject": {},
                "email": None,
                "department": None,
                "type": None,  # 'user' or 'service'
            }

            # Parse subject
            for attr in cert.subject:
                identity["subject"][attr.oid._name] = attr.value

                if attr.oid._name == "emailAddress":
                    identity["email"] = attr.value
                    identity["type"] = "user"
                elif attr.oid._name == "commonName":
                    if "@" in attr.value:
                        identity["email"] = attr.value
                        identity["type"] = "user"
                    else:
                        identity["service_name"] = attr.value
                        identity["type"] = "service"
                elif attr.oid._name == "organizationName":
                    identity["department"] = attr.value

            return identity

        except Exception as e:
            current_app.logger.error(f"Certificate error: {e}")
            return None

    def authenticate_request(self):
        """
        Authenticate request using Zero Trust principles
        Returns: (is_authenticated, identity, auth_method, error_message)
        """

        # 1. Extract client certificate (mTLS)
        cert_identity = self.extract_certificate()

        if cert_identity:
            # 2. Certificate is present (mTLS succeeded)
            current_app.logger.info(f"mTLS certificate: {cert_identity}")

            # 3. Check if this is a service or user
            if cert_identity["type"] == "service":
                # Service-to-service: Only mTLS required
                return True, cert_identity, "mTLS_service", None

            elif cert_identity["type"] == "user":
                # User request: Need BOTH mTLS AND JWT
                try:
                    verify_jwt_in_request()
                    jwt_user_id = get_jwt_identity()

                    # Verify JWT user matches certificate user
                    from app.models.user import User

                    user = User.query.get(jwt_user_id)

                    if user and user.email == cert_identity["email"]:
                        # JWT and mTLS match - strong authentication
                        return (
                            True,
                            {**cert_identity, "user_id": jwt_user_id, "user": user},
                            "mTLS_JWT",
                            None,
                        )
                    else:
                        return (
                            False,
                            None,
                            None,
                            "JWT does not match certificate identity",
                        )

                except Exception as e:
                    return False, None, None, f"JWT validation failed: {str(e)}"

        # No certificate or authentication failed
        return False, None, None, "Authentication required"

    def require_zta_auth(self, require_jwt_for_users=True):
        """
        Decorator for Zero Trust Authentication
        require_jwt_for_users: True = users need JWT+mTLS, False = services only need mTLS
        """

        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                authenticated, identity, auth_method, error = (
                    self.authenticate_request()
                )

                if not authenticated:
                    return (
                        jsonify(
                            {
                                "error": "Zero Trust Authentication failed",
                                "message": error,
                                "required": "mTLS"
                                + (" + JWT" if require_jwt_for_users else ""),
                                "hint": "For users: JWT token + client certificate\nFor services: Client certificate only",
                            }
                        ),
                        401,
                    )

                # Add authentication info to request
                request.zta_identity = identity
                request.zta_auth_method = auth_method

                # Log the authentication
                current_app.logger.info(
                    f"ZTA Auth: {auth_method} - {identity.get('email', identity.get('service_name', 'unknown'))}"
                )

                return f(*args, **kwargs)

            return decorated_function

        return decorator

    def check_opa_policy(self, resource, action, identity):
        """Check OPA policy for this request"""
        try:
            from app.policy.opa_client import opa_client

            # Prepare input for OPA
            input_data = {
                "input": {
                    "identity": identity,
                    "resource": resource,
                    "action": action,
                    "timestamp": datetime.utcnow().isoformat(),
                    "auth_method": getattr(request, "zta_auth_method", "unknown"),
                }
            }

            # Query OPA
            result = opa_client.check_policy("zta/main", input_data)

            if result.get("result", {}).get("allow", False):
                return True, result.get("result", {}).get("reason", "Allowed by policy")
            else:
                return False, result.get("result", {}).get("reason", "Denied by policy")

        except Exception as e:
            current_app.logger.error(f"OPA error: {e}")
            return False, f"Policy evaluation failed: {e}"


# Singleton instance
zta_auth = ZeroTrustAuthenticator()
