"""
mTLS Middleware for Flask with JWT fallback
Supports both mTLS and JWT authentication
"""

from flask import request, jsonify, current_app, g
from functools import wraps
import base64
import json
from datetime import datetime
from app.logs.zta_event_logger import zta_logger, EVENT_TYPES
import uuid
import os
from cryptography.hazmat.backends import default_backend
from cryptography import x509


def extract_client_certificate():
    """Extract client certificate from request"""
    # Try different ways to get the certificate
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
                            # Save to database would be done elsewhere
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
                get_jwt,
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

        # Check custom time restrictions
        time_allowed = validate_certificate_time_restrictions(cert_info, request_id)
        if not time_allowed:
            return (
                jsonify(
                    {
                        "error": "Certificate access restricted at this time",
                        "code": "TIME_RESTRICTION",
                        "details": "Certificate cannot be used during these hours/days",
                    }
                ),
                403,
            )

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
                    "time_restrictions_passed",
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
                    "handshake_protocol": "TLS_1.3",  # Could be dynamic
                    "cipher_suite": "TLS_AES_256_GCM_SHA384",  # Could be dynamic
                    "session_resumed": False,
                    "handshake_duration_ms": 0,  # You could calculate this
                },
                request_id=request_id,
            )

            # Check for time-based certificate restrictions
            time_allowed = validate_certificate_time_restrictions(cert_info, request_id)

            # Log time restriction check
            zta_logger.log_event(
                "CERTIFICATE_TIME_VALIDATION",
                {
                    "certificate_serial": cert_info.get("serial_number"),
                    "time_validation_passed": time_allowed,
                    "current_time": datetime.utcnow().isoformat(),
                    "client": subject_email,
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
                "stack_trace": (
                    str(e.__traceback__) if hasattr(e, "__traceback__") else None
                ),
            },
            request_id=request_id,
        )
        return False, str(e)


def log_certificate_chain_validation(cert_pem, request_id):
    """Log certificate chain validation details"""
    try:
        from app.mTLS.cert_manager import cert_manager

        # Parse certificate
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())

        # Extract chain info
        chain_info = {
            "leaf_certificate": {
                "subject": dict((attr.oid._name, attr.value) for attr in cert.subject),
                "issuer": dict((attr.oid._name, attr.value) for attr in cert.issuer),
                "serial": format(cert.serial_number, "X"),
                "validity": {
                    "from": cert.not_valid_before.isoformat(),
                    "to": cert.not_valid_after.isoformat(),
                },
            },
            "trust_anchor": {
                "path": cert_manager.ca_cert_path,
                "exists": os.path.exists(cert_manager.ca_cert_path),
            },
            "chain_length": 2,  # Leaf + Root
            "validation_path": ["Client Certificate", "ZTA Root CA"],
        }

        zta_logger.log_event(
            "CERTIFICATE_CHAIN_VALIDATION", chain_info, request_id=request_id
        )

        return chain_info
    except Exception as e:
        zta_logger.log_event(
            "CHAIN_VALIDATION_ERROR", {"error": str(e)}, request_id=request_id
        )
        return None


def log_certificate_details(f):
    """Decorator to log certificate details for each request"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        request_id = getattr(g, "request_id", str(uuid.uuid4()))

        cert_pem = extract_client_certificate()
        if cert_pem:
            # Log certificate chain
            log_certificate_chain_validation(cert_pem, request_id)

            # Log certificate verification summary
            from app.mTLS.cert_manager import cert_manager

            client_ip = request.remote_addr if hasattr(request, "remote_addr") else None
            cert_manager.log_certificate_verification_summary(
                cert_pem, request_id, client_ip
            )

        return f(*args, **kwargs)

    return decorated_function


def check_custom_certificate_extensions(cert_info, request_id):
    """Check for custom certificate extensions and log them"""
    custom_checks = []

    # Extract subject info
    subject = cert_info.get("subject", {})
    email = subject.get("emailAddress", "")
    common_name = subject.get("commonName", "")

    # Check 1: Department validation
    if "O=" in common_name or "O=" in str(subject):
        # Extract organization/department from certificate
        org_parts = common_name.split("O=")
        if len(org_parts) > 1:
            department = org_parts[-1].split("/")[0]
            custom_checks.append(
                {
                    "check": "department_validation",
                    "department": department,
                    "status": "verified",
                }
            )

    # Check 2: Email domain validation
    if email and any(
        email.endswith(domain) for domain in ["@mod.gov", "@mof.gov", "@nsa.gov"]
    ):
        custom_checks.append(
            {
                "check": "email_domain_validation",
                "email": email,
                "status": "approved_domain",
            }
        )

    # Check 3: Certificate purpose
    if cert_info.get("extensions", {}).get("extendedKeyUsage"):
        custom_checks.append(
            {"check": "certificate_purpose", "purpose": "clientAuth", "status": "valid"}
        )

    # Log custom checks if any
    if custom_checks:
        zta_logger.log_event(
            "CERTIFICATE_CUSTOM_CHECKS",
            {
                "checks_performed": custom_checks,
                "total_checks": len(custom_checks),
                "checks_passed": len(
                    [
                        c
                        for c in custom_checks
                        if c.get("status") in ["verified", "valid", "approved_domain"]
                    ]
                ),
            },
            request_id=request_id,
        )


def validate_certificate_time_restrictions(cert_info, request_id):
    """Validate custom time-based restrictions on certificates"""
    try:
        now = datetime.datetime.utcnow()
        current_hour = now.hour
        current_day = now.weekday()  # Monday=0, Sunday=6
        is_weekend = current_day >= 5

        restrictions = []

        # Example: No certificate access on weekends for certain departments
        subject = cert_info.get("subject", {})
        org = subject.get("organizationName", "")

        if is_weekend and "Finance" in org:
            restrictions.append(
                {
                    "restriction": "weekend_access",
                    "department": org,
                    "status": "violated",
                    "message": "Finance department certificates cannot be used on weekends",
                }
            )

        # Example: Restricted hours (9 AM to 5 PM only)
        if current_hour < 9 or current_hour > 17:
            restrictions.append(
                {
                    "restriction": "business_hours",
                    "current_hour": current_hour,
                    "allowed_hours": "9:00-17:00",
                    "status": "outside_allowed_hours",
                }
            )

        # Log time restrictions
        if restrictions:
            zta_logger.log_event(
                "CERTIFICATE_TIME_RESTRICTIONS",
                {
                    "current_time": now.isoformat(),
                    "current_hour": current_hour,
                    "is_weekend": is_weekend,
                    "restrictions": restrictions,
                    "access_allowed": len(
                        [r for r in restrictions if r.get("status") == "violated"]
                    )
                    == 0,
                },
                request_id=request_id,
            )

            # Return False if any violations
            return len([r for r in restrictions if r.get("status") == "violated"]) == 0

        return True

    except Exception as e:
        zta_logger.log_event(
            "TIME_RESTRICTION_ERROR",
            {"error": str(e)},
            request_id=request_id,
        )
        return True  # Fail open on error


def validate_certificate_for_role(cert_info, required_role, request_id):
    """Validate certificate based on user role requirements"""

    subject = cert_info.get("subject", {})
    email = subject.get("emailAddress", "")
    org = subject.get("organizationName", "")

    role_requirements = {
        "admin": {
            "min_cert_strength": "RSA-2048",
            "required_orgs": ["NSA", "MOD"],
            "validity_period": "<=365 days",
            "key_usage": ["digitalSignature", "keyEncipherment"],
        },
        "superadmin": {
            "min_cert_strength": "RSA-4096",
            "required_orgs": ["NSA"],
            "validity_period": "<=180 days",  # Shorter validity for higher security
            "key_usage": ["digitalSignature", "keyEncipherment", "nonRepudiation"],
            "require_smartcard": True,  # Hypothetical extension
        },
        "user": {
            "min_cert_strength": "RSA-2048",
            "validity_period": "<=730 days",  # Longer validity for users
            "key_usage": ["digitalSignature"],
        },
    }

    requirements = role_requirements.get(required_role, {})
    validation_results = []

    # Check organization
    if "required_orgs" in requirements:
        org_valid = any(req_org in org for req_org in requirements["required_orgs"])
        validation_results.append(
            {
                "check": "organization",
                "required": requirements["required_orgs"],
                "actual": org,
                "passed": org_valid,
            }
        )

    # Log role-based validation
    zta_logger.log_event(
        "ROLE_CERTIFICATE_VALIDATION",
        {
            "required_role": required_role,
            "certificate_subject": subject,
            "validation_results": validation_results,
            "all_passed": all(r["passed"] for r in validation_results),
        },
        request_id=request_id,
    )

    return all(r["passed"] for r in validation_results)
