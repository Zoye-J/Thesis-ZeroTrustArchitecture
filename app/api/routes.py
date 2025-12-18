from flask import Blueprint, request, jsonify, current_app, g
from flask_jwt_extended import jwt_required, get_jwt, get_jwt_identity
from app.mTLS.middleware import require_authentication, require_mtls, require_jwt
from app import db
from app.models.user import GovernmentDocument, AccessLog, User
from app.policy.opa_client import get_opa_client
from app.logs.request_logger import log_request
from app.logs.zta_event_logger import zta_logger, EVENT_TYPES
from datetime import datetime, timedelta
import uuid
import hashlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend


api_bp = Blueprint("api", __name__)


# Helper function to get user claims from either JWT or mTLS
def get_user_claims():
    """
    Get user claims from either JWT or mTLS certificate
    Returns: claims dict or None if not authenticated
    """
    # Check Flask's g object for authentication info from middleware
    auth_method = getattr(g, "auth_method", None)

    if auth_method == "mtls" and hasattr(g, "client_certificate"):
        # mTLS authentication
        cert_info = g.client_certificate

        # Try to find user by certificate fingerprint
        fingerprint = cert_info.get("fingerprint")
        if fingerprint:
            user = User.find_by_certificate_fingerprint(fingerprint)
            if user:
                return {
                    "sub": user.id,
                    "username": user.username,
                    "email": user.email,
                    "user_class": user.user_class,
                    "facility": user.facility,
                    "department": user.department,
                    "clearance_level": user.clearance_level,
                    "auth_method": "mTLS",
                }

        # If user not found by fingerprint, try by email from certificate
        email = cert_info.get("subject", {}).get("emailAddress")
        if email:
            user = User.query.filter_by(email=email).first()
            if user:
                return {
                    "sub": user.id,
                    "username": user.username,
                    "email": user.email,
                    "user_class": user.user_class,
                    "facility": user.facility,
                    "department": user.department,
                    "clearance_level": user.clearance_level,
                    "auth_method": "mTLS",
                }

    elif auth_method == "jwt":
        # JWT authentication
        user_id = getattr(g, "jwt_identity", None)
        if user_id:
            user = User.query.get(user_id)
            if user:
                return {
                    "sub": user.id,
                    "username": user.username,
                    "email": user.email,
                    "user_class": user.user_class,
                    "facility": user.facility,
                    "department": user.department,
                    "clearance_level": user.clearance_level,
                    "auth_method": "JWT",
                }

    # Fall back to old JWT method if g object doesn't have info
    try:
        from flask_jwt_extended import verify_jwt_in_request

        verify_jwt_in_request(optional=True)
        user_id = get_jwt_identity()
        if user_id:
            user = User.query.get(user_id)
            if user:
                return {
                    "sub": user.id,
                    "username": user.username,
                    "email": user.email,
                    "user_class": user.user_class,
                    "facility": user.facility,
                    "department": user.department,
                    "clearance_level": user.clearance_level,
                    "auth_method": "JWT",
                }
    except:
        pass

    return None


# Simple ZTA test endpoint
@api_bp.route("/zta-test", methods=["GET"])
def simple_zta_test():
    """
    Simple ZTA test endpoint - no authentication required
    Just checks if certificate is present
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
                "hint": "Connect with: curl --cert ./certs/clients/1/client.crt --key ./certs/clients/1/client.key --cacert ./certs/ca.crt https://localhost:8443/api/zta-test",
            }
        ),
        200,
    )


# Test authentication endpoint - accepts BOTH mTLS and JWT
@api_bp.route("/zta/test", methods=["GET"])
@require_authentication  # Accepts either mTLS or JWT
def test_zta_auth():
    """Test Zero Trust Authentication (JWT + mTLS)"""
    try:
        request_id = getattr(g, "request_id", str(uuid.uuid4()))
        claims = get_user_claims()

        if not claims:
            zta_logger.log_event(
                EVENT_TYPES["ACCESS_DENIED"],
                {"reason": "Authentication required", "test_endpoint": True},
                request_id=request_id,
            )
            return jsonify({"error": "Authentication required"}), 401

        auth_method = claims.get("auth_method", "unknown")
        user_id = claims.get("sub")

        if auth_method == "mTLS":
            # Get certificate info from g object
            cert_info = getattr(g, "client_certificate", {})

            # Log successful mTLS authentication
            zta_logger.log_event(
                EVENT_TYPES["ZTA_FLOW_COMPLETE"],
                {
                    "authentication_method": "mTLS",
                    "layers_validated": ["transport_security"],
                    "certificate_validated": True,
                    "test_endpoint": True,
                },
                user_id=user_id,
                request_id=request_id,
            )

            return (
                jsonify(
                    {
                        "status": "success",
                        "message": "Zero Trust Authentication successful",
                        "authentication_layers": {
                            "layer1_mtls": "✓ Client certificate validated",
                            "layer2_jwt": "✗ JWT token not required (mTLS only)",
                        },
                        "user": {
                            "id": user_id,
                            "username": claims.get("username"),
                            "email": claims.get("email"),
                            "department": claims.get("department"),
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

        elif auth_method == "JWT":
            # Log successful JWT authentication
            zta_logger.log_event(
                EVENT_TYPES["ZTA_FLOW_COMPLETE"],
                {
                    "authentication_method": "JWT",
                    "layers_validated": ["token_validation"],
                    "test_endpoint": True,
                },
                user_id=user_id,
                request_id=request_id,
            )

            return (
                jsonify(
                    {
                        "status": "success",
                        "message": "JWT Authentication successful",
                        "authentication_layers": {
                            "layer1_mtls": "✗ Client certificate not present",
                            "layer2_jwt": "✓ JWT token validated",
                        },
                        "user": {
                            "id": user_id,
                            "username": claims.get("username"),
                            "email": claims.get("email"),
                            "department": claims.get("department"),
                        },
                        "auth_method": "JWT",
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                ),
                200,
            )

    except Exception as e:
        zta_logger.log_event(
            "ZTA_TEST_ERROR",
            {"error": str(e), "test_endpoint": True},
            request_id=getattr(g, "request_id", str(uuid.uuid4())),
        )
        return jsonify({"error": "ZTA test failed", "message": str(e)}), 500


# Dashboard statistics - accepts BOTH authentication methods
@api_bp.route("/documents/stats", methods=["GET"])
@require_authentication
def get_dashboard_stats():
    """Get dashboard statistics - accepts either mTLS or JWT"""
    try:
        request_id = getattr(g, "request_id", str(uuid.uuid4()))
        claims = get_user_claims()

        if not claims:
            zta_logger.log_event(
                EVENT_TYPES["ACCESS_DENIED"],
                {"reason": "Authentication required", "endpoint": "stats"},
                request_id=request_id,
            )
            return jsonify({"error": "Authentication required"}), 401

        user_id = claims["sub"]
        user_facility = claims.get("facility")
        user_department = claims.get("department")
        auth_method = claims.get("auth_method", "unknown")

        # Count user's documents
        user_doc_count = GovernmentDocument.query.filter_by(owner_id=user_id).count()

        # Count today's accesses
        today = datetime.utcnow().date()
        today_accesses = AccessLog.query.filter(
            AccessLog.user_id == user_id, db.func.date(AccessLog.timestamp) == today
        ).count()

        # Log stats access
        zta_logger.log_event(
            EVENT_TYPES["ACCESS_GRANTED"],
            {
                "resource_type": "statistics",
                "auth_method": auth_method,
                "stats_accessed": True,
            },
            user_id=user_id,
            request_id=request_id,
        )

        return (
            jsonify(
                {
                    "your_documents": user_doc_count,
                    "today_accesses": today_accesses,
                    "facility": user_facility,
                    "department": user_department,
                    "auth_method": auth_method,
                    "zta_enforced": True,
                }
            ),
            200,
        )

    except Exception as e:
        zta_logger.log_event(
            "STATS_ERROR",
            {"error": str(e), "endpoint": "stats"},
            request_id=getattr(g, "request_id", str(uuid.uuid4())),
        )
        return jsonify({"error": "Failed to fetch stats", "message": str(e)}), 500


# Get documents - accepts BOTH authentication methods
@api_bp.route("/documents", methods=["GET"])
@require_authentication
def get_documents_list():  # CHANGED NAME
    """Get documents list - accepts either mTLS or JWT"""
    try:
        from app.middleware.zta_flow_middleware import (
            log_zta_flow_start,
            log_opa_to_api_server,
            log_api_to_server1,
            log_server1_to_user,
            log_zta_flow_complete,
        )

        # Get request ID from g (added by middleware) or generate one
        request_id = getattr(g, "request_id", str(uuid.uuid4()))
        g.request_id = request_id

        request_id = getattr(g, "request_id", str(uuid.uuid4()))
        claims = get_user_claims()

        if not claims:
            zta_logger.log_event(
                EVENT_TYPES["ACCESS_DENIED"],
                {"reason": "Authentication required", "endpoint": "documents_list"},
                request_id=request_id,
            )
            return jsonify({"error": "Authentication required"}), 401

        log_zta_flow_start(
            claims,
            {"type": "document_list", "facility": claims.get("facility")},
            "read",
        )

        user_id = claims["sub"]
        user_class = claims["user_class"]
        user_facility = claims.get("facility")
        user_department = claims.get("department")
        auth_method = claims.get("auth_method", "unknown")

        # Get OPA client
        opa_client = get_opa_client()

        from app.services.service_communicator import get_service_communicator

        communicator = get_service_communicator()

        # Log document list access attempt
        zta_logger.log_event(
            "DOCUMENT_LIST_ACCESS",
            {
                "user_class": user_class,
                "auth_method": auth_method,
                "department": user_department,
                "opa_available": opa_client is not None,
            },
            user_id=user_id,
            request_id=request_id,
        )

        # Build query
        query = GovernmentDocument.query.filter_by(
            facility=user_facility, is_archived=False
        )

        # Get query parameters
        classification = request.args.get("classification")
        department = request.args.get("department")
        category = request.args.get("category")
        search = request.args.get("search")

        # Apply filters
        if classification:
            query = query.filter_by(classification=classification)

        if department:
            query = query.filter_by(department=department)
        elif user_class in ["user", "admin"]:
            query = query.filter_by(department=user_department)

        if category:
            query = query.filter_by(category=category)

        if search:
            query = query.filter(
                db.or_(
                    GovernmentDocument.title.ilike(f"%{search}%"),
                    GovernmentDocument.description.ilike(f"%{search}%"),
                    GovernmentDocument.document_id.ilike(f"%{search}%"),
                )
            )

        # Execute query
        documents = query.order_by(GovernmentDocument.created_at.desc()).all()

        # Check OPA policy for each document WITH TIME RESTRICTIONS
        filtered_documents = []
        opa_checks_performed = 0
        opa_allows = 0
        opa_denies = 0
        time_restricted_denials = 0

        current_time = datetime.now()
        current_hour = current_time.hour

        for doc in documents:
            # Prepare OPA input
            opa_input = {
                "user": {
                    "id": user_id,
                    "username": claims.get("username", user_id),
                    "role": user_class,
                    "department": user_department,
                    "facility": user_facility,
                    "clearance": claims.get("clearance_level", "BASIC"),
                },
                "resource": {
                    "type": "document",
                    "id": doc.id,
                    "classification": doc.classification,
                    "facility": doc.facility,
                    "department": doc.department,
                    "owner": doc.owner_id,
                },
                "action": "read",
                "environment": {
                    "time": {
                        "hour": current_hour,
                        "minute": current_time.minute,
                        "weekday": current_time.strftime("%A"),
                        "weekend": current_time.weekday() >= 5,
                        "iso": current_time.isoformat(),
                    },
                    "ip_address": request.remote_addr if request else None,
                },
                "request_id": request_id,
                "authentication": {
                    "method": "mTLS_JWT" if auth_method == "mTLS" else "JWT",
                    "certificate": getattr(g, "client_certificate", None),
                    "jwt_valid": True,
                },
            }

            # Check OPA policy WITH TIME RESTRICTIONS
            if opa_client:
                try:
                    opa_checks_performed += 1

                    # Log individual document OPA check
                    zta_logger.log_event(
                        EVENT_TYPES["OPA_QUERY_SENT"],
                        {
                            "document_id": doc.id,
                            "classification": doc.classification,
                            "policy_path": "zta/main",
                            "individual_check": True,
                            "current_hour": current_hour,
                        },
                        user_id=user_id,
                        request_id=request_id,
                    )

                    # Use the new time-restricted evaluation
                    result = opa_client.evaluate_with_time_restrictions(
                        opa_input, request_id
                    )

                    allowed = result.get("overall_allow", False)
                    reason = result.get("reason", "Policy evaluation complete")

                    is_time_restricted = (
                        "outside business hours" in reason
                        or "9 PM" in reason
                        or "8 AM" in reason
                    )

                    log_opa_to_api_server(request_id, result)

                    if allowed:
                        opa_allows += 1
                        filtered_documents.append(doc)

                        zta_logger.log_event(
                            EVENT_TYPES["OPA_RESPONSE_RECEIVED"],
                            {
                                "decision": "allow",
                                "reason": reason,
                                "document_id": doc.id,
                                "individual_check": True,
                                "time_restriction_passed": doc.classification
                                == "TOP_SECRET",
                            },
                            user_id=user_id,
                            request_id=request_id,
                        )
                    else:
                        opa_denies += 1
                        if is_time_restricted:
                            time_restricted_denials += 1

                        zta_logger.log_event(
                            EVENT_TYPES["OPA_RESPONSE_RECEIVED"],
                            {
                                "decision": "deny",
                                "reason": reason,
                                "document_id": doc.id,
                                "individual_check": True,
                                "time_restricted": is_time_restricted,
                            },
                            user_id=user_id,
                            request_id=request_id,
                        )

                except Exception as e:
                    # If OPA fails, allow access (fail-open for development)
                    current_app.logger.warning(
                        f"OPA check failed for doc {doc.id}: {e}"
                    )
                    filtered_documents.append(doc)

                    zta_logger.log_event(
                        "OPA_CHECK_FAILED",
                        {
                            "document_id": doc.id,
                            "error": str(e),
                            "fallback": "allow (fail-open)",
                        },
                        user_id=user_id,
                        request_id=request_id,
                    )
            else:
                # No OPA client, allow access
                filtered_documents.append(doc)

        log_api_to_server1(request_id, success=True)
        # Log the overall access
        cert_fingerprint = None
        if hasattr(g, "client_certificate"):
            cert_fingerprint = g.client_certificate.get("fingerprint", "")[:16] + "..."

        log_request(
            user_id=user_id,
            endpoint="/api/documents",
            method="GET",
            status="allowed",
            reason=f"Access via {auth_method}",
            auth_method=auth_method,
            certificate_fingerprint=cert_fingerprint,
            time_restricted_documents_filtered=time_restricted_denials,
        )

        # Log summary of document access
        zta_logger.log_event(
            EVENT_TYPES["ACCESS_GRANTED"],
            {
                "resource_type": "document_list",
                "total_documents": len(documents),
                "accessible_documents": len(filtered_documents),
                "opa_checks_performed": opa_checks_performed,
                "opa_allows": opa_allows,
                "opa_denies": opa_denies,
                "time_restricted_denials": time_restricted_denials,
                "auth_method": auth_method,
                "policy_enforced": bool(opa_client),
                "current_time": current_time.strftime("%H:%M"),
                "top_secret_time_restriction": "9 PM to 8 AM",
            },
            user_id=user_id,
            request_id=request_id,
        )

        log_server1_to_user(request_id, allowed=True)
        log_zta_flow_complete(request_id, success=True)
        zta_logger.log_event(
            "ZTA_FLOW_COMPLETE",
            {
                "request_id": request_id,
                "success": True,
                "documents_returned": len(filtered_documents),
                "opa_checks": opa_checks_performed,
            },
            user_id=user_id,
            request_id=request_id,
        )

        return (
            jsonify(
                {
                    "documents": [
                        {
                            "id": doc.id,
                            "document_id": doc.document_id,
                            "title": doc.title,
                            "description": doc.description,
                            "classification": doc.classification,
                            "department": doc.department,
                            "category": doc.category,
                            "created_at": doc.created_at.isoformat(),
                            "owner_id": doc.owner_id,
                            "facility": doc.facility,
                        }
                        for doc in filtered_documents
                    ],
                    "zta_info": {
                        "auth_method": auth_method,
                        "policy_enforced": bool(opa_client),
                        "documents_filtered": len(documents) - len(filtered_documents),
                        "time_restricted_filtered": time_restricted_denials,
                        "opa_statistics": (
                            {
                                "checks_performed": opa_checks_performed,
                                "allowed": opa_allows,
                                "denied": opa_denies,
                                "time_restricted_denials": time_restricted_denials,
                            }
                            if opa_client
                            else None
                        ),
                        "request_id": request_id,
                        "current_time": current_time.isoformat(),
                        "top_secret_access_hours": "08:00 to 21:00",
                    },
                }
            ),
            200,
        )

    except Exception as e:
        zta_logger.log_event(
            "DOCUMENT_LIST_ERROR",
            {"error": str(e), "endpoint": "documents_list"},
            request_id=getattr(g, "request_id", str(uuid.uuid4())),
        )
        return jsonify({"error": "Failed to fetch documents", "message": str(e)}), 500


def evaluate_with_time_restrictions(self, input_data, request_id=None):
    """
    Wrapper method for backward compatibility with routes.py
    Calls the main evaluate_document_access method
    """
    try:
        self.logger.warning(
            f"⚠️ Using evaluate_with_time_restrictions wrapper - request_id: {request_id}"
        )

        # Extract user and document from input_data
        user_claims = {
            "id": input_data.get("user", {}).get("id"),
            "username": input_data.get("user", {}).get("username"),
            "user_class": input_data.get("user", {}).get("role"),
            "department": input_data.get("user", {}).get("department"),
            "facility": input_data.get("user", {}).get("facility"),
            "clearance_level": input_data.get("user", {}).get("clearance"),
        }

        document_info = {
            "id": input_data.get("resource", {}).get("id"),
            "document_id": input_data.get("resource", {}).get(
                "document_id", f"doc_{input_data.get('resource', {}).get('id')}"
            ),
            "classification": input_data.get("resource", {}).get(
                "classification", "BASIC"
            ),
            "department": input_data.get("resource", {}).get("department"),
            "facility": input_data.get("resource", {}).get("facility"),
        }

        # Call the main evaluation method
        result = self.evaluate_document_access(
            user_claims, document_info, input_data.get("action", "read")
        )

        # Add time restriction info for compatibility
        current_hour = datetime.now().hour
        is_time_restricted = document_info.get("classification") == "TOP_SECRET" and (
            current_hour >= 21 or current_hour < 8
        )

        return {
            "overall_allow": result.get("allowed", False),
            "reason": result.get("reason", "Policy evaluation complete"),
            "time_restriction_applied": is_time_restricted,
            "current_hour": current_hour,
            "original_result": result,
        }

    except Exception as e:
        self.logger.error(f"Error in evaluate_with_time_restrictions: {str(e)}")
        return {
            "overall_allow": False,
            "reason": f"Evaluation error: {str(e)}",
            "time_restriction_applied": False,
            "current_hour": datetime.now().hour,
        }


# Get single document - accepts BOTH authentication methods
@api_bp.route("/documents/<int:document_id>", methods=["GET"])
@require_authentication
def get_document(document_id):
    """Get single document - accepts either mTLS or JWT"""
    try:
        from app.middleware.zta_flow_middleware import (
            log_zta_flow_start,
            log_opa_to_api_server,
            log_api_to_server1,
            log_server1_to_user,
            log_zta_flow_complete,
        )

        # Get request ID from g (added by middleware) or generate one
        request_id = getattr(g, "request_id", str(uuid.uuid4()))
        g.request_id = request_id

        claims = get_user_claims()

        if not claims:
            # Log failed authentication attempt
            zta_logger.log_event(
                EVENT_TYPES["ACCESS_DENIED"],
                {
                    "resource_id": document_id,
                    "reason": "No valid authentication",
                    "auth_method": "none",
                },
                request_id=request_id,
            )
            return jsonify({"error": "Authentication required"}), 401

        log_zta_flow_start(claims, {"type": "document", "id": document_id}, "read")

        from app.services.service_communicator import get_service_communicator

        communicator = get_service_communicator()

        # Find document
        document = GovernmentDocument.query.get_or_404(document_id)

        # Get OPA client
        opa_client = get_opa_client()

        # Prepare OPA input with request ID
        opa_input = {
            "user": {
                "id": claims["sub"],
                "username": claims.get("username", claims["sub"]),
                "role": claims["user_class"],
                "department": claims.get("department"),
                "facility": claims.get("facility"),
                "clearance": claims.get("clearance_level", "BASIC"),
            },
            "resource": {
                "type": "document",
                "id": document.id,
                "classification": document.classification,
                "facility": document.facility,
                "department": document.department,
                "owner": document.owner_id,
            },
            "action": "read",
            "environment": {
                "time": {
                    "hour": datetime.now().hour,
                    "day_of_week": datetime.now().strftime("%A"),
                    "weekend": datetime.now().weekday() >= 5,
                },
                "ip_address": request.remote_addr if request else None,
            },
            "request_id": request_id,
            "authentication": {
                "method": "mTLS_JWT" if claims.get("auth_method") == "mTLS" else "JWT",
                "certificate": getattr(g, "client_certificate", None),
                "jwt_valid": True,
            },
        }

        # Log OPA query being sent
        zta_logger.log_event(
            EVENT_TYPES["OPA_QUERY_SENT"],
            {
                "policy_path": "zta/main",
                "input_summary": {
                    "user": claims.get("username"),
                    "resource_id": document.id,
                    "classification": document.classification,
                    "action": "read",
                    "auth_method": claims.get("auth_method"),
                    "user_clearance": claims.get("clearance_level"),
                    "document_clearance": document.classification,
                },
            },
            user_id=claims.get("sub"),
            request_id=request_id,
        )

        # Check OPA policy WITH TIME RESTRICTIONS
        if opa_client:
            try:
                # Use the new time-restricted evaluation method
                result = opa_client.evaluate_with_time_restrictions(
                    opa_input, request_id
                )

                allowed = result.get("overall_allow", False)
                reason = result.get("reason", "Policy evaluation complete")
                decision_id = "time_restricted_evaluation"

                log_opa_to_api_server(request_id, result)

                # Log time-based restriction check
                if document.classification == "TOP_SECRET":
                    current_hour = datetime.now().hour
                    time_restricted = current_hour >= 21 or current_hour < 8
                    zta_logger.log_event(
                        "TIME_RESTRICTION_CHECK",
                        {
                            "document_classification": "TOP_SECRET",
                            "current_hour": current_hour,
                            "restricted_hours": "9 PM to 8 AM",
                            "is_restricted_time": time_restricted,
                            "access_allowed": not time_restricted,
                        },
                        user_id=claims.get("sub"),
                        request_id=request_id,
                    )

                # Log OPA response
                zta_logger.log_event(
                    EVENT_TYPES["OPA_RESPONSE_RECEIVED"],
                    {
                        "decision": allowed,
                        "reason": reason,
                        "decision_id": decision_id,
                        "clearance_match": claims.get("clearance_level")
                        == document.classification,
                        "department_match": claims.get("department")
                        == document.department,
                        "time_restrictions_applied": document.classification
                        == "TOP_SECRET",
                        "time_based_result": result.get("time_based_restrictions", {}),
                    },
                    user_id=claims.get("sub"),
                    request_id=request_id,
                )

                if not allowed:

                    log_api_to_server1(request_id, success=False)
                    log_server1_to_user(request_id, allowed=False)
                    log_zta_flow_complete(request_id, success=False)
                    # Log denied access with OPA reason
                    cert_fingerprint = None
                    if hasattr(g, "client_certificate"):
                        cert_fingerprint = (
                            g.client_certificate.get("fingerprint", "")[:16] + "..."
                        )

                    # Check if denial is due to time restriction
                    is_time_restriction = (
                        "outside business hours" in reason
                        or "9 PM" in reason
                        or "8 AM" in reason
                    )

                    # Log using original logger
                    log_request(
                        user_id=claims.get("sub"),
                        endpoint=f"/api/documents/{document_id}",
                        method="GET",
                        status="denied",
                        reason=f"OPA denied access: {reason}",
                        document_id=document_id,
                        auth_method=claims.get("auth_method", "unknown"),
                        certificate_fingerprint=cert_fingerprint,
                        request_id=request_id,
                        time_restriction_applied=is_time_restriction,
                    )

                    # Also log using ZTA event logger
                    zta_logger.log_event(
                        EVENT_TYPES["ACCESS_DENIED"],
                        {
                            "resource_id": document_id,
                            "resource_type": "document",
                            "classification": document.classification,
                            "opa_decision": "deny",
                            "opa_reason": reason,
                            "auth_method": claims.get("auth_method"),
                            "clearance": claims.get("clearance_level"),
                            "zta_violation": True,
                            "time_restriction": is_time_restriction,
                            "current_time": datetime.now().isoformat(),
                        },
                        user_id=claims.get("sub"),
                        request_id=request_id,
                    )

                    # Special response for time-based restrictions
                    if is_time_restriction:
                        return (
                            jsonify(
                                {
                                    "error": "Access denied due to time restrictions",
                                    "reason": reason,
                                    "details": f"TOP_SECRET documents cannot be accessed between 12 AM and 8 AM",
                                    "current_time": datetime.now().strftime("%H:%M"),
                                    "zta_context": {
                                        "auth_method": claims.get("auth_method"),
                                        "policy_violation": True,
                                        "request_id": request_id,
                                        "time_restriction": True,
                                        "restricted_hours": "00:00 to 08:00",
                                    },
                                }
                            ),
                            403,
                        )
                    else:
                        return (
                            jsonify(
                                {
                                    "error": "Access denied",
                                    "reason": reason,
                                    "zta_context": {
                                        "auth_method": claims.get("auth_method"),
                                        "policy_violation": True,
                                        "request_id": request_id,
                                        "user_clearance": claims.get("clearance_level"),
                                        "required_clearance": document.classification,
                                    },
                                }
                            ),
                            403,
                        )

            except Exception as opa_error:
                # OPA error - log but allow access (fail-open)
                current_app.logger.warning(f"OPA check failed: {opa_error}")

                # Log OPA failure event
                zta_logger.log_event(
                    "OPA_ERROR",
                    {"error": str(opa_error), "fallback": "fail-open (access allowed)"},
                    user_id=claims.get("sub"),
                    request_id=request_id,
                )

        log_api_to_server1(request_id, success=True)

        # Log allowed access with original logger
        cert_fingerprint = None
        if hasattr(g, "client_certificate"):
            cert_fingerprint = g.client_certificate.get("fingerprint", "")[:16] + "..."

        log_request(
            user_id=claims.get("sub"),
            endpoint=f"/api/documents/{document_id}",
            method="GET",
            status="allowed",
            reason="Access allowed",
            document_id=document_id,
            auth_method=claims.get("auth_method", "unknown"),
            certificate_fingerprint=cert_fingerprint,
            request_id=request_id,
        )

        # Log ZTA access granted event
        zta_logger.log_event(
            EVENT_TYPES["ACCESS_GRANTED"],
            {
                "resource_id": document_id,
                "resource_type": "document",
                "classification": document.classification,
                "opa_decision": "allow" if opa_client else "no_check",
                "auth_method": claims.get("auth_method"),
                "clearance": claims.get("clearance_level"),
                "department_match": claims.get("department") == document.department,
                "zta_compliant": True,
                "time_restriction_passed": document.classification == "TOP_SECRET",
                "current_time": datetime.now().strftime("%H:%M"),
            },
            user_id=claims.get("sub"),
            request_id=request_id,
        )

        # Log complete ZTA flow
        zta_logger.log_event(
            EVENT_TYPES["ZTA_FLOW_COMPLETE"],
            {
                "steps_completed": [
                    "authentication_verified",
                    "opa_policy_check" if opa_client else "no_policy_check",
                    (
                        "time_restriction_check"
                        if document.classification == "TOP_SECRET"
                        else "no_time_check"
                    ),
                    "access_decision_made",
                ],
                "outcome": "access_granted",
                "zta_principles_applied": [
                    "verify_explicitly",
                    "least_privilege",
                    "assume_breach",
                    "time_based_access_control",
                ],
                "request_id": request_id,
            },
            user_id=claims.get("sub"),
            request_id=request_id,
        )

        log_server1_to_user(request_id, allowed=True)
        log_zta_flow_complete(request_id, success=True)

        return (
            jsonify(
                {
                    "document": {
                        "id": document.id,
                        "document_id": document.document_id,
                        "title": document.title,
                        "description": document.description,
                        "content": document.content,
                        "classification": document.classification,
                        "facility": document.facility,
                        "department": document.department,
                        "category": document.category,
                    },
                    "zta_context": {
                        "auth_method": claims.get("auth_method"),
                        "policy_decision": "allowed" if opa_client else "no_policy",
                        "request_id": request_id,
                        "zta_flow_completed": True,
                        "user_clearance": claims.get("clearance_level"),
                        "document_clearance": document.classification,
                        "time_based_control_applied": document.classification
                        == "TOP_SECRET",
                        "access_time": datetime.now().isoformat(),
                    },
                }
            ),
            200,
        )

    except Exception as e:
        zta_logger.log_event(
            "DOCUMENT_ACCESS_ERROR",
            {
                "error": str(e),
                "document_id": document_id,
                "endpoint": "single_document",
            },
            request_id=getattr(g, "request_id", str(uuid.uuid4())),
        )
        return jsonify({"error": "Failed to fetch document", "message": str(e)}), 500


# Create document - accepts BOTH authentication methods
@api_bp.route("/documents", methods=["POST"])
@require_authentication
def create_document():
    """Create document - accepts either mTLS or JWT"""
    try:
        request_id = getattr(g, "request_id", str(uuid.uuid4()))
        claims = get_user_claims()

        if not claims:
            zta_logger.log_event(
                EVENT_TYPES["ACCESS_DENIED"],
                {"reason": "Authentication required", "action": "create_document"},
                request_id=request_id,
            )
            return jsonify({"error": "Authentication required"}), 401

        user_id = claims["sub"]
        user_facility = claims.get("facility")
        user_department = claims.get("department")
        auth_method = claims.get("auth_method", "unknown")

        data = request.get_json()

        # Log document creation attempt
        zta_logger.log_event(
            "DOCUMENT_CREATE_ATTEMPT",
            {
                "user_id": user_id,
                "auth_method": auth_method,
                "has_data": data is not None,
            },
            user_id=user_id,
            request_id=request_id,
        )

        # Validate required fields
        required_fields = ["title", "classification", "category"]
        for field in required_fields:
            if field not in data:
                zta_logger.log_event(
                    "DOCUMENT_CREATE_ERROR",
                    {"error": f"Missing field: {field}", "action": "create_document"},
                    user_id=user_id,
                    request_id=request_id,
                )
                return jsonify({"error": f"{field} is required"}), 400

        # Check if user has sufficient clearance
        clearance_levels = ["BASIC", "CONFIDENTIAL", "SECRET", "TOP_SECRET"]
        user_clearance = claims.get("clearance_level", "BASIC")
        doc_classification = data["classification"]

        user_idx = (
            clearance_levels.index(user_clearance)
            if user_clearance in clearance_levels
            else 0
        )
        doc_idx = (
            clearance_levels.index(doc_classification)
            if doc_classification in clearance_levels
            else 0
        )

        if doc_idx > user_idx:
            zta_logger.log_event(
                EVENT_TYPES["ACCESS_DENIED"],
                {
                    "reason": "Insufficient clearance",
                    "user_clearance": user_clearance,
                    "required_clearance": doc_classification,
                    "clearance_violation": True,
                    "action": "create_document",
                },
                user_id=user_id,
                request_id=request_id,
            )
            return (
                jsonify(
                    {
                        "error": "Insufficient clearance",
                        "message": f"Your clearance ({user_clearance}) is insufficient to create {doc_classification} documents",
                        "zta_context": {
                            "user_clearance": user_clearance,
                            "required_clearance": doc_classification,
                        },
                    }
                ),
                403,
            )

        # Generate document ID
        document_id = f"{user_facility[:3].upper()}-{user_department[:3].upper()}-{datetime.utcnow().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"

        # Create document
        new_document = GovernmentDocument(
            document_id=document_id,
            title=data["title"],
            description=data.get("description", ""),
            content=data.get("content", ""),
            classification=data["classification"],
            facility=user_facility,
            department=user_department,
            category=data["category"],
            owner_id=user_id,
            created_by=user_id,
            expiry_date=data.get("expiry_date"),
        )

        db.session.add(new_document)
        db.session.commit()

        # Log creation with original logger
        cert_fingerprint = None
        if hasattr(g, "client_certificate"):
            cert_fingerprint = g.client_certificate.get("fingerprint", "")[:16] + "..."

        log_request(
            user_id=user_id,
            endpoint="/api/documents",
            method="POST",
            status="allowed",
            reason=f"Created document {document_id} via {auth_method}",
            document_id=new_document.id,
            auth_method=auth_method,
            certificate_fingerprint=cert_fingerprint,
        )

        # Log ZTA document creation event
        zta_logger.log_event(
            EVENT_TYPES["ACCESS_GRANTED"],
            {
                "action": "create_document",
                "document_id": new_document.id,
                "classification": new_document.classification,
                "auth_method": auth_method,
                "clearance_validated": True,
                "zta_compliant": True,
            },
            user_id=user_id,
            request_id=request_id,
        )

        return (
            jsonify(
                {
                    "message": "Document created successfully",
                    "document": {
                        "id": new_document.id,
                        "document_id": new_document.document_id,
                        "title": new_document.title,
                        "classification": new_document.classification,
                    },
                    "zta_context": {
                        "auth_method": auth_method,
                        "created_via": "Zero Trust Authentication",
                        "request_id": request_id,
                        "clearance_validated": True,
                    },
                }
            ),
            201,
        )

    except Exception as e:
        db.session.rollback()
        zta_logger.log_event(
            "DOCUMENT_CREATE_ERROR",
            {"error": str(e), "action": "create_document"},
            request_id=getattr(g, "request_id", str(uuid.uuid4())),
        )
        return jsonify({"error": "Failed to create document", "message": str(e)}), 500


# Get access logs - STRICT mTLS only (admin endpoint)
@api_bp.route("/logs", methods=["GET"])
@require_mtls  # Strict: Only mTLS certificates allowed for admin logs
def get_logs():
    """Get access logs - requires mTLS certificate (admin only)"""
    try:
        request_id = getattr(g, "request_id", str(uuid.uuid4()))
        claims = get_user_claims()

        if not claims:
            zta_logger.log_event(
                EVENT_TYPES["ACCESS_DENIED"],
                {"reason": "Authentication required", "endpoint": "logs"},
                request_id=request_id,
            )
            return jsonify({"error": "Authentication required"}), 401

        user_id = claims["sub"]
        user_class = claims["user_class"]
        user_facility = claims.get("facility")
        auth_method = claims.get("auth_method", "unknown")

        # Log log access attempt
        zta_logger.log_event(
            "LOG_ACCESS_ATTEMPT",
            {
                "user_class": user_class,
                "auth_method": auth_method,
                "endpoint": "logs",
                "mTLS_required": True,
            },
            user_id=user_id,
            request_id=request_id,
        )

        # Only admin and superadmin can access logs
        if user_class not in ["admin", "superadmin"]:
            zta_logger.log_event(
                EVENT_TYPES["ACCESS_DENIED"],
                {
                    "reason": "Insufficient privileges",
                    "required_role": "admin",
                    "user_role": user_class,
                    "endpoint": "logs",
                },
                user_id=user_id,
                request_id=request_id,
            )
            return (
                jsonify(
                    {
                        "error": "Admin access required",
                        "zta_context": {
                            "required_role": "admin or superadmin",
                            "your_role": user_class,
                        },
                    }
                ),
                403,
            )

        # Get query parameters
        limit = request.args.get("limit", 100, type=int)
        user_filter = request.args.get("user_id", type=int)
        document_filter = request.args.get("document_id", type=int)

        # Build query
        query = AccessLog.query

        # Filter by user if requested
        if user_filter and user_class == "superadmin":
            query = query.filter(AccessLog.user_id == user_filter)
        else:
            # Admin can only see logs from their facility
            query = query.join(User).filter(User.facility == user_facility)

        if document_filter:
            query = query.filter(AccessLog.document_id == document_filter)

        # Order by most recent and limit
        logs = query.order_by(AccessLog.timestamp.desc()).limit(limit).all()

        # Log successful log access
        zta_logger.log_event(
            EVENT_TYPES["ACCESS_GRANTED"],
            {
                "endpoint": "logs",
                "log_count": len(logs),
                "auth_method": auth_method,
                "user_role": user_class,
                "mTLS_validated": True,
            },
            user_id=user_id,
            request_id=request_id,
        )

        return (
            jsonify(
                {
                    "logs": [
                        {
                            "id": log.id,
                            "user_id": log.user_id,
                            "username": log.user.username if log.user else "Unknown",
                            "document_id": log.document_id,
                            "document_title": (
                                log.document.title if log.document else "Unknown"
                            ),
                            "action": log.action,
                            "timestamp": log.timestamp.isoformat(),
                            "status": log.status,
                            "reason": log.reason,
                            "ip_address": log.ip_address,
                            "auth_method": getattr(log, "auth_method", "legacy"),
                            "certificate_fingerprint": getattr(
                                log, "certificate_fingerprint", None
                            ),
                        }
                        for log in logs
                    ],
                    "total": len(logs),
                    "zta_context": {
                        "auth_method": auth_method,
                        "facility": user_facility,
                        "access_restriction": "mTLS certificate required",
                        "request_id": request_id,
                    },
                }
            ),
            200,
        )

    except Exception as e:
        zta_logger.log_event(
            "LOG_ACCESS_ERROR",
            {"error": str(e), "endpoint": "logs"},
            request_id=getattr(g, "request_id", str(uuid.uuid4())),
        )
        return jsonify({"error": "Failed to fetch logs", "message": str(e)}), 500


# Get users - STRICT mTLS only (admin endpoint)
@api_bp.route("/users", methods=["GET"])
@require_mtls  # Strict: Only mTLS certificates allowed for admin users
def get_users():
    """Get users - requires mTLS certificate (admin only)"""
    try:
        request_id = getattr(g, "request_id", str(uuid.uuid4()))
        claims = get_user_claims()

        if not claims:
            zta_logger.log_event(
                EVENT_TYPES["ACCESS_DENIED"],
                {"reason": "Authentication required", "endpoint": "users"},
                request_id=request_id,
            )
            return jsonify({"error": "Authentication required"}), 401

        user_class = claims["user_class"]
        auth_method = claims.get("auth_method", "unknown")

        # Log user list access attempt
        zta_logger.log_event(
            "USER_LIST_ACCESS_ATTEMPT",
            {
                "user_class": user_class,
                "auth_method": auth_method,
                "endpoint": "users",
                "mTLS_required": True,
            },
            user_id=claims.get("sub"),
            request_id=request_id,
        )

        # Only admin and superadmin can access user list
        if user_class not in ["admin", "superadmin"]:
            zta_logger.log_event(
                EVENT_TYPES["ACCESS_DENIED"],
                {
                    "reason": "Insufficient privileges",
                    "required_role": "admin",
                    "user_role": user_class,
                    "endpoint": "users",
                },
                user_id=claims.get("sub"),
                request_id=request_id,
            )
            return (
                jsonify(
                    {
                        "error": "Admin access required",
                        "zta_context": {
                            "required_role": "admin or superadmin",
                            "your_role": user_class,
                        },
                    }
                ),
                403,
            )

        user_facility = claims.get("facility")

        # Get query parameters
        department = request.args.get("department")
        user_class_filter = request.args.get("user_class")

        # Build query - only show users from the same facility
        query = User.query.filter_by(facility=user_facility)

        # Apply filters
        if department:
            query = query.filter_by(department=department)

        if user_class_filter:
            query = query.filter_by(user_class=user_class_filter)

        # Include certificate info in response
        users = query.order_by(User.created_at.desc()).all()

        # Count users with certificates
        users_with_certs = sum(1 for user in users if user.certificate_fingerprint)

        # Log successful user list access
        zta_logger.log_event(
            EVENT_TYPES["ACCESS_GRANTED"],
            {
                "endpoint": "users",
                "user_count": len(users),
                "users_with_certificates": users_with_certs,
                "auth_method": auth_method,
                "user_role": user_class,
                "mTLS_validated": True,
            },
            user_id=claims.get("sub"),
            request_id=request_id,
        )

        return (
            jsonify(
                {
                    "users": [
                        {
                            "id": user.id,
                            "username": user.username,
                            "email": user.email,
                            "user_class": user.user_class,
                            "facility": user.facility,
                            "department": user.department,
                            "clearance_level": user.clearance_level,
                            "created_at": user.created_at.isoformat(),
                            "is_active": user.is_active,
                            "has_certificate": bool(user.certificate_fingerprint),
                            "certificate_expires": (
                                user.certificate_expires.isoformat()
                                if user.certificate_expires
                                else None
                            ),
                            "mfa_enabled": user.mfa_enabled,
                        }
                        for user in users
                    ],
                    "total": len(users),
                    "zta_context": {
                        "auth_method": auth_method,
                        "facility": user_facility,
                        "certificate_based_auth_enabled": users_with_certs > 0,
                        "certificate_users_count": users_with_certs,
                        "access_restriction": "mTLS certificate required",
                        "request_id": request_id,
                    },
                }
            ),
            200,
        )

    except Exception as e:
        zta_logger.log_event(
            "USER_LIST_ERROR",
            {"error": str(e), "endpoint": "users"},
            request_id=getattr(g, "request_id", str(uuid.uuid4())),
        )
        return jsonify({"error": "Failed to fetch users", "message": str(e)}), 500


# Test OPA endpoint - accepts BOTH authentication methods
@api_bp.route("/opa-test", methods=["GET"])
@require_authentication
def opa_test():
    """Test OPA integration - accepts either mTLS or JWT"""
    try:
        request_id = getattr(g, "request_id", str(uuid.uuid4()))
        opa_client = get_opa_client()

        claims = get_user_claims()
        auth_method = claims.get("auth_method", "unknown") if claims else "unknown"

        # Log OPA test attempt
        zta_logger.log_event(
            "OPA_TEST_ATTEMPT",
            {
                "auth_method": auth_method,
                "opa_client_available": opa_client is not None,
            },
            user_id=claims.get("sub") if claims else None,
            request_id=request_id,
        )

        # Test OPA connection
        if opa_client and opa_client.health_check():
            zta_logger.log_event(
                EVENT_TYPES["OPA_RESPONSE_RECEIVED"],
                {
                    "status": "connected",
                    "opa_url": opa_client.opa_url,
                    "health_check": "passed",
                },
                user_id=claims.get("sub") if claims else None,
                request_id=request_id,
            )

            return (
                jsonify(
                    {
                        "message": "OPA integration working",
                        "opa_url": (
                            opa_client.opa_url if opa_client else "Not configured"
                        ),
                        "status": "connected",
                        "zta_context": {
                            "auth_method": auth_method,
                            "request_id": request_id,
                        },
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                ),
                200,
            )
        else:
            zta_logger.log_event(
                "OPA_HEALTH_CHECK_FAILED",
                {
                    "status": "disconnected",
                    "opa_url": opa_client.opa_url if opa_client else "Not configured",
                    "health_check": "failed",
                },
                user_id=claims.get("sub") if claims else None,
                request_id=request_id,
            )

            return (
                jsonify(
                    {
                        "message": "OPA server not reachable",
                        "opa_url": (
                            opa_client.opa_url if opa_client else "Not configured"
                        ),
                        "status": "disconnected",
                        "zta_context": {
                            "auth_method": auth_method,
                            "request_id": request_id,
                        },
                    }
                ),
                503,
            )

    except Exception as e:
        zta_logger.log_event(
            "OPA_TEST_ERROR",
            {"error": str(e), "endpoint": "opa-test"},
            request_id=getattr(g, "request_id", str(uuid.uuid4())),
        )
        return jsonify({"error": "OPA test failed", "message": str(e)}), 500


# Service health endpoint - STRICT mTLS only (for services)
@api_bp.route("/service/health", methods=["GET"])
@require_mtls  # Services only need mTLS
def service_health():
    """Service health check - mTLS only (service-to-service)"""
    request_id = str(uuid.uuid4())
    claims = get_user_claims()
    auth_method = claims.get("auth_method", "unknown") if claims else "unknown"

    # Log service health check
    zta_logger.log_event(
        "SERVICE_HEALTH_CHECK",
        {
            "status": "healthy",
            "auth_method": auth_method,
            "service_type": "mTLS_only",
            "request_source": "service",
        },
        user_id=claims.get("sub") if claims else None,
        request_id=request_id,
    )

    return jsonify(
        {
            "status": "healthy",
            "service": "ZTA Government System",
            "auth_method": auth_method,
            "timestamp": datetime.utcnow().isoformat(),
            "zta_enabled": True,
            "features": ["JWT", "mTLS", "OPA", "Certificate Validation", "RBAC"],
            "access_restriction": "mTLS certificate required for services",
            "request_id": request_id,
        }
    )


# Legacy JWT-only endpoint (for backward compatibility)
@api_bp.route("/legacy/documents", methods=["GET"])
@require_jwt  # Only JWT tokens allowed (no mTLS fallback)
def legacy_get_documents():
    """Legacy endpoint - JWT only (for backward compatibility)"""
    request_id = str(uuid.uuid4())

    # Log legacy endpoint access warning
    zta_logger.log_event(
        "LEGACY_ENDPOINT_ACCESS",
        {
            "warning": "Legacy JWT-only endpoint accessed",
            "recommendation": "Migrate to ZTA endpoints",
            "security_level": "reduced",
        },
        request_id=request_id,
    )

    current_app.logger.warning(
        "Legacy JWT-only endpoint accessed - consider migrating to ZTA endpoints"
    )

    # Call the get_documents function logic
    try:
        claims = get_user_claims()
        if not claims:
            zta_logger.log_event(
                EVENT_TYPES["ACCESS_DENIED"],
                {"reason": "Authentication required", "endpoint": "legacy_documents"},
                request_id=request_id,
            )
            return jsonify({"error": "Authentication required"}), 401

        user_id = claims["sub"]
        user_class = claims["user_class"]
        user_facility = claims.get("facility")
        user_department = claims.get("department")
        auth_method = claims.get("auth_method", "unknown")

        # Log legacy access
        zta_logger.log_event(
            "LEGACY_DOCUMENT_ACCESS",
            {
                "user_class": user_class,
                "auth_method": auth_method,
                "zta_compliance": "partial",
                "missing_layers": ["mTLS", "OPA_policy_check"],
            },
            user_id=user_id,
            request_id=request_id,
        )

        # Simple query for legacy endpoint
        query = GovernmentDocument.query.filter_by(
            facility=user_facility, is_archived=False
        )

        if user_class in ["user", "admin"]:
            query = query.filter_by(department=user_department)

        documents = query.order_by(GovernmentDocument.created_at.desc()).all()

        return (
            jsonify(
                {
                    "documents": [
                        {
                            "id": doc.id,
                            "document_id": doc.document_id,
                            "title": doc.title,
                            "description": doc.description,
                            "classification": doc.classification,
                            "department": doc.department,
                        }
                        for doc in documents
                    ],
                    "legacy_warning": "This endpoint uses JWT only. Migrate to /api/documents for dual authentication support.",
                    "auth_method": auth_method,
                    "zta_context": {
                        "security_level": "reduced",
                        "missing_features": ["mTLS", "OPA_policy_enforcement"],
                        "request_id": request_id,
                    },
                }
            ),
            200,
        )

    except Exception as e:
        zta_logger.log_event(
            "LEGACY_ENDPOINT_ERROR",
            {"error": str(e), "endpoint": "legacy_documents"},
            request_id=request_id,
        )
        return jsonify({"error": "Failed to fetch documents", "message": str(e)}), 500


# Certificate verification logging endpoint
@api_bp.route("/certificate/verify", methods=["POST"])
@require_mtls  # Requires mTLS certificate
def verify_certificate():
    """Endpoint to verify and log certificate details"""
    try:
        request_id = getattr(g, "request_id", str(uuid.uuid4()))

        # Get certificate from g object
        if not hasattr(g, "client_certificate"):
            return jsonify({"error": "No certificate provided"}), 400

        cert_info = g.client_certificate

        # Extract certificate details for logging
        from app.mTLS.cert_manager import cert_manager

        # Get certificate PEM if available
        cert_pem = request.environ.get("SSL_CLIENT_CERT")
        if cert_pem:
            # Use enhanced logging
            is_valid, detailed_info, validation_checks = (
                cert_manager.validate_certificate_with_detailed_logging(
                    cert_pem, request_id, request.remote_addr
                )
            )
        else:
            # Fallback to basic info
            is_valid = True
            detailed_info = cert_info
            validation_checks = {}

        # Log certificate verification details
        zta_logger.log_event(
            "CERTIFICATE_VERIFICATION_DETAILED",
            {
                "certificate_info": detailed_info,
                "validation_checks": validation_checks,
                "is_valid": is_valid,
                "client_ip": request.remote_addr,
                "verification_timestamp": datetime.utcnow().isoformat(),
            },
            request_id=request_id,
        )

        return (
            jsonify(
                {
                    "status": "success",
                    "certificate_valid": is_valid,
                    "certificate_details": detailed_info,
                    "validation_checks": validation_checks,
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
        zta_logger.log_event(
            "CERTIFICATE_VERIFICATION_ERROR",
            {"error": str(e), "client_ip": request.remote_addr},
            request_id=getattr(g, "request_id", str(uuid.uuid4())),
        )
        return (
            jsonify({"error": "Certificate verification failed", "message": str(e)}),
            500,
        )
