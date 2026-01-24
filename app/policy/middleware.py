"""
Policy evaluation middleware for Flask
"""

from functools import wraps
from flask import request, jsonify, g
from flask_jwt_extended import verify_jwt_in_request, get_jwt
from app.policy.opa_client import get_opa_client
from app.logs.request_tracker import log_request
import uuid
from datetime import datetime


def policy_protected(resource_type, action):
    """
    Decorator to protect routes with OPA policy evaluation

    Args:
        resource_type: Type of resource ('document', 'user', 'audit')
        action: Action being performed ('read', 'write', 'delete', 'create')
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Verify JWT
                verify_jwt_in_request()
                claims = get_jwt()

                # Generate request ID for tracing
                request_id = str(uuid.uuid4())[:8]
                g.request_id = request_id

                # Get OPA client
                opa_client = get_opa_client()

                # Get resource from route parameters or request body
                resource = get_resource_from_request(resource_type, kwargs, request)

                if not resource:
                    return (
                        jsonify(
                            {"error": "Resource not found", "request_id": request_id}
                        ),
                        404,
                    )

                # Evaluate policy
                if resource_type == "document":
                    allowed, reason, decision_id = opa_client.evaluate_document_access(
                        claims, resource, action
                    )
                elif resource_type == "user":
                    allowed, reason, decision_id = opa_client.evaluate_user_management(
                        claims, resource, action
                    )
                else:
                    # Generic policy evaluation
                    input_data = {
                        "user": {
                            "id": claims.get("sub"),
                            "role": claims.get("user_class"),
                            "department": claims.get("department"),
                            "facility": claims.get("facility"),
                            "clearance": claims.get("clearance_level", "BASIC"),
                        },
                        "resource": {
                            "type": resource_type,
                            "id": resource.get("id"),
                            **resource,
                        },
                        "action": action,
                        "environment": {
                            "time": {"hour": datetime.now().hour},
                            "ip_address": request.remote_addr,
                            "user_agent": (
                                request.user_agent.string
                                if request.user_agent
                                else None
                            ),
                        },
                        "request_id": request_id,
                    }

                    allowed, reason, decision_id = opa_client.evaluate_policy(
                        input_data
                    )

                # Log the policy decision
                log_request(
                    user_id=claims.get("sub"),
                    endpoint=request.path,
                    method=request.method,
                    status="allowed" if allowed else "denied",
                    reason=f"OPA Decision [{decision_id}]: {reason}",
                    policy_evaluated=True,
                    decision_id=decision_id,
                    request_id=request_id,
                )

                if not allowed:
                    return (
                        jsonify(
                            {
                                "error": "Access denied",
                                "reason": reason,
                                "decision_id": decision_id,
                                "request_id": request_id,
                            }
                        ),
                        403,
                    )

                # Store policy decision in Flask g for later use
                g.policy_decision = {
                    "allowed": allowed,
                    "reason": reason,
                    "decision_id": decision_id,
                    "request_id": request_id,
                }

                return f(*args, **kwargs)

            except Exception as e:
                return (
                    jsonify(
                        {
                            "error": "Policy evaluation failed",
                            "message": str(e),
                            "request_id": g.get("request_id", "unknown"),
                        }
                    ),
                    500,
                )

        return decorated_function

    return decorator


def get_resource_from_request(resource_type, route_kwargs, request):
    """
    Extract resource information from request
    """
    if resource_type == "document":
        # For document operations, we might need to fetch from database
        # This is a simplified version
        document_id = route_kwargs.get("document_id")
        if document_id:
            return {"id": document_id, "type": "document"}

        # For document creation, resource is in request body
        if request.method == "POST":
            data = request.get_json() or {}
            return {
                "type": "document",
                "classification": data.get("classification", "BASIC"),
                "department": data.get("department"),
                "facility": data.get("facility"),
            }

    elif resource_type == "user":
        user_id = route_kwargs.get("user_id")
        if user_id:
            return {"id": user_id, "type": "user"}

        if request.method == "POST":
            data = request.get_json() or {}
            return {
                "type": "user",
                "role": data.get("user_class", "user"),
                "department": data.get("department"),
                "facility": data.get("facility"),
            }

    return None


def require_policy(policy_name):
    """
    Require specific policy to be satisfied
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Similar to policy_protected but for named policies
            pass

        return decorated_function

    return decorator
