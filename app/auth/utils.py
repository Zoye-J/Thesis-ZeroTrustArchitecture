from functools import wraps
from flask import request, jsonify
from flask_jwt_extended import verify_jwt_in_request, get_jwt
from app.logs.request_tracker import log_request


def role_required(required_role):
    """Decorator to check user role"""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                verify_jwt_in_request()
                claims = get_jwt()

                user_id = claims.get("sub")
                user_role = claims.get("user_class")

                # Role hierarchy: superadmin > admin > user
                role_hierarchy = {"superadmin": 3, "admin": 2, "user": 1}

                if role_hierarchy.get(user_role, 0) < role_hierarchy.get(
                    required_role, 0
                ):
                    log_request(
                        user_id=user_id,
                        endpoint=request.path,
                        method=request.method,
                        status="denied",
                        reason=f"Insufficient role. Required: {required_role}, Has: {user_role}",
                    )
                    return (
                        jsonify(
                            {
                                "error": "Forbidden",
                                "message": f"{required_role} role required",
                            }
                        ),
                        403,
                    )

                return f(*args, **kwargs)

            except Exception as e:
                return (
                    jsonify({"error": "Authentication failed", "message": str(e)}),
                    401,
                )

        return decorated_function

    return decorator


def department_required(allowed_departments):
    """Decorator to check user department"""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                verify_jwt_in_request()
                claims = get_jwt()

                user_department = claims.get("department")

                if (
                    user_department not in allowed_departments
                    and "all" not in allowed_departments
                ):
                    log_request(
                        user_id=claims.get("sub"),
                        endpoint=request.path,
                        method=request.method,
                        status="denied",
                        reason=f"Department access denied. Required: {allowed_departments}, Has: {user_department}",
                    )
                    return (
                        jsonify(
                            {
                                "error": "Forbidden",
                                "message": f"Access restricted to departments: {allowed_departments}",
                            }
                        ),
                        403,
                    )

                return f(*args, **kwargs)

            except Exception as e:
                return (
                    jsonify({"error": "Authentication failed", "message": str(e)}),
                    401,
                )

        return decorated_function

    return decorator
