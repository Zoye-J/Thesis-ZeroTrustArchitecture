from flask import Blueprint, request, jsonify, render_template
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    get_jwt,
)
from app import db
from app.models.user import User, AccessLog
from app.logs.request_logger import log_request
from datetime import datetime, timedelta
from app.logs.zta_event_logger import zta_logger, EVENT_TYPES
import uuid

auth_bp = Blueprint("auth", __name__)


# Home/Landing page
@auth_bp.route("/")
def home():
    """Handle root route - check if it's an API call or web request"""
    # Check if this is an API call (has Accept header for JSON)
    if request.headers.get("Accept", "").lower().find("application/json") >= 0:
        return jsonify(
            {
                "system": "ZTA Government Document System",
                "version": "1.0",
                "endpoints": {
                    "auth": "/api/auth/login",
                    "documents": "/api/documents",
                    "health": "/api/service/health",
                },
            }
        )

    # Web browser request - serve login page
    return render_template("login.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Handle both login page (GET) and login API (POST)"""
    if request.method == "GET":
        return render_template("login.html")

    # POST method - handle login API
    try:
        data = request.get_json()
        request_id = str(uuid.uuid4())
        zta_logger.log_event(
            "LOGIN_ATTEMPT",
            {
                "username": data.get("username"),
                "source_ip": request.remote_addr,
                "user_agent": (
                    request.user_agent.string[:200] if request.user_agent else None
                ),
            },
            request_id=request_id,
        )

        if not data:
            return jsonify({"error": "No data provided"}), 400

        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400

        # Find user
        user = User.query.filter_by(username=username).first()

        if not user:
            log_request(
                user_id=None,
                endpoint="/login",
                method="POST",
                status="denied",
                reason="User not found",
                request_id=request_id,
            )
            return jsonify({"error": "Invalid credentials"}), 401

        if not user.is_active:
            log_request(
                user_id=user.id,
                endpoint="/login",
                method="POST",
                status="denied",
                reason="User account inactive",
                request_id=request_id,
            )
            return jsonify({"error": "Account is inactive"}), 401

        # Check password
        if not user.check_password(password):
            log_request(
                user_id=user.id,
                endpoint="/login",
                method="POST",
                status="denied",
                reason="Invalid password",
                request_id=request_id,
            )
            return jsonify({"error": "Invalid credentials"}), 401

        # Create JWT tokens
        additional_claims = {
            "username": user.username,
            "user_class": user.user_class,
            "department": user.department,
            "facility": user.facility,
            "clearance_level": user.clearance_level,
            "is_superadmin": user.user_class == "superadmin",
            "is_admin": user.user_class in ["admin", "superadmin"],
        }

        access_token = create_access_token(
            identity=user.id,
            additional_claims=additional_claims,
            expires_delta=timedelta(hours=8),  # CHANGED HERE
        )

        refresh_token = create_refresh_token(
            identity=user.id, additional_claims=additional_claims
        )

        # Log JWT token creation/validation
        zta_logger.log_event(
            EVENT_TYPES["JWT_TOKEN_ISSUED"],
            {
                "user_id": user.id,
                "username": user.username,
                "token_claims": additional_claims,
                "auth_method": "password",
                "token_expires": (
                    datetime.utcnow() + timedelta(hours=8)  # CHANGED HERE
                ).isoformat(),
            },
            user_id=user.id,
            request_id=request_id,
        )

        # Log successful login
        log_request(
            user_id=user.id,
            endpoint="/login",
            method="POST",
            status="allowed",
            reason="Authentication successful",
            request_id=request_id,
        )

        return (
            jsonify(
                {
                    "message": "Login successful",
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "user": user.to_dict(),
                }
            ),
            200,
        )

    except Exception as e:
        # Log the actual error for debugging
        import traceback

        error_traceback = traceback.format_exc()
        print(f"Login error: {e}")
        print(f"Traceback: {error_traceback}")

        # Log the error
        zta_logger.log_event(
            "LOGIN_ERROR",
            {
                "error": str(e),
                "traceback": error_traceback[-500:] if error_traceback else None,
            },
            request_id=getattr(locals(), "request_id", str(uuid.uuid4())),
        )

        return jsonify({"error": "Login failed", "message": str(e)}), 500


# Login API (POST)
@auth_bp.route("/login", methods=["POST"])
def login_api():
    try:
        data = request.get_json()
        request_id = str(uuid.uuid4())
        zta_logger.log_event(
            "LOGIN_ATTEMPT",
            {
                "username": data.get("username"),
                "source_ip": request.remote_addr,
                "user_agent": (
                    request.user_agent.string[:200] if request.user_agent else None
                ),
            },
            request_id=request_id,
        )

        if not data:
            return jsonify({"error": "No data provided"}), 400

        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400

        # Find user
        user = User.query.filter_by(username=username).first()

        if not user:
            log_request(
                user_id=None,
                endpoint="/login",
                method="POST",
                status="denied",
                reason="User not found",
            )
            return jsonify({"error": "Invalid credentials"}), 401

        if not user.is_active:
            log_request(
                user_id=user.id,
                endpoint="/login",
                method="POST",
                status="denied",
                reason="User account inactive",
            )
            return jsonify({"error": "Account is inactive"}), 401

        # Check password
        if not user.check_password(password):
            log_request(
                user_id=user.id,
                endpoint="/login",
                method="POST",
                status="denied",
                reason="Invalid password",
            )
            return jsonify({"error": "Invalid credentials"}), 401

        # Create JWT tokens
        additional_claims = {
            "username": user.username,
            "user_class": user.user_class,
            "department": user.department,
            "facility": user.facility,
            "clearance_level": user.clearance_level,
            "is_superadmin": user.user_class == "superadmin",
            "is_admin": user.user_class in ["admin", "superadmin"],
        }

        access_token = create_access_token(
            identity=user.id,
            additional_claims=additional_claims,
            expires_delta=datetime.timedelta(hours=8),
        )

        refresh_token = create_refresh_token(
            identity=user.id, additional_claims=additional_claims
        )

        # Log JWT token creation/validation
        zta_logger.log_event(
            EVENT_TYPES["JWT_TOKEN_ISSUED"],  # Changed from JWT_TOKEN_VALIDATED
            {
                "user_id": user.id,
                "username": user.username,
                "token_claims": additional_claims,
                "auth_method": "password",
                "token_expires": (datetime.utcnow() + timedelta(hours=8)).isoformat(),
            },
            user_id=user.id,
            request_id=request_id,
        )
        # Log successful login
        log_request(
            user_id=user.id,
            endpoint="/login",
            method="POST",
            status="allowed",
            reason="Authentication successful",
        )

        return (
            jsonify(
                {
                    "message": "Login successful",
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "user": user.to_dict(),
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": "Login failed", "message": str(e)}), 500


# Token refresh
@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        if not user or not user.is_active:
            return jsonify({"error": "User not found or inactive"}), 401

        # Log token refresh attempt
        zta_logger.log_event(
            "TOKEN_REFRESH_ATTEMPT",
            {
                "user_id": current_user_id,
                "source_ip": request.remote_addr,
            },
            user_id=current_user_id,
            request_id=str(uuid.uuid4()),
        )

        additional_claims = {
            "username": user.username,
            "user_class": user.user_class,
            "department": user.department,
            "facility": user.facility,
            "clearance_level": user.clearance_level,
            "is_superadmin": user.user_class == "superadmin",
            "is_admin": user.user_class in ["admin", "superadmin"],
        }

        new_access_token = create_access_token(
            identity=current_user_id, additional_claims=additional_claims
        )

        # Log successful refresh
        zta_logger.log_event(
            EVENT_TYPES["JWT_TOKEN_ISSUED"],
            {
                "user_id": current_user_id,
                "action": "token_refresh",
                "new_expiry": (
                    datetime.utcnow() + datetime.timedelta(hours=8)
                ).isoformat(),
            },
            user_id=current_user_id,
            request_id=str(uuid.uuid4()),
        )

        return jsonify({"access_token": new_access_token}), 200

    except Exception as e:
        return jsonify({"error": "Token refresh failed", "message": str(e)}), 500


# Logout - client-side only (just remove token)
@auth_bp.route("/logout", methods=["POST"])
def logout():
    return jsonify({"message": "Logout successful (client should remove token)"}), 200


# Get current user info
@auth_bp.route("/me", methods=["GET"])
@jwt_required(optional=True)
def get_current_user():
    """Get current user info - returns JSON"""
    current_user_id = get_jwt_identity()

    if not current_user_id:
        return jsonify({"authenticated": False}), 200

    user = User.query.get(current_user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"authenticated": True, "user": user.to_dict()}), 200


# Simple registration page
@auth_bp.route("/register", methods=["GET"])
def register_page():
    return render_template("register.html")


# Other routes (documents, users, etc.) - update to use JWT instead of sessions
@auth_bp.route("/documents", methods=["GET"])
@jwt_required()
def documents_page():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    return render_template("documents.html")


@auth_bp.route("/users", methods=["GET"])
@jwt_required()
def users_list_page():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    # Check admin privileges in JWT claims
    claims = get_jwt()
    if not claims.get("is_admin"):
        return jsonify({"error": "Admin access required"}), 403

    return render_template("users_list.html")


@auth_bp.route("/register-user", methods=["GET"])
@jwt_required()
def register_user_page():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    # Check admin privileges
    claims = get_jwt()
    if not claims.get("is_admin"):
        return jsonify({"error": "Admin access required"}), 403

    return render_template("register_user.html")


# Handle direct root access
@auth_bp.route("/", methods=["GET"])
def root_redirect():
    """Handle root URL access - redirect to login"""
    return render_template("login.html")


# Login event logging endpoint (optional)
@auth_bp.route("/login-event", methods=["POST"])
@jwt_required()
def log_login_event():
    """Log login event to ZTA dashboard"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        if not user:
            return jsonify({"error": "User not found"}), 404

        data = request.get_json()

        # Log to ZTA events
        from app.logs.zta_event_logger import zta_logger, EVENT_TYPES
        import uuid

        zta_logger.log_event(
            EVENT_TYPES["JWT_TOKEN_VALIDATED"],
            {
                "user_id": user.id,
                "username": user.username,
                "login_method": "password",
                "timestamp": (
                    data.get("timestamp")
                    if data
                    else datetime.datetime.utcnow().isoformat()
                ),
                "action": "user_login",
            },
            user_id=user.id,
            request_id=str(uuid.uuid4()),
        )

        return jsonify({"success": True, "message": "Login logged"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
