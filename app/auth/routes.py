# app/auth/routes.py - COMPLETE FIXED VERSION
from flask import Blueprint, request, jsonify, render_template, current_app
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    get_jwt,
)
from app import jwt
from app.api_models import db, User
import uuid
import requests
from datetime import datetime, timedelta
import traceback


try:
    # Try to import for API Server
    from app.api_models import User
    from app.logs.request_logger import log_request
    from app.logs.zta_event_logger import zta_logger, EVENT_TYPES

    HAS_DB_ACCESS = True
    print("✅ Auth routes: Running in API Server mode (DB access enabled)")
except ImportError:
    # Gateway Server - no DB access
    HAS_DB_ACCESS = False
    User = None

    # Create dummy logger functions for Gateway
    def log_request(*args, **kwargs):
        pass

    class DummyZTALogger:
        def log_event(self, event_type, details=None, user_id=None, request_id=None):
            print(f"[ZTA Log] {event_type}: {details}")

    zta_logger = DummyZTALogger()
    EVENT_TYPES = {
        "JWT_TOKEN_ISSUED": "JWT_TOKEN_ISSUED",
        "LOGIN_ATTEMPT": "LOGIN_ATTEMPT",
        "TOKEN_REFRESH_ATTEMPT": "TOKEN_REFRESH_ATTEMPT",
    }
    print("✅ Auth routes: Running in Gateway Server mode (API calls only)")

auth_bp = Blueprint("auth", __name__)


# ============ HELPER FUNCTIONS ============
def create_jwt_tokens(user_data, user_id):
    """Create JWT tokens for authenticated user"""
    additional_claims = {
        "username": user_data.get("username"),
        "user_class": user_data.get("user_class"),
        "department": user_data.get("department"),
        "facility": user_data.get("facility"),
        "clearance_level": user_data.get("clearance_level"),
        "is_superadmin": user_data.get("user_class") == "superadmin",
        "is_admin": user_data.get("user_class") in ["admin", "superadmin"],
    }

    access_token = create_access_token(
        identity=user_id,
        additional_claims=additional_claims,
        expires_delta=timedelta(hours=8),
    )

    refresh_token = create_refresh_token(
        identity=user_id, additional_claims=additional_claims
    )

    return access_token, refresh_token, additional_claims


# ============ ROUTES ============
@auth_bp.route("/")
def home():
    """Handle root route - check if it's an API call or web request"""
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

        if not data:
            return jsonify({"error": "No data provided"}), 400

        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400

        # Log login attempt
        zta_logger.log_event(
            "LOGIN_ATTEMPT",
            {
                "username": username,
                "source_ip": request.remote_addr,
                "user_agent": (
                    request.user_agent.string[:200] if request.user_agent else None
                ),
            },
            request_id=request_id,
        )

        # ======== CHECK SERVER MODE ========
        if HAS_DB_ACCESS:
            # API Server mode - direct DB access
            return handle_login_api_mode(username, password, request_id)
        else:
            # Gateway mode - call API Server
            return handle_login_gateway_mode(username, password, request_id)

    except Exception as e:
        error_traceback = traceback.format_exc()
        print(f"Login error: {e}")

        zta_logger.log_event(
            "LOGIN_ERROR",
            {
                "error": str(e),
                "traceback": error_traceback[-500:] if error_traceback else None,
            },
            request_id=request_id,
        )

        return jsonify({"error": "Login failed", "message": str(e)}), 500


def handle_login_api_mode(username, password, request_id):
    """API Server login - direct DB access"""
    # Find user in database
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
    access_token, refresh_token, additional_claims = create_jwt_tokens(
        user.to_dict(), user.id
    )

    # Log successful login
    zta_logger.log_event(
        EVENT_TYPES["JWT_TOKEN_ISSUED"],
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


def handle_login_gateway_mode(username, password, request_id):
    """Gateway Server login - calls API Server"""
    api_server_url = current_app.config.get("API_SERVER_URL", "http://localhost:5001")

    try:
        # Call API Server's login endpoint
        response = requests.post(
            f"{api_server_url}/api/auth/login",
            json={"username": username, "password": password},
            headers={"Content-Type": "application/json", "X-Request-ID": request_id},
            timeout=5,
        )

        # Return the API Server's response directly
        return jsonify(response.json()), response.status_code

    except requests.exceptions.RequestException as e:
        print(f"API Server connection error: {e}")
        return (
            jsonify(
                {
                    "error": "Authentication service unavailable",
                    "message": "Cannot connect to API server",
                }
            ),
            503,
        )


# Token refresh
@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    try:
        current_user_id = get_jwt_identity()
        request_id = str(uuid.uuid4())

        # Log token refresh attempt
        zta_logger.log_event(
            "TOKEN_REFRESH_ATTEMPT",
            {
                "user_id": current_user_id,
                "source_ip": request.remote_addr,
            },
            user_id=current_user_id,
            request_id=request_id,
        )

        if HAS_DB_ACCESS:
            # API Server mode
            user = User.query.get(current_user_id)

            if not user or not user.is_active:
                return jsonify({"error": "User not found or inactive"}), 401

            user_data = user.to_dict()
        else:
            # Gateway mode - call API Server
            api_server_url = current_app.config.get(
                "API_SERVER_URL", "http://localhost:5001"
            )

            try:
                response = requests.post(
                    f"{api_server_url}/api/auth/refresh",
                    headers={
                        "Authorization": request.headers.get("Authorization", ""),
                        "Content-Type": "application/json",
                        "X-Request-ID": request_id,
                    },
                    timeout=5,
                )

                # Return API Server's response
                return jsonify(response.json()), response.status_code

            except requests.exceptions.RequestException as e:
                return jsonify({"error": "Token refresh service unavailable"}), 503

        # Create new access token
        access_token, _, additional_claims = create_jwt_tokens(
            user_data, current_user_id
        )

        # Log successful refresh
        zta_logger.log_event(
            EVENT_TYPES["JWT_TOKEN_ISSUED"],
            {
                "user_id": current_user_id,
                "action": "token_refresh",
                "new_expiry": (datetime.utcnow() + timedelta(hours=8)).isoformat(),
            },
            user_id=current_user_id,
            request_id=request_id,
        )

        return jsonify({"access_token": access_token}), 200

    except Exception as e:
        return jsonify({"error": "Token refresh failed", "message": str(e)}), 500


# Get current user info
@auth_bp.route("/me", methods=["GET"])
@jwt_required(optional=True)
def get_current_user():
    """Get current user info - returns JSON"""
    current_user_id = get_jwt_identity()

    if not current_user_id:
        return jsonify({"authenticated": False}), 200

    if HAS_DB_ACCESS:
        # API Server mode
        user = User.query.get(current_user_id)
        if not user:
            return jsonify({"authenticated": False}), 200

        return jsonify({"authenticated": True, "user": user.to_dict()}), 200
    else:
        # Gateway mode - call API Server
        api_server_url = current_app.config.get(
            "API_SERVER_URL", "http://localhost:5001"
        )

        try:
            response = requests.get(
                f"{api_server_url}/api/auth/me",
                headers={
                    "Authorization": request.headers.get("Authorization", ""),
                    "Content-Type": "application/json",
                },
                timeout=5,
            )

            if response.status_code == 200:
                return jsonify(response.json()), 200
            else:
                return jsonify({"authenticated": False}), 200

        except requests.exceptions.RequestException:
            return jsonify({"authenticated": False}), 200


# Logout - client-side only
@auth_bp.route("/logout", methods=["POST"])
def logout():
    return jsonify({"message": "Logout successful (client should remove token)"}), 200


# HTML Pages (these work in both modes)
@auth_bp.route("/register", methods=["GET"])
def register_page():
    return render_template("register.html")


@auth_bp.route("/documents", methods=["GET"])
@jwt_required()
def documents_page():
    # This route needs to be handled by gateway_routes.py for Gateway
    # For API Server, we should redirect or handle differently
    if HAS_DB_ACCESS:
        # API Server shouldn't serve HTML pages
        return jsonify({"error": "Use Gateway server for web interface"}), 400
    else:
        # Gateway will handle this via templates
        current_user_id = get_jwt_identity()
        return render_template("documents.html")


@auth_bp.route("/users", methods=["GET"])
@jwt_required()
def users_list_page():
    if HAS_DB_ACCESS:
        return jsonify({"error": "Use Gateway server for web interface"}), 400
    else:
        # Check admin privileges
        claims = get_jwt()
        if not claims.get("is_admin"):
            return jsonify({"error": "Admin access required"}), 403
        return render_template("users_list.html")


@auth_bp.route("/register-user", methods=["GET"])
@jwt_required()
def register_user_page():
    if HAS_DB_ACCESS:
        return jsonify({"error": "Use Gateway server for web interface"}), 400
    else:
        # Check admin privileges
        claims = get_jwt()
        if not claims.get("is_admin"):
            return jsonify({"error": "Admin access required"}), 403
        return render_template("register_user.html")


@auth_bp.route("/dashboard", methods=["GET"])
@jwt_required()
def dashboard_page():
    if HAS_DB_ACCESS:
        return jsonify({"error": "Use Gateway server for web interface"}), 400
    else:
        return render_template("dashboard.html")


@auth_bp.route("/audit", methods=["GET"])
@jwt_required()
def audit_page():
    if HAS_DB_ACCESS:
        return jsonify({"error": "Use Gateway server for web interface"}), 400
    else:
        # Check admin privileges
        claims = get_jwt()
        if not claims.get("is_admin"):
            return jsonify({"error": "Admin access required"}), 403
        return render_template("audit.html")
