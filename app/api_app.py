# api_app.py - CORRECTED VERSION
"""
API Server Flask App Factory
"""

from flask import Flask, request, jsonify, g
import json
import uuid
from datetime import datetime
from app import cors
from app.config import DevelopmentConfig
from app.api_models import db  # Import from api_models, not from app


def create_api_app(config_name="development"):
    """Create Flask app for API Server"""
    app = Flask(__name__)

    # Load configuration
    if config_name == "production":
        from app.config import ProductionConfig as ConfigClass
    else:
        ConfigClass = DevelopmentConfig

    app.config.from_object(ConfigClass)

    # Initialize extensions
    db.init_app(app)  # This is from api_models
    cors.init_app(app)

    # Register API blueprints
    from app.api.api_routes import api_bp
    from app.auth.routes import auth_bp
    from app.api.registration import registration_bp

    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(registration_bp, url_prefix="/api/register")
    app.register_blueprint(api_bp, url_prefix="/api")

    # ======== ADD HEALTH ENDPOINT ========
    @app.route("/health", methods=["GET"])
    def health():
        """Health check endpoint"""
        return jsonify(
            {
                "status": "healthy",
                "server": "api_server",
                "timestamp": datetime.utcnow().isoformat(),
            }
        )

    # ======== END HEALTH ENDPOINT ========

    # ======== ADD MIDDLEWARE ========
    API_SERVICE_TOKEN = app.config.get("API_SERVICE_TOKEN", "api-token-2024")

    @app.before_request
    def verify_service_token():
        """Middleware to verify service token from Gateway"""
        if request.endpoint == "health":
            return

        service_token = request.headers.get("X-Service-Token")
        if not service_token or service_token != API_SERVICE_TOKEN:
            return (
                jsonify(
                    {
                        "error": "Invalid service token",
                        "zta_context": {"server": "api_server"},
                    }
                ),
                401,
            )

        # Extract user claims from gateway
        user_claims_json = request.headers.get("X-User-Claims")
        if user_claims_json:
            g.user_claims = json.loads(user_claims_json)

        g.request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))

    # ======== END MIDDLEWARE ========

    # Create tables
    with app.app_context():
        db.create_all()
        print("✅ API Server: Database initialized")

    return app


