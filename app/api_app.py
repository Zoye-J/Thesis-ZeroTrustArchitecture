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
from app.api_models import db
from app.models.user import GovernmentDocument


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
    # Enable CORS
    cors.init_app(app, origins=["https://localhost:5000", "http://localhost:5000"])

    # Handle OPTIONS requests
    @app.after_request
    def after_request(response):
        response.headers.add("Access-Control-Allow-Origin", "https://localhost:5000")
        response.headers.add(
            "Access-Control-Allow-Headers",
            "Content-Type, X-Service-Token, X-Request-ID, Authorization",
        )
        response.headers.add(
            "Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS"
        )
        response.headers.add("Access-Control-Allow-Credentials", "true")
        return response

    # Register API blueprints
    from app.api.api_routes import api_bp
    from app.auth.routes import auth_bp
    from app.api.registration import registration_bp

    # ======== ADD RESOURCES ENDPOINT ========
    @api_bp.route("/resources", methods=["GET"])
    def get_resources_api():
        """Get resources from database for API calls"""
        try:
            user_claims = g.get("user_claims", {})
            if not user_claims:
                return jsonify({"error": "User claims required"}), 400

            user_department = user_claims.get("department")
            user_clearance = user_claims.get("clearance_level", "BASIC")
            current_hour = datetime.now().hour

            # Get all non-archived documents
            documents = GovernmentDocument.query.filter_by(is_archived=False).all()

            # Map database classifications to tier names
            classification_map = {
                "PUBLIC": "PUBLIC",
                "DEPARTMENT": "DEPARTMENT",
                "TOP_SECRET": "TOP_SECRET",
                "CONFIDENTIAL": "DEPARTMENT",  # If you have this
                "SECRET": "DEPARTMENT",  # If you have this
            }

            # Filter resources based on department and clearance
            filtered_resources = []
            for doc in documents:
                tier = classification_map.get(doc.classification, "PUBLIC")

                # Apply access rules
                if tier == "PUBLIC":
                    filtered_resources.append(
                        {
                            "id": doc.id,
                            "name": doc.title,
                            "tier": "PUBLIC",
                            "department": doc.department,
                            "description": doc.description,
                        }
                    )
                elif tier == "DEPARTMENT" and doc.department == user_department:
                    filtered_resources.append(
                        {
                            "id": doc.id,
                            "name": doc.title,
                            "tier": "DEPARTMENT",
                            "department": doc.department,
                            "description": doc.description,
                        }
                    )
                elif tier == "TOP_SECRET" and doc.department == user_department:
                    # Check clearance and time
                    if user_clearance in ["SECRET", "TOP_SECRET"]:
                        if 8 <= current_hour < 16:
                            filtered_resources.append(
                                {
                                    "id": doc.id,
                                    "name": doc.title,
                                    "tier": "TOP_SECRET",
                                    "department": doc.department,
                                    "description": doc.description,
                                }
                            )
                        else:
                            # Show as restricted
                            filtered_resources.append(
                                {
                                    "id": doc.id,
                                    "name": f"🔒 {doc.title} (Available 8 AM - 4 PM)",
                                    "tier": "TOP_SECRET",
                                    "department": doc.department,
                                    "restricted": True,
                                }
                            )

            return jsonify(
                {
                    "resources": filtered_resources,
                    "user_info": {
                        "department": user_department,
                        "clearance": user_clearance,
                        "current_hour": current_hour,
                    },
                    "zta_context": {
                        "server": "api_server",
                        "request_id": g.get("request_id", "unknown"),
                    },
                }
            )

        except Exception as e:
            return (
                jsonify({"error": "Failed to fetch resources", "message": str(e)}),
                500,
            )

    # ======== END RESOURCES ENDPOINT ========

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
    API_SERVICE_TOKEN = app.config.get("API_SERVICE_TOKEN", "api-token-2024-zta")

    @app.before_request
    def verify_service_token():
        """Middleware to verify service token from Gateway"""
        # Allow CORS preflight OPTIONS requests
        if request.method == "OPTIONS":
            return

        # Allow health endpoint
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
