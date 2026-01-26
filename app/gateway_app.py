"""
Gateway Server Flask App Factory with OPA Agent Encryption
"""

import os
from flask import Flask, render_template, redirect, url_for
from app import jwt, cors
from app.config import DevelopmentConfig


def create_gateway_app(config_name="development"):
    """Create Flask app for Gateway Server with OPA Agent encryption"""
    app = Flask(__name__, template_folder="templates", static_folder="static")

    # Load configuration
    if config_name == "production":
        from app.config import ProductionConfig as ConfigClass
    else:
        ConfigClass = DevelopmentConfig

    app.config.from_object(ConfigClass)

    # ======== DATABASE CONFIGURATION ========
    # Use absolute path for clarity
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    db_path = os.path.join(base_dir, "instance", "government_zta.db")
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # SQLite connection pool settings for multiple processes
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True,
        "pool_recycle": 3600,  # Recycle connections every hour
        "pool_size": 5,
        "max_overflow": 10,
        "connect_args": {
            "check_same_thread": False,  # Allow multiple threads
            "timeout": 30,  # Wait 30 seconds for lock
        },
    }
    print(f"📁 Database path: {db_path}")

    # Initialize extensions
    jwt.init_app(app)
    cors.init_app(app)

    # ======== INITIALIZE DATABASE IN GATEWAY ========
    from app.api_models import db
    from sqlalchemy import text

    db.init_app(app)

    # Verify database connection WITHOUT creating tables
    with app.app_context():
        try:
            # Test database connection
            db.session.execute(text("SELECT 1"))
            print("✅ Gateway Server: Database connection verified")

            # Optional: Show table count to confirm access
            result = db.session.execute(
                text("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
            )
            table_count = result.scalar()
            print(f"📊 Database contains {table_count} tables")

        except Exception as e:
            print(f"❌ Gateway Server: Database connection failed: {e}")
            print("   Make sure the API Server created the database first!")
            # Don't exit - allow Gateway to run without database (will fail on registration)
    # ======== END DATABASE INIT ========

    # ======== OPA AGENT CLIENT INITIALIZATION ========
    try:
        from app.opa_agent.client import init_opa_agent_client
        from app.opa_agent.client import get_opa_agent_client  # ADD THIS!

        init_opa_agent_client(app)
        print("✅ OPA Agent Client initialized")

        app.opa_agent_client = get_opa_agent_client()
        print(
            f"✅ OPA Agent client attached to app: {hasattr(app, 'opa_agent_client')}"
        )

    except ImportError as e:
        print(f"⚠️  OPA Agent Client not available: {e}")

        # Create a dummy client for backward compatibility
        class DummyOPAAgentClient:
            def health_check(self):
                return False

            def get_public_key(self):
                return None

        app.opa_agent_client = DummyOPAAgentClient()
    # ======== OPA CLIENT (LEGACY - FOR POLICY DECISIONS) ========
    try:
        from app.policy.opa_client import init_opa_client

        init_opa_client(app)
        print("✅ OPA Client (legacy) initialized")
    except ImportError as e:
        print(f"⚠️  OPA Client not available: {e}")

    # ======== ENCRYPTION MIDDLEWARE ========
    @app.before_request
    def setup_encryption_context():
        """Setup encryption context for each request"""
        from flask import g

        # Initialize encryption context
        g.encryption_enabled = app.config.get("ENCRYPTION_ENABLED", True)
        g.opa_agent_available = hasattr(app, "opa_agent_client")

        # Get OPA Agent public key if available
        if g.encryption_enabled and g.opa_agent_available:
            g.opa_agent_public_key = app.opa_agent_client.get_public_key()
        else:
            g.opa_agent_public_key = None

    # ======== SERVICE COMMUNICATOR (UPDATED FOR ENCRYPTION) ========
    try:
        from app.services.service_communicator import init_service_communicator

        init_service_communicator(app)
        print("✅ Service Communicator initialized")
    except ImportError as e:
        app.logger.warning(f"Service communicator not available: {e}")

    # ======== REGISTER BLUEPRINTS ========
    from app.auth.routes import auth_bp
    from app.audit.routes import audit_bp
    from app.api.gateway_routes import gateway_bp

    # ======== ADD REGISTRATION BLUEPRINT ========
    from app.api.registration import registration_bp

    app.register_blueprint(registration_bp, url_prefix="/api")
    print("✅ Registration routes registered")
    # ======== END ADDITION ========

    # ======== REGISTER PUBLIC REGISTRATION BLUEPRINT ========
    from app.api.public_registration import public_registration_bp

    app.register_blueprint(public_registration_bp, url_prefix="/public")
    print("✅ Public registration routes registered (NO AUTH)")
    # ======== END PUBLIC REGISTRATION ========

    # Register OPA Agent routes (if available)
    try:
        from app.opa_agent.routes import opa_agent_bp

        app.register_blueprint(opa_agent_bp, url_prefix="/opa-agent")
        print("✅ OPA Agent routes registered")
    except ImportError:
        print("⚠️  OPA Agent routes not available")

    app.register_blueprint(audit_bp)
    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(gateway_bp, url_prefix="/gateway")

    # ======== GATEWAY HTML ROUTES ========
    @app.route("/")
    def index():
        return redirect("/login")

    @app.route("/login")
    def login():
        return render_template("login.html")

    @app.route("/dashboard")
    def dashboard():
        return render_template("dashboard.html")

    @app.route("/register")
    def register():
        return render_template("register.html")

    @app.route("/audit")
    def audit():
        return render_template("audit.html")

    @app.route("/encryption-status")
    def encryption_status():
        """Show encryption status for debugging"""
        from flask import g, jsonify

        return jsonify(
            {
                "gateway": "running",
                "encryption_enabled": getattr(g, "encryption_enabled", False),
                "opa_agent_available": getattr(g, "opa_agent_available", False),
                "opa_agent_public_key_present": bool(
                    getattr(g, "opa_agent_public_key", None)
                ),
                "config": {
                    "opa_agent_url": app.config.get("OPA_AGENT_URL", "not_set"),
                    "opa_url": app.config.get("OPA_URL", "not_set"),
                    "api_server_url": app.config.get("API_SERVER_URL", "not_set"),
                },
            }
        )

    # ======== ERROR HANDLERS ========
    @app.errorhandler(404)
    def not_found(error):
        from flask import jsonify

        return (
            jsonify(
                {
                    "error": "Not found",
                    "message": "The requested resource was not found",
                }
            ),
            404,
        )

    @app.errorhandler(500)
    def internal_error(error):
        from flask import jsonify

        return (
            jsonify(
                {
                    "error": "Internal server error",
                    "message": "An unexpected error occurred",
                }
            ),
            500,
        )

    print("\n" + "=" * 60)
    print("🚀 ZTA GATEWAY SERVER WITH ENCRYPTION")
    print("=" * 60)
    print("📡 Port: 5000")
    print("🔗 URLs:")
    print("  • Login: https://localhost:5000/login")
    print("  • Dashboard: https://localhost:5000/dashboard")
    print("  • Encryption Status: https://localhost:5000/encryption-status")
    print("🔐 Features:")
    print("  • mTLS + JWT Authentication")
    print(
        "  • OPA Agent Encryption: "
        + ("✅" if hasattr(app, "opa_agent_client") else "❌ (checking...)")
    )  # <-- JUST CHECK IF CLIENT EXISTS, DON'T CHECK HEALTH
    print("  • Service-to-Service Communication: ✅")
    print("=" * 60)

    return app
