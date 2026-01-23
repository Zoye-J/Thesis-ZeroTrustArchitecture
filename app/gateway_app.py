# gateway_app.py - UPDATED VERSION

"""
Gateway Server Flask App Factory
"""

from flask import Flask, render_template, redirect, url_for
from app import jwt, cors
from app.config import DevelopmentConfig


def create_gateway_app(config_name="development"):
    """Create Flask app for Gateway Server"""
    app = Flask(__name__)

    # Load configuration
    if config_name == "production":
        from app.config import ProductionConfig as ConfigClass
    else:
        ConfigClass = DevelopmentConfig

    app.config.from_object(ConfigClass)

    # ======== ADD THESE CONFIGURATIONS ========
    # Explicitly disable SQLAlchemy for Gateway
    app.config["SQLALCHEMY_DATABASE_URI"] = None
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": False,
        "pool_recycle": -1,
    }
    # ======== END ADDITIONS ========

    # Initialize extensions
    jwt.init_app(app)
    cors.init_app(app)

    # Initialize OPA client
    from app.policy.opa_client import init_opa_client

    init_opa_client(app)

    # Initialize Service Communicator
    try:
        from app.services.service_communicator import init_service_communicator

        init_service_communicator(app)
    except ImportError as e:
        app.logger.warning(f"Service communicator not available: {e}")

    # Register blueprints (routes are in these blueprints)
    from app.auth.routes import auth_bp
    from app.audit.routes import audit_bp
    from app.api.gateway_routes import gateway_bp

    app.register_blueprint(audit_bp)
    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(gateway_bp, url_prefix="/api")

    # Gateway HTML routes (these are fine here since they're simple redirects/render)
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

    return app
