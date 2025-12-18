from flask import Flask, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_cors import CORS

db = SQLAlchemy()
jwt = JWTManager()
cors = CORS()


def create_app(config_name="default"):
    """Application factory pattern"""
    app = Flask(__name__)

    # Load configuration
    if config_name == "production":
        from app.config import ProductionConfig as ConfigClass
    elif config_name == "development":
        from app.config import DevelopmentConfig as ConfigClass
    else:
        from app.config import Config as ConfigClass

    app.config.from_object(ConfigClass)

    # Initialize extensions
    db.init_app(app)
    jwt.init_app(app)
    cors.init_app(app)

    # Initialize OPA client
    from app.policy.opa_client import init_opa_client

    init_opa_client(app)

    # Register blueprints
    from app.auth.routes import auth_bp
    from app.api.routes import api_bp
    from app.api.registration import registration_bp
    from app.audit.routes import audit_bp

    app.register_blueprint(audit_bp)
    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(registration_bp, url_prefix="/api/register")
    app.register_blueprint(api_bp, url_prefix="/api")

    # Add main routes for HTML pages
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

    @app.route("/documents")
    def documents():
        return render_template("documents.html")

    @app.route("/my_documents")
    def my_documents():
        return render_template("my_documents.html")

    @app.route("/profile")
    def profile():
        return render_template("profile.html")

    @app.route("/admin/users")
    def admin_users():
        return render_template("admin_users.html")

    @app.route("/audit")
    def audit():
        return render_template("audit.html")

    @app.route("/search")
    def search():
        return render_template("search.html")

    return app
