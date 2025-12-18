import os
from datetime import timedelta


class Config:
    SECRET_KEY = os.environ.get(
        "SECRET_KEY", "government-secure-key-change-in-production-2024"
    )
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///government_zta.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # JWT
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "jwt-government-secure-key-2024")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=8)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)

    # OPA Configuration
    OPA_URL = os.environ.get("OPA_URL", "http://localhost:8181")
    OPA_TIMEOUT = int(os.environ.get("OPA_TIMEOUT", 5))

    # SERVICE COMMUNICATION
    API_SERVER_URL = os.environ.get("API_SERVER_URL", "http://localhost:5000")

    # Service tokens for communication between services
    SERVICE_TOKEN = os.environ.get("SERVICE_TOKEN", "server1-service-token-2024-zta")
    OPA_SERVICE_TOKEN = os.environ.get("OPA_SERVICE_TOKEN", "opa-agent-token-2024-zta")

    # Service roles
    SERVER1_ROLE = "server1"
    OPA_AGENT_ROLE = "opa_agent"
    API_SERVER_ROLE = "api_server"

    # Service communication timeout
    SERVICE_TIMEOUT = int(os.environ.get("SERVICE_TIMEOUT", 10))

    # Service-to-service mTLS settings
    SERVICE_MTLS_ENABLED = (
        os.environ.get("SERVICE_MTLS_ENABLED", "true").lower() == "true"
    )
    SERVICE_CERT_DIR = os.environ.get("SERVICE_CERT_DIR", "./certs/services")

    # Service communication headers
    SERVICE_HEADERS = {
        "X-Service-Role": SERVER1_ROLE,
        "X-Service-Token": SERVICE_TOKEN,
        "X-Request-Source": "server1",
        "Content-Type": "application/json",
    }

    # mTLS Configuration
    SSL_CERT_PATH = os.environ.get("SSL_CERT_PATH", "./certs")
    MTLS_ENABLED = False  # Default to False, enable in production
    CA_CERT_PATH = os.path.join(SSL_CERT_PATH, "ca.crt")
    SERVER_CERT_PATH = os.path.join(SSL_CERT_PATH, "server.crt")
    SERVER_KEY_PATH = os.path.join(SSL_CERT_PATH, "server.key")

    # Security headers for mTLS
    SECURITY_HEADERS = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
    }

    # Logging
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")


class DevelopmentConfig(Config):
    DEBUG = True
    MTLS_ENABLED = False  # Disable mTLS in development for easier testing


class ProductionConfig(Config):
    DEBUG = False
    MTLS_ENABLED = True  # Enable mTLS in production
    JWT_COOKIE_SECURE = True
    JWT_COOKIE_SAMESITE = "Strict"


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    MTLS_ENABLED = False


config_dict = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig,
}
