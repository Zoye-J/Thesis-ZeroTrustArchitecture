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

    # JWT (Only for Gateway Server)
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "jwt-government-secure-key-2024")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=8)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)

    # ============ DISTRIBUTED SERVER PORTS ============
    API_SERVER_PORT = int(os.environ.get("API_SERVER_PORT", 5001))
    GATEWAY_SERVER_PORT = int(os.environ.get("GATEWAY_SERVER_PORT", 8443))
    OPA_SERVER_PORT = int(os.environ.get("OPA_SERVER_PORT", 8181))

    # ============ SERVICE COMMUNICATION URLs ============
    OPA_SERVER_URL = os.environ.get("OPA_SERVER_URL", "http://localhost:8181")
    API_SERVER_URL = os.environ.get("API_SERVER_URL", "http://localhost:5001")
    GATEWAY_SERVER_URL = os.environ.get("GATEWAY_SERVER_URL", "https://localhost:8443")

    # Timeouts
    OPA_TIMEOUT = int(os.environ.get("OPA_TIMEOUT", 5))
    SERVICE_TIMEOUT = int(os.environ.get("SERVICE_TIMEOUT", 10))

    # ============ SERVICE TOKENS ============
    SERVICE_TOKENS = {
        "gateway": os.environ.get("GATEWAY_SERVICE_TOKEN", "gateway-token-2024-zta"),
        "api": os.environ.get("API_SERVICE_TOKEN", "api-token-2024-zta"),
        "opa": os.environ.get("OPA_SERVICE_TOKEN", "opa-token-2024-zta"),
    }

    # Individual token access (for convenience)
    GATEWAY_SERVICE_TOKEN = SERVICE_TOKENS["gateway"]
    API_SERVICE_TOKEN = SERVICE_TOKENS["api"]
    OPA_SERVICE_TOKEN = SERVICE_TOKENS["opa"]

    # ============ SERVICE COMMUNICATION SETTINGS ============
    SERVICE_MTLS_ENABLED = (
        os.environ.get("SERVICE_MTLS_ENABLED", "false").lower() == "true"
    )
    SERVICE_CERT_DIR = os.environ.get("SERVICE_CERT_DIR", "./certs/services")

    # Retry settings for service communication
    SERVICE_RETRY_ATTEMPTS = int(os.environ.get("SERVICE_RETRY_ATTEMPTS", 3))
    SERVICE_RETRY_DELAY = int(os.environ.get("SERVICE_RETRY_DELAY", 1))

    # ============ mTLS CONFIGURATION (For Gateway) ============
    SSL_CERT_PATH = os.environ.get("SSL_CERT_PATH", "./certs")
    MTLS_ENABLED = False  # Default to False, enable in production
    CA_CERT_PATH = os.path.join(SSL_CERT_PATH, "ca.crt")
    SERVER_CERT_PATH = os.path.join(SSL_CERT_PATH, "server.crt")
    SERVER_KEY_PATH = os.path.join(SSL_CERT_PATH, "server.key")

    # ============ SECURITY HEADERS ============
    SECURITY_HEADERS = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
    }

    # ============ LOGGING ============
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
    LOG_FORMAT = os.environ.get(
        "LOG_FORMAT",
        "%(asctime)s - %(name)s - %(levelname)s - [%(server)s] - %(message)s",
    )

    # ============ DISTRIBUTED TRACING ============
    TRACING_ENABLED = os.environ.get("TRACING_ENABLED", "true").lower() == "true"
    TRACE_HEADER_NAME = os.environ.get("TRACE_HEADER_NAME", "X-Request-ID")

    # ============ HEALTH CHECK SETTINGS ============
    HEALTH_CHECK_INTERVAL = int(os.environ.get("HEALTH_CHECK_INTERVAL", 30))
    HEALTH_CHECK_TIMEOUT = int(os.environ.get("HEALTH_CHECK_TIMEOUT", 5))

    # ============ RATE LIMITING (Gateway Only) ============
    RATE_LIMIT_ENABLED = os.environ.get("RATE_LIMIT_ENABLED", "false").lower() == "true"
    RATE_LIMIT_REQUESTS = int(os.environ.get("RATE_LIMIT_REQUESTS", 100))
    RATE_LIMIT_PERIOD = int(os.environ.get("RATE_LIMIT_PERIOD", 60))  # seconds


class DevelopmentConfig(Config):
    DEBUG = True
    MTLS_ENABLED = False  # Disable mTLS in development for easier testing
    LOG_LEVEL = "DEBUG"
    TRACING_ENABLED = True


class ProductionConfig(Config):
    DEBUG = False
    MTLS_ENABLED = True  # Enable mTLS in production
    JWT_COOKIE_SECURE = True
    JWT_COOKIE_SAMESITE = "Strict"
    LOG_LEVEL = "WARNING"
    SERVICE_MTLS_ENABLED = True  # Enable mTLS between services in production
    RATE_LIMIT_ENABLED = True


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    MTLS_ENABLED = False
    SERVICE_MTLS_ENABLED = False
    LOG_LEVEL = "DEBUG"


config_dict = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig,
}
