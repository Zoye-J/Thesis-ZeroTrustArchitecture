"""
ZTA Gateway Server - Handles client authentication (mTLS + JWT)
Forwards authorized requests to API server
UPDATED: Uses real service communicator
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify, g
import uuid
from datetime import datetime

from app.gateway_app import create_gateway_app

app = create_gateway_app()

if __name__ == "__main__":
    print("=" * 60)
    print("ZTA GATEWAY SERVER")
    print("=" * 60)
    print("Port: 5000")
    print("Authentication: mTLS + JWT")
    print("=" * 60)

    app.run(debug=True, port=5000, ssl_context=("certs/server.crt", "certs/server.key"))
# Import real service communicator
from app.services.service_communicator import process_gateway_request


@app.before_request
def generate_request_id():
    """Generate request ID for all requests"""
    g.request_id = str(uuid.uuid4())


# Gateway proxy endpoint - uses REAL service communicator
@app.route("/api/<path:subpath>", methods=["GET", "POST", "PUT", "DELETE"])
def gateway_proxy(subpath):
    """
    Gateway endpoint - authenticates client and forwards to API server
    Uses REAL service communicator for distributed flow
    """
    try:
        # Authenticate client (using middleware decorators)
        # The authentication will be handled by require_authentication decorator
        # on individual endpoints in app/api/gateway_routes.py

        # For now, we'll handle authentication directly here
        from app.mTLS.middleware import (
            extract_client_certificate,
            require_authentication,
        )
        from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity

        user_claims = None

        # Try JWT first
        try:
            verify_jwt_in_request(optional=True)
            user_id = get_jwt_identity()
            if user_id:
                from app.models.user import User

                user = User.query.get(user_id)
                if user:
                    user_claims = {
                        "sub": user.id,
                        "username": user.username,
                        "email": user.email,
                        "user_class": user.user_class,
                        "facility": user.facility,
                        "department": user.department,
                        "clearance_level": user.clearance_level,
                        "auth_method": "JWT",
                    }
                    g.auth_method = "jwt"
                    g.jwt_identity = user_id
        except:
            pass

        # Try mTLS if JWT failed
        if not user_claims:
            cert_pem = extract_client_certificate()
            if cert_pem:
                from app.mTLS.cert_manager import cert_manager

                is_valid, cert_info = cert_manager.validate_certificate(cert_pem)
                if is_valid:
                    # Find user by certificate
                    from app.models.user import User

                    fingerprint = cert_info.get("fingerprint")
                    if fingerprint:
                        user = User.find_by_certificate_fingerprint(fingerprint)
                        if user:
                            user_claims = {
                                "sub": user.id,
                                "username": user.username,
                                "email": user.email,
                                "user_class": user.user_class,
                                "facility": user.facility,
                                "department": user.department,
                                "clearance_level": user.clearance_level,
                                "auth_method": "mTLS",
                            }
                            g.auth_method = "mtls"
                            g.client_certificate = cert_info

        if not user_claims:
            return jsonify({"error": "Authentication required"}), 401

        # Use REAL service communicator to process request
        return process_gateway_request(request, user_claims)

    except Exception as e:
        return (
            jsonify(
                {
                    "error": "Gateway processing failed",
                    "message": str(e),
                    "zta_context": {"server": "gateway"},
                }
            ),
            500,
        )


# Keep some direct endpoints for testing
@app.route("/api/zta-test", methods=["GET"])
def zta_test():
    """Simple test endpoint"""
    return jsonify(
        {
            "status": "success",
            "message": "Gateway server is running",
            "server": "gateway",
        }
    )


@app.route("/health", methods=["GET"])
def health():
    """Health check"""
    return jsonify(
        {
            "status": "healthy",
            "server": "gateway",
            "timestamp": datetime.utcnow().isoformat(),
        }
    )


if __name__ == "__main__":
    print("=" * 60)
    print("ZTA GATEWAY SERVER")
    print("=" * 60)
    print(f"Port: {app.config['GATEWAY_SERVER_PORT']}")
    print(f"Forwarding to API: {app.config['API_SERVER_URL']}")
    print(f"OPA Server: {app.config['OPA_SERVER_URL']}")
    print("Authentication: mTLS + JWT")
    print("=" * 60)

    import ssl

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(
        certfile=app.config["SERVER_CERT_PATH"], keyfile=app.config["SERVER_KEY_PATH"]
    )

    app.run(
        debug=True,
        port=app.config["GATEWAY_SERVER_PORT"],
        ssl_context=context,
        host="0.0.0.0",
    )
