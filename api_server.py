"""
ZTA API Server - Business logic and database operations
Only accepts requests from Gateway with valid service tokens
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify, g
import json
import uuid
from datetime import datetime

from app.api_app import create_api_app

# Create the app
app = create_api_app()

if __name__ == "__main__":
    print("=" * 60)
    print("ZTA API SERVER")
    print("=" * 60)
    print(f"Port: {app.config.get('API_SERVER_PORT', 5001)}")
    print("Authentication: Service tokens only")
    print(
        f"Service Token: {app.config.get('API_SERVICE_TOKEN', 'api-token-2024')[:10]}..."
    )
    print("=" * 60)

    app.run(
        debug=True,
        port=app.config.get("API_SERVER_PORT", 5001),
        ssl_context=("certs/server.crt", "certs/server.key"),
    )

# Service token from config
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


# Note: The actual API endpoints are registered via blueprint in create_app()
# They will be in app/api/api_routes.py


if __name__ == "__main__":
    print("=" * 60)
    print("ZTA API SERVER")
    print("=" * 60)
    print(f"Port: {app.config['API_SERVER_PORT']}")
    print("Authentication: Service tokens only")
    print(f"Service Token: {API_SERVICE_TOKEN[:10]}...")
    print("=" * 60)

    app.run(debug=True, port=app.config["API_SERVER_PORT"], host="0.0.0.0")
