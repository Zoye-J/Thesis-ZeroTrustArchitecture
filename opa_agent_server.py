# CREATE: app/opa_agent_server.py
"""
OPA Agent Server with Encryption
Runs on Port 8282
"""

from flask import Flask, request, jsonify, g
from app.opa_agent.agent import OpaAgent
import uuid
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_opa_agent_app():
    """Create OPA Agent Flask application"""
    app = Flask(__name__)
    agent = OpaAgent()

    @app.before_request
    def setup_request():
        """Setup request context"""
        g.request_id = str(uuid.uuid4())
        g.agent = agent

    @app.route("/health", methods=["GET"])
    def health():
        """Health check endpoint"""
        return (
            jsonify(
                {
                    "status": "healthy",
                    "service": "OPA Agent",
                    "port": 8282,
                    "encryption": "RSA-2048",
                    "public_key_available": bool(agent.get_public_key()),
                }
            ),
            200,
        )

    @app.route("/evaluate", methods=["POST"])
    def evaluate():
        """
        Main endpoint: Receive encrypted request, process, return encrypted response

        Expected payload:
        {
            "encrypted_request": "base64_encrypted_data",
            "user_public_key": "PEM_public_key",
            "request_id": "optional_id"
        }
        """
        try:
            data = request.json
            request_id = data.get("request_id", g.request_id)

            logger.info(f"[{request_id}] OPA Agent received request")

            # Step 1: Decrypt request with agent's private key
            encrypted_request = data["encrypted_request"]
            decrypted_data = agent.decrypt_request(encrypted_request)

            # Step 2: Parse decrypted data
            import json

            request_info = json.loads(decrypted_data)

            # Step 3: Forward to OPA Server for policy evaluation
            opa_result = agent.query_opa_server(request_info)

            # Step 4: Check if access is allowed
            if not opa_result.get("allow", False):
                # Access denied - still encrypt response
                response_data = {
                    "allowed": False,
                    "reason": opa_result.get("reason", "Access denied"),
                    "opa_result": opa_result,
                }
            else:
                # Access allowed - call API Server
                logger.info(f"[{request_id}] Access allowed, calling API Server")

                # Extract API call info from request
                api_response = agent.call_api_server(request_info)

                response_data = {
                    "allowed": True,
                    "api_response": api_response,
                    "opa_result": opa_result,
                }

            # Step 5: Encrypt response with user's public key
            user_public_key = data["user_public_key"]
            encrypted_response = agent.encrypt_response(response_data, user_public_key)

            logger.info(f"[{request_id}] OPA Agent processing complete")

            return (
                jsonify(
                    {
                        "encrypted_response": encrypted_response,
                        "request_id": request_id,
                        "agent_timestamp": g.request_id,
                    }
                ),
                200,
            )

        except Exception as e:
            logger.error(f"OPA Agent error: {e}")
            return jsonify({"error": "Processing failed", "message": str(e)}), 500

    @app.route("/public-key", methods=["GET"])
    def get_public_key():
        """Get OPA Agent's public key"""
        public_key = agent.get_public_key()
        return (
            jsonify(
                {
                    "public_key": public_key,
                    "algorithm": "RSA",
                    "key_size": 2048,
                    "format": "PEM",
                }
            ),
            200,
        )

    return app


if __name__ == "__main__":
    app = create_opa_agent_app()
    print("=" * 60)
    print("🔐 OPA AGENT SERVER WITH ENCRYPTION")
    print("=" * 60)
    print("📡 Port: 8282")
    print("🔗 URL: http://localhost:8282")
    print("🏥 Health: http://localhost:8282/health")
    print("🔑 Public Key: http://localhost:8282/public-key")
    print("⚖️  Evaluate: POST http://localhost:8282/evaluate")
    print("=" * 60)
    print("Press Ctrl+C to stop\n")

    app.run(host="0.0.0.0", port=8282, debug=True)
