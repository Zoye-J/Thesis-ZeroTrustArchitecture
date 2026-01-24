"""
Service Communicator for ENCRYPTED ZTA Workflow
Handles encrypted communication between Gateway → OPA Agent → OPA Server → API Server
"""

import requests
import json
import uuid
from flask import current_app, request, g, jsonify
import logging
from app.logs.zta_event_logger import event_logger, EventType  # CHANGED HERE
from datetime import datetime

logger = logging.getLogger(__name__)


class EncryptedServiceCommunicator:

    def __init__(self):
        self.opa_agent_client = None
        self.api_server_url = None
        self._initialized = False

    def init_app(self, app):
        """Initialize with Flask app"""
        self.api_server_url = app.config.get("API_SERVER_URL", "https://localhost:5001")

        # Initialize OPA Agent Client
        try:
            from app.opa_agent.client import init_opa_agent_client

            init_opa_agent_client(app)
            from app.opa_agent.client import get_opa_agent_client

            self.opa_agent_client = get_opa_agent_client()
            logger.info("✅ OPA Agent Client integrated into Service Communicator")
        except ImportError as e:
            logger.warning(f"OPA Agent not available: {e}")
            self.opa_agent_client = None

        self._initialized = True
        logger.info("=== ENCRYPTED Service Communicator Initialized ===")
        logger.info(f"API Server URL: {self.api_server_url}")
        logger.info(
            f"OPA Agent Client: {'Available' if self.opa_agent_client else 'Not available'}"
        )

    def process_encrypted_request(self, flask_request, user_claims):
        """
        NEW ENCRYPTED WORKFLOW:
        User → Gateway → (Encrypted) → OPA Agent → OPA Server → API Server → (Encrypted) → Gateway → User
        """
        request_id = str(uuid.uuid4())
        g.request_id = request_id

        logger.info(f"[{request_id}] === ENCRYPTED ZTA FLOW START ===")
        logger.info(f"[{request_id}] User: {user_claims.get('username')}")
        logger.info(f"[{request_id}] Endpoint: {flask_request.path}")

        try:
            # Step 1: Get user's public key
            user_public_key = self._get_user_public_key(user_claims.get("sub"))
            if not user_public_key:
                return self._create_error_response(
                    400,
                    "User public key not found. Please complete registration.",
                    request_id,
                )

            # Step 2: Prepare request data
            request_data = self._build_request_data(
                flask_request, user_claims, request_id
            )

            # Step 3: Check if OPA Agent is available
            if not self.opa_agent_client:
                return self._create_error_response(
                    503, "OPA Agent service unavailable", request_id
                )

            # Step 4: Encrypt and send to OPA Agent
            try:
                encrypted_request = self.opa_agent_client.encrypt_for_agent(
                    request_data
                )

                agent_response = self.opa_agent_client.send_to_agent(
                    encrypted_request, user_public_key, request_id
                )

                if not agent_response:
                    return self._create_error_response(
                        503, "OPA Agent did not respond", request_id
                    )

                # Step 5: Extract encrypted response
                encrypted_response = agent_response.get("encrypted_response")
                if not encrypted_response:
                    return self._create_error_response(
                        500, "No encrypted response from OPA Agent", request_id
                    )

                # Step 6: Return encrypted response to client
                # (Client will decrypt with their private key)
                logger.info(f"[{request_id}] Returning encrypted response to user")

                # Log successful encrypted flow
                event_logger.log_event(
                    event_type=EventType.RESPONSE_ENCRYPTED,
                    source_component="service_communicator",
                    action="Encrypted response returned",
                    user_id=user_claims.get("sub"),
                    username=user_claims.get("username"),
                    details={
                        "request_id": request_id,
                        "endpoint": flask_request.path,
                        "encryption_used": True,
                        "algorithm": "RSA-OAEP-SHA256",
                    },
                    status="success",
                    trace_id=request_id,
                )

                return (
                    jsonify(
                        {
                            "status": "success",
                            "encrypted_payload": encrypted_response,
                            "encryption_info": {
                                "algorithm": "RSA-OAEP-SHA256",
                                "key_size": 2048,
                                "format": "base64",
                                "request_id": request_id,
                            },
                            "zta_context": {
                                "flow": "User → Gateway → OPA Agent → OPA Server → API Server → Gateway → User",
                                "request_id": request_id,
                                "encryption_used": True,
                            },
                        }
                    ),
                    200,
                )

            except Exception as e:
                logger.error(f"[{request_id}] OPA Agent communication error: {e}")

                # Log error event
                event_logger.log_event(
                    event_type=EventType.ENCRYPTION_FAILED,
                    source_component="service_communicator",
                    action="OPA Agent communication error",
                    user_id=user_claims.get("sub"),
                    username=user_claims.get("username"),
                    details={
                        "request_id": request_id,
                        "error": str(e),
                        "endpoint": flask_request.path,
                    },
                    status="failure",
                    trace_id=request_id,
                )

                return self._create_error_response(
                    500, f"OPA Agent error: {str(e)}", request_id
                )

        except Exception as e:
            logger.error(f"[{request_id}] Encrypted flow error: {e}")

            # Log error event
            event_logger.log_event(
                event_type=EventType.ERROR,
                source_component="service_communicator",
                action="Encrypted flow error",
                user_id=user_claims.get("sub"),
                username=user_claims.get("username"),
                details={
                    "request_id": request_id,
                    "error": str(e),
                    "endpoint": flask_request.path,
                },
                status="failure",
                trace_id=request_id,
            )

            return self._create_error_response(
                500, f"Encrypted processing error: {str(e)}", request_id
            )
        finally:
            logger.info(f"[{request_id}] === ENCRYPTED ZTA FLOW END ===")

    def _get_user_public_key(self, user_id):
        """Get user's public key from database or key storage"""
        try:
            # Try to get from database first
            from app.api_models import User

            user = User.query.get(user_id)
            if user and user.public_key:
                logger.debug(f"Found public key in database for user {user_id}")
                return user.public_key

            # Try to get from key storage
            try:
                from app.mTLS.cert_manager import cert_manager

                key = cert_manager.get_user_public_key(user_id)
                if key:
                    logger.debug(f"Found public key in key storage for user {user_id}")
                    return key
            except:
                pass

            logger.warning(f"No public key found for user {user_id}")
            return None

        except Exception as e:
            logger.error(f"Failed to get user public key: {e}")
            return None

    def _build_request_data(self, flask_request, user_claims, request_id):
        """Build request data for OPA Agent"""
        # Extract resource type from path
        resource_type = (
            "document"
            if "/documents" in flask_request.path
            else (
                "user"
                if "/users" in flask_request.path
                else "log" if "/logs" in flask_request.path else "unknown"
            )
        )

        # Get request body if present
        request_body = None
        if flask_request.method in ["POST", "PUT", "PATCH"]:
            try:
                request_body = flask_request.get_json(silent=True)
            except:
                pass

        return {
            "user": {
                "id": user_claims.get("sub"),
                "username": user_claims.get("username"),
                "role": user_claims.get("user_class"),
                "department": user_claims.get("department"),
                "facility": user_claims.get("facility"),
                "clearance": user_claims.get("clearance_level", "BASIC"),
                "email": user_claims.get("email"),
            },
            "resource": {
                "type": resource_type,
                "path": flask_request.path,
                "method": flask_request.method,
                "query_params": dict(flask_request.args),
            },
            "request": {
                "body": request_body,
                "headers": {
                    k: v
                    for k, v in flask_request.headers.items()
                    if k.lower() not in ["authorization", "cookie"]
                },
            },
            "environment": {
                "timestamp": datetime.now().isoformat(),
                "client_ip": flask_request.remote_addr,
                "user_agent": (
                    flask_request.user_agent.string
                    if flask_request.user_agent
                    else None
                ),
            },
            "action": flask_request.method.lower(),
            "needs_api_call": True,
            "request_id": request_id,
        }

    def _create_error_response(self, status_code, message, request_id):
        """Create error response"""
        # Log error event
        event_logger.log_event(
            event_type=EventType.ERROR,
            source_component="service_communicator",
            action="Encrypted flow error",
            details={
                "error": message,
                "request_id": request_id,
                "status_code": status_code,
                "flow_step": "service_communicator",
            },
            status="failure",
            trace_id=request_id,
        )

        return (
            jsonify(
                {
                    "error": "Encrypted workflow failed",
                    "message": message,
                    "zta_context": {
                        "failed_component": "service_communicator",
                        "request_id": request_id,
                        "flow_interrupted": True,
                    },
                }
            ),
            status_code,
        )

    def health_check(self):
        """Check health of all services in encrypted workflow"""
        health_status = {
            "gateway": "running",
            "opa_agent": "unknown",
            "api_server": "unknown",
            "timestamp": datetime.now().isoformat(),
        }

        # Check OPA Agent
        if self.opa_agent_client:
            health_status["opa_agent"] = (
                "healthy" if self.opa_agent_client.health_check() else "unhealthy"
            )
        else:
            health_status["opa_agent"] = "not_initialized"

        # Check API Server
        try:
            # Use direct service token for health check
            headers = {
                "X-Service-Token": current_app.config.get(
                    "GATEWAY_SERVICE_TOKEN", "gateway-token-2024"
                ),
                "X-Request-ID": str(uuid.uuid4())[:8],
            }
            api_response = requests.get(
                f"{self.api_server_url}/health",
                headers=headers,
                timeout=3,
                verify=False,
            )  # For self-signed certs
            health_status["api_server"] = (
                "healthy" if api_response.status_code == 200 else "unhealthy"
            )
        except:
            health_status["api_server"] = "unreachable"

        return health_status


# Singleton instance
encrypted_service_communicator = EncryptedServiceCommunicator()


def init_service_communicator(app):
    """Initialize ENCRYPTED service communicator"""
    encrypted_service_communicator.init_app(app)


def get_service_communicator():
    """Get ENCRYPTED service communicator instance"""
    return encrypted_service_communicator


def process_encrypted_request(request, user_claims):
    """
    Simple wrapper for gateway server to use

    Usage in gateway routes:
    @app.route('/api/documents')
    @require_authentication
    def get_documents():
        user_claims = get_jwt_claims()  # From auth
        return process_encrypted_request(request, user_claims)
    """
    communicator = get_service_communicator()
    return communicator.process_encrypted_request(request, user_claims)
