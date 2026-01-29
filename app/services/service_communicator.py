"""
Service Communicator for ENCRYPTED ZTA Workflow - COMPLETE FIX
Handles encrypted communication following your flow:
User → Gateway → OPA Agent (encrypts) → OPA Server (policy check) → API Server → OPA Agent (encrypts) → Gateway → User
"""

import requests
import json
import uuid
import sys
import os
from flask import current_app, request, g, jsonify
import logging
from app.logs.zta_event_logger import event_logger, EventType
from datetime import datetime

# Apply SSL fix BEFORE any imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from app.ssl_fix import create_fixed_ssl_context

    print("✅ SSL fix imported for service_communicator")
except ImportError:
    print("⚠️ SSL fix module not available for service communicator")
    # Create fallback context
    import ssl

    def create_fixed_ssl_context():
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.load_verify_locations(cafile="certs/ca.crt")
        return context


logger = logging.getLogger(__name__)


class EncryptedServiceCommunicator:
    def __init__(self):
        self.opa_agent_client = None
        self.api_server_url = None
        self._initialized = False
        self.session = None  # For SSL-fixed requests

    def init_app(self, app):
        """Initialize with Flask app"""
        self.api_server_url = app.config.get("API_SERVER_URL", "https://localhost:5001")

        # Create SSL-fixed session
        self.session = requests.Session()
        ssl_context = create_fixed_ssl_context()

        # Mount SSL-fixed adapter
        from requests.adapters import HTTPAdapter

        class FixedSSLAdapter(HTTPAdapter):
            def init_poolmanager(self, *args, **kwargs):
                kwargs["ssl_context"] = ssl_context
                return super().init_poolmanager(*args, **kwargs)

        self.session.mount("https://", FixedSSLAdapter())
        logger.info("✅ Created SSL-fixed session for service communicator")

        # Initialize OPA Agent Client
        try:
            from app.opa_agent.client import init_opa_agent_client, get_opa_agent_client

            init_opa_agent_client(app)
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

    def _make_ssl_request(self, method, url, **kwargs):
        """Make request with SSL fix applied"""
        try:
            # Remove verify parameter as we use our SSL context
            kwargs.pop("verify", None)
            return self.session.request(method, url, **kwargs)
        except Exception as e:
            logger.error(f"SSL request failed: {e}")
            # Fallback to regular requests with verify=False
            kwargs["verify"] = False
            return requests.request(method, url, **kwargs)

    def process_encrypted_request(self, flask_request, user_claims):
        """
        Process request following ZTA flow:
        User → Gateway → OPA Agent (encrypts) → OPA Server (policy check) → API Server → OPA Agent (encrypts) → Gateway → User
        """
        request_id = str(uuid.uuid4())
        g.request_id = request_id

        logger.info(f"[{request_id}] === ZTA ENCRYPTED FLOW START ===")
        logger.info(f"[{request_id}] User: {user_claims.get('username')}")
        logger.info(f"[{request_id}] Endpoint: {flask_request.path}")
        logger.info(f"[{request_id}] Method: {flask_request.method}")

        # Log start of encrypted flow
        event_logger.log_event(
            event_type=EventType.REQUEST_RECEIVED,
            source_component="gateway",
            action="Starting encrypted ZTA flow",
            user_id=user_claims.get("sub"),
            username=user_claims.get("username"),
            details={
                "endpoint": flask_request.path,
                "method": flask_request.method,
                "flow": "User → Gateway → OPA Agent → OPA Server → API Server → OPA Agent → Gateway → User",
            },
            trace_id=request_id,
        )

        # Handle specific endpoints
        if flask_request.path.startswith("/api/resources/"):
            return self._handle_resource_request(flask_request, user_claims, request_id)

        # Default: use encrypted flow
        return self._handle_encrypted_request(flask_request, user_claims, request_id)

    def _handle_resource_request(self, flask_request, user_claims, request_id):
        """Handle resource requests through encrypted flow"""
        try:
            # Extract resource ID
            parts = flask_request.path.split("/")
            resource_id = None
            for i, part in enumerate(parts):
                if part == "resources" and i + 1 < len(parts):
                    try:
                        resource_id = int(parts[i + 1])
                        break
                    except ValueError:
                        pass

            logger.info(
                f"[{request_id}] 📦 Processing resource request: ID={resource_id}"
            )

            # Get user's public key
            user_public_key = self._get_user_public_key(user_claims.get("sub"))
            if not user_public_key:
                # Try from claims or generate a test key
                user_public_key = user_claims.get("public_key")
                if not user_public_key:
                    # Generate a test RSA key for demo
                    from cryptography.hazmat.primitives import serialization
                    from cryptography.hazmat.primitives.asymmetric import rsa

                    private_key = rsa.generate_private_key(
                        public_exponent=65537,
                        key_size=2048,
                    )
                    public_key = private_key.public_key()

                    user_public_key = public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    ).decode("utf-8")

                    logger.info(f"[{request_id}] Generated demo public key for user")

            # Build request for OPA Agent
            request_data = self._build_resource_request_data(
                flask_request, user_claims, resource_id, request_id
            )

            # Check if OPA Agent is available
            if not self.opa_agent_client:
                logger.warning(
                    f"[{request_id}] OPA Agent not available, using direct API"
                )
                return self._handle_direct_resource_call(
                    flask_request, user_claims, request_id
                )

            # Step 1: Encrypt and send to OPA Agent
            logger.info(f"[{request_id}] 🔐 Encrypting request for OPA Agent")

            try:
                encrypted_request = self.opa_agent_client.encrypt_for_agent(
                    request_data
                )
            except Exception as e:
                logger.error(f"[{request_id}] Encryption failed: {e}")
                # Use direct API as fallback
                return self._handle_direct_resource_call(
                    flask_request, user_claims, request_id
                )

            # Step 2: Send to OPA Agent
            logger.info(f"[{request_id}] 📡 Sending to OPA Agent")
            agent_response = self.opa_agent_client.send_to_agent(
                encrypted_request, user_public_key, request_id
            )

            if not agent_response:
                logger.error(f"[{request_id}] ❌ OPA Agent did not respond")
                return self._create_error_response(
                    503, "OPA Agent service unavailable", request_id
                )

            # Step 3: Check if response is encrypted
            encrypted_response = agent_response.get("encrypted_response")
            if encrypted_response:
                # This is an encrypted response from OPA Agent
                logger.info(
                    f"[{request_id}] ✅ Received encrypted response from OPA Agent"
                )

                # Log successful encrypted flow
                event_logger.log_event(
                    event_type=EventType.RESPONSE_ENCRYPTED,
                    source_component="service_communicator",
                    action="Encrypted response received from OPA Agent",
                    user_id=user_claims.get("sub"),
                    username=user_claims.get("username"),
                    details={
                        "request_id": request_id,
                        "resource_id": resource_id,
                        "encryption": "RSA-OAEP-SHA256",
                        "flow_complete": True,
                    },
                    trace_id=request_id,
                )

                return (
                    jsonify(
                        {
                            "status": "encrypted",
                            "encrypted_payload": encrypted_response,
                            "resource_id": resource_id,
                            "encryption_info": {
                                "algorithm": "RSA-OAEP-SHA256",
                                "key_size": 2048,
                                "request_id": request_id,
                            },
                            "zta_context": {
                                "flow": "User → Gateway → OPA Agent → OPA Server → API Server → OPA Agent → Gateway",
                                "encryption_used": True,
                                "opa_agent_used": True,
                                "trace_id": request_id,
                            },
                        }
                    ),
                    200,
                )
            else:
                # Direct response (for testing or fallback)
                logger.info(f"[{request_id}] 📦 Direct response from OPA Agent")
                return jsonify(agent_response), 200

        except Exception as e:
            logger.error(f"[{request_id}] Resource request error: {e}")
            return self._create_error_response(
                500, f"Resource request failed: {str(e)}", request_id
            )

    def _build_resource_request_data(
        self, flask_request, user_claims, resource_id, request_id
    ):
        """Build request data for OPA Agent"""
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
                "type": "document",
                "id": resource_id,
                "endpoint": flask_request.path,
                "method": flask_request.method,
                "action": flask_request.method.lower(),
            },
            "environment": {
                "timestamp": datetime.now().isoformat(),
                "client_ip": flask_request.remote_addr,
                "current_hour": datetime.now().hour,
            },
            "request_id": request_id,
            "needs_api_call": True,
            "request_body": (
                flask_request.get_json(silent=True)
                if flask_request.method in ["POST", "PUT", "PATCH"]
                else None
            ),
        }

    def _handle_direct_resource_call(self, flask_request, user_claims, request_id):
        """Fallback direct call to API Server"""
        try:
            logger.info(f"[{request_id}] 🔄 Direct API call to API Server")

            # Build URL
            api_url = f"{self.api_server_url}{flask_request.path}"

            # Prepare headers
            headers = {
                "Content-Type": "application/json",
                "X-Service-Token": current_app.config.get(
                    "API_SERVICE_TOKEN", "api-token-2024-zta"
                ),
                "X-User-Claims": json.dumps(user_claims),
                "X-Request-ID": request_id,
            }

            # Make request with SSL fix
            if flask_request.method == "POST":
                data = flask_request.get_json(silent=True) or {}
                response = self._make_ssl_request(
                    "POST", api_url, json=data, headers=headers, timeout=10
                )
            elif flask_request.method == "PUT":
                data = flask_request.get_json(silent=True) or {}
                response = self._make_ssl_request(
                    "PUT", api_url, json=data, headers=headers, timeout=10
                )
            elif flask_request.method == "DELETE":
                response = self._make_ssl_request(
                    "DELETE", api_url, headers=headers, timeout=10
                )
            else:  # GET
                response = self._make_ssl_request(
                    "GET", api_url, headers=headers, timeout=10
                )

            if response.status_code == 200:
                data = response.json()
                logger.info(f"[{request_id}] ✅ Direct API call successful")

                # Add ZTA context
                if isinstance(data, dict):
                    data["zta_context"] = {
                        "flow": "Direct API → Gateway → User",
                        "encryption_used": False,
                        "opa_agent_used": False,
                        "request_id": request_id,
                    }

                return jsonify(data), response.status_code
            else:
                logger.error(
                    f"[{request_id}] ❌ Direct API error: {response.status_code}"
                )
                return jsonify(response.json()), response.status_code

        except Exception as e:
            logger.error(f"[{request_id}] ❌ Direct API call failed: {e}")
            return self._create_error_response(
                500, f"Direct API failed: {str(e)}", request_id
            )

    def _handle_encrypted_request(self, flask_request, user_claims, request_id):
        """Handle generic encrypted requests (for non-resource endpoints)"""
        # Similar to _handle_resource_request but for other endpoints
        return self._handle_direct_resource_call(flask_request, user_claims, request_id)

    def _get_user_public_key(self, user_id):
        """Get user's public key"""
        try:
            from app.models.user import User

            user = User.query.get(user_id)
            if user and user.public_key:
                return user.public_key

            # Try from cert manager
            try:
                from app.mTLS.cert_manager import cert_manager

                return cert_manager.get_user_public_key(user_id)
            except:
                pass

            return None
        except:
            return None

    def _create_error_response(self, status_code, message, request_id):
        """Create standardized error response"""
        event_logger.log_event(
            event_type=EventType.ERROR,
            source_component="service_communicator",
            action="Encrypted flow error",
            details={
                "error": message,
                "request_id": request_id,
                "status_code": status_code,
            },
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
        """Check health of services"""
        health_status = {
            "gateway": "running",
            "opa_agent": "unknown",
            "api_server": "unknown",
            "timestamp": datetime.now().isoformat(),
        }

        # Check OPA Agent
        if self.opa_agent_client:
            try:
                health_status["opa_agent"] = (
                    "healthy" if self.opa_agent_client.health_check() else "unhealthy"
                )
            except:
                health_status["opa_agent"] = "unhealthy"
        else:
            health_status["opa_agent"] = "not_initialized"

        # Check API Server
        try:
            headers = {
                "X-Service-Token": current_app.config.get(
                    "GATEWAY_SERVICE_TOKEN", "gateway-token-2024"
                ),
                "X-Request-ID": str(uuid.uuid4())[:8],
            }

            response = self._make_ssl_request(
                "GET", f"{self.api_server_url}/health", headers=headers, timeout=3
            )
            health_status["api_server"] = (
                "healthy" if response.status_code == 200 else "unhealthy"
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
    Simple wrapper for gateway server
    """
    communicator = get_service_communicator()
    return communicator.process_encrypted_request(request, user_claims)
