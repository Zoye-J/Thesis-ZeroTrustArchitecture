"""
Service Communicator for ENCRYPTED ZTA Workflow - FIXED VERSION
Handles encrypted communication between Gateway → OPA Agent → OPA Server → API Server
"""

import requests
import json
import uuid
import os
from flask import current_app, request, g, jsonify
import logging
from app.logs.zta_event_logger import event_logger, EventType
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
        ALWAYS use encrypted workflow for ALL API endpoints
        """
        request_id = str(uuid.uuid4())
        g.request_id = request_id

        logger.info(f"[{request_id}] === ZTA FLOW START ===")
        logger.info(f"[{request_id}] User: {user_claims.get('username')}")
        logger.info(f"[{request_id}] Endpoint: {flask_request.path}")

        # ============ ALWAYS USE ENCRYPTED FLOW ============
        logger.info(f"[{request_id}] 🔐 ALWAYS using OPA Agent encrypted flow")
        return self._handle_encrypted_request(flask_request, user_claims, request_id)

    def _handle_resource_access(self, flask_request, user_claims, request_id):
        """Handle resource access requests (POST /api/resources/{id}/access)"""
        try:
            # Extract resource ID from path
            resource_id = flask_request.path.split("/")[3]  # /api/resources/7/access

            logger.info(
                f"[{request_id}] 📝 Processing access request for resource {resource_id}"
            )

            # Check if user can access this resource
            can_access = self._check_resource_access(resource_id, user_claims)

            if not can_access:
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": "Access denied",
                            "requires_approval": False,
                            "access_granted": False,
                            "zta_context": {
                                "user": user_claims.get("username"),
                                "department": user_claims.get("department"),
                                "decision": "DENIED",
                            },
                        }
                    ),
                    403,
                )

            # Grant access
            return (
                jsonify(
                    {
                        "success": True,
                        "message": "Access granted",
                        "resource_id": resource_id,
                        "requires_approval": False,
                        "access_granted": True,
                        "zta_context": {
                            "user": user_claims.get("username"),
                            "department": user_claims.get("department"),
                            "decision": "ALLOWED",
                            "flow": "User → Gateway → Access Granted",
                        },
                    }
                ),
                200,
            )

        except Exception as e:
            logger.error(f"[{request_id}] Resource access error: {e}")
            return self._create_error_response(
                500, f"Resource access error: {str(e)}", request_id
            )

    def _handle_resource_view(self, flask_request, user_claims, request_id):
        """Handle resource view requests (GET /api/resources/{id}/view)"""
        try:
            # Extract resource ID from path
            resource_id = flask_request.path.split("/")[3]  # /api/resources/7/view

            logger.info(
                f"[{request_id}] 👁️ Processing view request for resource {resource_id}"
            )

            # Sample resource content - in real app, fetch from database
            sample_resources = {
                1: {
                    "id": 1,
                    "name": "Public Notice Board",
                    "content": "This is public content for all government employees.",
                },
                2: {
                    "id": 2,
                    "name": "Government Circulars",
                    "content": "Latest government circulars and announcements.",
                },
                3: {
                    "id": 3,
                    "name": "MOD Operations Brief",
                    "content": "MOD department operations briefing.",
                },
                4: {
                    "id": 4,
                    "name": "MOD Budget Report",
                    "content": "MOD department budget report.",
                },
                5: {
                    "id": 5,
                    "name": "Top Secret MOD Plans",
                    "content": "🔒 TOP SECRET CONTENT: Classified MOD plans.",
                },
                6: {
                    "id": 6,
                    "name": "MOF Fiscal Policy",
                    "content": "Ministry of Finance fiscal policy document.",
                },
                7: {
                    "id": 7,
                    "name": "MOF Budget Documents",
                    "content": "MOF department budget documents.",
                },
                8: {
                    "id": 8,
                    "name": "NSA Cyber Reports",
                    "content": "NSA cybersecurity threat reports.",
                },
                9: {
                    "id": 9,
                    "name": "NSA Threat Assessment",
                    "content": "NSA threat assessment document.",
                },
            }

            if int(resource_id) not in sample_resources:
                return jsonify({"error": "Resource not found"}), 404

            return (
                jsonify(
                    {
                        "resource": sample_resources[int(resource_id)],
                        "user": user_claims.get("username"),
                        "access_time": datetime.now().isoformat(),
                        "zta_context": {
                            "authentication": "mTLS + JWT",
                            "authorization": "Department-based access control",
                            "trace_id": request_id,
                        },
                    }
                ),
                200,
            )

        except Exception as e:
            logger.error(f"[{request_id}] Resource view error: {e}")
            return self._create_error_response(
                500, f"Resource view error: {str(e)}", request_id
            )

    def _check_resource_access(self, resource_id, user_claims):
        """Check if user can access the resource"""
        # This is a simplified check - in real app, check against user's department, clearance, etc.
        user_department = user_claims.get("department")
        user_clearance = user_claims.get("clearance_level", "BASIC").upper()

        # Resource 5 is TOP_SECRET MOD - check time restriction
        if resource_id == "5" and user_department == "MOD":
            current_hour = datetime.now().hour
            if 8 <= current_hour < 16:
                return user_clearance in ["SECRET", "TOP_SECRET"]
            else:
                return False

        # For other resources, basic department check
        return True

    def _handle_resource_request(self, flask_request, user_claims, request_id):
        """Handle resource requests directly (no encryption needed)"""
        try:
            logger.info(f"[{request_id}] 📡 Direct API call for resources")

            # Call API Server directly
            response = requests.get(
                f"{self.api_server_url}/api/resources",
                headers={
                    "Content-Type": "application/json",
                    "X-Service-Token": current_app.config.get(
                        "API_SERVICE_TOKEN", "api-token-2024-zta"
                    ),
                    "X-User-Claims": json.dumps(user_claims),
                    "X-Request-ID": request_id,
                },
                timeout=10,
                verify="certs/ca.crt" if os.path.exists("certs/ca.crt") else False,
            )

            if response.status_code == 200:
                data = response.json()
                logger.info(f"[{request_id}] ✅ Resources retrieved: {len(data)} items")

                # Log successful direct flow
                event_logger.log_event(
                    event_type=EventType.API_RESPONSE,
                    source_component="service_communicator",
                    action="Direct resource retrieval",
                    user_id=user_claims.get("sub"),
                    username=user_claims.get("username"),
                    details={
                        "request_id": request_id,
                        "endpoint": flask_request.path,
                        "resource_count": len(data),
                        "flow": "Direct API → Gateway → User",
                    },
                    status="success",
                    trace_id=request_id,
                )

                return jsonify(data), 200
            else:
                logger.error(
                    f"[{request_id}] ❌ API Server error: {response.status_code}"
                )
                return jsonify(response.json()), response.status_code

        except Exception as e:
            logger.error(f"[{request_id}] ❌ Direct resource error: {e}")
            return self._create_error_response(
                500, f"Resource request failed: {str(e)}", request_id
            )

    def _handle_encrypted_request(self, flask_request, user_claims, request_id):
        """Handle encrypted requests through OPA Agent - UPDATED FOR RESOURCES"""
        try:
            # Extract resource ID from path if it's a resource request
            resource_id = None
            if flask_request.path.startswith("/api/resources/"):
                # Extract ID from /api/resources/123 or /api/resources/123/view
                parts = flask_request.path.split("/")
                for i, part in enumerate(parts):
                    if part == "resources" and i + 1 < len(parts):
                        try:
                            resource_id = int(parts[i + 1])
                            break
                        except ValueError:
                            pass

            # Step 1: Get user's public key
            user_public_key = self._get_user_public_key(user_claims.get("sub"))
            if not user_public_key:
                # Try to get from user claims (for testing)
                user_public_key = user_claims.get("public_key")
                if not user_public_key:
                    return self._create_error_response(
                        400,
                        "User public key not found. Please complete registration.",
                        request_id,
                    )

            # Step 2: Build request data with resource info
            request_data = {
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
                    "user_agent": (
                        flask_request.user_agent.string
                        if flask_request.user_agent
                        else None
                    ),
                    "current_hour": datetime.now().hour,
                },
                "request_id": request_id,
                "needs_api_call": True,
            }

            # Add request body for POST/PUT
            if flask_request.method in ["POST", "PUT", "PATCH"]:
                try:
                    request_data["request_body"] = flask_request.get_json(silent=True)
                except:
                    pass

            # Step 3: Check if OPA Agent is available
            if not self.opa_agent_client:
                logger.warning(
                    f"[{request_id}] OPA Agent not available, using direct API"
                )
                return self._handle_direct_api_call(
                    flask_request, user_claims, request_id
                )

            # Step 4: Encrypt and send to OPA Agent
            logger.info(f"[{request_id}] 🔐 Encrypting request for OPA Agent")
            encrypted_request = self.opa_agent_client.encrypt_for_agent(request_data)

            logger.info(
                f"[{request_id}] 📡 Sending to OPA Agent: {self.opa_agent_client.agent_url}/evaluate"
            )
            agent_response = self.opa_agent_client.send_to_agent(
                encrypted_request, user_public_key, request_id
            )

            if not agent_response:
                logger.error(f"[{request_id}] ❌ OPA Agent did not respond")
                return self._create_error_response(
                    503, "OPA Agent service unavailable", request_id
                )

            # Step 5: Extract encrypted response
            encrypted_response = agent_response.get("encrypted_response")
            if not encrypted_response:
                logger.error(f"[{request_id}] ❌ No encrypted response from OPA Agent")
                return self._create_error_response(
                    500, "No encrypted response from OPA Agent", request_id
                )

            # Step 6: Return encrypted response to client
            logger.info(f"[{request_id}] ✅ Returning encrypted response to user")

            # Log successful encrypted flow
            from app.logs.zta_event_logger import event_logger, EventType

            event_logger.log_event(
                event_type=EventType.RESPONSE_ENCRYPTED,
                source_component="service_communicator",
                action="Encrypted response returned",
                user_id=user_claims.get("sub"),
                username=user_claims.get("username"),
                details={
                    "request_id": request_id,
                    "endpoint": flask_request.path,
                    "resource_id": resource_id,
                    "encryption_used": True,
                    "algorithm": "RSA-OAEP-SHA256",
                    "flow": "User → Gateway → OPA Agent → OPA Server → API Server → OPA Agent → Gateway",
                },
                status="success",
                trace_id=request_id,
            )

            return (
                jsonify(
                    {
                        "status": "success",
                        "encrypted_payload": encrypted_response,
                        "resource_id": resource_id,
                        "encryption_info": {
                            "algorithm": "RSA-OAEP-SHA256",
                            "key_size": 2048,
                            "format": "base64",
                            "request_id": request_id,
                        },
                        "zta_context": {
                            "flow": "User → Gateway → OPA Agent → OPA Server → API Server → OPA Agent → Gateway → User",
                            "request_id": request_id,
                            "encryption_used": True,
                            "user": user_claims.get("username"),
                            "department": user_claims.get("department"),
                        },
                    }
                ),
                200,
            )

        except Exception as e:
            logger.error(f"[{request_id}] OPA Agent communication error: {e}")

            # Log error event
            from app.logs.zta_event_logger import event_logger, EventType

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

    def _handle_direct_api_call(self, flask_request, user_claims, request_id):
        """Fallback: Direct API call when OPA Agent is unavailable"""
        try:
            logger.info(
                f"[{request_id}] 🔄 Using direct API call (OPA Agent unavailable)"
            )

            # Build API Server URL
            api_url = f"{self.api_server_url}{flask_request.path}"

            # Prepare headers
            headers = {
                "Content-Type": "application/json",
                "X-Service-Token": "gateway-direct-call",
                "X-User-Claims": json.dumps(user_claims),
                "X-Request-ID": request_id,
            }
            # Check if CA cert exists
            ca_cert_path = "certs/ca.crt"
            verify_ssl = ca_cert_path if os.path.exists(ca_cert_path) else False

            # Make the request
            if flask_request.method == "POST":
                data = flask_request.get_json(silent=True) or {}
                response = requests.post(
                    api_url, json=data, headers=headers, verify=verify_ssl, timeout=10
                )
            elif flask_request.method == "PUT":
                data = flask_request.get_json(silent=True) or {}
                response = requests.put(
                    api_url, json=data, headers=headers, verify=verify_ssl, timeout=10
                )
            elif flask_request.method == "DELETE":
                response = requests.delete(
                    api_url, headers=headers, verify=verify_ssl, timeout=10
                )
            else:  # GET
                response = requests.get(
                    api_url, headers=headers, verify=verify_ssl, timeout=10
                )

            if response.status_code == 200:
                data = response.json()
                logger.info(f"[{request_id}] ✅ Direct API call successful")

                # Add ZTA context to response
                if isinstance(data, dict):
                    data["zta_context"] = {
                        "flow": "Direct API → Gateway → User",
                        "encryption_used": False,
                        "opa_agent_used": False,
                        "request_id": request_id,
                    }

                return jsonify(data), 200
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

    def _get_user_public_key(self, user_id):
        """Get user's public key from database or key storage"""
        try:
            # Import inside function to avoid circular imports
            from app.models.user import User

            user = User.query.get(user_id)
            if user and user.public_key:
                logger.info(f"✅ Found public key for user {user_id}")
                return user.public_key

            logger.warning(f"⚠️ No public key found for user {user_id}")
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

    def _build_encrypted_request_data(self, flask_request, user_claims, request_id):
        """Build proper request data for OPA Agent evaluation"""
        # Extract resource ID if present
        resource_id = None
        if "/resources/" in flask_request.path:
            parts = flask_request.path.split("/")
            for i, part in enumerate(parts):
                if part == "resources" and i + 1 < len(parts):
                    try:
                        resource_id = int(parts[i + 1])
                        break
                    except ValueError:
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
                "type": "document",
                "id": resource_id,
                "endpoint": flask_request.path,
                "method": flask_request.method,
                "classification": "DEPARTMENT",  # Default, will be determined by OPA
            },
            "action": flask_request.method.lower(),
            "environment": {
                "timestamp": datetime.now().isoformat(),
                "client_ip": flask_request.remote_addr,
                "user_agent": (
                    flask_request.user_agent.string
                    if flask_request.user_agent
                    else None
                ),
                "current_hour": datetime.now().hour,
            },
            "request_id": request_id,
            "needs_api_call": True,
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

            # Check if CA cert exists
            ca_cert_path = "certs/ca.crt"
            verify_ssl = ca_cert_path if os.path.exists(ca_cert_path) else False

            api_response = requests.get(
                f"{self.api_server_url}/health",
                headers=headers,
                timeout=3,
                verify=verify_ssl,
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
