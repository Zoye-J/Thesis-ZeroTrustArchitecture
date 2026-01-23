"""
REAL Service-to-Service Communication Handler
Manages ACTUAL HTTP communication between Gateway Server, OPA, and API Server
"""

import requests
import json
import uuid
from flask import current_app, request, g
import logging
from app.logs.zta_event_logger import zta_logger, EVENT_TYPES
import base64
import os
from datetime import datetime

logger = logging.getLogger(__name__)


class RealServiceCommunicator:

    def __init__(self):
        self.opa_url = None
        self.api_server_url = None
        self.gateway_service_token = None
        self.api_service_token = None
        self._initialized = False

    def init_app(self, app):

        self.opa_url = app.config.get("OPA_URL", "http://localhost:8181")
        self.api_server_url = app.config.get(
            "API_SERVER_URL", "http://localhost:3000"
        )  # CHANGED: Port 3000 for API server
        self.gateway_service_token = app.config.get(
            "GATEWAY_SERVICE_TOKEN", "gateway-token-2024"
        )
        self.api_service_token = app.config.get("API_SERVICE_TOKEN", "api-token-2024")
        self._initialized = True

        logger.info("=== REAL Service Communicator Initialized ===")
        logger.info(f"OPA URL: {self.opa_url}")
        logger.info(f"API Server URL: {self.api_server_url}")
        logger.info("Service-to-service communication ENABLED")

    def query_opa_for_decision(self, user_claims, request_info, request_id=None):
        """
        Gateway → OPA: REAL HTTP call to OPA server
        Returns: OPA decision dict
        """
        if not request_id:
            request_id = str(uuid.uuid4())

        try:
            # Prepare OPA input based on actual request
            opa_input = self._build_opa_input(user_claims, request_info, request_id)

            # REAL HTTP request to OPA server
            response = requests.post(
                f"{self.opa_url}/v1/data/zta/allow",  # CHANGED: Use correct endpoint
                json={"input": opa_input},
                headers={
                    "Content-Type": "application/json",
                    "X-Service-Token": self.gateway_service_token,
                    "X-Request-ID": request_id,
                },
                timeout=5,
            )

            # Log REAL OPA communication
            zta_logger.log_event(
                "REAL_OPA_QUERY_SENT",
                {
                    "from": "gateway_server",
                    "to": "opa_server",
                    "request_id": request_id,
                    "opa_url": self.opa_url,
                    "status_code": response.status_code,
                },
                user_id=user_claims.get("sub"),
                request_id=request_id,
            )

            if response.status_code == 200:
                result = response.json().get("result", {})
                logger.info(
                    f"[{request_id}] OPA Decision: {result.get('allow', False)}"
                )
                return result
            else:
                logger.error(
                    f"[{request_id}] OPA request failed: {response.status_code}"
                )
                # Fallback for OPA failure
                return {"allow": True, "reason": "OPA unavailable - fail open"}

        except Exception as e:
            logger.error(f"[{request_id}] OPA communication failed: {e}")
            # Fallback: allow access if OPA is down (for demo)
            return {"allow": True, "reason": f"OPA error: {str(e)} - fail open"}

    def forward_to_api_server(
        self, flask_request, user_claims, opa_decision, request_id
    ):
        """
        Gateway → API Server: REAL HTTP call to API server
        Returns: requests.Response object
        """
        try:
            # Build headers with service tokens and user claims
            headers = self._build_api_headers(user_claims, opa_decision, request_id)

            # Extract request data
            method = flask_request.method
            url = f"{self.api_server_url}{flask_request.path}"

            # Handle different HTTP methods
            if method in ["POST", "PUT", "PATCH"]:
                data = flask_request.get_json(silent=True) or {}
                # REAL HTTP request with data
                response = requests.request(
                    method=method, url=url, json=data, headers=headers, timeout=10
                )
            else:
                # GET, DELETE, etc.
                response = requests.request(
                    method=method, url=url, headers=headers, timeout=10
                )

            # Log REAL API communication
            zta_logger.log_event(
                "REAL_API_REQUEST_SENT",
                {
                    "from": "gateway_server",
                    "to": "api_server",
                    "request_id": request_id,
                    "api_url": url,
                    "method": method,
                    "status_code": response.status_code,
                },
                user_id=user_claims.get("sub"),
                request_id=request_id,
            )

            return response

        except Exception as e:
            logger.error(f"[{request_id}] API Server communication failed: {e}")

            # Log error
            zta_logger.log_event(
                "API_COMMUNICATION_ERROR",
                {
                    "error": str(e),
                    "request_id": request_id,
                    "api_url": self.api_server_url,
                },
                request_id=request_id,
            )

            # Return error response
            return self._create_error_response(500, f"API Server unavailable: {str(e)}")

    def process_gateway_request(self, flask_request, user_claims):
        """
        Complete REAL flow for gateway server:
        Gateway (auth) → OPA → API Server → Gateway → User
        """
        request_id = str(uuid.uuid4())
        g.request_id = request_id  # Store in Flask's g

        logger.info(f"[{request_id}] === REAL ZTA FLOW START ===")
        logger.info(f"[{request_id}] User: {user_claims.get('username')}")
        logger.info(f"[{request_id}] Endpoint: {flask_request.path}")

        try:
            # Step 1: Query OPA for policy decision
            request_info = {
                "path": flask_request.path,
                "method": flask_request.method,
                "resource_type": self._extract_resource_type(flask_request.path),
            }

            opa_decision = self.query_opa_for_decision(
                user_claims, request_info, request_id
            )

            if not opa_decision.get("allow", False):
                logger.info(f"[{request_id}] OPA denied access")
                return self._create_denied_response(opa_decision, request_id)

            # Step 2: Forward to API Server
            api_response = self.forward_to_api_server(
                flask_request, user_claims, opa_decision, request_id
            )

            # Step 3: Process API response
            if api_response.status_code >= 400:
                logger.warning(
                    f"[{request_id}] API returned error: {api_response.status_code}"
                )

            # Convert API response to Flask response
            return self._convert_to_flask_response(api_response)

        except Exception as e:
            logger.error(f"[{request_id}] ZTA flow error: {e}")

            zta_logger.log_event(
                "ZTA_FLOW_ERROR",
                {
                    "error": str(e),
                    "request_id": request_id,
                    "flow_step": "gateway_processing",
                },
                request_id=request_id,
            )

            return self._create_error_response(
                500, f"Gateway processing error: {str(e)}"
            )
        finally:
            logger.info(f"[{request_id}] === REAL ZTA FLOW END ===")

    def _build_opa_input(self, user_claims, request_info, request_id):
        """Build OPA input for REAL policy evaluation"""
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
                "type": request_info.get("resource_type", "unknown"),
                "path": request_info.get("path"),
                "method": request_info.get("method"),
            },
            "action": request_info.get("method", "read").lower(),
            "environment": {
                "time": {
                    "hour": datetime.now().hour,
                    "weekday": datetime.now().strftime("%A"),
                    "weekend": datetime.now().weekday() >= 5,
                    "timestamp": datetime.now().isoformat(),
                },
                "ip_address": request.remote_addr if request else None,
            },
            "request_id": request_id,
            "authentication": {
                "method": user_claims.get("auth_method", "JWT"),
                "source": "gateway_server",
            },
        }

    def _build_api_headers(self, user_claims, opa_decision, request_id):
        """Build headers for API server request"""
        headers = {
            "Content-Type": "application/json",
            "X-Service-Token": self.api_service_token,  # REAL service token
            "X-Gateway-Token": self.gateway_service_token,
            "X-Request-ID": request_id,
            "X-User-Claims": json.dumps(user_claims),  # Send user claims
            "X-OPA-Decision": json.dumps(opa_decision),  # Send OPA decision
            "X-Forwarded-For": request.remote_addr if request else "unknown",
            "X-Forwarded-Host": request.host if request else "unknown",
        }

        # Preserve client certificate if present (for mTLS)
        if hasattr(g, "client_certificate"):
            cert_info = g.client_certificate
            headers["X-Client-Certificate-Info"] = json.dumps(
                {
                    "fingerprint": cert_info.get("fingerprint", "")[:16] + "...",
                    "email": cert_info.get("subject", {}).get("emailAddress"),
                }
            )

        return headers

    def _extract_resource_type(self, path):
        """Extract resource type from URL path"""
        if "/documents" in path:
            return "document"
        elif "/users" in path:
            return "user"
        elif "/logs" in path:
            return "log"
        else:
            return "unknown"

    def _convert_to_flask_response(self, requests_response):
        """Convert requests.Response to Flask response"""
        from flask import Response

        # Get content
        try:
            content = requests_response.json()
        except:
            content = requests_response.text

        # Create Flask response
        response = Response(
            response=json.dumps(content) if isinstance(content, dict) else content,
            status=requests_response.status_code,
            mimetype="application/json",
        )

        # Copy relevant headers
        for key, value in requests_response.headers.items():
            if key.lower() not in ["server", "date", "connection"]:
                response.headers[key] = value

        return response

    def _create_denied_response(self, opa_decision, request_id):
        """Create response for denied access"""
        from flask import jsonify

        zta_logger.log_event(
            "ACCESS_DENIED_BY_OPA",
            {
                "request_id": request_id,
                "opa_reason": opa_decision.get("reason", "Policy violation"),
                "opa_allow": opa_decision.get("allow", False),
            },
            request_id=request_id,
        )

        return (
            jsonify(
                {
                    "error": "Access denied",
                    "reason": opa_decision.get("reason", "Policy violation"),
                    "zta_context": {
                        "denied_by": "OPA_policy",
                        "request_id": request_id,
                        "flow": "User → Gateway → OPA → [DENIED]",
                    },
                }
            ),
            403,
        )

    def _create_error_response(self, status_code, message):
        """Create error response"""
        from flask import jsonify

        return (
            jsonify(
                {
                    "error": "Service communication failed",
                    "message": message,
                    "zta_context": {
                        "failed_component": "service_communicator",
                        "request_id": getattr(g, "request_id", "unknown"),
                    },
                }
            ),
            status_code,
        )

    def health_check(self):
        """Check health of all services"""
        health_status = {
            "gateway": "running",
            "opa": "unknown",
            "api_server": "unknown",
            "timestamp": datetime.now().isoformat(),
        }

        # Check OPA
        try:
            opa_response = requests.get(f"{self.opa_url}/health", timeout=3)
            health_status["opa"] = (
                "healthy" if opa_response.status_code == 200 else "unhealthy"
            )
        except:
            health_status["opa"] = "unreachable"

        # Check API Server
        try:
            api_response = requests.get(f"{self.api_server_url}/health", timeout=3)
            health_status["api_server"] = (
                "healthy" if api_response.status_code == 200 else "unhealthy"
            )
        except:
            health_status["api_server"] = "unreachable"

        return health_status

    def send_direct_to_api(self, endpoint, method="GET", data=None, user_claims=None):
        """
        Direct API call for internal use (bypassing OPA)
        Useful for service-to-service calls within the system
        """
        headers = {
            "Content-Type": "application/json",
            "X-Service-Token": self.api_service_token,
            "X-Internal-Call": "true",
        }

        if user_claims:
            headers["X-User-Claims"] = json.dumps(user_claims)

        url = f"{self.api_server_url}{endpoint}"

        try:
            if method in ["POST", "PUT", "PATCH"]:
                response = requests.request(
                    method, url, json=data, headers=headers, timeout=10
                )
            else:
                response = requests.request(method, url, headers=headers, timeout=10)

            return response
        except Exception as e:
            logger.error(f"Direct API call failed: {e}")
            return None


real_service_communicator = RealServiceCommunicator()


def init_service_communicator(app):
    """Initialize REAL service communicator"""
    real_service_communicator.init_app(app)


def get_service_communicator():
    """Get REAL service communicator instance"""
    return real_service_communicator


def process_gateway_request(request, user_claims):
    """
    Simple wrapper for gateway server to use
    Example usage in gateway_server.py:

    @app.route('/api/documents')
    def get_documents():
        user_claims = get_user_claims()  # From auth
        return process_gateway_request(request, user_claims)
    """
    communicator = get_service_communicator()
    return communicator.process_gateway_request(request, user_claims)
