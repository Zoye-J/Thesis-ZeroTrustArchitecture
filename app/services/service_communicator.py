"""
Service-to-Service Communication Handler
Manages communication between Server1, OPA Agent, and API Server
"""

import requests
import json
import uuid
from flask import current_app, request
import logging
from app.logs.zta_event_logger import zta_logger, EVENT_TYPES
import base64
import os

logger = logging.getLogger(__name__)


class ServiceCommunicator:
    def __init__(self):
        self.opa_url = None
        self.api_server_url = None
        self.service_token = None
        self._initialized = False

    def init_app(self, app):
        """Initialize with app config"""
        self.opa_url = app.config.get("OPA_URL", "http://localhost:8181")
        self.api_server_url = app.config.get("API_SERVER_URL", "http://localhost:5000")
        self.service_token = app.config.get("SERVICE_TOKEN", "server1-service-token")
        self._initialized = True
        logger.info(f"Service Communicator initialized")
        logger.info(f"OPA URL: {self.opa_url}")
        logger.info(f"API Server URL: {self.api_server_url}")

    def get_opa_decision(self, input_data, request_id):
        """
        Server1 → OPA Agent for verification
        """
        try:
            logger.info(
                f"[{request_id}] Server1 → OPA Agent: Requesting policy decision"
            )

            # Prepare OPA request with service token
            opa_headers = {
                "Content-Type": "application/json",
                "X-Service-Token": self.service_token,
                "X-Request-ID": request_id,
            }

            # Log the request
            zta_logger.log_event(
                "SERVICE_TO_OPA_REQUEST",
                {
                    "from": "server1",
                    "to": "opa-agent",
                    "request_id": request_id,
                    "resource_type": input_data.get("resource", {}).get("type"),
                    "user": input_data.get("user", {}).get("username"),
                },
                request_id=request_id,
            )

            # Send to OPA
            response = requests.post(
                f"{self.opa_url}/v1/data/zta/decision",
                json={"input": input_data},
                headers=opa_headers,
                timeout=5,
            )

            if response.status_code == 200:
                result = response.json().get("result", {})
                logger.info(f"[{request_id}] OPA Agent → Server1: Decision received")

                zta_logger.log_event(
                    "OPA_TO_SERVICE_RESPONSE",
                    {
                        "from": "opa-agent",
                        "to": "server1",
                        "request_id": request_id,
                        "decision": result.get("allow", False),
                        "reason": result.get("reason", "No reason provided"),
                    },
                    request_id=request_id,
                )

                return result
            else:
                logger.error(
                    f"[{request_id}] OPA request failed: {response.status_code}"
                )
                return {"allow": False, "reason": f"OPA error: {response.status_code}"}

        except Exception as e:
            logger.error(f"[{request_id}] OPA communication error: {e}")
            return {"allow": False, "reason": f"OPA communication error: {str(e)}"}

    def forward_to_api_server(self, original_request, opa_decision, request_id):
        """
        OPA Agent → API Server (if OPA allows)
        Only Server1 and OPA Agent can communicate with API Server with valid tokens
        """
        try:
            if not opa_decision.get("allow", False):
                logger.info(
                    f"[{request_id}] OPA denied access, not forwarding to API Server"
                )
                return None

            logger.info(
                f"[{request_id}] OPA Agent → API Server: Forwarding allowed request"
            )

            # Get the original request details
            method = original_request.method
            endpoint = original_request.path
            data = original_request.get_json(silent=True) or {}

            # Prepare API Server request with service token
            api_headers = {
                "Content-Type": "application/json",
                "X-Service-Token": self.service_token,
                "X-Request-ID": request_id,
                "X-OPA-Decision": json.dumps(opa_decision),
            }

            # Preserve original auth headers if present
            if "Authorization" in original_request.headers:
                api_headers["Authorization"] = original_request.headers["Authorization"]

            # Add certificate info for mTLS requests
            if (
                hasattr(original_request, "environ")
                and "SSL_CLIENT_CERT" in original_request.environ
            ):
                cert_pem = original_request.environ["SSL_CLIENT_CERT"]
                if cert_pem:
                    api_headers["X-Client-Certificate"] = base64.b64encode(
                        cert_pem.encode()
                    ).decode()

            zta_logger.log_event(
                "OPA_TO_API_REQUEST",
                {
                    "from": "opa-agent",
                    "to": "api-server",
                    "request_id": request_id,
                    "method": method,
                    "endpoint": endpoint,
                    "opa_decision": opa_decision,
                },
                request_id=request_id,
            )

            # Forward to API Server
            api_url = f"{self.api_server_url}{endpoint}"

            if method == "GET":
                response = requests.get(api_url, headers=api_headers, timeout=10)
            elif method == "POST":
                response = requests.post(
                    api_url, json=data, headers=api_headers, timeout=10
                )
            elif method == "PUT":
                response = requests.put(
                    api_url, json=data, headers=api_headers, timeout=10
                )
            elif method == "DELETE":
                response = requests.delete(api_url, headers=api_headers, timeout=10)
            else:
                return None

            logger.info(
                f"[{request_id}] API Server → OPA Agent: Response received: {response.status_code}"
            )

            zta_logger.log_event(
                "API_TO_OPA_RESPONSE",
                {
                    "from": "api-server",
                    "to": "opa-agent",
                    "request_id": request_id,
                    "status_code": response.status_code,
                    "success": response.status_code < 400,
                },
                request_id=request_id,
            )

            return response

        except Exception as e:
            logger.error(f"[{request_id}] API Server communication error: {e}")
            zta_logger.log_event(
                "API_COMMUNICATION_ERROR",
                {
                    "error": str(e),
                    "request_id": request_id,
                    "from": "opa-agent",
                    "to": "api-server",
                },
                request_id=request_id,
            )
            return None

    def return_to_user(self, api_response, request_id):
        """
        API Server → Server1 → User
        """
        try:
            if not api_response:
                logger.info(f"[{request_id}] No API response to return to user")
                return {
                    "status_code": 500,
                    "content": {"error": "Service communication failed"},
                    "headers": {},
                }

            logger.info(f"[{request_id}] Server1 → User: Returning final response")

            # Extract response data
            status_code = api_response.status_code

            try:
                content = api_response.json()
            except:
                content = {"data": api_response.text}

            # Filter sensitive headers
            headers = {}
            for key, value in api_response.headers.items():
                if key.lower() not in ["server", "date", "connection"]:
                    headers[key] = value

            zta_logger.log_event(
                "SERVICE_TO_USER_RESPONSE",
                {
                    "from": "server1",
                    "to": "user",
                    "request_id": request_id,
                    "status_code": status_code,
                    "response_size": len(str(content)),
                },
                request_id=request_id,
            )

            return {"status_code": status_code, "content": content, "headers": headers}

        except Exception as e:
            logger.error(f"[{request_id}] Error returning to user: {e}")
            return {
                "status_code": 500,
                "content": {"error": "Failed to process response"},
                "headers": {},
            }

    def process_user_request(
        self, user_claims, resource_info, action, original_request
    ):
        """
        Complete flow: User → Server1 → OPA Agent → API Server → Server1 → User
        """
        request_id = str(uuid.uuid4())

        logger.info(f"=== START ZTA FLOW [{request_id}] ===")
        logger.info(f"User: {user_claims.get('username')}")
        logger.info(f"Action: {action} on {resource_info.get('type')}")

        try:
            # Step 1: User → Server1 (already happened, we're in Server1)

            # Step 2: Server1 → OPA Agent
            opa_input = self._prepare_opa_input(
                user_claims, resource_info, action, request_id
            )
            opa_decision = self.get_opa_decision(opa_input, request_id)

            if not opa_decision.get("allow", False):
                logger.info(f"[{request_id}] OPA denied access, stopping flow")
                return self._create_denied_response(opa_decision, request_id)

            # Step 3: OPA Agent → API Server
            api_response = self.forward_to_api_server(
                original_request, opa_decision, request_id
            )

            if not api_response:
                logger.error(f"[{request_id}] Failed to get API response")
                return {
                    "status_code": 500,
                    "content": {"error": "Service unavailable"},
                    "headers": {},
                }

            # Step 4: API Server → Server1 → User
            final_response = self.return_to_user(api_response, request_id)

            logger.info(f"=== END ZTA FLOW [{request_id}] ===")

            return final_response

        except Exception as e:
            logger.error(f"[{request_id}] ZTA flow error: {e}")
            zta_logger.log_event(
                "ZTA_FLOW_ERROR",
                {
                    "error": str(e),
                    "request_id": request_id,
                    "flow_step": "unknown",
                },
                request_id=request_id,
            )
            return {
                "status_code": 500,
                "content": {"error": "ZTA processing failed"},
                "headers": {},
            }

    def _prepare_opa_input(self, user_claims, resource_info, action, request_id):
        """Prepare OPA input data"""
        from datetime import datetime

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
            "resource": resource_info,
            "action": action,
            "environment": {
                "time": {
                    "hour": datetime.now().hour,
                    "weekday": datetime.now().strftime("%A"),
                    "weekend": datetime.now().weekday() >= 5,
                },
                "ip_address": request.remote_addr if request else None,
            },
            "request_id": request_id,
            "authentication": {
                "method": user_claims.get("auth_method", "JWT"),
                "service_communication": True,
                "source": "server1",
            },
        }

    def _create_denied_response(self, opa_decision, request_id):
        """Create response for denied access"""
        zta_logger.log_event(
            "ACCESS_DENIED_FINAL",
            {
                "request_id": request_id,
                "opa_reason": opa_decision.get("reason", "No reason provided"),
                "flow_stopped_at": "opa_verification",
            },
            request_id=request_id,
        )

        return {
            "status_code": 403,
            "content": {
                "error": "Access denied",
                "reason": opa_decision.get("reason", "Policy violation"),
                "zta_context": {
                    "flow": "User → Server1 → OPA Agent → [DENIED]",
                    "request_id": request_id,
                    "opa_decision": opa_decision,
                },
            },
            "headers": {},
        }


# Global instance
service_communicator = ServiceCommunicator()


def init_service_communicator(app):
    """Initialize service communicator"""
    service_communicator.init_app(app)


def get_service_communicator():
    return service_communicator
