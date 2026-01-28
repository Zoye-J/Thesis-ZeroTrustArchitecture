# app/opa_agent/agent.py
import json
import requests
from flask import current_app
import logging
from app.opa_agent.crypto_handler import CryptoHandler

logger = logging.getLogger(__name__)


class OpaAgent:
    def __init__(self):
        self.crypto = CryptoHandler()
        # Try to load existing keys, generate if not exist
        self.agent_private_key, self.agent_public_key = self._load_or_generate_keys()
        self.opa_url = "https://localhost:8181"
        self.api_server_url = "https://localhost:5001"
        logger.info("OPA Agent initialized")

    def _load_or_generate_keys(self):
        """Load existing keys or generate new ones"""
        import os
        from app.mTLS.cert_manager import cert_manager

        # Try to load from certs/opa_agent directory
        opa_agent_dir = os.path.join(cert_manager.cert_dir, "opa_agent")
        private_key_path = os.path.join(opa_agent_dir, "private.pem")
        public_key_path = os.path.join(opa_agent_dir, "public.pem")

        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            try:
                with open(private_key_path, "r") as f:
                    private_key = f.read()
                with open(public_key_path, "r") as f:
                    public_key = f.read()
                logger.info("Loaded existing OPA Agent keys")
                return private_key, public_key
            except Exception as e:
                logger.warning(f"Failed to load existing keys: {e}")

        # Generate new keys
        logger.info("Generating new OPA Agent keys")
        return self.crypto.generate_key_pair()

    def decrypt_request(self, encrypted_data):
        """Decrypt incoming request from Gateway"""
        try:
            return self.crypto.decrypt_from_user(encrypted_data, self.agent_private_key)
        except Exception as e:
            logger.error(f"Failed to decrypt request: {e}")
            raise

    def evaluate_with_risk(self, request_data):
        """Evaluate request with risk scoring"""
        from app.services.risk_scorer import RiskScorer

        # Calculate risk score
        scorer = RiskScorer()
        resource_sensitivity = request_data.get("resource", {}).get(
            "classification", "PUBLIC"
        )
        risk_score = scorer.calculate_risk(request_data, resource_sensitivity)
        risk_level = scorer.get_risk_level(risk_score)

        # Add risk to request data
        request_data["risk"] = {
            "score": risk_score,
            "level": risk_level,
            "threshold": 50,  # Score above 50 requires additional checks
        }

        print(f"📊 Risk Score: {risk_score} ({risk_level})")

        # Call OPA Server with risk info
        opa_input = {
            "input": {
                **request_data,
                "risk_score": risk_score,
                "risk_level": risk_level,
            }
        }

        # Send to OPA Server
        response = requests.post(
            "https://localhost:8181/v1/data/zta/allow", json=opa_input, timeout=5
        )

        if response.status_code == 200:
            result = response.json()
            result["risk_assessment"] = {
                "score": risk_score,
                "level": risk_level,
                "factors_considered": ["time", "location", "device", "authentication"],
            }
            return result

        return {"allow": False, "reason": "OPA Server error"}

    def encrypt_response(self, data, user_public_key):
        """Encrypt response for specific user"""
        try:
            return self.crypto.encrypt_for_user(json.dumps(data), user_public_key)
        except Exception as e:
            logger.error(f"Failed to encrypt response: {e}")
            raise

    def query_opa_server(self, request_data):
        """Forward request to OPA Server for policy evaluation"""
        try:
            logger.info(f"Querying OPA Server: {self.opa_url}")

            # Prepare input for OPA
            opa_input = self._prepare_opa_input(request_data)

            # Use session with SSL verification disabled (for self-signed certs)
            import requests

            session = requests.Session()
            session.verify = False  # Disable SSL verification for self-signed certs

            response = session.post(
                f"{self.opa_url}/v1/data/zta/allow",
                json={"input": opa_input},
                timeout=5,
            )

            if response.status_code == 200:
                result = response.json()
                logger.info(f"OPA Server response: {result}")
                return result
            else:
                logger.error(
                    f"OPA Server error: {response.status_code} - {response.text}"
                )
                return {
                    "result": False,
                    "reason": f"OPA Server error: {response.status_code}",
                }

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to connect to OPA Server: {e}")
            return {"result": False, "reason": f"OPA Server unavailable: {str(e)}"}

    def call_api_server(self, request_info):
        """Call API Server after OPA approval"""
        try:
            # Extract the actual API endpoint and method
            endpoint = request_info.get("endpoint", "/api/documents")
            method = request_info.get("method", "GET").upper()
            data = request_info.get("data")
            user_claims = request_info.get("user", {})

            logger.info(f"Calling API Server: {method} {endpoint}")

            # Prepare headers for API Server
            headers = {
                "Content-Type": "application/json",
                "X-Service-Token": "opa-agent-service-token",
                "X-Request-ID": request_info.get("request_id", "unknown"),
                "X-User-Claims": json.dumps(user_claims),
                "X-Forwarded-By": "OPA-Agent",
            }

            # Make the request to API Server
            if method == "POST":
                response = requests.post(
                    f"{self.api_server_url}{endpoint}",
                    json=data,
                    headers=headers,
                    timeout=10,
                    verify=False,  # For self-signed certs
                )
            elif method == "PUT":
                response = requests.put(
                    f"{self.api_server_url}{endpoint}",
                    json=data,
                    headers=headers,
                    timeout=10,
                    verify=False,
                )
            elif method == "DELETE":
                response = requests.delete(
                    f"{self.api_server_url}{endpoint}",
                    headers=headers,
                    timeout=10,
                    verify=False,
                )
            else:  # GET
                response = requests.get(
                    f"{self.api_server_url}{endpoint}",
                    headers=headers,
                    timeout=10,
                    verify=False,
                )

            logger.info(f"API Server response status: {response.status_code}")

            # Prepare response
            api_response = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "success": 200 <= response.status_code < 300,
            }

            try:
                if response.headers.get("Content-Type", "").startswith(
                    "application/json"
                ):
                    api_response["data"] = response.json()
                else:
                    api_response["data"] = response.text
            except:
                api_response["data"] = response.text

            return api_response

        except requests.exceptions.Timeout:
            logger.error("API Server request timeout")
            return {"status_code": 504, "error": "API Server timeout", "success": False}
        except requests.exceptions.RequestException as e:
            logger.error(f"API Server connection failed: {e}")
            return {
                "status_code": 503,
                "error": f"API Server unavailable: {str(e)}",
                "success": False,
            }
        except Exception as e:
            logger.error(f"Unexpected error calling API Server: {e}")
            return {
                "status_code": 500,
                "error": f"Internal error: {str(e)}",
                "success": False,
            }

    def _prepare_opa_input(self, request_data):
        """Prepare input data for OPA Server"""
        user = request_data.get("user", {})
        resource_type = self._extract_resource_type(request_data.get("endpoint", ""))

        return {
            "user": {
                "id": user.get("sub") or user.get("id"),
                "username": user.get("username"),
                "role": user.get("user_class") or user.get("role", "user"),
                "department": user.get("department", ""),
                "facility": user.get("facility", ""),
                "clearance": user.get("clearance_level")
                or user.get("clearance", "BASIC"),
                "email": user.get("email", ""),
            },
            "resource": {
                "type": resource_type,
                "path": request_data.get("endpoint", ""),
                "method": request_data.get("method", "GET"),
            },
            "action": request_data.get("method", "GET").lower(),
            "environment": {
                "time": request_data.get("timestamp"),
                "source": "opa_agent",
            },
            "request_id": request_data.get("request_id", "unknown"),
        }

    def _extract_resource_type(self, endpoint):
        """Extract resource type from endpoint"""
        if "/documents" in endpoint:
            return "document"
        elif "/users" in endpoint:
            return "user"
        elif "/logs" in endpoint:
            return "log"
        elif "/auth" in endpoint:
            return "auth"
        else:
            return "unknown"

    def get_public_key(self):
        """Get OPA Agent's public key"""
        return self.agent_public_key

    def health_check(self):
        """Check health of OPA Agent dependencies"""
        health = {
            "agent": "running",
            "opa_server": "unknown",
            "api_server": "unknown",
            "encryption": "available",
        }

        # Check OPA Server
        try:
            response = requests.get(f"{self.opa_url}/health", timeout=3)
            health["opa_server"] = (
                "healthy" if response.status_code == 200 else "unhealthy"
            )
        except:
            health["opa_server"] = "unreachable"

        # Check API Server
        try:
            response = requests.get(
                f"{self.api_server_url}/health", timeout=3, verify=False
            )
            health["api_server"] = (
                "healthy" if response.status_code == 200 else "unhealthy"
            )
        except:
            health["api_server"] = "unreachable"

        return health

    def process_request(self, encrypted_request, user_public_key, request_id):
        """
        Complete request processing:
        1. Decrypt request
        2. Query OPA Server
        3. If allowed, call API Server
        4. Encrypt response
        """
        try:
            logger.info(f"[{request_id}] Starting OPA Agent processing")

            # Step 1: Decrypt request
            decrypted_data = self.decrypt_request(encrypted_request)
            request_info = json.loads(decrypted_data)
            request_info["request_id"] = request_id

            logger.info(
                f"[{request_id}] Decrypted request from user: {request_info.get('user', {}).get('username')}"
            )

            # Step 2: Query OPA Server
            opa_result = self.query_opa_server(request_info)

            # Check OPA decision
            if not opa_result.get("result", False):
                logger.info(
                    f"[{request_id}] OPA denied access: {opa_result.get('reason', 'No reason')}"
                )
                response_data = {
                    "allowed": False,
                    "reason": opa_result.get("reason", "Access denied by policy"),
                    "opa_result": opa_result,
                    "request_id": request_id,
                }
            else:
                # Step 3: Call API Server
                logger.info(f"[{request_id}] OPA allowed access, calling API Server")
                api_response = self.call_api_server(request_info)

                response_data = {
                    "allowed": True,
                    "api_response": api_response,
                    "opa_result": opa_result,
                    "request_id": request_id,
                }

            # Step 4: Encrypt response
            encrypted_response = self.encrypt_response(response_data, user_public_key)

            logger.info(f"[{request_id}] OPA Agent processing complete")

            return {
                "encrypted_response": encrypted_response,
                "request_id": request_id,
                "agent_timestamp": request_id,
            }

        except json.JSONDecodeError as e:
            logger.error(f"[{request_id}] Invalid JSON in request: {e}")
            raise ValueError(f"Invalid request data: {str(e)}")
        except Exception as e:
            logger.error(f"[{request_id}] OPA Agent processing failed: {e}")
            raise
