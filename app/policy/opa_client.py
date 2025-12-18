"""
Open Policy Agent (OPA) Client for ZTA System
"""

import requests
import json
import uuid
from flask import current_app, request
from datetime import datetime
from app.logs.request_logger import log_request
import logging
from app.logs.zta_event_logger import zta_logger, EVENT_TYPES


logger = logging.getLogger(__name__)


class OPAClient:
    def __init__(self, opa_url=None, timeout=5):
        # Don't use current_app.config here - will be set later
        self.opa_url = opa_url or "http://localhost:8181"
        self.timeout = timeout
        self._initialized = False

    def init_app(self, app):
        """Initialize with Flask app config"""
        self.opa_url = app.config.get("OPA_URL", "http://localhost:8181")
        self.timeout = app.config.get("OPA_TIMEOUT", 5)
        self._initialized = True
        logger.info(f"OPA Client initialized with URL: {self.opa_url}")

    def health_check(self):
        """Check if OPA server is healthy"""
        try:
            response = requests.get(f"{self.opa_url}/health", timeout=self.timeout)
            return response.status_code == 200
        except requests.exceptions.RequestException as e:
            logger.error(f"OPA health check failed: {e}")
            return False

    def evaluate_policy(self, input_data, policy_path="zta/allow"):
        try:
            zta_logger.log_event(
                EVENT_TYPES["OPA_QUERY_SENT"],
                {
                    "policy_path": policy_path,
                    "input_summary": {
                        "user": input_data.get("user", {}).get("username"),
                        "resource": input_data.get("resource", {}).get("type"),
                        "action": input_data.get("action"),
                        "auth_method": input_data.get("authentication", {}).get(
                            "method"
                        ),
                    },
                },
                user_id=input_data.get("user", {}).get("id"),
                request_id=input_data.get("request_id"),
            )
            url = f"{self.opa_url}/v1/data/{policy_path}"

            logger.debug(f"OPA Request to {url}")

            response = requests.post(
                url,
                json={"input": input_data},
                timeout=self.timeout,
                headers={"Content-Type": "application/json"},
            )

            logger.debug(f"OPA Response Status: {response.status_code}")

            if response.status_code == 200:
                result = response.json()
                decision_id = response.headers.get("X-Decision-Id", "unknown")

                # OPA returns {"result": true/false} for allow policies
                allowed = result.get("result", False)

                # Try to get reason from decision if available
                if isinstance(result, dict) and "decision" in result:
                    decision = result["decision"]
                    reason = decision.get("reason", "Policy evaluation complete")
                else:
                    reason = "Policy evaluation complete"

                return allowed, reason, decision_id

            elif response.status_code == 404:
                logger.error(f"OPA policy path not found: {policy_path}")
                return False, f"Policy path '{policy_path}' not found", None
            else:
                logger.error(
                    f"OPA request failed with status {response.status_code}: {response.text}"
                )
                return False, f"OPA server error: {response.status_code}", None

        except requests.exceptions.Timeout:
            logger.error(f"OPA request timeout after {self.timeout}s")
            return False, "OPA evaluation timeout", None
        except requests.exceptions.RequestException as e:
            logger.error(f"OPA request failed: {e}")
            return False, f"OPA communication error: {str(e)}", None
        except Exception as e:
            logger.error(f"Unexpected error in OPA evaluation: {e}")
            return False, f"Policy evaluation error: {str(e)}", None

    def evaluate_document_access(self, user_claims, document, action):
        """
        Evaluate document access policy

        Args:
            user_claims: JWT claims dictionary
            document: Document object or dictionary
            action: string - 'read', 'write', 'delete', 'create'

        Returns:
            tuple: (allowed: bool, reason: str, decision_id: str)
        """
        # Prepare input for OPA
        if hasattr(document, "to_dict"):
            doc_dict = document.to_dict()
        else:
            doc_dict = document

        input_data = {
            "user": {
                "id": user_claims.get("sub"),
                "username": user_claims.get("username", user_claims.get("sub")),
                "role": user_claims.get("user_class"),
                "department": user_claims.get("department"),
                "facility": user_claims.get("facility"),
                "clearance": user_claims.get("clearance_level", "BASIC"),
            },
            "resource": {
                "type": "document",
                "id": doc_dict.get("id"),
                "classification": doc_dict.get("classification"),
                "department": doc_dict.get("department"),
                "facility": doc_dict.get("facility"),
                "owner": doc_dict.get("owner_id"),
            },
            "action": action,
            "environment": {
                "time": {
                    "hour": datetime.now().hour,
                    "day_of_week": datetime.now().strftime("%A"),
                    "weekend": datetime.now().weekday() >= 5,
                },
                "ip_address": request.remote_addr if request else None,
                "user_agent": (
                    request.user_agent.string
                    if request and request.user_agent
                    else None
                ),
            },
            "request_id": user_claims.get("request_id", "unknown"),
        }

        return self.evaluate_policy(input_data)

    def evaluate_user_management(self, admin_claims, target_user, action):
        """
        Evaluate user management policy

        Args:
            admin_claims: Admin user JWT claims
            target_user: Target user object or dictionary
            action: string - 'create', 'update', 'delete', 'promote'

        Returns:
            tuple: (allowed: bool, reason: str, decision_id: str)
        """
        if hasattr(target_user, "to_dict"):
            target_dict = target_user.to_dict()
        else:
            target_dict = target_user

        input_data = {
            "user": {
                "id": admin_claims.get("sub"),
                "role": admin_claims.get("user_class"),
                "department": admin_claims.get("department"),
                "facility": admin_claims.get("facility"),
                "clearance": admin_claims.get("clearance_level", "BASIC"),
            },
            "resource": {
                "type": "user",
                "id": target_dict.get("id"),
                "role": target_dict.get("user_class"),
                "department": target_dict.get("department"),
                "facility": target_dict.get("facility"),
            },
            "action": action,
            "environment": {"time": {"hour": datetime.now().hour}},
            "request_id": admin_claims.get("request_id", "unknown"),
        }

        return self.evaluate_policy(input_data, policy_path="zta/user_management")

    def build_zta_input(self, user, resource, action, request, auth_method="JWT"):
        """Build OPA input with ZTA authentication data"""

        # Extract certificate info if present
        certificate_info = None
        if hasattr(request, "client_certificate"):
            cert_info = request.client_certificate
            certificate_info = {
                "subject": cert_info.get("subject", {}),
                "issuer": cert_info.get("issuer", {}),
                "fingerprint": cert_info.get("fingerprint"),
                "not_valid_before": cert_info.get("not_valid_before"),
                "not_valid_after": cert_info.get("not_valid_after"),
                "keyUsage": {"clientAuth": True},
            }

        # Determine authentication method
        if auth_method == "mTLS_JWT":
            auth_strength = "mTLS_JWT"
        elif auth_method == "mTLS_service":
            auth_strength = "mTLS_service"
        else:
            auth_strength = "JWT"

        return {
            "input": {
                "user": user.to_dict() if user else None,
                "resource": resource,
                "action": action,
                "environment": {
                    "time": {
                        "hour": datetime.now().hour,
                        "weekend": datetime.now().weekday() >= 5,
                    },
                    "ip": request.remote_addr,
                },
                "authentication": {
                    "method": auth_strength,
                    "certificate": certificate_info,
                    "jwt_valid": auth_method in ["JWT", "mTLS_JWT"],
                },
                "request_id": request.headers.get("X-Request-ID", str(uuid.uuid4())),
            }
        }

    def evaluate_time_based_policies(self, input_data):
        """Evaluate time-based policies specifically"""
        try:
            response = requests.post(
                f"{self.opa_url}/v1/data/time_based/enhanced_decision",
                json={"input": input_data},
                timeout=self.timeout,
                headers={"Content-Type": "application/json"},
            )

            if response.status_code == 200:
                return response.json().get("result", {"allow": False})
            else:
                logger.error(
                    f"Time-based policy evaluation failed: {response.status_code}"
                )
                return {"allow": False, "reason": "Time policy evaluation failed"}

        except Exception as e:
            logger.error(f"Error evaluating time-based policies: {e}")
            return {"allow": False, "reason": f"Time policy error: {str(e)}"}

    def evaluate_zta_policies(self, input_data):
        """Evaluate ZTA policies"""
        try:
            response = requests.post(
                f"{self.opa_url}/v1/data/zta/decision",
                json={"input": input_data},
                timeout=self.timeout,
                headers={"Content-Type": "application/json"},
            )

            if response.status_code == 200:
                result = response.json().get("result", {})
                if isinstance(result, bool):
                    return {"allow": result, "reason": "Policy evaluation complete"}
                else:
                    return result
            else:
                logger.error(f"ZTA policy evaluation failed: {response.status_code}")
                return {"allow": False, "reason": "ZTA policy evaluation failed"}

        except Exception as e:
            logger.error(f"Error evaluating ZTA policies: {e}")
            return {"allow": False, "reason": f"ZTA policy error: {str(e)}"}

    def evaluate_with_time_restrictions(self, input_data, request_id=None):
        """Evaluate policy with time-based restrictions"""
        from app.logs.zta_event_logger import zta_logger

        # Add time context to input
        if "environment" not in input_data:
            input_data["environment"] = {}

        # Add current time
        import datetime

        now = datetime.datetime.utcnow()
        input_data["environment"]["time"] = {
            "hour": now.hour,
            "minute": now.minute,
            "weekday": now.strftime("%A"),
            "weekend": now.weekday() >= 5,  # Saturday=5, Sunday=6
            "iso": now.isoformat(),
        }

        # Log time context
        if request_id:
            zta_logger.log_event(
                "TIME_CONTEXT_ADDED",
                {
                    "time_context": input_data["environment"]["time"],
                    "classification": input_data.get("resource", {}).get(
                        "classification", "unknown"
                    ),
                    "restriction_applies": input_data.get("resource", {}).get(
                        "classification"
                    )
                    == "TOP_SECRET",
                },
                request_id=request_id,
            )

        # First evaluate time-based policies using the instance method
        time_result = self.evaluate_time_based_policies(input_data)

        # Log time-based decision
        if request_id:
            zta_logger.log_event(
                "TIME_BASED_EVALUATION",
                {
                    "result": time_result,
                    "resource_classification": input_data.get("resource", {}).get(
                        "classification", "unknown"
                    ),
                    "current_hour": now.hour,
                },
                request_id=request_id,
            )

        if not time_result.get("allow", False):
            # Time restriction applied
            return time_result

        # If time allows, evaluate main ZTA policies
        zta_result = self.evaluate_zta_policies(input_data)

        # Combine results
        combined_result = {
            **zta_result,
            "time_based_restrictions": time_result.get("time_context", {}),
            "overall_allow": zta_result.get("allow", False)
            and time_result.get("allow", False),
        }

        return combined_result


# Create instance but don't initialize with config yet
opa_client_instance = OPAClient("http://localhost:8181")


def init_opa_client(app):
    """Initialize OPA client with Flask app"""
    opa_client_instance.init_app(app)


# Function to get the client (for imports)
def get_opa_client():
    return opa_client_instance


# Standalone function for backward compatibility
def evaluate_with_time_restrictions(input_data, request_id=None):
    """Standalone function to evaluate policies with time restrictions"""
    return opa_client_instance.evaluate_with_time_restrictions(input_data, request_id)
