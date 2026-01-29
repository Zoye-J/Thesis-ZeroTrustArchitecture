# app/policy/opa_client.py - FIXED VERSION FOR YOUR POLICIES
import requests
import json
import uuid
import sys
import os
from flask import current_app, request
from datetime import datetime
import logging
from app.logs.zta_event_logger import event_logger, EventType  # CHANGED HERE

# Apply SSL fix BEFORE any imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from app.ssl_fix import create_fixed_ssl_context
except ImportError:
    print("⚠️ SSL fix module not available for OPA client")


logger = logging.getLogger(__name__)


class OPAClient:
    def __init__(self, opa_url=None, timeout=5):
        self.opa_url = opa_url or "https://localhost:8181"
        self.timeout = timeout
        self._initialized = False
        self.ca_cert_path = "certs/ca.crt"
        logger.info(f"OPA Client initialized with URL: {self.opa_url}")

    def init_app(self, app):
        """Initialize with Flask app config"""
        self.opa_url = app.config.get("OPA_URL", "https://localhost:8181")
        self.timeout = app.config.get("OPA_TIMEOUT", 5)
        self._initialized = True
        logger.info(f"OPA Client configured with URL: {self.opa_url}")

    def health_check(self):
        """Check if OPA server is healthy"""
        try:
            response = requests.get(f"{self.opa_url}/health", timeout=self.timeout)
            return response.status_code == 200
        except requests.exceptions.RequestException as e:
            logger.error(f"OPA health check failed: {e}")
            return False

    def evaluate_document_access(self, user_claims, document, action="read"):
        try:
            # Prepare document data
            if hasattr(document, "to_dict"):
                doc_dict = document.to_dict()
            elif isinstance(document, dict):
                doc_dict = document
            else:
                doc_dict = {"id": str(document)}
            # Get current time for time-based policies
            now = datetime.now()
            current_hour = now.hour
            is_weekend = now.weekday() >= 5  # Saturday=5, Sunday=6

            # Prepare input for OPA based on your policies.rego structure
            input_data = {
                "user": {
                    "id": user_claims.get("id") or user_claims.get("sub"),
                    "username": user_claims.get("username"),
                    "role": user_claims.get("user_class")
                    or user_claims.get("role", "user"),
                    "department": user_claims.get("department", "unknown"),
                    "facility": user_claims.get("facility", "unknown"),
                    "clearance": user_claims.get("clearance_level")
                    or user_claims.get("clearance", "BASIC"),
                    "email": user_claims.get("email", "unknown@example.gov"),
                },
                "resource": {
                    "type": "document",
                    "id": doc_dict.get("id"),
                    "document_id": doc_dict.get(
                        "document_id", f"doc_{doc_dict.get('id')}"
                    ),
                    "classification": doc_dict.get("classification", "BASIC"),
                    "department": doc_dict.get("department", "unknown"),
                    "facility": doc_dict.get("facility", "unknown"),
                    "category": doc_dict.get("category", "general"),
                    "owner_id": doc_dict.get("owner_id"),
                },
                "action": action,
                "environment": {
                    "time": {
                        "hour": current_hour,
                        "minute": now.minute,
                        "day_of_week": now.strftime("%A"),
                        "weekend": is_weekend,
                        "string": now.strftime("%H:%M"),
                    },
                    "ip_address": request.remote_addr if request else "127.0.0.1",
                },
                "authentication": {
                    "method": "JWT",  # Default for web access
                    "jwt": {
                        "valid": True,
                        "email": user_claims.get("email", "unknown@example.gov"),
                    },
                    "certificate": None,  # No mTLS for web UI
                },
                "request_id": str(uuid.uuid4())[:8],
            }

            # Log the ZTA flow step (MINIMAL - just key info)
            logger.info(
                f"🔐 ZTA Flow for doc {doc_dict.get('id')} ({doc_dict.get('classification')})"
            )

            # STEP 1: Forward to OPA Agent
            logger.info(f"📡 Querying OPA at {self.opa_url}")

            # Query OPA using your policies.rego structure
            result = self._query_opa_policy(input_data, "zta/allow")

            # STEP 2: Process OPA Decision
            if result and "result" in result:
                # Handle both boolean and dictionary responses
                if isinstance(result["result"], bool):
                    # Boolean response (like your logs show)
                    allowed = result["result"]
                    reason = result.get("reason", "Policy evaluation complete")

                    # Try to get decision details
                    decision_info = result.get("decision", {})
                    if isinstance(decision_info, dict):
                        reason = decision_info.get("reason", reason)

                    logger.info(
                        f"📊 OPA Decision: {'ALLOWED ✅' if allowed else 'DENIED ❌'} - {reason}"
                    )

                    # Log event
                    event_logger.log_event(
                        event_type=(
                            EventType.POLICY_ALLOW if allowed else EventType.POLICY_DENY
                        ),
                        source_component="OPA",
                        action="Document access evaluation",
                        user_id=user_claims.get("id") or user_claims.get("sub"),
                        username=user_claims.get("username"),
                        resource=doc_dict.get("document_id"),
                        details={
                            "document_id": doc_dict.get("document_id"),
                            "classification": doc_dict.get("classification"),
                            "reason": reason,
                            "opa_result": result,
                        },
                        status="success" if allowed else "failure",
                        trace_id=input_data.get("request_id"),
                    )

                    return {
                        "allowed": allowed,
                        "reason": reason,
                        "opa_response": result,
                        "zta_flow": {
                            "step1": "✅ JWT Auth",
                            "step2": "✅ OPA Query",
                            "step3": f"✅ {'ALLOWED' if allowed else 'DENIED'}",
                            "timestamp": datetime.utcnow().isoformat(),
                            "opa_agent_contacted": True,
                        },
                        "user_context": {
                            "username": user_claims.get("username"),
                            "role": user_claims.get("user_class"),
                            "clearance": user_claims.get("clearance_level"),
                        },
                        "resource_context": {
                            "document_id": doc_dict.get("document_id"),
                            "classification": doc_dict.get("classification"),
                        },
                    }

                elif isinstance(result["result"], dict):
                    # Dictionary response (your original expectation)
                    opa_result = result["result"]
                    allowed = opa_result.get("allow", False)
                    reason = opa_result.get("reason", "Policy evaluation complete")

                    logger.info(
                        f"📊 OPA Decision: {'ALLOWED ✅' if allowed else 'DENIED ❌'} - {reason}"
                    )

                    # Log event
                    event_logger.log_event(
                        event_type=(
                            EventType.POLICY_ALLOW if allowed else EventType.POLICY_DENY
                        ),
                        source_component="OPA",
                        action="Document access evaluation",
                        user_id=user_claims.get("id") or user_claims.get("sub"),
                        username=user_claims.get("username"),
                        resource=doc_dict.get("document_id"),
                        details={
                            "document_id": doc_dict.get("document_id"),
                            "classification": doc_dict.get("classification"),
                            "reason": reason,
                            "opa_result": opa_result,
                        },
                        status="success" if allowed else "failure",
                        trace_id=input_data.get("request_id"),
                    )

                    return {
                        "allowed": allowed,
                        "reason": reason,
                        "opa_response": opa_result,
                        "zta_flow": {
                            "step1": "✅ JWT Auth",
                            "step2": "✅ OPA Query",
                            "step3": f"✅ {'ALLOWED' if allowed else 'DENIED'}",
                            "timestamp": datetime.utcnow().isoformat(),
                            "opa_agent_contacted": True,
                        },
                        "user_context": {
                            "username": user_claims.get("username"),
                            "role": user_claims.get("user_class"),
                            "clearance": user_claims.get("clearance_level"),
                        },
                        "resource_context": {
                            "document_id": doc_dict.get("document_id"),
                            "classification": doc_dict.get("classification"),
                        },
                    }

            # If we get here, something went wrong with OPA
            logger.warning(f"⚠️ OPA unexpected response: {result}")

            # Log error event
            event_logger.log_event(
                event_type=EventType.ERROR,
                source_component="OPA",
                action="Document access evaluation error",
                user_id=user_claims.get("id") or user_claims.get("sub"),
                username=user_claims.get("username"),
                resource=doc_dict.get("document_id"),
                details={
                    "document_id": doc_dict.get("document_id"),
                    "classification": doc_dict.get("classification"),
                    "error": "Unexpected OPA response",
                    "opa_response": result,
                },
                status="failure",
                trace_id=input_data.get("request_id"),
            )

            # Fallback: If superadmin, allow access (for demo purposes)
            if user_claims.get("user_class") == "superadmin":
                logger.info("⚠️ OPA error - falling back to ALLOW for superadmin")

                event_logger.log_event(
                    event_type=EventType.POLICY_ALLOW,
                    source_component="OPA",
                    action="Superadmin fallback access",
                    user_id=user_claims.get("id") or user_claims.get("sub"),
                    username=user_claims.get("username"),
                    resource=doc_dict.get("document_id"),
                    details={
                        "document_id": doc_dict.get("document_id"),
                        "classification": doc_dict.get("classification"),
                        "reason": "Superadmin fallback (OPA error)",
                    },
                    status="success",
                    trace_id=input_data.get("request_id"),
                )

                return {
                    "allowed": True,
                    "reason": "Superadmin fallback access (OPA error)",
                    "opa_response": result,
                    "zta_flow": {
                        "step1": "✅ JWT Auth",
                        "step2": "⚠️ OPA Error",
                        "step3": "✅ ALLOWED (fallback)",
                        "timestamp": datetime.utcnow().isoformat(),
                        "opa_agent_contacted": True,
                    },
                }

            # Default deny
            return {
                "allowed": False,
                "reason": "OPA agent returned invalid response",
                "opa_response": result,
                "zta_flow": {
                    "step1": "✅ JWT Auth",
                    "step2": "❌ OPA Error",
                    "step3": "❌ DENIED",
                    "timestamp": datetime.utcnow().isoformat(),
                    "opa_agent_contacted": False,
                },
            }

        except Exception as e:
            logger.error(f"OPA evaluation error: {str(e)}")

            # Log error event
            event_logger.log_event(
                event_type=EventType.ERROR,
                source_component="OPA",
                action="Document access evaluation exception",
                user_id=user_claims.get("id") or user_claims.get("sub"),
                username=user_claims.get("username"),
                details={
                    "error": str(e),
                    "document_info": str(document),
                },
                status="failure",
            )

            # Fallback for superadmin
            if user_claims.get("user_class") == "superadmin":
                return {
                    "allowed": True,
                    "reason": f"Superadmin fallback (Error: {str(e)})",
                    "zta_flow": {
                        "step1": "✅ JWT Auth",
                        "step2": "❌ OPA Error",
                        "step3": "✅ ALLOWED (fallback)",
                        "timestamp": datetime.utcnow().isoformat(),
                        "error": str(e),
                    },
                }

            return {
                "allowed": False,
                "reason": f"OPA evaluation error: {str(e)}",
                "zta_flow": {
                    "step1": "✅ JWT Auth",
                    "step2": "❌ OPA Error",
                    "step3": "❌ DENIED",
                    "timestamp": datetime.utcnow().isoformat(),
                    "error": str(e),
                },
            }

    def _query_opa_policy(self, input_data, policy_path):
        """Query OPA with the given input and policy path"""
        try:
            url = f"{self.opa_url}/v1/data/{policy_path}"

            # Use SSL verification if CA cert exists
            verify_ssl = (
                self.ca_cert_path if os.path.exists(self.ca_cert_path) else False
            )

            logger.debug(f"OPA Request URL: {url}")
            logger.debug(f"SSL Verification: {verify_ssl}")

            response = requests.post(
                url,
                json={"input": input_data},
                timeout=self.timeout,
                headers={"Content-Type": "application/json"},
                verify=verify_ssl,
            )

            if response.status_code == 200:
                return response.json()
            else:
                logger.error(
                    f"OPA request failed: {response.status_code} - {response.text}"
                )
                return None

        except requests.exceptions.Timeout:
            logger.error(f"OPA request timeout after {self.timeout}s")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"OPA request failed: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error querying OPA: {e}")
            return None

    def check_zta_flow(self, user_info, document_info, action="read"):
        """
        Special method for ZTA flow demonstration
        Returns detailed flow information for the web interface
        """
        # First, check OPA health
        opa_healthy = self.health_check()

        if not opa_healthy:
            return {
                "zta_flow": {
                    "status": "error",
                    "steps": [
                        {
                            "id": 1,
                            "name": "JWT Authentication",
                            "status": "ready",
                            "details": "User authenticated",
                        },
                        {
                            "id": 2,
                            "name": "Connect to OPA Agent",
                            "status": "failed",
                            "details": "OPA agent unavailable",
                        },
                        {
                            "id": 3,
                            "name": "Policy Evaluation",
                            "status": "skipped",
                            "details": "Cannot proceed",
                        },
                        {
                            "id": 4,
                            "name": "Return Decision",
                            "status": "skipped",
                            "details": "Flow interrupted",
                        },
                    ],
                    "summary": "ZTA flow interrupted: OPA agent unavailable",
                    "visual_flow": "👤 User → 🌐 Server → ❌ OPA Agent → ⛔ STOPPED",
                }
            }

        # Prepare for OPA query
        now = datetime.now()
        input_data = {
            "user": user_info,
            "resource": document_info,
            "action": action,
            "environment": {
                "time": {
                    "hour": now.hour,
                    "minute": now.minute,
                    "string": now.strftime("%H:%M"),
                }
            },
            "authentication": {"method": "JWT"},
            "request_id": str(uuid.uuid4())[:8],
        }

        # Query OPA
        logger.info(f"🔐 Demonstrating ZTA flow for document access")
        result = self._query_opa_policy(input_data, "zta/allow")

        # Build flow steps for visualization
        steps = [
            {
                "id": 1,
                "name": "JWT Authentication",
                "status": "completed",
                "details": f"User {user_info.get('username')} authenticated",
                "component": "Flask-JWT",
                "timestamp": datetime.utcnow().isoformat(),
            },
            {
                "id": 2,
                "name": "Forward to OPA Agent",
                "status": "completed",
                "details": f"Request sent to OPA at {self.opa_url}",
                "component": "OPA Agent",
                "timestamp": datetime.utcnow().isoformat(),
            },
        ]

        if result and "result" in result:
            opa_result = result.get("result", {})
            allowed = opa_result.get("allow", False)

            steps.append(
                {
                    "id": 3,
                    "name": "Policy Evaluation",
                    "status": "completed",
                    "details": f"Decision: {'ALLOWED' if allowed else 'DENIED'}",
                    "component": "OPA Policies",
                    "timestamp": datetime.utcnow().isoformat(),
                    "opa_result": opa_result,
                }
            )

            steps.append(
                {
                    "id": 4,
                    "name": "Return Decision",
                    "status": "completed",
                    "details": f"{'Access granted' if allowed else 'Access denied'}",
                    "component": "API Server",
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )

            flow_status = "allowed" if allowed else "denied"
            visual_flow = (
                "👤 User → 🌐 Server → 📡 OPA Agent → ✅ API Server → 👤 User"
                if allowed
                else "👤 User → 🌐 Server → 📡 OPA Agent → ❌ BLOCKED"
            )

        else:
            steps.append(
                {
                    "id": 3,
                    "name": "Policy Evaluation",
                    "status": "failed",
                    "details": "OPA returned invalid response",
                    "component": "OPA Policies",
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )

            steps.append(
                {
                    "id": 4,
                    "name": "Return Decision",
                    "status": "failed",
                    "details": "Cannot determine access decision",
                    "component": "API Server",
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )

            flow_status = "error"
            visual_flow = "👤 User → 🌐 Server → 📡 OPA Agent → ⚠️ ERROR"

        return {
            "zta_flow": {
                "status": flow_status,
                "steps": steps,
                "summary": f"ZTA flow {'completed successfully' if flow_status == 'allowed' else 'completed with restrictions' if flow_status == 'denied' else 'encountered an error'}",
                "visual_flow": visual_flow,
                "opa_agent_url": self.opa_url,
                "timestamp": datetime.utcnow().isoformat(),
            }
        }

    # Add this method to your OPAClient class in opa_client.py (add it before the last line of the class)

    def evaluate_with_time_restrictions(self, input_data, request_id=None):

        try:
            # Extract user and document from input_data
            user_claims = {
                "id": input_data.get("user", {}).get("id"),
                "username": input_data.get("user", {}).get("username"),
                "user_class": input_data.get("user", {}).get("role"),
                "department": input_data.get("user", {}).get("department"),
                "facility": input_data.get("user", {}).get("facility"),
                "clearance_level": input_data.get("user", {}).get("clearance"),
                "email": input_data.get("user", {}).get("email", "unknown@example.gov"),
            }

            document_info = {
                "id": input_data.get("resource", {}).get("id"),
                "classification": input_data.get("resource", {}).get(
                    "classification", "BASIC"
                ),
                "department": input_data.get("resource", {}).get("department"),
                "facility": input_data.get("resource", {}).get("facility"),
            }

            # Call the main evaluation method
            result = self.evaluate_document_access(
                user_claims, document_info, input_data.get("action", "read")
            )

            # Add time restriction info for compatibility
            current_hour = datetime.now().hour
            is_time_restricted = document_info.get(
                "classification"
            ) == "TOP_SECRET" and (
                current_hour >= 21
                or current_hour < 8  # Change to 24 for 12 AM, 12 for 12 PM
            )

            return {
                "overall_allow": result.get("allowed", False),
                "   reason": result.get("reason", "Policy evaluation complete"),
                "time_restriction_applied": is_time_restricted,
                "current_hour": current_hour,
                "original_result": result,
            }

        except Exception as e:
            logger.error(f"Error in evaluate_with_time_restrictions: {str(e)}")
            return {
                "overall_allow": False,
                "reason": f"Evaluation error: {str(e)}",
                "time_restriction_applied": False,
                "current_hour": datetime.now().hour,
            }


# Create global instance
opa_client = OPAClient()


def init_opa_client(app):
    """Initialize OPA client with Flask app"""
    opa_client.init_app(app)


def get_opa_client():
    return opa_client
