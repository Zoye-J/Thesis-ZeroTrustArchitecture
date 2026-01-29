#!/usr/bin/env python3
"""
Python OPA Server for ZTA Thesis - FIXED VERSION
Serves as policy decision engine
"""

import sys
import os
import json
import time
import traceback
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.ssl_config import create_server_ssl_context
from app.logs.zta_event_logger import event_logger, EventType, Severity


class OPARequestHandler(BaseHTTPRequestHandler):
    def _send_json_response(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def _log_request(self, event_type, action, user="N/A", details=None):
        """Helper to log OPA events"""
        event_logger.log_event(
            event_type=event_type,
            source_component="opa_server",
            action=action,
            user_id=user,
            username=user if user != "N/A" else None,
            details=details,
            trace_id="unknown",  # Will be overridden if in input
            severity=Severity.INFO,
        )

    def do_GET(self):
        if self.path == "/health":
            self._log_request(
                EventType.API_REQUEST, "Health check", details={"path": self.path}
            )
            self._send_json_response(
                {
                    "status": "healthy",
                    "server": "opa_server",
                    "timestamp": time.time(),
                    "policies_loaded": True,
                }
            )
        elif self.path == "/v1/policies":
            self._log_request(
                EventType.POLICY_LOADED, "List policies", details={"path": self.path}
            )
            self._send_json_response(
                {"policies": ["zta/allow"], "loaded_policies": ["zta"]}
            )
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        try:
            if self.path == "/v1/data/zta/allow":
                content_length = int(self.headers.get("Content-Length", 0))
                post_data = self.rfile.read(content_length)

                # Parse input
                try:
                    data = json.loads(post_data.decode("utf-8"))
                    input_data = data.get("input", {})
                except json.JSONDecodeError as e:
                    self._send_json_response(
                        {
                            "result": False,
                            "reason": f"Invalid JSON: {str(e)}",
                            "error": "JSON parsing failed",
                        },
                        400,
                    )
                    return

                # Extract user info - FIXED: Handle both old and new formats
                user_data = input_data.get("user", {})
                resource_data = input_data.get("resource", {})
                environment_data = input_data.get("environment", {})
                request_id = input_data.get("request_id", "unknown")

                # Log the request
                self._log_request(
                    EventType.OPA_REQUEST_SENT,
                    "Policy evaluation request received",
                    user=user_data.get("username", "unknown"),
                    details={
                        "policy_path": "zta/allow",
                        "method": "POST",
                        "headers": dict(self.headers),
                        "request_id": request_id,
                        "user_clearance": user_data.get("clearance", "BASIC"),
                        "resource_classification": resource_data.get(
                            "classification", "BASIC"
                        ),
                    },
                )

                print(f"🔍 Evaluating policy: zta/allow")
                print(f"📥 Input: {json.dumps(data, indent=2)}")

                # Get user clearance - FIXED: Handle different field names
                user_clearance = user_data.get("clearance_level") or user_data.get(
                    "clearance", "BASIC"
                )
                username = user_data.get("username", "unknown")
                user_department = user_data.get("department", "")

                # Get resource classification - FIXED: Handle different field names
                resource_classification = resource_data.get("classification", "BASIC")
                resource_department = resource_data.get("department", "")

                print(f"📊 Package: zta, Type: allow")
                print(f"👤 User: {username}, Clearance: {user_clearance}")
                print(f"📄 Resource: {resource_classification}")

                # Log evaluation start
                self._log_request(
                    EventType.POLICY_EVALUATION,
                    "Policy evaluation started",
                    user=username,
                    details={
                        "policy_path": "zta/allow",
                        "user_role": user_data.get("role", "user"),
                        "action": resource_data.get("action", "get"),
                        "resource_type": resource_data.get("type", "unknown"),
                        "user_clearance": user_clearance,
                        "resource_classification": resource_classification,
                    },
                )

                # ============ SIMPLE POLICY EVALUATION (FIXED) ============
                clearance_hierarchy = ["BASIC", "CONFIDENTIAL", "SECRET", "TOP_SECRET"]

                try:
                    user_index = clearance_hierarchy.index(user_clearance)
                except ValueError:
                    user_index = 0  # Default to BASIC if unknown

                try:
                    resource_index = clearance_hierarchy.index(resource_classification)
                except ValueError:
                    resource_index = 0  # Default to BASIC if unknown

                # Check clearance
                clearance_passed = user_index >= resource_index

                # Check department
                department_passed = user_department == resource_department

                # Check time restrictions for TOP_SECRET
                time_passed = True
                if resource_classification == "TOP_SECRET":
                    current_hour = environment_data.get("current_hour", 12)
                    if current_hour < 8 or current_hour >= 16:
                        time_passed = False

                # Final decision
                allowed = clearance_passed and department_passed and time_passed

                # Build reason
                if not clearance_passed:
                    reason = f"Clearance insufficient: {user_clearance} < {resource_classification}"
                elif not department_passed:
                    reason = f"Department mismatch: {user_department} != {resource_department}"
                elif not time_passed:
                    reason = (
                        f"TOP_SECRET access restricted to business hours (8 AM - 4 PM)"
                    )
                else:
                    reason = f"Access granted: {user_clearance} clearance, {user_department} department"

                decision = {
                    "allowed": allowed,
                    "reason": reason,
                    "timestamp": time.time(),
                    "policy_path": "zta/allow",
                    "checks": {
                        "clearance_passed": clearance_passed,
                        "department_passed": department_passed,
                        "time_passed": time_passed,
                    },
                }

                response = {
                    "result": allowed,
                    "reason": reason,
                    "decision": decision,
                }

                # Log decision
                event_type = (
                    EventType.POLICY_ALLOW if allowed else EventType.POLICY_DENY
                )
                self._log_request(
                    event_type,
                    f"Policy decision: {'ALLOW' if allowed else 'DENY'}",
                    user=username,
                    details={
                        "policy_path": "zta/allow",
                        "decision": decision,
                        "request_id": request_id,
                    },
                )

                # Log response
                self._log_request(
                    EventType.OPA_RESPONSE_RECEIVED,
                    f"Policy response sent: {'ALLOW' if allowed else 'DENY'}",
                    user=username,
                    details={
                        "decision": decision,
                        "policy_path": "zta/allow",
                        "request_id": request_id,
                    },
                )

                print(f'[Python OPA] "POST {self.path} HTTP/1.1" 200 -')
                self._send_json_response(response)

            elif self.path.startswith("/v1/data/"):
                # Handle other policy paths
                self._send_json_response(
                    {
                        "result": False,
                        "reason": "Policy not implemented",
                        "error": "Only zta/allow is implemented",
                    }
                )
            else:
                self.send_response(404)
                self.end_headers()

        except Exception as e:
            print(f"❌ OPA Server error: {e}")
            traceback.print_exc()
            self._log_request(
                EventType.ERROR,
                "OPA Server error",
                details={"error": str(e), "traceback": traceback.format_exc()[-500:]},
            )
            self._send_json_response(
                {
                    "result": False,
                    "reason": f"Server error: {str(e)}",
                    "error": "Internal server error",
                },
                500,
            )

    def log_message(self, format, *args):
        """Override to prevent default logging"""
        pass


def run_opa_server():
    """Run the OPA server with fixed policies"""
    print("=" * 60)
    print("🚀 PYTHON OPA SERVER - FIXED VERSION")
    print("=" * 60)
    print("📡 Port: 8181")
    print("🔗 URL: https://localhost:8181")
    print("🏥 Health: https://localhost:8181/health")
    print("📋 Policies: https://localhost:8181/v1/policies")
    print("⚖️  Evaluate: POST https://localhost:8181/v1/data/zta/allow")
    print("💾 Policy logic: Built-in simple ZTA policies")
    print("=" * 60)
    print("📝 Policies implemented:")
    print("  • Clearance hierarchy: BASIC → CONFIDENTIAL → SECRET → TOP_SECRET")
    print("  • Department matching required")
    print("  • TOP_SECRET: Business hours only (8 AM - 4 PM)")
    print("=" * 60)
    print("📊 Event logging: ENABLED")
    print("🔐 SSL: TLSv1.2 (Python 3.13 compatibility)")
    print("\nPress Ctrl+C to stop the server")

    # Create SSL context
    ssl_context = create_server_ssl_context(verify_client=False, require_mtls=False)

    # Create server
    server_address = ("0.0.0.0", 8181)
    httpd = HTTPServer(server_address, OPARequestHandler)
    httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True)

    print(f"\n📋 Loaded policy: zta")
    print("✅ Server ready to evaluate policies")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except Exception as e:
        print(f"\n❌ Server error: {e}")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    run_opa_server()
