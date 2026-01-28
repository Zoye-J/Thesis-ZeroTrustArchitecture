#!/usr/bin/env python3
"""
Python-based OPA Server for ZTA Thesis
No Docker required!
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import time
import sys
import os
import re
from datetime import datetime
import ssl
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from app.logs.zta_event_logger import event_logger, EventType, Severity

    HAS_LOGGING = True
except ImportError as e:
    print(f"⚠️ Event logging disabled: {e}")
    HAS_LOGGING = False


class PythonOPAHandler(BaseHTTPRequestHandler):
    """Full-featured OPA-compatible server written in Python"""

    # Store policies in memory
    policies = {}
    data = {}

    def __init__(self, *args, **kwargs):
        # Load policies on startup
        self.load_policies()
        super().__init__(*args, **kwargs)

    def load_policies(self):
        """Load Rego policies from file"""
        policy_file = "app/policy/policies.rego"
        if os.path.exists(policy_file):
            try:
                with open(policy_file, "r") as f:
                    content = f.read()
                # Parse package name
                package_match = re.search(r"package\s+([a-zA-Z0-9_/]+)", content)
                if package_match:
                    package_name = package_match.group(1)
                    self.policies[package_name] = content
                    print(f"📋 Loaded policy: {package_name}")
            except Exception as e:
                print(f"⚠️  Failed to load policies: {e}")
        else:
            # Create default policy file
            self.create_default_policies()

    def create_default_policies(self):
        """Create default policies if file doesn't exist"""
        os.makedirs("app/policy", exist_ok=True)

        default_policy = """package zta

import future.keywords

# Default deny everything
default allow := false

#############################################
# DOCUMENT ACCESS POLICIES
#############################################

# Allow superadmin to do anything
allow {
    input.user.role == "superadmin"
    reason := "Superadmin has full access"
}

# Admin can manage documents in their facility
allow {
    input.user.role == "admin"
    input.resource.type == "document"
    input.resource.facility == input.user.facility
    input.action == "read"
    reason := "Admin can read documents in their facility"
}

# Regular user access rules
allow {
    input.user.role == "user"
    input.resource.type == "document"
    input.action == "read"
    input.resource.department == input.user.department
    input.resource.facility == input.user.facility
    
    # Check clearance level
    clearance_levels := ["BASIC", "CONFIDENTIAL", "SECRET", "TOP_SECRET"]
    clearance_index(resource_level) := i {
        clearance_levels[i] == resource_level
    }
    user_clearance_index := clearance_index(input.user.clearance)
    resource_clearance_index := clearance_index(input.resource.classification)
    user_clearance_index >= resource_clearance_index
    
    reason := sprintf("User has sufficient clearance: %s >= %s", [input.user.clearance, input.resource.classification])
}

# Users can read their own documents
allow {
    input.user.role == "user"
    input.resource.type == "document"
    input.action == "read"
    input.resource.owner == input.user.id
    reason := "User can read their own documents"
}

#############################################
# USER MANAGEMENT POLICIES
#############################################

user_management := {"allow": true, "reason": "Superadmin can manage any user"} {
    input.user.role == "superadmin"
}

user_management := {"allow": true, "reason": "Admin can manage users in their facility"} {
    input.user.role == "admin"
    input.action == "read"
    input.resource.facility == input.user.facility
}
"""

        with open("app/policy/policies.rego", "w") as f:
            f.write(default_policy)

        self.policies["zta"] = default_policy
        print("📋 Created default policy file")

    def do_GET(self):
        """Handle GET requests"""
        if self.path == "/health":
            self.send_health_response()

        elif self.path == "/v1/policies":
            self.send_policies_response()

        elif self.path == "/":
            self.send_welcome_response()

        else:
            self.send_error_response(404, "Not Found")

    def do_POST(self):
        """Handle POST requests for policy evaluation"""
        if self.path.startswith("/v1/data/"):
            self.handle_policy_evaluation()
        else:
            self.send_error_response(404, "Not Found")

    def do_PUT(self):
        """Handle PUT requests (for loading policies)"""
        if self.path.startswith("/v1/policies/"):
            self.handle_upload_policy()
        else:
            self.send_error_response(404, "Not Found")

    def send_health_response(self):
        """Send health check response"""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        response = {
            "healthy": True,
            "version": "1.0.0",
            "server": "Python OPA Server",
            "policies_loaded": len(self.policies),
        }
        self.wfile.write(json.dumps(response).encode())

    def send_policies_response(self):
        """Send list of policies"""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

        policy_list = []
        for package_name, content in self.policies.items():
            policy_list.append(
                {
                    "id": package_name,
                    "raw": content[:500] + "..." if len(content) > 500 else content,
                }
            )

        response = {"result": policy_list}
        self.wfile.write(json.dumps(response).encode())

    def send_welcome_response(self):
        """Send welcome message"""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        response = {
            "message": "Python OPA Server for ZTA Thesis",
            "endpoints": {
                "GET /health": "Health check",
                "GET /v1/policies": "List policies",
                "POST /v1/data/{path}": "Evaluate policy",
                "PUT /v1/policies/{id}": "Upload policy",
            },
            "status": "Running",
        }
        self.wfile.write(json.dumps(response).encode())

    def handle_policy_evaluation(self):
        """Handle policy evaluation requests"""
        try:
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)
            input_data = json.loads(post_data)

            # Extract trace ID if available
            trace_id = input_data.get("input", {}).get("trace_id", "unknown")

            # Extract policy path from URL
            path_parts = self.path.split("/")
            if len(path_parts) >= 4:
                policy_path = "/".join(path_parts[3:])  # Remove /v1/data/
            else:
                policy_path = "zta/allow"

            # LOG REQUEST RECEIVED
            if HAS_LOGGING:
                try:
                    user_info = input_data.get("input", {}).get("user", {})
                    event_logger.log_event(
                        event_type=EventType.OPA_REQUEST_SENT,
                        source_component="opa_server",
                        action=f"Policy evaluation request received",
                        user_id=user_info.get("id"),
                        username=user_info.get("username"),
                        trace_id=trace_id,
                        details={
                            "policy_path": policy_path,
                            "method": self.command,
                            "headers": dict(self.headers),
                        },
                        severity=Severity.INFO,
                    )
                except Exception as e:
                    print(f"⚠️ Failed to log OPA request: {e}")

            print(f"🔍 Evaluating policy: {policy_path}")
            print(f"📥 Input: {json.dumps(input_data, indent=2)}")

            # Evaluate policy
            result = self.evaluate_policy(policy_path, input_data.get("input", {}))

            # LOG RESPONSE SENT
            if HAS_LOGGING:
                try:
                    allowed = result.get("decision", {}).get("allowed", False)
                    user_info = input_data.get("input", {}).get("user", {})
                    event_logger.log_event(
                        event_type=EventType.OPA_RESPONSE_RECEIVED,
                        source_component="opa_server",
                        action=f"Policy response sent: {'ALLOW' if allowed else 'DENY'}",
                        user_id=user_info.get("id"),
                        username=user_info.get("username"),
                        trace_id=trace_id,
                        details={
                            "decision": result.get("decision", {}),
                            "policy_path": policy_path,
                        },
                        severity=Severity.INFO,
                    )
                except Exception as e:
                    print(f"⚠️ Failed to log OPA response: {e}")

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Decision-Id", f"pyopa-{int(time.time())}")
            self.end_headers()

            self.wfile.write(json.dumps(result).encode())

        except json.JSONDecodeError:
            self.send_error_response(400, "Invalid JSON")
        except Exception as e:
            self.send_error_response(500, f"Evaluation error: {str(e)}")

    def handle_upload_policy(self):
        """Handle policy upload"""
        try:
            # Extract policy ID from URL
            path_parts = self.path.split("/")
            policy_id = path_parts[-1] if len(path_parts) >= 4 else "unknown"

            content_length = int(self.headers["Content-Length"])  # FIXED LINE 265
            policy_content = self.rfile.read(content_length).decode("utf-8")

            # Parse package name from content
            package_match = re.search(r"package\s+([a-zA-Z0-9_/]+)", policy_content)
            if package_match:
                package_name = package_match.group(1)
                self.policies[package_name] = policy_content

                # Also save to file
                with open("app/policy/policies.rego", "w") as f:
                    f.write(policy_content)

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                response = {"result": f"Policy '{policy_id}' uploaded"}
                self.wfile.write(json.dumps(response).encode())
            else:
                self.send_error_response(400, "Invalid policy: No package declaration")

        except Exception as e:
            self.send_error_response(500, f"Upload error: {str(e)}")

    def evaluate_policy(self, policy_path, input_data):
        """Evaluate policy using Python logic"""
        # Parse the policy path
        if policy_path.endswith("/allow"):
            package = policy_path[:-6]  # Remove /allow
            policy_type = "allow"
        elif policy_path.endswith("/user_management"):
            package = policy_path[:-16]  # Remove /user_management
            policy_type = "user_management"
        else:
            package = policy_path
            policy_type = "allow"

        print(f"📊 Package: {package}, Type: {policy_type}")

        # LOG THE START OF POLICY EVALUATION
        if HAS_LOGGING:
            try:
                # Get user info for logging
                user_info = input_data.get("user", {})
                trace_id = input_data.get("trace_id", "unknown")

                event_logger.log_event(
                    event_type=EventType.POLICY_EVALUATION,
                    source_component="opa_server",
                    action=f"Policy evaluation started",
                    user_id=user_info.get("id"),
                    username=user_info.get("username"),
                    trace_id=trace_id,
                    details={
                        "policy_path": policy_path,
                        "user_role": user_info.get("role", "unknown"),
                        "action": input_data.get("action", "unknown"),
                        "resource_type": input_data.get("resource", {}).get(
                            "type", "unknown"
                        ),
                    },
                    severity=Severity.INFO,
                )
            except Exception as e:
                print(f"⚠️ Failed to log policy start: {e}")

        # Extract user and resource info
        user = input_data.get("user", {})
        resource = input_data.get("resource", {})
        action = input_data.get("action", "read")

        # Get current time info
        now = datetime.now()

        # Policy evaluation logic
        if policy_type == "allow":
            result = self.evaluate_allow_policy(user, resource, action, now)
        elif policy_type == "user_management":
            result = self.evaluate_user_management_policy(user, resource, action)
        else:
            result = {"result": False, "reason": "Unknown policy type"}

        # Add decision metadata
        result["decision"] = {
            "allowed": result.get("result", False),
            "reason": result.get("reason", "Policy evaluation complete"),
            "timestamp": time.time(),
            "policy_path": policy_path,
        }

        # LOG THE POLICY DECISION
        if HAS_LOGGING:
            try:
                allowed = result.get("result", False)
                user_info = input_data.get("user", {})
                trace_id = input_data.get("trace_id", "unknown")

                event_logger.log_event(
                    event_type=(
                        EventType.POLICY_ALLOW if allowed else EventType.POLICY_DENY
                    ),
                    source_component="opa_server",
                    action=f"Policy decision: {'ALLOW' if allowed else 'DENY'}",
                    user_id=user_info.get("id"),
                    username=user_info.get("username"),
                    trace_id=trace_id,
                    details={
                        "policy_path": policy_path,
                        "decision": result,
                        "user_role": user_info.get("role", "unknown"),
                        "resource": input_data.get("resource", {}),
                        "action": input_data.get("action", "unknown"),
                    },
                    severity=Severity.HIGH if allowed else Severity.MEDIUM,
                )
            except Exception as e:
                print(f"⚠️ Failed to log policy decision: {e}")

        return result

    def evaluate_allow_policy(self, user, resource, action, current_time):
        """Evaluate allow policies"""
        user_role = user.get("role", "user")
        user_dept = user.get("department", "")
        user_facility = user.get("facility", "")
        user_clearance = user.get("clearance", "BASIC")

        resource_type = resource.get("type", "document")
        resource_dept = resource.get("department", "")
        resource_facility = resource.get("facility", "")
        resource_classification = resource.get("classification", "BASIC")
        resource_owner = resource.get("owner")

        clearance_levels = ["BASIC", "CONFIDENTIAL", "SECRET", "TOP_SECRET"]

        # Rule 1: Superadmin can do anything
        if user_role == "superadmin":
            return {"result": True, "reason": "Superadmin has full access"}

        # Rule 2: Admin can read documents in their facility
        if user_role == "admin" and resource_type == "document":
            if action == "read" and resource_facility == user_facility:
                return {
                    "result": True,
                    "reason": "Admin can read documents in their facility",
                }
            elif (
                action in ["write", "create"]
                and resource_dept == user_dept
                and resource_facility == user_facility
            ):
                return {
                    "result": True,
                    "reason": "Admin can write to documents in their department",
                }

        # Rule 3: User can read same department documents with sufficient clearance
        if user_role == "user" and resource_type == "document" and action == "read":
            if resource_dept == user_dept and resource_facility == user_facility:
                # Check clearance
                try:
                    user_idx = clearance_levels.index(user_clearance)
                    resource_idx = clearance_levels.index(resource_classification)

                    if user_idx >= resource_idx:
                        return {
                            "result": True,
                            "reason": f"User has sufficient clearance: {user_clearance} >= {resource_classification}",
                        }
                    else:
                        return {
                            "result": False,
                            "reason": f"Insufficient clearance: {user_clearance} < {resource_classification}",
                        }
                except ValueError:
                    pass

        # Rule 4: User can read their own documents
        if user_role == "user" and resource_type == "document" and action == "read":
            if resource_owner == user.get("id"):
                return {"result": True, "reason": "User can read their own documents"}

        # Rule 5: Time-based restrictions
        if user_role == "user" and resource_classification == "TOP_SECRET":
            hour = current_time.hour
            if hour < 9 or hour > 17:
                return {
                    "result": False,
                    "reason": "TOP_SECRET access restricted to business hours (9 AM - 5 PM)",
                }

        # Default deny
        return {"result": False, "reason": "Access denied by policy"}

    def evaluate_user_management_policy(self, user, resource, action):
        """Evaluate user management policies"""
        user_role = user.get("role", "user")
        user_dept = user.get("department", "")
        user_facility = user.get("facility", "")

        resource_role = resource.get("role", "user")
        resource_dept = resource.get("department", "")
        resource_facility = resource.get("facility", "")

        # Superadmin can do anything
        if user_role == "superadmin":
            return {"result": True, "reason": "Superadmin can manage any user"}

        # Admin can manage users in their facility
        if user_role == "admin":
            if action == "read" and resource_facility == user_facility:
                return {
                    "result": True,
                    "reason": "Admin can view users in their facility",
                }
            elif (
                action in ["create", "update"]
                and resource_dept == user_dept
                and resource_facility == user_facility
            ):
                # Prevent privilege escalation
                role_hierarchy = {"user": 1, "admin": 2, "superadmin": 3}
                if role_hierarchy.get(resource_role, 0) <= role_hierarchy.get(
                    user_role, 0
                ):
                    return {
                        "result": True,
                        "reason": "Admin can manage users in their department",
                    }
                else:
                    return {
                        "result": False,
                        "reason": "Cannot assign higher role than self",
                    }

        return {"result": False, "reason": "User management not allowed"}

    def send_error_response(self, code, message):
        """Send error response"""
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        response = {"error": {"code": code, "message": message}}
        self.wfile.write(json.dumps(response).encode())

    def log_message(self, format, *args):
        """Custom log format"""
        print(f"[Python OPA] {format % args}")


def start_python_opa_server(port=8181):
    """Start the Python OPA server"""
    server_address = ("", port)
    httpd = HTTPServer(server_address, PythonOPAHandler)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("certs/server.crt", "certs/server.key")
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    # LOG SERVER STARTUP
    if HAS_LOGGING:
        try:
            event_logger.log_event(
                event_type=EventType.API_REQUEST,
                source_component="opa_server",
                action="OPA Server started",
                details={"port": port, "version": "1.0.0"},
                severity=Severity.INFO,
            )
        except Exception as e:
            print(f"⚠️ Failed to log server startup: {e}")

    print("=" * 60)
    print("🚀 Python OPA Server for ZTA Thesis")
    print("=" * 60)
    print(f"📡 Port: {port}")
    print(f"🔗 URL: https://localhost:{port}")
    print(f"🏥 Health: https://localhost:{port}/health")
    print(f"📋 Policies: https://localhost:{port}/v1/policies")
    print(f"⚖️  Evaluate: POST https://localhost:{port}/v1/data/zta/allow")
    print(f"💾 Policy file: app/policy/policies.rego")
    print("=" * 60)
    print("📝 Policies will be loaded from app/policy/policies.rego")
    print("📝 If file doesn't exist, default policies will be created")
    print("=" * 60)
    print(f"📊 Event logging: {'ENABLED' if HAS_LOGGING else 'DISABLED'}")
    print("\nPress Ctrl+C to stop the server\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        # LOG SERVER SHUTDOWN
        if HAS_LOGGING:
            try:
                event_logger.log_event(
                    event_type=EventType.API_REQUEST,
                    source_component="opa_server",
                    action="OPA Server stopped",
                    severity=Severity.INFO,
                )
            except Exception as e:
                print(f"⚠️ Failed to log server shutdown: {e}")

        print("\n🛑 Stopping Python OPA Server...")
        httpd.server_close()


if __name__ == "__main__":
    # Check if port is provided as argument
    port = 8181
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"⚠️  Invalid port: {sys.argv[1]}. Using default port 8181")

    start_python_opa_server(port)
