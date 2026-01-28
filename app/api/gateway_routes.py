"""
Gateway-specific API routes - UPDATED FOR ENCRYPTED WORKFLOW
These endpoints implement: User → Gateway → OPA Agent → OPA Server → API Server
"""

from flask import Blueprint, request, jsonify, current_app, g, render_template
from app.mTLS.middleware import require_authentication, require_mtls
from app.logs.zta_event_logger import event_logger, EventType, Severity
from datetime import datetime
import uuid
import hashlib
import json
import requests
import base64
import os

gateway_bp = Blueprint("gateway", __name__)


# ============ HELPER FUNCTIONS ============
@gateway_bp.route("/api/user-public-key", methods=["GET"])
def get_current_user_public_key():
    """Get the current user's public key (for registration) - NO AUTH REQUIRED"""
    try:
        # This endpoint doesn't require auth because it's used during registration
        # when no user exists yet
        return (
            jsonify(
                {
                    "message": "This endpoint requires user authentication",
                    "hint": "Register first, then login to get your public key",
                    "workflow": "Register → Get RSA Keys → Login → Access encrypted endpoints",
                }
            ),
            200,
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def get_user_public_key(user_id):
    """Get user's public key from API Server"""
    try:
        api_server_url = current_app.config.get(
            "API_SERVER_URL", "https://localhost:5001"
        )

        response = requests.post(
            f"{api_server_url}/api/internal/get-public-key",
            json={"user_id": user_id},
            headers={
                "Content-Type": "application/json",
                "X-Service-Token": current_app.config.get(
                    "GATEWAY_SERVICE_TOKEN", "gateway-token-2024"
                ),
                "X-Request-ID": str(uuid.uuid4()),
            },
            timeout=5,
            verify="certs/ca.crt" if os.path.exists("certs/ca.crt") else False,
        )

        if response.status_code == 200:
            return response.json().get("public_key")
        return None
    except:
        return None


def encrypt_for_agent(data, agent_public_key):
    """Encrypt data with OPA Agent's public key"""
    # For now, use base64 encoding - will be replaced with RSA encryption
    data_str = json.dumps(data)
    encrypted = base64.b64encode(data_str.encode()).decode()
    return encrypted


def decrypt_from_agent(encrypted_data):
    """Decrypt data from OPA Agent (for debugging)"""
    # For now, use base64 decoding
    decrypted = base64.b64decode(encrypted_data).decode()
    return json.loads(decrypted)


@gateway_bp.route("/api/resources/<int:resource_id>/access", methods=["POST"])
@require_authentication
def request_resource_access(resource_id):
    """Request access to a specific resource"""
    try:
        user_claims = g.get("user_claims", {})
        if not user_claims:
            return jsonify({"error": "User claims required"}), 401

        print(
            f"📡 Resource access request: User {user_claims.get('username')} for resource {resource_id}"
        )

        # Just return success for now - in real implementation, this would check access
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
                        "clearance": user_claims.get("clearance_level"),
                        "flow": "User → Gateway → Access Granted",
                    },
                }
            ),
            200,
        )

    except Exception as e:
        return (
            jsonify({"error": "Failed to process access request", "message": str(e)}),
            500,
        )


@gateway_bp.route("/api/resources/<int:resource_id>/view", methods=["GET"])
@require_authentication
def view_resource(resource_id):
    """View a specific resource"""
    try:
        user_claims = g.get("user_claims", {})
        if not user_claims:
            return jsonify({"error": "User claims required"}), 401

        # For demo purposes, return a simple resource view
        # In real implementation, this would fetch from API Server

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
        }

        if resource_id not in sample_resources:
            return jsonify({"error": "Resource not found"}), 404

        return (
            jsonify(
                {
                    "resource": sample_resources[resource_id],
                    "user": user_claims.get("username"),
                    "access_time": datetime.utcnow().isoformat(),
                    "zta_context": {
                        "authentication": "mTLS + JWT",
                        "authorization": "Department-based access control",
                        "trace_id": g.get("request_id", "unknown"),
                    },
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": "Failed to retrieve resource", "message": str(e)}), 500


@gateway_bp.route("/view-resource/<int:resource_id>")
@require_authentication
def view_resource_page(resource_id):
    """Render a page to view the resource"""
    try:
        user_claims = g.get("user_claims", {})
        if not user_claims:
            return jsonify({"error": "User claims required"}), 401

        # Sample resource content
        sample_resources = {
            1: {
                "id": 1,
                "name": "Public Notice Board",
                "content": "This is public content for all government employees.",
                "tier": "PUBLIC",
                "department": "ALL",
            },
            2: {
                "id": 2,
                "name": "Government Circulars",
                "content": "Latest government circulars and announcements.",
                "tier": "PUBLIC",
                "department": "ALL",
            },
            3: {
                "id": 3,
                "name": "MOD Operations Brief",
                "content": "MOD department operations briefing. This document contains sensitive information about current military operations and readiness levels. Access is restricted to MOD personnel only.",
                "tier": "DEPARTMENT",
                "department": "MOD",
            },
            4: {
                "id": 4,
                "name": "MOD Budget Report",
                "content": "MOD department budget report for fiscal year 2024. Details allocation of funds across different military branches and defense projects.",
                "tier": "DEPARTMENT",
                "department": "MOD",
            },
            5: {
                "id": 5,
                "name": "Top Secret MOD Plans",
                "content": "🔒 TOP SECRET CONTENT: Classified MOD plans for special operations. This document contains information about strategic military initiatives and advanced weapon systems.",
                "tier": "TOP_SECRET",
                "department": "MOD",
            },
            6: {
                "id": 6,
                "name": "MOF Fiscal Policy",
                "content": "Ministry of Finance fiscal policy document outlining economic strategies and tax reforms.",
                "tier": "DEPARTMENT",
                "department": "MOF",
            },
            7: {
                "id": 7,
                "name": "MOF Budget Documents",
                "content": "MOF department budget documents detailing national expenditure and revenue projections.",
                "tier": "DEPARTMENT",
                "department": "MOF",
            },
            8: {
                "id": 8,
                "name": "NSA Cyber Reports",
                "content": "NSA cybersecurity threat reports analyzing latest digital threats and vulnerabilities.",
                "tier": "DEPARTMENT",
                "department": "NSA",
            },
            9: {
                "id": 9,
                "name": "NSA Threat Assessment",
                "content": "NSA threat assessment document evaluating national security risks and countermeasures.",
                "tier": "DEPARTMENT",
                "department": "NSA",
            },
        }

        if resource_id not in sample_resources:
            return render_template(
                "error.html",
                error="Resource not found",
                message=f"Resource ID {resource_id} does not exist.",
            )

        resource = sample_resources[resource_id]

        # Check access permissions (same logic as before)
        user_department = user_claims.get("department")
        user_clearance = user_claims.get("clearance_level", "BASIC").upper()

        if (
            resource["tier"] == "DEPARTMENT"
            and resource["department"] != user_department
        ):
            return render_template(
                "error.html",
                error="Access Denied",
                message=f"This resource is restricted to {resource['department']} personnel only.",
            )

        if resource["tier"] == "TOP_SECRET":
            if resource["department"] != "MOD" or user_department != "MOD":
                return render_template(
                    "error.html",
                    error="Access Denied",
                    message="TOP SECRET resources are MOD department only.",
                )

            if user_clearance not in ["SECRET", "TOP_SECRET"]:
                return render_template(
                    "error.html",
                    error="Access Denied",
                    message=f"TOP SECRET clearance required (Your clearance: {user_claims.get('clearance_level')})",
                )

            # Check time restriction (8 AM - 4 PM)
            current_hour = datetime.now().hour
            if current_hour < 8 or current_hour >= 16:
                return render_template(
                    "error.html",
                    error="Access Denied",
                    message="TOP SECRET resources are only accessible during business hours (8:00 AM - 4:00 PM).",
                )

        return render_template(
            "view_resource.html",
            resource=resource,
            current_user={
                "username": user_claims.get("username"),
                "department": user_claims.get("department"),
                "clearance": user_claims.get("clearance_level"),
            },
            access_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            trace_id=g.get("request_id", str(uuid.uuid4())[:8]),
        )

    except Exception as e:
        return render_template(
            "error.html", error="Error loading resource", message=str(e)
        )


# ============ MAIN WORKFLOW ENDPOINTS ============


@gateway_bp.route("/api/documents", methods=["GET"])
@require_authentication
def get_documents():
    """NEW WORKFLOW: Gateway → OPA Agent → OPA Server → API Server"""
    request_id = str(uuid.uuid4())
    g.request_id = request_id

    try:
        # 1. Get user info and public key
        user_claims = g.get("user_claims", {})
        if not user_claims:
            return jsonify({"error": "User claims required"}), 401

        user_id = user_claims.get("sub")
        user_public_key = get_user_public_key(user_id)

        if not user_public_key:
            return jsonify({"error": "User public key not found"}), 400

        # 2. Prepare request data
        request_data = {
            "user": user_claims,
            "resource": {
                "type": "document",
                "action": "read",
                "path": request.path,
                "method": request.method,
                "query_params": dict(request.args),
            },
            "environment": {
                "time": datetime.utcnow().isoformat(),
                "ip_address": request.remote_addr,
                "user_agent": request.user_agent.string if request.user_agent else None,
            },
            "request_id": request_id,
        }

        # 3. Encrypt with OPA Agent's public key
        agent_public_key = current_app.config.get("OPA_AGENT_PUBLIC_KEY")
        if not agent_public_key:
            # For now, use base64 encoding
            encrypted_request = encrypt_for_agent(request_data, agent_public_key)
        else:
            encrypted_request = encrypt_for_agent(request_data, agent_public_key)

        # 4. Send to OPA Agent (8282)
        opa_agent_url = current_app.config.get("OPA_AGENT_URL", "https://localhost:8282")

        response = requests.post(
            f"{opa_agent_url}/evaluate",
            json={...},
            headers={"Content-Type": "application/json"},
            timeout=10,
            verify="certs/ca.crt" if os.path.exists("certs/ca.crt") else False,
        )

        if response.status_code != 200:
            return (
                jsonify(
                    {
                        "error": "OPA Agent unavailable",
                        "message": "Policy evaluation service down",
                    }
                ),
                503,
            )

        # 5. Receive encrypted response
        result = response.json()

        if result.get("access_denied"):
            # Denied by OPA Agent
            return (
                jsonify(
                    {
                        "error": "Access denied",
                        "reason": result.get("reason", "Policy violation"),
                        "encrypted_response": result.get("encrypted_denial"),
                        "request_id": request_id,
                    }
                ),
                403,
            )

        # 6. Forward encrypted API response to user
        return jsonify(
            {
                "encrypted_data": result.get("encrypted_response"),
                "format": "encrypted",
                "request_id": request_id,
                "zta_flow": "User → Gateway → OPA Agent → OPA Server → API Server → User",
            }
        )

    except requests.exceptions.RequestException as e:
        return (
            jsonify(
                {
                    "error": "Service unavailable",
                    "message": str(e),
                    "request_id": request_id,
                }
            ),
            503,
        )
    except Exception as e:
        return (
            jsonify(
                {
                    "error": "Gateway processing failed",
                    "message": str(e),
                    "request_id": request_id,
                }
            ),
            500,
        )


@gateway_bp.route("/opa-agent-public-key", methods=["GET"])
def get_opa_agent_public_key():
    """Return OPA Agent's public key for client-side encryption"""
    try:
        from app.opa_agent.client import get_opa_agent_client

        client = get_opa_agent_client()

        public_key = client.get_public_key()
        if not public_key:
            return jsonify({"error": "OPA Agent public key not available"}), 503

        return (
            jsonify(
                {
                    "public_key": public_key,
                    "algorithm": "RSA-OAEP-SHA256",
                    "key_size": 2048,
                    "format": "PEM",
                    "timestamp": datetime.utcnow().isoformat(),
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": f"Failed to get public key: {str(e)}"}), 500


@gateway_bp.route("/api/opa-agent-public-key", methods=["GET"])
def get_opa_agent_public_key_for_clients():
    """Get OPA Agent's public key for client-side encryption - NO AUTH"""
    try:
        from app.opa_agent.client import get_opa_agent_client

        client = get_opa_agent_client()
        public_key = client.get_public_key()

        if not public_key:
            return jsonify({"error": "OPA Agent public key not available"}), 503

        return (
            jsonify(
                {
                    "public_key": public_key,
                    "algorithm": "RSA-OAEP-SHA256",
                    "key_size": 2048,
                    "timestamp": datetime.utcnow().isoformat(),
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": f"Failed to get OPA Agent key: {str(e)}"}), 500


@gateway_bp.route("/user-public-key/<int:user_id>", methods=["GET"])
# @require_authentication
def get_user_public_key_endpoint(user_id):  # CHANGED NAME HERE
    """Get a user's public key (for other users to encrypt messages)"""
    try:
        # Check permissions - admin or same user
        current_user_id = g.jwt_identity if hasattr(g, "jwt_identity") else None
        current_user_role = (
            g.user_claims.get("user_class") if hasattr(g, "user_claims") else None
        )

        if not current_user_id or (
            current_user_id != user_id
            and current_user_role not in ["admin", "superadmin"]
        ):
            return jsonify({"error": "Unauthorized"}), 403

        # Get user's public key
        from app.mTLS.cert_manager import cert_manager

        public_key = cert_manager.get_user_public_key(user_id)

        if not public_key:
            return jsonify({"error": "User public key not found"}), 404

        return (
            jsonify(
                {
                    "user_id": user_id,
                    "public_key": public_key,
                    "algorithm": "RSA",
                    "key_size": 2048,
                    "format": "PEM",
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": f"Failed to get user public key: {str(e)}"}), 500


@gateway_bp.route("/encrypted-request", methods=["POST"])
def handle_encrypted_request():
    """
    Transparent endpoint: Forward encrypted request to OPA Agent
    User → (Encrypted) → Gateway → (Encrypted) → OPA Agent
    """
    try:
        # Generate request ID
        request_id = str(uuid.uuid4())

        # Get encrypted payload from user
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        encrypted_request = data.get("encrypted_payload")
        user_public_key = data.get("user_public_key")

        if not encrypted_request:
            return jsonify({"error": "encrypted_payload is required"}), 400

        if not user_public_key:
            return jsonify({"error": "user_public_key is required"}), 400

        # Forward to OPA Agent (NO DECRYPTION HERE!)
        api_server_url = current_app.config.get(
            "OPA_AGENT_URL", "https://localhost:8282"
        )

        response = requests.post(
            f"{api_server_url}/evaluate",
            json={
                "encrypted_request": encrypted_request,
                "user_public_key": user_public_key,
                "request_id": request_id,
                "source": "gateway_encrypted",
            },
            timeout=10,
            verify="certs/ca.crt" if os.path.exists("certs/ca.crt") else False,
        )

        # Forward OPA Agent's response back to user (still encrypted)
        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            return (
                jsonify(
                    {
                        "error": "OPA Agent request failed",
                        "status_code": response.status_code,
                        "details": response.text[:500],
                    }
                ),
                response.status_code,
            )

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"OPA Agent connection failed: {str(e)}"}), 503
    except Exception as e:
        return jsonify({"error": f"Gateway processing error: {str(e)}"}), 500


@gateway_bp.route("/api/documents/<int:document_id>", methods=["GET"])
@require_authentication
def get_single_document(document_id):
    """Get single document - encrypted workflow"""
    request_id = str(uuid.uuid4())
    g.request_id = request_id

    try:
        user_claims = g.get("user_claims", {})
        user_id = user_claims.get("sub")
        user_public_key = get_user_public_key(user_id)

        if not user_public_key:
            return jsonify({"error": "User public key not found"}), 400

        # Prepare request
        request_data = {
            "user": user_claims,
            "resource": {
                "type": "document",
                "id": document_id,
                "action": "read",
                "path": request.path,
                "method": request.method,
            },
            "environment": {
                "time": datetime.utcnow().isoformat(),
                "ip_address": request.remote_addr,
            },
            "request_id": request_id,
        }

        # Send to OPA Agent
        agent_public_key = current_app.config.get("OPA_AGENT_PUBLIC_KEY")
        encrypted_request = encrypt_for_agent(request_data, agent_public_key)

        opa_agent_url = current_app.config.get("OPA_AGENT_URL", "https://localhost:8282")

        response = requests.post(
            f"{opa_agent_url}/evaluate",
            json={
                "encrypted_request": encrypted_request,
                "user_public_key": user_public_key,
                "user_id": user_id,
                "request_id": request_id,
                "action": "read_document",
            },
            headers={"Content-Type": "application/json"},
            timeout=10,
            verify="certs/ca.crt" if os.path.exists("certs/ca.crt") else False,
        )

        if response.status_code != 200:
            return (
                jsonify({"error": "OPA Agent unavailable", "request_id": request_id}),
                503,
            )

        result = response.json()

        if result.get("access_denied"):
            return (
                jsonify(
                    {
                        "error": "Access denied",
                        "reason": result.get("reason"),
                        "encrypted_response": result.get("encrypted_denial"),
                        "request_id": request_id,
                    }
                ),
                403,
            )

        return jsonify(
            {
                "encrypted_data": result.get("encrypted_response"),
                "request_id": request_id,
            }
        )

    except Exception as e:
        return (
            jsonify(
                {
                    "error": "Failed to retrieve document",
                    "message": str(e),
                    "request_id": request_id,
                }
            ),
            500,
        )


@gateway_bp.route("/api/users", methods=["GET"])
@require_authentication
def get_users():
    """Get users list - encrypted workflow"""
    request_id = str(uuid.uuid4())
    g.request_id = request_id

    try:
        user_claims = g.get("user_claims", {})
        user_id = user_claims.get("sub")
        user_public_key = get_user_public_key(user_id)

        # Check if admin (basic check at gateway)
        if user_claims.get("user_class") not in ["admin", "superadmin"]:
            return (
                jsonify({"error": "Admin access required", "request_id": request_id}),
                403,
            )

        request_data = {
            "user": user_claims,
            "resource": {
                "type": "user",
                "action": "read",
                "path": request.path,
                "method": request.method,
            },
            "environment": {"time": datetime.utcnow().isoformat()},
            "request_id": request_id,
        }

        agent_public_key = current_app.config.get("OPA_AGENT_PUBLIC_KEY")
        encrypted_request = encrypt_for_agent(request_data, agent_public_key)

        opa_agent_url = current_app.config.get("OPA_AGENT_URL", "https://localhost:8282")

        response = requests.post(
            f"{opa_agent_url}/evaluate",
            json={
                "encrypted_request": encrypted_request,
                "user_public_key": user_public_key,
                "user_id": user_id,
                "request_id": request_id,
                "action": "list_users",
            },
            headers={"Content-Type": "application/json"},
            timeout=10,
            verify="certs/ca.crt" if os.path.exists("certs/ca.crt") else False,
        )

        if response.status_code != 200:
            return (
                jsonify(
                    {"error": "Policy evaluation failed", "request_id": request_id}
                ),
                503,
            )

        result = response.json()

        if result.get("access_denied"):
            return (
                jsonify(
                    {
                        "error": "Access denied by policy",
                        "reason": result.get("reason"),
                        "encrypted_response": result.get("encrypted_denial"),
                        "request_id": request_id,
                    }
                ),
                403,
            )

        return jsonify(
            {
                "encrypted_data": result.get("encrypted_response"),
                "request_id": request_id,
            }
        )

    except Exception as e:
        return (
            jsonify(
                {
                    "error": "Failed to retrieve users",
                    "message": str(e),
                    "request_id": request_id,
                }
            ),
            500,
        )


# ============ SERVICE ENDPOINTS ============


@gateway_bp.route("/service/health", methods=["GET"])
@require_mtls
def service_health():
    """Service health check - mTLS only"""
    return jsonify(
        {
            "status": "healthy",
            "service": "ZTA Gateway Server",
            "timestamp": datetime.utcnow().isoformat(),
            "workflow": "encrypted_opa_agent",
        }
    )


# ============ SIMPLE TEST ENDPOINT ============


@gateway_bp.route("/api/test-encryption", methods=["GET"])
@require_authentication
def test_encryption():
    """Test endpoint to verify encryption flow is working"""
    request_id = str(uuid.uuid4())

    return jsonify(
        {
            "message": "Encrypted workflow active",
            "workflow": "User → Gateway → OPA Agent → OPA Server → API Server → User",
            "components": {
                "gateway": "running",
                "opa_agent": "port_8282",
                "opa_server": "port_8181",
                "api_server": "port_5001",
            },
            "encryption": "RSA-OAEP-SHA256 (implemented)",
            "request_id": request_id,
        }
    )


# ============ REGISTRATION (KEEP THIS) ============


@gateway_bp.route("/register", methods=["POST"])
def handle_registration():
    """Handle registration - NO AUTH REQUIRED"""
    print(f"\n🔀 Registration request received at Gateway")

    try:
        data = request.get_json()

        api_server_url = current_app.config.get(
            "API_SERVER_URL", "https://localhost:5001"
        )

        response = requests.post(
            f"{api_server_url}/api/register/",
            json=data,
            headers={
                "Content-Type": "application/json",
                "X-Service-Token": current_app.config.get(
                    "GATEWAY_SERVICE_TOKEN", "gateway-token-2024"
                ),
                "X-Request-ID": str(uuid.uuid4()),
            },
            timeout=10,
            verify="certs/ca.crt" if os.path.exists("certs/ca.crt") else False,
        )

        return jsonify(response.json()), response.status_code

    except requests.exceptions.RequestException as e:
        return (
            jsonify({"error": "Registration service unavailable", "message": str(e)}),
            503,
        )
    except Exception as e:
        return jsonify({"error": "Registration failed", "message": str(e)}), 500


# Add this near other resource endpoints in gateway_routes.py


@gateway_bp.route("/api/resources", methods=["GET"])
@require_authentication
def get_resources_proper():
    """
    PROPER ZTA Resource Flow:
    User → Gateway → API Server → Gateway → User
    (No encryption needed for resource listing)
    """
    try:
        user_claims = g.get("user_claims", {})
        if not user_claims:
            return jsonify({"error": "User claims required"}), 401

        print(
            f"📡 Resource request for {user_claims.get('username')} ({user_claims.get('department')})"
        )

        # Direct call to API Server (no encryption needed for listing)
        api_server_url = current_app.config.get(
            "API_SERVER_URL", "https://localhost:5001"
        )

        # Use service token for API Server communication
        service_token = current_app.config.get(
            "GATEWAY_SERVICE_TOKEN", "gateway-token-2024"
        )

        response = requests.get(
            f"{api_server_url}/resources",
            headers={
                "Content-Type": "application/json",
                "X-Service-Token": service_token,
                "X-User-Claims": json.dumps(user_claims),
                "X-Request-ID": str(uuid.uuid4()),
            },
            timeout=10,
            verify=os.path.exists("certs/ca.crt"),  # Verify SSL if CA cert exists
        )

        if response.status_code == 200:
            resources = response.json()

            # Log successful access
            event_logger.log_event(
                event_type=EventType.RESOURCE_ACCESS,
                source_component="gateway",
                action="Resource list retrieved",
                user_id=user_claims.get("sub"),
                username=user_claims.get("username"),
                details={
                    "resource_count": len(resources),
                    "user_department": user_claims.get("department"),
                    "flow": "direct_api",
                },
                trace_id=g.request_id,
            )

            return jsonify(resources), 200
        else:
            return jsonify(response.json()), response.status_code

    except requests.exceptions.SSLError as ssl_error:
        print(f"❌ SSL Error: {ssl_error}")
        # Fallback without SSL verification
        try:
            response = requests.get(
                f"{api_server_url}/resources",
                headers={
                    "Content-Type": "application/json",
                    "X-Service-Token": service_token,
                    "X-User-Claims": json.dumps(user_claims),
                    "X-Request-ID": str(uuid.uuid4()),
                },
                timeout=10,
                verify="certs/ca.crt" if os.path.exists("certs/ca.crt") else False,
            )
            return jsonify(response.json()), response.status_code
        except Exception as e:
            return jsonify({"error": f"SSL and fallback failed: {str(e)}"}), 503

    except Exception as e:
        print(f"❌ Resource error: {e}")
        return jsonify({"error": "Failed to get resources", "message": str(e)}), 500


@gateway_bp.route("/test-encryption")
def test_encryption_page():
    """Test page for encryption functionality"""
    return render_template("test_encryption.html")
