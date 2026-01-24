from flask import Blueprint, request, jsonify, current_app
from app.api_models import db, User
from werkzeug.security import generate_password_hash
from datetime import datetime
import re
import hashlib  #
import os
import json
from app.logs.zta_event_logger import event_logger, EventType
import uuid
from app.opa_agent.crypto_handler import CryptoHandler 
registration_bp = Blueprint("registration", __name__)

# Email domain to facility mapping
DOMAIN_TO_FACILITY = {
    "mod.gov": "Ministry of Defence",
    "mof.gov": "Ministry of Finance",
    "nsa.gov": "National Security Agency",
}

# Email domain to default department mapping
DOMAIN_TO_DEFAULT_DEPT = {
    "mod.gov": "Operations",
    "mof.gov": "Budget",
    "nsa.gov": "Cyber Security",
}


# ADD THIS HELPER FUNCTION
def store_private_key(user_id, private_key_pem):
    """Store user's private key securely (in production, use HSM or KMS)"""
    # For development, store in a secure directory
    keys_dir = "keys/private"
    os.makedirs(keys_dir, exist_ok=True)

    key_file = os.path.join(keys_dir, f"user_{user_id}.pem")

    with open(key_file, "wb") as f:
        f.write(private_key_pem)

    # Set secure permissions (Unix only)
    try:
        os.chmod(key_file, 0o600)  # Read/write for owner only
    except:
        pass

    return key_file


# MODIFY THIS FUNCTION
def generate_user_keys(user_id):
    """Generate RSA key pair for new user"""
    try:
        # Import here to avoid circular imports
        from app.opa_agent.crypto_handler import CryptoHandler

        crypto = CryptoHandler()
        private_key_pem, public_key_pem = crypto.generate_key_pair()

        # Store public key in user record
        user = User.query.get(user_id)
        if not user:
            raise ValueError(f"User {user_id} not found")

        # Calculate fingerprint
        fingerprint = hashlib.sha256(public_key_pem).hexdigest()

        # Update user with public key
        user.public_key = public_key_pem.decode("utf-8")
        user.public_key_fingerprint = fingerprint

        db.session.commit()

        # Store private key securely
        private_key_path = store_private_key(user_id, private_key_pem)

        print(f"✅ Generated RSA keys for user {user.username}")
        print(f"   Public key fingerprint: {fingerprint[:16]}...")
        print(f"   Private key stored at: {private_key_path}")

        return public_key_pem.decode("utf-8"), private_key_path

    except Exception as e:
        print(f"❌ Error generating keys for user {user_id}: {e}")
        raise


# MODIFY THE MAIN REGISTRATION FUNCTION
@registration_bp.route("/", methods=["POST"])
@registration_bp.route("", methods=["POST"])
def register_user():
    try:
        print("=" * 50)
        print("REGISTRATION REQUEST RECEIVED")
        print("=" * 50)

        request_id = str(uuid.uuid4())
        print(f"Request ID: {request_id}")

        # Check content type
        content_type = request.headers.get("Content-Type", "")
        if "application/json" not in content_type:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        try:
            data = request.get_json()
        except Exception as json_error:
            return jsonify({"error": "Invalid JSON"}), 400

        if not data:
            return jsonify({"error": "No data provided"}), 400

        email = data.get("email", "").lower()
        username = data.get("username", "").lower()

        # Validate required fields
        required_fields = ["full_name", "email", "username", "password"]
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing field: {field}"}), 400

        # Extract domain from email
        domain_match = re.search(r"@([a-zA-Z0-9.-]+)$", email)
        if not domain_match:
            return jsonify({"error": "Invalid email format"}), 400

        domain = domain_match.group(1)

        # Check if domain is allowed
        if domain not in DOMAIN_TO_FACILITY:
            return (
                jsonify(
                    {
                        "error": "Unauthorized email domain",
                        "message": f'Only government email domains are allowed: {", ".join(DOMAIN_TO_FACILITY.keys())}',
                    }
                ),
                400,
            )

        # Check if email already exists
        if User.query.filter_by(email=email).first():
            return jsonify({"error": "Email already registered"}), 400

        # Check if username already exists
        if User.query.filter_by(username=username).first():
            return jsonify({"error": "Username already taken"}), 400

        # Validate password strength
        password = data["password"]
        if len(password) < 8:
            return jsonify({"error": "Password must be at least 8 characters"}), 400

        if not re.search(r"[A-Z]", password):
            return (
                jsonify(
                    {"error": "Password must contain at least one uppercase letter"}
                ),
                400,
            )

        if not re.search(r"[a-z]", password):
            return (
                jsonify(
                    {"error": "Password must contain at least one lowercase letter"}
                ),
                400,
            )

        if not re.search(r"\d", password):
            return jsonify({"error": "Password must contain at least one number"}), 400

        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
            return (
                jsonify(
                    {"error": "Password must contain at least one special character"}
                ),
                400,
            )

        # Get facility and department from domain
        facility = DOMAIN_TO_FACILITY[domain]
        department = DOMAIN_TO_DEFAULT_DEPT[domain]

        print(f"Creating user: {username}")
        print(f"Email: {email}")
        print(f"Facility: {facility}")
        print(f"Department: {department}")

        # Create new user (WITHOUT public key initially)
        new_user = User(
            username=username,
            email=email,
            user_class="user",
            facility=facility,
            department=department,
            clearance_level="BASIC",
            is_active=True,
            created_at=datetime.utcnow(),
            public_key=None,  # Will be set after key generation
            public_key_fingerprint=None,
        )

        # Set password
        new_user.password_hash = generate_password_hash(password)

        db.session.add(new_user)
        db.session.commit()

        print(f"✅ User {username} created with ID: {new_user.id}")

        # STEP 2: Generate RSA keys for the user
        try:
            public_key, private_key_path = generate_user_keys(new_user.id)
            print(f"✅ RSA keys generated for user {new_user.id}")
        except Exception as key_error:
            print(f"⚠️ Failed to generate RSA keys: {key_error}")
            # Continue anyway - user can login but won't have encrypted workflow
            public_key = None
            private_key_path = None

        # Log successful registration
        event_logger.log_event(
            event_type=EventType.USER_REGISTER,  # Changed from JWT_TOKEN_ISSUED to USER_REGISTER
            source_component="api_server",
            action="User registration",
            user_id=new_user.id,
            username=new_user.username,
            details={
                "email": new_user.email,
                "facility": new_user.facility,
                "department": new_user.department,
                "clearance": new_user.clearance_level,
                "has_rsa_keys": public_key is not None,
            },
            trace_id=request_id,
        )

        response_data = {
            "success": True,
            "message": "Registration successful! You can now login.",
            "user": {
                "id": new_user.id,
                "username": new_user.username,
                "email": new_user.email,
                "user_class": new_user.user_class,
                "facility": new_user.facility,
                "department": new_user.department,
                "clearance_level": new_user.clearance_level,
                "has_public_key": public_key is not None,
            },
            "request_id": request_id,
        }

        # Only include key info in development
        if current_app.config.get("DEBUG", False) and public_key:
            response_data["key_info"] = {
                "public_key_fingerprint": new_user.public_key_fingerprint[:16] + "...",
                "key_algorithm": "RSA-2048",
                "note": "Private key stored securely on server",
            }

        return jsonify(response_data), 201

    except Exception as e:
        db.session.rollback()
        print(f"Registration error: {str(e)}")
        import traceback

        traceback.print_exc()
        return jsonify({"error": "Registration failed", "message": str(e)}), 500


# Test endpoint
@registration_bp.route("/test", methods=["GET"])
def test():
    return jsonify({"message": "Registration API is working!"}), 200
