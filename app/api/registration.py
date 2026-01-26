from flask import Blueprint, request, jsonify, current_app
from app.api_models import db, User
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta  # ADD timedelta
import re
import hashlib  #
import os
import json
from app.logs.zta_event_logger import event_logger, EventType
import uuid
from app.opa_agent.crypto_handler import CryptoHandler
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from app.mTLS.middleware import require_authentication
from app.mTLS.middleware import no_auth_required

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


def sign_certificate_from_csr(csr_data, ca_cert_path, ca_key_path, user_id):
    """Sign a certificate from CSR data (simplified version)"""
    try:
        # csr_data might be JSON string, parse if needed
        if isinstance(csr_data, str):
            import json

            csr_data = json.loads(csr_data)

        user_info = csr_data.get("userInfo", {})
        subject_info = csr_data.get("subject", {})

        email = user_info.get("email") or subject_info.get("CN")
        department = user_info.get("department") or subject_info.get("O", "").replace(
            "Government ", ""
        )

        # Use existing certificate generation with user info
        from app.mTLS.cert_manager import cert_manager

        # Use the user_id from database
        cert_metadata = cert_manager.generate_client_certificate(
            user_id=user_id,
            email=email,
            department=department,
        )

        return cert_metadata

    except Exception as e:
        print(f"Error signing certificate: {e}")
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

        # ======== ADD CSR HANDLING HERE ========
        csr_data = data.get("csr_data")
        client_public_key = data.get("public_key")

        if csr_data and client_public_key:
            try:
                print(f"📝 Processing CSR for automated registration...")
                print(f"CSR data type: {type(csr_data)}")

                # Parse CSR data if it's a string
                if isinstance(csr_data, str):
                    try:
                        csr_data = json.loads(csr_data)
                    except:
                        pass

                # Store the client-provided public key
                new_user.public_key = client_public_key

                # Calculate fingerprint
                public_key_fingerprint = hashlib.sha256(
                    client_public_key.encode()
                ).hexdigest()
                new_user.public_key_fingerprint = public_key_fingerprint

                # Sign the certificate from CSR
                cert_metadata = sign_certificate_from_csr(
                    csr_data=csr_data,
                    ca_cert_path="certs/ca.crt",
                    ca_key_path="certs/ca.key",
                    user_id=new_user.id,  # Pass the actual user ID
                )

                # Read the generated certificate
                cert_path = cert_metadata["paths"]["cert"]
                if os.path.exists(cert_path):
                    with open(cert_path, "r") as f:
                        client_cert_pem = f.read()
                else:
                    print(f"⚠️ Certificate file not found: {cert_path}")
                    # Create a dummy certificate for now
                    client_cert_pem = "-----BEGIN CERTIFICATE-----\nDUMMY CERTIFICATE (File not generated)\n-----END CERTIFICATE-----"

                # Associate certificate with user
                cert_info = {
                    "fingerprint": cert_metadata.get("fingerprint"),
                    "serial_number": cert_metadata.get("serial_number"),
                    "subject": {
                        "CN": new_user.email,
                        "O": f"Government {new_user.department}",
                        "emailAddress": new_user.email,
                    },
                    "issuer": {"CN": "ZTA Root CA", "O": "Government ZTA"},
                    "not_valid_before": datetime.utcnow().isoformat(),
                    "not_valid_after": (
                        datetime.utcnow() + timedelta(days=365)
                    ).isoformat(),
                }

                new_user.associate_certificate(cert_info)
                db.session.commit()

                print(f"✅ Certificate generated from CSR for {new_user.email}")
                print(
                    f"   Certificate fingerprint: {cert_metadata.get('fingerprint')[:16]}..."
                )

                # Set public_key_available flag
                public_key = client_public_key

                # Log CSR-based certificate generation
                event_logger.log_event(
                    event_type=EventType.USER_REGISTER,
                    source_component="api_server",
                    action="Automated certificate generation",
                    user_id=new_user.id,
                    username=new_user.username,
                    details={
                        "email": new_user.email,
                        "certificate_source": "CSR",
                        "key_source": "client_generated",
                        "has_certificate": True,
                        "has_rsa_keys": True,
                    },
                    trace_id=request_id,
                )

            except Exception as csr_error:
                print(f"⚠️ CSR processing failed: {csr_error}")
                # Continue without certificate
                # Generate keys server-side as fallback
                try:
                    public_key, private_key_path = generate_user_keys(new_user.id)
                    print(
                        f"✅ Fallback: Generated RSA keys server-side for user {new_user.id}"
                    )
                except Exception as key_error:
                    print(f"⚠️ Failed to generate keys: {key_error}")
                    public_key = None
        else:
            # Original server-side key generation (for manual registration)
            try:
                public_key, private_key_path = generate_user_keys(new_user.id)
                print(f"✅ RSA keys generated for user {new_user.id}")
            except Exception as key_error:
                print(f"⚠️ Failed to generate RSA keys: {key_error}")
                # Continue anyway - user can login but won't have encrypted workflow
                public_key = None
                private_key_path = None
        # ======== END CSR HANDLING ========

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
                "registration_type": "automated" if csr_data else "manual",
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

        # Add certificate if generated from CSR
        if csr_data and "client_cert_pem" in locals():
            response_data["certificate"] = client_cert_pem
            response_data["certificate_info"] = {
                "fingerprint": cert_metadata.get("fingerprint"),
                "serial_number": cert_metadata.get("serial_number"),
            }

        # Only include key info in development
        if current_app.config.get("DEBUG", False) and public_key:
            response_data["key_info"] = {
                "public_key_fingerprint": new_user.public_key_fingerprint[:16] + "...",
                "key_algorithm": "RSA-2048",
                "key_source": "client" if csr_data else "server",
                "note": (
                    "Private key stored in browser (IndexedDB)"
                    if csr_data
                    else "Private key stored securely on server"
                ),
            }

        return jsonify(response_data), 201

    except Exception as e:
        db.session.rollback()
        print(f"Registration error: {str(e)}")
        import traceback

        traceback.print_exc()
        return jsonify({"error": "Registration failed", "message": str(e)}), 500


@registration_bp.route("/automated", methods=["POST"])
@no_auth_required
def automated_registration():
    """Automated registration with CSR and public key - NO AUTH REQUIRED"""
    try:
        print("=" * 50)
        print("AUTOMATED REGISTRATION REQUEST")
        print("=" * 50)

        data = request.get_json()

        # Extract data
        user_data = data.get("user_data", {})
        csr_data = data.get("csr_data")
        public_key = data.get("public_key")  # RSA public key

        if not user_data or not csr_data or not public_key:
            return (
                jsonify({"error": "Missing required data for automated registration"}),
                400,
            )

        # Create user (with full validation like regular registration)
        email = user_data.get("email", "").lower()
        username = user_data.get("username", "").lower()

        # ==== DOMAIN EXTRACTION AND VALIDATION ====
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

        # Get facility and department from domain
        facility = DOMAIN_TO_FACILITY[domain]
        department = DOMAIN_TO_DEFAULT_DEPT[domain]

        # Check if email already exists
        if User.query.filter_by(email=email).first():
            return jsonify({"error": "Email already registered"}), 400

        # Check if username already exists
        if User.query.filter_by(username=username).first():
            return jsonify({"error": "Username already taken"}), 400

        # Validate password strength
        password = user_data.get("password")
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
        # ==== END VALIDATION ====

        print(f"Creating user via automated registration: {username}")
        print(f"Email: {email}")
        print(f"Facility: {facility}")
        print(f"Department: {department}")

        # Create new user
        new_user = User(
            username=username,
            email=email,
            user_class="user",
            facility=facility,
            department=department,
            clearance_level="BASIC",
            is_active=True,
            created_at=datetime.utcnow(),
            public_key=public_key,
        )

        # Set password
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        print(f"✅ User {username} created with ID: {new_user.id}")

        # Generate certificate from CSR
        cert_metadata = sign_certificate_from_csr(
            csr_data=csr_data,
            ca_cert_path="certs/ca.crt",
            ca_key_path="certs/ca.key",
            user_id=new_user.id,
        )

        # Read certificate
        cert_path = cert_metadata["paths"]["cert"]
        if os.path.exists(cert_path):
            with open(cert_path, "r") as f:
                client_cert_pem = f.read()
        else:
            print(f"⚠️ Certificate file not found: {cert_path}")
            # Fallback
            client_cert_pem = "-----BEGIN CERTIFICATE-----\nDUMMY CERTIFICATE\n-----END CERTIFICATE-----"

        # Calculate fingerprint for public key
        public_key_fingerprint = hashlib.sha256(public_key.encode()).hexdigest()
        new_user.public_key_fingerprint = public_key_fingerprint

        # Associate certificate
        cert_info = {
            "fingerprint": cert_metadata.get("fingerprint"),
            "serial_number": cert_metadata.get("serial_number"),
            "subject": {
                "CN": new_user.email,
                "O": f"Government {new_user.department}",
                "emailAddress": new_user.email,
            },
            "issuer": {"CN": "ZTA Root CA", "O": "Government ZTA"},
            "not_valid_before": datetime.utcnow().isoformat(),
            "not_valid_after": (datetime.utcnow() + timedelta(days=365)).isoformat(),
        }

        new_user.associate_certificate(cert_info)
        db.session.commit()

        print(f"✅ Certificate generated for {new_user.email}")

        return (
            jsonify(
                {
                    "success": True,
                    "user_id": new_user.id,
                    "certificate": client_cert_pem,
                    "certificate_info": {
                        "fingerprint": cert_metadata.get("fingerprint"),
                        "serial_number": cert_metadata.get("serial_number"),
                    },
                    "message": "Automated registration successful",
                }
            ),
            201,
        )

    except Exception as e:
        db.session.rollback()
        print(f"Automated registration error: {str(e)}")
        import traceback

        traceback.print_exc()
        return jsonify({"error": "Registration failed", "message": str(e)}), 500


# Test endpoint
@registration_bp.route("/test", methods=["GET"])
def test():
    return jsonify({"message": "Registration API is working!"}), 200
