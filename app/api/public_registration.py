"""
Public Registration Blueprint
COMPLETELY SEPARATE from authentication system
Used ONLY for user registration (no auth required)
"""

from flask import Blueprint, request, jsonify
from app.api_models import db, User
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta
import re
import hashlib
import os
import json
from app.logs.zta_event_logger import event_logger, EventType
import uuid

# Create SEPARATE blueprint - no authentication middleware attached
public_registration_bp = Blueprint("public_registration", __name__)

# Email domain to facility mapping
DOMAIN_TO_FACILITY = {
    "mod.gov": "Ministry of Defence",
    "mof.gov": "Ministry of Finance",
    "nsa.gov": "National Security Agency",
}

DOMAIN_TO_DEFAULT_DEPT = {
    "mod.gov": "MOD",          
    "mof.gov": "MOF",            
    "nsa.gov": "NSA",           
}

DOMAIN_TO_CLEARANCE = {
    "mod.gov": "SECRET",  # MOD users get SECRET clearance
    "mof.gov": "CONFIDENTIAL",  # MOF users get CONFIDENTIAL
    "nsa.gov": "BASIC",  # NSA users get BASIC
}

# IN app/api/public_registration.py - UPDATE THIS FUNCTION:


def sign_certificate_from_csr(csr_data, ca_cert_path, ca_key_path, user_id):
    """Sign a certificate from CSR data with BANGLADESH context"""
    try:
        if isinstance(csr_data, str):
            csr_data = json.loads(csr_data)

        user_info = csr_data.get("userInfo", {})
        subject_info = csr_data.get("subject", {})

        email = user_info.get("email") or subject_info.get("CN")
        department = user_info.get("department") or subject_info.get("O", "").replace(
            "Government ", ""
        )

        # Get domain from email
        domain_match = re.search(r"@([a-zA-Z0-9.-]+)$", email)
        if domain_match:
            domain = domain_match.group(1)
            department_code = {
                "mod.gov": "mod",
                "mof.gov": "mof",
                "nsa.gov": "nsa",
            }.get(
                domain, "mod"
            )  # default to mod

        from app.mTLS.cert_manager import cert_manager

        # Pass department_code instead of department name
        cert_metadata = cert_manager.generate_client_certificate(
            user_id=user_id,
            email=email,
            department_code=department_code,
        )

        return cert_metadata

    except Exception as e:
        print(f"Error signing certificate: {e}")
        raise


@public_registration_bp.route("/automated", methods=["POST"])
def public_automated_registration():
    """Public automated registration - NO AUTHENTICATION AT ALL"""
    try:
        print("=" * 50)
        print("PUBLIC REGISTRATION - NO AUTH")
        print("=" * 50)

        data = request.get_json()

        if not data:
            return jsonify({"error": "No data provided"}), 400

        # Extract data
        user_data = data.get("user_data", {})
        csr_data = data.get("csr_data")
        public_key = data.get("public_key")  # RSA public key

        if not user_data or not csr_data or not public_key:
            return jsonify({"error": "Missing required data"}), 400

        # Create user (with full validation)
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

        print(f"Creating user via PUBLIC registration: {username}")
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
            clearance_level=DOMAIN_TO_CLEARANCE[domain],
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
        try:
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
                "not_valid_after": (
                    datetime.utcnow() + timedelta(days=365)
                ).isoformat(),
            }

            new_user.associate_certificate(cert_info)
            db.session.commit()

            print(f"✅ Certificate generated for {new_user.email}")

            # Log successful registration
            event_logger.log_event(
                event_type=EventType.USER_REGISTER,
                source_component="gateway_public",
                action="Public registration",
                user_id=new_user.id,
                username=new_user.username,
                details={
                    "email": new_user.email,
                    "facility": new_user.facility,
                    "department": new_user.department,
                    "registration_type": "public_automated",
                    "has_certificate": True,
                },
                trace_id=str(uuid.uuid4()),
            )

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
                        "message": "Registration successful! You can now login.",
                        "user": {
                            "id": new_user.id,
                            "username": new_user.username,
                            "email": new_user.email,
                            "facility": new_user.facility,
                            "department": new_user.department,
                        },
                    }
                ),
                201,
            )

        except Exception as cert_error:
            print(f"⚠️ Certificate generation failed: {cert_error}")
            # Still return success - user can login without certificate
            return (
                jsonify(
                    {
                        "success": True,
                        "user_id": new_user.id,
                        "message": "Registration successful (certificate generation failed). You can still login.",
                        "user": {
                            "id": new_user.id,
                            "username": new_user.username,
                            "email": new_user.email,
                        },
                        "warning": "Certificate not generated",
                    }
                ),
                201,
            )

    except Exception as e:
        db.session.rollback()
        print(f"Public registration error: {str(e)}")
        import traceback

        traceback.print_exc()
        return jsonify({"error": "Registration failed", "message": str(e)}), 500


# Simple test endpoint
@public_registration_bp.route("/test", methods=["GET"])
def public_test():
    return jsonify({"message": "Public registration API is working!"}), 200
