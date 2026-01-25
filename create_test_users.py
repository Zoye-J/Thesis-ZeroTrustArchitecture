# create_test_users.py
"""
Create 3 test users with different roles and facilities
Generate RSA keys and certificates for each
"""

import os
import sys
import hashlib
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def create_test_users():
    """Create 3 test users with different roles"""
    from app.api_models import db, User
    from app.api_app import create_api_app

    # Create app with database context
    app = create_api_app()

    with app.app_context():
        # Check if users already exist
        existing_users = User.query.all()
        if existing_users:
            print("⚠️  Users already exist in database:")
            for user in existing_users:
                print(f"  - {user.username} ({user.email})")
            print("Delete database first or use different emails.")
            return

        print("=" * 60)
        print("CREATING 3 TEST USERS")
        print("=" * 60)

        # Test users data
        test_users = [
            {
                "full_name": "Super Admin User",
                "username": "superadmin",
                "email": "superadmin@mod.gov",
                "password": "Test@123",
                "user_class": "superadmin",
                "facility": "Ministry of Defence",
                "department": "Cyber Security",
                "clearance_level": "TOP_SECRET",
            },
            {
                "full_name": "Admin User",
                "username": "admin1",
                "email": "admin1@mof.gov",
                "password": "Test@123",
                "user_class": "admin",
                "facility": "Ministry of Finance",
                "department": "Budget",
                "clearance_level": "SECRET",
            },
            {
                "full_name": "Regular User",
                "username": "user1",
                "email": "user1@nsa.gov",
                "password": "Test@123",
                "user_class": "user",
                "facility": "National Security Agency",
                "department": "Operations",
                "clearance_level": "CONFIDENTIAL",
            },
        ]

        created_users = []

        for user_data in test_users:
            print(f"\n📝 Creating user: {user_data['username']}")

            # Check if email already exists
            if User.query.filter_by(email=user_data["email"]).first():
                print(f"  ⚠️  Email {user_data['email']} already exists")
                continue

            # Check if username already exists
            if User.query.filter_by(username=user_data["username"]).first():
                print(f"  ⚠️  Username {user_data['username']} already exists")
                continue

            # Create user (without public key initially)
            new_user = User(
                username=user_data["username"],
                email=user_data["email"],
                user_class=user_data["user_class"],
                facility=user_data["facility"],
                department=user_data["department"],
                clearance_level=user_data["clearance_level"],
                is_active=True,
                created_at=datetime.now(timezone.utc),
                public_key=None,
                public_key_fingerprint=None,
            )

            # Set password
            new_user.password_hash = generate_password_hash(user_data["password"])

            db.session.add(new_user)
            db.session.commit()

            # Generate RSA keys
            public_key = generate_user_keys(new_user)

            created_users.append(
                {
                    "id": new_user.id,
                    "username": new_user.username,
                    "email": new_user.email,
                    "role": new_user.user_class,
                    "password": user_data["password"],
                    "public_key_fingerprint": new_user.public_key_fingerprint,
                }
            )

            print(f"  ✅ User created: {new_user.username} (ID: {new_user.id})")
            print(f"  📧 Email: {new_user.email}")
            print(f"  🏢 Facility: {new_user.facility}")
            print(f"  🔑 Clearance: {new_user.clearance_level}")
            print(f"  🗝️  RSA Key: {'Generated' if public_key else 'Failed'}")

        db.session.commit()

        print("\n" + "=" * 60)
        print("USER CREATION SUMMARY")
        print("=" * 60)

        for user in created_users:
            print(f"\n👤 {user['username']} ({user['role']})")
            print(f"   Email: {user['email']}")
            print(f"   Password: {user['password']}")
            print(f"   User ID: {user['id']}")
            print(
                f"   Key Fingerprint: {user['public_key_fingerprint'][:16]}..."
                if user["public_key_fingerprint"]
                else "   Key Fingerprint: None"
            )

        print("\n📋 Next steps:")
        print("1. Run: python generate_user_certificates.py")
        print("2. Import certificates to browser")
        print("3. Access: https://localhost:5000")

        return created_users


def generate_user_keys(user):
    """Generate RSA key pair for user"""
    try:
        from app.opa_agent.crypto_handler import CryptoHandler

        crypto = CryptoHandler()
        private_key_pem, public_key_pem = crypto.generate_key_pair()

        # Calculate fingerprint
        fingerprint = hashlib.sha256(public_key_pem).hexdigest()

        # Update user with public key
        user.public_key = public_key_pem.decode("utf-8")
        user.public_key_fingerprint = fingerprint

        # Store private key securely
        keys_dir = "keys/private"
        os.makedirs(keys_dir, exist_ok=True)
        key_file = os.path.join(keys_dir, f"user_{user.id}.pem")

        with open(key_file, "wb") as f:
            f.write(private_key_pem)

        # Set secure permissions (Unix only)
        try:
            os.chmod(key_file, 0o600)
        except:
            pass

        print(f"  ✅ RSA keys generated for user {user.username}")
        print(f"    Public key fingerprint: {fingerprint[:16]}...")
        print(f"    Private key stored at: {key_file}")

        return public_key_pem.decode("utf-8")

    except Exception as e:
        print(f"  ❌ Error generating RSA keys: {e}")
        return None


if __name__ == "__main__":
    create_test_users()
