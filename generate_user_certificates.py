# generate_user_certificates.py - FIXED VERSION
"""
Generate client certificates for all users in database
"""

import os
import sys
import json
from datetime import datetime, timedelta

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def generate_all_user_certificates():
    """Generate certificates for all users"""
    from app.api_models import db, User
    from app.api_app import create_api_app
    from app.mTLS.cert_manager import cert_manager

    # Create app with database context
    app = create_api_app()

    with app.app_context():
        # Get all users
        users = User.query.all()

        if not users:
            print("❌ No users found in database!")
            print("Run create_test_users.py first")
            return

        print("=" * 60)
        print(f"GENERATING CERTIFICATES FOR {len(users)} USERS")
        print("=" * 60)

        certs_generated = []

        for user in users:
            print(f"\n User: {user.username} (ID: {user.id})")
            print(f"   Email: {user.email}")
            print(f"   Role: {user.user_class}")

            # Check if certificate already exists
            cert_dir = f"certs/clients/{user.id}"
            cert_file = os.path.join(cert_dir, "client.crt")

            if os.path.exists(cert_file):
                print(f"   ⚠️  Certificate already exists at: {cert_file}")
                continue

            try:
                # Generate certificate using generate_client_certificate method
                print(f"   🔐 Generating certificate...")

                # Use user's department from database
                department = user.department if user.department else "Operations"

                # Call the CORRECT method: generate_client_certificate (returns metadata dict, not tuple)
                metadata = cert_manager.generate_client_certificate(
                    user_id=user.id, email=user.email, department=department
                )

                if metadata:
                    print(f"   ✅ Certificate generated successfully!")
                    print(f"   📁 Location: {cert_dir}")

                    # Create P12 bundle for browser import
                    p12_file = os.path.join(cert_dir, "client.p12")
                    p12_password = f"zta-{user.id}-{user.username}"

                    # Call create_p12_bundle method
                    success_p12, p12_result = cert_manager.create_p12_bundle(
                        user_id=str(user.id), p12_password=p12_password
                    )

                    if success_p12:
                        print(f"   📦 P12 bundle created: {p12_file}")
                        print(f"   🔐 P12 password: {p12_password}")
                    else:
                        print(f"   ⚠️  P12 bundle creation failed: {p12_result}")

                    certs_generated.append(
                        {
                            "user_id": user.id,
                            "username": user.username,
                            "email": user.email,
                            "cert_dir": cert_dir,
                            "p12_file": p12_file if success_p12 else None,
                            "p12_password": p12_password if success_p12 else None,
                            "metadata": metadata,
                        }
                    )
                else:
                    print(f"   ❌ Failed to generate certificate")

            except Exception as e:
                print(f"   ❌ Error: {e}")
                import traceback

                traceback.print_exc()

        print("\n" + "=" * 60)
        print("CERTIFICATE GENERATION SUMMARY")
        print("=" * 60)

        if certs_generated:
            print(f"\n ✅ Generated {len(certs_generated)} certificates:")
            for cert in certs_generated:
                print(f"\n {cert['username']}")
                print(f"   User ID: {cert['user_id']}")
                print(f"   Certificate directory: {cert['cert_dir']}")
                if cert["p12_file"]:
                    print(f"   P12 file: {cert['p12_file']}")
                    print(f"   P12 password: {cert['p12_password']}")
                if cert.get("metadata", {}).get("fingerprint"):
                    print(f"   Fingerprint: {cert['metadata']['fingerprint'][:16]}...")
        else:
            print("❌ No certificates were generated")

        # Create instructions file
        create_import_instructions(certs_generated)


def create_import_instructions(certs_generated):
    """Create instructions for importing certificates"""
    if not certs_generated:
        return

    instructions = []
    instructions.append("=" * 60)
    instructions.append("CERTIFICATE IMPORT INSTRUCTIONS")
    instructions.append("=" * 60)
    instructions.append("\nFor each user, import the P12 file into your browser:")

    for cert in certs_generated:
        if cert["p12_file"]:
            instructions.append(f"\nUSER: {cert['username']} ({cert['email']}):")
            instructions.append(f"  1. P12 file: {cert['p12_file']}")
            instructions.append(f"  2. Password: {cert['p12_password']}")
            instructions.append(f"  3. Browser import:")
            instructions.append(
                "     - Chrome: chrome://settings/certificates -> Import"
            )
            instructions.append(
                "     - Firefox: about:preferences#privacy -> Certificates -> Import"
            )

    instructions.append("\n" + "=" * 60)
    instructions.append("ACCESSING THE APPLICATION")
    instructions.append("=" * 60)
    instructions.append("1. Open browser to: https://localhost:5000")
    instructions.append("2. When prompted, select the appropriate certificate")
    instructions.append("3. Login with username/password:")

    for cert in certs_generated:
        instructions.append(f"   - {cert['username']}: Test@123")

    instructions.append("\n" + "=" * 60)

    # Save to file with UTF-8 encoding
    with open("certificate_instructions.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(instructions))

    print(f"\nInstructions saved to: certificate_instructions.txt")


if __name__ == "__main__":
    generate_all_user_certificates()
