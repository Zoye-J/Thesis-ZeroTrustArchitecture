# associate_certificates.py
"""
Associate existing certificates with users in database
"""

import os
import sys
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def associate_certificates():
    """Associate certificates with users"""
    from app.api_models import db, User
    from app.api_app import create_api_app
    from app.mTLS.cert_manager import cert_manager

    app = create_api_app()

    with app.app_context():
        print("=" * 60)
        print("ASSOCIATING CERTIFICATES WITH USERS")
        print("=" * 60)

        users = User.query.all()

        for user in users:
            print(f"\nUser: {user.username} (ID: {user.id})")

            # Check if certificate exists
            cert_dir = f"certs/clients/{user.id}"
            cert_file = os.path.join(cert_dir, "client.crt")
            metadata_file = os.path.join(cert_dir, "metadata.json")

            if not os.path.exists(cert_file):
                print(f"  ❌ Certificate not found: {cert_file}")
                continue

            try:
                # Read certificate
                with open(cert_file, "r") as f:
                    cert_pem = f.read()

                # Validate certificate
                is_valid, cert_info = cert_manager.validate_certificate(cert_pem)

                if is_valid:
                    # Associate with user
                    user.associate_certificate(cert_info)
                    print(f"  ✅ Certificate associated successfully!")
                    print(f"  Fingerprint: {cert_info['fingerprint'][:16]}...")

                    # Also update metadata
                    if os.path.exists(metadata_file):
                        with open(metadata_file, "r") as f:
                            metadata = json.load(f)
                        metadata["associated_at"] = datetime.now().isoformat()
                        with open(metadata_file, "w") as f:
                            json.dump(metadata, f, indent=2)
                else:
                    print(f"  ❌ Certificate validation failed: {cert_info}")

            except Exception as e:
                print(f"  ❌ Error: {e}")

        # Commit changes
        db.session.commit()
        print("\n" + "=" * 60)
        print("✅ Certificate association complete!")
        print("=" * 60)


if __name__ == "__main__":
    associate_certificates()
