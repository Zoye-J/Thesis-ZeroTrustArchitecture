# generate_missing_certs.py
"""
Generate certificates for users who don't have them
"""

import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.api_app import create_api_app
from app.mTLS.cert_manager import CertificateManager

app = create_api_app()

with app.app_context():
    from app.api_models import db, User

    cert_manager = CertificateManager()

    users = User.query.all()
    print(f"Found {len(users)} users")

    for user in users:
        print(f"\nUser {user.id}: {user.username} ({user.email})")

        if user.certificate_fingerprint:
            print(
                f"  ✓ Already has certificate: {user.certificate_fingerprint[:16]}..."
            )
            continue

        print(f"  🔐 Generating certificate...")

        try:
            cert_metadata = cert_manager.generate_client_certificate(
                user_id=user.id, email=user.email, department=user.department
            )

            if cert_metadata:
                # Read certificate to get fingerprint
                import hashlib
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend

                cert_path = cert_metadata["paths"]["cert"]
                with open(cert_path, "r") as f:
                    cert_pem = f.read()

                cert = x509.load_pem_x509_certificate(
                    cert_pem.encode(), default_backend()
                )

                cert_info = {
                    "fingerprint": cert.fingerprint(x509.hashes.SHA256()).hex(),
                    "serial_number": format(cert.serial_number, "X"),
                    "subject": {},
                    "issuer": {},
                    "not_valid_before": cert.not_valid_before.isoformat(),
                    "not_valid_after": cert.not_valid_after.isoformat(),
                }

                # Extract subject info
                for attr in cert.subject:
                    cert_info["subject"][attr.oid._name] = attr.value

                # Extract issuer info
                for attr in cert.issuer:
                    cert_info["issuer"][attr.oid._name] = attr.value

                # Associate with user
                user.associate_certificate(cert_info)
                db.session.commit()

                print(f"  ✅ Certificate generated: {cert_info['fingerprint'][:16]}...")
            else:
                print(f"  ❌ Failed to generate certificate")

        except Exception as e:
            print(f"  ❌ Error: {e}")

    print(f"\n✅ Done!")
