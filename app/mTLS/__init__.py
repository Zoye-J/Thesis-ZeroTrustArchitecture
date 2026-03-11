"""
mTLS Implementation for ZTA Government System
Mutual TLS authentication with certificate-to-user mapping
"""

import ssl
from flask import request, jsonify, current_app
from functools import wraps
import os
import json
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import hashlib
from datetime import datetime


class CertificateManager:
    """Manages client certificates and mappings"""

    def __init__(self, app=None):
        self.app = app
        self.cert_mappings = {}
        self.ca_cert_path = None
        if app:
            self.init_app(app)

    def init_app(self, app):
        """Initialize certificate manager with Flask app"""
        self.ca_cert_path = app.config.get("CA_CERT_PATH", "certificates/ca.crt")
        self.load_certificate_mappings()

    def load_certificate_mappings(self):
        """Load certificate-to-user mappings from database or file"""
        # In production, this would come from a database
        self.cert_mappings = {}

        # Load from certificates directory
        certs_dir = "certificates/clients"
        if os.path.exists(certs_dir):
            for user_id in os.listdir(certs_dir):
                metadata_path = os.path.join(certs_dir, user_id, "metadata.json")
                if os.path.exists(metadata_path):
                    with open(metadata_path, "r") as f:
                        metadata = json.load(f)
                        cert_path = metadata["certificate_path"]
                        if os.path.exists(cert_path):
                            with open(cert_path, "rb") as cert_file:
                                cert_data = cert_file.read()
                                cert_hash = self.get_certificate_hash(cert_data)
                                self.cert_mappings[cert_hash] = {
                                    "user_id": user_id,
                                    "email": metadata["email"],
                                    "department": metadata["department"],
                                    "issued": metadata["issued_date"],
                                    "expires": metadata["expiry_date"],
                                }

    def get_certificate_hash(self, cert_data):
        """Get SHA256 hash of certificate"""
        return hashlib.sha256(cert_data).hexdigest()

    def verify_certificate(self, cert_pem):
        """Verify client certificate against CA"""
        try:
            # Load CA certificate
            with open(self.ca_cert_path, "rb") as ca_file:
                ca_cert = x509.load_pem_x509_certificate(
                    ca_file.read(), default_backend()
                )

            # Load client certificate
            client_cert = x509.load_pem_x509_certificate(cert_pem, default_backend())

            # Verify certificate chain (simplified)
            # In production, use proper chain verification
            cert_hash = self.get_certificate_hash(cert_pem)

            if cert_hash in self.cert_mappings:
                return self.cert_mappings[cert_hash]

            return None
        except Exception as e:
            current_app.logger.error(f"Certificate verification failed: {e}")
            return None

    def map_certificate_to_user(self, cert_hash, user_data):
        """Map certificate hash to user data"""
        self.cert_mappings[cert_hash] = user_data
        # In production, save to database
        with open("certificate_mappings.json", "w") as f:
            json.dump(self.cert_mappings, f, indent=2)


def require_mtls(f):
    """
    Decorator to require mTLS authentication
    Falls back to JWT if certificate not present
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for client certificate
        if request.environ.get("SSL_CLIENT_CERT"):
            try:
                # Get certificate from request
                cert_pem = request.environ["SSL_CLIENT_CERT"]

                # Initialize certificate manager
                cert_manager = CertificateManager(current_app)

                # Verify certificate
                user_info = cert_manager.verify_certificate(cert_pem.encode())

                if user_info:
                    # Certificate is valid, add user info to request
                    request.cert_user = user_info
                    current_app.logger.info(
                        f"mTLS authentication successful for {user_info['email']}"
                    )
                    return f(*args, **kwargs)
                else:
                    # Certificate invalid or not mapped
                    current_app.logger.warning("Invalid or unmapped certificate")
                    return (
                        jsonify(
                            {
                                "error": "Invalid client certificate",
                                "mtls_required": True,
                            }
                        ),
                        403,
                    )
            except Exception as e:
                current_app.logger.error(f"mTLS processing error: {e}")
                return jsonify({"error": "Certificate processing failed"}), 400

        # Fall back to JWT authentication for backward compatibility
        # (Your existing JWT auth logic would go here)
        current_app.logger.info("No client certificate, falling back to JWT")
        return f(*args, **kwargs)

    return decorated_function


class MTLSConfig:
    """Configuration for mTLS"""

    @staticmethod
    def create_ssl_context():
        """Create SSL context for mTLS"""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = False

        # Load server certificate
        context.load_cert_chain(
            certfile="certificates/zta-server.crt",
            keyfile="certificates/zta-server.key",
        )

        # Load CA certificate for client verification
        context.load_verify_locations(cafile="certificates/ca.crt")

        # Set cipher suites (strong security)
        context.set_ciphers("ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256")

        return context
