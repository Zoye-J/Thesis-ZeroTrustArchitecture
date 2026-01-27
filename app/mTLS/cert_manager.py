"""
Certificate Manager for mTLS - Complete Implementation
Handles certificate generation, validation, and management
BANGLADESH GOVERNMENT VERSION
"""

import os
import subprocess
import json
import hashlib
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import current_app
import base64
from app.logs.zta_event_logger import event_logger, EventType


class CertificateManager:
    def __init__(self, cert_dir="./certs"):
        self.cert_dir = cert_dir
        self.ca_cert_path = os.path.join(cert_dir, "ca.crt")
        self.ca_key_path = os.path.join(cert_dir, "ca.key")
        self.keys_dir = os.path.join(cert_dir, "user_keys")

        # Bangladesh Government Structure
        self.bangladesh_departments = {
            "mod": "Ministry of Defence",
            "mof": "Ministry of Finance",
            "nsa": "National Security Agency",
        }
        self.ensure_dirs()

    def ensure_dirs(self):
        """Ensure all directories exist"""
        if not os.path.exists(self.cert_dir):
            os.makedirs(self.cert_dir)
            print(f"Created certificate directory: {self.cert_dir}")
        if not os.path.exists(self.keys_dir):
            os.makedirs(self.keys_dir)
            print(f"Created keys directory: {self.keys_dir}")

    def run_openssl_command(self, cmd):
        """Execute OpenSSL command with better error handling"""
        try:
            cmd = " ".join(cmd.split())
            print(f"  Running: {cmd[:80]}...")

            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=30
            )

            if result.returncode != 0:
                print(f"  ❌ OpenSSL Error (code {result.returncode}):")
                if result.stderr:
                    print(f"     Error: {result.stderr[:200]}")
                return False
            return True
        except subprocess.TimeoutExpired:
            print(f"  ❌ OpenSSL command timed out")
            return False
        except Exception as e:
            print(f"  ❌ Command execution error: {e}")
            return False

    def generate_root_ca(self):
        """Generate Root Certificate Authority for BANGLADESH"""
        print("🇧🇩 Generating Bangladesh Government Root CA...")

        # Generate CA private key
        ca_key_cmd = f"openssl genrsa -out {self.ca_key_path} 4096"
        if not self.run_openssl_command(ca_key_cmd):
            return False

        # Generate CA certificate with BANGLADESH context
        ca_cert_cmd = f"""
        openssl req -x509 -new -nodes -key {self.ca_key_path} \
        -sha256 -days 3650 -out {self.ca_cert_path} \
        -subj "/C=BD/ST=Dhaka Division/L=Dhaka/O=Government of Bangladesh/OU=ZTA Project/CN=Government ZTA Root CA"
        """
        if not self.run_openssl_command(ca_cert_cmd):
            return False

        print(f"✓ Bangladesh Root CA created: {self.ca_cert_path}")
        return True

    def generate_server_certificate(self, server_name="localhost"):
        """Generate server certificate for BANGLADESH government server"""
        server_key = os.path.join(self.cert_dir, "server.key")
        server_csr = os.path.join(self.cert_dir, "server.csr")
        server_crt = os.path.join(self.cert_dir, "server.crt")
        server_ext = os.path.join(self.cert_dir, "server.ext")

        print(f"🇧🇩 Generating server certificate for Bangladesh government...")

        # Generate server key
        if not self.run_openssl_command(f"openssl genrsa -out {server_key} 2048"):
            return False

        # Create CSR with BANGLADESH context
        csr_cmd = f"""
        openssl req -new -key {server_key} \
        -out {server_csr} \
        -subj "/C=BD/ST=Dhaka Division/L=Dhaka/O=Government ICT/OU=Digital Services/CN={server_name}"
        """
        if not self.run_openssl_command(csr_cmd):
            return False

        # Create extensions file
        ext_content = f"""authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = {server_name}
DNS.2 = localhost
IP.1 = 127.0.0.1
"""

        with open(server_ext, "w") as f:
            f.write(ext_content)

        # Sign certificate
        sign_cmd = f"""
        openssl x509 -req -in {server_csr} \
        -CA {self.ca_cert_path} -CAkey {self.ca_key_path} \
        -CAcreateserial -out {server_crt} \
        -days 365 -sha256 -extfile {server_ext}
        """
        if not self.run_openssl_command(sign_cmd):
            return False

        print(f"✓ Server certificate created: {server_crt}")
        return {"key": server_key, "cert": server_crt, "ca": self.ca_cert_path}

    def generate_client_certificate(self, user_id, email, department_code):
        """Generate client certificate for BANGLADESH government user"""
        # Define ALL file paths first
        client_dir = os.path.join(self.cert_dir, "clients", str(user_id))
        os.makedirs(client_dir, exist_ok=True)

        client_key = os.path.join(client_dir, "client.key")
        client_csr = os.path.join(client_dir, "client.csr")
        client_crt = os.path.join(client_dir, "client.crt")
        client_ext = os.path.join(client_dir, "client.ext")
        client_p12 = os.path.join(client_dir, "client.p12")
        metadata_file = os.path.join(client_dir, "metadata.json")

        # Get Bangladesh department name
        department_name = self.bangladesh_departments.get(
            department_code.lower(), f"Government {department_code}"
        )

        print(
            f"🇧🇩 Generating Bangladesh government certificate for {email} ({department_name})..."
        )

        # Generate client key
        if not self.run_openssl_command(f"openssl genrsa -out {client_key} 2048"):
            return None

        # Create CSR with BANGLADESH context
        csr_cmd = f"""
        openssl req -new -key {client_key} \
        -out {client_csr} \
        -subj "/C=BD/ST=Dhaka Division/L=Dhaka/O={department_name}/OU=ZTA Access/CN={email}/emailAddress={email}"
        """
        if not self.run_openssl_command(csr_cmd):
            return None

        # Create extensions file
        ext_content = f"""[ req ]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn

[ dn ]
C = BD
ST = Dhaka Division
L = Dhaka
O = {department_name}
OU = ZTA Access
CN = {email}
emailAddress = {email}

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = email:{email}
"""

        with open(client_ext, "w") as f:
            f.write(ext_content)

        # Sign certificate
        sign_cmd = f"""
        openssl x509 -req -in {client_csr} \
        -CA {self.ca_cert_path} -CAkey {self.ca_key_path} \
        -CAcreateserial -out {client_crt} \
        -days 365 -sha256 -extfile {client_ext} -extensions v3_req
        """
        if not self.run_openssl_command(sign_cmd):
            return None

        # Create PKCS12 bundle (for browsers)
        p12_cmd = f"""
        openssl pkcs12 -export -out {client_p12} \
        -inkey {client_key} -in {client_crt} \
        -certfile {self.ca_cert_path} -passout pass:password123
        """
        self.run_openssl_command(p12_cmd)  # Optional, don't fail if this doesn't work

        # Read certificate to get fingerprint
        with open(client_crt, "rb") as f:
            cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            serial = format(cert.serial_number, "X")

        # Create metadata
        metadata = {
            "user_id": user_id,
            "email": email,
            "department_code": department_code,
            "department_name": department_name,
            "country": "Bangladesh",
            "region": "Dhaka Division",
            "city": "Dhaka",
            "issued_date": datetime.now().isoformat(),
            "expiry_date": (datetime.now() + timedelta(days=365)).isoformat(),
            "fingerprint": fingerprint,
            "serial_number": serial,
            "paths": {
                "key": client_key,
                "cert": client_crt,
                "p12": client_p12,
                "ca": self.ca_cert_path,
            },
        }

        with open(metadata_file, "w") as f:
            json.dump(metadata, f, indent=2)

        print(f"✓ Client certificate created for {email}")
        print(f"  Certificate directory: {client_dir}")
        print(f"  Fingerprint: {fingerprint}")

        return metadata

    def validate_certificate(self, cert_pem):
        """Validate a client certificate"""
        try:
            # Parse certificate
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())

            # Check if CA exists
            if not os.path.exists(self.ca_cert_path):
                return False, "CA certificate not found"

            # Load CA certificate
            with open(self.ca_cert_path, "rb") as f:
                ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

            # Basic validation
            now = datetime.utcnow()

            if now < cert.not_valid_before:
                return False, "Certificate not yet valid"

            if now > cert.not_valid_after:
                return False, "Certificate expired"

            # Check issuer
            if cert.issuer != ca_cert.subject:
                return False, "Certificate not issued by trusted CA"

            # Extract info
            fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            serial = format(cert.serial_number, "X")

            # Extract subject info
            subject = {}
            for attr in cert.subject:
                subject[attr.oid._name] = attr.value

            issuer = {}
            for attr in cert.issuer:
                issuer[attr.oid._name] = attr.value

            cert_info = {
                "fingerprint": fingerprint,
                "serial_number": serial,
                "subject": subject,
                "issuer": issuer,
                "not_valid_before": cert.not_valid_before.isoformat(),
                "not_valid_after": cert.not_valid_after.isoformat(),
                "raw_certificate": base64.b64encode(cert_pem.encode()).decode(),
            }

            return True, cert_info

        except Exception as e:
            return False, f"Certificate validation error: {str(e)}"

    def validate_certificate_with_detailed_logging(
        self, cert_pem, request_id=None, client_ip=None
    ):
        """Enhanced certificate validation with detailed logging"""
        # ... [keep existing validation_with_detailed_logging method unchanged] ...
        pass  # Keep your existing implementation

    def log_certificate_verification_summary(self, cert_pem, request_id, client_ip):
        """Create a summary log entry for certificate verification"""
        # ... [keep existing log_certificate_verification_summary method unchanged] ...
        pass  # Keep your existing implementation

    def extract_key_usage(self, cert):
        """Extract key usage information from certificate"""
        # ... [keep existing extract_key_usage method unchanged] ...
        pass  # Keep your existing implementation

    def revoke_certificate(self, cert_pem):
        """Revoke a certificate"""
        # ... [keep existing revoke_certificate method unchanged] ...
        pass  # Keep your existing implementation

    def is_certificate_revoked(self, serial):
        """Check if certificate is revoked"""
        # ... [keep existing is_certificate_revoked method unchanged] ...
        pass  # Keep your existing implementation

    def generate_rsa_key_pair(self, user_id, email):
        """Generate RSA key pair for a user"""
        # ... [keep existing generate_rsa_key_pair method unchanged] ...
        pass  # Keep your existing implementation

    def get_user_public_key(self, user_id):
        """Get user's public key from storage"""
        # ... [keep existing get_user_public_key method unchanged] ...
        pass  # Keep your existing implementation

    def generate_opa_agent_keys(self):
        """Generate RSA keys for OPA Agent"""
        # ... [keep existing generate_opa_agent_keys method unchanged] ...
        pass  # Keep your existing implementation

    def load_opa_agent_public_key(self):
        """Load OPA Agent's public key"""
        # ... [keep existing load_opa_agent_public_key method unchanged] ...
        pass  # Keep your existing implementation

    def create_p12_bundle(self, user_id, p12_password):
        """Create PKCS12 bundle for browser import"""
        # ... [keep existing create_p12_bundle method unchanged] ...
        pass  # Keep your existing implementation


# Singleton instance
cert_manager = CertificateManager()
