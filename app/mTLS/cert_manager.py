"""
Certificate Manager for mTLS - Complete Implementation
Handles certificate generation, validation, and management
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


class CertificateManager:
    def __init__(self, cert_dir="./certs"):
        self.cert_dir = cert_dir
        self.ca_cert_path = os.path.join(cert_dir, "ca.crt")
        self.ca_key_path = os.path.join(cert_dir, "ca.key")
        # NEW: Add keys directory
        self.keys_dir = os.path.join(cert_dir, "user_keys")
        self.ensure_dirs()

    def ensure_dirs(self):
        """Ensure all directories exist"""
        if not os.path.exists(self.cert_dir):
            os.makedirs(self.cert_dir)
            print(f"Created certificate directory: {self.cert_dir}")
        # NEW: Ensure keys directory
        if not os.path.exists(self.keys_dir):
            os.makedirs(self.keys_dir)
            print(f"Created keys directory: {self.keys_dir}")

    def run_openssl_command(self, cmd):
        """Execute OpenSSL command"""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"OpenSSL Error: {result.stderr}")
                return False
            return True
        except Exception as e:
            print(f"Command execution error: {e}")
            return False

    def validate_certificate_with_detailed_logging(
        self, cert_pem, request_id=None, client_ip=None
    ):
        """Enhanced certificate validation with detailed logging for dashboard"""
        from app.logs.zta_event_logger import zta_logger

        validation_checks = {
            "certificate_present": False,
            "format_valid": False,
            "signature_valid": False,
            "not_expired": False,
            "not_revoked": False,
            "issuer_trusted": False,
            "key_usage_valid": False,
            "time_restrictions_passed": True,
        }

        cert_info = {}
        validation_result = "FAILED"

        try:
            # Parse certificate
            validation_checks["certificate_present"] = bool(cert_pem)

            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            validation_checks["format_valid"] = True

            # Extract certificate details
            fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            serial = format(cert.serial_number, "X")

            # Get subject and issuer
            subject = {}
            for attr in cert.subject:
                subject[attr.oid._name] = attr.value

            issuer = {}
            for attr in cert.issuer:
                issuer[attr.oid._name] = attr.value

            # Check validity period
            now = datetime.utcnow()
            validation_checks["not_expired"] = now < cert.not_valid_after
            validation_checks["not_yet_valid"] = now >= cert.not_valid_before

            # Check issuer
            if os.path.exists(self.ca_cert_path):
                with open(self.ca_cert_path, "rb") as f:
                    ca_cert = x509.load_pem_x509_certificate(
                        f.read(), default_backend()
                    )
                    validation_checks["issuer_trusted"] = cert.issuer == ca_cert.subject

            # Check revocation
            validation_checks["not_revoked"] = not self.is_certificate_revoked(serial)

            # Check key usage
            try:
                # Extract key usage extension
                key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
                validation_checks["key_usage_valid"] = key_usage.value.digital_signature
            except:
                validation_checks["key_usage_valid"] = (
                    True  # Assume valid if extension not present
                )

            # Build cert info
            cert_info = {
                "fingerprint": fingerprint,
                "serial_number": serial,
                "subject": subject,
                "issuer": issuer,
                "not_valid_before": cert.not_valid_before.isoformat(),
                "not_valid_after": cert.not_valid_after.isoformat(),
                "signature_algorithm": (
                    cert.signature_algorithm_oid._name
                    if hasattr(cert.signature_algorithm_oid, "_name")
                    else str(cert.signature_algorithm_oid)
                ),
                "version": cert.version.name,
            }

            # Determine overall result
            all_passed = all(validation_checks.values())
            validation_result = "PASSED" if all_passed else "FAILED"

            # Log detailed validation
            log_details = {
                "certificate_info": cert_info,
                "validation_checks": validation_checks,
                "overall_result": validation_result,
                "client_ip": client_ip,
                "checks_passed": sum(1 for v in validation_checks.values() if v),
                "total_checks": len(validation_checks),
            }

            if request_id:
                event_type = (
                    "CERTIFICATE_VALIDATION_PASSED"
                    if all_passed
                    else "CERTIFICATE_VALIDATION_FAILED"
                )
                zta_logger.log_event(
                    event_type,
                    log_details,
                    user_id=subject.get("emailAddress"),
                    request_id=request_id,
                )

            return all_passed, cert_info, validation_checks

        except Exception as e:
            # Log validation error
            log_details = {
                "error": str(e),
                "validation_checks": validation_checks,
                "overall_result": "ERROR",
                "client_ip": client_ip,
                "exception_type": type(e).__name__,
            }

        if request_id:
            zta_logger.log_event(
                "CERTIFICATE_VALIDATION_ERROR", log_details, request_id=request_id
            )

        return False, cert_info, validation_checks

    def log_certificate_verification_summary(self, cert_pem, request_id, client_ip):
        """Create a summary log entry for certificate verification"""
        from app.logs.zta_event_logger import zta_logger

        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            fingerprint = cert.fingerprint(hashes.SHA256()).hex()

            # Extract certificate chain info
            subject_info = {}
            for attr in cert.subject:
                subject_info[attr.oid._name] = attr.value

            issuer_info = {}
            for attr in cert.issuer:
                issuer_info[attr.oid._name] = attr.value

            # Calculate remaining validity
            now = datetime.utcnow()
            valid_days = (cert.not_valid_after - now).days

            # Log certificate verification summary
            summary = {
                "certificate_fingerprint": fingerprint,
                "subject": subject_info,
                "issuer": issuer_info,
                "validity": {
                    "from": cert.not_valid_before.isoformat(),
                    "to": cert.not_valid_after.isoformat(),
                    "remaining_days": valid_days,
                    "is_expired": valid_days <= 0,
                },
                "client_ip": client_ip,
                "verification_timestamp": now.isoformat(),
                "certificate_strength": "RSA-2048",  # You can extract this from cert
                "key_usage": self.extract_key_usage(cert),
            }

            zta_logger.log_event(
                "CERTIFICATE_VERIFICATION_SUMMARY", summary, request_id=request_id
            )

            return summary

        except Exception as e:
            zta_logger.log_event(
                "CERTIFICATE_SUMMARY_ERROR",
                {"error": str(e), "client_ip": client_ip},
                request_id=request_id,
            )
            return None

    def extract_key_usage(self, cert):
        """Extract key usage information from certificate"""
        key_usage = {}
        try:
            ku_ext = cert.extensions.get_extension_for_class(x509.KeyUsage)
            if ku_ext:
                key_usage = {
                    "digital_signature": ku_ext.value.digital_signature,
                    "key_encipherment": ku_ext.value.key_encipherment,
                    "data_encipherment": ku_ext.value.data_encipherment,
                    "key_agreement": ku_ext.value.key_agreement,
                    "key_cert_sign": ku_ext.value.key_cert_sign,
                    "crl_sign": ku_ext.value.crl_sign,
                }
        except:
            pass
        return key_usage

    def generate_root_ca(self):
        """Generate Root Certificate Authority"""
        print("Generating Root CA...")

        # Generate CA private key
        ca_key_cmd = f"openssl genrsa -out {self.ca_key_path} 4096"
        if not self.run_openssl_command(ca_key_cmd):
            return False

        # Generate CA certificate
        ca_cert_cmd = f"""
        openssl req -x509 -new -nodes -key {self.ca_key_path} \
        -sha256 -days 3650 -out {self.ca_cert_path} \
        -subj "/C=GB/ST=England/L=London/O=Government ZTA/CN=ZTA Root CA"
        """
        if not self.run_openssl_command(ca_cert_cmd):
            return False

        print(f"✓ Root CA created: {self.ca_cert_path}")
        return True

    def generate_server_certificate(self, server_name="localhost"):
        """Generate server certificate signed by CA"""
        server_key = os.path.join(self.cert_dir, "server.key")
        server_csr = os.path.join(self.cert_dir, "server.csr")
        server_crt = os.path.join(self.cert_dir, "server.crt")
        server_ext = os.path.join(self.cert_dir, "server.ext")

        print(f"Generating server certificate for {server_name}...")

        # Generate server key
        if not self.run_openssl_command(f"openssl genrsa -out {server_key} 2048"):
            return False

        # Create CSR
        csr_cmd = f"""
        openssl req -new -key {server_key} \
        -out {server_csr} \
        -subj "/C=GB/ST=England/L=London/O=Government Ministry/CN={server_name}"
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

    def generate_client_certificate(self, user_id, email, department):
        """Generate client certificate for a specific user"""
        client_dir = os.path.join(self.cert_dir, "clients", str(user_id))
        os.makedirs(client_dir, exist_ok=True)

        client_key = os.path.join(client_dir, "client.key")
        client_csr = os.path.join(client_dir, "client.csr")
        client_crt = os.path.join(client_dir, "client.crt")
        client_ext = os.path.join(client_dir, "client.ext")
        client_p12 = os.path.join(client_dir, "client.p12")
        metadata_file = os.path.join(client_dir, "metadata.json")

        print(f"Generating client certificate for {email}...")

        # Generate client key
        if not self.run_openssl_command(f"openssl genrsa -out {client_key} 2048"):
            return None

        # Create CSR
        csr_cmd = f"""
        openssl req -new -key {client_key} \
        -out {client_csr} \
        -subj "/C=GB/ST=England/L=London/O=Government {department}/CN={email}/emailAddress={email}"
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
C = GB
ST = England
L = London
O = Government {department}
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
            "department": department,
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

            # Check issuer (simplified - in production, verify chain properly)
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

    def revoke_certificate(self, cert_pem):
        """Revoke a certificate (add to CRL)"""
        # Placeholder - in production, implement proper CRL
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            serial = format(cert.serial_number, "X")

            # Add to revocation list
            crl_file = os.path.join(self.cert_dir, "crl.json")
            if os.path.exists(crl_file):
                with open(crl_file, "r") as f:
                    revoked = json.load(f)
            else:
                revoked = []

            revoked.append(
                {
                    "serial": serial,
                    "revoked_at": datetime.now().isoformat(),
                    "reason": "user_request",
                }
            )

            with open(crl_file, "w") as f:
                json.dump(revoked, f, indent=2)

            return True, f"Certificate {serial} revoked"
        except Exception as e:
            return False, str(e)

    def is_certificate_revoked(self, serial):
        """Check if certificate is revoked"""
        crl_file = os.path.join(self.cert_dir, "crl.json")
        if os.path.exists(crl_file):
            with open(crl_file, "r") as f:
                revoked = json.load(f)
                return any(entry["serial"] == serial for entry in revoked)
        return False

    # =========================================================================
    # NEW RSA KEY FUNCTIONS - MINIMAL ADDITION
    # =========================================================================

    def generate_rsa_key_pair(self, user_id, email):
        """Generate RSA key pair for a user (simplified version)"""
        # Create user-specific directory
        user_key_dir = os.path.join(self.keys_dir, str(user_id))
        os.makedirs(user_key_dir, exist_ok=True)

        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Generate public key
        public_key = private_key.public_key()

        # Serialize private key (PEM format)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Serialize public key (PEM format)
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Save keys to files
        private_key_path = os.path.join(user_key_dir, "private.pem")
        public_key_path = os.path.join(user_key_dir, "public.pem")

        with open(private_key_path, "wb") as f:
            f.write(private_pem)

        with open(public_key_path, "wb") as f:
            f.write(public_pem)

        # Return key info
        return {
            "user_id": user_id,
            "email": email,
            "public_key": public_pem.decode("utf-8"),
            "private_key_path": private_key_path,
            "public_key_path": public_key_path,
            "key_size": 2048,
            "algorithm": "RSA",
            "generated_at": datetime.now().isoformat(),
        }

    def get_user_public_key(self, user_id):
        """Get user's public key from storage"""
        user_key_dir = os.path.join(self.keys_dir, str(user_id))
        public_key_path = os.path.join(user_key_dir, "public.pem")

        if os.path.exists(public_key_path):
            with open(public_key_path, "r") as f:
                return f.read()
        return None

    def generate_opa_agent_keys(self):
        """Generate RSA keys for OPA Agent (simplified)"""
        agent_key_dir = os.path.join(self.cert_dir, "opa_agent")
        os.makedirs(agent_key_dir, exist_ok=True)

        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Generate public key
        public_key = private_key.public_key()

        # Serialize keys
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Save to files
        private_key_path = os.path.join(agent_key_dir, "private.pem")
        public_key_path = os.path.join(agent_key_dir, "public.pem")

        with open(private_key_path, "wb") as f:
            f.write(private_pem)

        with open(public_key_path, "wb") as f:
            f.write(public_pem)

        print(f"✓ OPA Agent keys generated in: {agent_key_dir}")
        return public_pem.decode("utf-8")

    def load_opa_agent_public_key(self):
        """Load OPA Agent's public key"""
        public_key_path = os.path.join(self.cert_dir, "opa_agent", "public.pem")

        if os.path.exists(public_key_path):
            with open(public_key_path, "r") as f:
                return f.read()

        # Generate if doesn't exist
        return self.generate_opa_agent_keys()


# Singleton instance
cert_manager = CertificateManager()
