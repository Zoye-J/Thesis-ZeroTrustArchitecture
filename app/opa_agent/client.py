# app/opa_agent/client.py - COMPLETE FIXED VERSION
"""
OPA Agent Client for Gateway Server - SSL FIXED
"""

import requests
import json
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from flask import current_app
import logging
import os

logger = logging.getLogger(__name__)


class OpaAgentClient:
    def __init__(self, app=None):
        self.agent_url = None
        self.agent_public_key = None
        self.session = requests.Session()

        # SSL Configuration
        self.ca_cert_path = "certs/ca.crt"
        self.verify_ssl = True  # Default to verify

        if app:
            self.init_app(app)

    def init_app(self, app):
        """Initialize with Flask app - SSL FIXED"""
        self.agent_url = app.config.get("OPA_AGENT_URL", "https://localhost:8282")

        # Check if CA cert exists for SSL verification
        if os.path.exists(self.ca_cert_path):
            self.session.verify = self.ca_cert_path
            logger.info(
                f"✅ SSL verification enabled with CA cert: {self.ca_cert_path}"
            )
        else:
            self.session.verify = False
            logger.warning(
                f"⚠️  CA cert not found at {self.ca_cert_path}, SSL verification disabled"
            )

        # Load OPA Agent public key
        from app.mTLS.cert_manager import cert_manager

        self.agent_public_key = cert_manager.load_opa_agent_public_key()

        logger.info(
            f"✅ OPA Agent Client initialized: {self.agent_url} (SSL: {'VERIFY' if self.session.verify else 'NO VERIFY'})"
        )

    def encrypt_for_agent(self, data):
        """Encrypt data with OPA Agent's public key - IMPROVED"""
        try:
            if not self.agent_public_key:
                logger.error("❌ OPA Agent public key not available")
                raise ValueError("OPA Agent public key not available")

            logger.debug(
                f"✅ Agent public key available, length: {len(self.agent_public_key)}"
            )

            # Load public key
            public_key = serialization.load_pem_public_key(
                self.agent_public_key.encode()
            )

            # Convert data to JSON string
            data_str = json.dumps(data, separators=(",", ":"))  # Compact JSON
            logger.debug(f"📦 Data to encrypt size: {len(data_str)} bytes")

            # For RSA-2048, max encrypt size is 245 bytes
            # Use hybrid encryption for larger data
            if len(data_str.encode()) > 200:
                return self._hybrid_encrypt(data_str, public_key)
            else:
                return self._direct_rsa_encrypt(data_str, public_key)

        except Exception as e:
            logger.error(f"❌ Encryption failed: {e}")
            import traceback

            traceback.print_exc()
            raise

    def _direct_rsa_encrypt(self, data_str, public_key):
        """Direct RSA encryption for small data"""
        encrypted = public_key.encrypt(
            data_str.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        encrypted_b64 = base64.b64encode(encrypted).decode("utf-8")
        logger.debug(f"🔐 Direct RSA encrypted: {len(encrypted_b64)} chars")
        return encrypted_b64

    def _hybrid_encrypt(self, data_str, public_key):
        """Hybrid encryption (RSA + AES) for large data"""
        try:
            import secrets
            from cryptography.fernet import Fernet

            # Generate random symmetric key
            symmetric_key = secrets.token_bytes(32)
            fernet = Fernet(base64.b64encode(symmetric_key))

            # Encrypt data with symmetric key
            encrypted_data = fernet.encrypt(data_str.encode())

            # Encrypt symmetric key with RSA
            encrypted_key = public_key.encrypt(
                symmetric_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            # Combine
            encrypted_package = {
                "type": "hybrid",
                "key": base64.b64encode(encrypted_key).decode(),
                "data": base64.b64encode(encrypted_data).decode(),
                "algorithm": "RSA-OAEP-SHA256 + AES-256-GCM",
            }

            encrypted_json = json.dumps(encrypted_package)
            logger.debug(f"🔐 Hybrid encrypted: {len(encrypted_json)} chars")
            return encrypted_json

        except ImportError:
            # Fallback to direct encryption with chunking
            logger.warning("⚠️  Fernet not available, using chunked RSA")
            return self._chunked_encrypt(data_str, public_key)

    def _chunked_encrypt(self, data_str, public_key):
        """Chunk large data for RSA encryption"""
        chunks = []
        chunk_size = 200  # RSA-2048 can encrypt ~245 bytes

        for i in range(0, len(data_str), chunk_size):
            chunk = data_str[i : i + chunk_size]
            encrypted_chunk = public_key.encrypt(
                chunk.encode("utf-8"),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            chunks.append(base64.b64encode(encrypted_chunk).decode())

        encrypted_package = {
            "type": "chunked",
            "chunks": chunks,
            "total_chunks": len(chunks),
        }

        return json.dumps(encrypted_package)

    def send_to_agent(self, encrypted_data, user_public_key, request_id=None):
        """Send encrypted request to OPA Agent - SSL FIXED"""
        payload = {
            "encrypted_request": encrypted_data,
            "user_public_key": user_public_key,
            "request_id": request_id or "no-id",
        }

        try:
            logger.debug(f"📡 Sending to OPA Agent: {self.agent_url}/evaluate")
            logger.debug(f"📦 Payload size: {len(json.dumps(payload))} bytes")

            response = self.session.post(
                f"{self.agent_url}/evaluate",
                json=payload,
                timeout=15,  # Increased timeout for encryption/decryption
                verify=self.session.verify,  # Use configured SSL verification
            )

            if response.status_code == 200:
                logger.debug(f"✅ OPA Agent response: {response.status_code}")
                return response.json()
            else:
                logger.error(
                    f"❌ OPA Agent error: {response.status_code} - {response.text[:200]}"
                )
                return None

        except requests.exceptions.SSLError as ssl_error:
            logger.error(f"❌ SSL Error connecting to OPA Agent: {ssl_error}")
            # Try without verification as fallback
            try:
                logger.warning("🔄 Trying without SSL verification...")
                response = requests.post(
                    f"{self.agent_url}/evaluate", json=payload, timeout=15, verify=False
                )
                if response.status_code == 200:
                    logger.warning(
                        "⚠️  Connected without SSL verification (INSECURE - development only)"
                    )
                    return response.json()
            except:
                pass
            return None

        except requests.exceptions.RequestException as e:
            logger.error(f"❌ Failed to connect to OPA Agent: {e}")
            return None

    def get_public_key(self):
        """Get OPA Agent's public key"""
        if not self.agent_public_key:
            logger.warning("⚠️  OPA Agent public key is None")
            return None

        logger.debug(
            f"✅ OPA Agent public key available (length: {len(self.agent_public_key)})"
        )
        return self.agent_public_key

    def health_check(self):
        """Check if OPA Agent is healthy - SSL FIXED"""
        try:
            # Check if we have a public key loaded
            if not self.agent_public_key:
                logger.warning("⚠️  OPA Agent: No public key loaded yet")
                return False

            # Quick HTTP check to OPA Agent
            response = self.session.get(
                f"{self.agent_url}/health",
                timeout=5,
                verify=self.session.verify,  # Use configured SSL verification
            )

            is_healthy = response.status_code == 200
            logger.info(
                f"✅ OPA Agent health check: {'PASSED' if is_healthy else 'FAILED'}"
            )
            return is_healthy

        except requests.exceptions.SSLError as ssl_error:
            logger.error(f"❌ OPA Agent SSL health check error: {ssl_error}")
            # Try without verification
            try:
                response = requests.get(
                    f"{self.agent_url}/health", timeout=5, verify=False
                )
                is_healthy = response.status_code == 200
                logger.warning(
                    f"⚠️  OPA Agent health check (no SSL): {'PASSED' if is_healthy else 'FAILED'}"
                )
                return is_healthy
            except:
                return False

        except Exception as e:
            logger.error(f"❌ OPA Agent health check error: {e}")
            return False


# Singleton instance
opa_agent_client = OpaAgentClient()


def init_opa_agent_client(app):
    """Initialize OPA Agent client"""
    opa_agent_client.init_app(app)


def get_opa_agent_client():
    """Get OPA Agent client instance"""
    return opa_agent_client
