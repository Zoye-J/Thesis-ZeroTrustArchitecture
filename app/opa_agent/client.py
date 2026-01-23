# CREATE: app/opa_agent/client.py
"""
OPA Agent Client for Gateway Server
Handles encryption/decryption with OPA Agent
"""

import requests
import json
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from flask import current_app
import logging

logger = logging.getLogger(__name__)


class OpaAgentClient:
    def __init__(self, app=None):
        self.agent_url = None
        self.agent_public_key = None
        self.session = requests.Session()

        if app:
            self.init_app(app)

    def init_app(self, app):
        """Initialize with Flask app"""
        self.agent_url = app.config.get("OPA_AGENT_URL", "http://localhost:8282")

        # Load OPA Agent public key
        from app.mTLS.cert_manager import cert_manager

        self.agent_public_key = cert_manager.load_opa_agent_public_key()

        logger.info(f"OPA Agent Client initialized: {self.agent_url}")

    def encrypt_for_agent(self, data):
        """Encrypt data with OPA Agent's public key"""
        if not self.agent_public_key:
            raise ValueError("OPA Agent public key not available")

        # Load public key
        public_key = serialization.load_pem_public_key(self.agent_public_key.encode())

        # Convert data to JSON string
        data_str = json.dumps(data)

        # Encrypt
        encrypted = public_key.encrypt(
            data_str.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Return base64 encoded
        return base64.b64encode(encrypted).decode("utf-8")

    def send_to_agent(self, encrypted_data, user_public_key, request_id=None):
        """Send encrypted request to OPA Agent"""
        payload = {
            "encrypted_request": encrypted_data,
            "user_public_key": user_public_key,
            "request_id": request_id or "no-id",
        }

        try:
            response = self.session.post(
                f"{self.agent_url}/evaluate", json=payload, timeout=10
            )

            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"OPA Agent error: {response.status_code}")
                return None

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to connect to OPA Agent: {e}")
            return None

    def get_public_key(self):
        """Get OPA Agent's public key"""
        return self.agent_public_key

    def health_check(self):
        """Check if OPA Agent is healthy"""
        try:
            response = self.session.get(f"{self.agent_url}/health", timeout=3)
            return response.status_code == 200
        except:
            return False


# Singleton instance
opa_agent_client = OpaAgentClient()


def init_opa_agent_client(app):
    """Initialize OPA Agent client"""
    opa_agent_client.init_app(app)


def get_opa_agent_client():
    """Get OPA Agent client instance"""
    return opa_agent_client
