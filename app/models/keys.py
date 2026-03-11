"""
Secure key storage model with proper encoding
"""

import base64
import json
from app.models import db
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

class UserKey(db.Model):
    """Store user's RSA keys securely"""
    __tablename__ = 'user_keys'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    
    # Store keys as base64 to avoid encoding issues
    public_key_b64 = db.Column(db.Text, nullable=False)
    private_key_b64 = db.Column(db.Text, nullable=False)
    
    # Metadata
    key_size = db.Column(db.Integer, default=2048)
    algorithm = db.Column(db.String(50), default='RSA-OAEP-SHA256')
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    last_used = db.Column(db.DateTime, nullable=True)
    
    def __init__(self, user_id, public_key_pem, private_key_pem):
        self.user_id = user_id
        
        # Convert PEM to base64 for safe storage
        self.public_key_b64 = base64.b64encode(public_key_pem.encode()).decode()
        self.private_key_b64 = base64.b64encode(private_key_pem.encode()).decode()
    
    def get_public_key_pem(self):
        """Retrieve public key as PEM"""
        return base64.b64decode(self.public_key_b64).decode()
    
    def get_private_key_pem(self):
        """Retrieve private key as PEM"""
        return base64.b64decode(self.private_key_b64).decode()
    
    @classmethod
    def generate_for_user(cls, user_id):
        """Generate RSA key pair for a user"""
        from app.opa_agent.crypto_handler import CryptoHandler
        
        crypto = CryptoHandler()
        private_pem, public_pem = crypto.generate_key_pair()
        
        # Save as base64
        user_key = cls(
            user_id=user_id,
            public_key_pem=public_pem.decode() if isinstance(public_pem, bytes) else public_pem,
            private_key_pem=private_pem.decode() if isinstance(private_pem, bytes) else private_pem
        )
        
        return user_key