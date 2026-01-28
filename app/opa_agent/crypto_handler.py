from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import base64


class CryptoHandler:
    def generate_key_pair(self):
        """Generate RSA key pair for user"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        public_key = private_key.public_key()

        # Serialize
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return private_pem, public_pem

    def encrypt_for_user(self, data, user_public_key_pem):
        """Encrypt data with user's public key - WITH VALIDATION"""
        try:
            # Debug: Check key format
            print(f"🔐 Encrypting for user - Key length: {len(user_public_key_pem)}")
            print(f"🔐 Key preview: {user_public_key_pem[:200]}")

            # Clean the key - remove any extra whitespace
            cleaned_key = user_public_key_pem.strip()

            # Ensure it has proper PEM format
            if not cleaned_key.startswith("-----BEGIN PUBLIC KEY-----"):
                # Try to fix common issues
                if "PUBLIC KEY" in cleaned_key:
                    # Key might be missing BEGIN/END lines
                    cleaned_key = f"-----BEGIN PUBLIC KEY-----\n{cleaned_key}\n-----END PUBLIC KEY-----"
                else:
                    # Might be in wrong format - convert from database format
                    cleaned_key = self._fix_public_key_format(cleaned_key)

            print(
                f"🔐 Cleaned key starts correctly: {cleaned_key.startswith('-----BEGIN PUBLIC KEY-----')}"
            )

            # Load public key
            public_key = serialization.load_pem_public_key(cleaned_key.encode())

            encrypted = public_key.encrypt(
                data.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            return base64.b64encode(encrypted).decode()

        except Exception as e:
            print(f"❌ Encryption error: {e}")
            import traceback

            traceback.print_exc()
            raise


def _fix_public_key_format(self, key_str):
    """Fix common public key format issues"""
    # Remove any database encoding issues
    key_str = key_str.replace("\\n", "\n").replace("\\r", "")

    # If it's base64 encoded, decode it
    if len(key_str) > 300 and " " not in key_str and "\n" not in key_str:
        try:
            # Might be base64 without PEM headers
            import base64

            decoded = base64.b64decode(key_str)
            # Convert back to PEM
            key_str = f"-----BEGIN PUBLIC KEY-----\n{base64.b64encode(decoded).decode()}\n-----END PUBLIC KEY-----"
        except:
            pass

    return key_str

    def decrypt_from_user(self, encrypted_data, agent_private_key_pem):
        """Decrypt data with agent's private key - FIXED"""
        try:
            # Make sure encrypted_data is base64 string
            if not isinstance(encrypted_data, str):
                raise ValueError("Encrypted data must be a string")

            # Clean up the encrypted data
            encrypted_data = encrypted_data.strip()

            # Debug
            print(f"🔐 Decrypting data length: {len(encrypted_data)}")
            print(f"🔐 First 100 chars: {encrypted_data[:100]}")

            # Decode base64
            try:
                encrypted_bytes = base64.b64decode(encrypted_data)
            except Exception as e:
                print(f"❌ Base64 decode error: {e}")
                # Try URL-safe base64
                import base64 as b64

                encrypted_bytes = b64.urlsafe_b64decode(
                    encrypted_data + "=" * (4 - len(encrypted_data) % 4)
                )

            print(f"🔐 Decoded bytes length: {len(encrypted_bytes)}")

            # Load private key
            private_key = serialization.load_pem_private_key(
                agent_private_key_pem.encode(), password=None
            )

            # Decrypt
            decrypted = private_key.decrypt(
                encrypted_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            print(f"✅ Decrypted successfully: {len(decrypted)} bytes")
            return decrypted.decode()

        except Exception as e:
            print(f"❌ Decryption failed: {e}")
            import traceback

            traceback.print_exc()
            raise
