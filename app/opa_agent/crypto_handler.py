from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os
import json
import re


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

    def _hybrid_encrypt(self, data_bytes, public_key):
        """
        Hybrid encryption: RSA + AES-GCM
        For data larger than RSA can handle directly
        """
        # Generate random AES key and IV
        aes_key = os.urandom(32)  # 256-bit
        iv = os.urandom(12)  # 96-bit for GCM recommended

        # Encrypt data with AES-GCM
        encryptor = Cipher(
            algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend()
        ).encryptor()

        encrypted_data = encryptor.update(data_bytes) + encryptor.finalize()

        # Get authentication tag
        tag = encryptor.tag

        # Encrypt AES key with RSA
        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Package everything
        result = {
            "type": "hybrid",
            "encrypted_key": base64.b64encode(encrypted_key).decode("utf-8"),
            "encrypted_data": base64.b64encode(encrypted_data).decode("utf-8"),
            "iv": base64.b64encode(iv).decode("utf-8"),
            "tag": base64.b64encode(tag).decode("utf-8"),
            "algorithm": "RSA-OAEP-SHA256 + AES-256-GCM",
        }

        return json.dumps(result)

    def encrypt_for_user(self, data, user_public_key_pem):
        """Encrypt data with user's public key - with hybrid encryption"""
        try:
            # Convert data to bytes
            if isinstance(data, dict):
                data_str = json.dumps(data)
            elif isinstance(data, str):
                data_str = data
            else:
                data_str = str(data)

            data_bytes = data_str.encode("utf-8")

            print(f"🔐 Encrypting for user: data size {len(data_bytes)} bytes")

            # Step 1: Validate and clean public key
            cleaned_key = self._validate_and_clean_public_key(user_public_key_pem)

            if not cleaned_key:
                print("❌ Invalid public key format after cleaning")
                raise ValueError("Invalid public key format")

            print(f"✅ Cleaned public key length: {len(cleaned_key)}")

            # Step 2: Load public key
            public_key = None
            errors = []

            # Try direct load
            try:
                public_key = serialization.load_pem_public_key(cleaned_key.encode())
                print("✅ Method 1 succeeded: direct PEM load")
            except Exception as e:
                errors.append(f"Method 1 failed: {e}")

            # Try with fixed format
            if not public_key:
                try:
                    fixed_key = self._try_fix_pem_format(cleaned_key)
                    public_key = serialization.load_pem_public_key(fixed_key.encode())
                    print("✅ Method 2 succeeded: fixed PEM format")
                except Exception as e:
                    errors.append(f"Method 2 failed: {e}")

            if not public_key:
                print("❌ All key loading methods failed")
                for error in errors:
                    print(f"  - {error}")
                raise ValueError("Failed to load public key")

            # Step 3: Choose encryption method based on data size
            max_rsa_size = 190  # Safe limit for RSA-2048 with OAEP

            if len(data_bytes) <= max_rsa_size:
                # Direct RSA encryption for small data
                print(f"📏 Using direct RSA encryption ({len(data_bytes)} bytes)")
                encrypted = public_key.encrypt(
                    data_bytes,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
                result = base64.b64encode(encrypted).decode("utf-8")
                print(f"✅ Direct encryption successful: {len(result)} chars")
                return result
            else:
                # Hybrid encryption for large data
                print(
                    f"📏 Data too large for RSA ({len(data_bytes)} > {max_rsa_size}), using hybrid encryption"
                )
                result = self._hybrid_encrypt(data_bytes, public_key)
                print(f"✅ Hybrid encryption successful: {len(result)} chars")
                return result

        except Exception as e:
            print(f"❌ Encryption error: {e}")
            import traceback

            traceback.print_exc()
            raise

    def decrypt_from_user(self, encrypted_data, agent_private_key_pem):
        """Decrypt data with agent's private key - handles both direct and hybrid"""
        try:
            # Check if this is hybrid encrypted
            if encrypted_data.startswith("{"):
                try:
                    package = json.loads(encrypted_data)
                    if package.get("type") == "hybrid":
                        return self._hybrid_decrypt(package, agent_private_key_pem)
                except:
                    pass  # Not JSON or not hybrid, continue with direct

            # Direct RSA decryption
            print(f"🔐 Direct decrypt: {len(encrypted_data)} chars")

            # Decode base64
            encrypted_bytes = base64.b64decode(encrypted_data)
            print(f"🔐 Decoded bytes: {len(encrypted_bytes)}")

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

            print(f"✅ Direct decrypt successful: {len(decrypted)} bytes")
            return decrypted.decode()

        except Exception as e:
            print(f"❌ Decryption failed: {e}")
            raise

    def _hybrid_decrypt(self, package, agent_private_key_pem):
        """Decrypt hybrid encrypted data"""
        print("🔐 Hybrid decrypt started")

        # Load private key
        private_key = serialization.load_pem_private_key(
            agent_private_key_pem.encode(), password=None
        )

        # Decode components
        encrypted_key = base64.b64decode(package["encrypted_key"])
        encrypted_data = base64.b64decode(package["encrypted_data"])
        iv = base64.b64decode(package["iv"])
        tag = base64.b64decode(package["tag"])

        # Decrypt AES key with RSA
        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Decrypt data with AES-GCM
        decryptor = Cipher(
            algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend()
        ).decryptor()

        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        print(f"✅ Hybrid decrypt successful: {len(decrypted_data)} bytes")
        return decrypted_data.decode()

    def _try_fix_pem_format(self, key_str):
        """Try to fix PEM format by ensuring proper headers and line breaks"""
        key_str = key_str.strip()

        if "-----BEGIN PUBLIC KEY-----" in key_str:
            match = re.search(
                r"-----BEGIN PUBLIC KEY-----(.*?)-----END PUBLIC KEY-----",
                key_str,
                re.DOTALL,
            )
            if match:
                content = match.group(1).strip()
                content = re.sub(r"\s", "", content)
                formatted = "-----BEGIN PUBLIC KEY-----\n"
                for i in range(0, len(content), 64):
                    formatted += content[i : i + 64] + "\n"
                formatted += "-----END PUBLIC KEY-----"
                return formatted

        return key_str

    def _validate_and_clean_public_key(self, key_str):
        """Validate and clean public key"""
        if not key_str or len(key_str) < 100:
            print(f"❌ Key too short: {len(key_str) if key_str else 0}")
            return None

        # Remove any database escape characters
        key_str = key_str.replace("\\n", "\n").replace("\\r", "\r").strip()

        # Ensure proper PEM format
        if "-----BEGIN PUBLIC KEY-----" not in key_str:
            key_str = f"-----BEGIN PUBLIC KEY-----\n{key_str}\n-----END PUBLIC KEY-----"

        # Ensure proper line breaks
        lines = key_str.split("\n")
        if len(lines) < 3:  # Single line PEM
            content = (
                lines[0]
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .strip()
            )
            formatted = "-----BEGIN PUBLIC KEY-----\n"
            for i in range(0, len(content), 64):
                formatted += content[i : i + 64] + "\n"
            formatted += "-----END PUBLIC KEY-----"
            return formatted

        return key_str
