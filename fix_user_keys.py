#!/usr/bin/env python3
"""
Fix all user public keys in database - CORRECTED VERSION
"""

import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def fix_user_keys():
    """Fix malformed public keys in database"""

    # CORRECT IMPORT: Use create_api_app instead of create_app
    from app.api_app import create_api_app

    app = create_api_app()

    with app.app_context():
        from app.models import db, User

        users = User.query.all()
        fixed_count = 0

        for user in users:
            try:
                print(f"\n🔍 Checking user: {user.username}")
                print(f"  ID: {user.id}")
                print(f"  Has public_key field: {bool(user.public_key)}")
                print(f"  Has keys relationship: {bool(user.keys)}")

                # Check UserKey relationship first
                if user.keys:
                    print(f"  ✅ User has UserKey relationship")
                    print(
                        f"  Public key length via keys: {len(user.keys.get_public_key_pem()) if user.keys.get_public_key_pem() else 0}"
                    )

                    # If UserKey exists but public_key field is empty, copy it
                    if not user.public_key and user.keys.get_public_key_pem():
                        user.public_key = user.keys.get_public_key_pem()
                        print(f"  ✅ Copied key from UserKey to public_key field")
                        fixed_count += 1
                        continue

                if user.public_key:
                    # Check if key is valid
                    key = user.public_key.strip()
                    print(f"  Current key length: {len(key)}")
                    print(f"  Starts with -----BEGIN: {key.startswith('-----BEGIN')}")

                    # Common fixes
                    if "-----BEGIN PUBLIC KEY-----" not in key:
                        print(f"⚠️  User {user.username}: Fixing malformed key...")

                        # Generate new key (simpler approach)
                        from app.opa_agent.crypto_handler import CryptoHandler

                        crypto = CryptoHandler()
                        _, new_public = crypto.generate_key_pair()

                        if isinstance(new_public, bytes):
                            new_public = new_public.decode()

                        user.public_key = new_public
                        fixed_count += 1
                        print(f"  ✅ Generated new key for {user.username}")
                        print(f"  New key length: {len(new_public)}")
                        print(
                            f"  New key starts correctly: {new_public.startswith('-----BEGIN PUBLIC KEY-----')}"
                        )

                    else:
                        print(f"✓ User {user.username}: Key looks valid")

                else:
                    print(f"⚠️ User {user.username}: No public key")
                    # Generate one
                    from app.opa_agent.crypto_handler import CryptoHandler

                    crypto = CryptoHandler()
                    _, new_public = crypto.generate_key_pair()

                    if isinstance(new_public, bytes):
                        new_public = new_public.decode()

                    user.public_key = new_public
                    fixed_count += 1
                    print(f"  ✅ Generated new key for {user.username}")
                    print(f"  New key length: {len(new_public)}")

            except Exception as e:
                print(f"❌ Error fixing {user.username}: {e}")
                import traceback

                traceback.print_exc()
                continue

        # Commit changes
        try:
            db.session.commit()
            print(f"\n" + "=" * 60)
            print(f"✅ SUCCESS: Fixed {fixed_count} user keys")
            print("=" * 60)

            # Test all users after fix
            print(f"\n🔍 VERIFICATION - All users:")
            print("-" * 60)

            for user in User.query.all():
                key = user.public_key or ""
                print(f"\n{user.username}:")
                print(f"  Length: {len(key)} chars")
                print(f"  Valid PEM: {key.startswith('-----BEGIN PUBLIC KEY-----')}")
                if key and len(key) > 50:
                    print(
                        f"  Preview: {key[:50]}...{key[-50:] if len(key) > 100 else ''}"
                    )

            print("-" * 60)
            print("✅ Fix completed successfully!")

            return True

        except Exception as e:
            db.session.rollback()
            print(f"❌ Failed to commit: {e}")
            import traceback

            traceback.print_exc()
            return False


if __name__ == "__main__":
    fix_user_keys()
