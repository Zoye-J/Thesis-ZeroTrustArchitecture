#!/usr/bin/env python
"""
Test SSL fix for OPA Agent connection
"""

import sys
import os

print(f"Python version: {sys.version}")

# Apply patch first
try:
    from app import ssl_patch

    print("✅ SSL patch applied")
except ImportError as e:
    print(f"❌ Could not import SSL patch: {e}")

# Now test connection
import requests

print("\nTesting OPA Agent connection...")
try:
    # Test with our patched SSL
    response = requests.get(
        "https://localhost:8282/health", verify="certs/ca.crt", timeout=5
    )
    print(f"✅ Connection successful: {response.status_code}")
    print(f"Response: {response.json()}")
except Exception as e:
    print(f"❌ Connection failed: {e}")

# Test OPA Agent client
print("\nTesting OPA Agent client...")
try:
    # Create a mock app for testing
    class MockApp:
        config = {
            "OPA_AGENT_URL": "https://localhost:8282",
            "CA_CERT_PATH": "certs/ca.crt",
        }

    from app.opa_agent.client import init_opa_agent_client, get_opa_agent_client

    # Initialize client
    init_opa_agent_client(MockApp())
    client = get_opa_agent_client()

    print(f"Client initialized: {client is not None}")
    print(f"Agent public key loaded: {bool(client.agent_public_key)}")
    print(
        f"Public key length: {len(client.agent_public_key) if client.agent_public_key else 0}"
    )
    print(f"Session created: {bool(client.session)}")

    # Test health check
    healthy = client.health_check()
    print(f"Health check: {'✅' if healthy else '❌'}")

    # Test encryption
    if client.agent_public_key:
        test_data = {"test": "data", "timestamp": "2024-01-01"}
        try:
            encrypted = client.encrypt_for_agent(test_data)
            print(f"✅ Encryption successful: {len(encrypted)} chars")

            # Don't actually send without a real user key
            print("✅ Encryption test passed")
        except Exception as e:
            print(f"❌ Encryption failed: {e}")

except Exception as e:
    print(f"❌ Client test failed: {e}")
    import traceback

    traceback.print_exc()
