<<<<<<< HEAD
# save as check_opa_cert.py
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import ssl
import socket


def check_cert(host, port):
    try:
        cert = ssl.get_server_certificate((host, port))
        print(f"Certificate for {host}:{port}:\n")
        cert_obj = x509.load_pem_x509_certificate(cert.encode(), default_backend())

        print(f"Subject: {cert_obj.subject}")
        print(f"Issuer: {cert_obj.issuer}")
        print(f"Version: {cert_obj.version}")

        # Check SAN
        try:
            san = cert_obj.extensions.get_extension_for_oid(
                x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            print(f"SAN: {san.value}")
        except:
            print("⚠️  No SAN extension found - THIS IS THE PROBLEM!")

    except Exception as e:
        print(f"Error: {e}")


check_cert("localhost", 8282)
=======
#!/usr/bin/env python3
"""
Test the OPA fix
"""

import requests
import json

def test_opa_directly():
    """Test OPA server directly"""
    url = "https://localhost:8181/v1/data/zta/allow"
    
    test_cases = [
        {
            "name": "SECRET user accessing SECRET resource (same dept)",
            "input": {
                "user": {
                    "username": "testuser",
                    "clearance": "SECRET",
                    "department": "MOD"
                },
                "resource": {
                    "type": "document",
                    "classification": "SECRET",
                    "department": "MOD"
                },
                "environment": {
                    "timestamp": "2024-01-01T12:00:00",
                    "current_hour": 12
                },
                "request_id": "test-1"
            }
        },
        {
            "name": "SECRET user accessing CONFIDENTIAL resource (same dept)",
            "input": {
                "user": {
                    "username": "testuser",
                    "clearance": "SECRET",
                    "department": "MOD"
                },
                "resource": {
                    "type": "document",
                    "classification": "CONFIDENTIAL",
                    "department": "MOD"
                },
                "environment": {
                    "timestamp": "2024-01-01T12:00:00",
                    "current_hour": 12
                },
                "request_id": "test-2"
            }
        }
    ]
    
    for test in test_cases:
        print(f"\n🧪 Testing: {test['name']}")
        print(f"📤 Sending: {json.dumps(test['input'], indent=2)}")
        
        try:
            response = requests.post(
                url,
                json={"input": test["input"]},
                verify=False,  # Self-signed cert
                timeout=5
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ Response: {result}")
                print(f"   Allowed: {result.get('result', False)}")
                print(f"   Reason: {result.get('reason', 'No reason')}")
            else:
                print(f"❌ Error: {response.status_code} - {response.text}")
                
        except Exception as e:
            print(f"❌ Request failed: {e}")

if __name__ == "__main__":
    print("🔍 Testing OPA Server Fix")
    print("=" * 50)
    test_opa_directly()
>>>>>>> 7a18c90c8355e5456552baf7e8b1720973772e89
