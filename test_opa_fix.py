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