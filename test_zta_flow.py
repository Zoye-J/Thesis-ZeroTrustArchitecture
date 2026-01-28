#!/usr/bin/env python
"""
Test ZTA Flow - Complete End-to-End Test
"""

import requests
import json
import sys
import os
import time
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def check_server_health():
    """Check if all servers are running"""
    servers = {
        "Gateway (5000)": "https://localhost:5000/login",
        "API Server (5001)": "https://localhost:5001/health",
        "OPA Agent (8282)": "https://localhost:8282/health",
        "OPA Server (8181)": "http://localhost:8181/health",
    }

    print("🔍 Checking server health...")
    for name, url in servers.items():
        try:
            if "https" in url:
                response = requests.get(url, verify=False, timeout=3)
            else:
                response = requests.get(url, timeout=3)

            if response.status_code == 200:
                print(f"✅ {name}: UP ({url})")
            else:
                print(f"⚠️  {name}: RESPONSE {response.status_code} ({url})")
        except Exception as e:
            print(f"❌ {name}: DOWN - {e}")


def login_test_user(username="testuser", password="Test@123"):
    """Test login and get JWT token"""
    print(f"\n🔐 Testing login for {username}...")

    try:
        response = requests.post(
            "https://localhost:5000/api/auth/login",
            json={"username": username, "password": password},
            verify=False,
            timeout=10,
        )

        if response.status_code == 200:
            token = response.json().get("access_token")
            user_data = response.json().get("user", {})

            print(f"✅ Login successful!")
            print(f"   Token: {token[:30]}...")
            print(f"   User: {user_data.get('username')}")
            print(f"   Department: {user_data.get('department')}")
            print(f"   Clearance: {user_data.get('clearance_level')}")

            return token, user_data
        else:
            print(f"❌ Login failed: {response.status_code}")
            print(f"   Error: {response.text}")
            return None, None

    except Exception as e:
        print(f"❌ Login error: {e}")
        return None, None


def test_simple_resource_flow(token):
    """Test the simple (non-encrypted) resource flow"""
    print("\n📡 Testing Simple Resource Flow...")

    try:
        # First try the current endpoint
        response = requests.get(
            "https://localhost:5000/api/resources",
            headers={"Authorization": f"Bearer {token}"},
            verify=False,
            timeout=10,
        )

        print(f"📊 Response: {response.status_code}")

        if response.status_code == 200:
            resources = response.json()
            print(f"✅ SUCCESS! Found {len(resources)} resources")

            # Show resource summary
            public = sum(1 for r in resources if r.get("classification") == "PUBLIC")
            dept = sum(1 for r in resources if r.get("classification") == "DEPARTMENT")
            ts = sum(1 for r in resources if r.get("classification") == "TOP_SECRET")

            print(f"   PUBLIC: {public}")
            print(f"   DEPARTMENT: {dept}")
            print(f"   TOP_SECRET: {ts}")

            # Show first 2 resources
            for i, resource in enumerate(resources[:2]):
                print(f"\n   Sample Resource {i+1}:")
                print(f"     Title: {resource.get('title')}")
                print(f"     Classification: {resource.get('classification')}")
                print(f"     Department: {resource.get('department')}")

            return True

        elif response.status_code == 500:
            print(f"❌ Server error (500)")
            print(f"   Response: {response.text[:200]}")
            return False
        else:
            print(f"❌ Unexpected status: {response.status_code}")
            print(f"   Response: {response.text[:200]}")
            return False

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_zta_encrypted_flow(token):
    """Test the full ZTA encrypted flow"""
    print("\n🔐 Testing ZTA Encrypted Flow...")

    # First check if OPA Agent is available
    try:
        opa_health = requests.get(
            "https://localhost:8282/health", verify=False, timeout=3
        )

        if opa_health.status_code != 200:
            print("❌ OPA Agent not healthy, skipping ZTA test")
            return False

    except:
        print("❌ OPA Agent not reachable, skipping ZTA test")
        return False

    # Try the ZTA endpoint
    try:
        response = requests.get(
            "https://localhost:5000/api/resources-zta",
            headers={"Authorization": f"Bearer {token}"},
            verify=False,
            timeout=15,
        )

        print(f"📊 ZTA Response: {response.status_code}")

        if response.status_code == 200:
            data = response.json()
            print(f"✅ ZTA Flow successful!")

            if "encrypted_payload" in data:
                print(f"   🔐 Encrypted payload received")
                print(f"   📦 Size: {len(data['encrypted_payload'])} bytes")

            if "zta_flow" in data:
                flow = data["zta_flow"]
                print(f"   📋 Flow: {flow.get('flow', 'Unknown')}")
                print(f"   🎯 Steps: {flow.get('steps_completed', 0)} completed")
                print(f"   ⚠️  Risk assessed: {flow.get('risk_assessed', False)}")

            return True

        elif response.status_code == 404:
            print("❌ ZTA endpoint not found (404)")
            print(
                "   Try: Add @gateway_bp.route('/api/resources-zta', methods=['GET']) to gateway_routes.py"
            )
            return False
        elif response.status_code == 500:
            print(f"❌ ZTA Server error (500)")
            print(f"   Response: {response.text[:200]}")
            return False
        else:
            print(f"❌ ZTA Unexpected status: {response.status_code}")
            print(f"   Response: {response.text[:200]}")
            return False

    except Exception as e:
        print(f"❌ ZTA Error: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_direct_api_call():
    """Test direct call to API Server (bypassing Gateway)"""
    print("\n🔄 Testing Direct API Server Call...")

    try:
        response = requests.get(
            "https://localhost:5001/resources",
            headers={
                "Content-Type": "application/json",
                "X-Service-Token": "api-token-2024-zta",
                "X-User-Claims": json.dumps(
                    {
                        "sub": 1,
                        "username": "testuser",
                        "user_class": "user",
                        "department": "MOD",
                        "clearance_level": "SECRET",
                    }
                ),
            },
            verify=False,
            timeout=10,
        )

        print(f"📊 Direct API Response: {response.status_code}")

        if response.status_code == 200:
            resources = response.json()
            print(f"✅ Direct API call successful!")
            print(f"   Found {len(resources)} resources")
            return True
        else:
            print(f"❌ Direct API call failed: {response.status_code}")
            print(f"   Response: {response.text[:200]}")
            return False

    except Exception as e:
        print(f"❌ Direct API Error: {e}")
        return False


def main():
    print("=" * 60)
    print("🧪 ZTA SYSTEM COMPREHENSIVE TEST")
    print("=" * 60)

    # Step 1: Check server health
    check_server_health()
    time.sleep(1)

    # Step 2: Login
    token, user_data = login_test_user()
    if not token:
        print("\n❌ Cannot proceed without valid token")
        sys.exit(1)

    # Step 3: Test simple flow
    simple_success = test_simple_resource_flow(token)

    # Step 4: Test ZTA flow
    zta_success = test_zta_encrypted_flow(token)

    # Step 5: Test direct API (optional)
    # direct_success = test_direct_api_call()

    # Summary
    print("\n" + "=" * 60)
    print("📊 TEST SUMMARY")
    print("=" * 60)
    print(f"✅ Login: {'SUCCESS' if token else 'FAILED'}")
    print(f"✅ Simple Resource Flow: {'SUCCESS' if simple_success else 'FAILED'}")
    print(f"✅ ZTA Encrypted Flow: {'SUCCESS' if zta_success else 'FAILED'}")
    # print(f"✅ Direct API Call: {'SUCCESS' if direct_success else 'FAILED'}")

    if simple_success:
        print("\n🎉 Your resource system is working!")
        print("   Users can access resources based on department and clearance.")
    else:
        print("\n🔧 Issues detected. Try these fixes:")
        print("   1. Check if API Server is running on port 5001")
        print("   2. Check if /resources endpoint exists in api/routes.py")
        print("   3. Check database connection")
        print("   4. Add a direct /api/resources route in gateway_routes.py")


if __name__ == "__main__":
    main()
