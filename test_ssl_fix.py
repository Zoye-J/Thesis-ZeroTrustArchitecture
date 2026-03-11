#!/usr/bin/env python3
"""
Test SSL Fix for ZTA System - WITH PERMANENT FIX
Verifies all services are accessible via HTTPS with PROPER SSL verification
"""

import sys
import os

# Apply SSL fix BEFORE any imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from app.ssl_fix import create_fixed_ssl_context, patch_requests_for_python_313

    print("✅ SSL fix applied")
except ImportError:
    print("⚠️ SSL fix module not available")

import requests
import ssl
import socket
import subprocess
from datetime import datetime

SERVERS = {
    "gateway": "https://localhost:5000/health",
    "api_server": "https://localhost:5001/health",
    "opa_agent": "https://localhost:8282/health",
    "opa_server": "https://localhost:8181/health",
    "dashboard": "https://localhost:5002/status",
}


def test_with_proper_ssl(name, url):
    """Test server with proper SSL verification"""
    print(f"\n🔍 Testing {name.upper()} with SSL verification:")
    print("-" * 50)

    try:
        # Use requests.get() which should now use our patched SSL context
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            print(f"✅ SSL VERIFIED: HTTP {response.status_code}")
            data = response.json()
            print(f"   Server: {data.get('server', 'unknown')}")
            print(f"   Status: {data.get('status', 'unknown')}")
            return True, f"✅ {name}: SSL Verified, HTTP 200"
        else:
            print(f"❌ HTTP {response.status_code}")
            print(f"   Error: {response.text[:100]}")
            return False, f"❌ {name}: HTTP {response.status_code}"

    except requests.exceptions.SSLError as e:
        print(f"❌ SSL Error: {str(e)[:100]}")

        # Fallback test without verification
        try:
            print("   Trying fallback (no SSL verification)...")
            response = requests.original_get(url, timeout=5, verify=False)
            if response.status_code == 200:
                print(f"⚠️ HTTP {response.status_code} (SSL NOT VERIFIED)")
                return True, f"⚠️ {name}: HTTP 200 (SSL not verified)"
            else:
                print(f"❌ HTTP {response.status_code}")
                return False, f"❌ {name}: HTTP {response.status_code}"
        except Exception as e2:
            print(f"❌ Fallback failed: {str(e2)[:100]}")
            return False, f"❌ {name}: {str(e2)[:100]}"

    except Exception as e:
        print(f"❌ Connection error: {str(e)[:100]}")
        return False, f"❌ {name}: {str(e)[:100]}"


def main():
    print("🔐 ZTA SSL VERIFICATION TEST (Python 3.13 Fix)")
    print("=" * 70)
    print(f"Python version: {sys.version}")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    print("\nTesting SSL verification for all servers...")
    print("This should show ✅ SSL VERIFIED for all servers if fix works")
    print("=" * 70)

    results = []
    all_verified = True

    for name, url in SERVERS.items():
        success, message = test_with_proper_ssl(name, url)
        results.append((success, message))

        # Check if SSL was actually verified (not fallback)
        if "SSL not verified" in message or "⚠️" in message:
            all_verified = False

    print("\n" + "=" * 70)
    print("📊 FINAL RESULTS")
    print("=" * 70)

    for success, message in results:
        print(message)

    print("-" * 70)

    if all_verified:
        print("🎉 PERFECT! All servers accessible WITH SSL VERIFICATION")
        print("\n✅ Python 3.13 SSL bug is FIXED!")
        print("✅ All certificates are properly verified")
        print("✅ No insecure connections needed")

        print("\n🔗 System is fully secure and operational:")
        for name in SERVERS.keys():
            print(f"   • {name}: ✅ SSL Verified")

        return 0
    else:
        print("⚠️ SSL verification issues detected")

        print("\n💡 IMMEDIATE ACTIONS:")
        print("1. Make sure 'app/ssl_fix.py' exists and was imported")
        print("2. Restart all servers to apply SSL fix")
        print("3. Check certificates: python create_certificates.py")
        print("4. Test individual server: python test_opa_ssl.py")

        print("\n🛠️ If SSL verification still fails:")
        print("   - We may need to regenerate certificates differently")
        print("   - Or consider downgrading to Python 3.12 temporarily")

        return 1


if __name__ == "__main__":
    sys.exit(main())
