#!/usr/bin/env python3
"""
Quick ZTA System Check
"""

import requests
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from app.ssl_fix import get_ssl_fixed_session

    session = get_ssl_fixed_session()
except:
    session = requests.Session()


def quick_check():
    print("⚡ ZTA QUICK SYSTEM CHECK")
    print("=" * 50)

    servers = [
        ("Gateway", "https://localhost:5000/health"),
        ("API Server", "https://localhost:5001/health"),
        ("OPA Agent", "https://localhost:8282/health"),
        ("OPA Server", "https://localhost:8181/health"),
        ("Dashboard", "https://localhost:5002/status"),
    ]

    for name, url in servers:
        try:
            response = session.get(url, timeout=3)
            if response.status_code == 200:
                print(f"✅ {name}: RUNNING")
            else:
                print(f"❌ {name}: HTTP {response.status_code}")
        except Exception as e:
            print(f"❌ {name}: {str(e)[:50]}")

    print("\n🔗 Quick Access:")
    print("   Login: https://localhost:5000/login")
    print("   Dashboard: https://localhost:5002")
    print("\n👤 Test Credentials:")
    print("   • admin / admin123")
    print("   • mod_user / mod123")
    print("   • mof_user / mof123")


if __name__ == "__main__":
    quick_check()
