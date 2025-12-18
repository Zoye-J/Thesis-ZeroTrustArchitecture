#!/usr/bin/env python3
"""
ZTA Government System - Main Web Server (HTTP for JWT)
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app

# Create app
app = create_app()

if __name__ == "__main__":
    print("=" * 60)
    print("🏛️ ZTA GOVERNMENT SYSTEM - WEB SERVER")
    print("=" * 60)
    print("\n📡 Server: HTTP (JWT Authentication)")
    print("🔌 Port: 5000")
    print("🌐 Access: http://localhost:5000/")
    print("\n🔗 Direct URLs:")
    print("  • Login: http://localhost:5000/login")
    print("  • Dashboard: http://localhost:5000/dashboard")
    print("  • Register: http://localhost:5000/register")
    print("\n🔐 Test Login: mod_admin / Admin@123")
    print("ZTA Dashboard at: http://localhost:5000/audit")
    print("=" * 60)

    # Debug: Print all registered routes
    # for rule in app.url_map.iter_rules():
    #   print(f"  {rule.rule} -> {rule.endpoint}")

    app.run(debug=True, port=5000, host="0.0.0.0")
