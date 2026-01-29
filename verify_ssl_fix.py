#!/usr/bin/env python3
"""
Quick verification that SSL fix is working
"""

import ssl
import socket
from urllib.request import urlopen
import sys

def test_ssl_connection():
    print("🔐 Testing SSL connection with Python 3.13 fix...")
    
    # Create fixed SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile="certs/ca.crt")
    context.verify_mode = ssl.CERT_REQUIRED
    
    try:
        # Try to connect to gateway
        print("\n1. Testing connection to Gateway (port 5000)...")
        with socket.create_connection(('localhost', 5000), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname='localhost') as ssock:
                cert = ssock.getpeercert()
                print(f"✅ Connected successfully!")
                print(f"   Certificate subject: {cert.get('subject', 'N/A')}")
                print(f"   Certificate issuer: {cert.get('issuer', 'N/A')}")
                return True
                
    except ssl.SSLCertVerificationError as e:
        print(f"❌ SSL Certificate verification failed: {e}")
        print(f"   Reason: {e.verify_message}")
        return False
    except Exception as e:
        print(f"❌ Connection error: {e}")
        return False

def test_with_urllib():
    print("\n2. Testing with urllib (common library)...")
    
    import urllib.request
    import ssl
    
    # Create custom context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile="certs/ca.crt")
    
    try:
        response = urllib.request.urlopen('https://localhost:5000/health', 
                                          context=context, 
                                          timeout=5)
        print(f"✅ urllib works with our SSL context!")
        print(f"   HTTP {response.status}")
        return True
    except Exception as e:
        print(f"❌ urllib failed: {e}")
        return False

if __name__ == "__main__":
    success1 = test_ssl_connection()
    success2 = test_with_urllib()
    
    print("\n" + "=" * 60)
    if success1 and success2:
        print("✅ SSL fix verification PASSED")
        print("Python 3.13 SSL bug is WORKAROUNDED")
        sys.exit(0)
    else:
        print("❌ SSL fix verification FAILED")
        print("\n💡 The SSL bug is still present. Options:")
        print("1. Use Python 3.11 or 3.12 (recommended)")
        print("2. Generate certificates with different SAN encoding")
        print("3. Accept 'verify=False' for development")
        sys.exit(1)