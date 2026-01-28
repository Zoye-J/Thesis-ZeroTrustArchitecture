# debug_ssl_verification.py
import ssl
import socket
import requests
from urllib3 import PoolManager
from urllib3.util import ssl_

def test_ssl_with_different_methods():
    """Test SSL verification with different methods"""
    print("🔐 Testing SSL Verification Methods")
    print("=" * 60)
    
    ca_path = "certs/ca.crt"
    
    # Test 1: Raw SSL socket verification
    print("\n1. Raw SSL Socket Verification:")
    try:
        context = ssl.create_default_context(cafile=ca_path)
        context.check_hostname = True
        
        with socket.create_connection(("localhost", 5000), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname="localhost") as ssock:
                print(f"  ✅ SSL Handshake successful")
                print(f"  📋 Protocol: {ssock.version()}")
                print(f"  🔐 Cipher: {ssock.cipher()[0]}")
    except ssl.SSLCertVerificationError as e:
        print(f"  ❌ SSL Verification failed: {e.reason}")
    except Exception as e:
        print(f"  ❌ Error: {type(e).__name__}: {e}")
    
    # Test 2: Requests with verify=True (system CA store)
    print("\n2. Requests with system CA store (verify=True):")
    try:
        response = requests.get("https://localhost:5000/health", verify=True, timeout=5)
        print(f"  ✅ Success: HTTP {response.status_code}")
    except requests.exceptions.SSLError as e:
        print(f"  ❌ SSL Error: {type(e).__name__}")
        print(f"     Details: {str(e)[:200]}")
    
    # Test 3: Requests with custom CA file
    print("\n3. Requests with custom CA file (verify='certs/ca.crt'):")
    try:
        response = requests.get("https://localhost:5000/health", verify=ca_path, timeout=5)
        print(f"  ✅ Success: HTTP {response.status_code}")
    except requests.exceptions.SSLError as e:
        print(f"  ❌ SSL Error: {type(e).__name__}")
        print(f"     Details: {str(e)[:200]}")
    
    # Test 4: Check if Python can read the CA certificate
    print("\n4. Checking CA certificate readability:")
    try:
        # Try to load the CA certificate
        context = ssl.create_default_context(cafile=ca_path)
        print(f"  ✅ CA certificate loaded successfully")
        
        # Check certificate count
        print(f"  📊 CA certificates loaded: Yes")
    except Exception as e:
        print(f"  ❌ Failed to load CA certificate: {e}")
    
    # Test 5: Test with urllib3 directly
    print("\n5. Testing with urllib3 directly:")
    try:
        # Create custom pool manager with our CA
        http = PoolManager(
            cert_reqs='CERT_REQUIRED',
            ca_certs=ca_path,
            assert_hostname='localhost'
        )
        
        response = http.request('GET', 'https://localhost:5000/health')
        print(f"  ✅ Success: HTTP {response.status}")
    except Exception as e:
        print(f"  ❌ Error: {type(e).__name__}: {str(e)[:200]}")

if __name__ == "__main__":
    test_ssl_with_different_methods()