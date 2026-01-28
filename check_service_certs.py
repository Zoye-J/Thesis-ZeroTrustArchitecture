# better_cert_check.py
import ssl
import socket
import OpenSSL.crypto as crypto

def get_raw_certificate(hostname, port):
    """Get raw certificate details"""
    print(f"\n🔍 {hostname}:{port}")
    
    try:
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Connect and get certificate
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Get certificate in binary form
                cert_bin = ssock.getpeercert(binary_form=True)
                
                if cert_bin:
                    # Convert to PEM
                    cert_pem = ssl.DER_cert_to_PEM_cert(cert_bin)
                    
                    # Parse with OpenSSL
                    x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
                    
                    print(f"  ✅ Certificate found ({len(cert_bin)} bytes)")
                    
                    # Get subject
                    subject = x509.get_subject()
                    print(f"  📋 Subject: CN={subject.CN}, C={subject.C}, O={subject.O}")
                    
                    # Get issuer
                    issuer = x509.get_issuer()
                    print(f"  🏢 Issuer: CN={issuer.CN}, C={issuer.C}, O={issuer.O}")
                    
                    # Check if it's our Bangladesh certificate
                    if subject.C == "BD" or issuer.C == "BD":
                        print(f"  🇧🇩 Bangladesh certificate detected!")
                    else:
                        print(f"  ⚠️  Not a Bangladesh certificate")
                    
                    # Check extensions
                    print(f"  🔍 Checking extensions...")
                    has_san = False
                    for i in range(x509.get_extension_count()):
                        ext = x509.get_extension(i)
                        ext_name = ext.get_short_name().decode('ascii')
                        if ext_name == 'subjectAltName':
                            has_san = True
                            print(f"    ✅ Has SubjectAltName: {str(ext)}")
                    
                    if not has_san:
                        print(f"    ⚠️  NO Subject Alternative Name extension")
                    
                    return True
                else:
                    print(f"  ❌ No certificate returned")
                    return False
                    
    except Exception as e:
        print(f"  ❌ Error: {type(e).__name__}: {e}")
        return False

if __name__ == "__main__":
    print("🔧 Advanced Certificate Diagnostic")
    print("=" * 60)
    
    services = [
        ("OPA Server", "localhost", 8181),
        ("OPA Agent", "localhost", 8282),
        ("API Server", "localhost", 5001),
        ("Gateway", "localhost", 5000),
    ]
    
    for name, host, port in services:
        print(f"\n{name}:")
        get_raw_certificate(host, port)