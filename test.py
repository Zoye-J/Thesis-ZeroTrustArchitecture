# find_old_cert.py
import ssl
import socket
import OpenSSL.crypto as crypto

def inspect_old_certificate():
    """Inspect the old certificate all services are using"""
    print("🔍 Inspecting OLD Certificate (a12676adcfd3ae3a)")
    print("=" * 60)
    
    try:
        # Get certificate from Gateway (representative of all)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection(("localhost", 5000), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname="localhost") as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                cert_pem = ssl.DER_cert_to_PEM_cert(cert_bin)
                
                # Parse certificate
                x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
                
                print("📋 Certificate Details:")
                print(f"  Subject: {x509.get_subject()}")
                print(f"  Issuer: {x509.get_issuer()}")
                print(f"  Serial: {x509.get_serial_number()}")
                
                # Check if it's a Flask default certificate
                subject = x509.get_subject()
                if subject.CN == "localhost" or "Flask" in str(subject):
                    print("\n💡 This is a DEFAULT Flask certificate!")
                else:
                    print("\n💡 This is a custom certificate (not Flask default)")
                
                # Check extensions
                print("\n🔍 Extensions:")
                has_san = False
                for i in range(x509.get_extension_count()):
                    ext = x509.get_extension(i)
                    ext_name = ext.get_short_name().decode('ascii')
                    print(f"  {ext_name}: {str(ext)}")
                    if ext_name == 'subjectAltName':
                        has_san = True
                
                if not has_san:
                    print("\n⚠️  This certificate has NO Subject Alternative Name!")
                    print("   This explains the 'Empty SAN' error!")
                
                return True
                
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    inspect_old_certificate()