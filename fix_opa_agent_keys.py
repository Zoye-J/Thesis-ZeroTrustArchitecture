#!/usr/bin/env python3
"""
Fix OPA Agent SSL Certificate with proper SAN
"""

import os
import subprocess

OPENSSL_PATH = r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
CERTS_DIR = "./certs"
OPA_AGENT_DIR = os.path.join(CERTS_DIR, "opa_agent")

def fix_opa_agent_cert():
    """Fix OPA Agent certificate with proper SAN"""
    
    print("🔐 Fixing OPA Agent SSL certificate...")
    
    # Ensure directory exists
    os.makedirs(OPA_AGENT_DIR, exist_ok=True)
    
    # Create proper OPA Agent configuration
    opa_config = f"""[req]
prompt = no
distinguished_name = dn
req_extensions = req_ext

[dn]
C = BD
ST = Dhaka Division
L = Dhaka
O = Government ICT
OU = Digital Services
CN = opa-agent.zta.gov.bd

[req_ext]
subjectAltName = @alt_names
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
basicConstraints = CA:FALSE

[alt_names]
DNS.1 = localhost
DNS.2 = opa-agent.zta.gov.bd
DNS.3 = 127.0.0.1
IP.1 = 127.0.0.1
IP.2 = ::1
"""

    config_path = os.path.join(OPA_AGENT_DIR, "opa_agent.cnf")
    with open(config_path, "w") as f:
        f.write(opa_config)
    
    # Create extensions file
    opa_ext = f"""authorityKeyIdentifier = keyid,issuer
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names
subjectKeyIdentifier = hash

[alt_names]
DNS.1 = localhost
DNS.2 = opa-agent.zta.gov.bd
DNS.3 = 127.0.0.1
IP.1 = 127.0.0.1
IP.2 = ::1
"""

    ext_path = os.path.join(OPA_AGENT_DIR, "opa_agent.ext")
    with open(ext_path, "w") as f:
        f.write(opa_ext)
    
    print(" 1. Generating new RSA key...")
    key_path = os.path.join(OPA_AGENT_DIR, "opa_agent.key")
    subprocess.run([OPENSSL_PATH, "genrsa", "-out", key_path, "2048"], check=True)
    
    print(" 2. Creating CSR with proper SAN...")
    csr_path = os.path.join(OPA_AGENT_DIR, "opa_agent.csr")
    subprocess.run([
        OPENSSL_PATH, "req", "-new",
        "-key", key_path,
        "-out", csr_path,
        "-config", config_path
    ], check=True)
    
    print(" 3. Signing certificate with CA...")
    cert_path = os.path.join(OPA_AGENT_DIR, "opa_agent.crt")
    subprocess.run([
        OPENSSL_PATH, "x509", "-req",
        "-in", csr_path,
        "-CA", os.path.join(CERTS_DIR, "ca.crt"),
        "-CAkey", os.path.join(CERTS_DIR, "ca.key"),
        "-CAcreateserial",
        "-out", cert_path,
        "-days", "365",
        "-sha256",
        "-extfile", ext_path
    ], check=True)
    
    print(" 4. Verifying certificate...")
    result = subprocess.run([
        OPENSSL_PATH, "verify",
        "-CAfile", os.path.join(CERTS_DIR, "ca.crt"),
        cert_path
    ], capture_output=True, text=True)
    
    if "OK" in result.stdout:
        print("✅ OPA Agent certificate FIXED successfully!")
        
        # Also copy to main certs directory for backward compatibility
        import shutil
        shutil.copy(cert_path, os.path.join(CERTS_DIR, "opa_agent.crt"))
        shutil.copy(key_path, os.path.join(CERTS_DIR, "opa_agent.key"))
        print("✅ Copied to certs/ directory for compatibility")
        
        # Display certificate info
        print("\n📋 Certificate Details:")
        subprocess.run([OPENSSL_PATH, "x509", "-in", cert_path, "-text", "-noout"])
        
    else:
        print(f"❌ Verification failed: {result.stdout}")
        return False
    
    return True

def update_ssl_config():
    """Update SSL config to use fixed certificate"""
    
    # Update app/ssl_config.py to use OPA Agent certificate
    ssl_config_path = "app/ssl_config.py"
    
    with open(ssl_config_path, "r") as f:
        content = f.read()
    
    # Check if create_opa_agent_ssl_context exists
    if "def create_opa_agent_ssl_context" not in content:
        print("⚠️ Adding create_opa_agent_ssl_context function...")
        
        # Find the last function in the file
        lines = content.split('\n')
        insert_index = len(lines)
        
        for i, line in enumerate(lines):
            if line.strip().startswith('def ') and 'create_server_ssl_context' in line:
                # Find the end of this function
                for j in range(i, len(lines)):
                    if lines[j].strip() == '' and j > i:
                        insert_index = j + 1
                        break
        
        # Add the function
        new_function = '''
def create_opa_agent_ssl_context():
    """
    Create SSL context for OPA Agent with dedicated certificate
    """
    verify_certificates()
    
    # Use OPA Agent specific certificate
    opa_agent_cert = CERTS_DIR / "opa_agent" / "opa_agent.crt"
    opa_agent_key = CERTS_DIR / "opa_agent" / "opa_agent.key"
    
    # Fallback to certs/ directory
    if not opa_agent_cert.exists() or not opa_agent_key.exists():
        opa_agent_cert = CERTS_DIR / "opa_agent.crt"
        opa_agent_key = CERTS_DIR / "opa_agent.key"
    
    if opa_agent_cert.exists() and opa_agent_key.exists():
        cert_file = str(opa_agent_cert)
        key_file = str(opa_agent_key)
        print("✅ Using OPA Agent dedicated certificate")
    else:
        cert_file = str(SERVER_CERT)
        key_file = str(SERVER_KEY)
        print("⚠️ Using shared server certificate for OPA Agent")
    
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    context.load_verify_locations(cafile=str(CA_CERT))
    
    # OPA Agent doesn't require client certificates
    context.verify_mode = ssl.CERT_NONE
    context.check_hostname = False
    
    return context
'''
        
        lines.insert(insert_index, new_function)
        content = '\n'.join(lines)
        
        with open(ssl_config_path, "w") as f:
            f.write(content)
        
        print("✅ Updated app/ssl_config.py")
    
    return True

if __name__ == "__main__":
    if fix_opa_agent_cert():
        update_ssl_config()
        print("\n🚀 Restart OPA Agent server to use the fixed certificate")