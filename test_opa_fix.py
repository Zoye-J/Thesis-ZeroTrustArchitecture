# save as check_opa_cert.py
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import ssl
import socket


def check_cert(host, port):
    try:
        cert = ssl.get_server_certificate((host, port))
        print(f"Certificate for {host}:{port}:\n")
        cert_obj = x509.load_pem_x509_certificate(cert.encode(), default_backend())

        print(f"Subject: {cert_obj.subject}")
        print(f"Issuer: {cert_obj.issuer}")
        print(f"Version: {cert_obj.version}")

        # Check SAN
        try:
            san = cert_obj.extensions.get_extension_for_oid(
                x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            print(f"SAN: {san.value}")
        except:
            print("⚠️  No SAN extension found - THIS IS THE PROBLEM!")

    except Exception as e:
        print(f"Error: {e}")


check_cert("localhost", 8282)
