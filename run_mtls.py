import ssl
from app import create_app

app = create_app()

if __name__ == "__main__":
    print("=" * 60)
    print("ZTA System - mTLS Server")
    print("Port: 8443")
    print("=" * 60)

    # Setup SSL with mTLS
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain("certs/server.crt", "certs/server.key")
    context.load_verify_locations("certs/ca.crt")

    app.run(debug=False, port=8443, host="0.0.0.0", ssl_context=context)
