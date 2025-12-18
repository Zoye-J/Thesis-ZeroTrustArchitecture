import ssl
from app import create_app

app = create_app('development')

if __name__ == "__main__":
    print("=" * 60)
    print("ZTA System - mTLS Server")
    print("Port: 8443")
    print("=" * 60)

    # Setup SSL with mTLS
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(
        certfile=app.config["SERVER_CERT_PATH"],
        keyfile=app.config["SERVER_KEY_PATH"]
    )
    context.load_verify_locations(cafile=app.config["CA_CERT_PATH"])
    app.run(debug=False, port=8443, host="0.0.0.0", ssl_context=context)
