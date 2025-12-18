#!/usr/bin/env python3
"""
Simple SSL Helper for ZTA System
Handles custom CA certificate trust
"""

import ssl
import os
from pathlib import Path


def get_ssl_context(ca_cert_path=None):
    """
    Get SSL context that trusts custom CA certificates

    Args:
        ca_cert_path: Path to CA certificate file

    Returns:
        SSL context configured to trust the specified CA
    """
    # Create default SSL context
    context = ssl.create_default_context()

    # If CA cert path is provided, load it
    if ca_cert_path and os.path.exists(ca_cert_path):
        context.load_verify_locations(cafile=ca_cert_path)
        print(f"✓ Loaded custom CA certificate: {ca_cert_path}")

    # For development, you might want to disable hostname verification
    context.check_hostname = False

    return context


def trust_zta_ca():
    """
    Convenience function to trust the ZTA CA certificate
    Returns the CA certificate path
    """
    ca_cert = Path("./certs/ca.crt")
    if ca_cert.exists():
        return str(ca_cert)
    else:
        print(f"⚠ CA certificate not found at {ca_cert}")
        return None


# Global variables for easy access
ZTA_CA_PATH = trust_zta_ca()
SSL_CONTEXT = get_ssl_context(ZTA_CA_PATH) if ZTA_CA_PATH else None
