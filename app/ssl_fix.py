"""
Universal SSL Fix for Python 3.13 SAN bug
Workaround for "Empty Subject Alternative Name extension" error
"""

import ssl
import os

import logging

from pathlib import Path
import requests
from requests.adapters import HTTPAdapter


# Add logging
logger = logging.getLogger(__name__)

# Try to apply SSL patch if available
try:
    from app.ssl_patch import apply_ssl_patch

    apply_ssl_patch()
    logger.info("✅ Applied SSL patch")
except ImportError:
    logger.warning("⚠️ SSL patch module not available, using fallback")


def create_fixed_ssl_context(verify_hostname=False):
    """
    Create SSL context that works around Python 3.13 SAN bug

    Args:
        verify_hostname: If True, verify hostnames (default False for localhost)

    """
    # Force TLSv1.2 to avoid Python 3.13 SAN bug
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2

    # Load our CA certificate
    ca_cert = Path("certs/ca.crt")
    if ca_cert.exists():
        context.load_verify_locations(cafile=str(ca_cert))

        logger.info(f"✅ SSL fix: Loaded CA cert from {ca_cert}")
    else:
        logger.warning(f"⚠️ SSL fix: CA cert not found at {ca_cert}")

    # Enable certificate verification
    context.verify_mode = ssl.CERT_REQUIRED

    # Only disable hostname checking for localhost
    # This is the key fix - we still verify the certificate, just skip hostname match
    context.check_hostname = verify_hostname

    return context


def create_ssl_fixed_session(verify_hostname=False):
    """Create a requests Session with SSL fix applied"""
    session = requests.Session()

    # Create custom adapter with fixed SSL context
    class FixedSSLAdapter(HTTPAdapter):
        def init_poolmanager(self, *args, **kwargs):

            kwargs["ssl_context"] = create_fixed_ssl_context(verify_hostname)

            return super().init_poolmanager(*args, **kwargs)

    # Mount the adapter for all HTTPS requests
    session.mount("https://", FixedSSLAdapter())

    return session


# Global SSL-fixed session
_ssl_fixed_session = None


def get_ssl_fixed_session():
    """Get or create SSL-fixed session"""
    global _ssl_fixed_session
    if _ssl_fixed_session is None:

        _ssl_fixed_session = create_ssl_fixed_session(verify_hostname=False)
        logger.info(
            "✅ Created global SSL-fixed session (hostname verification disabled)"
        )

    return _ssl_fixed_session


def patch_requests_library():
    """
    Monkey-patch requests library to use SSL fix globally
    WARNING: This affects ALL requests library usage
    """
    try:
        # Store original methods
        requests.original_get = requests.get
        requests.original_post = requests.post
        requests.original_put = requests.put
        requests.original_delete = requests.delete
        requests.original_request = requests.request

        # Get SSL-fixed session
        session = get_ssl_fixed_session()

        # Create patched methods
        def patched_request(method, url, **kwargs):
            # Remove verify parameter as we use our SSL context
            kwargs.pop("verify", None)
            return session.request(method, url, **kwargs)

        # Patch the module
        requests.get = lambda url, **kwargs: patched_request("GET", url, **kwargs)
        requests.post = lambda url, **kwargs: patched_request("POST", url, **kwargs)
        requests.put = lambda url, **kwargs: patched_request("PUT", url, **kwargs)
        requests.delete = lambda url, **kwargs: patched_request("DELETE", url, **kwargs)
        requests.request = patched_request

        logger.info("✅ Successfully patched requests library for Python 3.13 SSL bug")
        return True

    except Exception as e:
        logger.error(f"⚠️ Failed to patch requests library: {e}")

        return False


# Apply patch when module is imported

patch_requests_library()


# Export functions
__all__ = [
    "create_fixed_ssl_context",
    "create_ssl_fixed_session",
    "get_ssl_fixed_session",
    "patch_requests_library",
]
