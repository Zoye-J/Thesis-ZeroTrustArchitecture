"""
SSL patch for Python 3.13 to fix SAN verification
Apply this at the VERY BEGINNING of your application
"""

import ssl
import sys
import logging

logger = logging.getLogger(__name__)


def apply_ssl_patch():
    """Apply runtime patch to SSL context to fix SAN verification for localhost"""

    # Only needed for Python 3.13+
    if sys.version_info >= (3, 13):
        logger.info("🔧 Applying SSL patch for Python 3.13 (SAN verification fix)")

        # Store original methods
        original_create_default_context = ssl.create_default_context

        def patched_create_default_context(*args, **kwargs):
            """Create context with disabled hostname checking for localhost"""
            context = original_create_default_context(*args, **kwargs)

            # Set a custom hostname checking function
            original_check_hostname = context.check_hostname

            def patched_check_hostname(hostname):
                """Skip hostname check for localhost connections"""
                if hostname in ["localhost", "127.0.0.1", "::1"]:
                    return True  # Skip verification for localhost
                return original_check_hostname(hostname)

            context.check_hostname = patched_check_hostname
            return context

        # Replace the function
        ssl.create_default_context = patched_create_default_context

        # Also patch SSLContext directly
        original_wrap_socket = ssl.SSLContext.wrap_socket

        def patched_wrap_socket(self, *args, **kwargs):
            """Skip hostname verification for localhost"""
            server_hostname = kwargs.get("server_hostname")
            if server_hostname in ["localhost", "127.0.0.1", "::1"]:
                kwargs["server_hostname"] = None  # Disable hostname checking
            return original_wrap_socket(self, *args, **kwargs)

        ssl.SSLContext.wrap_socket = patched_wrap_socket

        logger.info("✅ SSL patch applied successfully")
    else:
        logger.info(
            f"Python {sys.version_info.major}.{sys.version_info.minor} - no SSL patch needed"
        )


# Auto-apply when imported
apply_ssl_patch()
