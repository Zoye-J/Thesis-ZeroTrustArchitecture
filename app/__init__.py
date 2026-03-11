"""
ZTA Application Package
Contains shared extensions for both Gateway and API servers
"""

from flask_jwt_extended import JWTManager
from flask_cors import CORS

# ============ SHARED EXTENSIONS ============
# Only JWT and CORS are shared between both servers
# Database is NOT shared - it's API Server only

jwt = JWTManager()
cors = CORS()

# ============ EXPORTS ============
__all__ = ["jwt", "cors"]

print("✅ ZTA app package initialized - jwt, cors extensions available (NO DB)")
