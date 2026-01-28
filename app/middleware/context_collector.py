"""
Context Collection Middleware for ZTA
Collects user, device, time, and location context
"""

from flask import request, g
from datetime import datetime
import json
import uuid


class ContextCollector:
    def __init__(self, app=None):
        self.app = app
        if app:
            self.init_app(app)

    def init_app(self, app):
        app.before_request(self.collect_context)

    def collect_context(self):
        """Collect context for each request"""
        context = {
            "request_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "network": {
                "ip_address": request.remote_addr,
                "user_agent": request.user_agent.string if request.user_agent else None,
                "referrer": request.referrer,
            },
            "authentication": {"method": self._detect_auth_method(), "strength": 0},
        }

        # Add user context if authenticated
        if hasattr(g, "jwt_identity") and g.jwt_identity:
            context["user"] = {
                "id": g.jwt_identity,
                "claims": getattr(g, "user_claims", {}),
            }

        # Add certificate context if mTLS
        if hasattr(g, "client_certificate"):
            context["certificate"] = g.client_certificate
            context["authentication"]["strength"] += 1

        # Add JWT context
        if hasattr(g, "jwt_identity"):
            context["authentication"]["strength"] += 1

        g.zta_context = context

    def _detect_auth_method(self):
        """Detect authentication method"""
        if hasattr(g, "client_certificate") and hasattr(g, "jwt_identity"):
            return "mTLS_JWT"
        elif hasattr(g, "client_certificate"):
            return "mTLS"
        elif hasattr(g, "jwt_identity"):
            return "JWT"
        return "none"
