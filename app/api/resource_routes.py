# app/api/resource_routes.py
from flask import Blueprint, render_template
from app.mTLS.middleware import require_authentication

resource_bp = Blueprint("resource", __name__)


@resource_bp.route("/resources")
def resource_portal():
    """Render the resource portal page"""
    return render_template("resource_portal.html")
