# app/api/resource_routes.py
from flask import Blueprint, render_template, jsonify, g, redirect, url_for, request
from app.mTLS.middleware import require_authentication
from app.api_models import GovernmentDocument
from datetime import datetime
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from app.models.user import User
import logging
import jwt
from flask import current_app

logger = logging.getLogger(__name__)
resource_bp = Blueprint("resource", __name__)


@resource_bp.route("/resources")
def resource_portal():
    """Render the resource portal page with database documents"""
    try:
        # Try to get token from Authorization header or cookie
        token = None

        # Check Authorization header
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]

        # If no header, check for token in localStorage via a preload script
        # For now, we'll redirect to login - the frontend will handle token attachment
        if not token:
            # Render a loader page that will fetch the token from localStorage
            # and then redirect with the token
            return render_template("resource_loader.html")

        # Verify token manually
        try:
            # Decode JWT to get user identity
            from flask_jwt_extended import decode_token

            decoded = decode_token(token)
            user_id = decoded["sub"]
        except Exception as e:
            logger.error(f"Token verification failed: {e}")
            return redirect(url_for("auth.login"))

        # Get user from database
        user = User.query.get(user_id)
        if not user:
            return redirect(url_for("auth.login"))

        # Get all non-archived documents
        documents = GovernmentDocument.query.filter_by(is_archived=False).all()

        # Filter documents based on user's department and clearance
        accessible_resources = []
        current_hour = datetime.now().hour

        for doc in documents:
            # PUBLIC - always accessible
            if doc.classification == "PUBLIC":
                accessible_resources.append(
                    {
                        "id": doc.id,
                        "name": doc.title,
                        "description": doc.description,
                        "tier": "PUBLIC",
                        "department": doc.department,
                        "facility": doc.facility,
                        "category": doc.category,
                    }
                )

            # DEPARTMENT - same department only
            elif (
                doc.classification == "DEPARTMENT" and doc.department == user.department
            ):
                accessible_resources.append(
                    {
                        "id": doc.id,
                        "name": doc.title,
                        "description": doc.description,
                        "tier": "DEPARTMENT",
                        "department": doc.department,
                        "facility": doc.facility,
                        "category": doc.category,
                    }
                )

            # TOP_SECRET - MOD department, proper clearance, business hours
            elif (
                doc.classification == "TOP_SECRET"
                and doc.department == "MOD"
                and user.department == "MOD"
            ):
                if user.clearance_level in ["SECRET", "TOP_SECRET"]:
                    if 8 <= current_hour < 16:
                        accessible_resources.append(
                            {
                                "id": doc.id,
                                "name": doc.title,
                                "description": doc.description,
                                "tier": "TOP_SECRET",
                                "department": doc.department,
                                "facility": doc.facility,
                                "category": doc.category,
                            }
                        )
                    else:
                        # Show as restricted
                        accessible_resources.append(
                            {
                                "id": doc.id,
                                "name": f"🔒 {doc.title} (Available 8 AM - 4 PM)",
                                "description": "Time-restricted TOP SECRET document",
                                "tier": "TOP_SECRET",
                                "department": doc.department,
                                "facility": doc.facility,
                                "category": doc.category,
                                "restricted": True,
                            }
                        )

        return render_template(
            "resource_portal.html",
            resources=accessible_resources,
            user=user,
            current_hour=current_hour,
        )

    except Exception as e:
        logger.error(f"Error loading resources: {e}")
        return render_template(
            "error.html", error=str(e), trace_id=getattr(g, "request_id", "unknown")
        )


@resource_bp.route("/resources-content")
def resources_content():
    """API endpoint that returns the rendered resource portal HTML"""
    try:
        # Get token from header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return "Unauthorized", 401

        token = auth_header.split(" ")[1]

        # Verify token
        try:
            from flask_jwt_extended import decode_token

            decoded = decode_token(token)
            user_id = decoded["sub"]
        except Exception as e:
            return "Invalid token", 401

        # Get user
        user = User.query.get(user_id)
        if not user:
            return "User not found", 401

        # Get documents and filter (same logic as above)
        documents = GovernmentDocument.query.filter_by(is_archived=False).all()
        accessible_resources = []
        current_hour = datetime.now().hour

        for doc in documents:
            if doc.classification == "PUBLIC":
                accessible_resources.append(
                    {
                        "id": doc.id,
                        "name": doc.title,
                        "description": doc.description,
                        "tier": "PUBLIC",
                        "department": doc.department,
                    }
                )
            elif (
                doc.classification == "DEPARTMENT" and doc.department == user.department
            ):
                accessible_resources.append(
                    {
                        "id": doc.id,
                        "name": doc.title,
                        "description": doc.description,
                        "tier": "DEPARTMENT",
                        "department": doc.department,
                    }
                )
            # ... rest of the filtering logic

        return render_template(
            "resource_portal.html",
            resources=accessible_resources,
            user=user,
            current_hour=current_hour,
        )

    except Exception as e:
        logger.error(f"Error loading resources content: {e}")
        return str(e), 500
