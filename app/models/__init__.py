# Import SQLAlchemy first
from app.api_models import db

# Import all models
from app.models.user import User, GovernmentDocument, AccessLog, Facility, Department
from app.models.keys import UserKey


# Create a registry to avoid circular imports
def init_models(app):
    """Initialize all models with the app"""
    with app.app_context():
        # Create all tables
        db.create_all()


# Export all models
__all__ = [
    "db",
    "User",
    "UserKey",  # ADD THIS
    "GovernmentDocument",
    "AccessLog",
    "Facility",
    "Department",
]
