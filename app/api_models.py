# app/api_models.py

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# Import models AFTER db is defined
# We need to import db first, then models
try:
    from app.models.user import (
        User,
        GovernmentDocument,
        AccessLog,
        Facility,
        Department,
    )

    print("✅ API Models loaded successfully")
except ImportError as e:
    print(f"⚠️  Could not import models: {e}")
    User = None
    GovernmentDocument = None
    AccessLog = None
    Facility = None
    Department = None

__all__ = ["db", "User", "GovernmentDocument", "AccessLog", "Facility", "Department"]
