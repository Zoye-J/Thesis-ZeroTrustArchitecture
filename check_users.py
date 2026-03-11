# create_sample_resources.py - FIXED VERSION
import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Use the factory function to create app
from app.api_app import create_api_app
from app.api_models import db
from app.models.user import GovernmentDocument, User
from datetime import datetime

# Create app instance using the factory function
app = create_api_app("development")

with app.app_context():
    # Find ANY existing user to own the resources (not necessarily admin)
    # Priority: admin > superadmin > any user
    user = User.query.filter_by(user_class="admin").first()
    if not user:
        user = User.query.filter_by(user_class="superadmin").first()
    if not user:
        user = User.query.first()  # Any user

    if not user:
        print("❌ No users found in database!")
        print("Please create users first (register some users)")
        exit(1)

    print(f"✅ Using user as owner: {user.username} ({user.email})")
    print(f"   Department: {user.department}, Role: {user.user_class}")

    sample_resources = [
        # PUBLIC resources (all departments can see)
        {
            "document_id": "GOV-PUB-001",
            "title": "Government Annual Report 2024",
            "description": "Public annual report of government activities",
            "content": "Annual report content...",
            "classification": "PUBLIC",
            "facility": "Government HQ",
            "department": "GENERAL",
            "category": "Reports",
            "owner_id": user.id,
            "created_by": user.id,
        },
        {
            "document_id": "GOV-PUB-002",
            "title": "Public Service Announcements",
            "description": "Latest public service announcements",
            "content": "PSA content...",
            "classification": "PUBLIC",
            "facility": "Government HQ",
            "department": "GENERAL",
            "category": "Announcements",
            "owner_id": user.id,
            "created_by": user.id,
        },
        # MOD Department resources
        {
            "document_id": "MOD-DEP-001",
            "title": "Military Readiness Report",
            "description": "Current military readiness status",
            "content": "Military readiness content...",
            "classification": "DEPARTMENT",
            "facility": "Ministry of Defence",
            "department": "MOD",
            "category": "Military",
            "owner_id": user.id,
            "created_by": user.id,
        },
        {
            "document_id": "MOD-DEP-002",
            "title": "Defense Budget Allocation",
            "description": "Quarterly defense budget allocation",
            "content": "Budget content...",
            "classification": "DEPARTMENT",
            "facility": "Ministry of Defence",
            "department": "MOD",
            "category": "Budget",
            "owner_id": user.id,
            "created_by": user.id,
        },
        # MOF Department resources
        {
            "document_id": "MOF-DEP-001",
            "title": "National Budget Proposal",
            "description": "Proposed national budget for next fiscal year",
            "content": "Budget proposal content...",
            "classification": "DEPARTMENT",
            "facility": "Ministry of Finance",
            "department": "MOF",
            "category": "Budget",
            "owner_id": user.id,
            "created_by": user.id,
        },
        {
            "document_id": "MOF-DEP-002",
            "title": "Tax Revenue Analysis",
            "description": "Analysis of national tax revenue collection",
            "content": "Tax analysis content...",
            "classification": "DEPARTMENT",
            "facility": "Ministry of Finance",
            "department": "MOF",
            "category": "Finance",
            "owner_id": user.id,
            "created_by": user.id,
        },
        # NSA Department resources
        {
            "document_id": "NSA-DEP-001",
            "title": "Cybersecurity Threat Assessment",
            "description": "Latest cybersecurity threat assessment",
            "content": "Threat assessment content...",
            "classification": "DEPARTMENT",
            "facility": "National Security Agency",
            "department": "NSA",
            "category": "Security",
            "owner_id": user.id,
            "created_by": user.id,
        },
        {
            "document_id": "NSA-DEP-002",
            "title": "Intelligence Briefing",
            "description": "Daily intelligence briefing",
            "content": "Intelligence content...",
            "classification": "DEPARTMENT",
            "facility": "National Security Agency",
            "department": "NSA",
            "category": "Intelligence",
            "owner_id": user.id,
            "created_by": user.id,
        },
        # MOD TOP SECRET resources
        {
            "document_id": "MOD-TS-001",
            "title": "TOP SECRET: Special Operations Plan",
            "description": "Detailed plan for special military operations",
            "content": "TOP SECRET content...",
            "classification": "TOP_SECRET",
            "facility": "Ministry of Defence",
            "department": "MOD",
            "category": "Operations",
            "owner_id": user.id,
            "created_by": user.id,
        },
        {
            "document_id": "MOD-TS-002",
            "title": "TOP SECRET: Advanced Weapons Research",
            "description": "Research on advanced military weapons systems",
            "content": "Research content...",
            "classification": "TOP_SECRET",
            "facility": "Ministry of Defence",
            "department": "MOD",
            "category": "Research",
            "owner_id": user.id,
            "created_by": user.id,
        },
    ]

    created_count = 0
    for resource_data in sample_resources:
        # Check if document already exists
        existing = GovernmentDocument.query.filter_by(
            document_id=resource_data["document_id"]
        ).first()

        if not existing:
            doc = GovernmentDocument(**resource_data)
            db.session.add(doc)
            print(
                f"✅ Created: {resource_data['document_id']} - {resource_data['title']}"
            )
            created_count += 1
        else:
            print(f"⏭️  Skipped (exists): {resource_data['document_id']}")

    db.session.commit()
    print(f"\n✅ Created {created_count} sample resources.")
    print(f"   Total resources in database: {GovernmentDocument.query.count()}")

    # Show resource summary
    print("\n📊 Resource Summary by Classification:")
    classifications = ["PUBLIC", "DEPARTMENT", "TOP_SECRET"]
    for cls in classifications:
        count = GovernmentDocument.query.filter_by(classification=cls).count()
        print(f"   {cls}: {count} resources")

    print("\n📊 Resource Summary by Department:")
    departments = ["MOD", "MOF", "NSA", "GENERAL"]
    for dept in departments:
        count = GovernmentDocument.query.filter_by(department=dept).count()
        print(f"   {dept}: {count} resources")
