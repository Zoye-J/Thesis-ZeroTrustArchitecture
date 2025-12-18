#!/usr/bin/env python3
"""
Smart Database Setup for ZTA Government Document System
Handles existing data gracefully
"""
import sys
import os
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def setup_database():
    """Create or update database for ZTA system"""
    try:
        from app import create_app, db
        from app.models.user import User, GovernmentDocument, Facility, Department

        app = create_app()

        with app.app_context():
            print("=" * 60)
            print("ZTA GOVERNMENT SYSTEM - DATABASE SETUP")
            print("=" * 60)

            # Create all tables
            print("\n1. Creating/verifying database tables...")
            db.create_all()
            print("✓ Tables ready")

            # Check existing facilities
            existing_facilities = {f.code: f for f in Facility.query.all()}

            # Facilities to create
            facilities_data = [
                {
                    "name": "Ministry of Defence",
                    "code": "MOD",
                    "type": "Ministry",
                    "location": "Capital City",
                },
                {
                    "name": "Ministry of Finance",
                    "code": "MOF",
                    "type": "Ministry",
                    "location": "Capital City",
                },
                {
                    "name": "National Security Agency",
                    "code": "NSA",
                    "type": "Agency",
                    "location": "Secure Location",
                },
            ]

            print("\n2. Setting up government facilities...")
            facility_objects = {}
            for fac_data in facilities_data:
                if fac_data["code"] in existing_facilities:
                    print(f"  ✓ {fac_data['name']} ({fac_data['code']}) already exists")
                    facility_objects[fac_data["code"]] = existing_facilities[
                        fac_data["code"]
                    ]
                else:
                    facility = Facility(**fac_data)
                    db.session.add(facility)
                    db.session.flush()
                    facility_objects[fac_data["code"]] = facility
                    print(f"  + Created: {fac_data['name']} ({fac_data['code']})")

            db.session.commit()

            # Create departments
            print("\n3. Setting up departments...")
            departments_data = [
                {"facility_code": "MOD", "name": "Operations", "code": "OPS"},
                {"facility_code": "MOD", "name": "Intelligence", "code": "INT"},
                {"facility_code": "MOD", "name": "Logistics", "code": "LOG"},
                {"facility_code": "MOF", "name": "Budget", "code": "BUD"},
                {"facility_code": "MOF", "name": "Taxation", "code": "TAX"},
                {"facility_code": "NSA", "name": "Cyber Security", "code": "CYB"},
                {"facility_code": "NSA", "name": "Counter Intelligence", "code": "CTI"},
            ]

            for dept_data in departments_data:
                # Check if department exists
                existing = Department.query.filter_by(
                    code=dept_data["code"],
                    facility_id=facility_objects[dept_data["facility_code"]].id,
                ).first()

                if not existing:
                    department = Department(
                        name=dept_data["name"],
                        code=dept_data["code"],
                        facility_id=facility_objects[dept_data["facility_code"]].id,
                    )
                    db.session.add(department)
                    print(
                        f"  + Created: {dept_data['name']} in {dept_data['facility_code']}"
                    )

            db.session.commit()

            # Create or update test users
            print("\n4. Setting up government users...")

            users_data = [
                # MOD Users
                {
                    "username": "mod_admin",
                    "email": "admin@mod.gov",
                    "password": "Admin@123",
                    "user_class": "superadmin",
                    "facility": "Ministry of Defence",
                    "department": "Operations",
                    "clearance_level": "TOP_SECRET",
                },
                {
                    "username": "intel_officer",
                    "email": "intel@mod.gov",
                    "password": "Intel@123",
                    "user_class": "admin",
                    "facility": "Ministry of Defence",
                    "department": "Intelligence",
                    "clearance_level": "SECRET",
                },
                {
                    "username": "logistics",
                    "email": "logistics@mod.gov",
                    "password": "Logistics@123",
                    "user_class": "user",
                    "facility": "Ministry of Defence",
                    "department": "Logistics",
                    "clearance_level": "CONFIDENTIAL",
                },
                # MOF Users
                {
                    "username": "mof_admin",
                    "email": "admin@mof.gov",
                    "password": "Admin@123",
                    "user_class": "admin",
                    "facility": "Ministry of Finance",
                    "department": "Budget",
                    "clearance_level": "SECRET",
                },
                {
                    "username": "tax_officer",
                    "email": "tax@mof.gov",
                    "password": "Tax@123",
                    "user_class": "user",
                    "facility": "Ministry of Finance",
                    "department": "Taxation",
                    "clearance_level": "CONFIDENTIAL",
                },
                # NSA Users
                {
                    "username": "cyber_analyst",
                    "email": "cyber@nsa.gov",
                    "password": "Cyber@123",
                    "user_class": "admin",
                    "facility": "National Security Agency",
                    "department": "Cyber Security",
                    "clearance_level": "TOP_SECRET",
                },
                # Legacy user
                {
                    "username": "admin",
                    "email": "admin@zta.gov",
                    "password": "Admin123",
                    "user_class": "superadmin",
                    "facility": "IT Department",
                    "department": "Administration",
                    "clearance_level": "TOP_SECRET",
                },
            ]

            for user_data in users_data:
                existing_user = User.query.filter_by(email=user_data["email"]).first()

                if existing_user:
                    # Update if needed
                    print(
                        f"  ✓ User exists: {user_data['username']} ({user_data['email']})"
                    )
                else:
                    user = User(
                        username=user_data["username"],
                        email=user_data["email"],
                        user_class=user_data["user_class"],
                        facility=user_data["facility"],
                        department=user_data["department"],
                        clearance_level=user_data["clearance_level"],
                    )
                    user.set_password(user_data["password"])
                    db.session.add(user)
                    print(
                        f"  + Created: {user_data['username']} ({user_data['email']})"
                    )

            db.session.commit()

            # Create sample documents if none exist
            print("\n5. Checking sample documents...")
            if GovernmentDocument.query.count() == 0:
                create_sample_documents()
            else:
                print(
                    f"  ✓ Database has {GovernmentDocument.query.count()} existing documents"
                )

            print("\n" + "=" * 60)
            print("SETUP COMPLETE - SYSTEM READY FOR DEMONSTRATION")
            print("=" * 60)

            print("\nDEMONSTRATION CREDENTIALS:")
            print("-" * 60)
            print("Ministry of Defence:")
            print("  • Superadmin: mod_admin / Admin@123 (TOP_SECRET)")
            print("  • Intelligence: intel_officer / Intel@123 (SECRET)")
            print("  • Logistics: logistics / Logistics@123 (CONFIDENTIAL)")
            print("\nMinistry of Finance:")
            print("  • Admin: mof_admin / Admin@123 (SECRET)")
            print("  • Tax Officer: tax_officer / Tax@123 (CONFIDENTIAL)")
            print("\nNational Security Agency:")
            print("  • Cyber Analyst: cyber_analyst / Cyber@123 (TOP_SECRET)")
            print("\nLegacy Admin:")
            print("  • Superadmin: admin / Admin123 (TOP_SECRET)")
            print("-" * 60)

            print("\nZTA ARCHITECTURE PORTS:")
            print("• Main Server (JWT): http://localhost:5000")
            print("• API Server (mTLS): https://localhost:8443")
            print("• OPA Agent: http://localhost:8181")
            print("=" * 60)

    except Exception as e:
        print(f"Error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


def create_sample_documents():
    """Create sample government documents"""
    try:
        from app.models.user import User, GovernmentDocument
        from app import db
        from datetime import datetime, timedelta

        users = User.query.all()

        if not users:
            print("  ⚠ No users found to create documents")
            return

        sample_documents = [
            {
                "title": "Defence Budget Allocation 2024",
                "description": "Annual budget allocation for defence operations",
                "content": "Confidential budget details for MOD operations...",
                "classification": "SECRET",
                "facility": "Ministry of Defence",
                "department": "Operations",
                "category": "Budget",
                "expiry_date": datetime.utcnow() + timedelta(days=365 * 5),
            },
            {
                "title": "Intelligence Report - Region X",
                "description": "Latest intelligence assessment",
                "content": "Top secret intelligence findings...",
                "classification": "TOP_SECRET",
                "facility": "Ministry of Defence",
                "department": "Intelligence",
                "category": "Intelligence",
                "expiry_date": datetime.utcnow() + timedelta(days=365 * 10),
            },
            {
                "title": "Logistics Supply Chain",
                "description": "Defence logistics supply chain details",
                "content": "Confidential logistics information...",
                "classification": "CONFIDENTIAL",
                "facility": "Ministry of Defence",
                "department": "Logistics",
                "category": "Operations",
                "expiry_date": datetime.utcnow() + timedelta(days=365 * 2),
            },
            {
                "title": "National Budget Framework",
                "description": "National budget framework document",
                "content": "Secret budget framework details...",
                "classification": "SECRET",
                "facility": "Ministry of Finance",
                "department": "Budget",
                "category": "Budget",
                "expiry_date": datetime.utcnow() + timedelta(days=365 * 3),
            },
            {
                "title": "Tax Policy Guidelines",
                "description": "Internal tax policy guidelines",
                "content": "Confidential tax policy details...",
                "classification": "CONFIDENTIAL",
                "facility": "Ministry of Finance",
                "department": "Taxation",
                "category": "Policy",
                "expiry_date": datetime.utcnow() + timedelta(days=365 * 2),
            },
            {
                "title": "Cyber Threat Assessment",
                "description": "National cyber threat assessment",
                "content": "Top secret threat intelligence...",
                "classification": "TOP_SECRET",
                "facility": "National Security Agency",
                "department": "Cyber Security",
                "category": "Security",
                "expiry_date": datetime.utcnow() + timedelta(days=365 * 7),
            },
            {
                "title": "Public Service Announcement",
                "description": "General public announcement",
                "content": "Public information for citizens...",
                "classification": "UNCLASSIFIED",
                "facility": "Ministry of Defence",
                "department": "Operations",
                "category": "Public",
                "expiry_date": None,
            },
        ]

        document_count = 0
        for doc_data in sample_documents:
            # Find a user from the same facility and department
            owner = next(
                (
                    u
                    for u in users
                    if u.facility == doc_data["facility"]
                    and u.department == doc_data["department"]
                ),
                users[0],
            )

            # Generate document ID
            doc_id = f"{doc_data['facility'][:3].upper()}-{doc_data['department'][:3].upper()}-{datetime.utcnow().strftime('%Y%m%d')}-{document_count + 1:04d}"

            # Check if document already exists
            existing = GovernmentDocument.query.filter_by(document_id=doc_id).first()
            if not existing:
                document = GovernmentDocument(
                    document_id=doc_id,
                    title=doc_data["title"],
                    description=doc_data["description"],
                    content=doc_data["content"],
                    classification=doc_data["classification"],
                    facility=doc_data["facility"],
                    department=doc_data["department"],
                    category=doc_data["category"],
                    owner_id=owner.id,
                    created_by=owner.id,
                    expiry_date=doc_data["expiry_date"],
                )
                db.session.add(document)
                document_count += 1
                print(f"  + Created: {doc_id} - {doc_data['title']}")

        if document_count > 0:
            db.session.commit()
            print(f"✓ Created {document_count} sample documents")
        else:
            print("  ✓ Sample documents already exist")

    except Exception as e:
        print(f"Warning: Could not create sample documents: {e}")


if __name__ == "__main__":
    setup_database()
