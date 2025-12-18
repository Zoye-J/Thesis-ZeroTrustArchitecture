"""
Create sample government documents for different departments
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import create_app, db
from app.models.user import GovernmentDocument, User, Department, Facility
from datetime import datetime, timedelta
import random

app = create_app()

with app.app_context():
    print("Creating sample government documents...")
    
    # Get all users
    users = User.query.all()
    
    if not users:
        print("No users found. Please register users first.")
        exit(1)
    
    # Sample documents for different departments
    sample_documents = [
        # Ministry of Defence (MOD) documents
        {
            "title": "National Defence Strategy 2025",
            "description": "Comprehensive national defence strategy including military modernization plans",
            "content": "This document outlines the 5-year defence strategy including troop deployments, equipment procurement, and international cooperation.",
            "classification": "TOP_SECRET",
            "department": "Operations",
            "facility": "Ministry of Defence",
            "category": "Strategy",
            "owner": None,  # Will be assigned
        },
        {
            "title": "Military Exercise Report: Operation Shield",
            "description": "After-action report for joint military exercise",
            "content": "Detailed analysis of military exercise outcomes, lessons learned, and recommendations for future exercises.",
            "classification": "SECRET",
            "department": "Operations",
            "facility": "Ministry of Defence",
            "category": "Operations",
        },
        {
            "title": "Weapons Procurement Budget Q4",
            "description": "Quarterly budget allocation for weapons procurement",
            "content": "Detailed budget breakdown for weapons systems procurement including timelines and vendor contracts.",
            "classification": "CONFIDENTIAL",
            "department": "Operations",
            "facility": "Ministry of Defence",
            "category": "Budget",
        },
        
        # Ministry of Finance (MOF) documents
        {
            "title": "National Budget 2025-2026",
            "description": "Complete national budget allocation for fiscal year",
            "content": "Detailed budget allocation across all government ministries including revenue projections and expenditure plans.",
            "classification": "CONFIDENTIAL",
            "department": "Budget",
            "facility": "Ministry of Finance",
            "category": "Budget",
        },
        {
            "title": "Tax Reform Proposal",
            "description": "Proposed changes to national tax structure",
            "content": "Comprehensive tax reform proposal including corporate tax adjustments, VAT changes, and implementation timeline.",
            "classification": "CONFIDENTIAL",
            "department": "Budget",
            "facility": "Ministry of Finance",
            "category": "Policy",
        },
        {
            "title": "Economic Stimulus Package",
            "description": "Emergency economic stimulus measures",
            "content": "Details of economic stimulus package including business grants, tax relief, and infrastructure spending.",
            "classification": "SECRET",
            "department": "Budget",
            "facility": "Ministry of Finance",
            "category": "Finance",
        },
        
        # National Security Agency (NSA) documents
        {
            "title": "Cyber Threat Assessment Q4",
            "description": "Quarterly assessment of cyber threats to national infrastructure",
            "content": "Analysis of cyber threats from state and non-state actors including attack vectors and mitigation strategies.",
            "classification": "TOP_SECRET",
            "department": "Cyber Security",
            "facility": "National Security Agency",
            "category": "Intelligence",
        },
        {
            "title": "Critical Infrastructure Protection Plan",
            "description": "Protection plan for national critical infrastructure",
            "content": "Comprehensive protection plan for power grid, water systems, and communication networks.",
            "classification": "SECRET",
            "department": "Cyber Security",
            "facility": "National Security Agency",
            "category": "Security",
        },
        {
            "title": "Encryption Standards Update",
            "description": "Updated encryption standards for government communications",
            "content": "New encryption protocols and standards for secure government communications.",
            "classification": "CONFIDENTIAL",
            "department": "Cyber Security",
            "facility": "National Security Agency",
            "category": "Technology",
        },
        
        # Additional documents
        {
            "title": "Personnel Security Clearance Review",
            "description": "Annual review of personnel security clearances",
            "content": "Review of all personnel security clearances with recommendations for upgrades or revocations.",
            "classification": "SECRET",
            "department": "Operations",
            "facility": "Ministry of Defence",
            "category": "Personnel",
        },
        {
            "title": "Foreign Intelligence Report",
            "description": "Monthly foreign intelligence summary",
            "content": "Summary of foreign intelligence activities and threat assessments.",
            "classification": "TOP_SECRET",
            "department": "Cyber Security",
            "facility": "National Security Agency",
            "category": "Intelligence",
        },
        {
            "title": "Public Debt Management Strategy",
            "description": "Strategy for managing national public debt",
            "content": "Comprehensive strategy for debt management including refinancing options and risk mitigation.",
            "classification": "CONFIDENTIAL",
            "department": "Budget",
            "facility": "Ministry of Finance",
            "category": "Finance",
        },
    ]
    
    # Create documents
    documents_created = 0
    
    for doc_data in sample_documents:
        # Find a user from the same department
        department_users = [u for u in users if u.department == doc_data["department"] and u.facility == doc_data["facility"]]
        
        if not department_users:
            # If no user in that department, use any user
            owner = random.choice(users)
        else:
            owner = random.choice(department_users)
        
        # Generate document ID
        facility_code = doc_data["facility"][:3].upper()
        dept_code = doc_data["department"][:3].upper()
        date_str = datetime.now().strftime('%Y%m%d')
        doc_id = f"{facility_code}-{dept_code}-{date_str}-{random.randint(1000, 9999)}"
        
        # Create document
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
            created_at=datetime.utcnow() - timedelta(days=random.randint(1, 365)),
            expiry_date=datetime.utcnow() + timedelta(days=random.randint(365, 1825)),
            is_archived=False
        )
        
        db.session.add(document)
        documents_created += 1
    
    db.session.commit()
    
    print(f"✅ Created {documents_created} sample government documents")
    print("\nDocuments created by department:")
    
    # Count by department
    docs = GovernmentDocument.query.all()
    dept_counts = {}
    for doc in docs:
        dept = f"{doc.facility} - {doc.department}"
        dept_counts[dept] = dept_counts.get(dept, 0) + 1
    
    for dept, count in dept_counts.items():
        print(f"  {dept}: {count} documents")
    
    print(f"\nTotal documents in database: {GovernmentDocument.query.count()}")