# create_fresh_resources.py
import sys
import os
from datetime import datetime

# Add to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from app.api_models import db
from app.models.user import GovernmentDocument, User

def create_fresh_resources():
    """Create fresh clean database resources"""
    app = create_app()
    
    with app.app_context():
        print("🗑️ Removing ALL existing resources...")
        
        # Delete all existing documents
        GovernmentDocument.query.delete()
        
        # Find testuser
        testuser = User.query.filter_by(username="testuser").first()
        if not testuser:
            print("❌ testuser not found")
            return
        
        print(f"✅ Found testuser: {testuser.username} (ID: {testuser.id})")
        
        # Create FRESH CLEAN resources
        fresh_resources = [
            {
                "document_id": "MOD-DEP-001",
                "title": "Military Readiness Report",
                "description": "Current military readiness status for Bangladesh Armed Forces",
                "content": "The military readiness report indicates optimal operational status across all branches. Regular training exercises are being conducted in Chittagong Hill Tracts and coastal regions. Equipment maintenance at 95% operational capacity.",
                "classification": "DEPARTMENT",
                "facility": "Ministry of Defence",
                "department": "MOD",
                "category": "Military Operations",
                "owner_id": testuser.id,
                "created_by": testuser.id,
                "is_archived": False,
            },
            {
                "document_id": "MOD-DEP-002",
                "title": "Defense Budget Allocation 2024",
                "description": "Quarterly defense budget allocation and expenditure report",
                "content": "Total defense budget for Q1 2024: $1.2 billion. Allocation breakdown: Army 45%, Navy 30%, Air Force 20%, Research & Development 5%. Major expenditures include naval vessel maintenance ($150M) and air force modernization ($200M).",
                "classification": "DEPARTMENT",
                "facility": "Ministry of Defence",
                "department": "MOD",
                "category": "Budget & Finance",
                "owner_id": testuser.id,
                "created_by": testuser.id,
                "is_archived": False,
            },
            {
                "document_id": "MOD-TS-001",
                "title": "TOP SECRET: Special Operations Plan",
                "description": "Detailed strategic plan for special military operations in border regions",
                "content": "CLASSIFIED - EYES ONLY\n\nOperation KALPANA: Coordinated response to cross-border security threats. Phase 1: Intelligence gathering complete. Phase 2: Strategic positioning underway. Phase 3: Contingency response protocols activated.\n\nAuthorized personnel: Director of Operations, Field Commanders, Intelligence Division Heads.",
                "classification": "TOP_SECRET",
                "facility": "Ministry of Defence",
                "department": "MOD",
                "category": "Special Operations",
                "owner_id": testuser.id,
                "created_by": testuser.id,
                "is_archived": False,
            },
            {
                "document_id": "GOV-PUB-001",
                "title": "Government Annual Report 2024",
                "description": "Public annual report of government activities and achievements",
                "content": "Government of Bangladesh Annual Report 2024\n\nEconomic Growth: GDP growth at 7.2%. Infrastructure Development: Padma Bridge operational, Metrorail Phase 1 complete. Social Welfare: Healthcare coverage expanded to 85% of population. Digital Bangladesh: 80% population now has internet access.\n\nPublished: January 2024 | Public Access: Unrestricted",
                "classification": "PUBLIC",
                "facility": "Government Secretariat",
                "department": "GENERAL",
                "category": "Public Reports",
                "owner_id": testuser.id,
                "created_by": testuser.id,
                "is_archived": False,
            },
            {
                "document_id": "MOD-CONF-001",
                "title": "Cybersecurity Threat Assessment",
                "description": "Monthly assessment of cybersecurity threats to government systems",
                "content": "Confidential - MOD Personnel Only\n\nThreat Level: ELEVATED\n\nKey Findings:\n1. Phishing attempts increased by 40%\n2. Ransomware threats targeting government payment systems\n3. APT group activity detected in finance sector\n\nRecommendations:\n- Implement multi-factor authentication for all MOD systems\n- Conduct security awareness training\n- Update intrusion detection systems",
                "classification": "DEPARTMENT",
                "facility": "Ministry of Defence",
                "department": "MOD",
                "category": "Cybersecurity",
                "owner_id": testuser.id,
                "created_by": testuser.id,
                "is_archived": False,
            }
        ]
        
        print("📝 Creating fresh database resources...")
        
        created_count = 0
        for resource_data in fresh_resources:
            # Create document
            doc = GovernmentDocument(**resource_data)
            db.session.add(doc)
            created_count += 1
            
            print(f"  ✅ {resource_data['document_id']}: {resource_data['title']}")
        
        db.session.commit()
        
        print("\n" + "=" * 60)
        print(f"✅ SUCCESS: Created {created_count} fresh database resources")
        print("=" * 60)
        
        # Verify
        total_docs = GovernmentDocument.query.count()
        print(f"📊 Total documents in database: {total_docs}")
        
        # List them
        print("\n📋 Database Contents:")
        docs = GovernmentDocument.query.all()
        for doc in docs:
            print(f"  - {doc.document_id}: {doc.title} ({doc.classification}, {doc.department})")

if __name__ == "__main__":
    create_fresh_resources()