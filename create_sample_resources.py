#!/usr/bin/env python3
"""
Create sample resources in the database - FIXED PATH VERSION
"""

import sys
import os
from datetime import datetime

# Get absolute path to project root
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

def create_sample_resources():
    """Direct database access with correct path"""
    
    print("📝 Creating sample resources...")
    
    try:
        # Set the correct database path BEFORE importing models
        db_path = os.path.join(BASE_DIR, "instance", "government_zta.db")
        print(f"📁 Database path: {db_path}")
        
        if not os.path.exists(db_path):
            print(f"❌ Database not found at: {db_path}")
            print("Please run setup_database.py first")
            return False
        
        # Now import with correct configuration
        from app.api_models import db
        from app.models.user import GovernmentDocument, User
        from werkzeug.security import generate_password_hash
        
        print("✅ Database models imported")
        
        # Create Flask app with correct config
        from flask import Flask
        app = Flask(__name__)
        
        # Use absolute path for SQLite
        app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        
        db.init_app(app)
        
        with app.app_context():
            # Check if testuser exists
            user = User.query.filter_by(username="testuser").first()
            if not user:
                print("❌ testuser not found, creating...")
                
                # Create testuser
                testuser = User(
                    username="testuser",
                    email="test@mod.gov",
                    password_hash=generate_password_hash("password123"),
                    user_class="user",
                    facility="Ministry of Defence",
                    department="MOD",
                    clearance_level="SECRET",
                    is_active=True
                )
                db.session.add(testuser)
                db.session.commit()
                user = testuser
                print("✅ Created testuser")
            
            print(f"✅ User: {user.username} (ID: {user.id}, Dept: {user.department}, Clearance: {user.clearance_level})")
            
            # Check existing resources
            existing_count = GovernmentDocument.query.count()
            if existing_count > 0:
                print(f"✅ Database already has {existing_count} documents")
                
                # Show existing
                resources = GovernmentDocument.query.all()
                print("📋 Existing documents:")
                for r in resources:
                    print(f"  • ID: {r.id}, Title: {r.title}, Classification: {r.classification}, Department: {r.department}")
                
                # Ask if we should add more
                response = input("\nAdd additional sample resources? (y/n): ").strip().lower()
                if response != 'y':
                    return True
            
            # Create sample resources
            sample_resources = [
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
            ]
            
            created_count = 0
            for resource_data in sample_resources:
                # Check if already exists
                existing = GovernmentDocument.query.filter_by(
                    document_id=resource_data["document_id"]
                ).first()
                
                if not existing:
                    doc = GovernmentDocument(**resource_data)
                    db.session.add(doc)
                    created_count += 1
                    print(f"✅ Created: {resource_data['document_id']} - {resource_data['title']}")
                else:
                    print(f"⚠️ Already exists: {resource_data['document_id']}")
            
            if created_count > 0:
                db.session.commit()
                print(f"\n✅ Successfully created {created_count} new sample resources")
            else:
                print(f"\n✅ All sample resources already exist")
            
            # Show all resources
            print("\n📊 ALL RESOURCES IN DATABASE:")
            resources = GovernmentDocument.query.all()
            for r in resources:
                print(f"  • ID: {r.id}, Title: {r.title}, Classification: {r.classification}, Department: {r.department}")
            
            return True
                
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return direct_sql_fix()
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return direct_sql_fix()

def direct_sql_fix():
    """Direct SQL method as fallback"""
    import sqlite3
    
    db_path = os.path.join(BASE_DIR, "instance", "government_zta.db")
    
    if not os.path.exists(db_path):
        print(f"❌ Database not found: {db_path}")
        return False
    
    print(f"\n🔄 Using direct SQL method for: {db_path}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Check testuser
        cursor.execute("SELECT id, username, department FROM user WHERE username = 'testuser'")
        user = cursor.fetchone()
        
        if not user:
            print("❌ testuser not found. Creating testuser...")
            
            # Create testuser
            cursor.execute('''
                INSERT INTO user (username, email, password_hash, user_class, facility, department, clearance_level, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                'testuser', 
                'test@mod.gov',
                'pbkdf2:sha256:260000$abc123$xyz456',  # dummy hash
                'user',
                'Ministry of Defence',
                'MOD',
                'SECRET',
                1
            ))
            conn.commit()
            
            cursor.execute("SELECT id, username, department FROM user WHERE username = 'testuser'")
            user = cursor.fetchone()
        
        user_id, username, department = user
        print(f"✅ User: {username} (ID: {user_id}, Dept: {department})")
        
        # Check existing documents
        cursor.execute("SELECT id, document_id, title, classification, department FROM government_document")
        existing_docs = cursor.fetchall()
        
        if existing_docs:
            print(f"\n📋 Existing documents ({len(existing_docs)}):")
            for doc in existing_docs:
                print(f"  • ID: {doc[0]}, DocID: {doc[1]}, Title: {doc[2]}, Class: {doc[3]}, Dept: {doc[4]}")
        
        # Create sample resources if needed
        sample_resources = [
            (None, 'MOD-DEP-001', 'Military Readiness Report', 'Current military readiness status', 
             'Military readiness content...', 'DEPARTMENT', 'Ministry of Defence', 'MOD', 'Military', 
             user_id, user_id, datetime.utcnow().isoformat(), datetime.utcnow().isoformat()),
            
            (None, 'MOD-DEP-002', 'Defense Budget Allocation', 'Quarterly defense budget allocation', 
             'Budget content...', 'DEPARTMENT', 'Ministry of Defence', 'MOD', 'Budget', 
             user_id, user_id, datetime.utcnow().isoformat(), datetime.utcnow().isoformat()),
            
            (None, 'MOD-TS-001', 'TOP SECRET: Special Operations Plan', 'Detailed plan for special military operations', 
             'TOP SECRET content...', 'TOP_SECRET', 'Ministry of Defence', 'MOD', 'Operations', 
             user_id, user_id, datetime.utcnow().isoformat(), datetime.utcnow().isoformat()),
            
            (None, 'GOV-PUB-001', 'Government Annual Report 2024', 'Public annual report of government activities', 
             'Annual report content...', 'PUBLIC', 'Government HQ', 'GENERAL', 'Reports', 
             user_id, user_id, datetime.utcnow().isoformat(), datetime.utcnow().isoformat()),
        ]
        
        created_count = 0
        for resource in sample_resources:
            cursor.execute("SELECT id FROM government_document WHERE document_id = ?", (resource[1],))
            if not cursor.fetchone():
                cursor.execute('''
                    INSERT INTO government_document 
                    (id, document_id, title, description, content, classification, facility, department, 
                     category, owner_id, created_by, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', resource)
                created_count += 1
                print(f"✅ Created: {resource[1]} - {resource[2]}")
        
        if created_count > 0:
            conn.commit()
            print(f"\n✅ Created {created_count} new resources")
        else:
            print(f"\n✅ All resources already exist")
        
        # Show final state
        cursor.execute("SELECT id, document_id, title, classification, department FROM government_document ORDER BY id")
        all_docs = cursor.fetchall()
        
        print(f"\n📊 FINAL DATABASE STATE ({len(all_docs)} documents):")
        for doc in all_docs:
            print(f"  • ID: {doc[0]}, DocID: {doc[1]}, Title: {doc[2][:30]}..., Class: {doc[3]}, Dept: {doc[4]}")
        
        conn.close()
        return True
        
    except sqlite3.Error as e:
        print(f"❌ SQL error: {e}")
        return False

def quick_database_check():
    """Quick check of database contents"""
    import sqlite3
    
    db_path = os.path.join(BASE_DIR, "instance", "government_zta.db")
    
    if not os.path.exists(db_path):
        print(f"❌ Database not found: {db_path}")
        return False
    
    print(f"\n🔍 QUICK DATABASE CHECK: {db_path}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Check users
        cursor.execute("SELECT COUNT(*) FROM user")
        user_count = cursor.fetchone()[0]
        print(f"👥 Users: {user_count}")
        
        cursor.execute("SELECT id, username, department, clearance_level FROM user")
        users = cursor.fetchall()
        for u in users:
            print(f"  • ID: {u[0]}, Username: {u[1]}, Dept: {u[2]}, Clearance: {u[3]}")
        
        # Check documents
        cursor.execute("SELECT COUNT(*) FROM government_document")
        doc_count = cursor.fetchone()[0]
        print(f"\n📄 Documents: {doc_count}")
        
        cursor.execute("SELECT id, document_id, title, classification, department FROM government_document")
        docs = cursor.fetchall()
        for d in docs:
            print(f"  • ID: {d[0]}, DocID: {d[1]}, Title: {d[2][:30]}..., Class: {d[3]}, Dept: {d[4]}")
        
        conn.close()
        return True
        
    except sqlite3.Error as e:
        print(f"❌ SQL error: {e}")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("📝 ZTA SYSTEM - CREATE SAMPLE RESOURCES")
    print("=" * 60)
    
    # First, check what's already in the database
    quick_database_check()
    
    print("\n" + "=" * 60)
    print("🛠️  CREATING/RESETTING RESOURCES")
    print("=" * 60)
    
    # Ask what to do
    print("\nOptions:")
    print("1. Add sample resources (keep existing)")
    print("2. Reset everything (delete existing, create fresh)")
    print("3. Just check database, don't change anything")
    
    choice = input("\nChoose option (1/2/3): ").strip()
    
    if choice == '1':
        create_sample_resources()
    elif choice == '2':
        print("\n⚠️  WARNING: This will DELETE ALL existing documents!")
        confirm = input("Are you sure? (yes/no): ").strip().lower()
        if confirm == 'yes':
            # Reset database
            import sqlite3
            db_path = os.path.join(BASE_DIR, "instance", "government_zta.db")
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM government_document")
            cursor.execute("DELETE FROM access_log")
            conn.commit()
            conn.close()
            print("✅ Cleared existing documents")
            create_sample_resources()
    else:
        print("\n✅ Database check complete")
    
    print("\n" + "=" * 60)
    print("🎯 READY FOR TESTING!")
    print("=" * 60)
    print("\nNow you can:")
    print("1. Start your servers:")
    print("   python run_opa_server.py")
    print("   python opa_agent_server.py")
    print("   python api_server.py")
    print("   python gateway_server.py")
    print("\n2. Login at: https://localhost:5000/login")
    print("   Username: testuser")
    print("   Password: password123")
    print("\n3. Go to Resources page")
    print("4. Click 'View' on a resource to test ZTA flow")