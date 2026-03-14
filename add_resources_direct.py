# add_resources_direct.py
import sqlite3
import os
from datetime import datetime

# Path to your database
DB_PATH = os.path.join("instance", "government_zta.db")


def add_resources_direct():
    """Add resources directly to SQLite database following policies.rego"""
    
    print("=" * 60)
    print("🔧 Adding Resources Following policies.rego")
    print("=" * 60)

    # Check if database exists
    if not os.path.exists(DB_PATH):
        print(f"❌ Database not found at: {DB_PATH}")
        print("Please make sure the database exists first.")
        return

    # Connect to database
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Get testuser
    cursor.execute(
        "SELECT id, username, department, clearance_level FROM user WHERE username = ?", 
        ("testuser",)
    )
    testuser = cursor.fetchone()

    if not testuser:
        print("❌ testuser not found in database!")
        print("Please register testuser first.")
        conn.close()
        return

    print(f"✅ Found testuser: {testuser['username']} (ID: {testuser['id']})")
    print(f"   Department: {testuser['department']}")
    print(f"   Clearance: {testuser['clearance_level']}")

    # First, delete all existing resources
    cursor.execute("DELETE FROM government_document")
    deleted_count = cursor.rowcount
    print(f"✅ Deleted {deleted_count} existing resources")

    # SIMPLE resources following policies.rego
    # Classification mapping: PUBLIC = BASIC, DEPARTMENT = CONFIDENTIAL, TOP_SECRET = TOP_SECRET
    resources = [
        # PUBLIC documents (BASIC in OPA) - Anyone can access
        (
            "PUB-001",
            "Public Announcement",
            "General public information",
            "This is a public document. All government employees can access this regardless of department.",
            "PUBLIC",  # Maps to BASIC in OPA
            "Government Secretariat",
            "GENERAL",
            "Public",
            testuser["id"],
            testuser["id"],
            datetime.utcnow().isoformat(),
            datetime.utcnow().isoformat(),
            0,
        ),
        (
            "PUB-002",
            "Government Holiday Schedule",
            "Official holiday calendar",
            "List of government holidays for the current year. Public information.",
            "PUBLIC",  # Maps to BASIC in OPA
            "Government Secretariat",
            "GENERAL",
            "Public",
            testuser["id"],
            testuser["id"],
            datetime.utcnow().isoformat(),
            datetime.utcnow().isoformat(),
            0,
        ),
        
        # MOD DEPARTMENT documents (CONFIDENTIAL in OPA) - Only MOD department
        (
            "MOD-DEP-001",
            "MOD Operations Manual",
            "Standard operating procedures for MOD",
            "This document contains MOD operational procedures. Only MOD personnel can access.",
            "DEPARTMENT",  # Maps to CONFIDENTIAL in OPA
            "Ministry of Defence",
            "MOD",
            "Operations",
            testuser["id"],
            testuser["id"],
            datetime.utcnow().isoformat(),
            datetime.utcnow().isoformat(),
            0,
        ),
        (
            "MOD-DEP-002",
            "MOD Personnel Roster",
            "Current MOD staff listing",
            "Confidential roster of MOD personnel. MOD access only.",
            "DEPARTMENT",  # Maps to CONFIDENTIAL in OPA
            "Ministry of Defence",
            "MOD",
            "Personnel",
            testuser["id"],
            testuser["id"],
            datetime.utcnow().isoformat(),
            datetime.utcnow().isoformat(),
            0,
        ),
        
        # MOF DEPARTMENT documents (CONFIDENTIAL in OPA) - Only MOF department
        (
            "MOF-DEP-001",
            "MOF Budget Guidelines",
            "Annual budget preparation guidelines",
            "Confidential budget guidelines for Ministry of Finance staff only.",
            "DEPARTMENT",  # Maps to CONFIDENTIAL in OPA
            "Ministry of Finance",
            "MOF",
            "Budget",
            testuser["id"],
            testuser["id"],
            datetime.utcnow().isoformat(),
            datetime.utcnow().isoformat(),
            0,
        ),
        (
            "MOF-DEP-002",
            "MOF Procurement Rules",
            "Government procurement regulations",
            "Internal procurement guidelines for MOF personnel only.",
            "DEPARTMENT",  # Maps to CONFIDENTIAL in OPA
            "Ministry of Finance",
            "MOF",
            "Procurement",
            testuser["id"],
            testuser["id"],
            datetime.utcnow().isoformat(),
            datetime.utcnow().isoformat(),
            0,
        ),
        
        # TOP_SECRET documents - MOD only, business hours, requires TOP_SECRET clearance
        (
            "MOD-TS-001",
            "MOD Strategic Defense Plan",
            "National defense strategy - TOP SECRET",
            "This document contains Bangladesh's national defense strategy. Access requires TOP_SECRET clearance and business hours (8 AM - 4 PM).",
            "TOP_SECRET",  # Maps to TOP_SECRET in OPA
            "Ministry of Defence",
            "MOD",
            "Strategy",
            testuser["id"],
            testuser["id"],
            datetime.utcnow().isoformat(),
            datetime.utcnow().isoformat(),
            0,
        ),
        (
            "MOD-TS-002",
            "MOD Intelligence Report",
            "Classified intelligence assessment",
            "Sensitive intelligence report. TOP_SECRET clearance required. Business hours only.",
            "TOP_SECRET",  # Maps to TOP_SECRET in OPA
            "Ministry of Defence",
            "MOD",
            "Intelligence",
            testuser["id"],
            testuser["id"],
            datetime.utcnow().isoformat(),
            datetime.utcnow().isoformat(),
            0,
        ),
        
        # NSA DEPARTMENT documents (CONFIDENTIAL in OPA) - Only NSA department
        (
            "NSA-DEP-001",
            "NSA Security Protocols",
            "National security agency protocols",
            "Internal security protocols for NSA personnel only.",
            "DEPARTMENT",  # Maps to CONFIDENTIAL in OPA
            "National Security Agency",
            "NSA",
            "Security",
            testuser["id"],
            testuser["id"],
            datetime.utcnow().isoformat(),
            datetime.utcnow().isoformat(),
            0,
        ),
    ]

    # Insert resources
    insert_sql = """
        INSERT INTO government_document 
        (document_id, title, description, content, classification, facility, department, 
         category, owner_id, created_by, created_at, updated_at, is_archived)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    cursor.executemany(insert_sql, resources)
    conn.commit()

    created_count = len(resources)
    print(f"\n✅ Created {created_count} new resources")

    # Show what was created
    print("\n" + "=" * 60)
    print("📋 Resource List (Following policies.rego):")
    print("=" * 60)
    print(f"{'ID':<4} {'Document ID':<15} {'Classification':<12} {'Department':<10} Title")
    print("-" * 60)

    cursor.execute(
        """
        SELECT id, document_id, title, classification, department 
        FROM government_document 
        ORDER BY 
            CASE classification
                WHEN 'PUBLIC' THEN 1
                WHEN 'DEPARTMENT' THEN 2
                WHEN 'TOP_SECRET' THEN 3
            END,
            department
    """
    )

    for row in cursor.fetchall():
        print(f"{row['id']:<4} {row['document_id']:<15} {row['classification']:<12} {row['department']:<10} {row['title'][:30]}")

    conn.close()

    print("\n" + "=" * 60)
    print("✅ Resources added successfully!")
    print("=" * 60)
    print("\n📌 Access Rules (from policies.rego):")
    print("   - PUBLIC (BASIC): Any authenticated user can access")
    print("   - DEPARTMENT (CONFIDENTIAL): Same department only")
    print("   - TOP_SECRET: MOD department + TOP_SECRET clearance + Business hours (8 AM - 4 PM)")
    print("\n📌 Your testuser (MOD, SECRET) can access:")
    print("   ✅ All PUBLIC documents")
    print("   ✅ MOD-DEP-001, MOD-DEP-002 (same department)")
    print("   ❌ MOF-DEP-001, MOF-DEP-002 (wrong department)")
    print("   ❌ NSA-DEP-001 (wrong department)")
    print("   ❌ MOD-TS-001, MOD-TS-002 (needs TOP_SECRET clearance)")


if __name__ == "__main__":
    add_resources_direct()