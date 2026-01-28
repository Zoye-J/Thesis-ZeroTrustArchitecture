# check_certificates.py
import os
from datetime import datetime

def check_certificate_files():
    """Check if certificate files exist and are new"""
    print("🔍 Checking Certificate Files")
    print("=" * 60)
    
    files_to_check = [
        ("CA Certificate", "certs/ca.crt"),
        ("Server Certificate", "certs/server.crt"),
        ("Server Key", "certs/server.key"),
    ]
    
    for name, path in files_to_check:
        if os.path.exists(path):
            mtime = os.path.getmtime(path)
            modified = datetime.fromtimestamp(mtime)
            size = os.path.getsize(path)
            
            print(f"\n{name}:")
            print(f"  ✅ File exists: {path}")
            print(f"  📅 Last modified: {modified}")
            print(f"  📏 Size: {size:,} bytes")
            
            # Check if it's the new certificate (created today)
            if modified.date() == datetime.today().date():
                print(f"  🆕 NEW (generated today)")
            else:
                print(f"  ⚠️  OLD (not regenerated)")
        else:
            print(f"\n{name}:")
            print(f"  ❌ Missing: {path}")

if __name__ == "__main__":
    check_certificate_files()