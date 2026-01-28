# check_certificate_time.py
from datetime import datetime
import subprocess

def check_certificate_times():
    """Check certificate validity times"""
    print("🕐 Checking Certificate Validity Times")
    print("=" * 60)
    
    # Check server certificate
    print("\n🔍 Server Certificate (certs/server.crt):")
    result = subprocess.run(
        ["openssl", "x509", "-in", "certs/server.crt", "-dates", "-noout"],
        capture_output=True,
        text=True
    )
    
    if result.returncode == 0:
        print(result.stdout)
        
        # Parse dates
        lines = result.stdout.strip().split('\n')
        not_before = None
        not_after = None
        
        for line in lines:
            if "notBefore=" in line:
                not_before = line.split('=')[1]
            elif "notAfter=" in line:
                not_after = line.split('=')[1]
        
        if not_before and not_after:
            print(f"\n📅 Current UTC time: {datetime.utcnow().strftime('%b %d %H:%M:%S %Y GMT')}")
            
            # Convert to datetime for comparison
            try:
                nb_dt = datetime.strptime(not_before, '%b %d %H:%M:%S %Y GMT')
                na_dt = datetime.strptime(not_after, '%b %d %H:%M:%S %Y GMT')
                now = datetime.utcnow()
                
                if now < nb_dt:
                    print(f"⚠️  Certificate NOT YET VALID (starts in {(nb_dt - now).days} days)")
                elif now > na_dt:
                    print(f"⚠️  Certificate EXPIRED (expired {(now - na_dt).days} days ago)")
                else:
                    print(f"✅ Certificate is currently valid")
                    print(f"   Valid for {(na_dt - now).days} more days")
                    
            except Exception as e:
                print(f"❌ Error parsing dates: {e}")
    
    # Check CA certificate
    print("\n🔍 CA Certificate (certs/ca.crt):")
    result = subprocess.run(
        ["openssl", "x509", "-in", "certs/ca.crt", "-dates", "-noout"],
        capture_output=True,
        text=True
    )
    
    if result.returncode == 0:
        print(result.stdout)

if __name__ == "__main__":
    check_certificate_times()