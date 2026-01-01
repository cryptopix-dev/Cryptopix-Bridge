"""
Quick VDS Test - Verify Sequence Number Fix

This is a minimal test to verify the packet sequence number fix works.
"""

import mysql.connector
import sys

print("=" * 80)
print("QUICK VDS TEST - Packet Sequence Number Fix Verification")
print("=" * 80)

try:
    print("\n1. Connecting to VDS...")
    conn = mysql.connector.connect(
        host='localhost',
        port=3306,
        user='root',
        password='password',
        connect_timeout=5
    )
    print("   ✅ Connected!")
    
    cursor = conn.cursor()
    
    print("\n2. Testing SELECT 1...")
    cursor.execute("SELECT 1")
    result = cursor.fetchone()
    print(f"   ✅ Result: {result}")
    
    print("\n3. Testing SELECT with string...")
    cursor.execute("SELECT 'hello' as greeting")
    result = cursor.fetchone()
    print(f"   ✅ Result: {result}")
    
    print("\n4. Testing SELECT with multiple columns...")
    cursor.execute("SELECT 1 as num, 'test' as text, 3.14 as pi")
    result = cursor.fetchone()
    print(f"   ✅ Result: {result}")
    
    print("\n5. Testing multiple rows...")
    cursor.execute("SELECT 1 UNION SELECT 2 UNION SELECT 3")
    results = cursor.fetchall()
    print(f"   ✅ Got {len(results)} rows: {results}")
    
    cursor.close()
    conn.close()
    
    print("\n" + "=" * 80)
    print("🎉 ALL TESTS PASSED!")
    print("=" * 80)
    print("\nThe packet sequence number fix is working correctly!")
    print("No sequence number errors occurred.")
    
except mysql.connector.Error as err:
    print(f"\n❌ MySQL Error: {err}")
    print(f"   Error Code: {err.errno if hasattr(err, 'errno') else 'N/A'}")
    print(f"   SQL State: {err.sqlstate if hasattr(err, 'sqlstate') else 'N/A'}")
    print(f"   Message: {err.msg if hasattr(err, 'msg') else str(err)}")
    
    if "sequence number" in str(err).lower():
        print("\n⚠️ SEQUENCE NUMBER ERROR STILL PRESENT!")
        print("   The fix may not have been applied correctly.")
        print("   Please restart the VDS server and try again.")
    
    sys.exit(1)
    
except Exception as e:
    print(f"\n❌ Unexpected Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
