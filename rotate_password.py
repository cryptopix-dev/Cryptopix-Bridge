#!/usr/bin/env python3
"""
CryptoPIX Bridge - Password Rotation Script
Rotate encryption password for encrypted database

Usage:
    python rotate_password.py

This script will:
1. Prompt for old and new passwords
2. Decrypt all data with old password
3. Re-encrypt all data with new password
4. Verify the rotation
5. Provide instructions for updating .env file
"""

import os
import sys
from pathlib import Path
import datetime

project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from app.services.password_rotation import PasswordRotationService
from app.core.encryption import clwe_encryptor
from app.config import settings


def validate_password_strength(password: str) -> tuple[bool, str]:
    """Validate password meets security requirements"""
    import re
    
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
        return False, "Password must contain at least one special character"
    
    return True, "Password meets all requirements"


def update_env_file(new_password: str):
    """Update .env file with new password"""
    try:
        env_path = project_root / '.env'
        
        if not env_path.exists():
            print(f"⚠️  .env file not found at {env_path}")
            print("   You'll need to manually update CRYPTOPIX_DEFAULT_PASSWORD")
            return False
        
        with open(env_path, 'r') as f:
            lines = f.readlines()
        
        password_found = False
        for i, line in enumerate(lines):
            if line.startswith('CRYPTOPIX_DEFAULT_PASSWORD=') or line.startswith('CRYPTOPIX_PASSWORD='):
                lines[i] = f'CRYPTOPIX_DEFAULT_PASSWORD={new_password}\n'
                password_found = True
                break
        
        if not password_found:
            lines.append(f'\nCRYPTOPIX_DEFAULT_PASSWORD={new_password}\n')
        
        with open(env_path, 'w') as f:
            f.writelines(lines)
        
        print(f"✅ Updated .env file with new password")
        return True
        
    except Exception as e:
        print(f"❌ Failed to update .env file: {e}")
        print(f"   Please manually update: CRYPTOPIX_DEFAULT_PASSWORD={new_password}")
        return False


def main():
    print("=" * 70)
    print(" " * 15 + "CryptoPIX Bridge - Password Rotation Tool")
    print("=" * 70)
    print()
    print("⚠️  WARNING: This will re-encrypt ALL data in your encrypted database!")
    print("⚠️  Make sure you have a backup before proceeding!")
    print()
    
    encrypted_db_url = os.getenv("ENCRYPTED_DB_URL")
    if not encrypted_db_url:
        print("❌ ERROR: ENCRYPTED_DB_URL not found in environment!")
        print("   Please set ENCRYPTED_DB_URL in your .env file")
        return 1
    
    print(f"📊 Database: {encrypted_db_url}")
    print()
    
    print("Step 1: Enter OLD (current) encryption password")
    print("-" * 70)
    old_password = input("OLD password: ").strip()
    
    if not old_password:
        print("❌ Old password is required!")
        return 1
    
    print()
    
    print("Step 2: Enter NEW encryption password")
    print("-" * 70)
    new_password = input("NEW password: ").strip()
    
    if not new_password:
        print("❌ New password is required!")
        return 1
    
    is_valid, message = validate_password_strength(new_password)
    if not is_valid:
        print(f"❌ {message}")
        return 1
    
    print(f"✅ {message}")
    print()
    
    confirm_password = input("Confirm NEW password: ").strip()
    
    if new_password != confirm_password:
        print("❌ Passwords don't match!")
        return 1
    
    print("✅ Passwords match")
    print()
    
    print("Step 3: Confirm password rotation")
    print("-" * 70)
    print("⚠️  This operation will:")
    print("   1. Decrypt ALL encrypted data with the old password")
    print("   2. Re-encrypt ALL data with the new password")
    print("   3. Update your .env file")
    print()
    print("⚠️  During this process:")
    print("   - The application should be in maintenance mode")
    print("   - No other processes should access the database")
    print("   - This may take a long time for large databases")
    print()
    
    confirm = input("Type 'YES' to proceed (anything else to cancel): ").strip()
    
    if confirm != "YES":
        print("❌ Operation cancelled by user")
        return 0
    
    print()
    print("=" * 70)
    print("🔄 Starting password rotation...")
    print("=" * 70)
    print()
    
    try:
        rotation_service = PasswordRotationService(
            encrypted_db_url=encrypted_db_url,
            clwe_encryptor=clwe_encryptor,
            old_password=old_password,
            new_password=new_password
        )
    except Exception as e:
        print(f"❌ Failed to initialize rotation service: {e}")
        return 1
    
    last_table = None
    def show_progress(table, progress, done, total):
        nonlocal last_table
        if table != last_table:
            print(f"\n📋 Processing table: {table}")
            last_table = table
        print(f"   Progress: {progress:3d}% ({done:,}/{total:,} rows)", end='\r')
    
    start_time = datetime.datetime.now()
    
    try:
        results = rotation_service.rotate_password_for_database(show_progress)
    except Exception as e:
        print(f"\n❌ Password rotation failed with exception: {e}")
        return 1
    
    end_time = datetime.datetime.now()
    duration = end_time - start_time
    
    print("\n")
    print("=" * 70)
    print("📊 Password Rotation Results")
    print("=" * 70)
    print()
    
    if results["status"] == "success":
        print("✅ Password rotation SUCCESSFUL!")
        print()
        print(f"   Duration: {duration}")
        print(f"   Tables processed: {results['tables_processed']}/{results['total_tables']}")
        print(f"   Total rows processed: {results['total_rows_processed']:,}")
        print()
        
        print("📋 Table Details:")
        for table_result in results.get("table_results", []):
            status_icon = "✅" if table_result["status"] == "success" else "⚠️"
            print(f"   {status_icon} {table_result['table']}: {table_result.get('rows_processed', 0):,} rows")
        
        print()
        print("=" * 70)
        print("🔍 Verifying password rotation...")
        print("=" * 70)
        print()
        
        try:
            if rotation_service.verify_password_rotation():
                print("✅ Verification SUCCESSFUL!")
                print("   All encrypted data can be decrypted with the new password")
                print()
                
                print("=" * 70)
                print("📝 Updating configuration...")
                print("=" * 70)
                print()
                
                if update_env_file(new_password):
                    print()
                    print("=" * 70)
                    print("🎉 PASSWORD ROTATION COMPLETE!")
                    print("=" * 70)
                    print()
                    print("✅ Next Steps:")
                    print("   1. Restart the CryptoPIX Bridge application")
                    print("   2. Test data access with critical queries")
                    print("   3. Monitor logs for any decryption errors")
                    print("   4. Update password in your password manager")
                    print("   5. Securely delete the old password from all systems")
                    print("   6. Keep database backup for at least 30 days")
                    print()
                    print("⚠️  Important:")
                    print("   - The old password will no longer work")
                    print("   - Make sure to save the new password securely")
                    print("   - Document this password change in your records")
                    print()
                    return 0
                else:
                    print()
                    print("⚠️  .env file update failed - please update manually")
                    print(f"   Set: CRYPTOPIX_DEFAULT_PASSWORD={new_password}")
                    print()
                    return 0
            else:
                print("❌ Verification FAILED!")
                print("   Some data may not decrypt correctly with the new password")
                print()
                print("⚠️  Recommended actions:")
                print("   1. Check the logs for specific errors")
                print("   2. Restore from backup if necessary")
                print("   3. Contact support for assistance")
                print()
                return 1
                
        except Exception as e:
            print(f"❌ Verification failed with exception: {e}")
            return 1
            
    elif results["status"] == "partial_success":
        print("⚠️  Password rotation PARTIALLY SUCCESSFUL")
        print()
        print(f"   Duration: {duration}")
        print(f"   Tables processed: {results['tables_processed']}/{results['total_tables']}")
        print(f"   Tables failed: {results['tables_failed']}")
        print(f"   Total rows processed: {results['total_rows_processed']:,}")
        print()
        print("📋 Failed Tables:")
        for table_result in results.get("table_results", []):
            if table_result["status"] == "failed":
                print(f"   ❌ {table_result['table']}: {table_result.get('error', 'Unknown error')}")
        print()
        print("⚠️  Some tables failed to rotate. Check logs for details.")
        print("   You may need to manually handle failed tables.")
        print()
        return 1
        
    else:
        print("❌ Password rotation FAILED!")
        print()
        print(f"   Error: {results.get('error', 'Unknown error')}")
        print(f"   Tables failed: {results['tables_failed']}/{results['total_tables']}")
        print()
        print("⚠️  Recommended actions:")
        print("   1. Check that the old password is correct")
        print("   2. Verify database connectivity")
        print("   3. Check logs for specific errors")
        print("   4. Ensure table mappings exist (schemas/mappings.json)")
        print()
        return 1


if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n❌ Operation cancelled by user (Ctrl+C)")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
