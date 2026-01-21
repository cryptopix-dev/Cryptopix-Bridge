"""
VDS OTP Pass-Through Mode
When client apps already have their own OTP verification,
VDS can operate in pass-through mode and just accept credentials
"""

import os
from pathlib import Path


class VDSMode:
    """VDS Operation Mode Configuration"""
    
    def __init__(self):
        # VDS Operation Mode
        # Options:
        #   'standalone' - VDS handles all OTP verification (default)
        #   'passthrough' - Client app handles OTP, VDS just passes through
        #   'hybrid' - Support both modes based on user configuration
        self.VDS_OTP_MODE = os.getenv('VDS_OTP_MODE', 'passthrough')
        
        # If passthrough mode, should VDS strip OTP from password?
        # true = Extract OTP and pass only password to backend DB
        # false = Pass entire "password:otp" string to backend DB
        self.VDS_STRIP_OTP_IN_PASSTHROUGH = os.getenv('VDS_STRIP_OTP_IN_PASSTHROUGH', 'true').lower() == 'true'
        
        # If hybrid mode, how to determine which users use VDS OTP?
        # Options:
        #   'database' - Check vds_users.db
        #   'always_passthrough' - Always pass through
        #   'always_vds' - Always use VDS OTP
        self.VDS_HYBRID_MODE_STRATEGY = os.getenv('VDS_HYBRID_MODE_STRATEGY', 'database')
        
        # Enable VDS OTP user management even in passthrough mode?
        # Useful if you want to add VDS OTP to some users later
        self.VDS_ENABLE_OTP_MANAGEMENT = os.getenv('VDS_ENABLE_OTP_MANAGEMENT', 'false').lower() == 'true'
    
    def is_passthrough_mode(self):
        """Check if VDS is in passthrough mode"""
        return self.VDS_OTP_MODE == 'passthrough'
    
    def is_standalone_mode(self):
        """Check if VDS handles OTP verification"""
        return self.VDS_OTP_MODE == 'standalone'
    
    def is_hybrid_mode(self):
        """Check if VDS supports both modes"""
        return self.VDS_OTP_MODE == 'hybrid'
    
    def should_strip_otp(self):
        """Check if OTP should be stripped from password in passthrough mode"""
        return self.is_passthrough_mode() and self.VDS_STRIP_OTP_IN_PASSTHROUGH
    
    def print_mode(self):
        """Print current VDS mode"""
        print("=" * 70)
        print("  VDS OTP Mode Configuration")
        print("=" * 70)
        print(f"\nOperation Mode: {self.VDS_OTP_MODE.upper()}")
        
        if self.is_passthrough_mode():
            print("\n📡 PASSTHROUGH MODE")
            print("  • Client app handles OTP verification")
            print("  • VDS acts as transparent database proxy")
            print(f"  • Strip OTP from password: {self.VDS_STRIP_OTP_IN_PASSTHROUGH}")
            print("  • VDS OTP verification: DISABLED")
        
        elif self.is_standalone_mode():
            print("\n🔐 STANDALONE MODE")
            print("  • VDS handles all OTP verification")
            print("  • Client sends password:otp format")
            print("  • VDS verifies OTP before connecting to backend")
        
        elif self.is_hybrid_mode():
            print("\n🔀 HYBRID MODE")
            print("  • Supports both VDS and client OTP")
            print(f"  • Strategy: {self.VDS_HYBRID_MODE_STRATEGY}")
            print("  • Per-user OTP configuration")
        
        print("\n" + "=" * 70)


# Global VDS mode instance
vds_mode = VDSMode()
