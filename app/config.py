"""
CryptoPIX Bridge v3.0 - Configuration
Simple configuration for the streamlined application
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Settings:
    """Application settings"""

    def __init__(self):
        # Base directory
        self.BASE_DIR = Path(__file__).parent.parent

        # Default encryption password (should be configurable)
        self.CRYPTOPIX_DEFAULT_PASSWORD = os.getenv("CRYPTOPIX_DEFAULT_PASSWORD", "default_password_123")

        # Security level
        self.default_security_level = os.getenv("SECURITY_LEVEL", "Min")

        # Tag salt for consistent hashing
        self.tag_salt = os.getenv("TAG_SALT", "cryptopix_bridge_salt_2024")

        # Database URLs (will be set during migration)
        self.SOURCE_DB_URL = os.getenv("SOURCE_DB_URL")
        self.ENCRYPTED_DB_URL = os.getenv("ENCRYPTED_DB_URL")

        # Virtual Database Server (VDS) settings
        self.VDS_HOST = os.getenv("VDS_HOST", "0.0.0.0")
        self.VDS_PORT = int(os.getenv("VDS_PORT", "4406"))
        self.VDS_PROTOCOL = os.getenv("VDS_PROTOCOL", "mysql")
        self.VDS_MAX_CONNECTIONS = int(os.getenv("VDS_MAX_CONNECTIONS", "100"))

        # VDS connection URL (for clients to connect to)
        # Format: mysql://user:password@bridge-server:4406/company_db
        self.VDS_URL = f"{self.VDS_PROTOCOL}://{self.VDS_HOST}:{self.VDS_PORT}"

        # MongoDB settings
        self.MONGODB_DATABASE = os.getenv("MONGODB_DATABASE", "cryptopix_bridge")

        # Hardware acceleration (placeholder)
        self.hardware_acceleration = False

        # Application settings
        self.APP_HOST = os.getenv("APP_HOST", "0.0.0.0")
        self.APP_PORT = int(os.getenv("APP_PORT", "8000"))
        self.DEBUG = os.getenv("DEBUG", "True").lower() == "true"

        # Session settings
        self.SECRET_KEY = os.getenv("SECRET_KEY", "cryptopix_bridge_secret_key_2024")


        # License server settings
        self.LICENSE_SERVER_URL = os.getenv("LICENSE_SERVER_URL", "https://your-license-server.com/api/bridge")

# Global settings instance
settings = Settings()