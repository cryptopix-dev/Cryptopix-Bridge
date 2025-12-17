import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

class Settings:
    def __init__(self):
        self.BASE_DIR = Path(__file__).parent.parent
        self.CRYPTOPIX_DEFAULT_PASSWORD = os.getenv("CRYPTOPIX_DEFAULT_PASSWORD", "your_secure_password_here")
        self.default_security_level = os.getenv("SECURITY_LEVEL", "Min")
        self.tag_salt = os.getenv("TAG_SALT", "your_tag_salt_here")
        self.SOURCE_DB_URL = os.getenv("SOURCE_DB_URL")
        self.ENCRYPTED_DB_URL = os.getenv("ENCRYPTED_DB_URL")
        self.VDS_HOST = os.getenv("VDS_HOST", "0.0.0.0")
        self.VDS_PORT = int(os.getenv("VDS_PORT", "4406"))
        self.VDS_PROTOCOL = os.getenv("VDS_PROTOCOL", "mysql")
        self.VDS_MAX_CONNECTIONS = int(os.getenv("VDS_MAX_CONNECTIONS", "100"))
        self.VDS_URL = f"{self.VDS_PROTOCOL}://{self.VDS_HOST}:{self.VDS_PORT}"
        self.MONGODB_DATABASE = os.getenv("MONGODB_DATABASE", "cryptopix_bridge")
        self.hardware_acceleration = False
        self.APP_HOST = os.getenv("APP_HOST", "0.0.0.0")
        self.APP_PORT = int(os.getenv("APP_PORT", "8000"))
        self.DEBUG = os.getenv("DEBUG", "True").lower() == "true"
        self.SECRET_KEY = os.getenv("SECRET_KEY", "your_secret_key_here")
        self.LICENSE_SERVER_URL = os.getenv("LICENSE_SERVER_URL", "https://your-license-server.com/api/bridge")

settings = Settings()