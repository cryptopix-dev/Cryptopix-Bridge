"""
CryptoPIX Bridge v3.0 - Minimal Database Adapters
Provides database type detection and adapter creation
"""

from enum import Enum
from typing import Any, Dict, Optional
import re

class DatabaseType(Enum):
    """Supported database types"""
    SQLITE = "sqlite"
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    MONGODB = "mongodb"

class DatabaseAdapter:
    """Minimal database adapter for URL parsing"""

    def __init__(self, db_url: str):
        self.db_url = db_url
        self.db_type = self._detect_db_type(db_url)

    def _detect_db_type(self, url: str) -> str:
        """Detect database type from URL"""
        url_lower = url.lower()
        if url_lower.startswith("sqlite"):
            return DatabaseType.SQLITE
        elif "mysql" in url_lower:
            return DatabaseType.MYSQL
        elif "postgresql" in url_lower or "postgres" in url_lower:
            return DatabaseType.POSTGRESQL
        elif "mssql" in url_lower or "sqlserver" in url_lower:
            return DatabaseType.MSSQL
        elif "oracle" in url_lower:
            return DatabaseType.ORACLE
        elif "mongodb" in url_lower:
            return DatabaseType.MONGODB
        else:
            return DatabaseType.SQLITE

def create_database_adapter(db_url: str) -> DatabaseAdapter:
    """Create database adapter from URL"""
    return DatabaseAdapter(db_url)