"""
Helper functions for database size calculation and metrics reporting
"""

import logging
import os
from sqlalchemy import create_engine, text, inspect
from pathlib import Path

logger = logging.getLogger(__name__)


def get_database_size(db_url: str) -> dict:
    """
    Calculate the size of a database.
    
    Args:
        db_url: Database connection URL
        
    Returns:
        Dictionary with size information in bytes and formatted
    """
    try:
        engine = create_engine(db_url)
        
        # Determine database type
        if 'sqlite' in db_url.lower():
            # For SQLite, get file size
            db_path = db_url.replace('sqlite:///', '')
            if os.path.exists(db_path):
                size_bytes = os.path.getsize(db_path)
            else:
                size_bytes = 0
                
        elif 'postgresql' in db_url.lower():
            # For PostgreSQL
            with engine.connect() as conn:
                result = conn.execute(text("SELECT pg_database_size(current_database())"))
                size_bytes = result.scalar()
                
        elif 'mysql' in db_url.lower():
            # For MySQL
            with engine.connect() as conn:
                result = conn.execute(text("""
                    SELECT SUM(data_length + index_length) 
                    FROM information_schema.tables 
                    WHERE table_schema = DATABASE()
                """))
                size_bytes = result.scalar() or 0
                
        elif 'mssql' in db_url.lower() or 'sqlserver' in db_url.lower():
            # For SQL Server
            with engine.connect() as conn:
                result = conn.execute(text("""
                    SELECT SUM(size) * 8 * 1024 
                    FROM sys.database_files
                """))
                size_bytes = result.scalar() or 0
        else:
            size_bytes = 0
            
        # Ensure size_bytes is a standard number (float) to avoid Decimal vs float issues
        if size_bytes is not None:
             size_bytes = float(size_bytes)
        else:
             size_bytes = 0.0
            
        engine.dispose()
        
        # Format size
        size_formatted = format_bytes(size_bytes)
        
        return {
            "size_bytes": size_bytes,
            "size_formatted": size_formatted,
            "size_mb": round(size_bytes / (1024 * 1024), 2),
            "size_gb": round(size_bytes / (1024 * 1024 * 1024), 4)
        }
        
    except Exception as e:
        logger.error(f"Failed to get database size: {e}")
        return {
            "size_bytes": 0,
            "size_formatted": "Unknown",
            "size_mb": 0,
            "size_gb": 0,
            "error": str(e)
        }


def format_bytes(bytes_size: int) -> str:
    """Format bytes to human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.2f} PB"


def send_metrics_to_license_server(license_key: str, metrics_data: dict) -> dict:
    """
    Send database metrics to license server.
    
    Args:
        license_key: User's license key
        metrics_data: Dictionary containing metrics to send
        
    Returns:
        Response from license server
    """
    import requests
    from app.config import settings
    import logging
    
    logger = logging.getLogger(__name__)
    
    try:
        # Use base LICENSE_SERVER_URL and append /api/metrics/database
        response = requests.post(
            f"{settings.LICENSE_SERVER_URL}/api/metrics/database",
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {license_key}'
            },
            json=metrics_data,
            timeout=10
        )
        
        if response.status_code == 200:
            return {'success': True, 'data': response.json()}
        else:
            return {'success': False, 'error': f'Server returned {response.status_code}'}
            
    except requests.RequestException as e:
        logger.error(f"Failed to send metrics to license server: {e}")
        return {'success': False, 'error': str(e)}
