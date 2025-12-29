"""
CryptoPIX Bridge v3.0 - Minimal Security Module
Provides audit logging functionality
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

# IST Timezone (UTC+5:30)
IST = timezone(timedelta(hours=5, minutes=30))

def get_ist_now():
    """Get current time in IST timezone"""
    return datetime.now(IST)

class AuditLogger:
    """Simple audit logger"""

    async def log_event(self,
                       event_type: str,
                       user_id: Optional[str] = None,
                       resource: Optional[str] = None,
                       action: str = "",
                       status: str = "success",
                       details: Optional[Dict[str, Any]] = None,
                       ip_address: Optional[str] = None):
        """Log audit event"""
        log_entry = {
            "timestamp": get_ist_now().isoformat(),
            "event_type": event_type,
            "user_id": user_id,
            "resource": resource,
            "action": action,
            "status": status,
            "details": details or {},
            "ip_address": ip_address
        }

        logger.info(f"AUDIT: {log_entry}")

# Global audit logger instance
audit_logger = AuditLogger()