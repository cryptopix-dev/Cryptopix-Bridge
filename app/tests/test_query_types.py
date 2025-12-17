
import os
import sys
import logging
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent.parent))

from app.services.console_service import ConsoleService
from app.config import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_tests():
    logger.info("Starting SQL Query Tests...")
    
    logger.info(f"DB URL: {settings.ENCRYPTED_DB_URL}")
    
    service = ConsoleService()
    
    test_cases = [
        ("TRANSACTION", "START TRANSACTION"),
        ("COMMIT", "COMMIT"),
        ("ROLLBACK", "ROLLBACK"),
        ("DCL", "GRANT SELECT ON test_table TO 'user'"),
        ("USE", "USE test_db"),
        ("CALL", "CALL test_proc()")
    ]
    
    for name, query in test_cases:
        logger.info(f"Testing {name}...")
        try:
            
            
            result = service._get_query_type(query)
            logger.info(f"Query Type Identified: {result}")
            
            if result not in ['TRANSACTION', 'DCL', 'USE', 'CALL']:
                 logger.error(f"FAILED: Identified as {result} instead of expected type")
            else:
                 logger.info("PASS: Query type identification")
                 
        except Exception as e:
            logger.error(f"Exception during test {name}: {e}")

if __name__ == "__main__":
    run_tests()
