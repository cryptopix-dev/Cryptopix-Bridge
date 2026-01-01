"""
VDS Data Type Testing Script

This script tests if the VDS properly handles and returns correct data types
to client applications.

Usage:
    python test_vds_datatypes.py

Requirements:
    - VDS must be running on localhost:3306
    - Test database with sample data
"""

import mysql.connector
import logging
from datetime import datetime, date
from decimal import Decimal

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def test_vds_datatypes():
    """Test VDS data type handling"""
    
    logger.info("=" * 80)
    logger.info("VDS DATA TYPE TEST")
    logger.info("=" * 80)
    
    try:
        # Connect to VDS
        logger.info("\n📡 Connecting to VDS on localhost:3306...")
        conn = mysql.connector.connect(
            host='localhost',
            port=3306,
            user='root',
            password='password',
            database='cryptopix_encrypted'
        )
        logger.info("✅ Connected successfully!")
        
        cursor = conn.cursor()
        
        # Test 1: Check column descriptions
        logger.info("\n" + "=" * 80)
        logger.info("TEST 1: Column Type Metadata")
        logger.info("=" * 80)
        
        test_query = "SELECT * FROM users LIMIT 1"
        logger.info(f"Query: {test_query}")
        
        cursor.execute(test_query)
        
        logger.info("\n📋 Column Descriptions:")
        logger.info(f"{'Column Name':<20} {'Type Code':<12} {'Display Size':<15} {'Internal Size':<15}")
        logger.info("-" * 80)
        
        for desc in cursor.description:
            col_name = desc[0]
            type_code = desc[1]
            display_size = desc[2]
            internal_size = desc[3]
            
            # Map type code to name
            type_names = {
                0: "DECIMAL", 1: "TINY", 2: "SHORT", 3: "LONG", 4: "FLOAT",
                5: "DOUBLE", 7: "TIMESTAMP", 8: "LONGLONG", 10: "DATE",
                11: "TIME", 12: "DATETIME", 246: "NEWDECIMAL", 252: "BLOB",
                253: "VAR_STRING", 254: "STRING"
            }
            type_name = type_names.get(type_code, f"UNKNOWN({type_code})")
            
            logger.info(f"{col_name:<20} {type_name:<12} {str(display_size):<15} {str(internal_size):<15}")
        
        # Test 2: Check actual data types
        logger.info("\n" + "=" * 80)
        logger.info("TEST 2: Actual Python Data Types")
        logger.info("=" * 80)
        
        row = cursor.fetchone()
        
        if row:
            logger.info("\n📊 Row Data:")
            logger.info(f"{'Column':<20} {'Value':<30} {'Python Type':<20} {'Expected':<20}")
            logger.info("-" * 90)
            
            for i, value in enumerate(row):
                col_name = cursor.description[i][0]
                type_code = cursor.description[i][1]
                python_type = type(value).__name__
                
                # Determine expected type based on MySQL type code
                expected_types = {
                    1: "int", 2: "int", 3: "int", 8: "int",  # Integer types
                    4: "float", 5: "float",  # Float types
                    246: "Decimal",  # Decimal
                    7: "datetime", 12: "datetime",  # Datetime types
                    10: "date",  # Date
                    11: "time",  # Time
                    253: "str", 254: "str"  # String types
                }
                expected = expected_types.get(type_code, "str")
                
                # Check if type matches
                match = "✅" if python_type == expected else "❌"
                
                value_str = str(value)[:28] if value is not None else "NULL"
                logger.info(f"{col_name:<20} {value_str:<30} {python_type:<20} {expected:<20} {match}")
        
        # Test 3: Specific type tests
        logger.info("\n" + "=" * 80)
        logger.info("TEST 3: Specific Data Type Tests")
        logger.info("=" * 80)
        
        test_cases = [
            ("SELECT 42 as test_int", "int", "Integer literal"),
            ("SELECT 3.14 as test_float", "float", "Float literal"),
            ("SELECT 'hello' as test_string", "str", "String literal"),
            ("SELECT CURDATE() as test_date", "date", "Current date"),
            ("SELECT NOW() as test_datetime", "datetime", "Current datetime"),
        ]
        
        for query, expected_type, description in test_cases:
            logger.info(f"\n🧪 {description}")
            logger.info(f"   Query: {query}")
            
            try:
                cursor.execute(query)
                result = cursor.fetchone()
                
                if result:
                    value = result[0]
                    actual_type = type(value).__name__
                    match = "✅" if actual_type == expected_type else "❌"
                    
                    logger.info(f"   Value: {value}")
                    logger.info(f"   Expected Type: {expected_type}")
                    logger.info(f"   Actual Type: {actual_type} {match}")
                    
                    if actual_type != expected_type:
                        logger.warning(f"   ⚠️ TYPE MISMATCH! Expected {expected_type}, got {actual_type}")
            except Exception as e:
                logger.error(f"   ❌ Error: {e}")
        
        # Summary
        logger.info("\n" + "=" * 80)
        logger.info("TEST SUMMARY")
        logger.info("=" * 80)
        logger.info("\nIf you see ❌ TYPE MISMATCH warnings above:")
        logger.info("1. Check VDS logs for column type extraction")
        logger.info("2. Verify console_service is returning column_types")
        logger.info("3. Ensure VDS is using column_types in packet building")
        logger.info("\nExpected behavior:")
        logger.info("- Integer columns should return Python int")
        logger.info("- Float columns should return Python float")
        logger.info("- Date columns should return Python date")
        logger.info("- Datetime columns should return Python datetime")
        logger.info("- String columns should return Python str")
        
        cursor.close()
        conn.close()
        
        logger.info("\n✅ Test completed!")
        
    except mysql.connector.Error as err:
        logger.error(f"\n❌ MySQL Error: {err}")
        logger.error(f"   Error Code: {err.errno}")
        logger.error(f"   SQL State: {err.sqlstate}")
        logger.error(f"   Message: {err.msg}")
    except Exception as e:
        logger.error(f"\n❌ Unexpected Error: {e}")
        import traceback
        logger.error(traceback.format_exc())


if __name__ == "__main__":
    test_vds_datatypes()
