"""
VDS Interface Error Diagnostic Script

This script helps diagnose interface/connection errors when client apps
connect to VDS.

Usage:
    python diagnose_vds_errors.py

This will test various connection scenarios and help identify the issue.
"""

import mysql.connector
import logging
import sys
import traceback
from datetime import datetime

# Setup detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def test_basic_connection():
    """Test 1: Basic connection to VDS"""
    logger.info("=" * 80)
    logger.info("TEST 1: Basic Connection")
    logger.info("=" * 80)
    
    try:
        logger.info("Attempting to connect to VDS on localhost:3306...")
        conn = mysql.connector.connect(
            host='localhost',
            port=3306,
            user='root',
            password='password',
            connect_timeout=10
        )
        logger.info("✅ Connection successful!")
        
        # Test ping
        logger.info("Testing connection ping...")
        conn.ping(reconnect=True, attempts=3, delay=1)
        logger.info("✅ Ping successful!")
        
        conn.close()
        logger.info("✅ Connection closed cleanly")
        return True
        
    except mysql.connector.Error as err:
        logger.error(f"❌ MySQL Error: {err}")
        logger.error(f"   Error Code: {err.errno}")
        logger.error(f"   SQL State: {err.sqlstate}")
        logger.error(f"   Message: {err.msg}")
        return False
    except Exception as e:
        logger.error(f"❌ Unexpected Error: {e}")
        logger.error(traceback.format_exc())
        return False


def test_database_selection():
    """Test 2: Database selection"""
    logger.info("\n" + "=" * 80)
    logger.info("TEST 2: Database Selection")
    logger.info("=" * 80)
    
    try:
        conn = mysql.connector.connect(
            host='localhost',
            port=3306,
            user='root',
            password='password'
        )
        logger.info("✅ Connected without database")
        
        cursor = conn.cursor()
        
        # Try to show databases
        logger.info("Executing: SHOW DATABASES")
        cursor.execute("SHOW DATABASES")
        databases = cursor.fetchall()
        logger.info(f"✅ Found {len(databases)} databases:")
        for db in databases:
            logger.info(f"   - {db[0]}")
        
        # Try to use a database
        if databases:
            db_name = databases[0][0]
            logger.info(f"\nTrying to USE database: {db_name}")
            cursor.execute(f"USE {db_name}")
            logger.info(f"✅ Successfully switched to database: {db_name}")
        
        cursor.close()
        conn.close()
        return True
        
    except mysql.connector.Error as err:
        logger.error(f"❌ MySQL Error: {err}")
        logger.error(f"   Error Code: {err.errno}")
        logger.error(f"   SQL State: {err.sqlstate}")
        logger.error(f"   Message: {err.msg}")
        return False
    except Exception as e:
        logger.error(f"❌ Unexpected Error: {e}")
        logger.error(traceback.format_exc())
        return False


def test_simple_query():
    """Test 3: Simple query execution"""
    logger.info("\n" + "=" * 80)
    logger.info("TEST 3: Simple Query Execution")
    logger.info("=" * 80)
    
    try:
        conn = mysql.connector.connect(
            host='localhost',
            port=3306,
            user='root',
            password='password'
        )
        cursor = conn.cursor()
        
        # Test 1: Simple SELECT
        logger.info("Test 3.1: SELECT 1")
        cursor.execute("SELECT 1")
        result = cursor.fetchone()
        logger.info(f"✅ Result: {result}")
        
        # Test 2: SELECT with string
        logger.info("\nTest 3.2: SELECT 'hello'")
        cursor.execute("SELECT 'hello' as greeting")
        result = cursor.fetchone()
        logger.info(f"✅ Result: {result}")
        
        # Test 3: SHOW TABLES
        logger.info("\nTest 3.3: SHOW TABLES")
        try:
            cursor.execute("SHOW TABLES")
            tables = cursor.fetchall()
            logger.info(f"✅ Found {len(tables)} tables:")
            for table in tables[:5]:  # Show first 5
                logger.info(f"   - {table[0]}")
        except Exception as e:
            logger.warning(f"⚠️ SHOW TABLES failed: {e}")
        
        cursor.close()
        conn.close()
        return True
        
    except mysql.connector.Error as err:
        logger.error(f"❌ MySQL Error: {err}")
        logger.error(f"   Error Code: {err.errno}")
        logger.error(f"   SQL State: {err.sqlstate if hasattr(err, 'sqlstate') else 'N/A'}")
        logger.error(f"   Message: {err.msg if hasattr(err, 'msg') else str(err)}")
        return False
    except Exception as e:
        logger.error(f"❌ Unexpected Error: {e}")
        logger.error(traceback.format_exc())
        return False


def test_table_query():
    """Test 4: Query actual table"""
    logger.info("\n" + "=" * 80)
    logger.info("TEST 4: Query Actual Table")
    logger.info("=" * 80)
    
    try:
        conn = mysql.connector.connect(
            host='localhost',
            port=3306,
            user='root',
            password='password'
        )
        cursor = conn.cursor()
        
        # Get first table
        cursor.execute("SHOW TABLES")
        tables = cursor.fetchall()
        
        if not tables:
            logger.warning("⚠️ No tables found in database")
            return True
        
        table_name = tables[0][0]
        logger.info(f"Testing with table: {table_name}")
        
        # Try to select from table
        query = f"SELECT * FROM {table_name} LIMIT 1"
        logger.info(f"Executing: {query}")
        
        cursor.execute(query)
        
        # Check column descriptions
        logger.info("\nColumn Descriptions:")
        for desc in cursor.description:
            logger.info(f"   {desc[0]}: type={desc[1]}")
        
        # Fetch result
        row = cursor.fetchone()
        if row:
            logger.info(f"\n✅ Successfully fetched row with {len(row)} columns")
            logger.info("First row data:")
            for i, value in enumerate(row):
                col_name = cursor.description[i][0]
                logger.info(f"   {col_name}: {value!r} (type: {type(value).__name__})")
        else:
            logger.info("⚠️ Table is empty")
        
        cursor.close()
        conn.close()
        return True
        
    except mysql.connector.Error as err:
        logger.error(f"❌ MySQL Error: {err}")
        logger.error(f"   Error Code: {err.errno if hasattr(err, 'errno') else 'N/A'}")
        logger.error(f"   SQL State: {err.sqlstate if hasattr(err, 'sqlstate') else 'N/A'}")
        logger.error(f"   Message: {err.msg if hasattr(err, 'msg') else str(err)}")
        logger.error("\nFull error details:")
        logger.error(traceback.format_exc())
        return False
    except Exception as e:
        logger.error(f"❌ Unexpected Error: {e}")
        logger.error(traceback.format_exc())
        return False


def test_multiple_queries():
    """Test 5: Multiple queries in sequence"""
    logger.info("\n" + "=" * 80)
    logger.info("TEST 5: Multiple Sequential Queries")
    logger.info("=" * 80)
    
    try:
        conn = mysql.connector.connect(
            host='localhost',
            port=3306,
            user='root',
            password='password'
        )
        cursor = conn.cursor()
        
        queries = [
            "SELECT 1",
            "SELECT 2",
            "SELECT 'test'",
            "SHOW TABLES",
        ]
        
        for i, query in enumerate(queries, 1):
            logger.info(f"\nQuery {i}: {query}")
            try:
                cursor.execute(query)
                result = cursor.fetchall()
                logger.info(f"✅ Success - {len(result)} rows")
            except Exception as e:
                logger.error(f"❌ Failed: {e}")
                return False
        
        cursor.close()
        conn.close()
        logger.info("\n✅ All queries executed successfully")
        return True
        
    except Exception as e:
        logger.error(f"❌ Error: {e}")
        logger.error(traceback.format_exc())
        return False


def test_connection_pool():
    """Test 6: Connection pooling"""
    logger.info("\n" + "=" * 80)
    logger.info("TEST 6: Connection Pooling")
    logger.info("=" * 80)
    
    try:
        from mysql.connector import pooling
        
        logger.info("Creating connection pool...")
        pool = pooling.MySQLConnectionPool(
            pool_name="vds_test_pool",
            pool_size=3,
            host='localhost',
            port=3306,
            user='root',
            password='password'
        )
        logger.info("✅ Pool created")
        
        # Get connection from pool
        logger.info("Getting connection from pool...")
        conn = pool.get_connection()
        logger.info("✅ Got connection from pool")
        
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        result = cursor.fetchone()
        logger.info(f"✅ Query result: {result}")
        
        cursor.close()
        conn.close()
        logger.info("✅ Connection returned to pool")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Error: {e}")
        logger.error(traceback.format_exc())
        return False


def main():
    """Run all diagnostic tests"""
    logger.info("=" * 80)
    logger.info("VDS INTERFACE ERROR DIAGNOSTIC")
    logger.info("=" * 80)
    logger.info(f"Start Time: {datetime.now()}")
    logger.info("")
    
    tests = [
        ("Basic Connection", test_basic_connection),
        ("Database Selection", test_database_selection),
        ("Simple Query", test_simple_query),
        ("Table Query", test_table_query),
        ("Multiple Queries", test_multiple_queries),
        ("Connection Pooling", test_connection_pool),
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results[test_name] = result
        except Exception as e:
            logger.error(f"❌ Test '{test_name}' crashed: {e}")
            logger.error(traceback.format_exc())
            results[test_name] = False
    
    # Summary
    logger.info("\n" + "=" * 80)
    logger.info("TEST SUMMARY")
    logger.info("=" * 80)
    
    passed = sum(1 for r in results.values() if r)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        logger.info(f"{test_name:<30} {status}")
    
    logger.info("")
    logger.info(f"Total: {passed}/{total} tests passed")
    
    if passed == total:
        logger.info("\n🎉 All tests passed! VDS is working correctly.")
    else:
        logger.info("\n⚠️ Some tests failed. Check the errors above.")
        logger.info("\nCommon issues:")
        logger.info("1. VDS not running on localhost:3306")
        logger.info("2. VDS crashed or has errors")
        logger.info("3. Database connection issues")
        logger.info("4. Protocol implementation bugs")
        logger.info("\nNext steps:")
        logger.info("1. Check VDS server logs for errors")
        logger.info("2. Verify VDS is running: netstat -an | findstr 3306")
        logger.info("3. Share the error messages above for help")
    
    logger.info(f"\nEnd Time: {datetime.now()}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\n\n⚠️ Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"\n\n❌ Fatal error: {e}")
        logger.error(traceback.format_exc())
        sys.exit(1)
