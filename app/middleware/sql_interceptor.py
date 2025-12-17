"""
CryptoPIX Bridge v2.0 - SQL Interceptor Middleware
Intercepts and translates SQL queries between client applications and encrypted database
"""

import logging
import re
from typing import Dict, Any, Optional, List, Union
from sqlalchemy import text

from app.services.sql_translator import sql_translator, TableMapping, ColumnMapping
from app.core.database import get_db_session
from app.core.security import audit_logger
from app.config import settings

logger = logging.getLogger(__name__)


class SQLInterceptor:
    """Intercepts and translates SQL queries"""

    def __init__(self):
        self.query_patterns = {
            'SELECT': re.compile(r'\bSELECT\b', re.IGNORECASE),
            'INSERT': re.compile(r'\bINSERT\b', re.IGNORECASE),
            'UPDATE': re.compile(r'\bUPDATE\b', re.IGNORECASE),
            'DELETE': re.compile(r'\bDELETE\b', re.IGNORECASE),
            'CREATE': re.compile(r'\bCREATE\b', re.IGNORECASE),
            'ALTER': re.compile(r'\bALTER\b', re.IGNORECASE),
            'DROP': re.compile(r'\bDROP\b', re.IGNORECASE),
            'WITH': re.compile(r'\bWITH\b', re.IGNORECASE),  # For CTEs
            'UNION': re.compile(r'\bUNION\b', re.IGNORECASE),  # For UNION queries
        }

        self.table_mappings: Dict[str, TableMapping] = {}

    def register_table_mapping(self, table_name: str, mapping: TableMapping):
        """Register table mapping for interception"""
        self.table_mappings[table_name] = mapping
        logger.info(f"Registered table mapping for SQL interception: {table_name}")

    def set_database_type(self, db_url: str):
        """Set the database type for the translator"""
        sql_translator.set_database_type(db_url)

    async def intercept_query(self,
                             query: str,
                             user_id: Optional[str] = None,
                             client_ip: Optional[str] = None) -> Dict[str, Any]:
        """
        Intercept and process SQL query

        Args:
            query: Original SQL query from client
            user_id: ID of the user making the query
            client_ip: IP address of the client

        Returns:
            Dict containing processed query and metadata
        """
        try:
            logger.info(f"Intercepting query from user {user_id}: {query[:100]}...")

            table_name = self._extract_table_name(query)
            if not table_name:
                return {
                    "success": False,
                    "error": "Could not determine table/collection name from query",
                    "original_query": query
                }

            if table_name not in self.table_mappings:
                logger.warning(f"No mapping found for table {table_name}, available mappings: {list(self.table_mappings.keys())}, passing through unchanged")
                return {
                    "success": True,
                    "translated_query": query,
                    "table_name": table_name,
                    "translated": False,
                    "original_query": query,
                    "database_type": sql_translator.database_type
                }

            table_mapping = self.table_mappings[table_name]
            translated_result = sql_translator.translate_query(query, table_name)

            if not translated_result[0]:
                return {
                    "success": False,
                    "error": f"Query translation failed: {translated_result[1]}",
                    "original_query": query
                }

            translated_query, metadata = translated_result

            if user_id:
                await self._audit_query(
                    query, translated_query, table_name, user_id, client_ip, metadata
                )

            logger.info(f"✅ Query translated for table {table_name} ({sql_translator.database_type})")

            return {
                "success": True,
                "translated_query": translated_query,
                "original_query": query,
                "table_name": table_name,
                "translated": True,
                "metadata": metadata,
                "database_type": sql_translator.database_type,
                "is_mongodb": sql_translator.database_type == "mongodb"
            }

        except Exception as e:
            logger.error(f"Query interception failed: {e}")
            return {
                "success": False,
                "error": f"Query interception failed: {str(e)}",
                "original_query": query
            }

    def _extract_table_name(self, query: str) -> Optional[str]:
        """Extract table name from SQL query"""
        try:
            query_upper = query.strip().upper()
            if query_upper.startswith(('SHOW', 'DESCRIBE', 'EXPLAIN')):
                return "system_tables"  # Dummy table name for system queries

            query = re.sub(r'\s+', ' ', query.strip())

            if query.upper().startswith('WITH'):
                main_query_match = re.search(r'WITH\s+.*?\s+SELECT', query, re.IGNORECASE | re.DOTALL)
                if main_query_match:
                    query = query[main_query_match.end() - 6:]  # Start from SELECT

            if 'UNION' in query.upper():
                query = query.split('UNION')[0]

            patterns = [
                r'\bFROM\s+(\w+)',
                r'\bINSERT\s+INTO\s+(\w+)',
                r'\bUPDATE\s+(\w+)',
                r'\bDELETE\s+FROM\s+(\w+)',
                r'\bCREATE\s+TABLE\s+(\w+)',
                r'\bALTER\s+TABLE\s+(\w+)',
                r'\bDROP\s+TABLE\s+(\w+)'
            ]

            for pattern in patterns:
                match = re.search(pattern, query, re.IGNORECASE)
                if match:
                    return match.group(1).strip('`')

            return None

        except Exception as e:
            logger.error(f"Failed to extract table name: {e}")
            return None

    async def _audit_query(self,
                          original_query: str,
                          translated_query: str,
                          table_name: str,
                          user_id: str,
                          client_ip: Optional[str],
                          metadata: Dict[str, Any]):
        """Audit SQL query execution"""
        try:
            query_type = "unknown"
            if original_query.strip().upper().startswith("SELECT"):
                query_type = "select"
            elif original_query.strip().upper().startswith("INSERT"):
                query_type = "insert"
            elif original_query.strip().upper().startswith("UPDATE"):
                query_type = "update"
            elif original_query.strip().upper().startswith("DELETE"):
                query_type = "delete"

            await audit_logger.log_event(
                event_type="data_access",
                user_id=user_id,
                resource=f"table:{table_name}",
                action=f"{query_type}_query",
                status="success",
                details={
                    "query_type": query_type,
                    "table_name": table_name,
                    "translated": True,
                    "original_query_length": len(original_query),
                    "translated_query_length": len(translated_query),
                    "columns_processed": metadata.get("columns_translated", 0),
                    "encryption_operations": metadata.get("encryption_operations", 0)
                },
                ip_address=client_ip
            )

        except Exception as e:
            logger.error(f"Query audit failed: {e}")

    async def execute_translated_query(self,
                                      translated_query: Union[str, Dict[str, Any]],
                                      table_name: str,
                                      user_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Execute translated query on encrypted database

        Args:
            translated_query: The translated SQL query or MongoDB query document
            table_name: Target table/collection name
            user_id: User ID for auditing

        Returns:
            Query execution result
        """
        try:
            if isinstance(translated_query, dict) and sql_translator.database_type == "mongodb":
                return await self._execute_mongodb_query(translated_query, table_name, user_id)

            with get_db_session("encrypted") as session:
                result = session.execute(text(translated_query))

                if translated_query.strip().upper().startswith("SELECT"):
                    rows = result.fetchall()
                    column_names = result.keys()

                    raw_results = []
                    for row in rows:
                        row_dict = {}
                        for i, column_name in enumerate(column_names):
                            row_dict[column_name] = row[i]
                        raw_results.append(row_dict)

                    if table_name in self.table_mappings:
                        table_mapping = self.table_mappings[table_name]
                        decrypted_results = sql_translator.decrypt_query_results(raw_results, table_mapping)
                    else:
                        decrypted_results = raw_results

                    return {
                        "success": True,
                        "query_type": "SELECT",
                        "rows": decrypted_results,
                        "row_count": len(decrypted_results),
                        "columns": list(column_names),
                        "decrypted": table_name in self.table_mappings
                    }

                else:
                    session.commit()

                    if hasattr(result, 'rowcount'):
                        affected_rows = result.rowcount
                    else:
                        affected_rows = 0

                    query_type = "UNKNOWN"
                    if translated_query.strip().upper().startswith("INSERT"):
                        query_type = "INSERT"
                    elif translated_query.strip().upper().startswith("UPDATE"):
                        query_type = "UPDATE"
                    elif translated_query.strip().upper().startswith("DELETE"):
                        query_type = "DELETE"

                    return {
                        "success": True,
                        "query_type": query_type,
                        "affected_rows": affected_rows
                    }

        except Exception as e:
            logger.error(f"Query execution failed: {e}")

            try:
                with get_db_session("encrypted") as session:
                    session.rollback()
            except:
                pass

            return {
                "success": False,
                "error": str(e),
                "query_type": "UNKNOWN"
            }

    async def _execute_mongodb_query(self, mongo_query: Dict[str, Any], collection_name: str, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Execute MongoDB query"""
        try:
            from pymongo import MongoClient
            from app.config import settings

            client = MongoClient(settings.ENCRYPTED_DB_URL)
            db = client[settings.MONGODB_DATABASE or "cryptopix_bridge"]
            collection = db[collection_name]

            operation = mongo_query.get("operation")

            if operation == "find":
                filter_doc = mongo_query.get("filter", {})
                limit = mongo_query.get("limit")

                cursor = collection.find(filter_doc)
                if limit:
                    cursor = cursor.limit(limit)

                results = list(cursor)

                if collection_name in self.table_mappings:
                    table_mapping = self.table_mappings[collection_name]
                    decrypted_results = sql_translator.decrypt_query_results(results, table_mapping)
                else:
                    decrypted_results = results

                client.close()

                return {
                    "success": True,
                    "query_type": "SELECT",
                    "rows": decrypted_results,
                    "row_count": len(decrypted_results),
                    "database_type": "mongodb"
                }

            elif operation == "insert_one":
                document = mongo_query.get("document", {})
                result = collection.insert_one(document)
                client.close()

                return {
                    "success": True,
                    "query_type": "INSERT",
                    "inserted_id": str(result.inserted_id),
                    "database_type": "mongodb"
                }

            elif operation == "update_many":
                filter_doc = mongo_query.get("filter", {})
                update_doc = mongo_query.get("update", {})
                result = collection.update_many(filter_doc, update_doc)
                client.close()

                return {
                    "success": True,
                    "query_type": "UPDATE",
                    "modified_count": result.modified_count,
                    "database_type": "mongodb"
                }

            elif operation == "delete_many":
                filter_doc = mongo_query.get("filter", {})
                result = collection.delete_many(filter_doc)
                client.close()

                return {
                    "success": True,
                    "query_type": "DELETE",
                    "deleted_count": result.deleted_count,
                    "database_type": "mongodb"
                }

            else:
                client.close()
                return {
                    "success": False,
                    "error": f"Unsupported MongoDB operation: {operation}",
                    "database_type": "mongodb"
                }

        except Exception as e:
            logger.error(f"MongoDB query execution failed: {e}")
            return {
                "success": False,
                "error": f"MongoDB execution failed: {str(e)}",
                "database_type": "mongodb"
            }

    async def get_table_info(self, table_name: str) -> Dict[str, Any]:
        """Get information about a table's encryption mapping"""
        if table_name not in self.table_mappings:
            return {
                "table_name": table_name,
                "mapped": False,
                "error": "No mapping found for table"
            }

        mapping = self.table_mappings[table_name]

        return {
            "table_name": table_name,
            "mapped": True,
            "encrypted_columns": len(mapping.encrypted_columns),
            "non_encrypted_columns": list(mapping.non_encrypted_columns),  # Return actual list, not length
            "primary_key": mapping.primary_key,
            "column_details": {
                col_name: {
                    "encrypted": col_mapping.is_encrypted,
                    "hashed": col_mapping.is_hashed,
                    "has_tag": col_mapping.tag_name is not None,
                    "tag_type": col_mapping.tag_type,
                    "data_type": col_mapping.data_type
                }
                for col_name, col_mapping in mapping.encrypted_columns.items()
            }
        }

    def clear_mappings(self):
        """Clear all table mappings"""
        self.table_mappings.clear()
        logger.info("Cleared all table mappings")

    def get_mapping_summary(self) -> Dict[str, Any]:
        """Get summary of all table mappings"""
        return {
            "total_tables": len(self.table_mappings),
            "table_names": list(self.table_mappings.keys()),
            "mappings": {
                table_name: {
                    "encrypted_columns": len(mapping.encrypted_columns),
                    "non_encrypted_columns": len(mapping.non_encrypted_columns)
                }
                for table_name, mapping in self.table_mappings.items()
            }
        }


sql_interceptor = SQLInterceptor()


async def intercept_and_execute_query(query: str,
                                    user_id: Optional[str] = None,
                                    client_ip: Optional[str] = None) -> Dict[str, Any]:
    """Convenience function to intercept and execute a query"""
    intercept_result = await sql_interceptor.intercept_query(query, user_id, client_ip)

    if not intercept_result["success"]:
        return intercept_result

    if intercept_result["translated"]:
        execution_result = await sql_interceptor.execute_translated_query(
            intercept_result["translated_query"],
            intercept_result["table_name"],
            user_id
        )

        return {
            **intercept_result,
            **execution_result
        }
    else:
        execution_result = await sql_interceptor.execute_translated_query(
            query,
            intercept_result["table_name"],
            user_id
        )

        return {
            **intercept_result,
            **execution_result
        }


def register_table_mapping(table_name: str, mapping: TableMapping):
    """Convenience function to register table mapping"""
    sql_interceptor.register_table_mapping(table_name, mapping)


def get_table_info(table_name: str) -> Dict[str, Any]:
    """Convenience function to get table information"""
    return sql_interceptor.get_table_info(table_name)