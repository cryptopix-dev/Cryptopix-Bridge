"""
AI Assistant Service for Query Console
Provides intelligent SQL assistance, auto-completion, and query suggestions
"""

import re
import logging
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum
from dataclasses import dataclass

from app.config import settings
from app.core.encryption import clwe_encryptor
from app.core.schema_encryption import schema_encryption_service, SchemaEncryptionLevel

logger = logging.getLogger(__name__)


@dataclass
class ColumnMapping:
    """Mapping for a single column"""
    original_name: str
    encrypted_name: str
    tag_name: str
    is_encrypted: bool
    is_hashed: bool
    data_type: str
    supports_ordering: bool = True
    supports_ranges: bool = True


@dataclass
class TableMapping:
    """Mapping for a table with encrypted columns"""
    original_name: str
    encrypted_columns: Dict[str, ColumnMapping]
    primary_key: str
    non_encrypted_columns: List[str]


class SuggestionType(Enum):
    """Types of suggestions the AI can provide"""
    AUTOCOMPLETE = "autocomplete"
    CORRECTION = "correction"
    SUGGESTION = "suggestion"
    EXPLANATION = "explanation"


class AIAssistant:
    """AI-powered assistant for SQL query console"""

    def __init__(self):
        self.sql_keywords = {
            'SELECT', 'FROM', 'WHERE', 'JOIN', 'INNER', 'LEFT', 'RIGHT', 'FULL', 'OUTER',
            'ON', 'GROUP', 'BY', 'HAVING', 'ORDER', 'BY', 'LIMIT', 'OFFSET', 'DISTINCT',
            'INSERT', 'INTO', 'VALUES', 'UPDATE', 'SET', 'DELETE',

            'CREATE', 'ALTER', 'DROP', 'TRUNCATE', 'MERGE', 'REPLACE',

            'WITH', 'UNION', 'INTERSECT', 'EXCEPT', 'MINUS', 'PIVOT', 'UNPIVOT',
            'OVER', 'PARTITION', 'ROWS', 'RANGE', 'PRECEDING', 'FOLLOWING',

            'AS', 'AND', 'OR', 'NOT', 'IN', 'EXISTS', 'BETWEEN', 'LIKE', 'IS', 'NULL',

            'CASE', 'WHEN', 'THEN', 'ELSE', 'END', 'COALESCE', 'NULLIF', 'IFNULL',

            'COUNT', 'SUM', 'AVG', 'MIN', 'MAX', 'STDDEV', 'VARIANCE',

            'ABS', 'ROUND', 'CEIL', 'FLOOR', 'POWER', 'SQRT', 'SIN', 'COS', 'TAN',
            'LOG', 'EXP', 'LN', 'MOD', 'GREATEST', 'LEAST',

            'CONCAT', 'SUBSTRING', 'SUBSTR', 'LENGTH', 'LEN', 'UPPER', 'LOWER',
            'TRIM', 'LTRIM', 'RTRIM', 'REPLACE', 'REGEXP_REPLACE',

            'NOW', 'CURRENT_DATE', 'CURRENT_TIME', 'CURRENT_TIMESTAMP',
            'DATE', 'TIME', 'YEAR', 'MONTH', 'DAY', 'HOUR', 'MINUTE', 'SECOND',
            'DATE_ADD', 'DATE_SUB', 'DATEDIFF', 'TIMESTAMPDIFF',

            'ROW_NUMBER', 'RANK', 'DENSE_RANK', 'NTILE', 'LAG', 'LEAD',
            'FIRST_VALUE', 'LAST_VALUE', 'NTH_VALUE',

            'JSON_EXTRACT', 'JSON_VALUE', 'JSON_QUERY', 'JSON_MODIFY',

            'TABLE', 'INDEX', 'VIEW', 'PROCEDURE', 'FUNCTION', 'TRIGGER',
            'CONSTRAINT', 'PRIMARY', 'KEY', 'FOREIGN', 'REFERENCES', 'UNIQUE',
            'CHECK', 'DEFAULT', 'AUTO_INCREMENT', 'IDENTITY',

            'BEGIN', 'COMMIT', 'ROLLBACK', 'SAVEPOINT', 'TRANSACTION',

            'GRANT', 'REVOKE', 'PRIVILEGES',

            'DATABASE', 'SCHEMA', 'USE', 'SHOW', 'DESCRIBE', 'EXPLAIN', 'ANALYZE'
        }

        self.table_schemas = {
            'departments': ['id', 'name', 'location', 'budget', 'created_at'],
            'employees': ['id', 'name', 'email', 'department_id', 'salary', 'hire_date'],
            'projects': ['id', 'name', 'description', 'start_date', 'end_date', 'budget'],
            'users': ['id', 'username', 'password', 'email', 'created_at']
        }

        self.table_relationships = {
            'employees': {
                'departments': {'foreign_key': 'department_id', 'primary_key': 'id', 'type': 'many_to_one'}
            },
            'projects': {
                'departments': {'foreign_key': 'department_id', 'primary_key': 'id', 'type': 'many_to_one'}
            }
        }

        self.query_patterns = {
            'cte': r'^\s*WITH\s+\w+\s+AS\s*\(',
            'subquery': r'SELECT.*\([^)]*SELECT.*\)',
            'complex_join': r'\bJOIN\b',  # Any JOIN is considered complex for now
            'window_function': r'\w+\(\)\s+OVER\s*\(',
            'recursive': r'WITH\s+RECURSIVE',
            'pivot': r'PIVOT|UNPIVOT',
            'json_query': r'JSON_',
            'stored_procedure': r'CALL|EXEC|EXECUTE'
        }

        self.table_mappings: Dict[str, TableMapping] = {}

        self.database_schemas: Dict[str, Dict[str, Any]] = {}

        self.query_history: List[Dict[str, Any]] = []

        self.encrypted_schemas: Dict[str, Any] = {}
        self.schema_encryption_enabled = True

        self._load_mappings_from_files()
        self._load_schemas_from_files()
        self._load_encrypted_schemas()

        self.common_mistakes = {
            r'\bselect\s+\*\s+from\s+(\w+)\s+where\s+(\w+)\s*=\s*([^\'"\s]+)(?!\s*[\'"])':  # Missing quotes
                lambda m: f"SELECT * FROM {m.group(1)} WHERE {m.group(2)} = '{m.group(3)}'",
            r'\bselect\s+(\w+)\s+from\s+(\w+)\s+where\s+(\w+)\s*=\s*(\w+)':  # Column comparison without quotes
                lambda m: f"SELECT {m.group(1)} FROM {m.group(2)} WHERE {m.group(3)} = '{m.group(4)}'",
            r'\binsert\s+into\s+(\w+)\s*\(\s*([^)]+)\s*\)\s*values\s*\(\s*([^)]+)\s*\)':  # INSERT format
                lambda m: f"INSERT INTO {m.group(1)} ({m.group(2)}) VALUES ({m.group(3)})",
        }

        self.insert_corrections = [
            (r'\bINSERT\s+INTO\s+(\w+)\s*\(\s*([^)]+)\s*\)\s*VALUES\s*\(\s*([^)]+)\s*\)',
             self._correct_insert_quotes),
        ]

    def _load_mappings_from_files(self):
        """Load table mappings from schema files"""
        try:
            import os
            from pathlib import Path
            import json

            schemas_dir = Path("schemas")
            schemas_dir.mkdir(exist_ok=True)
            if not schemas_dir.exists():
                logger.warning("No schemas directory found. Please run migration first to generate schema files.")
                self.table_mappings = {}
                return

            mapping_files = list(schemas_dir.glob("*_mappings.json"))
            if not mapping_files:
                logger.warning("No mapping files found in schemas directory. Please run migration first to generate schema files.")
                self.table_mappings = {}
                return

            latest_mapping = max(mapping_files, key=lambda f: f.stat().st_mtime)

            with open(latest_mapping, 'r') as f:
                mapping_data = json.load(f)

            table_mappings_data = mapping_data.get("table_mappings", {})

            self.table_mappings = {}
            for table_name, table_data in table_mappings_data.items():
                encrypted_columns = {}
                for col_name, col_data in table_data.get("encrypted_columns", {}).items():
                    encrypted_columns[col_name] = ColumnMapping(
                        original_name=col_data["original_name"],
                        encrypted_name=col_data["encrypted_name"],
                        tag_name=col_data["tag_name"],
                        is_encrypted=col_data["is_encrypted"],
                        is_hashed=col_data["is_hashed"],
                        data_type=col_data["data_type"],
                        supports_ordering=col_data.get("supports_ordering", True),
                        supports_ranges=col_data.get("supports_ranges", True)
                    )

                self.table_mappings[table_name] = TableMapping(
                    original_name=table_data["original_name"],
                    encrypted_columns=encrypted_columns,
                    primary_key=table_data.get("primary_key", "id"),
                    non_encrypted_columns=table_data.get("non_encrypted_columns", [])
                )

            logger.info(f"Loaded {len(self.table_mappings)} table mappings from {latest_mapping}")

        except Exception as e:
            logger.error(f"Failed to load mappings from files: {e}")
            logger.warning("Unable to load table mappings. Please ensure schema files exist and are valid.")
            self.table_mappings = {}

    def _load_schemas_from_files(self):
        """Load complete database schemas from JSON files"""
        try:
            import os
            from pathlib import Path
            import json

            schemas_dir = Path("schemas")
            schemas_dir.mkdir(exist_ok=True)
            if not schemas_dir.exists():
                logger.warning("No schemas directory found. Please run migration first to generate schema files.")
                self.database_schemas = {}
                return

            schema_files = list(schemas_dir.glob("*_schema.json"))
            if not schema_files:
                logger.warning("No schema files found in schemas directory. Please run migration first to generate schema files.")
                self.database_schemas = {}
                return

            for schema_file in schema_files:
                try:
                    with open(schema_file, 'r') as f:
                        schema_data = json.load(f)

                    filename = schema_file.name
                    if "_source_schema.json" in filename:
                        db_type = "source"
                    elif "_encrypted_schema.json" in filename:
                        db_type = "encrypted"
                    else:
                        db_type = "unknown"

                    self.database_schemas[db_type] = schema_data

                    logger.info(f"Loaded {db_type} schema from {schema_file}")

                except Exception as e:
                    logger.warning(f"Failed to load schema from {schema_file}: {e}")

            self._update_table_schemas_from_complete_schema()

        except Exception as e:
            logger.error(f"Failed to load schemas from files: {e}")
            logger.warning("Unable to load database schemas. Please ensure schema files exist and are valid.")
            self.database_schemas = {}

    def _load_encrypted_schemas(self):
        """Load encrypted schemas from schema encryption service"""
        try:
            import os
            from pathlib import Path

            schemas_dir = Path("schemas")
            schemas_dir.mkdir(exist_ok=True)

            encrypted_schema_files = list(schemas_dir.glob("*_encrypted_schema.json"))
            for schema_file in encrypted_schema_files:
                try:
                    encrypted_schema = schema_encryption_service.load_encrypted_schema(str(schema_file))

                    decrypted_schema = schema_encryption_service.decrypt_schema(encrypted_schema)
                    self.encrypted_schemas[encrypted_schema.database_name] = {
                        'encrypted': encrypted_schema,
                        'decrypted': decrypted_schema,
                        'metadata': {
                            'encryption_level': encrypted_schema.encryption_level.value,
                            'created_at': encrypted_schema.created_at,
                            'version': encrypted_schema.version
                        }
                    }

                    logger.info(f"Loaded and decrypted encrypted schema for {encrypted_schema.database_name}")

                except Exception as e:
                    logger.warning(f"Failed to load encrypted schema from {schema_file}: {e}")

        except Exception as e:
            logger.error(f"Failed to load encrypted schemas: {e}")

    def _update_table_schemas_from_complete_schema(self):
        """Update table_schemas with complete information from loaded schemas"""
        if "encrypted" in self.database_schemas:
            encrypted_schema = self.database_schemas["encrypted"]
            for table_name, table_info in encrypted_schema.get("tables", {}).items():
                if table_name in table_info and "columns" in table_info:
                    self.table_schemas[table_name] = []
                    for col_info in table_info["columns"]:
                        self.table_schemas[table_name].append(col_info["name"])

        self._update_table_relationships_from_schema()

    def _update_table_relationships_from_schema(self):
        """Update table relationships from schema foreign key information"""
        self.table_relationships = {}

        if "encrypted" in self.database_schemas:
            encrypted_schema = self.database_schemas["encrypted"]

            for table_name, table_info in encrypted_schema.get("tables", {}).items():
                foreign_keys = table_info.get("foreign_keys", [])
                if foreign_keys:
                    self.table_relationships[table_name] = {}

                    for fk_info in foreign_keys:
                        try:
                            constrained_columns = fk_info.get("constrained_columns", [])
                            referred_table = fk_info.get("referred_table")
                            referred_columns = fk_info.get("referred_columns", [])

                            if constrained_columns and referred_table and referred_columns:
                                fk_col = constrained_columns[0]  # Take first FK column
                                pk_col = referred_columns[0]    # Take first PK column

                                self.table_relationships[table_name][referred_table] = {
                                    'foreign_key': fk_col,
                                    'primary_key': pk_col,
                                    'type': 'many_to_one'
                                }

                                if referred_table not in self.table_relationships:
                                    self.table_relationships[referred_table] = {}
                                if table_name not in self.table_relationships[referred_table]:
                                    self.table_relationships[referred_table][table_name] = {
                                        'foreign_key': pk_col,
                                        'primary_key': fk_col,
                                        'type': 'one_to_many'
                                    }

                        except Exception as e:
                            logger.warning(f"Error processing foreign key for table {table_name}: {e}")

    def get_table_schema_info(self, table_name: str) -> Dict[str, Any]:
        """Get complete schema information for a table"""
        if "encrypted" in self.database_schemas:
            encrypted_schema = self.database_schemas["encrypted"]
            return encrypted_schema.get("tables", {}).get(table_name, {})
        return {}

    def get_column_info(self, table_name: str, column_name: str) -> Dict[str, Any]:
        """Get detailed information about a specific column"""
        table_info = self.get_table_schema_info(table_name)
        columns = table_info.get("columns", [])

        for col_info in columns:
            if col_info.get("name") == column_name:
                return col_info

        return {}

    def is_auto_increment_column(self, table_name: str, column_name: str) -> bool:
        """Check if a column is auto-increment"""
        col_info = self.get_column_info(table_name, column_name)
        return col_info.get("autoincrement", False)

    def get_primary_keys(self, table_name: str) -> List[str]:
        """Get primary key columns for a table"""
        table_info = self.get_table_schema_info(table_name)
        return table_info.get("primary_keys", [])

    def get_foreign_keys(self, table_name: str) -> List[Dict[str, Any]]:
        """Get foreign key information for a table"""
        table_info = self.get_table_schema_info(table_name)
        return table_info.get("foreign_keys", [])

    def get_column_type(self, table_name: str, column_name: str) -> str:
        """Get the data type of a column"""
        col_info = self.get_column_info(table_name, column_name)
        return col_info.get("type", "TEXT")

    def is_nullable_column(self, table_name: str, column_name: str) -> bool:
        """Check if a column is nullable"""
        col_info = self.get_column_info(table_name, column_name)
        return col_info.get("nullable", True)

    def register_table_mapping(self, table_name: str, mapping: TableMapping):
        """Register a table mapping"""
        self.table_mappings[table_name] = mapping
        logger.info(f"Registered AI table mapping for {table_name}")

    def _detect_database_type(self, schema_data: Dict[str, Any], database_name: str) -> str:
        """
        Detect the database type from schema data or database name

        Args:
            schema_data: Schema data to analyze
            database_name: Name of the database

        Returns:
            Database type string ("postgresql", "mysql", "sqlite", etc.)
        """
        try:
            db_name_lower = database_name.lower()

            if "postgres" in db_name_lower or "pg" in db_name_lower:
                return "postgresql"
            elif "mysql" in db_name_lower or "mariadb" in db_name_lower:
                return "mysql"
            elif "sqlite" in db_name_lower:
                return "sqlite"
            elif "mssql" in db_name_lower or "sqlserver" in db_name_lower:
                return "mssql"

            if schema_data:
                tables = schema_data.get('tables', {})

                for table_info in tables.values():
                    columns = table_info.get('columns', [])

                    for col in columns:
                        if isinstance(col, dict):
                            col_type = str(col.get('type', '')).upper()
                            if 'BYTEA' in col_type:
                                return "postgresql"

                    for col in columns:
                        if isinstance(col, dict):
                            col_type = str(col.get('type', ''))
                            if col_type.endswith('[]'):
                                return "postgresql"

                    for col in columns:
                        if isinstance(col, dict):
                            col_type = str(col.get('type', '')).upper()
                            if col_type in ['JSON', 'JSONB']:
                                return "postgresql"

            return "mysql"

        except Exception as e:
            logger.warning(f"Error detecting database type: {e}")
            return "mysql"  # Safe default

    def encrypt_database_schema(self, database_name: str, schema_data: Dict[str, Any], encryption_level: str = "ai_enhanced") -> Dict[str, Any]:
        """
        Encrypt an entire database schema using schema-level encryption

        Args:
            database_name: Name of the database
            schema_data: Schema data to encrypt
            encryption_level: Level of encryption ("basic", "full", "ai_enhanced")

        Returns:
            Dict containing encryption results and metadata
        """
        try:
            level_map = {
                "basic": SchemaEncryptionLevel.BASIC,
                "full": SchemaEncryptionLevel.FULL,
                "ai_enhanced": SchemaEncryptionLevel.AI_ENHANCED,
                "none": SchemaEncryptionLevel.NONE
            }

            level = level_map.get(encryption_level.lower(), SchemaEncryptionLevel.AI_ENHANCED)

            database_type = self._detect_database_type(schema_data, database_name)

            if database_type == "postgresql":
                encrypted_schema = schema_encryption_service.encrypt_postgresql_schema(
                    schema_data, database_name, level
                )
            else:
                encrypted_schema = schema_encryption_service.encrypt_schema(
                    schema_data, database_name, level
                )

            file_path = f"schemas/{database_name}_encrypted_schema.json"
            schema_encryption_service.save_encrypted_schema(encrypted_schema, file_path)

            if database_type == "postgresql":
                decrypted_schema = schema_encryption_service.decrypt_postgresql_schema(encrypted_schema)
            else:
                decrypted_schema = schema_encryption_service.decrypt_schema(encrypted_schema)
            self.encrypted_schemas[database_name] = {
                'encrypted': encrypted_schema,
                'decrypted': decrypted_schema,
                'metadata': {
                    'encryption_level': encrypted_schema.encryption_level.value,
                    'created_at': encrypted_schema.created_at,
                    'version': encrypted_schema.version
                }
            }

            result = {
                "success": True,
                "database_name": database_name,
                "database_type": database_type,
                "encryption_level": encryption_level,
                "file_path": file_path,
                "metadata": {
                    "table_count": len(encrypted_schema.tables),
                    "encryption_level": encrypted_schema.encryption_level.value,
                    "created_at": encrypted_schema.created_at,
                    "database_type": database_type,
                    "ai_context_available": bool(encrypted_schema.ai_context)
                },
                "ai_context": encrypted_schema.ai_context
            }

            logger.info(f"Successfully encrypted schema for database: {database_name}")
            return result

        except Exception as e:
            logger.error(f"Failed to encrypt schema for {database_name}: {e}")
            return {
                "success": False,
                "error": str(e),
                "database_name": database_name
            }

    def decrypt_database_schema(self, database_name: str) -> Dict[str, Any]:
        """
        Decrypt a database schema

        Args:
            database_name: Name of the database

        Returns:
            Dict containing decrypted schema and metadata
        """
        try:
            if database_name not in self.encrypted_schemas:
                return {
                    "success": False,
                    "error": f"No encrypted schema found for database: {database_name}"
                }

            encrypted_schema = self.encrypted_schemas[database_name]['encrypted']
            decrypted_schema = schema_encryption_service.decrypt_schema(encrypted_schema)

            result = {
                "success": True,
                "database_name": database_name,
                "schema": decrypted_schema,
                "metadata": self.encrypted_schemas[database_name]['metadata'],
                "table_count": len(decrypted_schema.get('tables', {})),
                "ai_context": decrypted_schema.get('ai_context', {})
            }

            logger.info(f"Successfully decrypted schema for database: {database_name}")
            return result

        except Exception as e:
            logger.error(f"Failed to decrypt schema for {database_name}: {e}")
            return {
                "success": False,
                "error": str(e),
                "database_name": database_name
            }

    def get_schema_insights(self, database_name: str) -> Dict[str, Any]:
        """
        Get AI-powered insights about an encrypted schema

        Args:
            database_name: Name of the database

        Returns:
            Dict containing schema insights and AI analysis
        """
        try:
            if database_name not in self.encrypted_schemas:
                return {
                    "success": False,
                    "error": f"No encrypted schema found for database: {database_name}"
                }

            schema_info = self.encrypted_schemas[database_name]
            encrypted_schema = schema_info['encrypted']
            decrypted_schema = schema_info['decrypted']

            insights = {
                "success": True,
                "database_name": database_name,
                "encryption_level": encrypted_schema.encryption_level.value,
                "table_count": len(encrypted_schema.tables),
                "ai_context": encrypted_schema.ai_context,
                "insights": {
                    "table_types": encrypted_schema.ai_context.get('table_types', {}),
                    "relationships": encrypted_schema.ai_context.get('relationships', []),
                    "data_patterns": encrypted_schema.ai_context.get('data_patterns', {}),
                    "query_patterns": encrypted_schema.ai_context.get('query_patterns', []),
                    "security_level": self._assess_security_level(encrypted_schema),
                    "performance_impact": self._estimate_performance_impact(encrypted_schema),
                    "recommendations": self._generate_schema_recommendations(encrypted_schema)
                }
            }

            return insights

        except Exception as e:
            logger.error(f"Failed to get schema insights for {database_name}: {e}")
            return {
                "success": False,
                "error": str(e),
                "database_name": database_name
            }

    def _assess_security_level(self, encrypted_schema) -> Dict[str, Any]:
        """Assess the security level of an encrypted schema"""
        level = encrypted_schema.encryption_level

        assessments = {
            SchemaEncryptionLevel.NONE: {
                "level": "none",
                "score": 0,
                "description": "No encryption applied",
                "risks": ["Data completely exposed", "No security protection"]
            },
            SchemaEncryptionLevel.BASIC: {
                "level": "basic",
                "score": 6,
                "description": "Basic column name and type encryption",
                "risks": ["Schema structure visible", "Column relationships exposed"]
            },
            SchemaEncryptionLevel.FULL: {
                "level": "full",
                "score": 8,
                "description": "Complete schema structure encryption",
                "risks": ["Higher computational overhead", "Complex key management"]
            },
            SchemaEncryptionLevel.AI_ENHANCED: {
                "level": "ai_enhanced",
                "score": 9,
                "description": "AI-aware encryption with semantic protection",
                "risks": ["Most complex implementation", "AI context exposure risk"]
            }
        }

        return assessments.get(level, assessments[SchemaEncryptionLevel.NONE])

    def _estimate_performance_impact(self, encrypted_schema) -> Dict[str, Any]:
        """Estimate performance impact of schema encryption"""
        level = encrypted_schema.encryption_level
        table_count = len(encrypted_schema.tables)

        impacts = {
            SchemaEncryptionLevel.NONE: {"cpu_overhead": 0, "memory_overhead": 0, "query_latency_increase": 0},
            SchemaEncryptionLevel.BASIC: {"cpu_overhead": 5, "memory_overhead": 10, "query_latency_increase": 2},
            SchemaEncryptionLevel.FULL: {"cpu_overhead": 15, "memory_overhead": 25, "query_latency_increase": 8},
            SchemaEncryptionLevel.AI_ENHANCED: {"cpu_overhead": 20, "memory_overhead": 30, "query_latency_increase": 12}
        }

        base_impact = impacts.get(level, impacts[SchemaEncryptionLevel.NONE])

        scale_factor = min(table_count / 10, 3)  # Cap at 3x for very large schemas

        return {
            "cpu_overhead_percent": base_impact["cpu_overhead"] * (1 + scale_factor),
            "memory_overhead_percent": base_impact["memory_overhead"] * (1 + scale_factor),
            "estimated_query_latency_increase_ms": base_impact["query_latency_increase"] * (1 + scale_factor),
            "recommendations": self._get_performance_recommendations(level, table_count)
        }

    def _generate_schema_recommendations(self, encrypted_schema) -> List[str]:
        """Generate recommendations for schema encryption"""
        recommendations = []
        level = encrypted_schema.encryption_level
        table_count = len(encrypted_schema.tables)

        if level == SchemaEncryptionLevel.NONE:
            recommendations.append("Consider enabling schema encryption for better security")
            recommendations.append("Start with BASIC encryption level for minimal performance impact")

        if level == SchemaEncryptionLevel.BASIC:
            recommendations.append("Consider upgrading to FULL encryption for complete schema protection")
            recommendations.append("AI_ENHANCED level provides intelligent query optimization")

        if table_count > 50:
            recommendations.append("Large schema detected - consider partitioning for better performance")
            recommendations.append("Implement schema caching to reduce decryption overhead")

        if encrypted_schema.ai_context:
            ai_insights = encrypted_schema.ai_context
            if ai_insights.get('relationships'):
                recommendations.append(f"Schema has {len(ai_insights['relationships'])} relationships - ensure foreign key encryption is consistent")

        return recommendations

    def _get_performance_recommendations(self, level: SchemaEncryptionLevel, table_count: int) -> List[str]:
        """Get performance recommendations based on encryption level and schema size"""
        recommendations = []

        if level in [SchemaEncryptionLevel.FULL, SchemaEncryptionLevel.AI_ENHANCED]:
            recommendations.append("Implement schema caching to reduce decryption overhead")
            recommendations.append("Consider query result caching for frequently accessed data")

        if table_count > 20:
            recommendations.append("Large schema - consider lazy loading of table definitions")
            recommendations.append("Implement connection pooling for better performance")

        if level == SchemaEncryptionLevel.AI_ENHANCED:
            recommendations.append("AI-enhanced encryption provides better query optimization")
            recommendations.append("Monitor AI context size for memory usage")

        return recommendations

    def query_with_schema_awareness(self, query: str, database_name: str = None) -> Dict[str, Any]:
        """
        Execute a query with schema-level awareness and AI optimization

        Args:
            query: SQL query to execute
            database_name: Target database name

        Returns:
            Dict containing query results and schema-aware insights
        """
        try:
            if not database_name:
                database_name = self._extract_database_from_query(query)

            schema_info = None
            if database_name and database_name in self.encrypted_schemas:
                schema_info = self.encrypted_schemas[database_name]

            analysis = self._analyze_query_with_schema_context(query, schema_info)

            suggestions = self._generate_schema_aware_suggestions(query, schema_info)

            result = {
                "success": True,
                "query": query,
                "database_name": database_name,
                "schema_analysis": analysis,
                "suggestions": suggestions,
                "ai_insights": {
                    "query_complexity": analysis.get('complexity', 'unknown'),
                    "security_implications": analysis.get('security_notes', []),
                    "performance_considerations": analysis.get('performance_notes', [])
                }
            }

            return result

        except Exception as e:
            logger.error(f"Schema-aware query failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "query": query
            }

    def _extract_database_from_query(self, query: str) -> Optional[str]:
        """Extract database name from query (if specified)"""
        if self.encrypted_schemas:
            return next(iter(self.encrypted_schemas.keys()))
        return None

    def _analyze_query_with_schema_context(self, query: str, schema_info) -> Dict[str, Any]:
        """Analyze query in the context of encrypted schema"""
        analysis = {
            "complexity": "simple",
            "security_notes": [],
            "performance_notes": [],
            "encryption_impact": "none"
        }

        if not schema_info:
            analysis["security_notes"].append("No encrypted schema context available")
            return analysis

        encrypted_schema = schema_info['encrypted']

        query_upper = query.upper()
        if 'JOIN' in query_upper:
            analysis["complexity"] = "high"
        elif 'UNION' in query_upper or 'WITH' in query_upper:
            analysis["complexity"] = "medium"
        else:
            analysis["complexity"] = "simple"

        if encrypted_schema.encryption_level != SchemaEncryptionLevel.NONE:
            analysis["encryption_impact"] = encrypted_schema.encryption_level.value
            analysis["security_notes"].append(f"Query operates on {encrypted_schema.encryption_level.value} encrypted schema")

        if encrypted_schema.encryption_level in [SchemaEncryptionLevel.FULL, SchemaEncryptionLevel.AI_ENHANCED]:
            analysis["performance_notes"].append("Full schema encryption may impact query performance")
            analysis["performance_notes"].append("Consider schema caching for frequently accessed tables")

        if encrypted_schema.ai_context:
            ai_context = encrypted_schema.ai_context
            table_count = ai_context.get('table_count', 0)
            if table_count > 20:
                analysis["performance_notes"].append(f"Large schema ({table_count} tables) - optimize query patterns")

        return analysis

    def _generate_schema_aware_suggestions(self, query: str, schema_info) -> List[Dict[str, Any]]:
        """Generate schema-aware query suggestions"""
        suggestions = []

        if not schema_info:
            return suggestions

        encrypted_schema = schema_info['encrypted']

        if encrypted_schema.encryption_level == SchemaEncryptionLevel.AI_ENHANCED:
            ai_context = encrypted_schema.ai_context

            relationships = ai_context.get('relationships', [])
            if relationships:
                suggestions.append({
                    "type": "relationship_join",
                    "description": f"Schema has {len(relationships)} table relationships - consider JOIN queries",
                    "example": "SELECT * FROM table1 JOIN table2 ON table1.fk = table2.pk"
                })

            query_patterns = ai_context.get('query_patterns', [])
            if query_patterns:
                suggestions.append({
                    "type": "common_patterns",
                    "description": f"Schema supports {len(query_patterns)} common query patterns",
                    "patterns": query_patterns[:3]  # Show first 3
                })

        if encrypted_schema.encryption_level != SchemaEncryptionLevel.NONE:
            suggestions.append({
                "type": "security_reminder",
                "description": "Query operates on encrypted data - results will be automatically decrypted",
                "security_level": encrypted_schema.encryption_level.value
            })

        return suggestions

    def import_schemas_mapping(self) -> Dict[str, Any]:
        """
        Manually import/reload schemas and mappings from files

        Returns:
            Dict containing import status and statistics
        """
        try:
            logger.info("Manually importing schemas and mappings from files")

            self.table_mappings = {}
            self.database_schemas = {}

            self._load_mappings_from_files()
            self._load_schemas_from_files()

            self._update_table_schemas_from_complete_schema()
            self._update_table_relationships_from_schema()

            mapping_count = len(self.table_mappings)
            schema_count = len(self.database_schemas)
            table_count = len(self.table_schemas)

            encrypted_columns = 0
            for table_mapping in self.table_mappings.values():
                encrypted_columns += len(table_mapping.encrypted_columns)

            result = {
                "success": True,
                "message": f"Successfully imported schemas and mappings",
                "statistics": {
                    "table_mappings_loaded": mapping_count,
                    "database_schemas_loaded": schema_count,
                    "tables_with_schemas": table_count,
                    "encrypted_columns_total": encrypted_columns,
                    "table_relationships": len(self.table_relationships)
                },
                "loaded_tables": list(self.table_mappings.keys()),
                "available_schemas": list(self.database_schemas.keys())
            }

            logger.info(f"Import completed: {mapping_count} mappings, {schema_count} schemas, {table_count} tables")
            return result

        except Exception as e:
            error_msg = f"Failed to import schemas and mappings: {str(e)}"
            logger.error(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "statistics": {
                    "table_mappings_loaded": 0,
                    "database_schemas_loaded": 0,
                    "tables_with_schemas": 0,
                    "encrypted_columns_total": 0,
                    "table_relationships": 0
                }
            }

    def _correct_insert_quotes(self, match):
        """Correct unquoted string literals in INSERT VALUES clauses"""
        table_name = match.group(1)
        columns_part = match.group(2)
        values_part = match.group(3)

        if values_part.startswith('(') and values_part.endswith(')'):
            values_content = values_part[1:-1]
        else:
            values_content = values_part

        corrected_values = self._add_quotes_to_values(values_content)

        return f"INSERT INTO {table_name} ({columns_part}) VALUES ({corrected_values})"

    def _add_quotes_to_values(self, values_str: str) -> str:
        """Add quotes around unquoted string literals in VALUES clause"""
        parts = []
        current_part = ""
        in_string = False
        string_char = None

        i = 0
        while i < len(values_str):
            char = values_str[i]

            if not in_string and (char == '"' or char == "'"):
                in_string = True
                string_char = char
                current_part += char
            elif in_string and char == string_char:
                if i + 1 < len(values_str) and values_str[i + 1] == string_char:
                    current_part += char + char
                    i += 1
                else:
                    in_string = False
                    current_part += char
            elif not in_string and char == ',':
                parts.append(current_part.strip())
                current_part = ""
            else:
                current_part += char

            i += 1

        if current_part.strip():
            parts.append(current_part.strip())

        corrected_parts = []
        for part in parts:
            part = part.strip()
            if not ((part.startswith("'") and part.endswith("'")) or
                    (part.startswith('"') and part.endswith('"')) or
                    part.upper() in ('NULL', 'DEFAULT') or
                    self._is_numeric(part)):
                part = f"'{part}'"
            corrected_parts.append(part)

        return ', '.join(corrected_parts)

    def _is_numeric(self, value: str) -> bool:
        """Check if a value is numeric"""
        try:
            float(value)
            return True
        except ValueError:
            return False

    def translate_query(self, query: str, table_name: str = None) -> Tuple[str, Dict[str, Any]]:
        """
        Translate a user query to work with encrypted database

        Args:
            query: The original SQL query
            table_name: Optional table name hint

        Returns:
            Tuple of (translated_query, metadata)
        """
        try:
            original_query = query
            for pattern, correction_func in self.insert_corrections:
                match = re.search(pattern, query, re.IGNORECASE | re.DOTALL)
                if match:
                    query = correction_func(match)
                    break

            query_upper = query.upper().strip()

            self._add_to_query_history(original_query, 'translate')

            complexity = self._analyze_query_complexity(query)

            if not table_name:
                table_name = self._extract_table_name(query)

            if complexity['has_cte']:
                return self._translate_cte_query(query)
            elif complexity['has_subquery']:
                return self._translate_subquery_query(query)
            elif complexity['has_complex_join']:
                return self._translate_complex_join_query(query)

            if not table_name or table_name not in self.table_mappings:
                return query, {
                    'query_type': self._determine_query_type(query),
                    'table_name': table_name,
                    'translated': False,
                    'complexity': complexity
                }

            table_mapping = self.table_mappings[table_name]

            if query_upper.startswith('SELECT'):
                return self._translate_select_query(query, table_mapping)
            elif query_upper.startswith('INSERT'):
                return self._translate_insert_query(query, table_mapping)
            elif query_upper.startswith('UPDATE'):
                return self._translate_update_query(query, table_mapping)
            elif query_upper.startswith('DELETE'):
                return self._translate_delete_query(query, table_mapping)
            elif query_upper.startswith('CREATE'):
                return self._translate_ddl_query(query)
            elif query_upper.startswith('WITH'):
                return self._translate_cte_query(query)
            else:
                return query, {
                    'query_type': self._determine_query_type(query),
                    'table_name': table_name,
                    'translated': False,
                    'complexity': complexity
                }

        except Exception as e:
            logger.error(f"Error translating query: {e}")
            return query, {
                'error': f"Translation failed: {str(e)}",
                'query_type': 'UNKNOWN',
                'translated': False
            }

    def _extract_table_name(self, query: str) -> Optional[str]:
        """Extract table name from query"""
        query_upper = query.upper()

        patterns = [
            r'FROM\s+(\w+)',
            r'INTO\s+(\w+)',
            r'UPDATE\s+(\w+)',
            r'TABLE\s+(\w+)'
        ]

        for pattern in patterns:
            match = re.search(pattern, query_upper, re.IGNORECASE)
            if match:
                table_name = match.group(1).lower()
                if table_name in self.table_schemas:
                    return table_name
                else:
                    return table_name  # Return the table name even if not in schemas

        logger.debug("No table name extracted")
        return None

    def _determine_query_type(self, query: str) -> str:
        """Determine the type of SQL query"""
        query_upper = query.upper().strip()

        if query_upper.startswith('SELECT'):
            return 'SELECT'
        elif query_upper.startswith('INSERT'):
            return 'INSERT'
        elif query_upper.startswith('UPDATE'):
            return 'UPDATE'
        elif query_upper.startswith('DELETE'):
            return 'DELETE'
        else:
            return 'UNKNOWN'

    def _translate_select_query(self, query: str, table_mapping: TableMapping) -> Tuple[str, Dict[str, Any]]:
        """Translate SELECT query for encrypted columns with deterministic encryption"""
        try:
            select_pattern = r'SELECT\s+(.+?)\s+FROM\s+([\w\s]+)(?:\s+WHERE\s+(.+?))?(?:\s+GROUP\s+BY\s+(.+?))?(?:\s+ORDER\s+BY\s+(.+?))?(?:\s+LIMIT\s+(\d+))?(?:\s+OFFSET\s+(\d+))?$'
            match = re.match(select_pattern, query, re.IGNORECASE | re.DOTALL)

            if not match:
                return query, {
                    'query_type': 'SELECT',
                    'table_name': table_mapping.original_name,
                    'translated': False,
                    'error': 'Could not parse SELECT query'
                }

            select_clause, table_name, where_clause, group_clause, order_clause, limit_clause, offset_clause = match.groups()

            translated_parts = [f"SELECT {select_clause} FROM {table_name}"]

            if where_clause:
                translated_where = self._translate_where_clause(where_clause.strip(), table_mapping)
                if translated_where:
                    translated_parts.append(f"WHERE {translated_where}")

            if group_clause:
                translated_parts.append(f"GROUP BY {group_clause.strip()}")

            if order_clause:
                translated_order = self._translate_order_clause(order_clause.strip(), table_mapping)
                if translated_order:
                    translated_parts.append(f"ORDER BY {translated_order}")

            if limit_clause:
                translated_parts.append(f"LIMIT {limit_clause}")
            if offset_clause:
                translated_parts.append(f"OFFSET {offset_clause}")

            translated_query = ' '.join(translated_parts)

            metadata = {
                'query_type': 'SELECT',
                'table_name': table_mapping.original_name,
                'translated': True,
                'encrypted_columns': list(table_mapping.encrypted_columns.keys()),
                'tag_columns': [col.tag_name for col in table_mapping.encrypted_columns.values()],
                'has_where': bool(where_clause),
                'has_group': bool(group_clause),
                'has_order': bool(order_clause),
                'has_limit': bool(limit_clause)
            }

            return translated_query, metadata

        except Exception as e:
            logger.error(f"Error translating SELECT query: {e}")
            return query, {
                'query_type': 'SELECT',
                'table_name': table_mapping.original_name,
                'translated': False,
                'error': str(e)
            }

    def _translate_insert_query(self, query: str, table_mapping: TableMapping) -> Tuple[str, Dict[str, Any]]:
        """Translate INSERT query for encrypted columns with schema-aware auto-increment handling"""
        try:
            insert_pattern = r'INSERT\s+INTO\s+(\w+)\s*\(\s*([^)]+)\s*\)\s*VALUES\s*(.+)$'
            match = re.match(insert_pattern, query, re.IGNORECASE | re.DOTALL)

            if not match:
                return query, {
                    'query_type': 'INSERT',
                    'table_name': table_mapping.original_name,
                    'translated': False,
                    'error': 'Could not parse INSERT query'
                }

            table_name, columns_str, values_part = match.groups()

            values_part = values_part.rstrip(';').strip()

            columns = [col.strip() for col in columns_str.split(',')]

            values_clauses = []
            current_clause = ""
            paren_depth = 0
            in_string = False
            string_char = None

            i = 0
            while i < len(values_part):
                char = values_part[i]

                if not in_string and (char == '"' or char == "'"):
                    in_string = True
                    string_char = char
                    current_clause += char  # Add the opening quote
                elif in_string and char == string_char:
                    if i + 1 < len(values_part) and values_part[i + 1] == string_char:
                        current_clause += char + char
                        i += 1  # Skip escaped quote
                    else:
                        in_string = False
                        current_clause += char  # Add the closing quote
                elif not in_string:
                    if char == '(':
                        paren_depth += 1
                        if paren_depth == 1:
                            current_clause = "("
                        else:
                            current_clause += char
                    elif char == ')':
                        paren_depth -= 1
                        current_clause += char
                        if paren_depth == 0:
                            values_clauses.append(current_clause.strip())
                            current_clause = ""
                    elif paren_depth > 0:
                        current_clause += char
                else:
                    current_clause += char

                i += 1

            cleaned_values_clauses = []
            for clause in values_clauses:
                if clause.startswith('(') and clause.endswith(')'):
                    cleaned_clause = clause[1:-1].strip()
                    cleaned_values_clauses.append(cleaned_clause)

            if not cleaned_values_clauses:
                return query, {
                    'query_type': 'INSERT',
                    'table_name': table_mapping.original_name,
                    'translated': False,
                    'error': 'No VALUES clauses found'
                }

            for i, clause in enumerate(cleaned_values_clauses):
                values = self._parse_values_list(clause)
                if len(values) != len(columns):
                    return query, {
                        'query_type': 'INSERT',
                        'table_name': table_mapping.original_name,
                        'translated': False,
                        'error': f'VALUES clause {i+1} has {len(values)} values but {len(columns)} columns expected'
                    }

            primary_keys = self.get_primary_keys(table_name)

            final_columns = []

            for col in columns:
                col = col.strip()
                if col in table_mapping.encrypted_columns:
                    final_columns.append(col)
                    final_columns.append(table_mapping.encrypted_columns[col].tag_name)
                else:
                    if col in primary_keys and self.is_auto_increment_column(table_name, col):
                        skip_pk = True
                        for clause in cleaned_values_clauses:
                            values = self._parse_values_list(clause)
                            col_idx = columns.index(col)
                            val = values[col_idx]
                            if not (val.upper() in ('NULL', 'DEFAULT', '') or val.strip("'\"") in ('', 'NULL')):
                                skip_pk = False
                                break
                        if not skip_pk:
                            final_columns.append(col)
                    else:
                        final_columns.append(col)

            final_values_clauses = []

            for clause in cleaned_values_clauses:
                values = self._parse_values_list(clause)
                final_values = []

                for i, (col, val) in enumerate(zip(columns, values)):
                    col = col.strip()
                    val = val.strip()

                    if col in table_mapping.encrypted_columns:
                        col_mapping = table_mapping.encrypted_columns[col]

                        if col in primary_keys and self.is_auto_increment_column(table_name, col):
                            if val.upper() in ('NULL', 'DEFAULT', '') or val.strip("'\"") in ('', 'NULL'):
                                continue  # Skip this column entirely for auto-increment
                            else:
                                final_values.append(val)
                                continue

                        try:
                            if (val.startswith("'") and val.endswith("'")) or (val.startswith('"') and val.endswith('"')):
                                clean_val = val[1:-1]
                            else:
                                clean_val = val

                            str_value = str(clean_val) if clean_val is not None else ''

                            encrypted_blob = clwe_encryptor.encrypt_value(clean_val, settings.CRYPTOPIX_DEFAULT_PASSWORD)
                            final_values.append(f"X'{encrypted_blob.hex()}'")

                            unified_tag = clwe_encryptor.generate_unified_tag(str_value, col_mapping.data_type)
                            final_values.append(f"'{unified_tag}'")

                        except Exception as e:
                            logger.error(f"Failed to encrypt value for column {col}: {e}")
                            final_values.append(val)
                            final_values.append("''")  # Empty tag as fallback
                    else:
                        if col in primary_keys and self.is_auto_increment_column(table_name, col):
                            if val.upper() in ('NULL', 'DEFAULT', '') or val.strip("'\"") in ('', 'NULL'):
                                continue  # Skip for auto-increment
                            else:
                                logger.debug(f"Adding non-encrypted value {repr(val)} for column {col}")
                                final_values.append(val)
                        else:
                            logger.debug(f"Adding non-encrypted value {repr(val)} for column {col}")
                            final_values.append(val)

                final_values_clauses.append(f"({', '.join(final_values)})")

            translated_query = f"INSERT INTO {table_name} ({', '.join(final_columns)}) VALUES {', '.join(final_values_clauses)}"

            metadata = {
                'query_type': 'INSERT',
                'table_name': table_mapping.original_name,
                'translated': True,
                'encrypted_columns': list(table_mapping.encrypted_columns.keys()),
                'original_columns': len(columns),
                'final_columns': len(final_columns),
                'values_clauses': len(final_values_clauses),
                'tags_generated': len([c for c in final_columns if c.startswith('tag_')]),
                'auto_increment_handled': any(self.is_auto_increment_column(table_name, pk) for pk in primary_keys)
            }

            return translated_query, metadata

        except Exception as e:
            logger.error(f"Error translating INSERT query: {e}")
            return query, {
                'query_type': 'INSERT',
                'table_name': table_mapping.original_name,
                'translated': False,
                'error': str(e)
            }

    def _translate_update_query(self, query: str, table_mapping: TableMapping) -> Tuple[str, Dict[str, Any]]:
        """Translate UPDATE query for encrypted columns with deterministic encryption"""
        try:
            update_pattern = r'UPDATE\s+(\w+)\s+SET\s+(.+?)(?:\s+WHERE\s+(.+))?$'
            match = re.match(update_pattern, query, re.IGNORECASE | re.DOTALL)

            if not match:
                return query, {
                    'query_type': 'UPDATE',
                    'table_name': table_mapping.original_name,
                    'translated': False,
                    'error': 'Could not parse UPDATE query'
                }

            table_name, set_clause, where_clause = match.groups()

            set_assignments = []
            for assignment in set_clause.split(','):
                assignment = assignment.strip()
                if '=' in assignment:
                    col, val = assignment.split('=', 1)
                    col = col.strip()
                    val = val.strip()

                    if col in table_mapping.encrypted_columns:
                        col_mapping = table_mapping.encrypted_columns[col]

                        if col == table_mapping.primary_key:
                            set_assignments.append(f"{col} = {val}")
                            continue

                        try:
                            if any(op in val for op in ['+', '-', '*', '/']) and col in val:
                                set_assignments.append(f"{col} = {val}")
                            else:
                                if (val.startswith("'") and val.endswith("'")) or (val.startswith('"') and val.endswith('"')):
                                    clean_val = val[1:-1]
                                else:
                                    clean_val = val

                                str_value = str(clean_val) if clean_val is not None else ''

                                encrypted_blob = clwe_encryptor.encrypt_value(clean_val, settings.CRYPTOPIX_DEFAULT_PASSWORD)
                                set_assignments.append(f"{col} = X'{encrypted_blob.hex()}'")

                                unified_tag = clwe_encryptor.generate_unified_tag(str_value, col_mapping.data_type)
                                set_assignments.append(f"{col_mapping.tag_name} = '{unified_tag}'")

                        except Exception as e:
                            logger.error(f"Failed to encrypt value for column {col}: {e}")
                            set_assignments.append(f"{col} = {val}")
                    else:
                        set_assignments.append(f"{col} = {val}")

            translated_set = ', '.join(set_assignments)

            translated_where = ""
            if where_clause:
                translated_where_clause = self._translate_where_clause(where_clause.strip(), table_mapping)
                if translated_where_clause:
                    translated_where = f" WHERE {translated_where_clause}"

            translated_query = f"UPDATE {table_name} SET {translated_set}{translated_where}"

            metadata = {
                'query_type': 'UPDATE',
                'table_name': table_mapping.original_name,
                'translated': True,
                'encrypted_columns': list(table_mapping.encrypted_columns.keys()),
                'set_columns': len(set_assignments),
                'has_where': bool(where_clause)
            }

            return translated_query, metadata

        except Exception as e:
            logger.error(f"Error translating UPDATE query: {e}")
            return query, {
                'query_type': 'UPDATE',
                'table_name': table_mapping.original_name,
                'translated': False,
                'error': str(e)
            }

    def _translate_where_clause(self, where_clause: str, table_mapping: TableMapping) -> str:
        """Translate WHERE clause for encrypted columns with deterministic encryption"""
        try:
            conditions = self._parse_where_conditions(where_clause)

            translated_conditions = []
            for condition in conditions:
                translated_condition = self._translate_single_condition(condition.strip(), table_mapping)
                if translated_condition:
                    translated_conditions.append(translated_condition)

            if translated_conditions:
                return ' AND '.join(translated_conditions)
            return ""

        except Exception as e:
            logger.error(f"Error translating WHERE clause: {e}")
            return where_clause

    def _translate_order_clause(self, order_clause: str, table_mapping: TableMapping) -> str:
        """Translate ORDER BY clause for encrypted columns using OPE component"""
        try:
            order_items = [item.strip() for item in order_clause.split(',')]
            translated_items = []

            for item in order_items:
                parts = item.split()
                col_name = parts[0]
                direction = parts[1] if len(parts) > 1 else 'ASC'

                if col_name in table_mapping.encrypted_columns:
                    tag_col = table_mapping.encrypted_columns[col_name].tag_name
                    translated_items.append(f"SUBSTR({tag_col}, 17, 16) {direction}")
                else:
                    translated_items.append(item)

            return ', '.join(translated_items)

        except Exception as e:
            logger.error(f"Error translating ORDER BY clause: {e}")
            return order_clause

    def _parse_where_conditions(self, where_clause: str) -> List[str]:
        """Parse WHERE clause into individual conditions"""
        protected_clause = where_clause

        between_pattern = r'BETWEEN\s+(.+?)\s+AND\s+(.+?)(?=\s*(?:AND|OR|$))'
        between_placeholders = []

        def replace_between(match):
            placeholder = f"__BETWEEN_PLACEHOLDER_{len(between_placeholders)}__"
            between_placeholders.append(match.group(0))
            return placeholder

        protected_clause = re.sub(between_pattern, replace_between, protected_clause, flags=re.IGNORECASE | re.DOTALL)

        conditions = []
        current_condition = ""
        paren_depth = 0
        in_string = False
        string_char = None

        i = 0
        while i < len(protected_clause):
            char = protected_clause[i]

            if not in_string and (char == '"' or char == "'"):
                in_string = True
                string_char = char
                current_condition += char
            elif in_string and char == string_char:
                in_string = False
                current_condition += char
            elif not in_string and char == '(':
                paren_depth += 1
                current_condition += char
            elif not in_string and char == ')':
                paren_depth -= 1
                current_condition += char
            elif not in_string and paren_depth == 0 and protected_clause[i:i+3].upper() in ['AND', ' OR']:
                if current_condition.strip():
                    conditions.append(current_condition.strip())
                while i < len(protected_clause) and protected_clause[i].isspace():
                    i += 1
                if protected_clause[i:i+3].upper() == 'AND':
                    i += 2
                elif protected_clause[i:i+3].upper() == ' OR':
                    i += 2
                while i < len(protected_clause) and protected_clause[i].isspace():
                    i += 1
                current_condition = ""
                continue
            else:
                current_condition += char

            i += 1

        if current_condition.strip():
            conditions.append(current_condition.strip())

        final_conditions = []
        for condition in conditions:
            restored_condition = condition
            for idx, between_clause in enumerate(between_placeholders):
                restored_condition = restored_condition.replace(f"__BETWEEN_PLACEHOLDER_{idx}__", between_clause)
            final_conditions.append(restored_condition)

        return final_conditions

    def _translate_single_condition(self, condition: str, table_mapping: TableMapping) -> str:
        """Translate a single WHERE condition"""
        try:
            condition_upper = condition.upper()

            if ' LIKE ' in condition_upper:
                return self._translate_like_condition(condition, table_mapping)

            if ' BETWEEN ' in condition_upper:
                return self._translate_between_condition(condition, table_mapping)

            if ' IN ' in condition_upper:
                return self._translate_in_condition(condition, table_mapping)

            for op in ['>=', '<=', '!=', '<>', '>', '<', '=']:
                if f' {op} ' in condition_upper or f'{op}' in condition_upper:
                    return self._translate_comparison_condition(condition, op, table_mapping)

            return condition

        except Exception as e:
            logger.error(f"Error translating condition '{condition}': {e}")
            return condition

    def _translate_like_condition(self, condition: str, table_mapping: TableMapping) -> str:
        """Translate LIKE condition using partial match hash component"""
        try:
            like_pattern = r'(\w+)\s+LIKE\s+(.+)'
            match = re.match(like_pattern, condition, re.IGNORECASE)

            if match:
                col_name, pattern = match.groups()
                col_name = col_name.strip()
                pattern = pattern.strip()

                actual_col_name = col_name
                if '.' in col_name:
                    actual_col_name = col_name.split('.')[-1].strip()

                if actual_col_name in table_mapping.encrypted_columns:
                    clean_pattern = pattern.strip("'\"")
                    tag_col = table_mapping.encrypted_columns[actual_col_name].tag_name
                    if '.' in col_name:
                        table_prefix = col_name.rsplit('.', 1)[0]
                        tag_col = f"{table_prefix}.{tag_col}"

                    if clean_pattern.endswith('%') and not any(char in clean_pattern[:-1] for char in ['_', '%', '[']):
                        prefix = clean_pattern[:-1]  # Remove %
                        if prefix:  # Only if there's a prefix to match
                            partial_hash = clwe_encryptor._generate_partial_hash(prefix)
                            prefix_length = len(prefix)
                            hash_length = prefix_length * 2
                            return f"SUBSTR({tag_col}, 33, {hash_length}) = '{partial_hash[:hash_length]}'"
                        else:
                            return "1=1"  # Always true condition
                    else:
                        return f"{tag_col} LIKE {pattern}"

            return condition

        except Exception as e:
            logger.error(f"Error translating LIKE condition: {e}")
            return condition

    def _translate_between_condition(self, condition: str, table_mapping: TableMapping) -> str:
        """Translate BETWEEN condition using OPE component"""
        try:
            between_pattern = r'(\w+)\s+BETWEEN\s+(.+)\s+AND\s+(.+)'
            match = re.search(between_pattern, condition, re.IGNORECASE)

            if match:
                col_name, value1, value2 = match.groups()
                col_name = col_name.strip()

                actual_col_name = col_name
                if '.' in col_name:
                    actual_col_name = col_name.split('.')[-1].strip()

                if actual_col_name in table_mapping.encrypted_columns:
                    tag_col = table_mapping.encrypted_columns[actual_col_name].tag_name
                    if '.' in col_name:
                        table_prefix = col_name.rsplit('.', 1)[0]
                        tag_col = f"{table_prefix}.{tag_col}"
                    ope_value1 = clwe_encryptor._generate_order_preserving_value(value1.strip().strip("'\""), 'text')
                    ope_value2 = clwe_encryptor._generate_order_preserving_value(value2.strip().strip("'\""), 'text')
                    return f"SUBSTR({tag_col}, 17, 16) BETWEEN '{ope_value1}' AND '{ope_value2}'"

            return condition

        except Exception as e:
            logger.error(f"Error translating BETWEEN condition: {e}")
            return condition

    def _translate_in_condition(self, condition: str, table_mapping: TableMapping) -> str:
        """Translate IN condition by encrypting each value"""
        try:
            in_pattern = r'(\w+)\s+IN\s*\((.+)\)'
            match = re.match(in_pattern, condition, re.IGNORECASE)

            if match:
                col_name, values_str = match.groups()
                col_name = col_name.strip()

                actual_col_name = col_name
                if '.' in col_name:
                    actual_col_name = col_name.split('.')[-1].strip()

                if actual_col_name in table_mapping.encrypted_columns:
                    values = [v.strip() for v in values_str.split(',')]
                    encrypted_values = []

                    for value in values:
                        clean_value = value.strip("'\"")
                        encrypted_blob = clwe_encryptor.encrypt_value(clean_value, settings.CRYPTOPIX_DEFAULT_PASSWORD)
                        encrypted_values.append(f"X'{encrypted_blob.hex()}'")

                    return f"{col_name} IN ({', '.join(encrypted_values)})"

            return condition

        except Exception as e:
            logger.error(f"Error translating IN condition: {e}")
            return condition

    def _translate_comparison_condition(self, condition: str, op: str, table_mapping: TableMapping) -> str:
        """Translate comparison condition (=, >, <, etc.) using appropriate tag components"""
        try:
            parts = re.split(rf'\s*{re.escape(op)}\s*', condition, flags=re.IGNORECASE)
            if len(parts) == 2:
                col_name = parts[0].strip()
                value = parts[1].strip()

                actual_col_name = col_name
                if '.' in col_name:
                    actual_col_name = col_name.split('.')[-1].strip()
                    logger.debug(f"Extracted column name '{actual_col_name}' from qualified name '{col_name}'")

                if actual_col_name in table_mapping.encrypted_columns:
                    if op == '=':
                        clean_value = value.strip("'\"")
                        encrypted_blob = clwe_encryptor.encrypt_value(clean_value, settings.CRYPTOPIX_DEFAULT_PASSWORD)
                        return f"{col_name} = X'{encrypted_blob.hex()}'"
                    else:
                        tag_col = table_mapping.encrypted_columns[actual_col_name].tag_name
                        if '.' in col_name:
                            table_prefix = col_name.rsplit('.', 1)[0]
                            tag_col = f"{table_prefix}.{tag_col}"
                        ope_value = clwe_encryptor._generate_order_preserving_value(value.strip("'\""), 'text')
                        return f"SUBSTR({tag_col}, 17, 16) {op} '{ope_value}'"

            return condition

        except Exception as e:
            logger.error(f"Error translating comparison condition: {e}")
            return condition

    def _translate_delete_query(self, query: str, table_mapping: TableMapping) -> Tuple[str, Dict[str, Any]]:
        """Translate DELETE query for encrypted columns with deterministic encryption"""
        try:
            delete_pattern = r'DELETE\s+FROM\s+(\w+)(?:\s+WHERE\s+(.+))?$'
            match = re.match(delete_pattern, query, re.IGNORECASE | re.DOTALL)

            if not match:
                return query, {
                    'query_type': 'DELETE',
                    'table_name': table_mapping.original_name,
                    'translated': False,
                    'error': 'Could not parse DELETE query'
                }

            table_name, where_clause = match.groups()

            translated_parts = [f"DELETE FROM {table_name}"]

            if where_clause:
                translated_where = self._translate_where_clause(where_clause.strip(), table_mapping)
                if translated_where:
                    translated_parts.append(f"WHERE {translated_where}")

            translated_query = ' '.join(translated_parts)

            metadata = {
                'query_type': 'DELETE',
                'table_name': table_mapping.original_name,
                'translated': True,
                'encrypted_columns': list(table_mapping.encrypted_columns.keys()),
                'has_where': bool(where_clause)
            }

            return translated_query, metadata

        except Exception as e:
            logger.error(f"Error translating DELETE query: {e}")
            return query, {
                'query_type': 'DELETE',
                'table_name': table_mapping.original_name,
                'translated': False,
                'error': str(e)
            }

    def _analyze_query_complexity(self, query: str) -> Dict[str, bool]:
        """Analyze the complexity of a SQL query"""
        complexity = {
            'has_cte': bool(re.search(self.query_patterns['cte'], query, re.IGNORECASE)),
            'has_subquery': bool(re.search(self.query_patterns['subquery'], query, re.IGNORECASE)),
            'has_complex_join': bool(re.search(self.query_patterns['complex_join'], query, re.IGNORECASE)),
            'has_window_function': bool(re.search(self.query_patterns['window_function'], query, re.IGNORECASE)),
            'has_recursive': bool(re.search(self.query_patterns['recursive'], query, re.IGNORECASE)),
            'has_pivot': bool(re.search(self.query_patterns['pivot'], query, re.IGNORECASE)),
            'has_json': bool(re.search(self.query_patterns['json_query'], query, re.IGNORECASE)),
            'has_stored_procedure': bool(re.search(self.query_patterns['stored_procedure'], query, re.IGNORECASE))
        }
        return complexity

    def _translate_cte_query(self, query: str) -> Tuple[str, Dict[str, Any]]:
        """Translate Common Table Expression (CTE) queries"""
        translated_query = query
        metadata = {
            'query_type': 'CTE',
            'translated': True,
            'complexity': 'high',
            'features': ['common_table_expression']
        }
        return translated_query, metadata

    def _translate_subquery_query(self, query: str) -> Tuple[str, Dict[str, Any]]:
        """Translate queries with subqueries"""
        translated_query = query
        metadata = {
            'query_type': 'SUBQUERY',
            'translated': True,
            'complexity': 'high',
            'features': ['subquery']
        }
        return translated_query, metadata

    def _translate_complex_join_query(self, query: str) -> Tuple[str, Dict[str, Any]]:
        """Translate JOIN queries with encrypted columns"""
        try:
            join_info = self._parse_join_query(query)
            if not join_info:
                return query, {
                    'query_type': 'COMPLEX_JOIN',
                    'translated': False,
                    'error': 'Could not parse JOIN query',
                    'complexity': 'high'
                }

            translated_query = self._build_translated_join_query(query, join_info)

            metadata = {
                'query_type': 'COMPLEX_JOIN',
                'translated': True,
                'complexity': 'high',
                'tables': join_info['tables'],  # Already a list of table names
                'join_type': join_info['join_type'],
                'features': ['joins']
            }

            return translated_query, metadata

        except Exception as e:
            logger.error(f"Error translating JOIN query: {e}")
            return query, {
                'query_type': 'COMPLEX_JOIN',
                'translated': False,
                'error': f'JOIN translation failed: {str(e)}',
                'complexity': 'high'
            }

    def _translate_ddl_query(self, query: str) -> Tuple[str, Dict[str, Any]]:
        """Translate DDL queries (CREATE, ALTER, DROP)"""
        translated_query = query
        metadata = {
            'query_type': 'DDL',
            'translated': False,  # DDL queries typically don't need encryption translation
            'complexity': 'medium'
        }
        return translated_query, metadata

    def _add_to_query_history(self, query: str, operation: str):
        """Add query to history for pattern analysis"""
        self.query_history.append({
            'query': query,
            'operation': operation,
            'timestamp': 'now',
            'complexity': self._analyze_query_complexity(query)
        })

        if len(self.query_history) > 100:
            self.query_history.pop(0)

    def get_suggestions(self, partial_query: str, cursor_position: int = None) -> Dict[str, Any]:
        """
        Get AI suggestions for a partial SQL query

        Args:
            partial_query: The current partial SQL query
            cursor_position: Current cursor position in the query

        Returns:
            Dict containing suggestions, corrections, and completions
        """
        try:
            suggestions = {
                'completions': [],
                'corrections': [],
                'suggestions': [],
                'explanations': [],
                'optimizations': [],
                'complexity_analysis': {}
            }

            if not partial_query.strip():
                suggestions['suggestions'] = self._get_initial_suggestions()
                return suggestions

            complexity = self._analyze_query_complexity(partial_query)
            suggestions['complexity_analysis'] = complexity

            suggestions['completions'] = self._get_completions(partial_query, cursor_position)

            corrections = self._check_for_corrections(partial_query)
            if corrections:
                suggestions['corrections'] = corrections

            suggestions['suggestions'] = self._get_context_suggestions(partial_query)

            suggestions['optimizations'] = self._get_optimization_suggestions(partial_query, complexity)

            advanced_suggestions = self._get_advanced_query_suggestions(partial_query, complexity)
            suggestions['suggestions'].extend(advanced_suggestions)

            return suggestions

        except Exception as e:
            logger.error(f"Error getting AI suggestions: {e}")
            return {'completions': [], 'corrections': [], 'suggestions': [], 'explanations': [], 'optimizations': [], 'complexity_analysis': {}}

    def _get_completions(self, partial_query: str, cursor_position: int = None) -> List[str]:
        """Get auto-completion suggestions based on current query context"""
        completions = []
        query_upper = partial_query.upper()

        if cursor_position is None:
            cursor_position = len(partial_query)

        words = re.findall(r'\b\w+\b', partial_query[:cursor_position])
        current_word = words[-1] if words else ""

        if not current_word:
            return completions

        current_word_upper = current_word.upper()

        keyword_matches = [kw for kw in self.sql_keywords if kw.startswith(current_word_upper)]
        completions.extend(keyword_matches)

        table_matches = [table for table in self.table_schemas.keys() if table.startswith(current_word.lower())]
        completions.extend(table_matches)

        column_completions = self._get_column_completions(partial_query, current_word)
        completions.extend(column_completions)

        return list(set(completions))  # Remove duplicates

    def _get_column_completions(self, query: str, current_word: str) -> List[str]:
        """Get column name completions based on query context"""
        completions = []

        table_matches = re.findall(r'\bFROM\s+(\w+)', query, re.IGNORECASE)
        table_matches.extend(re.findall(r'\bJOIN\s+(\w+)', query, re.IGNORECASE))

        for table in table_matches:
            table_lower = table.lower()
            if table_lower in self.table_schemas:
                columns = self.table_schemas[table_lower]
                column_matches = [col for col in columns if col.startswith(current_word.lower())]
                completions.extend(column_matches)

        return completions

    def _check_for_corrections(self, query: str) -> List[Dict[str, Any]]:
        """Check for common SQL mistakes and provide corrections"""
        corrections = []

        for pattern, correction_func in self.common_mistakes.items():
            matches = re.finditer(pattern, query, re.IGNORECASE)
            for match in matches:
                try:
                    corrected = correction_func(match)
                    if corrected != query:
                        corrections.append({
                            'original': query,
                            'corrected': corrected,
                            'explanation': 'Added missing quotes around string values'
                        })
                except Exception as e:
                    logger.warning(f"Error applying correction: {e}")

        if not query.strip().endswith(';') and not query.strip().upper().startswith(('SELECT', 'SHOW', 'SYSTEM')):
            corrections.append({
                'original': query,
                'corrected': query.strip() + ';',
                'explanation': 'Added missing semicolon'
            })

        return corrections

    def _get_context_suggestions(self, query: str) -> List[Dict[str, Any]]:
        """Get intelligent suggestions based on query context"""
        suggestions = []
        query_upper = query.upper().strip()

        if not query.strip():
            return self._get_initial_suggestions()

        if query_upper.startswith('SELECT'):
            suggestions.extend(self._get_select_suggestions(query))
        elif query_upper.startswith('INSERT'):
            suggestions.extend(self._get_insert_suggestions(query))
        elif query_upper.startswith('UPDATE'):
            suggestions.extend(self._get_update_suggestions(query))
        elif query_upper.startswith('DELETE'):
            suggestions.extend(self._get_delete_suggestions(query))

        if 'WHERE' not in query_upper and 'SELECT' in query_upper:
            suggestions.append({
                'query': query + ' WHERE ',
                'description': 'Add WHERE clause to filter results',
                'type': 'enhancement'
            })

        if 'LIMIT' not in query_upper and 'SELECT' in query_upper:
            suggestions.append({
                'query': query + ' LIMIT 10',
                'description': 'Limit results to first 10 rows',
                'type': 'enhancement'
            })

        return suggestions[:5]  # Limit to 5 suggestions

    def _get_initial_suggestions(self) -> List[Dict[str, Any]]:
        """Get initial suggestions for empty query input"""
        return [
            {
                'query': 'SELECT * FROM departments LIMIT 5',
                'description': 'View department records',
                'type': 'example'
            },
            {
                'query': 'SELECT * FROM employees LIMIT 5',
                'description': 'View employee records',
                'type': 'example'
            },
            {
                'query': 'SHOW STATS',
                'description': 'Show system statistics',
                'type': 'admin'
            },
            {
                'query': 'SYSTEM INFO',
                'description': 'Show system information',
                'type': 'admin'
            }
        ]

    def _get_select_suggestions(self, query: str) -> List[Dict[str, Any]]:
        """Get suggestions for SELECT queries"""
        suggestions = []

        if re.match(r'^\s*SELECT\s*$', query, re.IGNORECASE):
            for table, columns in self.table_schemas.items():
                suggestions.append({
                    'query': f'SELECT {", ".join(columns[:3])} FROM {table} LIMIT 5',
                    'description': f'Select key columns from {table}',
                    'type': 'template'
                })

        table_match = re.search(r'FROM\s+(\w+)', query, re.IGNORECASE)
        if table_match:
            table_name = table_match.group(1).lower()
            if table_name in self.table_schemas:
                columns = self.table_schemas[table_name]
                for col in columns[:3]:  # Suggest for first 3 columns
                    suggestions.append({
                        'query': query + f' WHERE {col} = ',
                        'description': f'Filter by {col}',
                        'type': 'filter'
                    })

        return suggestions

    def _get_insert_suggestions(self, query: str) -> List[Dict[str, Any]]:
        """Get suggestions for INSERT queries"""
        suggestions = []

        if re.match(r'^\s*INSERT\s*$', query, re.IGNORECASE):
            for table, columns in self.table_schemas.items():
                cols_str = ', '.join(columns)
                placeholders = ', '.join(['?' for _ in columns])
                suggestions.append({
                    'query': f'INSERT INTO {table} ({cols_str}) VALUES ({placeholders})',
                    'description': f'Insert into {table} table',
                    'type': 'template'
                })

        return suggestions

    def _get_update_suggestions(self, query: str) -> List[Dict[str, Any]]:
        """Get suggestions for UPDATE queries"""
        suggestions = []

        if re.match(r'^\s*UPDATE\s+(\w+)\s+SET\s*$', query, re.IGNORECASE):
            table_match = re.search(r'UPDATE\s+(\w+)', query, re.IGNORECASE)
            if table_match:
                table_name = table_match.group(1).lower()
                if table_name in self.table_schemas:
                    columns = self.table_schemas[table_name]
                    for col in columns:
                        if col != 'id':  # Don't suggest updating ID
                            suggestions.append({
                                'query': query + f' {col} = ',
                                'description': f'Update {col} column',
                                'type': 'update'
                            })

        return suggestions

    def _get_delete_suggestions(self, query: str) -> List[Dict[str, Any]]:
        """Get suggestions for DELETE queries"""
        suggestions = []

        if 'WHERE' not in query.upper():
            suggestions.append({
                'query': query + ' WHERE ',
                'description': 'Add WHERE clause to specify which records to delete',
                'type': 'safety'
            })

        return suggestions

    def _get_optimization_suggestions(self, query: str, complexity: Dict[str, bool]) -> List[Dict[str, Any]]:
        """Get query optimization suggestions"""
        suggestions = []
        query_upper = query.upper()

        if 'WHERE' in query_upper and 'LIKE' in query_upper:
            suggestions.append({
                'type': 'index',
                'suggestion': 'Consider adding an index on columns used in LIKE conditions',
                'impact': 'high'
            })

        if 'JOIN' in query_upper and 'WHERE' not in query_upper:
            suggestions.append({
                'type': 'join_optimization',
                'suggestion': 'Add WHERE clause to filter data before JOIN operations',
                'impact': 'high'
            })

        if complexity['has_subquery']:
            suggestions.append({
                'type': 'subquery_optimization',
                'suggestion': 'Consider converting subquery to JOIN for better performance',
                'impact': 'medium'
            })

        if 'DISTINCT' in query_upper and 'GROUP BY' not in query_upper:
            suggestions.append({
                'type': 'distinct_optimization',
                'suggestion': 'DISTINCT can be expensive; consider if GROUP BY would be more efficient',
                'impact': 'medium'
            })

        if 'SELECT' in query_upper and 'LIMIT' not in query_upper and 'ORDER BY' in query_upper:
            suggestions.append({
                'type': 'limit_optimization',
                'suggestion': 'Add LIMIT clause when using ORDER BY to improve performance',
                'impact': 'medium'
            })

        return suggestions

    def _get_advanced_query_suggestions(self, query: str, complexity: Dict[str, bool]) -> List[Dict[str, Any]]:
        """Get advanced query pattern suggestions"""
        suggestions = []
        query_upper = query.upper()

        if not complexity['has_cte'] and 'SELECT' in query_upper and len(query.split()) > 10:
            suggestions.append({
                'query': f"WITH query_data AS ({query.strip()}) SELECT * FROM query_data",
                'description': 'Convert to CTE for better readability and reusability',
                'type': 'cte_pattern'
            })

        if 'GROUP BY' in query_upper and 'ORDER BY' in query_upper and not complexity['has_window_function']:
            suggestions.append({
                'query': query + ' ROW_NUMBER() OVER (ORDER BY ...) as row_num',
                'description': 'Add window function for ranking/row numbering',
                'type': 'window_function'
            })

        table_match = re.search(r'FROM\s+(\w+)', query_upper, re.IGNORECASE)
        if table_match:
            table_name = table_match.group(1).lower()
            if table_name in self.table_relationships:
                for related_table, relation in self.table_relationships[table_name].items():
                    if related_table not in query_upper:
                        join_suggestion = f"{query} JOIN {related_table} ON {table_name}.{relation['foreign_key']} = {related_table}.{relation['primary_key']}"
                        suggestions.append({
                            'query': join_suggestion,
                            'description': f'Join with {related_table} table using {relation["type"]} relationship',
                            'type': 'relationship_join'
                        })

        if 'parent_id' in query.lower() or 'manager_id' in query.lower():
            suggestions.append({
                'query': f"WITH RECURSIVE hierarchy AS (SELECT * FROM ({query.strip()}) WHERE parent_id IS NULL UNION ALL SELECT t.* FROM ({query.strip()}) t JOIN hierarchy h ON t.parent_id = h.id) SELECT * FROM hierarchy",
                'description': 'Use recursive CTE for hierarchical/organizational data',
                'type': 'recursive_cte'
            })

        return suggestions[:3]  # Limit to 3 advanced suggestions

    def natural_language_to_sql(self, natural_query: str) -> Dict[str, Any]:
        """
        Convert natural language query to SQL

        Args:
            natural_query: Natural language description of desired query

        Returns:
            Dict containing generated SQL and metadata
        """
        try:
            natural_lower = natural_query.lower().strip()

            result = {
                'sql': '',
                'confidence': 0.0,
                'explanation': '',
                'alternatives': []
            }

            if any(word in natural_lower for word in ['show', 'get', 'find', 'list', 'display', 'select']):
                result = self._nl_to_select_query(natural_query)
            elif any(word in natural_lower for word in ['add', 'insert', 'create', 'new']):
                result = self._nl_to_insert_query(natural_query)
            elif any(word in natural_lower for word in ['update', 'change', 'modify', 'set']):
                result = self._nl_to_update_query(natural_query)
            elif any(word in natural_lower for word in ['delete', 'remove', 'erase']):
                result = self._nl_to_delete_query(natural_query)
            elif any(word in natural_lower for word in ['join', 'combine', 'with related']):
                result = self._nl_to_join_query(natural_query)
            else:
                result['sql'] = f"-- Unable to parse: {natural_query}"
                result['explanation'] = "Could not determine query type from natural language"

            return result

        except Exception as e:
            logger.error(f"Error converting natural language to SQL: {e}")
            return {
                'sql': f"-- Error: {str(e)}",
                'confidence': 0.0,
                'explanation': "Error processing natural language query",
                'alternatives': []
            }

    def _nl_to_select_query(self, natural_query: str) -> Dict[str, Any]:
        """Convert natural language to SELECT query"""
        result = {
            'sql': '',
            'confidence': 0.7,
            'explanation': '',
            'alternatives': []
        }

        natural_lower = natural_query.lower()

        table_name = None
        for table in self.table_schemas.keys():
            if table in natural_lower:
                table_name = table
                break

        if not table_name:
            result['sql'] = f"-- Could not identify table in: {natural_query}"
            result['confidence'] = 0.3
            return result

        columns = []
        for col in self.table_schemas[table_name]:
            if col in natural_lower or col.replace('_', ' ') in natural_lower:
                columns.append(col)

        if not columns:
            columns = ['*']

        sql = f"SELECT {', '.join(columns)} FROM {table_name}"

        where_conditions = []
        if 'where' in natural_lower or 'with' in natural_lower or 'having' in natural_lower:
            for col in self.table_schemas[table_name]:
                if col in natural_lower:
                    col_pattern = r"{}\s+(?:is|=|equals?)\s*['\"]?([^'\"\s]+)['\"]?".format(col)
                    match = re.search(col_pattern, natural_lower, re.IGNORECASE)
                    if match:
                        value = match.group(1)
                        where_conditions.append(f"{col} = '{value}'")

        if where_conditions:
            sql += f" WHERE {' AND '.join(where_conditions)}"

        if 'order' in natural_lower and 'by' in natural_lower:
            for col in self.table_schemas[table_name]:
                if col in natural_lower:
                    sql += f" ORDER BY {col}"
                    if 'desc' in natural_lower:
                        sql += " DESC"
                    break

        if 'limit' in natural_lower or 'top' in natural_lower:
            limit_match = re.search(r'(?:limit|top)\s+(\d+)', natural_lower)
            if limit_match:
                sql += f" LIMIT {limit_match.group(1)}"

        result['sql'] = sql
        result['explanation'] = f"Generated SELECT query for {table_name} table"
        result['alternatives'] = [
            f"SELECT * FROM {table_name}",
            f"SELECT COUNT(*) FROM {table_name}"
        ]

        return result

    def _nl_to_insert_query(self, natural_query: str) -> Dict[str, Any]:
        """Convert natural language to INSERT query"""
        result = {
            'sql': '',
            'confidence': 0.6,
            'explanation': '',
            'alternatives': []
        }

        natural_lower = natural_query.lower()

        table_name = None
        for table in self.table_schemas.keys():
            if table in natural_lower:
                table_name = table
                break

        if not table_name:
            result['sql'] = f"-- Could not identify table in: {natural_query}"
            result['confidence'] = 0.3
            return result

        columns = self.table_schemas[table_name]
        placeholders = ', '.join(['?' for _ in columns])

        sql = f"INSERT INTO {table_name} ({', '.join(columns)}) VALUES ({placeholders})"

        result['sql'] = sql
        result['explanation'] = f"Generated INSERT template for {table_name} table"
        result['alternatives'] = [
            f"INSERT INTO {table_name} ({columns[0]}) VALUES (?)"
        ]

        return result

    def _nl_to_update_query(self, natural_query: str) -> Dict[str, Any]:
        """Convert natural language to UPDATE query"""
        result = {
            'sql': '',
            'confidence': 0.5,
            'explanation': '',
            'alternatives': []
        }

        natural_lower = natural_query.lower()

        table_name = None
        for table in self.table_schemas.keys():
            if table in natural_lower:
                table_name = table
                break

        if not table_name:
            result['sql'] = f"-- Could not identify table in: {natural_query}"
            result['confidence'] = 0.3
            return result

        sql = f"UPDATE {table_name} SET "

        result['sql'] = sql + "column_name = value WHERE condition"
        result['explanation'] = f"Generated UPDATE template for {table_name} table"
        result['alternatives'] = []

        return result

    def _nl_to_delete_query(self, natural_query: str) -> Dict[str, Any]:
        """Convert natural language to DELETE query"""
        result = {
            'sql': '',
            'confidence': 0.4,
            'explanation': '',
            'alternatives': []
        }

        natural_lower = natural_query.lower()

        table_name = None
        for table in self.table_schemas.keys():
            if table in natural_lower:
                table_name = table
                break

        if not table_name:
            result['sql'] = f"-- Could not identify table in: {natural_query}"
            result['confidence'] = 0.3
            return result

        sql = f"DELETE FROM {table_name} WHERE condition"

        result['sql'] = sql
        result['explanation'] = f"Generated DELETE template for {table_name} table (add WHERE clause for safety)"
        result['alternatives'] = []

        return result

    def _nl_to_join_query(self, natural_query: str) -> Dict[str, Any]:
        """Convert natural language to JOIN query"""
        result = {
            'sql': '',
            'confidence': 0.5,
            'explanation': '',
            'alternatives': []
        }

        natural_lower = natural_query.lower()

        found_tables = []
        for table in self.table_schemas.keys():
            if table in natural_lower:
                found_tables.append(table)

        if len(found_tables) < 2:
            result['sql'] = f"-- Need at least 2 tables for JOIN: {natural_query}"
            result['confidence'] = 0.2
            return result

        table1, table2 = found_tables[0], found_tables[1]
        join_condition = ""

        if table1 in self.table_relationships and table2 in self.table_relationships[table1]:
            relation = self.table_relationships[table1][table2]
            join_condition = f"{table1}.{relation['foreign_key']} = {table2}.{relation['primary_key']}"

        sql = f"SELECT * FROM {table1} JOIN {table2} ON {join_condition}"

        result['sql'] = sql
        result['explanation'] = f"Generated JOIN query between {table1} and {table2}"
        result['alternatives'] = [
            f"SELECT * FROM {table1} LEFT JOIN {table2} ON {join_condition}",
            f"SELECT * FROM {table1} INNER JOIN {table2} ON {join_condition}"
        ]

        return result

    def explain_query(self, query: str) -> str:
        """Provide a human-readable explanation of what a SQL query does"""
        try:
            query_upper = query.upper().strip()

            if query_upper.startswith('SELECT'):
                return self._explain_select(query)
            elif query_upper.startswith('INSERT'):
                return self._explain_insert(query)
            elif query_upper.startswith('UPDATE'):
                return self._explain_update(query)
            elif query_upper.startswith('DELETE'):
                return self._explain_delete(query)
            elif query_upper.startswith('WITH'):
                return self._explain_cte(query)
            elif query_upper.startswith('SHOW STATS'):
                return "Displays system statistics including database status, migration progress, and performance metrics."
            elif query_upper.startswith('SYSTEM INFO'):
                return "Shows detailed system information including platform, version, and encryption capabilities."
            else:
                return "This appears to be a SQL query or admin command."

        except Exception as e:
            logger.error(f"Error explaining query: {e}")
            return "Unable to analyze this query."

    def _explain_select(self, query: str) -> str:
        """Explain a SELECT query"""
        explanation = "This query selects data from the database."

        if 'COUNT(' in query.upper():
            explanation = "This query counts records in the database."
        elif 'SUM(' in query.upper():
            explanation = "This query calculates the sum of numeric values."
        elif 'AVG(' in query.upper():
            explanation = "This query calculates the average of numeric values."

        table_match = re.search(r'FROM\s+(\w+)', query, re.IGNORECASE)
        if table_match:
            table = table_match.group(1)
            explanation += f" It retrieves data from the '{table}' table."

        if 'WHERE' in query.upper():
            explanation += " Results are filtered by specified conditions."

        limit_match = re.search(r'LIMIT\s+(\d+)', query, re.IGNORECASE)
        if limit_match:
            limit = limit_match.group(1)
            explanation += f" Limited to {limit} results."

        return explanation

    def _explain_insert(self, query: str) -> str:
        """Explain an INSERT query"""
        explanation = "This query inserts new data into the database."

        table_match = re.search(r'INTO\s+(\w+)', query, re.IGNORECASE)
        if table_match:
            table = table_match.group(1)
            explanation += f" It adds records to the '{table}' table."

        return explanation

    def _explain_update(self, query: str) -> str:
        """Explain an UPDATE query"""
        explanation = "This query modifies existing data in the database."

        table_match = re.search(r'UPDATE\s+(\w+)', query, re.IGNORECASE)
        if table_match:
            table = table_match.group(1)
            explanation += f" It updates records in the '{table}' table."

        return explanation

    def _explain_delete(self, query: str) -> str:
        """Explain a DELETE query"""
        explanation = "This query removes data from the database."

        table_match = re.search(r'FROM\s+(\w+)', query, re.IGNORECASE)
        if table_match:
            table = table_match.group(1)
            explanation += f" It deletes records from the '{table}' table."

        if 'WHERE' not in query.upper():
            explanation += " WARNING: No WHERE clause specified - this will delete ALL records!"

        return explanation

    def _explain_cte(self, query: str) -> str:
        """Explain a CTE (Common Table Expression) query"""
        explanation = "This query uses a Common Table Expression (CTE) with the WITH clause."

        cte_match = re.search(r'WITH\s+(\w+)\s+AS', query, re.IGNORECASE)
        if cte_match:
            cte_name = cte_match.group(1)
            explanation += f" It defines a temporary result set called '{cte_name}'."

        if 'RECURSIVE' in query.upper():
            explanation += " This is a recursive CTE, useful for hierarchical or tree-structured data."

        explanation += " CTEs improve query readability and can be referenced multiple times in the main query."

        return explanation

    def _parse_join_query(self, query: str) -> Dict[str, Any]:
        """Parse a JOIN query to extract table information"""
        try:

            from_match = re.search(r'FROM\s+([^\s]+)(?:\s+(\w+))?', query, re.IGNORECASE)
            if not from_match:
                return None

            from_table = from_match.group(1)
            from_alias = from_match.group(2) if from_match.group(2) else from_table

            join_match = re.search(r'JOIN\s+([^\s]+)(?:\s+(\w+))?\s+ON\s+(.+?)(?:\s+WHERE|$|\s+ORDER|\s+GROUP|\s+LIMIT|$)', query, re.IGNORECASE | re.DOTALL)
            if not join_match:
                return None

            join_table = join_match.group(1)
            join_alias = join_match.group(2) if join_match.group(2) else join_table
            join_condition = join_match.group(3).strip()

            select_match = re.search(r'SELECT\s+(.+?)\s+FROM', query, re.IGNORECASE | re.DOTALL)
            select_clause = select_match.group(1) if select_match else "*"

            table_aliases = {
                from_alias: from_table,
                join_alias: join_table
            }

            actual_tables = [from_table, join_table]

            return {
                'tables': actual_tables,  # List of actual table names
                'table_aliases': table_aliases,  # Dict mapping aliases to table names
                'from_table': from_table,
                'from_alias': from_alias,
                'join_table': join_table,
                'join_alias': join_alias,
                'join_condition': join_condition,
                'select_clause': select_clause,
                'join_type': 'INNER'
            }

        except Exception as e:
            logger.error(f"Error parsing JOIN query: {e}")
            return None

    def _build_translated_join_query(self, original_query: str, join_info: Dict[str, Any]) -> str:
        """Build a translated JOIN query for encrypted columns"""
        try:
            select_clause = join_info['select_clause']
            table_aliases = join_info.get('table_aliases', {})  # Dict mapping aliases to table names
            tables = join_info.get('tables', [])  # List of actual table names

            translated_select_parts = []
            select_items = [item.strip() for item in select_clause.split(',')]

            for item in select_items:
                item = item.strip()

                if '.' in item:
                    table_ref, column = item.split('.', 1)
                    table_ref = table_ref.strip()
                    column = column.strip()

                    actual_table = table_aliases.get(table_ref, table_ref)

                    if actual_table in self.table_mappings:
                        table_mapping = self.table_mappings[actual_table]
                        translated_select_parts.append(item)
                    else:
                        translated_select_parts.append(item)
                else:
                    translated_select_parts.append(item)

            translated_select = ', '.join(translated_select_parts)

            from_table = join_info['from_table']
            from_alias = join_info['from_alias']
            join_table = join_info['join_table']
            join_alias = join_info['join_alias']
            join_condition = join_info['join_condition']

            from_clause = f"FROM {from_table}"
            if from_alias != from_table:
                from_clause += f" {from_alias}"

            join_clause = f"JOIN {join_table}"
            if join_alias != join_table:
                join_clause += f" {join_alias}"
            join_clause += f" ON {join_condition}"

            translated_query = f"SELECT {translated_select} {from_clause} {join_clause}"


            return translated_query

        except Exception as e:
            logger.error(f"Error building translated JOIN query: {e}")
            return original_query

    def _parse_values_list(self, values_str: str) -> List[str]:
        """Parse a VALUES clause into individual values, handling quoted strings correctly"""
        values = []
        current_value = ""
        in_string = False
        string_char = None
        paren_depth = 0

        i = 0
        while i < len(values_str):
            char = values_str[i]

            if not in_string and not paren_depth and char == ',':
                values.append(current_value.strip())
                current_value = ""
                while i + 1 < len(values_str) and values_str[i + 1].isspace():
                    i += 1
            elif not in_string and (char == '"' or char == "'"):
                in_string = True
                string_char = char
                current_value += char
            elif in_string and char == string_char:
                if i + 1 < len(values_str) and values_str[i + 1] == string_char:
                    current_value += char + char
                    i += 1  # Skip next character
                else:
                    in_string = False
                    current_value += char
            elif not in_string and char == '(':
                paren_depth += 1
                current_value += char
            elif not in_string and char == ')':
                paren_depth -= 1
                current_value += char
            else:
                current_value += char

            i += 1

        if current_value.strip():
            values.append(current_value.strip())

        return values


ai_assistant = AIAssistant()