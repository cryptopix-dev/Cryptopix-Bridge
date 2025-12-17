"""
CryptoPIX Bridge v3.0 - Schema-Level Encryption Service
Handles encryption and decryption of entire database schemas with AI integration
"""

import logging
import json
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

from app.config import settings
from app.core.encryption import clwe_encryptor

logger = logging.getLogger(__name__)


class SchemaEncryptionLevel(Enum):
    """Schema encryption levels"""
    NONE = "none"
    BASIC = "basic"  # Encrypt column names and types
    FULL = "full"    # Encrypt entire schema structure
    AI_ENHANCED = "ai_enhanced"  # AI-aware schema encryption


@dataclass
class EncryptedSchema:
    """Represents an encrypted database schema"""
    database_name: str
    tables: Dict[str, Dict[str, Any]]
    encryption_level: SchemaEncryptionLevel
    encryption_metadata: Dict[str, Any]
    ai_context: Dict[str, Any]  # AI assistant context
    created_at: str
    version: str = "3.0"


class SchemaEncryptionService:
    """Service for encrypting and decrypting database schemas"""

    def __init__(self):
        self.schema_cache: Dict[str, EncryptedSchema] = {}
        self.encryption_key = settings.CRYPTOPIX_DEFAULT_PASSWORD

        # PostgreSQL-specific configurations
        self.postgresql_config = {
            "bytea_handling": True,
            "hex_encoding": True,
            "escape_string_literals": True,
            "schema_qualified_names": True
        }

    def encrypt_schema(self,
                       schema_data: Dict[str, Any],
                       database_name: str,
                       encryption_level: SchemaEncryptionLevel = SchemaEncryptionLevel.AI_ENHANCED) -> EncryptedSchema:
        """
        Encrypt an entire database schema

        Args:
            schema_data: Raw schema data (tables, columns, etc.)
            database_name: Name of the database
            encryption_level: Level of encryption to apply

        Returns:
            EncryptedSchema object
        """
        try:
            logger.info(f"Encrypting schema for database: {database_name} with level: {encryption_level.value}")

            # Create AI context for the schema
            ai_context = self._generate_ai_context(schema_data)

            # Encrypt based on level
            if encryption_level == SchemaEncryptionLevel.NONE:
                encrypted_tables = schema_data.get('tables', {})
                encryption_metadata = {"level": "none"}

            elif encryption_level == SchemaEncryptionLevel.BASIC:
                encrypted_tables, encryption_metadata = self._encrypt_basic(schema_data)

            elif encryption_level == SchemaEncryptionLevel.FULL:
                encrypted_tables, encryption_metadata = self._encrypt_full(schema_data)

            elif encryption_level == SchemaEncryptionLevel.AI_ENHANCED:
                encrypted_tables, encryption_metadata = self._encrypt_ai_enhanced(schema_data, ai_context)

            else:
                raise ValueError(f"Unknown encryption level: {encryption_level}")

            # Create encrypted schema object
            encrypted_schema = EncryptedSchema(
                database_name=database_name,
                tables=encrypted_tables,
                encryption_level=encryption_level,
                encryption_metadata=encryption_metadata,
                ai_context=ai_context,
                created_at=self._get_timestamp(),
                version="3.0"
            )

            # Cache the schema
            self.schema_cache[database_name] = encrypted_schema

            logger.info(f"Successfully encrypted schema for {database_name} with {len(encrypted_tables)} tables")
            return encrypted_schema

        except Exception as e:
            logger.error(f"Failed to encrypt schema for {database_name}: {e}")
            raise

    def decrypt_schema(self, encrypted_schema: EncryptedSchema) -> Dict[str, Any]:
        """
        Decrypt an encrypted schema back to readable format

        Args:
            encrypted_schema: EncryptedSchema object

        Returns:
            Decrypted schema data
        """
        try:
            logger.info(f"Decrypting schema for database: {encrypted_schema.database_name}")

            # Decrypt based on level
            if encrypted_schema.encryption_level == SchemaEncryptionLevel.NONE:
                decrypted_tables = encrypted_schema.tables

            elif encrypted_schema.encryption_level == SchemaEncryptionLevel.BASIC:
                decrypted_tables = self._decrypt_basic(encrypted_schema)

            elif encrypted_schema.encryption_level == SchemaEncryptionLevel.FULL:
                decrypted_tables = self._decrypt_full(encrypted_schema)

            elif encrypted_schema.encryption_level == SchemaEncryptionLevel.AI_ENHANCED:
                decrypted_tables = self._decrypt_ai_enhanced(encrypted_schema)

            else:
                raise ValueError(f"Unknown encryption level: {encrypted_schema.encryption_level}")

            # Return decrypted schema
            decrypted_schema = {
                "database_name": encrypted_schema.database_name,
                "tables": decrypted_tables,
                "encryption_level": encrypted_schema.encryption_level.value,
                "ai_context": encrypted_schema.ai_context,
                "decrypted_at": self._get_timestamp(),
                "version": encrypted_schema.version
            }

            logger.info(f"Successfully decrypted schema for {encrypted_schema.database_name}")
            return decrypted_schema

        except Exception as e:
            logger.error(f"Failed to decrypt schema for {encrypted_schema.database_name}: {e}")
            raise

    def _encrypt_basic(self, schema_data: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Basic schema encryption - encrypt column names and types"""
        encrypted_tables = {}
        encryption_metadata = {
            "level": "basic",
            "encrypted_elements": ["column_names", "data_types"],
            "algorithm": "CLWE"
        }

        for table_name, table_info in schema_data.get('tables', {}).items():
            encrypted_table = {
                "original_name": table_name,
                "encrypted_name": self._encrypt_string(table_name),
                "columns": {}
            }

            for col_name, col_info in table_info.get('columns', {}).items():
                encrypted_col_name = self._encrypt_string(col_name)
                encrypted_data_type = self._encrypt_string(str(col_info.get('type', 'TEXT')))

                encrypted_table["columns"][encrypted_col_name] = {
                    "original_name": col_name,
                    "original_type": str(col_info.get('type', 'TEXT')),
                    "encrypted_name": encrypted_col_name,
                    "encrypted_type": encrypted_data_type,
                    "nullable": col_info.get('nullable', True),
                    "primary_key": col_info.get('primary_key', False)
                }

            encrypted_tables[table_name] = encrypted_table

        return encrypted_tables, encryption_metadata

    def _decrypt_basic(self, encrypted_schema: EncryptedSchema) -> Dict[str, Any]:
        """Decrypt basic encrypted schema"""
        decrypted_tables = {}

        for table_name, encrypted_table in encrypted_schema.tables.items():
            decrypted_table = {
                "name": self._decrypt_string(encrypted_table["encrypted_name"]),
                "columns": {}
            }

            for enc_col_name, enc_col_info in encrypted_table["columns"].items():
                dec_col_name = self._decrypt_string(enc_col_info["encrypted_name"])
                dec_data_type = self._decrypt_string(enc_col_info["encrypted_type"])

                decrypted_table["columns"][dec_col_name] = {
                    "name": dec_col_name,
                    "type": dec_data_type,
                    "nullable": enc_col_info.get('nullable', True),
                    "primary_key": enc_col_info.get('primary_key', False)
                }

            decrypted_tables[decrypted_table["name"]] = decrypted_table

        return decrypted_tables

    def _encrypt_full(self, schema_data: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Full schema encryption - encrypt entire structure"""
        # Serialize entire schema and encrypt as one blob
        schema_json = json.dumps(schema_data, sort_keys=True)
        encrypted_blob = clwe_encryptor.encrypt_value(schema_json, self.encryption_key)

        encrypted_tables = {
            "_schema_blob": {
                "encrypted_data": encrypted_blob.hex(),
                "original_size": len(schema_json),
                "compression_ratio": len(encrypted_blob) / len(schema_json) if len(schema_json) > 0 else 1
            }
        }

        encryption_metadata = {
            "level": "full",
            "algorithm": "CLWE",
            "original_size": len(schema_json),
            "encrypted_size": len(encrypted_blob),
            "compression_ratio": len(encrypted_blob) / len(schema_json) if len(schema_json) > 0 else 1
        }

        return encrypted_tables, encryption_metadata

    def _decrypt_full(self, encrypted_schema: EncryptedSchema) -> Dict[str, Any]:
        """Decrypt full encrypted schema"""
        schema_blob = encrypted_schema.tables.get("_schema_blob", {})
        encrypted_hex = schema_blob.get("encrypted_data", "")

        if not encrypted_hex:
            raise ValueError("No encrypted schema data found")

        # Decrypt the blob
        encrypted_bytes = bytes.fromhex(encrypted_hex)
        decrypted_json = clwe_encryptor.decrypt_value(encrypted_bytes, self.encryption_key)

        # Parse back to schema
        return json.loads(decrypted_json)

    def _encrypt_ai_enhanced(self, schema_data: Dict[str, Any], ai_context: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """AI-enhanced schema encryption with semantic understanding"""
        # Combine schema data with AI context
        enhanced_data = {
            "schema": schema_data,
            "ai_context": ai_context,
            "semantic_mappings": self._generate_semantic_mappings(schema_data, ai_context)
        }

        # Use full encryption but keep AI context separately for performance
        schema_json = json.dumps(enhanced_data["schema"], sort_keys=True)
        encrypted_blob = clwe_encryptor.encrypt_value(schema_json, self.encryption_key)

        encrypted_tables = {
            "_schema_blob": {
                "encrypted_data": encrypted_blob.hex(),
                "ai_context": ai_context,  # Keep AI context unencrypted for performance
                "semantic_mappings": enhanced_data["semantic_mappings"],
                "original_size": len(schema_json),
                "compression_ratio": len(encrypted_blob) / len(schema_json) if len(schema_json) > 0 else 1
            }
        }

        encryption_metadata = {
            "level": "ai_enhanced",
            "algorithm": "CLWE",
            "ai_features": ["semantic_mapping", "query_intent_understanding", "context_awareness"],
            "original_size": len(schema_json),
            "encrypted_size": len(encrypted_blob)
        }

        return encrypted_tables, encryption_metadata

    def _decrypt_ai_enhanced(self, encrypted_schema: EncryptedSchema) -> Dict[str, Any]:
        """Decrypt AI-enhanced encrypted schema"""
        schema_blob = encrypted_schema.tables.get("_schema_blob", {})
        encrypted_hex = schema_blob.get("encrypted_data", "")

        if not encrypted_hex:
            raise ValueError("No encrypted schema data found")

        # Decrypt the schema
        encrypted_bytes = bytes.fromhex(encrypted_hex)
        decrypted_json = clwe_encryptor.decrypt_value(encrypted_bytes, self.encryption_key)

        # Parse and enhance with AI context
        schema_data = json.loads(decrypted_json)

        # Add AI context back
        schema_data["ai_context"] = schema_blob.get("ai_context", {})
        schema_data["semantic_mappings"] = schema_blob.get("semantic_mappings", {})

        return schema_data

    def _encrypt_string(self, text: str) -> str:
        """Encrypt a string value"""
        if not text:
            return ""
        encrypted = clwe_encryptor.encrypt_value(text, self.encryption_key)
        return encrypted.hex()

    def _decrypt_string(self, encrypted_hex: str) -> str:
        """Decrypt a string value"""
        if not encrypted_hex:
            return ""
        try:
            encrypted_bytes = bytes.fromhex(encrypted_hex)
            return clwe_encryptor.decrypt_value(encrypted_bytes, self.encryption_key)
        except Exception as e:
            logger.error(f"Failed to decrypt string: {e}")
            return f"<DECRYPTION_FAILED:{encrypted_hex[:20]}...>"

    def _generate_ai_context(self, schema_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate AI context for schema understanding"""
        ai_context = {
            "table_count": len(schema_data.get('tables', {})),
            "total_columns": sum(len(table.get('columns', {})) for table in schema_data.get('tables', {}).values()),
            "table_types": {},
            "relationships": self._analyze_relationships(schema_data),
            "data_patterns": self._analyze_data_patterns(schema_data),
            "query_patterns": self._generate_query_patterns(schema_data)
        }

        # Analyze table types
        for table_name, table_info in schema_data.get('tables', {}).items():
            table_type = self._classify_table_type(table_name, table_info)
            ai_context["table_types"][table_name] = table_type

        return ai_context

    def _classify_table_type(self, table_name: str, table_info: Dict[str, Any]) -> str:
        """Classify table type based on structure and naming"""
        table_name_lower = table_name.lower()

        # Common table type patterns
        if 'user' in table_name_lower or 'account' in table_name_lower:
            return "user_management"
        elif 'order' in table_name_lower or 'invoice' in table_name_lower:
            return "transaction"
        elif 'product' in table_name_lower or 'item' in table_name_lower:
            return "catalog"
        elif 'log' in table_name_lower or 'audit' in table_name_lower:
            return "audit"
        elif 'config' in table_name_lower or 'setting' in table_name_lower:
            return "configuration"
        else:
            return "data"

    def _analyze_relationships(self, schema_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze table relationships"""
        relationships = []

        tables = schema_data.get('tables', {})

        for table_name, table_info in tables.items():
            for col_name, col_info in table_info.get('columns', {}).items():
                # Look for foreign key patterns
                if 'id' in col_name.lower() and col_name.lower() != 'id':
                    # Potential foreign key
                    referenced_table = col_name.lower().replace('_id', '').replace('id', '')
                    if referenced_table in tables:
                        relationships.append({
                            "from_table": table_name,
                            "to_table": referenced_table,
                            "foreign_key": col_name,
                            "relationship_type": "foreign_key"
                        })

        return relationships

    def _analyze_data_patterns(self, schema_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze data patterns in schema"""
        patterns = {
            "common_column_types": {},
            "naming_conventions": [],
            "data_types_used": set()
        }

        for table_info in schema_data.get('tables', {}).values():
            for col_info in table_info.get('columns', {}).values():
                data_type = str(col_info.get('type', 'TEXT'))
                patterns["data_types_used"].add(data_type)

                # Count common column types
                col_name = col_info.get('name', '').lower()
                if col_name in patterns["common_column_types"]:
                    patterns["common_column_types"][col_name] += 1
                else:
                    patterns["common_column_types"][col_name] = 1

        patterns["data_types_used"] = list(patterns["data_types_used"])
        return patterns

    def _generate_query_patterns(self, schema_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate common query patterns for AI assistance"""
        patterns = []

        for table_name, table_info in schema_data.get('tables', {}).items():
            # Basic SELECT patterns
            patterns.append({
                "type": "select_all",
                "table": table_name,
                "query": f"SELECT * FROM {table_name}",
                "description": f"Get all records from {table_name}"
            })

            # SELECT with LIMIT
            patterns.append({
                "type": "select_limited",
                "table": table_name,
                "query": f"SELECT * FROM {table_name} LIMIT 10",
                "description": f"Get first 10 records from {table_name}"
            })

            # Check for ID columns for specific queries
            has_id = any('id' in col.get('name', '').lower() for col in table_info.get('columns', {}).values())

            if has_id:
                patterns.append({
                    "type": "select_by_id",
                    "table": table_name,
                    "query": f"SELECT * FROM {table_name} WHERE id = ?",
                    "description": f"Get specific record from {table_name} by ID"
                })

        return patterns

    def _generate_semantic_mappings(self, schema_data: Dict[str, Any], ai_context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate semantic mappings for AI-enhanced queries"""
        semantic_mappings = {
            "table_aliases": {},
            "column_synonyms": {},
            "query_intents": {}
        }

        # Generate table aliases
        for table_name in schema_data.get('tables', {}):
            aliases = self._generate_table_aliases(table_name)
            semantic_mappings["table_aliases"][table_name] = aliases

        # Generate column synonyms
        for table_name, table_info in schema_data.get('tables', {}).items():
            for col_name in table_info.get('columns', {}):
                synonyms = self._generate_column_synonyms(col_name)
                if synonyms:
                    semantic_mappings["column_synonyms"][f"{table_name}.{col_name}"] = synonyms

        return semantic_mappings

    def _generate_table_aliases(self, table_name: str) -> List[str]:
        """Generate common aliases for a table"""
        aliases = []
        name_lower = table_name.lower()

        # Remove common suffixes
        if name_lower.endswith('s'):
            aliases.append(name_lower[:-1])  # users -> user
        if name_lower.endswith('ies'):
            aliases.append(name_lower[:-3] + 'y')  # categories -> category

        # Add common abbreviations
        if 'user' in name_lower:
            aliases.append('u')
        if 'product' in name_lower:
            aliases.append('p')
        if 'order' in name_lower:
            aliases.append('o')
        if 'customer' in name_lower:
            aliases.append('c')

        return list(set(aliases))  # Remove duplicates

    def _generate_column_synonyms(self, column_name: str) -> List[str]:
        """Generate synonyms for column names"""
        synonyms = []
        name_lower = column_name.lower()

        # Common synonyms
        synonym_map = {
            'name': ['title', 'label', 'identifier'],
            'email': ['email_address', 'mail', 'e-mail'],
            'phone': ['telephone', 'phone_number', 'mobile'],
            'address': ['location', 'addr'],
            'created_at': ['created_date', 'creation_time', 'date_created'],
            'updated_at': ['updated_date', 'modification_time', 'last_modified']
        }

        for key, syns in synonym_map.items():
            if key in name_lower:
                synonyms.extend(syns)

        return list(set(synonyms))  # Remove duplicates

    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.utcnow().isoformat()

    def save_encrypted_schema(self, encrypted_schema: EncryptedSchema, file_path: str):
        """Save encrypted schema to file"""
        try:
            schema_dict = asdict(encrypted_schema)
            with open(file_path, 'w') as f:
                json.dump(schema_dict, f, indent=2)
            logger.info(f"Saved encrypted schema to {file_path}")
        except Exception as e:
            logger.error(f"Failed to save encrypted schema: {e}")
            raise

    def load_encrypted_schema(self, file_path: str) -> EncryptedSchema:
        """Load encrypted schema from file"""
        try:
            with open(file_path, 'r') as f:
                schema_dict = json.load(f)

            # Convert back to EncryptedSchema object
            encrypted_schema = EncryptedSchema(**schema_dict)
            logger.info(f"Loaded encrypted schema from {file_path}")
            return encrypted_schema
        except Exception as e:
            logger.error(f"Failed to load encrypted schema: {e}")
            raise

    def encrypt_postgresql_schema(self,
                                  schema_data: Dict[str, Any],
                                  database_name: str,
                                  encryption_level: SchemaEncryptionLevel = SchemaEncryptionLevel.AI_ENHANCED) -> EncryptedSchema:
        """
        Encrypt PostgreSQL database schema with BYTEA-specific handling

        Args:
            schema_data: PostgreSQL schema data
            database_name: Name of the database
            encryption_level: Level of encryption to apply

        Returns:
            EncryptedSchema object optimized for PostgreSQL
        """
        try:
            logger.info(f"Encrypting PostgreSQL schema for database: {database_name}")

            # Enhance schema data with PostgreSQL-specific information
            postgresql_schema = self._enhance_postgresql_schema(schema_data)

            # Use standard encryption but with PostgreSQL optimizations
            encrypted_schema = self.encrypt_schema(postgresql_schema, database_name, encryption_level)

            # Add PostgreSQL-specific metadata
            encrypted_schema.encryption_metadata.update({
                "database_type": "postgresql",
                "bytea_optimized": True,
                "hex_encoding_support": True,
                "schema_qualified_support": True
            })

            logger.info(f"Successfully encrypted PostgreSQL schema for {database_name}")
            return encrypted_schema

        except Exception as e:
            logger.error(f"Failed to encrypt PostgreSQL schema for {database_name}: {e}")
            raise

    def decrypt_postgresql_schema(self, encrypted_schema: EncryptedSchema) -> Dict[str, Any]:
        """
        Decrypt PostgreSQL schema with BYTEA-specific handling

        Args:
            encrypted_schema: Encrypted PostgreSQL schema

        Returns:
            Decrypted PostgreSQL schema data
        """
        try:
            logger.info(f"Decrypting PostgreSQL schema for database: {encrypted_schema.database_name}")

            # Use standard decryption
            decrypted_schema = self.decrypt_schema(encrypted_schema)

            # Add PostgreSQL-specific enhancements
            decrypted_schema = self._restore_postgresql_schema(decrypted_schema)

            logger.info(f"Successfully decrypted PostgreSQL schema for {encrypted_schema.database_name}")
            return decrypted_schema

        except Exception as e:
            logger.error(f"Failed to decrypt PostgreSQL schema for {encrypted_schema.database_name}: {e}")
            raise

    def handle_postgresql_bytea_data(self, data: Any, operation: str = "encrypt") -> Any:
        """
        Handle PostgreSQL BYTEA data for encryption/decryption

        Args:
            data: Data to process (bytes, string, etc.)
            operation: "encrypt" or "decrypt"

        Returns:
            Processed data
        """
        try:
            if operation == "encrypt":
                return self._encrypt_for_postgresql_bytea(data)
            elif operation == "decrypt":
                return self._decrypt_from_postgresql_bytea(data)
            else:
                raise ValueError(f"Unknown operation: {operation}")
        except Exception as e:
            logger.error(f"Failed to handle PostgreSQL BYTEA data: {e}")
            raise

    def _encrypt_for_postgresql_bytea(self, data: Any) -> str:
        """Encrypt data and format for PostgreSQL BYTEA storage"""
        try:
            # Convert data to string if needed
            if isinstance(data, (dict, list)):
                data_str = json.dumps(data, separators=(',', ':'))
            else:
                data_str = str(data)

            # Encrypt using CLWE
            encrypted_blob = clwe_encryptor.encrypt_value(data_str, self.encryption_key)

            # Return as hex string for PostgreSQL BYTEA
            return encrypted_blob.hex()

        except Exception as e:
            logger.error(f"Failed to encrypt for PostgreSQL BYTEA: {e}")
            raise

    def _decrypt_from_postgresql_bytea(self, data: Any) -> Any:
        """Decrypt data from PostgreSQL BYTEA format"""
        try:
            # Handle different input formats
            if isinstance(data, str):
                # Check if it's PostgreSQL BYTEA hex format (\x...)
                if data.startswith('\\x') and len(data) > 2:
                    hex_part = data[2:]  # Remove \x prefix
                    if len(hex_part) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in hex_part):
                        encrypted_bytes = bytes.fromhex(hex_part)
                    else:
                        raise ValueError(f"Invalid PostgreSQL BYTEA hex format: {data}")
                # Check if it's pure hex string
                elif len(data) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in data):
                    encrypted_bytes = bytes.fromhex(data)
                else:
                    raise ValueError(f"Unsupported BYTEA format: {data}")
            elif isinstance(data, bytes):
                encrypted_bytes = data
            elif isinstance(data, memoryview):
                encrypted_bytes = data.tobytes()
            else:
                raise ValueError(f"Unsupported data type for BYTEA decryption: {type(data)}")

            # Decrypt using CLWE
            decrypted_str = clwe_encryptor.decrypt_value(encrypted_bytes, self.encryption_key)

            # Try to parse as JSON, otherwise return as string
            try:
                return json.loads(decrypted_str)
            except (json.JSONDecodeError, TypeError):
                return decrypted_str

        except Exception as e:
            logger.error(f"Failed to decrypt from PostgreSQL BYTEA: {e}")
            raise

    def _enhance_postgresql_schema(self, schema_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance schema data with PostgreSQL-specific information"""
        enhanced_schema = schema_data.copy()

        # Add PostgreSQL-specific metadata
        enhanced_schema["postgresql_metadata"] = {
            "bytea_columns": [],
            "array_columns": [],
            "json_columns": [],
            "enum_types": [],
            "composite_types": [],
            "domains": []
        }

        # Analyze tables for PostgreSQL-specific features
        for table_name, table_info in schema_data.get('tables', {}).items():
            for col_name, col_info in table_info.get('columns', {}).items():
                data_type = str(col_info.get('type', '')).upper()

                # Identify BYTEA columns
                if 'BYTEA' in data_type:
                    enhanced_schema["postgresql_metadata"]["bytea_columns"].append({
                        "table": table_name,
                        "column": col_name,
                        "encrypted": True
                    })

                # Identify array columns
                if data_type.endswith('[]'):
                    enhanced_schema["postgresql_metadata"]["array_columns"].append({
                        "table": table_name,
                        "column": col_name,
                        "element_type": data_type[:-2]
                    })

                # Identify JSON columns
                if 'JSON' in data_type:
                    enhanced_schema["postgresql_metadata"]["json_columns"].append({
                        "table": table_name,
                        "column": col_name,
                        "json_type": data_type
                    })

        return enhanced_schema

    def _restore_postgresql_schema(self, decrypted_schema: Dict[str, Any]) -> Dict[str, Any]:
        """Restore PostgreSQL-specific features to decrypted schema"""
        restored_schema = decrypted_schema.copy()

        # Add PostgreSQL-specific query helpers
        postgresql_metadata = decrypted_schema.get("postgresql_metadata", {})

        # Generate BYTEA-specific query patterns
        if postgresql_metadata.get("bytea_columns"):
            restored_schema["postgresql_helpers"] = {
                "bytea_insert_pattern": "INSERT INTO {table} ({columns}) VALUES ({values})",
                "bytea_select_pattern": "SELECT {columns} FROM {table}",
                "bytea_update_pattern": "UPDATE {table} SET {column} = {value} WHERE {condition}"
            }

        return restored_schema

    def generate_postgresql_bytea_query(self, table_name: str, operation: str, columns: List[str] = None) -> str:
        """
        Generate PostgreSQL query optimized for BYTEA operations

        Args:
            table_name: Name of the table
            operation: Type of operation (SELECT, INSERT, UPDATE)
            columns: List of columns involved

        Returns:
            Optimized SQL query string
        """
        try:
            if operation.upper() == "SELECT":
                if columns:
                    cols_str = ', '.join(columns)
                else:
                    cols_str = '*'
                return f"SELECT {cols_str} FROM {table_name}"

            elif operation.upper() == "INSERT":
                if not columns:
                    raise ValueError("Columns required for INSERT operation")
                cols_str = ', '.join(columns)
                placeholders = ', '.join([f'${i+1}' for i in range(len(columns))])
                return f"INSERT INTO {table_name} ({cols_str}) VALUES ({placeholders})"

            elif operation.upper() == "UPDATE":
                if not columns:
                    raise ValueError("Columns required for UPDATE operation")
                set_clause = ', '.join([f"{col} = ${i+1}" for i, col in enumerate(columns)])
                return f"UPDATE {table_name} SET {set_clause} WHERE id = $%d" % (len(columns) + 1)

            else:
                raise ValueError(f"Unsupported operation: {operation}")

        except Exception as e:
            logger.error(f"Failed to generate PostgreSQL BYTEA query: {e}")
            raise

    def validate_postgresql_bytea_data(self, data: Any) -> Dict[str, Any]:
        """
        Validate data for PostgreSQL BYTEA compatibility

        Args:
            data: Data to validate

        Returns:
            Validation result with recommendations
        """
        validation_result = {
            "valid": True,
            "warnings": [],
            "recommendations": [],
            "bytea_compatible": True
        }

        try:
            # Check data size (PostgreSQL BYTEA has practical limits)
            if isinstance(data, (bytes, str)):
                data_size = len(data) if isinstance(data, bytes) else len(data.encode('utf-8'))
                if data_size > 100 * 1024 * 1024:  # 100MB limit
                    validation_result["warnings"].append("Data size exceeds recommended limit for BYTEA")
                    validation_result["recommendations"].append("Consider using Large Object storage for data > 100MB")

            # Check for null bytes that might cause issues
            if isinstance(data, bytes) and b'\x00' in data:
                validation_result["warnings"].append("Data contains null bytes which may cause issues")
                validation_result["recommendations"].append("Consider base64 encoding for data with null bytes")

            # Check for high Unicode characters
            if isinstance(data, str):
                high_unicode = [ord(c) for c in data if ord(c) > 0xFFFF]
                if high_unicode:
                    validation_result["warnings"].append(f"Data contains {len(high_unicode)} high Unicode characters")
                    validation_result["recommendations"].append("Ensure proper UTF-8 encoding for Unicode data")

        except Exception as e:
            validation_result["valid"] = False
            validation_result["error"] = str(e)

        return validation_result


# Global schema encryption service instance
schema_encryption_service = SchemaEncryptionService()