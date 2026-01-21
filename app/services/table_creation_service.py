"""
CryptoPIX Bridge - Interactive Table Creation Service
Handles CREATE TABLE with encryption configuration dialog
"""

import logging
import re
from typing import Dict, Any, List, Tuple, Optional
from sqlalchemy import create_engine, text, inspect
from app.core.encryption import clwe_encryptor
from app.services.sql_translator import sql_translator

logger = logging.getLogger(__name__)


class TableCreationService:
    """Service for interactive table creation with encryption configuration"""

    def __init__(self):
        self.supported_types = [
            'INT', 'INTEGER', 'BIGINT', 'SMALLINT', 'TINYINT',
            'VARCHAR', 'CHAR', 'TEXT', 'MEDIUMTEXT', 'LONGTEXT',
            'DECIMAL', 'FLOAT', 'DOUBLE',
            'DATE', 'DATETIME', 'TIMESTAMP', 'TIME',
            'BOOLEAN', 'BOOL',
            'BLOB', 'MEDIUMBLOB', 'LONGBLOB',
            'JSON'
        ]

    def parse_create_table_statement(self, sql: str) -> Dict[str, Any]:
        """
        Parse CREATE TABLE statement to extract table name and columns
        
        Args:
            sql: CREATE TABLE SQL statement
            
        Returns:
            Dict with table_name, columns, and parsed structure
        """
        try:
            # Remove comments and normalize whitespace
            sql = re.sub(r'--.*$', '', sql, flags=re.MULTILINE)
            sql = re.sub(r'/\*.*?\*/', '', sql, flags=re.DOTALL)
            sql = ' '.join(sql.split())

            # Extract table name
            table_match = re.search(
                r'CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?`?(\w+)`?',
                sql,
                re.IGNORECASE
            )
            if not table_match:
                raise ValueError("Could not parse table name from CREATE TABLE statement")

            table_name = table_match.group(1)

            # Extract column definitions (everything between parentheses)
            columns_match = re.search(r'\((.*)\)', sql, re.DOTALL | re.IGNORECASE)
            if not columns_match:
                raise ValueError("Could not parse column definitions")

            columns_text = columns_match.group(1)

            # Parse individual columns
            columns = []
            constraints = []
            
            # Split by comma, but be careful with nested parentheses
            parts = self._split_column_definitions(columns_text)

            for part in parts:
                part = part.strip()
                if not part:
                    continue

                # Check if this is a constraint (must start with keyword, not just contain it)
                upper_part = part.upper()
                is_constraint = False
                for keyword in ['CONSTRAINT', 'PRIMARY KEY', 'FOREIGN KEY', 'UNIQUE', 'INDEX', 'KEY', 'CHECK', 'FULLTEXT']:
                    if upper_part.startswith(keyword):
                        is_constraint = True
                        break
                
                if is_constraint:
                    constraints.append(part)
                    continue

                # Parse column definition
                column_info = self._parse_column_definition(part)
                if column_info:
                    columns.append(column_info)

            return {
                'table_name': table_name,
                'columns': columns,
                'constraints': constraints,
                'original_sql': sql
            }

        except Exception as e:
            logger.error(f"Error parsing CREATE TABLE statement: {e}")
            raise ValueError(f"Failed to parse CREATE TABLE statement: {str(e)}")

    def _split_column_definitions(self, text: str) -> List[str]:
        """Split column definitions by comma, respecting parentheses"""
        parts = []
        current = []
        paren_depth = 0

        for char in text:
            if char == '(':
                paren_depth += 1
            elif char == ')':
                paren_depth -= 1
            elif char == ',' and paren_depth == 0:
                parts.append(''.join(current))
                current = []
                continue
            current.append(char)

        if current:
            parts.append(''.join(current))

        return parts

    def _parse_column_definition(self, definition: str) -> Optional[Dict[str, Any]]:
        """Parse a single column definition"""
        try:
            # Match: column_name data_type(size) [NOT NULL] [DEFAULT value] [AUTO_INCREMENT] etc.
            # Updated regex to be more robust
            match = re.match(
                r'`?(\w+)`?\s+([A-Z0-9_]+)(?:\(([^)]+)\))?\s*(.*)',
                definition.strip(),
                re.IGNORECASE
            )

            if not match:
                # Basic fallback for simple cases if regex fails
                parts = definition.strip().split()
                if len(parts) >= 2:
                    return {
                        'name': parts[0].strip('`'),
                        'data_type': parts[1].upper(),
                        'size': None,
                        'nullable': True,
                        'auto_increment': False,
                        'primary_key': False,
                        'unique': False,
                        'default': None,
                        'encryptable': False,
                        'full_definition': definition.strip()
                    }
                return None

            column_name = match.group(1)
            data_type = match.group(2).upper()
            size = match.group(3)
            modifiers = match.group(4).upper() if match.group(4) else ''

            # Determine if column can be encrypted (text-based types)
            encryptable = data_type in ['VARCHAR', 'CHAR', 'TEXT', 'MEDIUMTEXT', 'LONGTEXT']

            return {
                'name': column_name,
                'data_type': data_type,
                'size': size,
                'nullable': 'NOT NULL' not in modifiers,
                'auto_increment': 'AUTO_INCREMENT' in modifiers,
                'primary_key': 'PRIMARY KEY' in modifiers,
                'unique': 'UNIQUE' in modifiers,
                'default': self._extract_default(modifiers),
                'encryptable': encryptable,
                'full_definition': definition.strip()
            }

        except Exception as e:
            logger.warning(f"Could not parse column definition '{definition}': {e}")
            return None

    def _extract_default(self, modifiers: str) -> Optional[str]:
        """Extract DEFAULT value from modifiers"""
        default_match = re.search(r'DEFAULT\s+([^\s,]+)', modifiers, re.IGNORECASE)
        if default_match:
            return default_match.group(1).strip("'\"")
        return None

    def create_encrypted_table(
        self,
        original_sql: str,
        table_config: Dict[str, Any],
        source_db_url: str,
        encrypted_db_url: str,
        db_id: str
    ) -> Dict[str, Any]:
        """
        Create table in both source and encrypted databases with proper configuration
        
        Args:
            original_sql: Original CREATE TABLE statement
            table_config: Configuration with encrypted_columns list
            source_db_url: Source database URL
            encrypted_db_url: Encrypted database URL
            db_id: Database ID for state management
            
        Returns:
            Dict with success status and details
        """
        try:
            table_name = table_config['table_name']
            encrypted_columns = table_config.get('encrypted_columns', [])

            logger.info(f"Creating table '{table_name}' with {len(encrypted_columns)} encrypted columns")

            # Step 1: Create table in source database (original schema)
            logger.info(f"Creating table in source database: {table_name}")
            source_engine = create_engine(source_db_url)
            try:
                with source_engine.connect() as conn:
                    conn.execute(text(original_sql))
                    conn.commit()
                logger.info(f"✓ Table '{table_name}' created in source database")
            finally:
                source_engine.dispose()

            # Step 2: Generate encrypted schema
            encrypted_sql = self._generate_encrypted_schema(
                original_sql,
                table_config
            )

            # Step 3: Create table in encrypted database
            logger.info(f"Creating encrypted table in encrypted database: {table_name}")
            encrypted_engine = create_engine(encrypted_db_url)
            try:
                with encrypted_engine.connect() as conn:
                    conn.execute(text(encrypted_sql))
                    conn.commit()
                logger.info(f"✓ Encrypted table '{table_name}' created in encrypted database")
            finally:
                encrypted_engine.dispose()

            # Step 4: Update migration state AND all schema files
            self._update_all_schema_files(
                db_id,
                table_name,
                table_config,
                encrypted_columns
            )

            # Step 5: Register with SQL translator
            self._register_table_mapping(
                table_name,
                table_config,
                encrypted_columns
            )

            return {
                'success': True,
                'table_name': table_name,
                'encrypted_columns': encrypted_columns,
                'message': f"Table '{table_name}' created successfully with {len(encrypted_columns)} encrypted columns",
                'original_sql': original_sql,
                'encrypted_sql': encrypted_sql
            }

        except Exception as e:
            logger.error(f"Error creating encrypted table: {e}")
            # Attempt rollback
            try:
                self._rollback_table_creation(table_name, source_db_url, encrypted_db_url)
            except:
                pass
            
            return {
                'success': False,
                'error': f"Failed to create table: {str(e)}"
            }

    def _generate_encrypted_schema(
        self,
        original_sql: str,
        table_config: Dict[str, Any]
    ) -> str:
        """
        Generate encrypted schema SQL from original CREATE TABLE statement
        
        Encrypted columns are converted to TEXT/BLOB
        Tag columns are added for encrypted columns
        """
        table_name = table_config['table_name']
        columns = table_config['columns']
        encrypted_columns = table_config.get('encrypted_columns', [])
        constraints = table_config.get('constraints', [])

        # Build new column definitions
        new_columns = []

        for col in columns:
            col_name = col['name']
            
            if col_name in encrypted_columns:
                # Encrypted column: convert to TEXT
                new_columns.append(f"`{col_name}` TEXT")
                # Add tag column
                new_columns.append(f"`tag_{col_name}` VARCHAR(255)")
            else:
                # Keep original definition
                new_columns.append(col['full_definition'])

        # Combine columns and constraints
        all_definitions = new_columns + constraints

        # Build final SQL
        encrypted_sql = f"CREATE TABLE `{table_name}` (\n  "
        encrypted_sql += ",\n  ".join(all_definitions)
        encrypted_sql += "\n)"

        return encrypted_sql

    def _update_all_schema_files(
        self,
        db_id: str,
        table_name: str,
        table_config: Dict[str, Any],
        encrypted_columns: List[str]
    ):
        """Update all schema files including migration_state, original_schema, encrypted_schema, mappings"""
        try:
            # 1. Update Migration State (Active Config)
            self._update_migration_state(db_id, table_name, table_config, encrypted_columns)
            
            # 2. Update Static Schema Files
            # Get schema folder path
            from app.services.database_registry import database_registry
            db_info = database_registry.get_database(db_id)
            if not db_info or 'schema_folder' not in db_info:
                logger.warning(f"Could not find schema folder for db {db_id}, skipping static file updates")
                return
            
            schema_folder = db_info['schema_folder']
            if not os.path.isabs(schema_folder):
                schema_folder = os.path.abspath(schema_folder)
            
            if not os.path.exists(schema_folder):
                logger.warning(f"Schema folder {schema_folder} does not exist")
                return

            # Update original_schema.json
            self._update_original_schema_file(schema_folder, table_name, table_config)
            
            # Update encrypted_schema.json
            self._update_encrypted_schema_file(schema_folder, table_name, table_config, encrypted_columns)
            
            # Update mappings.json
            self._update_mappings_file(schema_folder, table_name, table_config, encrypted_columns)
            
            logger.info("✓ All schema files updated successfully")

        except Exception as e:
            logger.error(f"Error updating schema files: {e}")

    def _update_original_schema_file(self, schema_folder: str, table_name: str, table_config: Dict[str, Any]):
        """Update original_schema.json"""
        file_path = os.path.join(schema_folder, 'original_schema.json')
        if not os.path.exists(file_path):
            return

        try:
            with open(file_path, 'r') as f:
                data = json.load(f)

            # Build column definitions
            columns = []
            for col in table_config['columns']:
                type_str = col['data_type']
                if col['size']:
                    type_str += f"({col['size']})"
                
                columns.append({
                    "name": col['name'],
                    "type": type_str,
                    "nullable": col['nullable'],
                    "default": col['default'],
                    "primary_key": col['primary_key']
                })

            # Add/Update table
            if 'tables' not in data:
                data['tables'] = {}
            
            data['tables'][table_name] = {"columns": columns}

            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
                
            logger.info(f"Updated original_schema.json for {table_name}")

        except Exception as e:
            logger.error(f"Failed to update original_schema.json: {e}")

    def _update_encrypted_schema_file(self, schema_folder: str, table_name: str, table_config: Dict[str, Any], encrypted_columns: List[str]):
        """Update encrypted_schema.json"""
        file_path = os.path.join(schema_folder, 'encrypted_schema.json')
        if not os.path.exists(file_path):
            return

        try:
            with open(file_path, 'r') as f:
                data = json.load(f)

            # Build encrypted schema columns
            columns = []
            for col in table_config['columns']:
                col_name = col['name']
                is_encrypted = col_name in encrypted_columns
                
                if is_encrypted:
                    # Encrypted column becomes TEXT
                    columns.append({
                        "name": col_name,
                        "type": "TEXT",
                        "nullable": col['nullable'],
                        "default": None, # Encrypted usually removes default
                        "primary_key": False
                    })
                    # Add tag column
                    columns.append({
                        "name": f"tag_{col_name}",
                        "type": "VARCHAR(255)",
                        "nullable": True,
                        "default": None,
                        "primary_key": False
                    })
                else:
                    # Normal column
                    type_str = col['data_type']
                    if col['size']:
                        type_str += f"({col['size']})"
                        
                    columns.append({
                        "name": col_name,
                        "type": type_str,
                        "nullable": col['nullable'],
                        "default": col['default'],
                        "primary_key": col['primary_key']
                    })

            # Add/Update table
            if 'tables' not in data:
                data['tables'] = {}
            
            data['tables'][table_name] = {"columns": columns}

            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
                
            logger.info(f"Updated encrypted_schema.json for {table_name}")

        except Exception as e:
            logger.error(f"Failed to update encrypted_schema.json: {e}")

    def _update_mappings_file(self, schema_folder: str, table_name: str, table_config: Dict[str, Any], encrypted_columns: List[str]):
        """Update mappings.json"""
        file_path = os.path.join(schema_folder, 'mappings.json')
        if not os.path.exists(file_path):
            return

        try:
            with open(file_path, 'r') as f:
                data = json.load(f)

            encrypted_cols_map = {}
            non_encrypted_cols = []
            primary_key = None

            for col in table_config['columns']:
                col_name = col['name']
                if col['primary_key']:
                    primary_key = col_name

                # Construct full type string
                type_str = col['data_type']
                if col['size']:
                    type_str += f"({col['size']})"

                if col_name in encrypted_columns:
                    encrypted_cols_map[col_name] = {
                        "original_name": col_name,
                        "encrypted_name": col_name,
                        "tag_name": f"tag_{col_name}",
                        "is_encrypted": True,
                        "is_hashed": False,
                        "data_type": type_str,
                        "supports_ordering": True,
                        "supports_ranges": True
                    }
                else:
                    non_encrypted_cols.append(col_name)

            # Add/Update table mapping
            if 'table_mappings' not in data:
                data['table_mappings'] = {}

            data['table_mappings'][table_name] = {
                "original_name": table_name,
                "encrypted_columns": encrypted_cols_map,
                "primary_key": primary_key,
                "non_encrypted_columns": non_encrypted_cols
            }

            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
                
            logger.info(f"Updated mappings.json for {table_name}")

        except Exception as e:
            logger.error(f"Failed to update mappings.json: {e}")

    def _update_migration_state(
        self,
        db_id: str,
        table_name: str,
        table_config: Dict[str, Any],
        encrypted_columns: List[str]
    ):
        """Update migration state files with new table configuration"""
        try:
            # Import here to avoid circular imports
            from app.main import load_migration_state_from_files, save_migration_state_to_files
            
            # Load existing state
            migration_state = load_migration_state_from_files(db_id=db_id)
            
            if not migration_state:
                logger.warning(f"No migration state found for db_id: {db_id}")
                return

            # Initialize table_configs if not exists
            if 'table_configs' not in migration_state:
                migration_state['table_configs'] = {}

            # Build column configuration
            column_config = {}
            for col in table_config['columns']:
                col_name = col['name']
                column_config[col_name] = {
                    'type': 'encrypt' if col_name in encrypted_columns else 'normal',
                    'data_type': col['data_type'],
                    'size': col.get('size'),
                    'nullable': col.get('nullable', True),
                    'auto_increment': col.get('auto_increment', False),
                    'primary_key': col.get('primary_key', False)
                }

            # Add table configuration
            migration_state['table_configs'][table_name] = column_config

            # Save updated state
            save_migration_state_to_files(migration_state, db_id=db_id)
            logger.info(f"✓ Migration state updated for table '{table_name}'")

        except Exception as e:
            logger.error(f"Error updating migration state: {e}")
            raise

    def _register_table_mapping(
        self,
        table_name: str,
        table_config: Dict[str, Any],
        encrypted_columns: List[str]
    ):
        """Register table mapping with SQL translator"""
        try:
            # Register with SQL translator
            from app.services.sql_translator import sql_translator
            
            # Build column mappings
            encrypted_col_info = {}
            for col in table_config['columns']:
                if col['name'] in encrypted_columns:
                    encrypted_col_info[col['name']] = {
                        'data_type': col['data_type'],
                        'size': col.get('size')
                    }

            # Register table
            sql_translator.register_table(table_name, encrypted_col_info)
            logger.info(f"✓ Table mapping registered for '{table_name}'")

        except Exception as e:
            logger.error(f"Error registering table mapping: {e}")
            # Non-critical, don't raise

    def _rollback_table_creation(
        self,
        table_name: str,
        source_db_url: str,
        encrypted_db_url: str
    ):
        """Attempt to rollback table creation on error"""
        logger.warning(f"Attempting rollback for table '{table_name}'")
        
        try:
            source_engine = create_engine(source_db_url)
            with source_engine.connect() as conn:
                conn.execute(text(f"DROP TABLE IF EXISTS `{table_name}`"))
                conn.commit()
            source_engine.dispose()
        except:
            pass

        try:
            encrypted_engine = create_engine(encrypted_db_url)
            with source_engine.connect() as conn:
                conn.execute(text(f"DROP TABLE IF EXISTS `{table_name}`"))
                conn.commit()
            encrypted_engine.dispose()
        except:
            pass


# Global instance
table_creation_service = TableCreationService()
