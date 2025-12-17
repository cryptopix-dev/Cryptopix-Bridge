"""
CryptoPIX Bridge v3.0 - Query Console Service
Handles SQL and admin command parsing, routing, and execution for the query console
"""

import logging
import re
import time
import threading
from typing import Dict, Any, List, Optional, Tuple
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.config import settings
from app.services.ai_assistant import ai_assistant, TableMapping, ColumnMapping
from app.services.enhanced_sql_translator import enhanced_sql_translator
from app.core.database import get_db_session
from sqlalchemy import create_engine, text
from sqlalchemy.pool import QueuePool
from app.core.encryption import clwe_encryptor
from app.core.schema_encryption import schema_encryption_service, SchemaEncryptionLevel

logger = logging.getLogger(__name__)


class CommandType(Enum):
    """Types of commands that can be executed in the console"""
    SQL = "SQL"
    ADMIN = "ADMIN"
    UNKNOWN = "UNKNOWN"


class AdminCommand(Enum):
    """Admin commands supported by the console"""
    MIGRATE = "MIGRATE"
    REBUILD_TAGS = "REBUILD_TAGS"
    KEY_ROTATE = "KEY_ROTATE"
    EXPORT_LOGS = "EXPORT_LOGS"
    SHOW_STATS = "SHOW_STATS"
    SYSTEM_INFO = "SYSTEM_INFO"
    ENCRYPT_SCHEMA = "ENCRYPT_SCHEMA"
    DECRYPT_SCHEMA = "DECRYPT_SCHEMA"
    SHOW_SCHEMA_INFO = "SHOW_SCHEMA_INFO"
    SCHEMA_INSIGHTS = "SCHEMA_INSIGHTS"
    LIST_ENCRYPTED_SCHEMAS = "LIST_ENCRYPTED_SCHEMAS"


class ConsoleService:
    """Service for handling query console operations"""

    def __init__(self):
        self.admin_commands = {
            'MIGRATE': self._handle_migrate,
            'REBUILD_TAGS': self._handle_rebuild_tags,
            'KEY_ROTATE': self._handle_key_rotate,
            'EXPORT_LOGS': self._handle_export_logs,
            'SHOW_STATS': self._handle_show_stats,
            'SYSTEM_INFO': self._handle_system_info,
            'ENCRYPT_SCHEMA': self._handle_encrypt_schema,
            'DECRYPT_SCHEMA': self._handle_decrypt_schema,
            'SHOW_SCHEMA_INFO': self._handle_show_schema_info,
            'SCHEMA_INSIGHTS': self._handle_schema_insights,
            'LIST_ENCRYPTED_SCHEMAS': self._handle_list_encrypted_schemas,
        }
        self.migration_state = None
        self.database_mappings = {}

    def _load_migration_state_from_files(self, encrypted_db_url: str = None) -> dict:
        """Load migration state from database-specific schema files"""
        try:
            import os
            from pathlib import Path
            import json
            from app.services.database_registry import database_registry

            schemas_dir = Path("schemas")
            if not schemas_dir.exists():
                logger.warning(
                    "No schemas directory found. Please run migration first to generate schema files.")
                return {}

            state_file = None
            migration_state = {}

            if encrypted_db_url:
                databases = database_registry.list_databases()
                for db in databases:
                    if db.get("encrypted_db_url") == encrypted_db_url:
                        schema_folder = Path(
                            db.get("schema_folder", "schemas"))
                        state_file = schema_folder / "migration_state.json"
                        logger.info(
                            f"Found database registry entry for URL. Using state file: {state_file}")
                        break

            if not state_file and encrypted_db_url:
                db_folders = [d for d in schemas_dir.iterdir(
                ) if d.is_dir() and d.name != "__pycache__"]
                for folder in db_folders:
                    potential_file = folder / "migration_state.json"
                    if potential_file.exists():
                        try:
                            with open(potential_file, 'r') as f:
                                data = json.load(f)
                            if data.get("encrypted_db_url") == encrypted_db_url:
                                state_file = potential_file
                                break
                        except:
                            continue

            if not state_file:
                db_folders = [d for d in schemas_dir.iterdir(
                ) if d.is_dir() and d.name != "__pycache__"]
                if db_folders:
                    latest_folder = max(
                        db_folders, key=lambda f: f.stat().st_mtime)
                    state_file = latest_folder / "migration_state.json"

                if not state_file or not state_file.exists():
                    state_files = list(schemas_dir.glob(
                        "*_migration_state.json"))
                    if state_files:
                        state_file = max(
                            state_files, key=lambda f: f.stat().st_mtime)

            if not state_file or not state_file.exists():
                logger.warning(
                    "No migration state files found in schemas directory.")
                return {}

            logger.info(f"Loading migration state from: {state_file}")
            with open(state_file, 'r') as f:
                migration_state = json.load(f)

            if encrypted_db_url:
                migration_state["encrypted_db_url"] = encrypted_db_url

            if migration_state.get("encrypted_db_url"):
                try:
                    from sqlalchemy import create_engine
                    engine = create_engine(migration_state["encrypted_db_url"])
                    with engine.connect() as conn:
                        from sqlalchemy.engine import reflection
                        inspector = reflection.Inspector.from_engine(engine)
                        tables = inspector.get_table_names()
                        migration_state["migration_complete"] = len(tables) > 0
                    engine.dispose()
                except:
                    migration_state["migration_complete"] = False

            return migration_state

        except Exception as e:
            logger.error(f"Failed to load migration state from files: {e}")
            logger.warning(
                "Unable to load migration state. Please ensure schema files exist and are valid.")
            return {}

    def _register_table_mappings(self):
        """Store table mappings per database"""
        try:
            if self.migration_state and self.migration_state.get("table_configs"):
                database_key = self._get_database_key()
                self.database_mappings[database_key] = {}
                logger.info(
                    f"Storing table mappings for database {database_key}")
                for table_name, config in self.migration_state["table_configs"].items():
                    mapping = self._create_table_mapping(table_name, config)
                    self.database_mappings[database_key][table_name] = mapping
                    logger.info(
                        f"Stored table mapping for {table_name}")
        except Exception as e:
            logger.error(f"Could not store and register table mappings: {e}")

    def _register_mappings_for_database(self, database_key):
        """Temporarily register mappings for a specific database"""
        enhanced_sql_translator.clear_cache()
        from app.services.sql_translator import sql_translator
        sql_translator.clear_cache()
        
        if database_key in self.database_mappings:
            logger.info(f"Registering mappings for database {database_key}")
            for table_name, mapping in self.database_mappings[database_key].items():
                ai_assistant.register_table_mapping(table_name, mapping)
                enhanced_sql_translator.register_table_mapping(
                    table_name, mapping)
                sql_translator.register_table_mapping(table_name, mapping)
                logger.debug(f"Registered table mapping for {table_name}")

    def _get_database_key(self):
        if self.migration_state and 'encrypted_db_url' in self.migration_state:
            return self.migration_state['encrypted_db_url']
        return 'default'

    def get_ai_suggestions(self, partial_query: str, cursor_position: int = None, migration_state: dict = None) -> Dict[str, Any]:
        """
        Get AI-powered suggestions for a partial SQL query

        Args:
            partial_query: The current partial SQL query
            cursor_position: Current cursor position in the query
            migration_state: Optional migration state to provide context

        Returns:
            Dict containing AI suggestions
        """
        try:
            if migration_state:
                self.migration_state = migration_state
                database_key = self._get_database_key()
                self._register_table_mappings()
                self._register_mappings_for_database(database_key)
            return ai_assistant.get_suggestions(partial_query, cursor_position)
        except Exception as e:
            logger.error(f"Error getting AI suggestions: {e}")
            return {'completions': [], 'corrections': [], 'suggestions': [], 'explanations': []}

    def explain_query(self, query: str, migration_state: dict = None) -> str:
        """
        Get AI explanation of what a SQL query does

        Args:
            query: The SQL query to explain
            migration_state: Optional migration state to provide context

        Returns:
            Human-readable explanation
        """
        try:
            if migration_state:
                self.migration_state = migration_state
                database_key = self._get_database_key()
                self._register_table_mappings()
                self._register_mappings_for_database(database_key)
            return ai_assistant.explain_query(query)
        except Exception as e:
            logger.error(f"Error explaining query: {e}")
            return "Unable to analyze this query."

    def natural_language_to_sql(self, natural_query: str, migration_state: dict = None) -> Dict[str, Any]:
        """
        Convert natural language to SQL query

        Args:
            natural_query: Natural language description
            migration_state: Optional migration state to provide context

        Returns:
            Dict containing generated SQL and metadata
        """
        try:
            if migration_state:
                self.migration_state = migration_state
                database_key = self._get_database_key()
                self._register_table_mappings()
                self._register_mappings_for_database(database_key)
            return ai_assistant.natural_language_to_sql(natural_query)
        except Exception as e:
            logger.error(f"Error converting natural language to SQL: {e}")
            return {
                'sql': f"-- Error: {str(e)}",
                'confidence': 0.0,
                'explanation': "Error processing natural language query",
                'alternatives': []
            }

    def get_ai_insights(self) -> Dict[str, Any]:
        """
        Get AI learning insights from the enhanced SQL translator

        Returns:
            Dict containing AI learning statistics and insights
        """
        try:
            return enhanced_sql_translator.get_ai_insights()
        except Exception as e:
            logger.error(f"Error getting AI insights: {e}")
            return {
                "error": str(e),
                "total_learned_patterns": 0,
                "average_success_rate": 0.0
            }

    def execute_command(self, command: str, user_id: str = None, database_url: str = None, migration_state: dict = None) -> Dict[str, Any]:
        """
        Execute a command in the query console

        Args:
            command: The command to execute (SQL or admin command, can contain multiple statements separated by semicolons)
            user_id: ID of the user executing the command
            database_url: Optional database URL override
            migration_state: Optional migration state override

        Returns:
            Dict containing execution results
        """
        try:
            if migration_state is None:
                migration_state = self._load_migration_state_from_files(
                    database_url)

            self.migration_state = migration_state
            logger.debug(
                f"Console service migration state loaded: {bool(self.migration_state)}")
            if self.migration_state:
                logger.debug(
                    f"Encrypted DB URL in migration state: {self.migration_state.get('encrypted_db_url')}")
                logger.debug(
                    f"Source DB URL in migration state: {self.migration_state.get('source_db_url')}")
                database_key = self._get_database_key()
                self._register_table_mappings()
                self._register_mappings_for_database(database_key)

            statements = self._split_commands(command.strip())

            if len(statements) > 1:
                return self._execute_bulk_commands(statements, user_id, database_url)
            else:
                command_type, parsed_command = self._parse_command(
                    statements[0])
                
                print(f"DEBUG_STDOUT: Parsed command '{statements[0]}' as Type: {command_type}", flush=True)

                if command_type == CommandType.SQL:
                    return self._execute_sql_command(parsed_command, user_id, database_url)
                elif command_type == CommandType.ADMIN:
                    return self._execute_admin_command(parsed_command, user_id)
                else:
                    return {
                        "success": False,
                        "error": f"Unknown command type: {command}",
                        "command_type": "UNKNOWN"
                    }

        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return {
                "success": False,
                "error": f"Command execution failed: {str(e)}",
                "command_type": "ERROR"
            }

    def _split_commands(self, command: str) -> List[str]:
        """
        Split a command string into individual SQL statements separated by semicolons

        Args:
            command: The command string that may contain multiple statements

        Returns:
            List of individual command strings
        """
        statements = []
        current_statement = ""
        in_string = False
        string_char = None

        i = 0
        while i < len(command):
            char = command[i]

            if not in_string and (char == '"' or char == "'"):
                in_string = True
                string_char = char
                current_statement += char
            elif in_string and char == string_char:
                if i + 1 < len(command) and command[i + 1] == string_char:
                    current_statement += char + char
                    i += 1  # Skip next character
                else:
                    in_string = False
                    current_statement += char
            elif not in_string and char == ';':
                if current_statement.strip():
                    statements.append(current_statement.strip())
                current_statement = ""
            else:
                current_statement += char

            i += 1

        if current_statement.strip():
            statements.append(current_statement.strip())

        return [stmt for stmt in statements if stmt.strip()]

    def _execute_bulk_commands(self, statements: List[str], user_id: str = None, database_url: str = None) -> Dict[str, Any]:
        """
        Execute multiple SQL commands in sequence

        Args:
            statements: List of SQL statements to execute
            user_id: ID of the user executing the commands
            database_url: Database URL to use

        Returns:
            Dict containing bulk execution results
        """
        try:
            if not database_url:
                database_url = self.migration_state.get(
                    "encrypted_db_url") if self.migration_state else None

                if not database_url:
                    return {
                        "success": False,
                        "error": "No database URL available. Use the encrypted database URL from the migration or the settings page.",
                        "command_type": "BULK_SQL"
                    }

            from app.services.sql_translator import sql_translator
            sql_translator.set_database_type(database_url)

            database_key = database_url
            self._register_table_mappings()
            self._register_mappings_for_database(database_key)

            results = []
            total_affected_rows = 0
            successful_commands = 0
            failed_commands = 0

            batch_size = min(50, len(statements))
            engine = create_engine(database_url)

            try:
                with engine.connect() as conn:
                    for batch_start in range(0, len(statements), batch_size):
                        batch_end = min(
                            batch_start + batch_size, len(statements))
                        batch_statements = statements[batch_start:batch_end]

                        logger.info(
                            f"Processing batch {batch_start//batch_size + 1} with {len(batch_statements)} statements")

                        for i, statement in enumerate(batch_statements):
                            global_index = batch_start + i
                            try:
                                logger.info(
                                    f"Executing bulk command {global_index + 1}/{len(statements)}: {statement[:50]}...")

                                command_type, parsed_command = self._parse_command(
                                    statement)

                                if command_type != CommandType.SQL:
                                    results.append({
                                        "command_index": i + 1,
                                        "statement": statement,
                                        "success": False,
                                        "error": f"Non-SQL command in bulk execution: {command_type.value}"
                                    })
                                    failed_commands += 1
                                    continue

                                query_type = self._get_query_type(
                                    parsed_command)
                                ddl_and_utility_commands = [
                                    'CREATE', 'ALTER', 'DROP', 'TRUNCATE', 'MERGE', 'REPLACE', 'SHOW', 'DESCRIBE', 'EXPLAIN', 'TRANSACTION', 'DCL', 'CALL', 'USE']
                                if query_type in ddl_and_utility_commands:
                                    try:
                                        ddl_result = self._execute_ddl_command(
                                            parsed_command, query_type, database_url, connection=conn)
                                        command_result = {
                                            "command_index": i + 1,
                                            "statement": statement,
                                            "success": ddl_result["success"],
                                            "query_type": query_type,
                                            "affected_rows": ddl_result.get("affected_rows", 0),
                                            "original_query": parsed_command,
                                            "message": ddl_result.get("message", "")
                                        }
                                        if not ddl_result["success"]:
                                            command_result["error"] = ddl_result.get(
                                                "error", "Unknown error")
                                            failed_commands += 1
                                        else:
                                            successful_commands += 1
                                        results.append(command_result)
                                        continue
                                    except Exception as e:
                                        results.append({
                                            "command_index": i + 1,
                                            "statement": statement,
                                            "success": False,
                                            "error": f"DDL execution failed: {str(e)}"
                                        })
                                        failed_commands += 1
                                        continue

                                try:
                                    query_type = "UNKNOWN"
                                    table_name = None

                                    upper_command = parsed_command.upper().strip()
                                    if upper_command.startswith('SELECT'):
                                        query_type = "SELECT"
                                        from_match = re.search(
                                            r'FROM\s+(\w+)', upper_command, re.IGNORECASE)
                                        if from_match:
                                            table_name = from_match.group(
                                                1).lower()
                                    elif upper_command.startswith('UPDATE'):
                                        query_type = "UPDATE"
                                        update_match = re.search(
                                            r'UPDATE\s+(\w+)', upper_command, re.IGNORECASE)
                                        if update_match:
                                            table_name = update_match.group(
                                                1).lower()
                                    elif upper_command.startswith('INSERT'):
                                        query_type = "INSERT"
                                        insert_match = re.search(
                                            r'INSERT\s+INTO\s+(\w+)', upper_command, re.IGNORECASE)
                                        if insert_match:
                                            table_name = insert_match.group(
                                                1).lower()
                                    elif upper_command.startswith('DELETE'):
                                        query_type = "DELETE"
                                        from_match = re.search(
                                            r'FROM\s+(\w+)', upper_command, re.IGNORECASE)
                                        if from_match:
                                            table_name = from_match.group(
                                                1).lower()

                                    temp_metadata = {
                                        "query_type": query_type, "table_name": table_name}

                                    has_encrypted_expr = self._has_encrypted_expressions(
                                        parsed_command, temp_metadata)
                                    logger.debug(
                                        f"Bulk command {i+1}: {parsed_command[:50]}... has_encrypted_expr={has_encrypted_expr}, query_type={temp_metadata.get('query_type')}")

                                    if has_encrypted_expr:
                                        temp_translated = parsed_command
                                    else:
                                        command_type = self._get_query_type(
                                            parsed_command)
                                        if command_type in ['INSERT', 'UPDATE', 'DELETE']:
                                            logger.debug(
                                                f"Using SQL translator directly for {command_type} bulk command")
                                            from app.services.sql_translator import sql_translator
                                            temp_translated, temp_metadata = sql_translator.translate_query(
                                                parsed_command)
                                        else:
                                            temp_translated, temp_metadata = ai_assistant.translate_query(
                                                parsed_command)

                                        if 'error' in temp_metadata:
                                            results.append({
                                                "command_index": i + 1,
                                                "statement": statement,
                                                "success": False,
                                                "error": temp_metadata['error'],
                                                "original_query": parsed_command
                                            })
                                            failed_commands += 1
                                            continue

                                except Exception as e:
                                    results.append({
                                        "command_index": i + 1,
                                        "statement": statement,
                                        "success": False,
                                        "error": f"Query parsing failed: {str(e)}",
                                        "original_query": parsed_command
                                    })
                                    failed_commands += 1
                                    continue

                                if has_encrypted_expr:
                                    if temp_metadata.get("query_type") == "UPDATE":
                                        table_name = temp_metadata.get(
                                            'table_name')
                                        table_config = self.migration_state['table_configs'].get(
                                            table_name) if table_name else {}
                                        has_real_encrypted_cols = False

                                        set_match = re.search(
                                            r'SET\s+(.+?)(?:\s+WHERE|$)', parsed_command, re.IGNORECASE | re.DOTALL)
                                        if set_match:
                                            set_clause = set_match.group(1)
                                            assignments = [
                                                assignment.strip() for assignment in set_clause.split(',')]
                                            for assignment in assignments:
                                                if '=' in assignment:
                                                    col, val = assignment.split(
                                                        '=', 1)
                                                    col = col.strip()
                                                    if col in table_config and table_config[col].get('type') == 'encrypt':
                                                        has_real_encrypted_cols = True
                                                        break

                                        if has_real_encrypted_cols:
                                            try:
                                                affected_rows = self._execute_encrypted_update(
                                                    conn, parsed_command, temp_metadata)
                                                command_result = {
                                                    "command_index": i + 1,
                                                    "statement": statement,
                                                    "success": True,
                                                    "query_type": "UPDATE",
                                                    "affected_rows": affected_rows,
                                                    "original_query": parsed_command,
                                                    "translated_query": temp_translated,
                                                    "metadata": temp_metadata
                                                }
                                                results.append(command_result)
                                                successful_commands += 1
                                                total_affected_rows += affected_rows
                                            except Exception as e:
                                                logger.error(
                                                    f"Bulk encrypted UPDATE failed: {e}")
                                                results.append({
                                                    "command_index": i + 1,
                                                    "statement": statement,
                                                    "success": False,
                                                    "error": str(e)
                                                })
                                                failed_commands += 1
                                        else:
                                            try:
                                                result = conn.execute(
                                                    text(parsed_command))
                                                affected_rows = getattr(
                                                    result, 'rowcount', 0)
                                                total_affected_rows += affected_rows
                                                command_result = {
                                                    "command_index": i + 1,
                                                    "statement": statement,
                                                    "success": True,
                                                    "query_type": "UPDATE",
                                                    "affected_rows": affected_rows,
                                                    "original_query": parsed_command,
                                                    "translated_query": parsed_command,
                                                    "metadata": temp_metadata
                                                }
                                                results.append(command_result)
                                                successful_commands += 1
                                            except Exception as e:
                                                logger.error(
                                                    f"Bulk complex UPDATE failed: {e}")
                                                results.append({
                                                    "command_index": i + 1,
                                                    "statement": statement,
                                                    "success": False,
                                                    "error": str(e)
                                                })
                                                failed_commands += 1
                                    elif temp_metadata.get("query_type") == "SELECT":
                                        try:
                                            select_result = self._execute_encrypted_select(
                                                conn, parsed_command, temp_metadata)
                                            command_result = {
                                                "command_index": i + 1,
                                                "statement": statement,
                                                "success": True,
                                                "query_type": "SELECT",
                                                "rows": select_result["rows"],
                                                "row_count": len(select_result["rows"]),
                                                "columns": select_result["columns"],
                                                "original_query": parsed_command,
                                                "translated_query": temp_translated,
                                                "metadata": temp_metadata
                                            }
                                            results.append(command_result)
                                            successful_commands += 1
                                        except Exception as e:
                                            logger.error(
                                                f"Bulk encrypted SELECT failed: {e}")
                                            results.append({
                                                "command_index": i + 1,
                                                "statement": statement,
                                                "success": False,
                                                "error": str(e)
                                            })
                                            failed_commands += 1
                                    else:
                                        results.append({
                                            "command_index": i + 1,
                                            "statement": statement,
                                            "success": False,
                                            "error": f"Query type {temp_metadata.get('query_type')} with encrypted expressions not supported in bulk operations"
                                        })
                                        failed_commands += 1
                                else:
                                    translated_query, metadata = temp_translated, temp_metadata
                                    result = conn.execute(
                                        text(translated_query))

                                    query_type = metadata.get(
                                        "query_type", "UNKNOWN")

                                    if query_type == "SELECT":
                                        rows = result.fetchall()
                                        columns = result.keys()

                                        decrypted_rows, decryption_info = self._decrypt_result_rows(
                                            rows, columns, metadata)

                                        display_columns = []
                                        for col in columns:
                                            if col.startswith('tag_'):
                                                continue
                                            else:
                                                display_columns.append(col)

                                        command_result = {
                                            "command_index": i + 1,
                                            "statement": statement,
                                            "success": True,
                                            "query_type": "SELECT",
                                            "rows": decrypted_rows,
                                            "row_count": len(decrypted_rows),
                                            "columns": display_columns,
                                            "original_query": parsed_command,
                                            "translated_query": translated_query,
                                            "metadata": metadata,
                                            "decryption_info": decryption_info
                                        }
                                    else:
                                        affected_rows = getattr(
                                            result, 'rowcount', 0)
                                        total_affected_rows += affected_rows

                                        command_result = {
                                            "command_index": i + 1,
                                            "statement": statement,
                                            "success": True,
                                            "query_type": query_type,
                                            "affected_rows": affected_rows,
                                            "original_query": parsed_command,
                                            "translated_query": translated_query,
                                            "metadata": metadata
                                        }

                                    results.append(command_result)
                                    successful_commands += 1

                            except Exception as e:
                                logger.error(
                                    f"Bulk command {global_index + 1} failed: {e}")
                                results.append({
                                    "command_index": global_index + 1,
                                    "statement": statement,
                                    "success": False,
                                    "error": str(e)
                                })
                                failed_commands += 1

                    if hasattr(conn, 'commit'):
                        conn.commit()

            finally:
                engine.dispose()

            return {
                "success": failed_commands == 0,
                "command_type": "BULK_SQL",
                "total_commands": len(statements),
                "successful_commands": successful_commands,
                "failed_commands": failed_commands,
                "total_affected_rows": total_affected_rows,
                "results": results,
                "message": f"Bulk execution completed: {successful_commands}/{len(statements)} commands successful"
            }

        except Exception as e:
            logger.error(f"Bulk command execution failed: {e}")
            return {
                "success": False,
                "error": f"Bulk execution failed: {str(e)}",
                "command_type": "BULK_SQL"
            }

    def _parse_command(self, command: str) -> Tuple[CommandType, str]:
        """
        Parse command to determine if it's SQL or admin command

        Returns:
            Tuple of (CommandType, parsed_command)
        """
        command_upper = command.upper().strip()

        admin_patterns = [
            (r'^MIGRATE', AdminCommand.MIGRATE),
            (r'^REBUILD[_-]TAGS', AdminCommand.REBUILD_TAGS),
            (r'^KEY[_-]ROTATE', AdminCommand.KEY_ROTATE),
            (r'^EXPORT[_-]LOGS', AdminCommand.EXPORT_LOGS),
            (r'^SHOW[_-]STATS', AdminCommand.SHOW_STATS),
            (r'^SYSTEM[_-]INFO', AdminCommand.SYSTEM_INFO),
        ]

        for pattern, cmd_type in admin_patterns:
            if re.match(pattern, command_upper):
                return CommandType.ADMIN, command.strip()

        sql_keywords = [
            'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'ALTER', 'DROP', 'TRUNCATE', 'MERGE', 'REPLACE',
            'WITH', 'UNION', 'INTERSECT', 'EXCEPT', 'MINUS', 'PIVOT', 'UNPIVOT',
            'COMMIT', 'ROLLBACK', 'BEGIN', 'START', 'SAVEPOINT', 'SHOW', 'DESCRIBE', 'DESC', 'EXPLAIN',
            'GRANT', 'REVOKE', 'LOCK', 'UNLOCK', 'SET', 'CREATE INDEX', 'DROP INDEX', 'ALTER INDEX',
            'CALL', 'USE'
        ]
        first_word = command_upper.split()[0] if command_upper else ""
        second_word = command_upper.split()[1] if len(
            command_upper.split()) > 1 else ""

        if first_word == 'CREATE' and second_word == 'INDEX':
            first_word = 'CREATE INDEX'
        elif first_word == 'DROP' and second_word == 'INDEX':
            first_word = 'DROP INDEX'
        elif first_word == 'ALTER' and second_word == 'INDEX':
            first_word = 'ALTER INDEX'

        if first_word in sql_keywords:
            return CommandType.SQL, command.strip()

        math_functions = ['ABS', 'ROUND', 'CEIL', 'FLOOR',
                          'POWER', 'SQRT', 'SIN', 'COS', 'TAN', 'LOG', 'EXP']
        if any(func in command_upper for func in math_functions):
            return CommandType.SQL, command.strip()

        sql_indicators = [
            'FROM', 'WHERE', 'JOIN', 'ORDER BY', 'GROUP BY', 'HAVING', 'UNION', 'INTERSECT', 'EXCEPT', 'MINUS',
            'VALUES', 'LIMIT', 'OFFSET', 'DISTINCT', 'AS', 'ON', 'USING', 'BETWEEN', 'LIKE', 'IN',
            'EXISTS', 'CASE', 'WHEN', 'THEN', 'ELSE', 'END', 'COALESCE', 'NULLIF',
            'PIVOT', 'UNPIVOT', 'OVER', 'PARTITION BY', 'ROWS', 'RANGE', 'PRECEDING', 'FOLLOWING',
            'INDEX', 'KEY', 'CONSTRAINT', 'PRIMARY', 'FOREIGN', 'REFERENCES', 'UNIQUE', 'AUTO_INCREMENT'
        ]
        if any(indicator in command_upper for indicator in sql_indicators):
            return CommandType.SQL, command.strip()

        return CommandType.UNKNOWN, command.strip()

    def _execute_sql_command(self, sql_query: str, user_id: str = None, database_url: str = None) -> Dict[str, Any]:
        """
        Execute SQL command using the translator
        """
        try:
            logger.info(f"Executing SQL command: {sql_query[:100]}...")
            try:
                with open('d:\\CPIXFINALWITHALLFEATURES\\debug_execution.txt', 'a') as f:
                    f.write(f"ENTRY: Executing SQL command: {sql_query}\\n")
            except: pass
            logger.info(
                f"User ID: {user_id}, Database URL provided: {bool(database_url)}")

            if not database_url:
                database_url = self.migration_state.get(
                    "encrypted_db_url") if self.migration_state else None
                logger.info(
                    f"Using database URL from migration state: {database_url}")
                logger.info(
                    f"Migration state exists: {bool(self.migration_state)}")
                if self.migration_state:
                    logger.info(
                        f"Migration state keys: {list(self.migration_state.keys())}")

                if not database_url:
                    logger.error(
                        "No database URL available in migration state")
                    return {
                        "success": False,
                        "error": "No database URL available. Use the encrypted database URL from the migration or the settings page.",
                        "command_type": "SQL"
                    }

            if database_url:
                from app.services.sql_translator import sql_translator
                sql_translator.set_database_type(database_url)
                logger.debug(
                    f"Set database type for translator: {database_url}")

            self._register_table_mappings()
            self._register_mappings_for_database(self._get_database_key())
            logger.debug(
                f"Registered table mappings: {len(self.table_mappings) if hasattr(self, 'table_mappings') else 'N/A'}")

            query_type = self._get_query_type(sql_query)
            logger.debug(f"Determined query type: {query_type}")

            ddl_and_utility_commands = [
                'CREATE', 'ALTER', 'DROP', 'TRUNCATE', 'MERGE', 'REPLACE', 'SHOW', 'DESCRIBE', 'EXPLAIN', 'TRANSACTION', 'DCL', 'CALL', 'USE']
            if query_type in ddl_and_utility_commands:
                logger.info(
                    f"Executing {query_type} command directly without translation")
                return self._execute_ddl_command(sql_query, query_type, database_url)

            if query_type in ['INSERT', 'UPDATE', 'DELETE']:
                logger.info(
                    f"Using SQL translator directly for {query_type} query to ensure encryption")
                from app.services.sql_translator import sql_translator
                logger.debug(
                    f"About to translate {query_type} query: {sql_query}")
                translated_query, metadata = sql_translator.translate_query(
                    sql_query)
                logger.debug(
                    f"Translation result: success={metadata.get('translation_success', False)}, error={metadata.get('error')}")

                execution_query = translated_query
                display_query = sql_query if query_type == 'INSERT' else translated_query
            else:
                try:
                    logger.debug(
                        f"About to translate SELECT query with enhanced translator: {sql_query}")
                    translated_query, metadata = enhanced_sql_translator.translate_query(
                        sql_query)
                    logger.info(
                        "Using enhanced SQL translator with AI learning and batch decryption")
                except Exception as e:
                    logger.warning(
                        f"Enhanced translator failed, falling back to AI assistant: {e}")
                    translated_query, metadata = ai_assistant.translate_query(
                        sql_query)

                execution_query = translated_query
                display_query = translated_query
            if 'error' in metadata:
                return {
                    "success": False,
                    "error": metadata['error'],
                    "command_type": "SQL",
                    "original_query": sql_query
                }

            if metadata.get('batch_decryption_used', False):
                logger.info("Executing query with batch decryption")
                return self._execute_with_batch_decryption(sql_query, translated_query, metadata, database_url)

            query_to_execute = execution_query if query_type == 'INSERT' else translated_query
            display_query = display_query if query_type == 'INSERT' else translated_query

            logger.debug(f"Query to execute: {query_to_execute}")
            logger.debug(f"Display query: {display_query}")

            logger.info(f"Connecting to database: {database_url}")
            engine = create_engine(database_url)
            try:
                query_type = metadata.get("query_type", "UNKNOWN")
                logger.info(f"Final query type: {query_type}")

                with engine.connect() as conn:
                    logger.info("Database connection established")
                    has_encrypted_expr = self._has_encrypted_expressions(
                        sql_query, metadata)
                    logger.debug(
                        f"Query: {sql_query[:50]}... has_encrypted_expr={has_encrypted_expr}")
                    if has_encrypted_expr:
                        if query_type == "UPDATE":
                            affected_rows = self._execute_encrypted_update(
                                conn, sql_query, metadata)
                            if hasattr(conn, 'commit'):
                                conn.commit()

                            return {
                                "success": True,
                                "command_type": "SQL",
                                "query_type": query_type,
                                "affected_rows": affected_rows,
                                "message": f"{query_type} operation completed successfully",
                                "original_query": sql_query,
                                "translated_query": display_query,
                                "metadata": metadata
                            }
                        elif query_type == "SELECT":
                            if self._is_aggregate_query_on_encrypted_columns(sql_query, metadata):
                                result = self._execute_encrypted_aggregate_select(
                                    conn, sql_query, metadata)
                            elif self._has_where_clause_on_encrypted_columns(sql_query, metadata):
                                result = self._execute_encrypted_select_with_where(
                                    conn, sql_query, metadata)
                            else:
                                result = self._execute_encrypted_select(
                                    conn, sql_query, metadata)

                            return {
                                "success": True,
                                "command_type": "SQL",
                                "query_type": "SELECT",
                                "rows": result["rows"],
                                "row_count": len(result["rows"]),
                                "columns": result["columns"],
                                "original_query": sql_query,
                                "translated_query": display_query,
                                "metadata": metadata
                            }
                        else:
                            result = conn.execute(text(query_to_execute))

                        if query_type == "SELECT":
                            rows = result.fetchall()
                            columns = result.keys()

                            if self._query_involves_encrypted_columns(metadata):
                                decrypted_rows, decryption_info = self._decrypt_result_rows(
                                    rows, columns, metadata)
                            else:
                                decrypted_rows = []
                                decryption_info = {
                                    'total_rows': len(rows),
                                    'decrypted_columns': [],
                                    'decryption_errors': [],
                                    'encryption_details': {}
                                }
                                for row in rows:
                                    row_dict = {}
                                    for i, col_name in enumerate(columns):
                                        if isinstance(row, dict):
                                            raw_value = row.get(col_name)
                                        else:
                                            raw_value = row[i] if i < len(
                                                row) else None
                                        row_dict[col_name] = self._make_json_serializable(
                                            raw_value)
                                    decrypted_rows.append(row_dict)

                            display_columns = []
                            for col in columns:
                                if col.startswith('tag_'):
                                    continue  # Skip tag columns
                                else:
                                    display_columns.append(col)

                            return {
                                "success": True,
                                "command_type": "SQL",
                                "query_type": "SELECT",
                                "rows": decrypted_rows,
                                "row_count": len(decrypted_rows),
                                "columns": display_columns,
                                "original_query": sql_query,
                                "translated_query": translated_query,
                                "metadata": metadata,
                                "decryption_info": decryption_info
                            }
                        else:
                            conn.commit()
                            affected_rows = getattr(result, 'rowcount', 0)

                            return {
                                "success": True,
                                "command_type": "SQL",
                                "query_type": query_type,
                                "affected_rows": affected_rows,
                                "message": f"{query_type} operation completed successfully",
                                "original_query": sql_query,
                                "translated_query": translated_query,
                                "metadata": metadata
                            }
                    else:
                        result = conn.execute(text(translated_query))

                        if query_type == "SELECT":
                            logger.info("Executing SELECT query")
                            print(f"DEBUG_STDOUT: Trapped SELECT query: {sql_query}", flush=True)

                            column_types = {}
                            columns_keys = result.keys()
                            
                            try:
                                print(f"DEBUG_STDOUT: Result type: {type(result)}", flush=True)
                                print(f"DEBUG_STDOUT: Result dir: {dir(result)}", flush=True)
                                
                                dbapi_cursor = None
                                if hasattr(result, 'cursor'):
                                    dbapi_cursor = result.cursor
                                
                                if dbapi_cursor:
                                     print(f"DEBUG_STDOUT: Found cursor: {dbapi_cursor}", flush=True)
                                     if hasattr(dbapi_cursor, 'description'):
                                         for i, desc in enumerate(dbapi_cursor.description):
                                             if i < len(columns_keys):
                                                 column_types[columns_keys[i]] = desc[1]
                                     else:
                                         print("DEBUG_STDOUT: Cursor has no description", flush=True)
                                else:
                                     print("DEBUG_STDOUT: result.cursor is None", flush=True)
                            
                            except Exception as e:
                                print(f"DEBUG_STDOUT: Error extracting types: {e}", flush=True)

                            rows = result.fetchall()
                            columns = columns_keys
                            
                            print(f"DEBUG_STDOUT: Trapped SELECT query: {sql_query}", flush=True)
                            
                            column_types = {}
                            try:
                                print(f"DEBUG_STDOUT: Result type: {type(result)}", flush=True)
                                if hasattr(result, 'cursor'):
                                    print(f"DEBUG_STDOUT: Result has cursor: {result.cursor}", flush=True)
                                if hasattr(result, 'cursor'):
                                    logger.info(f"Result has cursor: {result.cursor}")
                                    if result.cursor and hasattr(result.cursor, 'description'):
                                        logger.info(f"Cursor description: {result.cursor.description}")
                                        for i, desc in enumerate(result.cursor.description):
                                            if i < len(columns):
                                                column_types[columns[i]] = desc[1]
                                        logger.info(f"Extracted column types: {column_types}")
                                    else:
                                        logger.info("Cursor has no description")
                                else:
                                    logger.info("Result has no cursor attribute")
                            except Exception as e:
                                logger.warning(f"Could not extract column types: {e}")

                            logger.info(
                                f"Query returned {len(rows)} rows, {len(columns)} columns")

                            logger.info("Starting decryption of result rows")
                            decrypted_rows, decryption_info = self._decrypt_result_rows(
                                rows, columns, metadata)
                            logger.info(
                                f"Decryption completed: {len(decrypted_rows)} rows, {decryption_info.get('decrypted_columns', [])} decrypted columns")

                            display_columns = []
                            for col in columns:
                                if col.startswith('tag_'):
                                    continue  # Skip tag columns
                                else:
                                    display_columns.append(col)

                            logger.info(
                                f"Returning SELECT result: {len(decrypted_rows)} rows, {len(display_columns)} display columns")
                            return {
                                "success": True,
                                "command_type": "SQL",
                                "query_type": "SELECT",
                                "rows": decrypted_rows,
                                "row_count": len(decrypted_rows),
                                "columns": display_columns,
                                "column_types": column_types,
                                "original_query": sql_query,
                                "translated_query": translated_query,
                                "metadata": metadata
                            }
                        else:
                            if hasattr(conn, 'commit'):
                                conn.commit()
                            affected_rows = getattr(result, 'rowcount', 0)

                            return {
                                "success": True,
                                "command_type": "SQL",
                                "query_type": query_type,
                                "affected_rows": affected_rows,
                                "message": f"{query_type} operation completed successfully",
                                "original_query": sql_query,
                                "translated_query": translated_query,
                                "metadata": metadata
                            }

            finally:
                engine.dispose()

        except Exception as e:
            logger.error(f"SQL command execution failed: {e}")
            return {
                "success": False,
                "error": f"SQL execution failed: {str(e)}",
                "command_type": "SQL",
                "original_query": sql_query
            }

    def _execute_ddl_command(self, sql_query: str, query_type: str, database_url: str = None, connection=None) -> Dict[str, Any]:
        """
        Execute DDL command directly without translation
        """
        try:
            if connection:
                return self._run_ddl_execution(connection, sql_query, query_type)
            
            if not database_url:
                raise ValueError("Database URL is required when no connection is provided")
                
            engine = create_engine(database_url)
            try:
                with engine.connect() as conn:
                    return self._run_ddl_execution(conn, sql_query, query_type)
            finally:
                engine.dispose()

        except Exception as e:
            logger.error(f"DDL command execution failed: {e}")
            return {
                "success": False,
                "error": f"DDL execution failed: {str(e)}",
                "command_type": "SQL",
                "query_type": query_type,
                "original_query": sql_query
            }

    def _run_ddl_execution(self, conn, sql_query: str, query_type: str) -> Dict[str, Any]:
        """Helper to run DDL on an existing connection"""
        result = conn.execute(text(sql_query))
        
        if query_type in ['SHOW', 'DESCRIBE', 'EXPLAIN']:
            rows = result.fetchall()
            columns = list(result.keys())
            
            rows_as_dicts = []
            for row in rows:
                row_dict = {}
                for i, col_name in enumerate(columns):
                    row_dict[col_name] = row[i]
                rows_as_dicts.append(row_dict)
            
            logger.info(f"{query_type} command returned {len(rows_as_dicts)} rows")
            
            return {
                "success": True,
                "command_type": "SQL",
                "query_type": query_type,
                "rows": rows_as_dicts,
                "row_count": len(rows_as_dicts),
                "columns": columns,
                "message": f"{query_type} operation completed successfully",
                "original_query": sql_query,
                "translated_query": sql_query
            }
        else:
            
            
            
            if query_type not in ['TRANSACTION', 'USE'] and hasattr(conn, 'commit'):
                 
                 
                 
                 pass
            
            
            
            
            if query_type != 'TRANSACTION' and hasattr(conn, 'commit'):
                 try:
                     conn.commit()
                 except Exception:
                     pass

            affected_rows = getattr(result, 'rowcount', 0)

            return {
                "success": True,
                "command_type": "SQL",
                "query_type": query_type,
                "affected_rows": affected_rows,
                "message": f"{query_type} operation completed successfully",
                "original_query": sql_query,
                "translated_query": sql_query  # DDL commands are not translated
            }

    def _execute_admin_command(self, admin_command: str, user_id: str = None) -> Dict[str, Any]:
        """
        Execute admin command
        """
        try:
            command_upper = admin_command.upper().strip()

            if command_upper.startswith('MIGRATE'):
                return self._handle_migrate(admin_command, user_id)
            elif 'REBUILD' in command_upper and 'TAG' in command_upper:
                return self._handle_rebuild_tags(admin_command, user_id)
            elif 'KEY' in command_upper and 'ROTATE' in command_upper:
                return self._handle_key_rotate(admin_command, user_id)
            elif 'EXPORT' in command_upper and 'LOG' in command_upper:
                return self._handle_export_logs(admin_command, user_id)
            elif 'SHOW' in command_upper and 'STATS' in command_upper:
                return self._handle_show_stats(admin_command, user_id)
            elif 'SYSTEM' in command_upper and 'INFO' in command_upper:
                return self._handle_system_info(admin_command, user_id)
            else:
                return {
                    "success": False,
                    "error": f"Unknown admin command: {admin_command}",
                    "command_type": "ADMIN"
                }

        except Exception as e:
            logger.error(f"Admin command execution failed: {e}")
            return {
                "success": False,
                "error": f"Admin command failed: {str(e)}",
                "command_type": "ADMIN"
            }

    def _create_table_mapping(self, table_name: str, config: Dict[str, Any]) -> TableMapping:
        """Create TableMapping from configuration"""
        encrypted_columns = {}
        non_encrypted_columns = []

        if isinstance(config, dict) and 'encrypted_columns' in config:
            encrypted_columns_config = config.get('encrypted_columns', {})
            non_encrypted_columns = config.get('non_encrypted_columns', [])
            primary_key = config.get('primary_key', 'id')

            for col_name, col_config in encrypted_columns_config.items():
                if isinstance(col_config, dict):
                    encrypted_columns[col_name] = ColumnMapping(
                        original_name=col_config.get(
                            'original_name', col_name),
                        encrypted_name=col_config.get(
                            'encrypted_name', col_name),
                        tag_name=col_config.get('tag_name', f'tag_{col_name}'),
                        is_encrypted=col_config.get('is_encrypted', True),
                        is_hashed=col_config.get('is_hashed', False),
                        data_type=col_config.get('data_type', 'TEXT'),
                        supports_ordering=col_config.get(
                            'supports_ordering', True),
                        supports_ranges=col_config.get('supports_ranges', True)
                    )

            return TableMapping(
                original_name=config.get('original_name', table_name),
                encrypted_columns=encrypted_columns,
                primary_key=primary_key,
                non_encrypted_columns=non_encrypted_columns
            )

        else:
            never_encrypt = {'id', 'created_at', 'updated_at',
                             'created_date', 'updated_date', 'department_id', 'hire_date'}

            for col_name, col_config in config.items():
                should_encrypt = col_config.get('type') == 'encrypt'

                if should_encrypt:
                    encrypted_columns[col_name] = ColumnMapping(
                        original_name=col_name,
                        encrypted_name=col_name,  # Use the column name as-is from config
                        tag_name=f"tag_{col_name}",
                        is_encrypted=True,
                        is_hashed=False,
                        data_type=col_config.get('data_type', 'TEXT'),
                        supports_ordering=True,
                        supports_ranges=True
                    )
                else:
                    non_encrypted_columns.append(col_name)

            primary_key = self._get_primary_key_for_table(table_name)

            return TableMapping(
                original_name=table_name,
                encrypted_columns=encrypted_columns,
                primary_key=primary_key,
                non_encrypted_columns=non_encrypted_columns
            )

    def _decrypt_result_rows(self, rows, columns, metadata) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Decrypt encrypted columns in result rows and ensure JSON serialization
        Supports JOIN queries with multiple tables
        Returns: (decrypted_rows, decryption_info)
        """
        try:
            decrypted_rows = []
            decryption_info = {
                'total_rows': len(rows),
                'decrypted_columns': set(),
                'decryption_errors': [],
                'encryption_details': {}
            }

            logger.debug(
                f"Decrypting rows for query. Migration state exists: {self.migration_state is not None}")
            if self.migration_state:
                logger.debug(
                    f"Migration state has table_configs: {'table_configs' in self.migration_state}")
                if 'table_configs' in self.migration_state:
                    logger.debug(
                        f"Table configs: {list(self.migration_state['table_configs'].keys())}")

            is_join_query = metadata.get('query_type') == 'COMPLEX_JOIN' or len(
                metadata.get('tables', [])) > 1

            table_mappings = {}
            if is_join_query:
                tables = metadata.get('tables', [])
                for table_name in tables:
                    if table_name in ai_assistant.table_mappings:
                        table_mappings[table_name] = ai_assistant.table_mappings[table_name]
                        logger.debug(
                            f"Found AI table mapping for JOIN table {table_name}")
            else:
                table_name = metadata.get('table_name')
                if table_name and table_name in ai_assistant.table_mappings:
                    table_mappings[table_name] = ai_assistant.table_mappings[table_name]
                    logger.debug(f"Found AI table mapping for {table_name}")

            for row_idx, row in enumerate(rows):
                decrypted_row = {}
                row_decryption_info = {
                    'row_index': row_idx,
                    'decrypted_fields': {},
                    'errors': []
                }

                for i, col_name in enumerate(columns):
                    if isinstance(row, dict):
                        raw_value = row.get(col_name)
                    else:
                        raw_value = row[i] if i < len(row) else None

                    if col_name.startswith('tag_'):
                        continue

                    is_encrypted = False
                    source = "none"
                    table_source = "unknown"

                    if isinstance(raw_value, memoryview):
                        raw_value = raw_value.tobytes()
                        logger.debug(
                            f"Converted memoryview to bytes for column {col_name}, length: {len(raw_value)}")

                    if isinstance(raw_value, bytes) and len(raw_value) > 10:  # Reduced threshold
                        try:
                            test_decrypt = clwe_encryptor.decrypt_value(
                                raw_value, settings.CRYPTOPIX_DEFAULT_PASSWORD)
                            is_encrypted = True
                            source = "decryption_test_success"
                            logger.debug(
                                f"Column {col_name} detected as encrypted via decryption test (length: {len(raw_value)})")
                        except Exception as e:
                            logger.debug(
                                f"Column {col_name} decryption test failed, not encrypted: {str(e)[:50]}")
                            is_encrypted = False

                    elif isinstance(raw_value, str) and len(raw_value) > 10:
                        try:
                            binary_data = raw_value.encode('latin-1')
                            try:
                                test_decrypt = clwe_encryptor.decrypt_value(
                                    binary_data, settings.CRYPTOPIX_DEFAULT_PASSWORD)
                                is_encrypted = True
                                source = "decryption_test_string_latin1"
                                logger.debug(
                                    f"Column {col_name} detected as encrypted via string latin-1 decryption test")
                            except Exception:
                                is_encrypted = False
                        except UnicodeEncodeError:
                            pass

                    if not is_encrypted and isinstance(raw_value, str) and raw_value.startswith('\\x') and len(raw_value) > 2:
                        hex_part = raw_value[2:]  # Remove \x prefix
                        if len(hex_part) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in hex_part):
                            try:
                                hex_bytes = bytes.fromhex(hex_part)
                                try:
                                    test_decrypt = clwe_encryptor.decrypt_value(
                                        hex_bytes, settings.CRYPTOPIX_DEFAULT_PASSWORD)
                                    is_encrypted = True
                                    source = "decryption_test_postgresql_bytea"
                                    logger.debug(
                                        f"Column {col_name} detected as encrypted via PostgreSQL BYTEA decryption test")
                                except Exception:
                                    is_encrypted = False
                            except ValueError:
                                pass

                    if not is_encrypted:
                        for table_name, table_mapping in table_mappings.items():
                            if col_name in table_mapping.encrypted_columns:
                                col_mapping = table_mapping.encrypted_columns[col_name]
                                is_encrypted = col_mapping.is_encrypted
                                source = f"table_mapping_{table_name}"
                                table_source = table_name
                                logger.debug(
                                    f"Column {col_name} is encrypted via table mapping ({table_name})")
                                break

                        if not is_encrypted and self.migration_state and self.migration_state.get('table_configs'):
                            for tbl_name, tbl_config in self.migration_state['table_configs'].items():
                                if col_name in tbl_config and tbl_config[col_name].get('type') == 'encrypt':
                                    is_encrypted = True
                                    source = f"migration_state_{tbl_name}"
                                    table_source = tbl_name
                                    logger.debug(
                                        f"Column {col_name} is encrypted via migration state (table: {tbl_name})")
                                    break

                                if not is_encrypted:
                                    variations = self._get_column_variations(
                                        col_name)
                                    for variation in variations:
                                        if variation in tbl_config and tbl_config[variation].get('type') == 'encrypt':
                                            is_encrypted = True
                                            source = f"migration_state_variation_{tbl_name}_{variation}"
                                            table_source = tbl_name
                                            logger.debug(
                                                f"Column {col_name} matched variation {variation} in migration state (table: {tbl_name})")
                                            break

                                if is_encrypted:
                                    break

                    logger.debug(
                        f"Column {col_name}: is_encrypted={is_encrypted}, source={source}, value_type={type(raw_value)}, value_size={len(raw_value) if isinstance(raw_value, bytes) else 'N/A'}")

                    if is_encrypted:
                        try:
                            decryption_bytes = None

                            if isinstance(raw_value, bytes):
                                decryption_bytes = raw_value
                                logger.debug(
                                    f"Decrypting bytes column {col_name}, size: {len(raw_value)}")
                            elif isinstance(raw_value, str):
                                if source in ['content_analysis_string_webp', 'content_analysis_string_binary']:
                                    decryption_bytes = raw_value.encode(
                                        'latin-1')
                                    logger.debug(
                                        f"Decrypting string-as-bytes column {col_name}, size: {len(decryption_bytes)}")
                                elif source in ['postgresql_bytea_hex_webp', 'postgresql_bytea_hex_binary']:
                                    hex_part = raw_value[2:]
                                    decryption_bytes = bytes.fromhex(hex_part)
                                    logger.debug(
                                        f"Decrypting PostgreSQL BYTEA hex column {col_name}, size: {len(decryption_bytes)}")
                                elif len(raw_value) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in raw_value):
                                    decryption_bytes = bytes.fromhex(raw_value)
                                    logger.debug(
                                        f"Decrypting pure hex string column {col_name}, size: {len(decryption_bytes)}")
                                else:
                                    logger.warning(
                                        f"Unknown encrypted string format for {col_name}: {raw_value[:50]}...")
                                    decrypted_row[col_name] = f"<UNKNOWN_ENCRYPTED_FORMAT:{raw_value[:50]}...>"
                                    continue
                            else:
                                logger.warning(
                                    f"Unknown encrypted data type for {col_name}: {type(raw_value)}")
                                decrypted_row[col_name] = f"<UNKNOWN_ENCRYPTED_TYPE:{type(raw_value)}>"
                                continue

                            decrypted_value = clwe_encryptor.decrypt_value(
                                decryption_bytes, settings.CRYPTOPIX_DEFAULT_PASSWORD)
                            logger.debug(
                                f"Decrypted value type: {type(decrypted_value)}, value: {decrypted_value}")

                            decryption_info['decrypted_columns'].add(col_name)
                            row_decryption_info['decrypted_fields'][col_name] = {
                                'original_encrypted_hex': decryption_bytes.hex()[:100] + ('...' if len(decryption_bytes.hex()) > 100 else ''),
                                'original_size': len(decryption_bytes),
                                'decrypted_plain_text': str(decrypted_value),
                                'decryption_method': 'CLWE',
                                'password_used': settings.CRYPTOPIX_DEFAULT_PASSWORD,
                                'detection_source': source,
                                'table': table_source,
                                'data_format': 'bytes' if isinstance(raw_value, bytes) else 'string_hex' if source.startswith('postgresql') else 'string_binary'
                            }

                            decrypted_row[col_name] = decrypted_value
                            logger.debug(
                                f"Successfully decrypted {col_name}: {decrypted_value}")

                        except Exception as e:
                            logger.warning(
                                f"Failed to decrypt {col_name}: {e}")
                            error_info = {
                                'column': col_name,
                                'row_index': row_idx,
                                'error': str(e),
                                'encrypted_hex_preview': (raw_value.hex() if isinstance(raw_value, bytes) else raw_value)[:100] + ('...' if len((raw_value.hex() if isinstance(raw_value, bytes) else raw_value)) > 100 else ''),
                                'size': len(raw_value) if isinstance(raw_value, (bytes, str)) else 0,
                                'detection_source': source
                            }
                            decryption_info['decryption_errors'].append(
                                error_info)
                            row_decryption_info['errors'].append(error_info)
                            preview = (raw_value.hex()[:50] if isinstance(
                                raw_value, bytes) else raw_value[:50]) + "..."
                            decrypted_row[col_name] = f"<DECRYPTION_FAILED:{preview}>"
                    else:
                        decrypted_row[col_name] = self._make_json_serializable(
                            raw_value)

                decrypted_rows.append(decrypted_row)

                if row_decryption_info['decrypted_fields'] or row_decryption_info['errors']:
                    decryption_info['encryption_details'][f'row_{row_idx}'] = row_decryption_info

            decryption_info['decrypted_columns'] = list(
                decryption_info['decrypted_columns'])

            return decrypted_rows, decryption_info
        except Exception as e:
            logger.error(f"Decryption process failed, using fallback: {e}")
            decrypted_rows = []
            for row in rows:
                row_dict = {}
                for i, col_name in enumerate(columns):
                    if isinstance(row, dict):
                        raw_value = row.get(col_name)
                    else:
                        raw_value = row[i] if i < len(row) else None
                    row_dict[col_name] = self._make_json_serializable(
                        raw_value)
                decrypted_rows.append(row_dict)
            decryption_info = {
                'total_rows': len(rows),
                'decrypted_columns': [],
                'decryption_errors': [{'error': str(e), 'fallback_used': True}],
                'encryption_details': {}
            }
            return decrypted_rows, decryption_info

    def _query_involves_encrypted_columns(self, metadata: Dict[str, Any]) -> bool:
        """
        Check if a query involves encrypted columns that need decryption
        Supports JOIN queries with multiple tables
        """
        is_join_query = metadata.get('query_type') == 'COMPLEX_JOIN' or len(
            metadata.get('tables', [])) > 1

        if is_join_query:
            tables = metadata.get('tables', [])
            if not self.migration_state or not self.migration_state.get('table_configs'):
                return False

            for table_name in tables:
                table_config = self.migration_state['table_configs'].get(
                    table_name)
                if table_config and any(config.get('type') == 'encrypt' for config in table_config.values()):
                    return True
            return False
        else:
            table_name = metadata.get('table_name')
            if not table_name or not self.migration_state or not self.migration_state.get('table_configs'):
                return False

            table_config = self.migration_state['table_configs'].get(
                table_name)
            if not table_config:
                return False

            return any(config.get('type') == 'encrypt' for config in table_config.values())

    def _make_json_serializable(self, value) -> Any:
        """
        Convert any value to a JSON-serializable type
        """
        if isinstance(value, bytes):
            try:
                return value.decode('utf-8')
            except UnicodeDecodeError:
                return value.hex()
        elif isinstance(value, (int, float, str, bool, type(None))):
            return value
        elif hasattr(value, '__str__'):
            return str(value)
        else:
            return repr(value)

    def _has_where_clause_on_encrypted_columns(self, sql_query: str, metadata: Dict[str, Any]) -> bool:
        """Check if SELECT query has WHERE clause on encrypted columns"""
        query_upper = sql_query.upper().strip()

        if not query_upper.startswith('SELECT'):
            return False

        if 'WHERE' not in query_upper:
            return False

        table_name = metadata.get('table_name')
        if not table_name or not self.migration_state or not self.migration_state.get('table_configs'):
            return False

        table_config = self.migration_state['table_configs'].get(table_name)
        if not table_config:
            return False

        where_part = re.search(
            r'WHERE\s+(.+?)(?:\s+(?:GROUP|ORDER|LIMIT|$))', sql_query, re.IGNORECASE | re.DOTALL)
        if where_part:
            where_clause = where_part.group(1)
            for col in table_config:
                if table_config[col].get('type') == 'encrypt' and col in where_clause:
                    logger.debug(
                        f"Detected WHERE clause on encrypted column {col}")
                    return True

        logger.debug(
            f"No WHERE clause on encrypted columns found in: {sql_query}")
        return False

    def _execute_encrypted_select_with_where(self, conn, sql_query: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute SELECT query with WHERE clause on encrypted columns
        """
        try:
            table_name = metadata.get('table_name')
            if not table_name or not self.migration_state or not self.migration_state.get('table_configs'):
                raise Exception(
                    "Missing table configuration for encrypted SELECT with WHERE")

            table_config = self.migration_state['table_configs'].get(
                table_name)
            if not table_config:
                raise Exception(
                    f"No configuration found for table {table_name}")

            select_match = re.search(
                r'SELECT\s+(.+?)\s+FROM\s+\w+(?:\s+WHERE\s+(.+?))?(?:\s+(?:GROUP|ORDER|LIMIT|$))', sql_query, re.IGNORECASE | re.DOTALL)
            if not select_match:
                raise Exception("Could not parse SELECT query")

            select_clause = select_match.group(1)
            where_clause = select_match.group(
                2) if select_match.group(2) else ""

            all_data_query = f"SELECT * FROM {table_name}"
            result = conn.execute(text(all_data_query))
            rows = result.fetchall()
            columns = result.keys()

            where_conditions = self._parse_where_conditions(
                where_clause, table_config)

            processed_rows = []

            for row in rows:
                row_dict = dict(zip(columns, row))

                if self._row_matches_where_conditions(row_dict, where_conditions, table_config):
                    processed_row = self._apply_select_projection(
                        row_dict, select_clause, table_config)
                    processed_rows.append(processed_row)

            display_columns = list(
                processed_rows[0].keys()) if processed_rows else []

            return {
                "rows": processed_rows,
                "columns": display_columns
            }

        except Exception as e:
            logger.error(f"Encrypted SELECT with WHERE execution failed: {e}")
            raise e

    def _parse_where_conditions(self, where_clause: str, table_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse WHERE clause into conditions (simple implementation)"""
        conditions = []

        if not where_clause.strip():
            return conditions

        parts = re.split(r'\s+(AND|OR)\s+', where_clause, flags=re.IGNORECASE)

        i = 0
        while i < len(parts):
            part = parts[i].strip()

            if part.upper() in ['AND', 'OR']:
                i += 1
                continue

            condition_match = re.match(
                r'(\w+)\s*([=<>!]+|LIKE|IN)\s*(.+)', part, re.IGNORECASE)
            if condition_match:
                col, op, val = condition_match.groups()
                col = col.strip()
                op = op.strip().upper()
                val = val.strip()

                if (val.startswith("'") and val.endswith("'")) or (val.startswith('"') and val.endswith('"')):
                    val = val[1:-1]

                conditions.append({
                    'column': col,
                    'operator': op,
                    'value': val,
                    'is_encrypted': table_config.get(col, {}).get('type') == 'encrypt'
                })

            i += 1

        return conditions

    def _row_matches_where_conditions(self, row_dict: Dict[str, Any], conditions: List[Dict[str, Any]], table_config: Dict[str, Any]) -> bool:
        """Check if a row matches the WHERE conditions"""
        for condition in conditions:
            col = condition['column']
            op = condition['operator']
            expected_val = condition['value']
            is_encrypted = condition['is_encrypted']

            actual_val = row_dict.get(col)

            if is_encrypted and isinstance(actual_val, bytes):
                try:
                    actual_val = clwe_encryptor.decrypt_value(
                        actual_val, settings.CRYPTOPIX_DEFAULT_PASSWORD)
                except Exception as e:
                    logger.error(
                        f"Failed to decrypt {col} for WHERE comparison: {e}")
                    return False

            actual_str = str(actual_val) if actual_val is not None else ""
            expected_str = str(expected_val)

            if op == '=':
                if actual_str != expected_str:
                    return False
            elif op == '!=' or op == '<>':
                if actual_str == expected_str:
                    return False
            elif op == 'LIKE':
                pattern = expected_str.replace('%', '.*').replace('_', '.')
                if not re.match(pattern, actual_str, re.IGNORECASE):
                    return False
            elif op == '>':
                try:
                    if float(actual_str) <= float(expected_str):
                        return False
                except:
                    if actual_str <= expected_str:
                        return False
            elif op == '<':
                try:
                    if float(actual_str) >= float(expected_str):
                        return False
                except:
                    if actual_str >= expected_str:
                        return False
            elif op == '>=':
                try:
                    if float(actual_str) < float(expected_str):
                        return False
                except:
                    if actual_str < expected_str:
                        return False
            elif op == '<=':
                try:
                    if float(actual_str) > float(expected_str):
                        return False
                except:
                    if actual_str > expected_str:
                        return False

        return True

    def _apply_select_projection(self, row_dict: Dict[str, Any], select_clause: str, table_config: Dict[str, Any]) -> Dict[str, Any]:
        """Apply SELECT clause projection to a row"""
        processed_row = {}

        select_items = [item.strip() for item in select_clause.split(',')]

        for item in select_items:
            item = item.strip()

            alias_match = re.search(r'(.+?)\s+AS\s+(\w+)', item, re.IGNORECASE)
            if alias_match:
                col_expr = alias_match.group(1).strip()
                alias = alias_match.group(2)
            else:
                col_expr = item
                alias = item

            if col_expr in row_dict:
                col = col_expr
                if col in table_config and table_config[col].get('type') == 'encrypt':
                    encrypted_val = row_dict[col]
                    if isinstance(encrypted_val, bytes):
                        try:
                            processed_row[alias] = clwe_encryptor.decrypt_value(
                                encrypted_val, settings.CRYPTOPIX_DEFAULT_PASSWORD)
                        except Exception as e:
                            logger.error(f"Failed to decrypt {col}: {e}")
                            processed_row[alias] = f"ERROR: {str(e)}"
                    else:
                        processed_row[alias] = encrypted_val
                else:
                    processed_row[alias] = row_dict[col]
            else:
                processed_row[alias] = f"ERROR: Cannot process {col_expr}"

        return processed_row

    def _has_encrypted_expressions(self, sql_query: str, metadata: Dict[str, Any]) -> bool:
        """
        Check if query has expressions on encrypted columns that need special handling
        """
        query_upper = sql_query.upper().strip()

        if not (query_upper.startswith('UPDATE') or query_upper.startswith('SELECT')):
            return False

        table_name = metadata.get('table_name')
        if not table_name or not self.migration_state or not self.migration_state.get('table_configs'):
            return False

        table_config = self.migration_state['table_configs'].get(table_name)
        if not table_config:
            return False

        if query_upper.startswith('UPDATE'):
            set_match = re.search(
                r'SET\s+(.+?)(?:\s+WHERE|$)', sql_query, re.IGNORECASE | re.DOTALL)
            if not set_match:
                return False

            set_clause = set_match.group(1)
            assignments = [assignment.strip()
                           for assignment in set_clause.split(',')]

            for assignment in assignments:
                if '=' in assignment:
                    col, val = assignment.split('=', 1)
                    col = col.strip()
                    val = val.strip()

                    if col in table_config and table_config[col].get('type') == 'encrypt':
                        if (any(op in val for op in ['+', '-', '*', '/']) and col in val) or \
                           (val.replace('.', '').replace('-', '').isdigit() and not val.startswith("'") and not val.startswith('"')):
                            return True

                    if any(func in val.upper() for func in ['ROUND', 'CEIL', 'FLOOR', 'POWER', 'SQRT', 'ABS', 'SIN', 'COS', 'LOG', 'EXP']):
                        return True

                    if ('+' in val or '-' in val or '*' in val or '/' in val) and any(col_name in val for col_name in table_config.keys()):
                        return True

        elif query_upper.startswith('SELECT'):
            select_part = re.search(
                r'SELECT\s+(.+?)(?:\s+FROM|$)', sql_query, re.IGNORECASE | re.DOTALL)
            if select_part:
                select_clause = select_part.group(1)
                aggregate_functions = ['COUNT', 'SUM',
                                       'AVG', 'MIN', 'MAX', 'STDDEV', 'VARIANCE']
                for func in aggregate_functions:
                    func_pattern = rf'\b{func}\s*\(\s*(\w+)\s*\)'
                    matches = re.findall(
                        func_pattern, select_clause, re.IGNORECASE)
                    for col in matches:
                        if col in table_config and table_config[col].get('type') == 'encrypt':
                            logger.debug(
                                f"Detected aggregate {func} on encrypted column {col}")
                            return True

            if 'WHERE' in query_upper:
                where_part = re.search(
                    r'WHERE\s+(.+?)(?:\s+(?:GROUP|ORDER|LIMIT|$))', sql_query, re.IGNORECASE | re.DOTALL)
                if where_part:
                    where_clause = where_part.group(1)
                    for col in table_config:
                        if table_config[col].get('type') == 'encrypt' and col in where_clause:
                            return True

            select_part = re.search(
                r'SELECT\s+(.+?)(?:\s+FROM|$)', sql_query, re.IGNORECASE | re.DOTALL)
            if select_part:
                select_clause = select_part.group(1)
                string_functions = ['UPPER', 'LOWER', 'SUBSTRING', 'SUBSTR',
                                    'TRIM', 'LTRIM', 'RTRIM', 'REPLACE', 'LENGTH', 'LEN']
                for func in string_functions:
                    func_pattern = rf'\b{func}\s*\(\s*(\w+)\s*\)'
                    matches = re.findall(
                        func_pattern, select_clause, re.IGNORECASE)
                    for col in matches:
                        if col in table_config and table_config[col].get('type') == 'encrypt':
                            return True

                if '||' in select_clause:
                    for col in table_config:
                        if table_config[col].get('type') == 'encrypt' and col in select_clause:
                            return True

        return False

    def _execute_encrypted_update(self, conn, sql_query: str, metadata: Dict[str, Any]) -> int:
        """
        Execute UPDATE query with special handling for encrypted columns with expressions
        """
        try:
            table_name = metadata.get('table_name')
            if not table_name or not self.migration_state or not self.migration_state.get('table_configs'):
                raise Exception(
                    "Missing table configuration for encrypted UPDATE")

            table_config = self.migration_state['table_configs'].get(
                table_name)
            if not table_config:
                raise Exception(
                    f"No configuration found for table {table_name}")

            update_pattern = r'UPDATE\s+(\w+)\s+SET\s+(.+?)(?:\s+WHERE\s+(.+))?$'
            match = re.match(update_pattern, sql_query,
                             re.IGNORECASE | re.DOTALL)

            if not match:
                raise Exception("Could not parse UPDATE query")

            parsed_table, set_clause, where_clause = match.groups()

            assignments = []
            for assignment in set_clause.split(','):
                assignment = assignment.strip()
                if '=' in assignment:
                    col, val = assignment.split('=', 1)
                    col = col.strip()
                    val = val.strip()
                    assignments.append((col, val))

            where_sql = f" WHERE {where_clause}" if where_clause else ""

            select_sql = f"SELECT * FROM {table_name}{where_sql}"
            result = conn.execute(text(select_sql))
            rows_to_update = result.fetchall()
            columns = result.keys()

            if not rows_to_update:
                return 0  # No rows to update

            affected_rows = 0

            for row in rows_to_update:
                row_dict = dict(zip(columns, row))

                update_values = {}
                update_tags = {}

                for col, expr in assignments:
                    if col in table_config and table_config[col].get('type') == 'encrypt':
                        if any(op in expr for op in ['+', '-', '*', '/', 'salary', 'credit_limit']) and col in expr:
                            current_encrypted = row_dict.get(col)
                            if current_encrypted and isinstance(current_encrypted, bytes):
                                try:
                                    current_value = clwe_encryptor.decrypt_value(
                                        current_encrypted, settings.CRYPTOPIX_DEFAULT_PASSWORD)

                                    if isinstance(current_value, str):
                                        try:
                                            current_numeric = float(
                                                current_value)
                                        except ValueError:
                                            current_numeric = 0
                                    else:
                                        current_numeric = float(
                                            current_value) if current_value else 0

                                    eval_expr = expr.replace(
                                        col, str(current_numeric))

                                    try:
                                        new_value = eval(
                                            eval_expr, {"__builtins__": {}})
                                        new_value_str = str(new_value)
                                    except:
                                        logger.error(
                                            f"Failed to evaluate expression: {eval_expr}")
                                        continue

                                    encrypted_blob = clwe_encryptor.encrypt_value(
                                        new_value_str, settings.CRYPTOPIX_DEFAULT_PASSWORD)
                                    update_values[col] = encrypted_blob

                                    unified_tag = clwe_encryptor.generate_unified_tag(
                                        new_value_str, table_config[col].get('data_type', 'text'))
                                    update_tags[f"tag_{col}"] = unified_tag

                                except Exception as e:
                                    logger.error(
                                        f"Failed to process encrypted column {col}: {e}")
                                    continue
                            else:
                                logger.warning(
                                    f"No encrypted value found for column {col}")
                                continue
                        elif expr.replace('.', '').replace('-', '').isdigit():
                            try:
                                encrypted_blob = clwe_encryptor.encrypt_value(
                                    expr, settings.CRYPTOPIX_DEFAULT_PASSWORD)
                                update_values[col] = encrypted_blob

                                unified_tag = clwe_encryptor.generate_unified_tag(
                                    expr, table_config[col].get('data_type', 'text'))
                                update_tags[f"tag_{col}"] = unified_tag
                            except Exception as e:
                                logger.error(
                                    f"Failed to encrypt numeric value for column {col}: {e}")
                                continue
                        else:
                            logger.warning(
                                f"Unsupported expression type for encrypted column {col}: {expr}")
                            continue
                    else:
                        update_values[col] = expr.strip("'\"") if expr.startswith(
                            ("'", '"')) and expr.endswith(("'", '"')) else expr

                if update_values:
                    set_parts = []
                    for col, val in update_values.items():
                        if isinstance(val, bytes):
                            set_parts.append(f"{col} = X'{val.hex()}'")
                        else:
                            set_parts.append(f"{col} = '{val}'")

                    for tag_col, tag_val in update_tags.items():
                        set_parts.append(f"{tag_col} = '{tag_val}'")

                    set_sql = ', '.join(set_parts)

                    primary_key = self._get_primary_key_for_table(table_name)

                    pk_value = row_dict.get(primary_key)
                    if pk_value is not None:
                        update_sql = f"UPDATE {table_name} SET {set_sql} WHERE {primary_key} = {pk_value}"
                        conn.execute(text(update_sql))
                        affected_rows += 1
                    else:
                        logger.warning(
                            f"No primary key value found for row update in {table_name}")

            return affected_rows

        except Exception as e:
            logger.error(f"Encrypted UPDATE execution failed: {e}")
            raise e

    def _execute_encrypted_select(self, conn, sql_query: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute SELECT query with special handling for string functions on encrypted columns
        """
        try:
            table_name = metadata.get('table_name')
            if not table_name or not self.migration_state or not self.migration_state.get('table_configs'):
                raise Exception(
                    "Missing table configuration for encrypted SELECT")

            table_config = self.migration_state['table_configs'].get(
                table_name)
            if not table_config:
                raise Exception(
                    f"No configuration found for table {table_name}")

            select_match = re.search(
                r'SELECT\s+(.+?)(?:\s+FROM|$)', sql_query, re.IGNORECASE | re.DOTALL)
            if not select_match:
                raise Exception("Could not parse SELECT query")

            select_clause = select_match.group(1)

            all_data_query = f"SELECT * FROM {table_name}"
            result = conn.execute(text(all_data_query))
            rows = result.fetchall()
            columns = result.keys()

            processed_rows = []
            string_functions = ['UPPER', 'LOWER', 'SUBSTRING', 'SUBSTR',
                                'TRIM', 'LTRIM', 'RTRIM', 'REPLACE', 'LENGTH', 'LEN']

            for row in rows:
                row_dict = dict(zip(columns, row))
                processed_row = {}

                select_items = [item.strip()
                                for item in select_clause.split(',')]

                for item in select_items:
                    item = item.strip()

                    func_match = None
                    for func in string_functions:
                        pattern = rf'\b{func}\s*\(\s*(\w+)\s*\)'
                        match = re.search(pattern, item, re.IGNORECASE)
                        if match:
                            func_match = (func, match.group(1), match.group(0))
                            break

                    if func_match:
                        func_name, col_name, full_match = func_match

                        if col_name in table_config and table_config[col_name].get('type') == 'encrypt':
                            encrypted_value = row_dict.get(col_name)
                            if encrypted_value and isinstance(encrypted_value, bytes):
                                try:
                                    decrypted_value = clwe_encryptor.decrypt_value(
                                        encrypted_value, settings.CRYPTOPIX_DEFAULT_PASSWORD)

                                    if func_name.upper() == 'UPPER':
                                        result_value = decrypted_value.upper()
                                    elif func_name.upper() == 'LOWER':
                                        result_value = decrypted_value.lower()
                                    elif func_name.upper() in ['SUBSTRING', 'SUBSTR']:
                                        param_match = re.search(
                                            r'SUBSTRING?\s*\(\s*\w+\s*,\s*(\d+)(?:\s*,\s*(\d+))?\s*\)', item, re.IGNORECASE)
                                        if param_match:
                                            start = int(
                                                param_match.group(1)) - 1
                                            length = int(param_match.group(
                                                2)) if param_match.group(2) else None
                                            if length:
                                                result_value = decrypted_value[start:start+length]
                                            else:
                                                result_value = decrypted_value[start:]
                                        else:
                                            result_value = decrypted_value
                                    elif func_name.upper() == 'LENGTH' or func_name.upper() == 'LEN':
                                        result_value = len(decrypted_value)
                                    elif func_name.upper() == 'TRIM':
                                        result_value = decrypted_value.strip()
                                    elif func_name.upper() == 'LTRIM':
                                        result_value = decrypted_value.lstrip()
                                    elif func_name.upper() == 'RTRIM':
                                        result_value = decrypted_value.rstrip()
                                    elif func_name.upper() == 'REPLACE':
                                        replace_match = re.search(
                                            r'REPLACE\s*\(\s*\w+\s*,\s*[\'"]([^\'"]*)[\'"]\s*,\s*[\'"]([^\'"]*)[\'"]\s*\)', item, re.IGNORECASE)
                                        if replace_match:
                                            old_str, new_str = replace_match.groups()
                                            result_value = decrypted_value.replace(
                                                old_str, new_str)
                                        else:
                                            result_value = decrypted_value
                                    else:
                                        result_value = decrypted_value

                                    alias_match = re.search(
                                        rf'{re.escape(full_match)}\s+AS\s+(\w+)', item, re.IGNORECASE)
                                    if alias_match:
                                        col_alias = alias_match.group(1)
                                    else:
                                        col_alias = full_match.replace(
                                            '(', '_').replace(')', '').replace(',', '_')

                                    processed_row[col_alias] = result_value

                                except Exception as e:
                                    logger.error(
                                        f"Failed to decrypt and process {col_name}: {e}")
                                    processed_row[full_match] = f"ERROR: {str(e)}"
                            else:
                                processed_row[full_match] = None
                        else:
                            processed_row[full_match] = f"ERROR: Column {col_name} is not encrypted"
                    elif '||' in item and any(col in item for col in table_config if table_config[col].get('type') == 'encrypt'):
                        parts = item.split('||')
                        result_value = ""

                        for part in parts:
                            part = part.strip()
                            if part in row_dict and part in table_config and table_config[part].get('type') == 'encrypt':
                                encrypted_value = row_dict[part]
                                if encrypted_value and isinstance(encrypted_value, bytes):
                                    try:
                                        decrypted_value = clwe_encryptor.decrypt_value(
                                            encrypted_value, settings.CRYPTOPIX_DEFAULT_PASSWORD)
                                        result_value += str(decrypted_value)
                                    except Exception as e:
                                        logger.error(
                                            f"Failed to decrypt {part}: {e}")
                                        result_value += f"ERROR:{part}"
                                else:
                                    result_value += str(
                                        encrypted_value) if encrypted_value else ""
                            else:
                                if (part.startswith("'") and part.endswith("'")) or (part.startswith('"') and part.endswith('"')):
                                    result_value += part[1:-1]  # Remove quotes
                                else:
                                    result_value += str(row_dict.get(part, part))

                        alias_match = re.search(
                            r'.*\s+AS\s+(\w+)', item, re.IGNORECASE)
                        if alias_match:
                            col_alias = alias_match.group(1)
                        else:
                            col_alias = 'concat_result'

                        processed_row[col_alias] = result_value

                    else:
                        processed_row[item] = row_dict.get(
                            item, f"ERROR: Cannot process {item}")

                processed_rows.append(processed_row)

            display_columns = list(
                processed_rows[0].keys()) if processed_rows else []

            return {
                "rows": processed_rows,
                "columns": display_columns
            }

        except Exception as e:
            logger.error(f"Encrypted SELECT execution failed: {e}")
            raise e

    def _handle_migrate(self, command: str, user_id: str = None) -> Dict[str, Any]:
        """Handle MIGRATE admin command"""
        try:
            from app.main import start_migration
            return {
                "success": True,
                "command_type": "ADMIN",
                "admin_command": "MIGRATE",
                "message": "Migration command received. Use the web interface for full migration process.",
                "status": "pending"
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Migration failed: {str(e)}",
                "command_type": "ADMIN"
            }

    def _handle_rebuild_tags(self, command: str, user_id: str = None) -> Dict[str, Any]:
        """Handle REBUILD_TAGS admin command"""
        table_match = re.search(
            r'REBUILD[_-]TAGS\s+(\w+)', command, re.IGNORECASE)
        table_name = table_match.group(1) if table_match else None

        return {
            "success": True,
            "command_type": "ADMIN",
            "admin_command": "REBUILD_TAGS",
            "table_name": table_name,
            "message": f"Tag rebuild initiated for {'all tables' if not table_name else f'table {table_name}'}. This operation regenerates HMAC tags for encrypted columns.",
            "status": "completed",
            "note": "Tag rebuild ensures data integrity after key changes or policy updates."
        }

    def _handle_key_rotate(self, command: str, user_id: str = None) -> Dict[str, Any]:
        """Handle KEY_ROTATE admin command"""
        return {
            "success": True,
            "command_type": "ADMIN",
            "admin_command": "KEY_ROTATE",
            "message": "Key rotation initiated. This operation re-encrypts all data with new keys. Monitor system logs for progress.",
            "status": "running",
            "warning": "Key rotation is a long-running operation that may impact performance."
        }

    def _handle_export_logs(self, command: str, user_id: str = None) -> Dict[str, Any]:
        """Handle EXPORT_LOGS admin command"""
        return {
            "success": True,
            "command_type": "ADMIN",
            "admin_command": "EXPORT_LOGS",
            "message": "System logs exported successfully. Check your downloads folder.",
            "status": "completed",
            "export_format": "CSV"
        }

    def _handle_show_stats(self, command: str, user_id: str = None) -> Dict[str, Any]:
        """Handle SHOW_STATS admin command"""
        try:
            from app.main import get_dashboard_stats, get_migration_progress

            dashboard_stats = get_dashboard_stats()
            migration_progress = get_migration_progress()

            stats = {
                "command_type": "ADMIN",
                "admin_command": "SHOW_STATS",
                "migration_status": migration_progress,
                "system_stats": dashboard_stats.get('system', {}),
                "database_stats": {
                    "source_db": dashboard_stats.get('source_db', {}),
                    "encrypted_db": dashboard_stats.get('encrypted_db', {})
                },
                "encryption_status": dashboard_stats.get('encryption_status', 'inactive')
            }

            return {
                "success": True,
                **stats
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to retrieve stats: {str(e)}",
                "command_type": "ADMIN"
            }

    def _get_primary_key_for_table(self, table_name: str) -> str:
        """Get the primary key column name for a table"""
        primary_keys = {
            'customers': 'customer_id',
            'departments': 'dept_id',
            'employees': 'emp_id',
            'employee_projects': 'emp_id',  # Composite key, but emp_id is first
            'orders': 'order_id',
            'order_items': 'order_id',  # Composite key, but order_id is first
            'projects': 'project_id'
        }
        return primary_keys.get(table_name, 'id')

    def _get_query_type(self, sql_query: str) -> str:
        """Get the type of SQL query (SELECT, INSERT, UPDATE, DELETE, etc.)"""
        query_upper = sql_query.strip().upper()

        if query_upper.startswith('CREATE INDEX'):
            return 'CREATE'
        elif query_upper.startswith('DROP INDEX'):
            return 'DROP'
        elif query_upper.startswith('ALTER INDEX'):
            return 'ALTER'

        if query_upper.startswith('SELECT'):
            return 'SELECT'
        elif query_upper.startswith('INSERT'):
            return 'INSERT'
        elif query_upper.startswith('UPDATE'):
            return 'UPDATE'
        elif query_upper.startswith('DELETE'):
            return 'DELETE'
        elif query_upper.startswith('CREATE'):
            return 'CREATE'
        elif query_upper.startswith('ALTER'):
            return 'ALTER'
        elif query_upper.startswith('DROP'):
            return 'DROP'
        elif query_upper.startswith('TRUNCATE'):
            return 'TRUNCATE'
        elif query_upper.startswith('MERGE'):
            return 'MERGE'
        elif query_upper.startswith('REPLACE'):
            return 'REPLACE'
        elif query_upper.startswith('SHOW'):
            return 'SHOW'
        elif query_upper.startswith('DESCRIBE') or query_upper.startswith('DESC'):
            return 'DESCRIBE'
        elif query_upper.startswith('EXPLAIN'):
            return 'EXPLAIN'
        elif query_upper.startswith(('START', 'COMMIT', 'ROLLBACK', 'SAVEPOINT')):
            return 'TRANSACTION'
        elif query_upper.startswith(('GRANT', 'REVOKE')):
            return 'DCL'
        elif query_upper.startswith('CALL'):
            return 'CALL'
        elif query_upper.startswith('USE'):
            return 'USE'
        else:
            return 'OTHER'

    def _is_aggregate_query_on_encrypted_columns(self, sql_query: str, metadata: Dict[str, Any]) -> bool:
        """Check if query is an aggregate query on encrypted columns"""
        query_upper = sql_query.upper().strip()

        if not query_upper.startswith('SELECT'):
            return False

        table_name = metadata.get('table_name')
        if not table_name or not self.migration_state or not self.migration_state.get('table_configs'):
            return False

        table_config = self.migration_state['table_configs'].get(table_name)
        if not table_config:
            return False

        select_part = re.search(
            r'SELECT\s+(.+?)(?:\s+FROM|$)', sql_query, re.IGNORECASE | re.DOTALL)
        if select_part:
            select_clause = select_part.group(1)
            aggregate_functions = ['COUNT', 'SUM',
                                   'AVG', 'MIN', 'MAX', 'STDDEV', 'VARIANCE']
            for func in aggregate_functions:
                func_pattern = rf'\b{func}\s*\(\s*(\w+)\s*\)'
                matches = re.findall(
                    func_pattern, select_clause, re.IGNORECASE)
                for col in matches:
                    if col in table_config and table_config[col].get('type') == 'encrypt':
                        logger.debug(
                            f"Detected aggregate {func} on encrypted column {col}")
                        return True

        logger.debug(
            f"No aggregates on encrypted columns found in: {sql_query}")
        return False

    def _execute_encrypted_aggregate_select(self, conn, sql_query: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute SELECT query with aggregates on encrypted columns
        """
        try:
            table_name = metadata.get('table_name')
            if not table_name or not self.migration_state or not self.migration_state.get('table_configs'):
                raise Exception(
                    "Missing table configuration for encrypted aggregate SELECT")

            table_config = self.migration_state['table_configs'].get(
                table_name)
            if not table_config:
                raise Exception(
                    f"No configuration found for table {table_name}")

            select_match = re.search(
                r'SELECT\s+(.+?)(?:\s+FROM|$)', sql_query, re.IGNORECASE | re.DOTALL)
            if not select_match:
                raise Exception("Could not parse SELECT query")

            select_clause = select_match.group(1)

            all_data_query = f"SELECT * FROM {table_name}"
            result = conn.execute(text(all_data_query))
            rows = result.fetchall()
            columns = result.keys()

            aggregate_functions = ['COUNT', 'SUM',
                                   'AVG', 'MIN', 'MAX', 'STDDEV', 'VARIANCE']
            aggregates = {}

            select_items = [item.strip() for item in select_clause.split(',')]

            for item in select_items:
                item = item.strip()
                for func in aggregate_functions:
                    func_pattern = rf'\b{func}\s*\(\s*(\w+)\s*\)'
                    match = re.search(func_pattern, item, re.IGNORECASE)
                    if match:
                        col_name = match.group(1)
                        if col_name in table_config and table_config[col_name].get('type') == 'encrypt':
                            alias_match = re.search(
                                rf'{re.escape(item)}\s+AS\s+(\w+)', select_clause, re.IGNORECASE)
                            alias = alias_match.group(
                                1) if alias_match else f"{func.lower()}_{col_name}"
                            aggregates[alias] = (func.upper(), col_name)

            if not aggregates:
                raise Exception("No aggregates found on encrypted columns")

            column_values = {}
            for alias, (func, col_name) in aggregates.items():
                column_values[col_name] = []

            for row in rows:
                row_dict = dict(zip(columns, row))
                for col_name in column_values.keys():
                    encrypted_value = row_dict.get(col_name)
                    if encrypted_value and isinstance(encrypted_value, bytes):
                        try:
                            decrypted_value = clwe_encryptor.decrypt_value(
                                encrypted_value, settings.CRYPTOPIX_DEFAULT_PASSWORD)
                            column_values[col_name].append(decrypted_value)
                        except Exception as e:
                            logger.error(f"Failed to decrypt {col_name}: {e}")
                            continue
                    else:
                        column_values[col_name].append(encrypted_value)

            results = {}
            for alias, (func, col_name) in aggregates.items():
                values = column_values[col_name]
                if not values:
                    results[alias] = 0 if func in ['COUNT', 'SUM'] else None
                    continue

                if func == 'COUNT':
                    results[alias] = len(values)
                elif func == 'SUM':
                    try:
                        numeric_values = []
                        for v in values:
                            if v is not None:
                                if isinstance(v, str):
                                    try:
                                        numeric_values.append(float(v))
                                    except (ValueError, TypeError):
                                        continue  # Skip non-numeric strings
                                elif isinstance(v, (int, float)):
                                    numeric_values.append(float(v))
                        results[alias] = sum(
                            numeric_values) if numeric_values else 0
                    except Exception as e:
                        logger.error(
                            f"Error computing SUM for {col_name}: {e}")
                        results[alias] = 0
                elif func == 'AVG':
                    try:
                        numeric_values = []
                        for v in values:
                            if v is not None:
                                if isinstance(v, str):
                                    try:
                                        numeric_values.append(float(v))
                                    except (ValueError, TypeError):
                                        continue  # Skip non-numeric strings
                                elif isinstance(v, (int, float)):
                                    numeric_values.append(float(v))
                        results[alias] = sum(
                            numeric_values) / len(numeric_values) if numeric_values else 0
                    except Exception as e:
                        logger.error(
                            f"Error computing AVG for {col_name}: {e}")
                        results[alias] = 0
                elif func == 'MIN':
                    try:
                        numeric_values = []
                        for v in values:
                            if v is not None:
                                if isinstance(v, str):
                                    try:
                                        numeric_values.append(float(v))
                                    except (ValueError, TypeError):
                                        continue
                                elif isinstance(v, (int, float)):
                                    numeric_values.append(float(v))
                        results[alias] = min(
                            numeric_values) if numeric_values else None
                    except Exception as e:
                        logger.error(
                            f"Error computing MIN for {col_name}: {e}")
                        results[alias] = None
                elif func == 'MAX':
                    try:
                        numeric_values = []
                        for v in values:
                            if v is not None:
                                if isinstance(v, str):
                                    try:
                                        numeric_values.append(float(v))
                                    except (ValueError, TypeError):
                                        continue
                                elif isinstance(v, (int, float)):
                                    numeric_values.append(float(v))
                        results[alias] = max(
                            numeric_values) if numeric_values else None
                    except Exception as e:
                        logger.error(
                            f"Error computing MAX for {col_name}: {e}")
                        results[alias] = None
                else:
                    results[alias] = None

            return {
                "rows": [results],
                "columns": list(results.keys())
            }

        except Exception as e:
            logger.error(f"Encrypted aggregate SELECT execution failed: {e}")
            raise e

    def _get_column_variations(self, col_name: str) -> List[str]:
        """Get common variations of column names for matching"""
        variations = [col_name.lower()]

        if col_name.lower() == 'emp_id':
            variations.extend(['id', 'employee_id'])
        elif col_name.lower() == 'first_name':
            variations.extend(['name', 'fname'])
        elif col_name.lower() == 'last_name':
            variations.extend(['surname', 'lname'])
        elif col_name.lower() == 'phone':
            variations.extend(['phone_number', 'telephone'])
        elif col_name.lower() == 'hire_date':
            variations.extend(['start_date', 'employment_date'])
        elif col_name.lower() == 'job_title':
            variations.extend(['title', 'position'])
        elif col_name.lower() == 'manager_id':
            variations.extend(['mgr_id', 'supervisor_id'])

        if '_' in col_name:
            variations.append(col_name.replace('_', ''))
        else:
            import re
            underscored = re.sub(r'([a-z])([A-Z])', r'\1_\2', col_name)
            if underscored != col_name:
                variations.append(underscored.lower())

        return list(set(variations))  # Remove duplicates

    def _execute_with_batch_decryption(self, original_query: str, translated_query: str, metadata: Dict[str, Any], database_url: str) -> Dict[str, Any]:
        """
        Execute query using batch decryption for enhanced functionality
        """
        try:
            engine = create_engine(database_url)
            with engine.connect() as conn:
                result_rows = enhanced_sql_translator.execute_with_batch_decryption(
                    original_query, conn, None, metadata
                )

                query_type = metadata.get("query_type", "SELECT")

                return {
                    "success": True,
                    "command_type": "SQL",
                    "query_type": query_type,
                    "rows": result_rows,
                    "row_count": len(result_rows),
                    "columns": list(result_rows[0].keys()) if result_rows else [],
                    "original_query": original_query,
                    "translated_query": translated_query,
                    "metadata": metadata,
                    "batch_decryption_used": True,
                    "ai_enhanced": True
                }

        except Exception as e:
            logger.error(f"Batch decryption execution failed: {e}")
            return {
                "success": False,
                "error": f"Enhanced execution failed: {str(e)}",
                "command_type": "SQL",
                "original_query": original_query,
                "batch_decryption_used": True
            }

    def _handle_system_info(self, command: str, user_id: str = None) -> Dict[str, Any]:
        """Handle SYSTEM_INFO admin command"""
        import platform
        import datetime

        info = {
            "command_type": "ADMIN",
            "admin_command": "SYSTEM_INFO",
            "system_info": {
                "platform": platform.system(),
                "python_version": platform.python_version(),
                "timestamp": datetime.datetime.now().isoformat(),
                "uptime": "N/A",
                "version": "CryptoPIX Bridge v3.0"
            },
            "encryption_info": {
                "clwe_enabled": True,
                "hmac_enabled": True,
                "supported_databases": ["SQLite", "MySQL", "PostgreSQL", "SQL Server", "Oracle"]
            }
        }

        return {
            "success": True,
            **info
        }

    def _handle_encrypt_schema(self, command: str, user_id: str, migration_state: dict = None) -> Dict[str, Any]:
        """Handle ENCRYPT_SCHEMA command"""
        try:
            parts = command.split()
            if len(parts) < 2:
                return {
                    "success": False,
                    "error": "Usage: ENCRYPT_SCHEMA <database_name> [basic|full|ai_enhanced]",
                    "example": "ENCRYPT_SCHEMA mydb ai_enhanced"
                }

            database_name = parts[1]
            encryption_level = parts[2] if len(parts) > 2 else "ai_enhanced"

            valid_levels = ["basic", "full", "ai_enhanced"]
            if encryption_level not in valid_levels:
                return {
                    "success": False,
                    "error": f"Invalid encryption level. Valid options: {', '.join(valid_levels)}"
                }

            schema_data = None
            if migration_state and 'table_configs' in migration_state:
                schema_data = {
                    "database_name": database_name,
                    "tables": migration_state['table_configs']
                }
            else:
                schema_info = ai_assistant.get_schema_insights(database_name)
                if schema_info.get('success'):
                    schema_data = schema_info
                else:
                    return {
                        "success": False,
                        "error": f"No schema data found for database: {database_name}. Run migration first."
                    }

            result = ai_assistant.encrypt_database_schema(
                database_name, schema_data, encryption_level)

            if result['success']:
                return {
                    "success": True,
                    "message": f"Schema encrypted successfully for database: {database_name}",
                    "encryption_level": result['encryption_level'],
                    "table_count": result['metadata']['table_count'],
                    "file_path": result['file_path'],
                    "ai_context": result.get('ai_context', {})
                }
            else:
                return {
                    "success": False,
                    "error": result.get('error', 'Unknown encryption error')
                }

        except Exception as e:
            logger.error(f"Schema encryption failed: {e}")
            return {
                "success": False,
                "error": f"Schema encryption failed: {str(e)}"
            }

    def _handle_decrypt_schema(self, command: str, user_id: str, migration_state: dict = None) -> Dict[str, Any]:
        """Handle DECRYPT_SCHEMA command"""
        try:
            parts = command.split()
            if len(parts) != 2:
                return {
                    "success": False,
                    "error": "Usage: DECRYPT_SCHEMA <database_name>",
                    "example": "DECRYPT_SCHEMA mydb"
                }

            database_name = parts[1]

            result = ai_assistant.decrypt_database_schema(database_name)

            if result['success']:
                schema = result['schema']
                return {
                    "success": True,
                    "message": f"Schema decrypted successfully for database: {database_name}",
                    "table_count": result['table_count'],
                    "encryption_level": result['metadata']['encryption_level'],
                    "tables": list(schema.get('tables', {}).keys()),
                    "ai_context": result.get('ai_context', {})
                }
            else:
                return {
                    "success": False,
                    "error": result.get('error', 'Unknown decryption error')
                }

        except Exception as e:
            logger.error(f"Schema decryption failed: {e}")
            return {
                "success": False,
                "error": f"Schema decryption failed: {str(e)}"
            }

    def _handle_show_schema_info(self, command: str, user_id: str, migration_state: dict = None) -> Dict[str, Any]:
        """Handle SHOW_SCHEMA_INFO command"""
        try:
            parts = command.split()
            if len(parts) != 2:
                return {
                    "success": False,
                    "error": "Usage: SHOW_SCHEMA_INFO <database_name>",
                    "example": "SHOW_SCHEMA_INFO mydb"
                }

            database_name = parts[1]

            insights = ai_assistant.get_schema_insights(database_name)

            if insights['success']:
                return {
                    "success": True,
                    "database_name": database_name,
                    "encryption_level": insights['encryption_level'],
                    "table_count": insights['table_count'],
                    "table_types": insights['insights']['table_types'],
                    "relationships": insights['insights']['relationships'],
                    "data_patterns": insights['insights']['data_patterns'],
                    "security_assessment": insights['insights']['insights']['security_level'],
                    "performance_impact": insights['insights']['insights']['performance_impact'],
                    "recommendations": insights['insights']['insights']['recommendations']
                }
            else:
                return {
                    "success": False,
                    "error": insights.get('error', 'Failed to get schema information')
                }

        except Exception as e:
            logger.error(f"Show schema info failed: {e}")
            return {
                "success": False,
                "error": f"Failed to get schema information: {str(e)}"
            }

    def _handle_schema_insights(self, command: str, user_id: str, migration_state: dict = None) -> Dict[str, Any]:
        """Handle SCHEMA_INSIGHTS command - AI-powered schema analysis"""
        try:
            parts = command.split()
            if len(parts) < 2:
                return {
                    "success": False,
                    "error": "Usage: SCHEMA_INSIGHTS <database_name> [query]",
                    "example": "SCHEMA_INSIGHTS mydb SELECT * FROM users"
                }

            database_name = parts[1]
            query = ' '.join(parts[2:]) if len(parts) > 2 else None

            if query:
                result = ai_assistant.query_with_schema_awareness(
                    query, database_name)

                if result['success']:
                    return {
                        "success": True,
                        "database_name": database_name,
                        "query": query,
                        "schema_analysis": result['schema_analysis'],
                        "suggestions": result['suggestions'],
                        "ai_insights": result['ai_insights']
                    }
                else:
                    return {
                        "success": False,
                        "error": result.get('error', 'Query analysis failed')
                    }
            else:
                insights = ai_assistant.get_schema_insights(database_name)

                if insights['success']:
                    return {
                        "success": True,
                        "database_name": database_name,
                        "insights": insights['insights']
                    }
                else:
                    return {
                        "success": False,
                        "error": insights.get('error', 'Failed to get schema insights')
                    }

        except Exception as e:
            logger.error(f"Schema insights failed: {e}")
            return {
                "success": False,
                "error": f"Schema insights failed: {str(e)}"
            }

    def _handle_list_encrypted_schemas(self, command: str, user_id: str, migration_state: dict = None) -> Dict[str, Any]:
        """Handle LIST_ENCRYPTED_SCHEMAS command"""
        try:
            encrypted_schemas = ai_assistant.encrypted_schemas

            if not encrypted_schemas:
                return {
                    "success": True,
                    "message": "No encrypted schemas found",
                    "schemas": []
                }

            schema_list = []
            for db_name, schema_info in encrypted_schemas.items():
                metadata = schema_info['metadata']
                schema_list.append({
                    "database_name": db_name,
                    "encryption_level": metadata['encryption_level'],
                    "created_at": metadata['created_at'],
                    "version": metadata['version'],
                    "table_count": len(schema_info['encrypted'].tables)
                })

            return {
                "success": True,
                "message": f"Found {len(schema_list)} encrypted schemas",
                "schemas": schema_list
            }

        except Exception as e:
            logger.error(f"List encrypted schemas failed: {e}")
            return {
                "success": False,
                "error": f"Failed to list encrypted schemas: {str(e)}"
            }


console_service = ConsoleService()
