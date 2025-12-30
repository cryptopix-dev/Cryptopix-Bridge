"""
CryptoPIX Bridge v3.0 - Virtual Database Server (VDS)
A smart intermediary that allows client applications to interact with fully encrypted databases
exactly as if they were communicating with a normal database. The VDS emulates the original
database protocol, accepts SQL queries from the application without requiring any code or
configuration changes, and manages all encryption and decryption processes internally.
"""

import asyncio
import logging
import socket
import struct
import threading
import time
from typing import Dict, Any, Optional, List, Tuple
from concurrent.futures import ThreadPoolExecutor
import json
import random
import re
from pathlib import Path

# Database protocol libraries
try:
    import pymysql
    from pymysql.connections import Connection
    from pymysql.cursors import Cursor
    PYMYSQL_AVAILABLE = True
except ImportError:
    PYMYSQL_AVAILABLE = False
    pymysql = None

try:
    import psycopg2
    from psycopg2 import connect as pg_connect
    from psycopg2.extensions import cursor as pg_cursor
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False
    psycopg2 = None

from sqlalchemy import create_engine, text, inspect
from sqlalchemy.engine import Engine

from app.config import settings
from app.middleware.sql_interceptor import sql_interceptor
from app.services.ai_assistant import ai_assistant, TableMapping, ColumnMapping
from app.services.enhanced_sql_translator import enhanced_sql_translator
from app.services.console_service import console_service
from app.core.encryption import clwe_encryptor
from app.core.database_adapters import DatabaseType

logger = logging.getLogger(__name__)


# MySQL Protocol Constants
MYSQL_PROTOCOL_VERSION = 10
MYSQL_SERVER_VERSION = "8.0.32-CryptoPIX"
MYSQL_DEFAULT_CHARSET = 255

# MySQL Capability Flags
CLIENT_LONG_PASSWORD = 0x00000001
CLIENT_FOUND_ROWS = 0x00000002
CLIENT_LONG_FLAG = 0x00000004
CLIENT_CONNECT_WITH_DB = 0x00000008
CLIENT_NO_SCHEMA = 0x00000010
CLIENT_COMPRESS = 0x00000020
CLIENT_ODBC = 0x00000040
CLIENT_LOCAL_FILES = 0x00000080
CLIENT_IGNORE_SPACE = 0x00000100
CLIENT_PROTOCOL_41 = 0x00000200
CLIENT_INTERACTIVE = 0x00000400
CLIENT_SSL = 0x00000800
CLIENT_IGNORE_SIGPIPE = 0x00001000
CLIENT_TRANSACTIONS = 0x00002000
CLIENT_RESERVED = 0x00004000
CLIENT_SECURE_CONNECTION = 0x00008000
CLIENT_MULTI_STATEMENTS = 0x00010000
CLIENT_MULTI_RESULTS = 0x00020000
CLIENT_PS_MULTI_RESULTS = 0x00040000
CLIENT_PLUGIN_AUTH = 0x00080000
CLIENT_CONNECT_ATTRS = 0x00100000
CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000
CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS = 0x00400000
CLIENT_SESSION_TRACK = 0x00800000
CLIENT_DEPRECATE_EOF = 0x01000000

MYSQL_DEFAULT_CAPABILITIES = (
    CLIENT_LONG_PASSWORD |
    CLIENT_FOUND_ROWS |
    CLIENT_LONG_FLAG |
    CLIENT_CONNECT_WITH_DB |
    CLIENT_NO_SCHEMA |
    CLIENT_COMPRESS |
    CLIENT_ODBC |
    CLIENT_LOCAL_FILES |
    CLIENT_IGNORE_SPACE |
    CLIENT_PROTOCOL_41 |
    CLIENT_INTERACTIVE |
    CLIENT_IGNORE_SIGPIPE |
    CLIENT_TRANSACTIONS |
    CLIENT_RESERVED |
    CLIENT_SECURE_CONNECTION |
    CLIENT_MULTI_STATEMENTS |
    CLIENT_MULTI_RESULTS |
    CLIENT_PS_MULTI_RESULTS |
    CLIENT_PLUGIN_AUTH |
    CLIENT_CONNECT_ATTRS |
    CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA |
    CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS |
    CLIENT_SESSION_TRACK |
    CLIENT_DEPRECATE_EOF
)

# MySQL Status Flags
SERVER_STATUS_IN_TRANS = 0x0001
SERVER_STATUS_AUTOCOMMIT = 0x0002
SERVER_MORE_RESULTS_EXISTS = 0x0008
SERVER_STATUS_NO_GOOD_INDEX_USED = 0x0010
SERVER_STATUS_NO_INDEX_USED = 0x0020
SERVER_STATUS_CURSOR_EXISTS = 0x0040
SERVER_STATUS_LAST_ROW_SENT = 0x0080
SERVER_STATUS_DB_DROPPED = 0x0100
SERVER_STATUS_NO_BACKSLASH_ESCAPES = 0x0200
SERVER_STATUS_METADATA_CHANGED = 0x0400
SERVER_QUERY_WAS_SLOW = 0x0800
SERVER_PS_OUT_PARAMS = 0x1000
SERVER_STATUS_IN_TRANS_READONLY = 0x2000
SERVER_SESSION_STATE_CHANGED = 0x4000

MYSQL_DEFAULT_STATUS = SERVER_STATUS_AUTOCOMMIT

# MySQL Command Types
COM_SLEEP = 0x00
COM_QUIT = 0x01
COM_INIT_DB = 0x02
COM_QUERY = 0x03
COM_FIELD_LIST = 0x04
COM_CREATE_DB = 0x05
COM_DROP_DB = 0x06
COM_REFRESH = 0x07
COM_SHUTDOWN = 0x08
COM_STATISTICS = 0x09
COM_PROCESS_INFO = 0x0a
COM_CONNECT = 0x0b
COM_PROCESS_KILL = 0x0c
COM_DEBUG = 0x0d
COM_PING = 0x0e
COM_TIME = 0x0f
COM_DELAYED_INSERT = 0x10
COM_CHANGE_USER = 0x11
COM_BINLOG_DUMP = 0x12
COM_TABLE_DUMP = 0x13
COM_CONNECT_OUT = 0x14
COM_REGISTER_SLAVE = 0x15
COM_STMT_PREPARE = 0x16
COM_STMT_EXECUTE = 0x17
COM_STMT_SEND_LONG_DATA = 0x18
COM_STMT_CLOSE = 0x19
COM_STMT_RESET = 0x1a
COM_SET_OPTION = 0x1b
COM_STMT_FETCH = 0x1c
COM_DAEMON = 0x1d
COM_BINLOG_DUMP_GTID = 0x1e
COM_RESET_CONNECTION = 0x1f

# MySQL Response Types
OK_PACKET = 0x00
ERR_PACKET = 0xff
EOF_PACKET = 0xfe


class VDSInstance:
    """
    Independent Virtual Database Server Instance - Fully isolated VDS with own resources.

    Each VDSInstance owns its own socket, console_service, threads, DB connection, and running flag.
    Multiple instances can run simultaneously without resource conflicts.
    """

    def __init__(self, host='0.0.0.0', port=3306, encrypted_db_url=None, target_protocol='mysql',
                 table_mappings=None, max_connections=100, migration_state=None):
        """
        Initialize an independent VDS instance

        Args:
            host: Host to bind to
            port: Port to bind to
            encrypted_db_url: URL of the underlying encrypted database
            target_protocol: Protocol to emulate (mysql, postgresql)
            table_mappings: Dictionary of table mappings (config/schema)
            max_connections: Maximum concurrent connections
            migration_state: Full migration state dictionary
        """
        self.host = host
        self.port = port
        self.encrypted_db_url = encrypted_db_url or settings.ENCRYPTED_DB_URL
        # Ensure MySQL URLs use PyMySQL driver
        if self.encrypted_db_url.startswith('mysql://'):
            self.encrypted_db_url = self.encrypted_db_url.replace(
                'mysql://', 'mysql+pymysql://', 1)
        self.target_protocol = target_protocol.lower()
        self.max_connections = max_connections
        self.table_mappings = table_mappings or {}

        # Per-instance service instances - no global sharing
        from app.services.console_service import ConsoleService
        from app.services.ai_assistant import AIAssistant
        self.console_service = ConsoleService()
        self.ai_assistant = AIAssistant()

        # Per-instance migration state
        self.migration_state = migration_state
        if not self.migration_state:
            self.migration_state = self.console_service._load_migration_state_from_files(
                self.encrypted_db_url)

        # Per-instance resources
        self.running = False
        self.server_socket = None
        self.executor = ThreadPoolExecutor(
            max_workers=max_connections, thread_name_prefix=f'VDS-{host}-{port}')

        # Per-instance connection tracking
        self.active_connections = {}
        self.connection_counter = 0
        self.connection_lock = threading.Lock()

        # Per-instance schema cache
        self.schema_cache = {}
        self.cache_lock = threading.Lock()

        # Per-instance prepared statement cache
        # Format: {connection_id: {stmt_id: {'sql': str, 'params': list, 'num_params': int}}}
        self.prepared_statements = {}
        self.stmt_counter = 0
        self.stmt_lock = threading.Lock()

        # Per-instance accept thread
        self.accept_thread = None

        # Initialize per-instance components
        self._setup_schema_mappings()
        self._setup_encryption_engine()

        logger.info(
            f"VDS Instance initialized for {target_protocol} protocol on {host}:{port}")
        logger.info(
            f"Instance owns dedicated resources: socket, services, threads, DB connection")
        logger.info(f"VDS encrypted DB URL: {self.encrypted_db_url}")

    def _setup_schema_mappings(self):
        """Setup schema mappings for translating normal column names to encrypted equivalents"""
        try:
            # Load migration state using the same method as console service
            if not hasattr(self, 'migration_state') or not self.migration_state:
                self.migration_state = self.console_service._load_migration_state_from_files(
                    self.encrypted_db_url)
            
            # Ensure the console service has the migration state set
            self.console_service.migration_state = self.migration_state

            logger.info(
                f"VDS Instance loaded migration state: {bool(self.migration_state)}")
            if self.migration_state:
                logger.info(
                    f"Migration state keys: {list(self.migration_state.keys())}")
                if self.migration_state.get("encrypted_db_url"):
                    self.encrypted_db_url = self.migration_state["encrypted_db_url"]
                    # Ensure MySQL URLs use PyMySQL driver
                    if self.encrypted_db_url.startswith('mysql://'):
                        self.encrypted_db_url = self.encrypted_db_url.replace(
                            'mysql://', 'mysql+pymysql://', 1)
                    logger.info(
                        f"Using encrypted DB URL from migration state: {self.encrypted_db_url}")

            # Register table mappings using the same method as console service
            self.console_service._register_table_mappings()

            # Get table mappings from console service's database_mappings
            database_key = self.console_service._get_database_key()
            if database_key in self.console_service.database_mappings:
                self.table_mappings = self.console_service.database_mappings[database_key].copy()
                logger.info(
                    f"VDS Instance loaded {len(self.table_mappings)} table mappings from console service")
            else:
                logger.warning(f"No database mappings found for key: {database_key}")
                self.table_mappings = {}

            # Also get database schemas if available
            self.database_schemas = {}

            logger.info(
                f"VDS Instance table_mappings: {list(self.table_mappings.keys())}")

            # Set database type for translators
            from app.services import enhanced_sql_translator
            from app.middleware.sql_interceptor import sql_interceptor
            from app.services.sql_translator import sql_translator
            sql_translator.set_database_type(self.encrypted_db_url)
            sql_interceptor.set_database_type(self.encrypted_db_url)

            # Debug: Log detailed mapping info
            for table_name, mapping in self.table_mappings.items():
                logger.info(
                    f"VDS Instance Table {table_name} mapping: encrypted_cols={list(mapping.encrypted_columns.keys())}, non_encrypted={mapping.non_encrypted_columns}")

        except Exception as e:
            logger.error(
                f"Failed to setup schema mappings in VDS Instance: {e}")
            import traceback
            logger.error(traceback.format_exc())
            # Set empty mappings as fallback
            self.table_mappings = {}
            self.database_schemas = {}
            logger.warning("VDS Instance using empty table mappings")

    def _setup_encryption_engine(self):
        """Setup encryption engine for transparent data handling"""
        try:
            # Verify CLWE encryption is working
            test_data = "test_encryption"
            encrypted = clwe_encryptor.encrypt_value(
                test_data, settings.CRYPTOPIX_DEFAULT_PASSWORD)
            decrypted = clwe_encryptor.decrypt_value(
                encrypted, settings.CRYPTOPIX_DEFAULT_PASSWORD)

            if decrypted == test_data:
                logger.info(
                    "CLWE encryption engine verified and ready for VDS Instance")
            else:
                logger.error(
                    "CLWE encryption engine verification failed for VDS Instance")
        except Exception as e:
            logger.error(
                f"Failed to setup encryption engine for VDS Instance: {e}")

    def start(self):
        """Start the VDS instance"""
        try:
            if self.running:
                logger.warning(
                    f"VDS Instance {self.host}:{self.port} is already running")
                return

            self.server_socket = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(self.max_connections)
            # Non-blocking accept to allow immediate shutdown
            self.server_socket.settimeout(0.1)
            self.running = True

            logger.info(
                f"VDS Instance started on {self.host}:{self.port}")
            logger.info(
                f"Accepting {self.target_protocol} connections with transparent encryption")

            # Start accepting connections in a dedicated thread
            self.accept_thread = threading.Thread(
                target=self._accept_connections, daemon=True, name=f'VDS-Accept-{self.host}-{self.port}')
            self.accept_thread.start()

        except Exception as e:
            logger.error(f"Failed to start VDS Instance: {e}")
            self.running = False
            raise

    def stop(self, timeout=5.0):
        """Stop the VDS instance with proper timeout"""
        try:
            logger.info(f"Stopping VDS Instance {self.host}:{self.port}...")
            self.running = False

            # Join the accept thread with timeout
            if self.accept_thread and self.accept_thread.is_alive():
                self.accept_thread.join(timeout=timeout)
                if self.accept_thread.is_alive():
                    logger.warning(
                        f"Accept thread for {self.host}:{self.port} did not terminate within {timeout}s")

            # Close all active connections
            with self.connection_lock:
                # Create a copy of items to avoid runtime error during iteration
                active_conns = list(self.active_connections.items())
                for conn_id, conn_info in active_conns:
                    try:
                        if conn_info.get('socket'):
                            conn_info['socket'].shutdown(socket.SHUT_RDWR)
                            conn_info['socket'].close()
                        logger.info(
                            f"Closed connection {conn_id} for VDS Instance {self.host}:{self.port}")
                    except Exception as e:
                        logger.warning(
                            f"Error closing connection {conn_id}: {e}")
                self.active_connections.clear()

            # Close server socket
            if self.server_socket:
                try:
                    self.server_socket.shutdown(socket.SHUT_RDWR)
                    self.server_socket.close()
                except Exception as e:
                    logger.warning(
                        f"Error closing server socket for {self.host}:{self.port}: {e}")
                self.server_socket = None

            # Shutdown executor with timeout
            self.executor.shutdown(wait=True, timeout=timeout)

            logger.info(
                f"VDS Instance {self.host}:{self.port} stopped successfully")

        except Exception as e:
            logger.error(
                f"Error during VDS Instance {self.host}:{self.port} stop: {e}")

    def _accept_connections(self):
        """Accept incoming client connections for this instance"""
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()

                # Check connection limit
                with self.connection_lock:
                    if len(self.active_connections) >= self.max_connections:
                        logger.warning(
                            f"Connection limit reached ({self.max_connections}) for VDS {self.host}:{self.port}, rejecting connection from {client_address}")
                        client_socket.close()
                        continue

                    self.connection_counter += 1
                    connection_id = self.connection_counter

                    self.active_connections[connection_id] = {
                        'socket': client_socket,
                        'address': client_address,
                        'connected_at': time.time(),
                        'last_activity': time.time()
                    }

                logger.info(
                    f"VDS Instance {self.host}:{self.port}: New connection {connection_id} from {client_address}")

                # Handle connection in separate thread
                self.executor.submit(
                    self._handle_connection, connection_id, client_socket, client_address)

            except socket.timeout:
                # Timeout occurred, check if we should still be running
                continue
            except OSError:
                # Socket was closed
                break
            except Exception as e:
                if not self.running:
                    break
                logger.error(
                    f"Error accepting connection for VDS {self.host}:{self.port}: {e}")

    def _handle_connection(self, connection_id: int, client_socket: socket.socket, client_address: tuple):
        """Handle individual client connection with session isolation"""
        try:
            if self.target_protocol == "mysql":
                self._handle_mysql_connection_logic(connection_id, client_socket)
            else:
                # For other protocols, send simple acknowledgment
                greeting = b"VDS Ready\n"
                client_socket.sendall(greeting)
                
                while self.running:
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    # Simple echo for now
                    client_socket.sendall(f"Received: {len(data)} bytes\n".encode())

        except Exception as e:
            logger.error(f"Error in connection handler {connection_id}: {e}")
        finally:
            # Clean up connection
            try:
                client_socket.close()
            except:
                pass
            with self.connection_lock:
                if connection_id in self.active_connections:
                    del self.active_connections[connection_id]
            logger.info(f"VDS Instance {self.host}:{self.port}: Connection {connection_id} closed")

    def _handle_mysql_connection_logic(self, connection_id: int, client_socket: socket.socket):
        """Handle MySQL wire protocol connection"""
        try:
            logger.info(f"Handling MySQL connection {connection_id}")

            # Send greeting packet
            greeting_packet = self._build_mysql_greeting_packet()
            if not greeting_packet:
                logger.error("Failed to build greeting packet")
                return

            client_socket.send(greeting_packet)
            logger.info(f"Sent MySQL greeting to connection {connection_id} (seq 0)")

            # Handle handshake response first
            sequence_number = 1  # Greeting was sequence 0

            # Receive handshake response with improved error handling
            header = b""
            while len(header) < 4:
                chunk = client_socket.recv(4 - len(header))
                if not chunk:
                    logger.warning("Connection closed during handshake")
                    return
                header += chunk

            packet_length = struct.unpack('<I', header[:3] + b'\x00')[0]
            packet_seq = header[3]

            # Validate packet length
            if packet_length > 16 * 1024 * 1024:  # 16MB max
                logger.error(f"Handshake packet too large: {packet_length} bytes")
                return

            packet_body = b""
            while len(packet_body) < packet_length:
                remaining = packet_length - len(packet_body)
                chunk = client_socket.recv(min(4096, remaining))
                if not chunk:
                    return
                packet_body += chunk

            # Process handshake response
            if not self._process_mysql_handshake_response(packet_body, connection_id):
                logger.error(f"Handshake failed for connection {connection_id}")
                return

            # Send OK packet to acknowledge authentication
            sequence_number = (packet_seq + 1) % 256
            ok_packet = self._build_mysql_ok_packet(sequence_number)
            client_socket.send(ok_packet)
            logger.info(f"Sent auth OK packet with seq {sequence_number}")
            sequence_number = (sequence_number + 1) % 256

            # Mark as authenticated
            if connection_id in self.active_connections:
                self.active_connections[connection_id]['authenticated'] = True

            # Now handle subsequent packets (queries)
            while self.running:
                try:
                    # Receive packet header
                    header = b""
                    while len(header) < 4:
                        chunk = client_socket.recv(4 - len(header))
                        if not chunk:
                            break
                        header += chunk

                    if len(header) != 4:
                        break

                    packet_length = struct.unpack('<I', header[:3] + b'\x00')[0]
                    packet_seq = header[3]

                    # Validate packet length
                    if packet_length > 16 * 1024 * 1024:
                        break

                    # Update sequence number based on received packet
                    sequence_number = (packet_seq + 1) % 256

                    # Receive packet body
                    packet_body = b""
                    while len(packet_body) < packet_length:
                        remaining = packet_length - len(packet_body)
                        chunk = client_socket.recv(min(4096, remaining))
                        if not chunk:
                            break
                        packet_body += chunk

                    if len(packet_body) != packet_length:
                        break

                    # Process packet based on first byte
                    if packet_body:
                        packet_type = packet_body[0]

                        if packet_type == COM_QUIT:
                            logger.info(f"Client {connection_id} sent COM_QUIT")
                            # Clean up prepared statements for this connection
                            with self.stmt_lock:
                                if connection_id in self.prepared_statements:
                                    del self.prepared_statements[connection_id]
                            break
                            
                        elif packet_type == COM_QUERY:
                            # Handle SQL query
                            query = packet_body[1:].decode('utf-8', errors='ignore')
                            logger.info(f"COM_QUERY from {connection_id}: {query[:100]}...")

                            response_packets = self._process_mysql_query(query, connection_id, sequence_number)
                            # Handle both list of packets and single concatenated bytes
                            if response_packets:
                                if len(response_packets) == 1 and isinstance(response_packets[0], bytes):
                                    # Single item - could be concatenated packets or single packet
                                    client_socket.sendall(response_packets[0])
                                else:
                                    # Multiple packets
                                    for packet in response_packets:
                                        if isinstance(packet, bytes):
                                            client_socket.sendall(packet)
                            # Don't update sequence_number here - it's managed in _process_mysql_query
                            
                        elif packet_type == COM_STMT_PREPARE:
                            # Handle prepared statement preparation
                            query = packet_body[1:].decode('utf-8', errors='ignore')
                            logger.info(f"COM_STMT_PREPARE from {connection_id}: {query[:100]}...")
                            
                            response_packets = self._handle_stmt_prepare(query, connection_id, sequence_number)
                            if response_packets:
                                for packet in response_packets:
                                    if isinstance(packet, bytes):
                                        client_socket.sendall(packet)
                                        
                        elif packet_type == COM_STMT_EXECUTE:
                            # Handle prepared statement execution
                            logger.info(f"COM_STMT_EXECUTE from {connection_id}")
                            
                            response_packets = self._handle_stmt_execute(packet_body, connection_id, sequence_number)
                            if response_packets:
                                if len(response_packets) == 1 and isinstance(response_packets[0], bytes):
                                    client_socket.sendall(response_packets[0])
                                else:
                                    for packet in response_packets:
                                        if isinstance(packet, bytes):
                                            client_socket.sendall(packet)
                                            
                        elif packet_type == COM_STMT_CLOSE:
                            # Handle prepared statement close
                            if len(packet_body) >= 5:
                                stmt_id = struct.unpack('<I', packet_body[1:5])[0]
                                logger.info(f"COM_STMT_CLOSE from {connection_id}, stmt_id={stmt_id}")
                                
                                with self.stmt_lock:
                                    if connection_id in self.prepared_statements:
                                        if stmt_id in self.prepared_statements[connection_id]:
                                            del self.prepared_statements[connection_id][stmt_id]
                                            logger.info(f"Closed prepared statement {stmt_id}")
                            # No response needed for COM_STMT_CLOSE
                            
                        elif packet_type == COM_INIT_DB:
                            # Handle database selection
                            db_name = packet_body[1:].decode('utf-8', errors='ignore')
                            logger.info(f"COM_INIT_DB from {connection_id}: {db_name}")
                            if connection_id in self.active_connections:
                                self.active_connections[connection_id]['database'] = db_name
                            ok_packet = self._build_mysql_ok_packet(sequence_number)
                            client_socket.send(ok_packet)
                            sequence_number = (sequence_number + 1) % 256
                            
                        elif packet_type == COM_PING:
                            # Handle ping
                            logger.debug(f"COM_PING from {connection_id}")
                            ok_packet = self._build_mysql_ok_packet(sequence_number)
                            client_socket.send(ok_packet)
                            sequence_number = (sequence_number + 1) % 256
                            
                        elif packet_type == COM_STMT_RESET:
                            # Handle statement reset
                            if len(packet_body) >= 5:
                                stmt_id = struct.unpack('<I', packet_body[1:5])[0]
                                logger.info(f"COM_STMT_RESET from {connection_id}, stmt_id={stmt_id}")
                            ok_packet = self._build_mysql_ok_packet(sequence_number)
                            client_socket.send(ok_packet)
                            sequence_number = (sequence_number + 1) % 256
                            
                        else:
                            # Unknown command - send OK
                            logger.warning(f"Unknown command type 0x{packet_type:02x} from {connection_id}")
                            ok_packet = self._build_mysql_ok_packet(sequence_number)
                            client_socket.send(ok_packet)
                            sequence_number = (sequence_number + 1) % 256

                except socket.error:
                    break

        except Exception as e:
            logger.error(f"Error handling MySQL connection {connection_id}: {e}")

    def _process_mysql_handshake_response(self, packet_body: bytes, connection_id: int) -> bool:
        """Process the handshake response from client"""
        try:
            if len(packet_body) < 32:
                logger.warning(f"Handshake response too short: {len(packet_body)}")
                return False
            
            idx = 32
            user_end = packet_body.find(b'\x00', idx)
            if user_end != -1:
                username = packet_body[idx:user_end].decode('utf-8', errors='ignore')
                if connection_id in self.active_connections:
                    self.active_connections[connection_id]['username'] = username
                logger.info(f"Connection {connection_id} authenticated as user '{username}'")
                
            return True
        except Exception as e:
            logger.error(f"Error processing handshake response: {e}")
            return False

    def _process_mysql_query(self, query: str, connection_id: int, sequence_number: int) -> List[bytes]:
        """Process MySQL query and return response packets"""
        try:
            query_type = self._analyze_query_type(query) 
            logger.info(f"Processing {query_type} query: {query[:50]}...")
            
            # DEBUG TRACE
            try:
                 with open('d:\\CPIXFINALWITHALLFEATURES\\debug_vds.txt', 'a') as f:
                     f.write(f"VDS Process: {query} -> Type: {query_type}\\n")
            except: pass
            
            if query_type == "SELECT":
                result = self._execute_query(query, connection_id)
                if not result.get("success", False):
                    return [self._build_mysql_error_packet(result.get("error", "Unknown error"))]
                # Return list containing the concatenated result set packets
                return [self._build_mysql_result_set_packets(result, sequence_number)]
                
            elif query_type in ("INSERT", "UPDATE", "DELETE"):
                result = self._execute_query(query, connection_id)
                if not result.get("success", False):
                    return [self._build_mysql_error_packet(result.get("error", "Unknown error"))]
                return [self._build_mysql_ok_packet(sequence_number, result.get("affected_rows", 0))]
                
            elif query_type == "DDL":
                return self._handle_ddl_query(query, connection_id, sequence_number)
                
            elif query_type == "SHOW":
                return self._handle_show_mysql_command(query, sequence_number)
                
            elif query_type == "TRANSACTION":
                 # Simple OK for now
                return [self._build_mysql_ok_packet(sequence_number)]

            elif query_type == "SET":
               return [self._build_mysql_ok_packet(sequence_number)]
               
            else:
                result = self._execute_query(query, connection_id)
                if not result.get("success", False):
                     return [self._build_mysql_error_packet(result.get("error", "Unknown error"))]
                return [self._build_mysql_ok_packet(sequence_number, result.get("affected_rows", 0))]

        except Exception as e:
            logger.error(f"Error processing MySQL query: {e}")
            return [self._build_mysql_error_packet(str(e))]

    def _execute_query(self, query: str, connection_id: int) -> Dict[str, Any]:
        """Execute query using console service"""
        try:
            result = self.console_service.execute_command(
                command=query,
                user_id=f"vds_client_{self.host}_{self.port}_{connection_id}",
                database_url=self.encrypted_db_url,
                migration_state=self.migration_state
            )
            result["processed_by"] = f"VDS_Instance_{self.host}_{self.port}"
            result["connection_id"] = connection_id
            return result
        except Exception as e:
            logger.error(f"Error executing query: {e}")
            return {"success": False, "error": str(e)}

    def _handle_ddl_query(self, query: str, connection_id: int, sequence_number: int) -> List[bytes]:
        """Handle DDL queries using console service for consistent table mapping access"""
        try:
            # Use console service to ensure proper table mapping and migration state handling
            result = self._execute_query(query, connection_id)
            if result.get("success"):
                return [self._build_mysql_ok_packet(sequence_number)]
            else:
                return [self._build_mysql_error_packet(result.get("error", "DDL Failed"))]
        except Exception as e:
            logger.error(f"Error handling DDL query: {e}")
            return [self._build_mysql_error_packet(str(e))]

    def _handle_show_mysql_command(self, query: str, sequence_number: int) -> List[bytes]:
        """Handle SHOW commands"""
        query_upper = query.strip().upper()
        
        if "DATABASES" in query_upper:
             result = {"success": True, "query_type": "SELECT", "columns": ["Database"], "rows": [["encrypted_db"]]}
             return [self._build_mysql_result_set_packets(result, sequence_number)]
        
        if "TABLES" in query_upper:
             try:
                 # First try to get from table_mappings
                 tables = list(self.table_mappings.keys()) if hasattr(self, 'table_mappings') and self.table_mappings else []
                 logger.info(f"VDS table_mappings has {len(tables)} tables: {tables}")
                 
                 if tables:
                     # Use table mappings
                     rows = [[t] for t in tables]
                     result = {"success": True, "query_type": "SELECT", "columns": ["Tables_in_encrypted_db"], "rows": rows}
                     logger.info(f"Returning {len(rows)} tables from table_mappings")
                     return [self._build_mysql_result_set_packets(result, sequence_number)]
                 else:
                     # Fallback: query console service
                     logger.info("No table_mappings, querying console service for SHOW TABLES")
                     res = self._execute_query("SHOW TABLES", 0)
                     logger.info(f"Console service SHOW TABLES result: success={res.get('success')}, rows={len(res.get('rows', []))}")
                     
                     if res.get("success") and res.get("rows"):
                         # Console service returned results
                         logger.info(f"Returning {len(res.get('rows', []))} tables from console service")
                         return [self._build_mysql_result_set_packets(res, sequence_number)]
                     else:
                         # No tables found, return empty result
                         logger.warning("No tables found in console service result")
                         result = {"success": True, "query_type": "SELECT", "columns": ["Tables_in_encrypted_db"], "rows": []}
                         return [self._build_mysql_result_set_packets(result, sequence_number)]
             except Exception as e:
                 logger.error(f"Error handling SHOW TABLES: {e}")
                 return [self._build_mysql_error_packet(f"Error: {str(e)}")]

        # Default fall through for other SHOW commands
        result = self._execute_query(query, 0)
        if result.get("success", False):
             if result.get("query_type") == "SELECT":
                 return [self._build_mysql_result_set_packets(result, sequence_number)]
             else:
                 return [self._build_mysql_ok_packet(sequence_number)]
        return [self._build_mysql_error_packet(result.get("error", "Unknown error"))]

    def _execute_direct_query(self, query: str) -> Dict[str, Any]:
        """
        Execute raw SQL directly on encrypted DB
        
        WARNING: DEPRECATED - This method bypasses the console service and should NOT be used
        for normal operations. It does not:
        - Use proper table mappings
        - Update migration state
        - Handle encryption/decryption properly
        - Maintain consistency with the console service
        
        Use _execute_query() instead, which properly routes through console_service.
        """
        logger.warning("_execute_direct_query is deprecated and bypasses console service. Use _execute_query instead.")
        try:
            engine = create_engine(self.encrypted_db_url)
            with engine.connect() as conn:
                conn.execute(text(query))
                conn.commit()
            return {"success": True}
        except Exception as e:
            logger.error(f"Direct query failed: {e}")
            return {"success": False, "error": str(e)}

    def _describe_table(self, table_name: str) -> Dict[str, Any]:
        return {"success": False, "error": "Not implemented"}

    # Prepared Statement Handlers
    def _handle_stmt_prepare(self, query: str, connection_id: int, sequence_number: int) -> List[bytes]:
        """Handle COM_STMT_PREPARE - prepare a statement and return metadata"""
        try:
            # Generate statement ID
            with self.stmt_lock:
                self.stmt_counter += 1
                stmt_id = self.stmt_counter
                
                # Initialize connection's prepared statements if needed
                if connection_id not in self.prepared_statements:
                    self.prepared_statements[connection_id] = {}
                
                # Count parameters in the query
                num_params = query.count('?')
                
                # Store prepared statement
                self.prepared_statements[connection_id][stmt_id] = {
                    'sql': query,
                    'num_params': num_params,
                    'params': []
                }
                
            logger.info(f"Prepared statement {stmt_id} with {num_params} parameters: {query[:100]}...")
            
            # Build COM_STMT_PREPARE_OK response
            # Format: [header] status(0x00) stmt_id(4) num_columns(2) num_params(2) reserved(1) warning_count(2)
            packets = [self._build_stmt_prepare_ok(stmt_id, num_params, sequence_number)]
            sequence_number = (sequence_number + 1) % 256
            
            # If we have parameters, we MUST send parameter definition packets
            if num_params > 0:
                for i in range(num_params):
                    # Send dummy parameter definition (standard practice)
                    packets.append(self._build_mysql_column_definition_packet("?", sequence_number))
                    sequence_number = (sequence_number + 1) % 256
                
                # Send EOF after params
                packets.append(self._build_mysql_eof_packet(sequence_number))
                sequence_number = (sequence_number + 1) % 256
                
            # Note: We currently send num_columns=0 in OK packet, so we don't send column definitions here.
            # If we ever strictly determine output columns, we'd need to send them here too.
            
            return packets
            
        except Exception as e:
            logger.error(f"Error preparing statement: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return [self._build_mysql_error_packet(f"Failed to prepare statement: {str(e)}", sequence_number)]

    def _handle_stmt_execute(self, packet_body: bytes, connection_id: int, sequence_number: int) -> List[bytes]:
        """Handle COM_STMT_EXECUTE - execute a prepared statement with bound parameters"""
        try:
            if len(packet_body) < 5:
                return [self._build_mysql_error_packet("Invalid COM_STMT_EXECUTE packet", sequence_number)]
            
            # Parse statement ID (bytes 1-4)
            stmt_id = struct.unpack('<I', packet_body[1:5])[0]
            
            # Get prepared statement
            with self.stmt_lock:
                if connection_id not in self.prepared_statements:
                    return [self._build_mysql_error_packet(f"No prepared statements for connection {connection_id}", sequence_number)]
                
                if stmt_id not in self.prepared_statements[connection_id]:
                    return [self._build_mysql_error_packet(f"Unknown statement ID: {stmt_id}", sequence_number)]
                
                stmt_info = self.prepared_statements[connection_id][stmt_id]
            
            sql_template = stmt_info['sql']
            num_params = stmt_info['num_params']
            
            logger.info(f"Executing prepared statement {stmt_id}: {sql_template[:100]}... with {num_params} params")
            
            # Parse parameters from packet
            params = []
            if num_params > 0:
                try:
                    params = self._parse_stmt_execute_params(packet_body, num_params)
                    logger.info(f"Parsed {len(params)} parameters: {params}")
                except Exception as e:
                    logger.error(f"Error parsing parameters: {e}")
                    # Continue with empty params - better than failing
                    params = [None] * num_params
            
            # Build final SQL by replacing ? with actual values
            final_sql = self._build_sql_from_template(sql_template, params)
            logger.info(f"Final SQL to execute: {final_sql[:200]}...")
            
            # Determine query type for separate handling (Binary vs OK)
            query_type = self._analyze_query_type(final_sql)
            
            # Execute query first
            result = self._execute_query(final_sql, connection_id)
            
            if not result.get("success", False):
                return [self._build_mysql_error_packet(result.get("error", "Unknown error"), sequence_number)]
            
            if query_type in ("SELECT", "SHOW", "EXPLAIN"):
                # Return Binary Result Set (required for COM_STMT_EXECUTE)
                return self._build_mysql_binary_result_set_packets(result, sequence_number)
            else:
                # Return OK Packet
                return [self._build_mysql_ok_packet(sequence_number, result.get("affected_rows", 0))]
            
        except Exception as e:
            logger.error(f"Error executing prepared statement: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return [self._build_mysql_error_packet(f"Failed to execute statement: {str(e)}", sequence_number)]

    def _parse_stmt_execute_params(self, packet_body: bytes, num_params: int) -> List[Any]:
        """Parse parameters from COM_STMT_EXECUTE packet"""
        try:
            # COM_STMT_EXECUTE packet structure:
            # 1 byte: command (0x17)
            # 4 bytes: statement_id
            # 1 byte: flags
            # 4 bytes: iteration_count
            # If num_params > 0:
            #   (num_params+7)/8 bytes: null_bitmap
            #   1 byte: new_params_bound_flag
            #   If new_params_bound_flag == 1:
            #     num_params * 2 bytes: parameter types
            #     variable: parameter values
            
            idx = 5  # After command and stmt_id
            
            if len(packet_body) < idx + 5:
                logger.warning("Packet too short for flags and iteration count")
                return [None] * num_params
            
            flags = packet_body[idx]
            idx += 1
            
            iteration_count = struct.unpack('<I', packet_body[idx:idx+4])[0]
            idx += 4
            
            if num_params == 0:
                return []
            
            # Null bitmap
            null_bitmap_len = (num_params + 7) // 8
            if len(packet_body) < idx + null_bitmap_len:
                logger.warning("Packet too short for null bitmap")
                return [None] * num_params
            
            null_bitmap = packet_body[idx:idx + null_bitmap_len]
            idx += null_bitmap_len
            
            # Check if new params are bound
            if len(packet_body) < idx + 1:
                logger.warning("Packet too short for new_params_bound_flag")
                return [None] * num_params
            
            new_params_bound = packet_body[idx]
            idx += 1
            
            params = []
            param_types = []
            
            if new_params_bound == 1:
                # Read parameter types
                if len(packet_body) < idx + (num_params * 2):
                    logger.warning("Packet too short for parameter types")
                    return [None] * num_params
                
                for i in range(num_params):
                    field_type = packet_body[idx]
                    unsigned = packet_body[idx + 1]
                    param_types.append((field_type, unsigned))
                    idx += 2
                
                # Read parameter values
                for i in range(num_params):
                    # Check null bitmap
                    is_null = (null_bitmap[i // 8] & (1 << (i % 8))) != 0
                    
                    if is_null:
                        params.append(None)
                    else:
                        field_type, unsigned = param_types[i]
                        value, bytes_read = self._read_param_value(packet_body, idx, field_type, unsigned)
                        params.append(value)
                        idx += bytes_read
            else:
                # Use previous parameter types (not implemented - use None)
                params = [None] * num_params
            
            return params
            
        except Exception as e:
            logger.error(f"Error parsing statement parameters: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return [None] * num_params

    def _read_param_value(self, data: bytes, offset: int, field_type: int, unsigned: int) -> Tuple[Any, int]:
        """Read a single parameter value from the packet"""
        try:
            # MySQL field types
            MYSQL_TYPE_TINY = 1
            MYSQL_TYPE_SHORT = 2
            MYSQL_TYPE_LONG = 3
            MYSQL_TYPE_LONGLONG = 8
            MYSQL_TYPE_FLOAT = 4
            MYSQL_TYPE_DOUBLE = 5
            MYSQL_TYPE_STRING = 254
            MYSQL_TYPE_VAR_STRING = 253
            MYSQL_TYPE_BLOB = 252
            
            if field_type == MYSQL_TYPE_TINY:
                return struct.unpack('<B' if unsigned else '<b', data[offset:offset+1])[0], 1
            elif field_type == MYSQL_TYPE_SHORT:
                return struct.unpack('<H' if unsigned else '<h', data[offset:offset+2])[0], 2
            elif field_type == MYSQL_TYPE_LONG:
                return struct.unpack('<I' if unsigned else '<i', data[offset:offset+4])[0], 4
            elif field_type == MYSQL_TYPE_LONGLONG:
                return struct.unpack('<Q' if unsigned else '<q', data[offset:offset+8])[0], 8
            elif field_type == MYSQL_TYPE_FLOAT:
                return struct.unpack('<f', data[offset:offset+4])[0], 4
            elif field_type == MYSQL_TYPE_DOUBLE:
                return struct.unpack('<d', data[offset:offset+8])[0], 8
            elif field_type in (MYSQL_TYPE_STRING, MYSQL_TYPE_VAR_STRING, MYSQL_TYPE_BLOB):
                # Length-encoded string
                length, length_bytes = self._read_length_encoded_integer(data, offset)
                if length is None:
                    return None, length_bytes
                string_data = data[offset + length_bytes:offset + length_bytes + length]
                try:
                    value = string_data.decode('utf-8')
                except:
                    value = string_data.decode('latin1')
                return value, length_bytes + length
            else:
                logger.warning(f"Unknown field type: {field_type}, treating as string")
                length, length_bytes = self._read_length_encoded_integer(data, offset)
                if length is None:
                    return None, length_bytes
                string_data = data[offset + length_bytes:offset + length_bytes + length]
                return string_data.decode('utf-8', errors='ignore'), length_bytes + length
                
        except Exception as e:
            logger.error(f"Error reading parameter value: {e}")
            return None, 1

    def _read_length_encoded_integer(self, data: bytes, offset: int) -> Tuple[Optional[int], int]:
        """Read a MySQL length-encoded integer"""
        if offset >= len(data):
            return None, 0
        
        first_byte = data[offset]
        
        if first_byte < 251:
            return first_byte, 1
        elif first_byte == 251:
            return None, 1  # NULL
        elif first_byte == 252:
            if offset + 3 > len(data):
                return 0, 1
            return struct.unpack('<H', data[offset+1:offset+3])[0], 3
        elif first_byte == 253:
            if offset + 4 > len(data):
                return 0, 1
            return struct.unpack('<I', data[offset+1:offset+4] + b'\x00')[0], 4
        elif first_byte == 254:
            if offset + 9 > len(data):
                return 0, 1
            return struct.unpack('<Q', data[offset+1:offset+9])[0], 9
        else:
            return 0, 1

    def _build_sql_from_template(self, template: str, params: List[Any]) -> str:
        """Build final SQL by replacing ? placeholders with actual parameter values"""
        try:
            # Simple replacement - replace each ? with the corresponding parameter
            result = template
            for param in params:
                if param is None:
                    value_str = 'NULL'
                elif isinstance(param, str):
                    # Escape single quotes and wrap in quotes
                    escaped = param.replace("'", "''")
                    value_str = f"'{escaped}'"
                elif isinstance(param, (int, float)):
                    value_str = str(param)
                elif isinstance(param, bytes):
                    # Convert bytes to hex string
                    value_str = f"X'{param.hex()}'"
                else:
                    # Default: convert to string and quote
                    value_str = f"'{str(param)}'"
                
                # Replace first occurrence of ?
                result = result.replace('?', value_str, 1)
            
            return result
            
        except Exception as e:
            logger.error(f"Error building SQL from template: {e}")
            return template

    def _build_stmt_prepare_ok(self, stmt_id: int, num_params: int, sequence_number: int) -> bytes:
        """Build COM_STMT_PREPARE_OK response packet"""
        try:
            # Packet payload:
            # 1 byte: OK (0x00)
            # 4 bytes: statement_id
            # 2 bytes: num_columns (0 for non-SELECT)
            # 2 bytes: num_params
            # 1 byte: reserved (0x00)
            # 2 bytes: warning_count (0)
            
            payload = struct.pack('<BIHBH',
                0x00,           # OK
                stmt_id,        # statement_id
                0,              # num_columns (we'll set to 0 for simplicity)
                num_params,     # num_params
                0x00,           # reserved
                0               # warning_count
            )
            
            # Build packet with header
            packet_length = len(payload)
            header = struct.pack('<I', packet_length)[:3] + struct.pack('<B', sequence_number)
            
            return header + payload
            
        except Exception as e:
            logger.error(f"Error building STMT_PREPARE_OK: {e}")
            return self._build_mysql_error_packet(f"Internal error: {str(e)}", sequence_number)

    # Protocol handling methods (copied from VirtualDatabaseServer)
    def _analyze_query_type(self, query: str) -> str:
        """Analyze the type of SQL query"""
        query_upper = query.strip().upper()

        if query_upper.startswith("SELECT"):
            return "SELECT"
        elif query_upper.startswith("INSERT"):
            return "INSERT"
        elif query_upper.startswith("UPDATE"):
            return "UPDATE"
        elif query_upper.startswith("DELETE"):
            return "DELETE"
        elif query_upper.startswith(("CREATE", "ALTER", "DROP", "TRUNCATE", "RENAME")):
            return "DDL"
        elif query_upper.startswith(("BEGIN", "START", "COMMIT", "ROLLBACK", "SAVEPOINT")):
            return "TRANSACTION"
        elif query_upper.startswith(("GRANT", "REVOKE")):
            return "PRIVILEGE"
        elif query_upper.startswith(("LOCK", "UNLOCK")):
            return "LOCK"
        elif query_upper.startswith(("EXPLAIN", "DESCRIBE", "DESC")):
            return "EXPLAIN"
        elif query_upper.startswith(("SET", "SHOW")):
            return "SYSTEM"
        elif query_upper.startswith(("CREATE INDEX", "DROP INDEX", "ALTER INDEX")):
            return "INDEX"
        else:
            return "OTHER"

    def _receive_handshake_response(self, client_socket: socket.socket, connection_id: int) -> bool:
        """
        Receive and process the client's handshake response (Login Packet).
        This consumes the packet sent by the client after our Greeting.
        """
        try:
            # Read packet header (4 bytes)
            header = b""
            while len(header) < 4:
                chunk = client_socket.recv(4 - len(header))
                if not chunk:
                    logger.warning(f"Connection {connection_id} closed during handshake")
                    return False
                header += chunk

            packet_length = struct.unpack('<I', header[:3] + b'\x00')[0]
            # sequence_number = header[3]  # Should be 1

            # Validate packet length
            if packet_length > 16 * 1024 * 1024:
                logger.error(f"Handshake packet too large: {packet_length}")
                return False

            # Read packet data
            data = b""
            while len(data) < packet_length:
                chunk = client_socket.recv(min(packet_length - len(data), 4096))
                if not chunk:
                    return False
                data += chunk

            # Parse handshake response 4.1
            if len(data) > 32:
                # Capability Flags (4) + Max Packet Size (4) + Charset (1) + Reserved (23) = 32 bytes
                # Username follows, null terminated
                username_end = data.find(b'\x00', 32)
                if username_end != -1:
                    username = data[32:username_end].decode('utf-8', errors='ignore')
                    logger.info(f"VDS {self.host}:{self.port}: Client logging in as '{username}' (Connection {connection_id})")
                else:
                    logger.debug(f"VDS {self.host}:{self.port}: Could not parse username from handshake (Connection {connection_id})")

            return True

        except Exception as e:
            logger.error(f"Error receiving handshake response for connection {connection_id}: {e}")
            return False

    def _receive_mysql_query(self, client_socket: socket.socket) -> str:
        """Receive MySQL query from client with improved error handling"""
        try:
            # Read packet header (4 bytes: 3 bytes length + 1 byte sequence)
            header = b""
            while len(header) < 4:
                chunk = client_socket.recv(4 - len(header))
                if not chunk:
                    return ""
                header += chunk

            if len(header) != 4:
                logger.warning(
                    f"Incomplete header received: {len(header)} bytes")
                return ""

            packet_length = struct.unpack('<I', header[:3] + b'\x00')[0]
            sequence_number = header[3]

            # Validate packet length (prevent buffer overflow attacks)
            if packet_length > 16 * 1024 * 1024:  # 16MB max
                logger.error(f"Packet too large: {packet_length} bytes")
                return ""

            # Read packet data
            data = b""
            while len(data) < packet_length:
                remaining = packet_length - len(data)
                chunk = client_socket.recv(min(remaining, 4096))
                if not chunk:
                    logger.warning(
                        f"Incomplete packet data: got {len(data)} of {packet_length} bytes")
                    return ""
                data += chunk

            if len(data) != packet_length:
                logger.warning(
                    f"Packet size mismatch: expected {packet_length}, got {len(data)}")
                return ""

            # First byte is command type
            command_type = data[0]
            query_data = data[1:]

            if command_type == COM_QUERY:
                # Regular query
                try:
                    return query_data.decode('utf-8', errors='ignore')
                except UnicodeDecodeError:
                    logger.warning("Failed to decode query as UTF-8")
                    return ""
            elif command_type == COM_QUIT:
                # Client wants to quit
                return "QUIT"
            else:
                logger.debug(f"Unsupported MySQL command: {command_type}")
                return ""

        except (OSError, struct.error) as e:
            logger.error(
                f"Network or protocol error receiving MySQL query: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error receiving MySQL query: {e}")
            return None

    def _build_mysql_response(self, result: Dict[str, Any]) -> bytes:
        """Build MySQL response packet from query result"""
        try:
            if not result.get("success", False):
                return self._build_mysql_error_packet(result.get("error", "Unknown error"))

            if result.get("query_type") == "SELECT":
                packets = self._build_mysql_result_set_packets(result, 1)
                return b"".join(packets)
            else:
                # OK packet for non-SELECT queries
                affected_rows = result.get("affected_rows", 0)
                return self._build_mysql_ok_packet(sequence_number=1, affected_rows=affected_rows)

        except Exception as e:
            logger.error(f"Error building MySQL response: {e}")
            return self._build_mysql_error_packet(str(e))

    def _build_mysql_result_set_packets(self, result: Dict[str, Any], start_sequence: int) -> List[bytes]:
        """Build MySQL result set packets (column definition + data rows)"""
        packets = []
        sequence_number = start_sequence

        try:
            if not result.get("success", False):
                # Return error packet
                return [self._build_mysql_error_packet(sequence_number, result.get("error", "Query failed"))]

            if result.get("query_type") == "SELECT":
                rows = result.get("rows", [])
                columns = result.get("columns", [])
                column_types = result.get("column_types", {})

                if not columns:
                    # No columns - return OK packet
                    packets.append(
                        self._build_mysql_ok_packet(sequence_number))
                    return packets

                # Column count packet
                column_count_packet = self._build_mysql_column_count_packet(
                    len(columns), sequence_number)
                packets.append(column_count_packet)
                sequence_number = (sequence_number + 1) % 256

                # Column definition packets
                for col_name in columns:
                    # Type 0xfd is MYSQL_TYPE_VAR_STRING
                    col_type = column_types.get(col_name, 0xfd)
                    col_def_packet = self._build_mysql_column_definition_packet(
                        col_name, sequence_number, col_type)
                    packets.append(col_def_packet)
                    sequence_number = (sequence_number + 1) % 256

                # EOF packet after column definitions
                eof_packet = self._build_mysql_eof_packet(sequence_number)
                packets.append(eof_packet)
                sequence_number = (sequence_number + 1) % 256

                # Data row packets
                for row in rows:
                    row_packet = self._build_mysql_data_row_packet(
                        row, columns, sequence_number)
                    packets.append(row_packet)
                    sequence_number = (sequence_number + 1) % 256

                # Final EOF packet
                eof_packet = self._build_mysql_eof_packet(sequence_number)
                packets.append(eof_packet)

            else:
                # Non-SELECT query - return OK
                packets.append(self._build_mysql_ok_packet(sequence_number))

        except Exception as e:
            logger.error(f"Error building result set packets: {e}")
            return [self._build_mysql_error_packet(start_sequence, str(e))]

        return packets

    def _build_mysql_column_definition_packet(self, column_name: str, sequence_number: int) -> bytes:
        """Build MySQL column definition packet with simplified format"""
        try:
            # Use a very basic format that should work with most MySQL clients
            # This is a minimal implementation that avoids complex length encoding

            # Catalog "def" (3 bytes + null terminator = 4 bytes, but we'll use simple format)
            catalog = b"def\x00"

            # Empty strings for schema, table, org_table, org_name (1 byte each for length 0)
            empty_str = b"\x00"

            # Column name with length prefix
            name_bytes = column_name.encode('utf-8')
            name_with_len = bytes([len(name_bytes)]) + name_bytes

            # Fixed fields: charset(2), length(4), type(1), flags(2), decimals(1), filler(2)
            fixed_fields = (
                struct.pack('<H', 33) +      # charset utf8_general_ci
                struct.pack('<I', 16777215) + # max length (16MB) - Fixed from 255
                b'\xfd' +                     # VARCHAR type
                struct.pack('<H', 0) +       # flags
                b'\x00' +                     # decimals
                b'\x00\x00'                   # filler
            )

            # Build the packet content
            packet = (
                catalog +           # 4 bytes
                empty_str +         # 1 byte (schema)
                empty_str +         # 1 byte (table)
                empty_str +         # 1 byte (org_table)
                name_with_len +     # name
                name_with_len +     # org_name (same as name)
                b'\x0c' +           # length of fixed fields
                fixed_fields        # 12 bytes
            )

            # Add packet header
            packet_length = len(packet)
            header = struct.pack('<I', packet_length)[
                :3] + bytes([sequence_number])

            logger.debug(
                f"Built column def for '{column_name}': {packet_length} bytes content + 4 bytes header")
            return header + packet

        except Exception as e:
            logger.error(f"Error building column definition packet: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return b""

    def _build_mysql_eof_packet(self, sequence_number: int) -> bytes:
        """Build MySQL EOF packet"""
        eof_data = bytes([EOF_PACKET, 0x00, 0x00])
        header = struct.pack('<I', len(eof_data))[
            :3] + bytes([sequence_number])
        return header + eof_data

    def _build_mysql_error_packet(self, error_message: str, sequence_number: int = 1) -> bytes:
        """Build MySQL error packet"""
        error_data = bytes([ERR_PACKET])
        error_data += b'\x00\x00'  # error code (placeholder)
        error_data += b'#00000'   # SQL state
        error_data += error_message.encode('utf-8')

        header = struct.pack('<I', len(error_data))[
            :3] + bytes([sequence_number])
        return header + error_data

    def _build_mysql_ok_packet(self, sequence_number: int = 1, affected_rows: int = 0) -> bytes:
        """Build MySQL OK packet"""
        try:
            packet = b""

            # OK packet header (0x00)
            packet += bytes([OK_PACKET])

            # Affected rows (length-encoded integer)
            packet += self._encode_length_encoded_int(affected_rows)

            # Last insert ID (length-encoded integer)
            packet += self._encode_length_encoded_int(0)

            # Status flags (2 bytes)
            packet += struct.pack('<H', MYSQL_DEFAULT_STATUS)

            # Warnings (2 bytes)
            packet += struct.pack('<H', 0)

            packet_length = len(packet)
            header = struct.pack('<I', packet_length)[
                :3] + bytes([sequence_number])

            return header + packet

        except Exception as e:
            logger.error(f"Failed to build MySQL OK packet: {e}")
            return b""

    def _encode_length_encoded_int(self, value: int) -> bytes:
        """Encode an integer as MySQL length-encoded integer"""
        if value < 251:
            return bytes([value])
        elif value < 2**16:
            return b'\xfc' + struct.pack('<H', value)
        elif value < 2**24:
            return b'\xfd' + struct.pack('<I', value)[:3]
        else:
            return b'\xfe' + struct.pack('<Q', value)

    def _decrypt_value_for_vds(self, col_name: str, value: Any) -> str:
        """
        VDS DECRYPTION: Decrypt any encrypted data before sending to MySQL clients.
        This ensures VDS always returns plaintext data regardless of console service processing.
        """
        try:
            # Skip tag columns
            if col_name.startswith('tag_'):
                return ""

            # If value is None, return empty string
            if value is None:
                return ""

            # If value is already a string, check if it's actually encrypted hex data
            if isinstance(value, str):
                # Check if it's a hex string that represents encrypted data
                if len(value) > 100 and len(value) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in value):
                    try:
                        hex_bytes = bytes.fromhex(value)
                        if hex_bytes.startswith(b'RIFF') and b'WEBP' in hex_bytes[:20]:
                            logger.info(
                                f"VDS DECRYPT: Found encrypted hex WebP data in {col_name}")
                            decrypted_value = clwe_encryptor.decrypt_value(
                                hex_bytes, settings.CRYPTOPIX_DEFAULT_PASSWORD)
                            return str(decrypted_value)
                    except Exception as e:
                        logger.debug(
                            f"VDS DECRYPT: Hex string in {col_name} not encrypted")
                # Otherwise, it's already decrypted
                return value

            # If value is bytes, it needs decryption
            if isinstance(value, bytes):
                try:
                    logger.info(
                        f"VDS DECRYPT: Decrypting bytes data in {col_name} (size: {len(value)})")
                    decrypted_value = clwe_encryptor.decrypt_value(
                        value, settings.CRYPTOPIX_DEFAULT_PASSWORD)
                    logger.info(
                        f"VDS DECRYPT: Successfully decrypted {col_name}")
                    return str(decrypted_value)
                except Exception as e:
                    logger.error(
                        f"VDS DECRYPT: Failed to decrypt bytes in {col_name}: {e}")
                    # If decryption fails, it might not be encrypted - return as hex
                    return value.hex()

            # For any other type, convert to string
            return str(value)

        except Exception as e:
            logger.error(
                f"VDS DECRYPT: Critical error processing {col_name}: {e}")
            return f"<ERROR:{str(e)}>"

    def _build_mysql_data_row_packet(self, row: Dict[str, Any], columns: List[str], sequence_number: int) -> bytes:
        """Build data row packet with advanced decryption support using console service logic"""
        try:
            packet = b""

            for col_name in columns:
                value = row.get(col_name, None)

                # Handle NULL values
                if value is None:
                    # NULL is represented as 0xFB (251) in MySQL protocol
                    packet += b'\xfb'
                else:
                    # Use the same decryption logic as console service for consistency
                    str_value = self._decrypt_value_for_vds(col_name, value)

                    # Encode as UTF-8
                    encoded_value = str_value.encode('utf-8')

                    # Length-encoded: proper encoding for any length
                    packet += self._encode_length_encoded_int(len(encoded_value)) + encoded_value

            packet_length = len(packet)
            header = struct.pack('<I', packet_length)[
                :3] + bytes([sequence_number])

            logger.debug(
                f"Built data row packet: seq={sequence_number}, content_length={packet_length}")
            return header + packet

        except Exception as e:
            logger.error(f"Error building data row packet: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return b""

    # BINARY PROTOCOL SUPPORT FOR PREPARED STATEMENTS
    def _build_mysql_binary_result_set_packets(self, result: Dict[str, Any], start_sequence: int) -> List[bytes]:
        """Build MySQL Binary Protocol result set packets (for Prepared Statements)"""
        packets = []
        sequence_number = start_sequence

        try:
            if not result.get("success", False):
                return [self._build_mysql_error_packet(result.get("error", "Query failed"), sequence_number)]

            if result.get("query_type") == "SELECT":
                rows = result.get("rows", [])
                columns = result.get("columns", [])
                column_types = result.get("column_types", {})

                if not columns:
                    packets.append(self._build_mysql_ok_packet(sequence_number))
                    return packets

                # Column count packet
                column_count_packet = self._build_mysql_column_count_packet(len(columns), sequence_number)
                packets.append(column_count_packet)
                sequence_number = (sequence_number + 1) % 256

                # Column definition packets
                for col_name in columns:
                    col_type = column_types.get(col_name, 0xfd) # 0xfd = VARCHAR
                    col_def_packet = self._build_mysql_column_definition_packet(col_name, sequence_number)
                    packets.append(col_def_packet)
                    sequence_number = (sequence_number + 1) % 256

                # EOF packet after column definitions
                eof_packet = self._build_mysql_eof_packet(sequence_number)
                packets.append(eof_packet)
                sequence_number = (sequence_number + 1) % 256

                # Binary Data row packets
                for row in rows:
                    try:
                        row_packet = self._build_mysql_binary_data_row_packet(row, columns, sequence_number)
                        packets.append(row_packet)
                        sequence_number = (sequence_number + 1) % 256
                    except Exception as e:
                        logger.error(f"Error building binary row: {e}")
                        # Skip row or break? Skip for now.

                # Final EOF packet
                eof_packet = self._build_mysql_eof_packet(sequence_number)
                packets.append(eof_packet)

            else:
                packets.append(self._build_mysql_ok_packet(sequence_number, result.get("affected_rows", 0)))

        except Exception as e:
            logger.error(f"Error building binary result set: {e}")
            return [self._build_mysql_error_packet(str(e), start_sequence)]

        return packets

    def _build_mysql_binary_data_row_packet(self, row: Dict[str, Any], columns: List[str], sequence_number: int) -> bytes:
        """
        Build a Binary Protocol Data Row Packet.
        Format:
        - 1 byte: Packet Header (0x00)
        - (num_columns + 7 + 2) / 8 bytes: Null Bitmap
        - Data values (encoded strictly according to type)
        """
        try:
            num_columns = len(columns)
            
            # 1. Packet Header
            packet_body = b'\x00'
            
            # 2. Null Bitmap
            # Offset is 2 bits for Binary Protocol Result Set (unlike Execute Packet which is 0)
            bitmap_len = (num_columns + 7 + 2) // 8
            null_bitmap = bytearray(bitmap_len)
            
            values_data = b""
            
            for i, col_name in enumerate(columns):
                value = row.get(col_name)
                
                if value is None:
                    # Set bit in null bitmap
                    # Bit offset: i + 2
                    byte_pos = (i + 2) // 8
                    bit_pos = (i + 2) % 8
                    null_bitmap[byte_pos] |= (1 << bit_pos)
                else:
                    # Encode value
                    str_value = self._decrypt_value_for_vds(col_name, value)
                    
                    # In VDS, we treat everything as strings (VARCHAR) because
                    # our console service returns Python strings/objects, and we declared
                    # columns as VARCHAR (0xfd) in column definitions.
                    # Binary Protocol for VARCHAR is Length-Encoded String.
                    
                    encoded_val = str_value.encode('utf-8')
                    values_data += self._encode_length_encoded_int(len(encoded_val)) + encoded_val

            packet_body += null_bitmap + values_data
            
            # Add Header
            packet_length = len(packet_body)
            header = struct.pack('<I', packet_length)[:3] + bytes([sequence_number])
            
            return header + packet_body
            
        except Exception as e:
            logger.error(f"Error building binary data row: {e}")
            raise

    def _build_mysql_greeting_packet(self) -> bytes:
        """Build MySQL greeting (handshake) packet"""
        try:
            # Generate random connection ID
            connection_id = random.randint(1, 2**32 - 1)

            # Generate random auth plugin data (20 bytes total, split into two parts)
            auth_plugin_data = b''.join(
                [bytes([random.randint(0, 255)]) for _ in range(20)])
            auth_plugin_data_part1 = auth_plugin_data[:8]
            auth_plugin_data_part2 = auth_plugin_data[8:]

            # Auth plugin name
            auth_plugin_name = b"mysql_native_password\x00"

            # Build the packet
            packet = b""

            # Protocol version (1 byte)
            packet += bytes([MYSQL_PROTOCOL_VERSION])

            # Server version (null-terminated string)
            packet += MYSQL_SERVER_VERSION.encode() + b'\x00'

            # Connection ID (4 bytes, little endian)
            packet += struct.pack('<I', connection_id)

            # Auth plugin data part 1 (8 bytes)
            packet += auth_plugin_data_part1

            # Filler (1 byte, always 0x00)
            packet += b'\x00'

            # Capability flags lower 2 bytes
            packet += struct.pack('<H', MYSQL_DEFAULT_CAPABILITIES & 0xFFFF)

            # Character set (1 byte)
            packet += bytes([MYSQL_DEFAULT_CHARSET])

            # Status flags (2 bytes)
            packet += struct.pack('<H', MYSQL_DEFAULT_STATUS)

            # Capability flags upper 2 bytes
            packet += struct.pack('<H',
                                  (MYSQL_DEFAULT_CAPABILITIES >> 16) & 0xFFFF)

            # Auth plugin data length (1 byte) - includes trailing null
            packet += bytes([len(auth_plugin_data_part2) + 1])

            # Reserved (10 bytes, all 0x00)
            packet += b'\x00' * 10

            # Auth plugin data part 2 (null-terminated)
            packet += auth_plugin_data_part2 + b'\x00'

            # Auth plugin name (null-terminated)
            packet += auth_plugin_name

            # Add packet length and sequence number (3 bytes length + 1 byte seq)
            packet_length = len(packet)
            sequence_number = 0
            header = struct.pack('<I', packet_length)[
                :3] + bytes([sequence_number])

            return header + packet

        except Exception as e:
            logger.error(f"Failed to build MySQL greeting packet: {e}")
            return b""

    def _format_result_for_client(self, result: Dict[str, Any]) -> str:
        """Format query result for simple text-based client response"""
        try:
            if not result.get("success", False):
                return f"ERROR: {result.get('error', 'Unknown error')}"

            if result.get("query_type") == "SELECT":
                rows = result.get("rows", [])
                columns = result.get("columns", [])

                if not rows:
                    return "Empty result set"

                # Format as simple text table
                output = []
                output.append("| " + " | ".join(columns) + " |")
                output.append("|" + "|".join("-" * (len(col) + 2)
                              for col in columns) + "|")

                for row in rows[:10]:  # Limit to first 10 rows
                    row_values = []
                    for col in columns:
                        value = row.get(col, "")
                        if value is None:
                            value = "NULL"
                        else:
                            value = str(value)[:50]  # Truncate long values
                        row_values.append(value)
                    output.append("| " + " | ".join(row_values) + " |")

                if len(rows) > 10:
                    output.append(f"... and {len(rows) - 10} more rows")

                return "\n".join(output)
            else:
                affected_rows = result.get("affected_rows", 0)
                return f"Query OK, {affected_rows} rows affected"

        except Exception as e:
            logger.error(f"Error formatting result: {e}")
            return f"ERROR: Failed to format result: {str(e)}"


    def _analyze_query_type(self, query: str) -> str:
        """Analyze the type of SQL query"""
        query_upper = query.strip().upper()
        if query_upper.startswith("SELECT"): return "SELECT"
        if query_upper.startswith("INSERT"): return "INSERT"
        if query_upper.startswith("UPDATE"): return "UPDATE"
        if query_upper.startswith("DELETE"): return "DELETE"
        if query_upper.startswith(("CREATE", "ALTER", "DROP", "TRUNCATE", "RENAME")): return "DDL"
        if query_upper.startswith(("BEGIN", "START", "COMMIT", "ROLLBACK", "SAVEPOINT")): return "TRANSACTION"
        if query_upper.startswith("SHOW"): return "SHOW"
        if query_upper.startswith("DESC") or query_upper.startswith("DESCRIBE"): return "SHOW"
        if query_upper.startswith("SET"): return "SET"
        if query_upper.startswith("USE"): return "SET"
        return "UNKNOWN"

    def _decrypt_value_for_vds(self, col_name: str, value: Any) -> str:
        """
        VDS DECRYPTION: Decrypt any encrypted data before sending to MySQL clients.
        """
        try:
            if col_name.startswith('tag_'): return ""
            if value is None: return ""
            if isinstance(value, str):
                if len(value) > 100 and len(value) % 2 == 0:
                    try:
                        hex_bytes = bytes.fromhex(value)
                        if hex_bytes.startswith(b'RIFF') and b'WEBP' in hex_bytes[:20]:
                            val = clwe_encryptor.decrypt_value(hex_bytes, settings.CRYPTOPIX_DEFAULT_PASSWORD)
                            return str(val)
                    except: pass
                return value
            if isinstance(value, bytes):
                try:
                    val = clwe_encryptor.decrypt_value(value, settings.CRYPTOPIX_DEFAULT_PASSWORD)
                    return str(val)
                except: return value.hex()
            return str(value)
        except Exception as e:
            logger.error(f"VDS DECRYPT: error processing {col_name}: {e}")
            return f"<ERROR:{str(e)}>"

    def _build_mysql_greeting_packet(self) -> bytes:
        try:
            connection_id = random.randint(1, 2**32 - 1)
            auth_plugin_data = b''.join([bytes([random.randint(0, 255)]) for _ in range(20)])
            auth_plugin_data_part1 = auth_plugin_data[:8]
            auth_plugin_data_part2 = auth_plugin_data[8:]
            
            packet = b""
            packet += bytes([MYSQL_PROTOCOL_VERSION])
            packet += MYSQL_SERVER_VERSION.encode() + b'\x00'
            packet += struct.pack('<I', connection_id)
            packet += auth_plugin_data_part1
            packet += b'\x00'
            packet += struct.pack('<H', MYSQL_DEFAULT_CAPABILITIES & 0xFFFF)
            packet += bytes([MYSQL_DEFAULT_CHARSET])
            packet += struct.pack('<H', MYSQL_DEFAULT_STATUS)
            packet += struct.pack('<H', (MYSQL_DEFAULT_CAPABILITIES >> 16) & 0xFFFF)
            packet += bytes([len(auth_plugin_data_part2) + 1])
            packet += b'\x00' * 10
            packet += auth_plugin_data_part2 + b'\x00'
            packet += b"mysql_native_password\x00"
            
            packet_length = len(packet)
            header = struct.pack('<I', packet_length)[:3] + bytes([0])
            return header + packet
        except Exception as e:
            logger.error(f"Failed to build greeting packet: {e}")
            return b""

    def _build_mysql_ok_packet(self, sequence_number: int = 1, affected_rows: int = 0) -> bytes:
        try:
            packet = b""
            packet += bytes([OK_PACKET])
            packet += self._encode_length_encoded_int(affected_rows)
            packet += self._encode_length_encoded_int(0)
            packet += struct.pack('<H', MYSQL_DEFAULT_STATUS)
            packet += struct.pack('<H', 0)
            
            packet_length = len(packet)
            header = struct.pack('<I', packet_length)[:3] + bytes([sequence_number])
            return header + packet
        except Exception as e:
            logger.error(f"Failed to build OK packet: {e}")
            return b""

    def _build_mysql_error_packet(self, error_message: str) -> bytes:
        error_data = bytes([ERR_PACKET])
        error_data += b'\x00\x00'
        error_data += b'#00000'
        error_data += error_message.encode('utf-8')
        header = struct.pack('<I', len(error_data))[:3] + bytes([1])
        return header + error_data

    def _build_mysql_result_set_packets(self, result: Dict[str, Any], start_sequence: int = 1) -> bytes:
        try:
            packets = b""
            sequence = start_sequence
            columns = result.get("columns", [])
            rows = result.get("rows", [])
            
            col_count_packet = struct.pack('<B', len(columns))
            header = struct.pack('<I', len(col_count_packet))[:3] + bytes([sequence])
            packets += header + col_count_packet
            sequence = (sequence + 1) % 256
            
            for col_name in columns:
                col_packet = self._build_mysql_column_definition_packet(col_name, sequence)
                packets += col_packet
                sequence = (sequence + 1) % 256
                
            packets += self._build_mysql_eof_packet(sequence)
            sequence = (sequence + 1) % 256
            
            for row in rows:
                row_packet = self._build_mysql_data_row_packet(row, columns, sequence)
                packets += row_packet
                sequence = (sequence + 1) % 256
                
            packets += self._build_mysql_eof_packet(sequence)
            return packets
        except Exception as e:
            logger.error(f"Error building result packets: {e}")
            return self._build_mysql_error_packet(str(e))

    def _build_mysql_column_definition_packet(self, column_name: str, sequence_number: int, column_type: int = 0xfd) -> bytes:
        """Build MySQL column definition packet with proper protocol structure"""
        try:
            # Helper function to encode length-encoded string
            def encode_lenenc_string(s: str) -> bytes:
                if not s:
                    return b'\x00'
                b = s.encode('utf-8')
                if len(b) < 251:
                    return bytes([len(b)]) + b
                elif len(b) < 2**16:
                    return b'\xfc' + struct.pack('<H', len(b)) + b
                elif len(b) < 2**24:
                    return b'\xfd' + struct.pack('<I', len(b))[:3] + b
                else:
                    return b'\xfe' + struct.pack('<Q', len(b)) + b
            
            packet = b""
            
            # Catalog (always "def")
            packet += encode_lenenc_string("def")
            
            # Schema (empty for now)
            packet += encode_lenenc_string("")
            
            # Table (virtual table name)
            packet += encode_lenenc_string("")
            
            # Original table (empty)
            packet += encode_lenenc_string("")
            
            # Column name
            packet += encode_lenenc_string(column_name)
            
            # Original column name (same as column name)
            packet += encode_lenenc_string(column_name)
            
            # Fixed length fields marker (0x0c = 12 bytes follow)
            packet += b'\x0c'
            
            # Character set (utf8_general_ci = 33)
            # Use binary collation (63) for non-string types or 33 for strings
            packet += struct.pack('<H', 33)
            
            # Column length (max length for VARCHAR)
            packet += struct.pack('<I', 255)
            
            # Column type (Use provided type, default to MYSQL_TYPE_VAR_STRING = 0xfd)
            if isinstance(column_type, int) and 0 <= column_type <= 255:
                packet += bytes([column_type])
            else:
                packet += b'\xfd'
            
            # Flags (0 = no special flags)
            packet += struct.pack('<H', 0)
            
            # Decimals (0 for string types)
            packet += b'\x00'
            
            # Filler (2 bytes of 0x00)
            packet += b'\x00\x00'
            
            # Add packet header (length + sequence number)
            packet_length = len(packet)
            header = struct.pack('<I', packet_length)[:3] + bytes([sequence_number])
            
            return header + packet
            
        except Exception as e:
            logger.error(f"Error building column definition: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return b""

    def _build_mysql_data_row_packet(self, row: Any, columns: List[str], sequence_number: int) -> bytes:
        try:
            packet = b""
            row_dict = {}
            if isinstance(row, dict): row_dict = row
            elif isinstance(row, (list, tuple)): row_dict = dict(zip(columns, row))
                
            for col_name in columns:
                value = row_dict.get(col_name)
                if value is None: packet += b'\xfb'
                else:
                    str_value = self._decrypt_value_for_vds(col_name, value)
                    encoded = str_value.encode('utf-8')
                    if len(encoded) < 251: packet += bytes([len(encoded)]) + encoded
                    else: packet += bytes([250]) + encoded[:250]
                        
            packet_length = len(packet)
            header = struct.pack('<I', packet_length)[:3] + bytes([sequence_number])
            return header + packet
        except Exception as e:
            logger.error(f"Error building data row: {e}")
            return b""

    def _build_mysql_eof_packet(self, sequence_number: int) -> bytes:
        # EOF packet structure: 0xFE + warnings (2 bytes) + status flags (2 bytes)
        eof = bytes([EOF_PACKET])
        eof += struct.pack('<H', 0)  # warnings count (2 bytes)
        eof += struct.pack('<H', MYSQL_DEFAULT_STATUS)  # status flags (2 bytes)
        header = struct.pack('<I', len(eof))[:3] + bytes([sequence_number])
        return header + eof

    def _encode_length_encoded_int(self, value: int) -> bytes:
        if value < 251: return bytes([value])
        elif value < 2**16: return b'\xfc' + struct.pack('<H', value)
        elif value < 2**24: return b'\xfd' + struct.pack('<I', value)[:3]
        else: return b'\xfe' + struct.pack('<Q', value)

    def _format_result_for_client(self, result: Dict[str, Any]) -> str:
        if not result.get("success"): return f"ERROR: {result.get('error')}"
        if result.get("query_type") == "SELECT":
             rows = result.get("rows", [])
             return f"Rows: {len(rows)}"
        return f"Affected: {result.get('affected_rows', 0)}"


class VirtualDatabaseServer:
    """
    Virtual Database Server (VDS) - Smart intermediary for encrypted databases.

    The VDS allows client applications to interact with fully encrypted databases exactly as if
    they were communicating with a normal database. Instead of connecting directly to MySQL,
    PostgreSQL, or any other database engine, the application connects to the Virtual Database
    URL provided by the Bridge (e.g., mysql://user:password@bridge-server:4406/company_db).

    The VDS emulates the original database protocol, accepts SQL queries from the application
    without requiring any code or configuration changes, and manages all encryption and
    decryption processes internally.
    """

    def _create_table_mapping_from_migration_state(self, table_name: str, config: Dict[str, Any]) -> TableMapping:
        """Create TableMapping from migration state configuration"""
        logger.info(
            f"Creating table mapping for {table_name} with config keys: {list(config.keys())}")
        encrypted_columns = {}
        non_encrypted_columns = []

        for col_name, col_config in config.items():
            # Check if column should be encrypted based on configuration
            should_encrypt = col_config.get('type') == 'encrypt'
            logger.info(
                f"Column {col_name}: type={col_config.get('type')}, should_encrypt={should_encrypt}")

            if should_encrypt:
                # Create mapping for encrypted columns
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
                logger.info(f"Created encrypted column mapping for {col_name}")
            else:
                non_encrypted_columns.append(col_name)
                logger.info(f"Added {col_name} to non-encrypted columns")

        # Set primary key based on table name or config
        primary_key = None
        if 'primary_keys' in config and config['primary_keys']:
            primary_key = config['primary_keys'][0]  # Take first primary key
        else:
            # Default primary keys for common tables
            primary_keys = {
                'users': 'id',
                'customers': 'id',
                'employees': 'id',
                'orders': 'id',
                'products': 'id'
            }
            primary_key = primary_keys.get(table_name, 'id')

        logger.info(
            f"Table {table_name}: primary_key={primary_key}, encrypted_cols={len(encrypted_columns)}, non_encrypted_cols={len(non_encrypted_columns)}")

        return TableMapping(
            original_name=table_name,
            encrypted_columns=encrypted_columns,
            primary_key=primary_key,
            non_encrypted_columns=non_encrypted_columns
        )

    def _setup_schema_mappings(self):
        """Setup schema mappings for translating normal column names to encrypted equivalents"""
        try:
            # Use the console service's migration state loading and table mapping registration
            # This ensures VDS uses the same logic as the query console

            # Load migration state using the same method as console service
            # If migration_state was provided in init, use it, otherwise load it
            if not hasattr(self, 'migration_state') or not self.migration_state:
                self.migration_state = self.console_service._load_migration_state_from_files(
                    self.encrypted_db_url)

            logger.info(
                f"VDS loaded migration state: {bool(self.migration_state)}")
            if self.migration_state:
                logger.info(
                    f"Migration state keys: {list(self.migration_state.keys())}")
                if self.migration_state.get("encrypted_db_url"):
                    self.encrypted_db_url = self.migration_state["encrypted_db_url"]
                    # Ensure MySQL URLs use PyMySQL driver
                    if self.encrypted_db_url.startswith('mysql://'):
                        self.encrypted_db_url = self.encrypted_db_url.replace(
                            'mysql://', 'mysql+pymysql://', 1)
                    logger.info(
                        f"Using encrypted DB URL from migration state: {self.encrypted_db_url}")

            # Register table mappings using the same method as console service
            self.console_service._register_table_mappings()

            # Now get the registered mappings from the AI assistant (which console service just updated)
            self.table_mappings = self.ai_assistant.table_mappings.copy()
            self.database_schemas = self.ai_assistant.database_schemas.copy()

            logger.info(
                f"VDS using {len(self.table_mappings)} table mappings from AI assistant")
            logger.info(
                f"VDS using {len(self.database_schemas)} database schemas from AI assistant")

            # Set database type for translators
            enhanced_sql_translator.set_database_type(self.encrypted_db_url)
            sql_interceptor.set_database_type(self.encrypted_db_url)

            # Verify registration worked
            logger.info(
                f"VDS - Translator has {len(enhanced_sql_translator.table_mappings)} mappings: {list(enhanced_sql_translator.table_mappings.keys())}")
            logger.info(
                f"VDS - Interceptor has {len(sql_interceptor.table_mappings)} mappings: {list(sql_interceptor.table_mappings.keys())}")

            # Debug: Log detailed mapping info
            for table_name, mapping in self.table_mappings.items():
                logger.info(
                    f"VDS Table {table_name} mapping: encrypted_cols={list(mapping.encrypted_columns.keys())}, non_encrypted={mapping.non_encrypted_columns}")

        except Exception as e:
            logger.error(f"Failed to setup schema mappings in VDS: {e}")
            # Fallback to basic setup if console service loading fails
            try:
                import_result = self.ai_assistant.import_schemas_mapping()
                self.table_mappings = self.ai_assistant.table_mappings.copy()
                self.database_schemas = self.ai_assistant.database_schemas.copy()
                logger.warning("VDS fell back to basic schema mapping setup")
            except Exception as fallback_e:
                logger.error(
                    f"VDS fallback schema setup also failed: {fallback_e}")

    def _load_migration_state(self):
        """Load migration state from files"""
        try:
            import os
            from pathlib import Path
            import json

            # Get the directory where this script is located
            script_dir = Path(__file__).parent.parent  # Go up to project root
            schemas_dir = script_dir / "schemas"
            logger.info(f"Looking for schemas in: {schemas_dir}")
            if not schemas_dir.exists():
                logger.warning(
                    f"No schemas directory found at {schemas_dir}. Migration may not be completed yet.")
                return {}

            # Find migration state files
            state_files = list(schemas_dir.glob("*_migration_state.json"))
            logger.info(
                f"Found migration state files: {[str(f) for f in state_files]}")
            if not state_files:
                logger.warning(
                    "No migration state files found. Migration may not be completed yet.")
                return {}

            # Load migration state files and find the most recent one with table configs
            valid_states = []
            for state_file in state_files:
                try:
                    with open(state_file, 'r') as f:
                        state_data = json.load(f)
                        # Accept migration states that have table configs, even if not complete
                        if state_data.get('table_configs'):
                            valid_states.append((state_file, state_data))
                except Exception as e:
                    logger.warning(
                        f"Failed to load migration state file {state_file}: {e}")

            if not valid_states:
                logger.warning(
                    "No migration state files with table configs found.")
                return {}

            # Find the most recent migration state with table configs
            latest_state_file, migration_state = max(
                valid_states, key=lambda x: x[0].stat().st_mtime)

            logger.info(
                f"Loaded completed migration state from {latest_state_file}")
            logger.info(
                f"Migration complete: {migration_state.get('migration_complete', False)}")
            logger.info(
                f"Encrypted DB URL: {migration_state.get('encrypted_db_url', 'Not found')}")
            logger.info(
                f"Table configs: {list(migration_state.get('table_configs', {}).keys())}")
            return migration_state

        except Exception as e:
            logger.error(f"Failed to load migration state: {e}")
            return {}

    def _setup_encryption_engine(self):
        """Setup encryption engine for transparent data handling"""
        try:
            # Verify CLWE encryption is working
            test_data = "test_encryption"
            encrypted = clwe_encryptor.encrypt_value(
                test_data, settings.CRYPTOPIX_DEFAULT_PASSWORD)
            decrypted = clwe_encryptor.decrypt_value(
                encrypted, settings.CRYPTOPIX_DEFAULT_PASSWORD)

            if decrypted == test_data:
                logger.info("CLWE encryption engine verified and ready")
            else:
                logger.error("CLWE encryption engine verification failed")
        except Exception as e:
            logger.error(f"Failed to setup encryption engine: {e}")

    def start(self):
        """Start the Virtual Database Server"""
        try:
            if self.running:
                logger.warning("VDS is already running")
                return

            self.server_socket = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(self.max_connections)
            # Non-blocking accept to allow immediate shutdown
            self.server_socket.settimeout(0.1)
            self.running = True

            logger.info(
                f"Virtual Database Server started on {self.host}:{self.port}")
            logger.info(
                f"Accepting {self.target_protocol} connections with transparent encryption")

            # Start accepting connections in a separate thread
            self.accept_thread = threading.Thread(
                target=self._accept_connections, daemon=True)
            self.accept_thread.start()

        except Exception as e:
            logger.error(f"Failed to start VDS: {e}")
            self.running = False
            raise

    def stop(self):
        """Stop the Virtual Database Server"""
        try:
            self.running = False

            # Join the accept thread to ensure it terminates
            if hasattr(self, 'accept_thread') and self.accept_thread.is_alive():
                self.accept_thread.join(timeout=1.0)

            # Close all active connections
            with self.connection_lock:
                # Create a copy of items to avoid runtime error during iteration
                active_conns = list(self.active_connections.items())
                for conn_id, conn_info in active_conns:
                    try:
                        if conn_info.get('socket'):
                            conn_info['socket'].shutdown(socket.SHUT_RDWR)
                            conn_info['socket'].close()
                        logger.info(f"Forced closure of connection {conn_id}")
                    except Exception as e:
                        logger.warning(
                            f"Error closing connection {conn_id}: {e}")
                self.active_connections.clear()

            # Close server socket
            if self.server_socket:
                try:
                    self.server_socket.shutdown(socket.SHUT_RDWR)
                    self.server_socket.close()
                except Exception as e:
                    logger.warning(f"Error closing server socket: {e}")
                self.server_socket = None

            # Shutdown executor
            self.executor.shutdown(wait=False)
            logger.info("Virtual Database Server stopped")

        except Exception as e:
            logger.error(f"Error during VDS stop: {e}")

    def _accept_connections(self):
        """Accept incoming client connections"""
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()

                # Check connection limit
                with self.connection_lock:
                    if len(self.active_connections) >= self.max_connections:
                        logger.warning(
                            f"Connection limit reached ({self.max_connections}), rejecting connection from {client_address}")
                        client_socket.close()
                        continue

                    self.connection_counter += 1
                    connection_id = self.connection_counter

                    self.active_connections[connection_id] = {
                        'socket': client_socket,
                        'address': client_address,
                        'connected_at': time.time(),
                        'last_activity': time.time()
                    }

                logger.info(
                    f"New connection {connection_id} from {client_address}")

                # Handle connection in separate thread
                self.executor.submit(
                    self._handle_connection, connection_id, client_socket, client_address)

            except socket.timeout:
                # Timeout occurred, check if we should still be running
                continue
            except OSError:
                # Socket was closed
                break
            except Exception as e:
                if not self.running:
                    break
                logger.error(f"Error accepting connection: {e}")

    def _handle_connection(self, connection_id: int, client_socket: socket.socket, client_address: tuple):
        """Handle individual client connection with session isolation"""
        try:
            # Send greeting based on protocol
            if self.target_protocol == "mysql":
                # 1. Send Server Greeting (Handshake V10)
                greeting = self._build_mysql_greeting_packet()
                client_socket.sendall(greeting)

                # 2. Receive Client Authentication Packet (Handshake Response)
                if not self._receive_handshake_response(client_socket, connection_id):
                    logger.warning(f"Connection {connection_id} handshake failed")
                    return

                # 3. Send OK Packet to complete authentication
                ok_packet = self._build_mysql_ok_packet(sequence_number=2)
                client_socket.sendall(ok_packet)
                
            else:
                # For other protocols, send simple acknowledgment
                greeting = b"VDS Ready\n"
                client_socket.sendall(greeting)
        except Exception as e:
            logger.error(
                f"Error sending greeting to connection {connection_id}: {e}")
            return

            # Connection loop
            while self.running:
                try:
                    # Receive query/command
                    if self.target_protocol == "mysql":
                        query = self._receive_mysql_query(client_socket)
                    else:
                        # Simple text-based protocol for other databases
                        data = client_socket.recv(4096)
                        if not data:
                            break
                        query = data.decode().strip()

                    if query is None:
                        break

                    if not query:
                        if query == "QUIT":
                            break
                        continue

                    # Update last activity
                    with self.connection_lock:
                        if connection_id in self.active_connections:
                            self.active_connections[connection_id]['last_activity'] = time.time(
                            )

                    logger.debug(
                        f"Connection {connection_id}: Processing query: {query[:100]}...")

                    # Process query through VDS pipeline
                    result = self._process_query(query, connection_id)

                    # Send response back to client
                    try:
                        if self.target_protocol == "mysql":
                            response = self._build_mysql_response(result)
                            client_socket.sendall(response)
                        else:
                            response = self._format_result_for_client(result)
                            client_socket.sendall(response.encode() + b"\n")
                    except Exception as e:
                        logger.error(
                            f"Error sending response to connection {connection_id}: {e}")
                        break

                except ConnectionResetError:
                    logger.info(f"Connection {connection_id} reset by client")
                    break
                except Exception as e:
                    logger.error(
                        f"Error handling query for connection {connection_id}: {e}")
                    # Send error response
                    if self.target_protocol == "mysql":
                        error_response = self._build_mysql_error_packet(str(e))
                        client_socket.sendall(error_response)
                    else:
                        error_response = f"ERROR: {str(e)}\n"
                        client_socket.sendall(error_response.encode())
                    break

        except Exception as e:
            logger.error(f"Error in connection handler {connection_id}: {e}")
        finally:
            # Clean up connection
            client_socket.close()
            with self.connection_lock:
                if connection_id in self.active_connections:
                    del self.active_connections[connection_id]
            logger.info(f"Connection {connection_id} closed")

    def _process_query(self, query: str, connection_id: int) -> Dict[str, Any]:
        """
        Process SQL query through the VDS pipeline using console service.
        The console service already handles all decryption, so VDS just passes through the results.
        """
        try:
            # Use the console service's execute_command method for consistent processing
            # The console service already handles all decryption for SELECT queries
            result = self.console_service.execute_command(
                command=query,
                user_id=f"vds_client_{connection_id}",
                database_url=self.encrypted_db_url,
                migration_state=self.migration_state
            )

            # Add VDS-specific metadata
            result["processed_by"] = "VDS"
            result["connection_id"] = connection_id

            return result

        except Exception as e:
            logger.error(f"Error processing query in VDS: {e}")
            return {
                "success": False,
                "error": str(e),
                "query_type": "ERROR",
                "processed_by": "VDS",
                "connection_id": connection_id
            }

    def _analyze_query_type(self, query: str) -> str:
        """Analyze the type of SQL query"""
        query_upper = query.strip().upper()

        if query_upper.startswith("SELECT"):
            return "SELECT"
        elif query_upper.startswith("INSERT"):
            return "INSERT"
        elif query_upper.startswith("UPDATE"):
            return "UPDATE"
        elif query_upper.startswith("DELETE"):
            return "DELETE"
        elif query_upper.startswith(("CREATE", "ALTER", "DROP", "TRUNCATE", "RENAME")):
            return "DDL"
        elif query_upper.startswith(("BEGIN", "START", "COMMIT", "ROLLBACK", "SAVEPOINT")):
            return "TRANSACTION"
        elif query_upper.startswith(("GRANT", "REVOKE")):
            return "PRIVILEGE"
        elif query_upper.startswith(("LOCK", "UNLOCK")):
            return "LOCK"
        elif query_upper.startswith(("EXPLAIN", "DESCRIBE", "DESC")):
            return "EXPLAIN"
        elif query_upper.startswith(("SET", "SHOW")):
            return "SYSTEM"
        elif query_upper.startswith(("CREATE INDEX", "DROP INDEX", "ALTER INDEX")):
            return "INDEX"
        else:
            return "OTHER"

    def _handle_select_query(self, query: str, connection_id: int) -> Dict[str, Any]:
        """
        Handle SELECT queries with transparent decryption using the console service for consistency.
        This ensures complex queries with JOINs, aliases, and multiple tables work properly.
        """
        try:
            logger.info(
                f"VDS processing SELECT query using console service: {query[:100]}...")

            # Use the console service for consistent query processing
            # This ensures complex queries with JOINs, aliases, and schema mapping work properly
            from app.services.console_service import console_service

            # Load migration state for the console service
            migration_state = self.migration_state or self._load_migration_state()

            # Execute the query using console service (same as query console)
            result = console_service.execute_command(
                query,
                user_id=f"virtual_client_{connection_id}",
                database_url=self.encrypted_db_url,
                migration_state=migration_state
            )

            # Ensure the result has the correct query type
            if result.get("success") and result.get("query_type") in ["SELECT", "SQL"]:
                result["query_type"] = "SELECT"

            logger.info(
                f"VDS SELECT query result: success={result.get('success')}, row_count={result.get('row_count', 'N/A')}")

            return result

        except Exception as e:
            logger.error(f"Error in VDS SELECT query processing: {e}")
            return {
                "success": False,
                "error": str(e),
                "query_type": "SELECT"
            }

    def _handle_write_query(self, query: str, connection_id: int) -> Dict[str, Any]:
        """
        Handle INSERT/UPDATE/DELETE queries with transparent encryption.
        For write operations, plaintext values are encrypted using the Cryptopix CLWE engine
        before being sent to the physical encrypted database, ensuring that no unencrypted
        data is ever stored.
        """
        try:
            # Extract table name to check mapping
            table_name = self._extract_table_name(query)
            if not table_name:
                return {
                    "success": False,
                    "error": "Could not determine table name from query",
                    "query_type": query.split()[0].upper()
                }

            # Check if table is configured for encryption
            if table_name not in self.table_mappings:
                logger.warning(
                    f"Attempted write operation on unmapped table '{table_name}' - rejecting to ensure encryption")
                return {
                    "success": False,
                    "error": f"Table '{table_name}' is not configured for encrypted storage. All data must be encrypted before storage.",
                    "query_type": query.split()[0].upper()
                }

            logger.info(
                f"VDS encrypting data for write query on table '{table_name}'")

            # Use console service for consistent synchronous processing
            result = self.console_service.execute_command(
                command=query,
                user_id=f"virtual_client_{connection_id}",
                database_url=self.encrypted_db_url,
                migration_state=self.migration_state
            )

            if not result.get("success"):
                logger.error(f"Query execution failed: {result.get('error')}")
                return {
                    "success": False,
                    "error": result.get("error", "Query execution failed"),
                    "query_type": query.split()[0].upper()
                }

            logger.info(
                f"Query execution result: success={result.get('success')}, affected_rows={result.get('affected_rows', 'N/A')}")

            return {
                "success": True,
                "query_type": query.split()[0].upper(),
                "affected_rows": result.get("affected_rows", 0)
            }

        except Exception as e:
            logger.error(f"Error in write query processing: {e}")
            return {
                "success": False,
                "error": str(e),
                "query_type": query.split()[0].upper()
            }

    def _column_needs_decryption(self, column_name: str, original_query: str) -> bool:
        """Determine if a column needs decryption based on schema mappings"""
        # Extract table name from query (simplified)
        table_match = re.search(r'FROM\s+(\w+)', original_query, re.IGNORECASE)
        if table_match:
            table_name = table_match.group(1)
            table_mapping = self.table_mappings.get(table_name)

            if table_mapping and hasattr(table_mapping, 'encrypted_columns'):
                # Check if column is in encrypted columns
                column_mapping = table_mapping.encrypted_columns.get(
                    column_name)
                if column_mapping and hasattr(column_mapping, 'is_encrypted'):
                    return column_mapping.is_encrypted

        return False

    def _handle_ddl_query(self, query: str, connection_id: int) -> Dict[str, Any]:
        """Handle DDL queries by executing them directly on the encrypted database"""
        try:
            logger.info(f"VDS executing DDL query: {query[:100]}...")

            # Execute DDL directly on encrypted database
            result = self._execute_direct_query(query, "system")

            # Override query_type for DDL
            result["query_type"] = "DDL"

            logger.info(
                f"DDL execution result: success={result.get('success')}, affected_rows={result.get('affected_rows', 'N/A')}")

            return result

        except Exception as e:
            logger.error(f"Error executing DDL query: {e}")
            return {
                "success": False,
                "error": str(e),
                "query_type": "DDL"
            }

    def _handle_transaction_query(self, query: str, connection_id: int) -> Dict[str, Any]:
        """Handle transaction control queries"""
        try:
            query_upper = query.strip().upper()
            logger.info(f"VDS handling transaction query: {query}")

            if query_upper.startswith("BEGIN") or query_upper.startswith("START"):
                # For VDS, transactions are handled at the connection level
                return {
                    "success": True,
                    "query_type": "TRANSACTION",
                    "message": "Transaction started",
                    "transaction_status": "active"
                }
            elif query_upper.startswith("COMMIT"):
                return {
                    "success": True,
                    "query_type": "TRANSACTION",
                    "message": "Transaction committed",
                    "transaction_status": "committed"
                }
            elif query_upper.startswith("ROLLBACK"):
                return {
                    "success": True,
                    "query_type": "TRANSACTION",
                    "message": "Transaction rolled back",
                    "transaction_status": "rolled_back"
                }
            elif query_upper.startswith("SAVEPOINT"):
                return {
                    "success": True,
                    "query_type": "TRANSACTION",
                    "message": "Savepoint created",
                    "transaction_status": "active"
                }
            else:
                return {
                    "success": False,
                    "error": f"Unsupported transaction command: {query}",
                    "query_type": "TRANSACTION"
                }

        except Exception as e:
            logger.error(f"Error handling transaction query: {e}")
            return {
                "success": False,
                "error": str(e),
                "query_type": "TRANSACTION"
            }

    def _handle_privilege_query(self, query: str, connection_id: int) -> Dict[str, Any]:
        """Handle privilege management queries"""
        try:
            query_upper = query.strip().upper()
            logger.info(f"VDS handling privilege query: {query}")

            # In VDS context, privilege commands are informational
            if query_upper.startswith("GRANT"):
                return {
                    "success": True,
                    "query_type": "PRIVILEGE",
                    "message": "GRANT command acknowledged (VDS operates with full privileges)",
                    "note": "Virtual Database Server provides transparent access to encrypted data"
                }
            elif query_upper.startswith("REVOKE"):
                return {
                    "success": True,
                    "query_type": "PRIVILEGE",
                    "message": "REVOKE command acknowledged (VDS operates with full privileges)",
                    "note": "Virtual Database Server provides transparent access to encrypted data"
                }
            else:
                return {
                    "success": False,
                    "error": f"Unsupported privilege command: {query}",
                    "query_type": "PRIVILEGE"
                }

        except Exception as e:
            logger.error(f"Error handling privilege query: {e}")
            return {
                "success": False,
                "error": str(e),
                "query_type": "PRIVILEGE"
            }

    def _handle_lock_query(self, query: str, connection_id: int) -> Dict[str, Any]:
        """Handle table locking queries"""
        try:
            query_upper = query.strip().upper()
            logger.info(f"VDS handling lock query: {query}")

            # VDS handles locking at the virtual level
            if query_upper.startswith("LOCK"):
                return {
                    "success": True,
                    "query_type": "LOCK",
                    "message": "Table(s) locked successfully",
                    "lock_status": "acquired"
                }
            elif query_upper.startswith("UNLOCK"):
                return {
                    "success": True,
                    "query_type": "LOCK",
                    "message": "Table(s) unlocked successfully",
                    "lock_status": "released"
                }
            else:
                return {
                    "success": False,
                    "error": f"Unsupported lock command: {query}",
                    "query_type": "LOCK"
                }

        except Exception as e:
            logger.error(f"Error handling lock query: {e}")
            return {
                "success": False,
                "error": str(e),
                "query_type": "LOCK"
            }

    def _handle_explain_query(self, query: str, connection_id: int) -> Dict[str, Any]:
        """Handle EXPLAIN/DESCRIBE queries"""
        try:
            query_upper = query.strip().upper()
            logger.info(f"VDS handling explain query: {query}")

            if query_upper.startswith("EXPLAIN"):
                # Extract the query to explain
                explain_match = re.search(
                    r'EXPLAIN\s+(.+)', query, re.IGNORECASE | re.DOTALL)
                if explain_match:
                    inner_query = explain_match.group(1).strip()
                    return {
                        "success": True,
                        "query_type": "EXPLAIN",
                        "explained_query": inner_query,
                        "explanation": f"Query execution plan for: {inner_query[:100]}...",
                        "note": "VDS provides transparent encryption/decryption - execution plan shows virtual schema"
                    }
                else:
                    return {
                        "success": False,
                        "error": "Invalid EXPLAIN syntax",
                        "query_type": "EXPLAIN"
                    }

            elif query_upper.startswith(("DESCRIBE", "DESC")):
                # Extract table name
                desc_match = re.search(
                    r'DESCRIBE\s+(\w+)', query, re.IGNORECASE)
                if desc_match:
                    table_name = desc_match.group(1)
                    return self._describe_table(table_name, connection_id)
                else:
                    return {
                        "success": False,
                        "error": "Invalid DESCRIBE syntax",
                        "query_type": "EXPLAIN"
                    }
            else:
                return {
                    "success": False,
                    "error": f"Unsupported explain command: {query}",
                    "query_type": "EXPLAIN"
                }

        except Exception as e:
            logger.error(f"Error handling explain query: {e}")
            return {
                "success": False,
                "error": str(e),
                "query_type": "EXPLAIN"
            }

    def _handle_system_query(self, query: str, connection_id: int) -> Dict[str, Any]:
        """Handle system-level queries like SET and SHOW"""
        try:
            query_upper = query.strip().upper()
            logger.info(f"VDS handling system query: {query}")

            if query_upper.startswith("SET"):
                # Handle SET commands (variables, etc.)
                return {
                    "success": True,
                    "query_type": "SYSTEM",
                    "message": "System variable set (acknowledged by VDS)",
                    "note": "VDS maintains virtual session state"
                }
            elif query_upper.startswith("SHOW"):
                # Handle various SHOW commands
                return self._handle_show_command(query, connection_id)
            else:
                return {
                    "success": False,
                    "error": f"Unsupported system command: {query}",
                    "query_type": "SYSTEM"
                }

        except Exception as e:
            logger.error(f"Error handling system query: {e}")
            return {
                "success": False,
                "error": str(e),
                "query_type": "SYSTEM"
            }

    def _handle_index_query(self, query: str, connection_id: int) -> Dict[str, Any]:
        """Handle index management queries"""
        try:
            query_upper = query.strip().upper()
            logger.info(f"VDS handling index query: {query}")

            # Execute index operations directly on encrypted database
            result = self._execute_direct_query(query, "system")
            result["query_type"] = "INDEX"

            logger.info(
                f"Index operation result: success={result.get('success')}, affected_rows={result.get('affected_rows', 'N/A')}")

            return result

        except Exception as e:
            logger.error(f"Error handling index query: {e}")
            return {
                "success": False,
                "error": str(e),
                "query_type": "INDEX"
            }

    def _execute_passthrough_query(self, query: str, connection_id: int) -> Dict[str, Any]:
        """Execute queries using the console service for consistency"""
        try:
            # Handle USE commands specially - ignore them since VDS always uses encrypted DB
            query_upper = query.strip().upper()
            if query_upper.startswith("USE "):
                logger.info(f"Ignoring USE command in VDS: {query}")
                return {
                    "success": True,
                    "query_type": "OTHER",
                    "message": "Database selection ignored in virtual database server"
                }

            logger.info(
                f"VDS processing passthrough query using console service: {query[:50]}...")

            # Use console service for consistent synchronous processing
            result = self.console_service.execute_command(
                command=query,
                user_id=f"virtual_client_{connection_id}",
                database_url=self.encrypted_db_url,
                migration_state=self.migration_state
            )

            if not result.get("success"):
                logger.error(f"Query execution failed: {result.get('error')}")
                return {
                    "success": False,
                    "error": result.get("error", "Query execution failed"),
                    "query_type": "OTHER"
                }

            logger.info(
                f"Query execution result: success={result.get('success')}, type={result.get('query_type')}")

            # Return the results
            return {
                "success": True,
                "query_type": result.get("query_type", "OTHER"),
                "rows": result.get("rows", []),
                "row_count": result.get("row_count", 0),
                "columns": result.get("columns", []),
                "affected_rows": result.get("affected_rows", 0)
            }

        except Exception as e:
            logger.error(f"Error in passthrough query: {e}")
            return {
                "success": False,
                "error": str(e),
                "query_type": "OTHER"
            }

    def _receive_handshake_response(self, client_socket: socket.socket, connection_id: int) -> bool:
        """
        Receive and process the client's handshake response (Login Packet).
        This consumes the packet sent by the client after our Greeting.
        """
        try:
            # Read packet header (4 bytes)
            header = b""
            while len(header) < 4:
                chunk = client_socket.recv(4 - len(header))
                if not chunk:
                    logger.warning(f"Connection {connection_id} closed during handshake")
                    return False
                header += chunk

            packet_length = struct.unpack('<I', header[:3] + b'\x00')[0]
            # sequence_number = header[3]  # Should be 1

            # Validate packet length
            if packet_length > 16 * 1024 * 1024:
                logger.error(f"Handshake packet too large: {packet_length}")
                return False

            # Read packet data
            data = b""
            while len(data) < packet_length:
                chunk = client_socket.recv(min(packet_length - len(data), 4096))
                if not chunk:
                    return False
                data += chunk

            # Parse handshake response 4.1
            if len(data) > 32:
                # Capability Flags (4) + Max Packet Size (4) + Charset (1) + Reserved (23) = 32 bytes
                # Username follows, null terminated
                username_end = data.find(b'\x00', 32)
                if username_end != -1:
                    username = data[32:username_end].decode('utf-8', errors='ignore')
                    logger.info(f"Client logging in as '{username}' (Connection {connection_id})")
                else:
                    logger.debug(f"Could not parse username from handshake (Connection {connection_id})")

            return True

        except Exception as e:
            logger.error(f"Error receiving handshake response for connection {connection_id}: {e}")
            return False

    def _receive_mysql_query(self, client_socket: socket.socket) -> str:
        """Receive MySQL query from client with improved error handling"""
        try:
            # Read packet header (4 bytes: 3 bytes length + 1 byte sequence)
            header = b""
            while len(header) < 4:
                chunk = client_socket.recv(4 - len(header))
                if not chunk:
                    return ""
                header += chunk

            if len(header) != 4:
                logger.warning(
                    f"Incomplete header received: {len(header)} bytes")
                return ""

            packet_length = struct.unpack('<I', header[:3] + b'\x00')[0]
            sequence_number = header[3]

            # Validate packet length (prevent buffer overflow attacks)
            if packet_length > 16 * 1024 * 1024:  # 16MB max
                logger.error(f"Packet too large: {packet_length} bytes")
                return ""

            # Read packet data
            data = b""
            while len(data) < packet_length:
                remaining = packet_length - len(data)
                chunk = client_socket.recv(min(remaining, 4096))
                if not chunk:
                    logger.warning(
                        f"Incomplete packet data: got {len(data)} of {packet_length} bytes")
                    return ""
                data += chunk

            if len(data) != packet_length:
                logger.warning(
                    f"Packet size mismatch: expected {packet_length}, got {len(data)}")
                return ""

            # First byte is command type
            command_type = data[0]
            query_data = data[1:]

            if command_type == COM_QUERY:
                # Regular query
                try:
                    return query_data.decode('utf-8', errors='ignore')
                except UnicodeDecodeError:
                    logger.warning("Failed to decode query as UTF-8")
                    return ""
            elif command_type == COM_QUIT:
                # Client wants to quit
                return "QUIT"
            else:
                logger.debug(f"Unsupported MySQL command: {command_type}")
                return ""

        except (OSError, struct.error) as e:
            if getattr(e, 'winerror', 0) == 10053 or "aborted" in str(e):
                logger.info(f"Connection aborted by client (WinError 10053)")
            else:
                logger.error(f"Network or protocol error receiving MySQL query: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error receiving MySQL query: {e}")
            return None

    def _build_mysql_response(self, result: Dict[str, Any]) -> bytes:
        """Build MySQL response packet from query result"""
        try:
            if not result.get("success", False):
                return self._build_mysql_error_packet(result.get("error", "Unknown error"))

            if result.get("query_type") == "SELECT":
                packets = self._build_mysql_result_set_packets(result, 1)
                return b"".join(packets)
            else:
                # OK packet for non-SELECT queries
                affected_rows = result.get("affected_rows", 0)
                return self._build_mysql_ok_packet(sequence_number=1, affected_rows=affected_rows)

        except Exception as e:
            logger.error(f"Error building MySQL response: {e}")
            return self._build_mysql_error_packet(str(e))

    def _build_mysql_result_set_packets(self, result: Dict[str, Any], start_sequence: int) -> List[bytes]:
        """Build MySQL result set packets (column definition + data rows)"""
        packets = []
        sequence_number = start_sequence

        try:
            if not result.get("success", False):
                # Return error packet
                return [self._build_mysql_error_packet(sequence_number, result.get("error", "Query failed"))]

            if result.get("query_type") == "SELECT":
                rows = result.get("rows", [])
                columns = result.get("columns", [])

                if not columns:
                    # No columns - return OK packet
                    packets.append(
                        self._build_mysql_ok_packet(sequence_number))
                    return packets

                # Column count packet
                column_count_packet = self._build_mysql_column_count_packet(
                    len(columns), sequence_number)
                packets.append(column_count_packet)
                sequence_number = (sequence_number + 1) % 256

                # Column definition packets
                for col_name in columns:
                    col_def_packet = self._build_mysql_column_definition_packet(
                        col_name, sequence_number)
                    packets.append(col_def_packet)
                    sequence_number = (sequence_number + 1) % 256

                # EOF packet after column definitions
                eof_packet = self._build_mysql_eof_packet(sequence_number)
                packets.append(eof_packet)
                sequence_number = (sequence_number + 1) % 256

                # Data row packets
                for row in rows:
                    row_packet = self._build_mysql_data_row_packet(
                        row, columns, sequence_number)
                    packets.append(row_packet)
                    sequence_number = (sequence_number + 1) % 256

                # Final EOF packet
                eof_packet = self._build_mysql_eof_packet(sequence_number)
                packets.append(eof_packet)

            else:
                # Non-SELECT query - return OK
                packets.append(self._build_mysql_ok_packet(sequence_number))

        except Exception as e:
            logger.error(f"Error building result set packets: {e}")
            return [self._build_mysql_error_packet(start_sequence, str(e))]

        return packets

    def _build_mysql_column_definition_packet(self, column_name: str, sequence_number: int) -> bytes:
        """Build MySQL column definition packet with simplified format"""
        try:
            # Use a very basic format that should work with most MySQL clients
            # This is a minimal implementation that avoids complex length encoding

            # Catalog "def" (3 bytes + null terminator = 4 bytes, but we'll use simple format)
            catalog = b"def\x00"

            # Empty strings for schema, table, org_table, org_name (1 byte each for length 0)
            empty_str = b"\x00"

            # Column name with length prefix
            name_bytes = column_name.encode('utf-8')
            name_with_len = bytes([len(name_bytes)]) + name_bytes

            # Fixed fields: charset(2), length(4), type(1), flags(2), decimals(1), filler(2)
            fixed_fields = (
                struct.pack('<H', 33) +      # charset utf8_general_ci
                struct.pack('<I', 255) +     # max length
                b'\xfd' +                     # VARCHAR type
                struct.pack('<H', 0) +       # flags
                b'\x00' +                     # decimals
                b'\x00\x00'                   # filler
            )

            # Build the packet content
            packet = (
                catalog +           # 4 bytes
                empty_str +         # 1 byte (schema)
                empty_str +         # 1 byte (table)
                empty_str +         # 1 byte (org_table)
                name_with_len +     # name
                name_with_len +     # org_name (same as name)
                b'\x0c' +           # length of fixed fields
                fixed_fields        # 12 bytes
            )

            # Add packet header
            packet_length = len(packet)
            header = struct.pack('<I', packet_length)[
                :3] + bytes([sequence_number])

            logger.debug(
                f"Built column def for '{column_name}': {packet_length} bytes content + 4 bytes header")
            return header + packet

        except Exception as e:
            logger.error(f"Error building column definition packet: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return b""

    def _build_mysql_eof_packet(self, sequence_number: int) -> bytes:
        """Build MySQL EOF packet"""
        eof_data = bytes([EOF_PACKET, 0x00, 0x00])
        header = struct.pack('<I', len(eof_data))[
            :3] + bytes([sequence_number])
        return header + eof_data

    def _build_mysql_error_packet(self, error_message: str) -> bytes:
        """Build MySQL error packet"""
        error_data = bytes([ERR_PACKET])
        error_data += b'\x00\x00'  # error code (placeholder)
        error_data += b'#00000'   # SQL state
        error_data += error_message.encode('utf-8')

        header = struct.pack('<I', len(error_data))[
            :3] + bytes([1])  # sequence number
        return header + error_data

    def _build_mysql_ok_packet(self, sequence_number: int = 1, affected_rows: int = 0) -> bytes:
        """Build MySQL OK packet"""
        try:
            packet = b""

            # OK packet header (0x00)
            packet += bytes([OK_PACKET])

            # Affected rows (length-encoded integer)
            packet += self._encode_length_encoded_int(affected_rows)

            # Last insert ID (length-encoded integer)
            packet += self._encode_length_encoded_int(0)

            # Status flags (2 bytes)
            packet += struct.pack('<H', MYSQL_DEFAULT_STATUS)

            # Warnings (2 bytes)
            packet += struct.pack('<H', 0)

            packet_length = len(packet)
            header = struct.pack('<I', packet_length)[
                :3] + bytes([sequence_number])

            return header + packet

        except Exception as e:
            logger.error(f"Failed to build MySQL OK packet: {e}")
            return b""

    def _format_result_for_client(self, result: Dict[str, Any]) -> str:
        """Format query result for simple text-based client response"""
        try:
            if not result.get("success", False):
                return f"ERROR: {result.get('error', 'Unknown error')}"

            if result.get("query_type") == "SELECT":
                rows = result.get("rows", [])
                columns = result.get("columns", [])

                if not rows:
                    return "Empty result set"

                # Format as simple text table
                output = []
                output.append("| " + " | ".join(columns) + " |")
                output.append("|" + "|".join("-" * (len(col) + 2)
                              for col in columns) + "|")

                for row in rows[:10]:  # Limit to first 10 rows
                    row_values = []
                    for col in columns:
                        value = row.get(col, "")
                        if value is None:
                            value = "NULL"
                        else:
                            value = str(value)[:50]  # Truncate long values
                        row_values.append(value)
                    output.append("| " + " | ".join(row_values) + " |")

                if len(rows) > 10:
                    output.append(f"... and {len(rows) - 10} more rows")

                return "\n".join(output)
            else:
                affected_rows = result.get("affected_rows", 0)
                return f"Query OK, {affected_rows} rows affected"

        except Exception as e:
            logger.error(f"Error formatting result: {e}")
            return f"ERROR: Failed to format result: {str(e)}"

    def _build_mysql_greeting_packet(self) -> bytes:
        """Build MySQL greeting (handshake) packet"""
        try:
            # Generate random connection ID
            connection_id = random.randint(1, 2**32 - 1)

            # Generate random auth plugin data (20 bytes total, split into two parts)
            auth_plugin_data = b''.join(
                [bytes([random.randint(0, 255)]) for _ in range(20)])
            auth_plugin_data_part1 = auth_plugin_data[:8]
            auth_plugin_data_part2 = auth_plugin_data[8:]

            # Auth plugin name
            auth_plugin_name = b"mysql_native_password\x00"

            # Build the packet
            packet = b""

            # Protocol version (1 byte)
            packet += bytes([MYSQL_PROTOCOL_VERSION])

            # Server version (null-terminated string)
            packet += MYSQL_SERVER_VERSION.encode() + b'\x00'

            # Connection ID (4 bytes, little endian)
            packet += struct.pack('<I', connection_id)

            # Auth plugin data part 1 (8 bytes)
            packet += auth_plugin_data_part1

            # Filler (1 byte, always 0x00)
            packet += b'\x00'

            # Capability flags lower 2 bytes
            packet += struct.pack('<H', MYSQL_DEFAULT_CAPABILITIES & 0xFFFF)

            # Character set (1 byte)
            packet += bytes([MYSQL_DEFAULT_CHARSET])

            # Status flags (2 bytes)
            packet += struct.pack('<H', MYSQL_DEFAULT_STATUS)

            # Capability flags upper 2 bytes
            packet += struct.pack('<H',
                                  (MYSQL_DEFAULT_CAPABILITIES >> 16) & 0xFFFF)

            # Auth plugin data length (1 byte) - includes trailing null
            packet += bytes([len(auth_plugin_data_part2) + 1])

            # Reserved (10 bytes, all 0x00)
            packet += b'\x00' * 10

            # Auth plugin data part 2 (null-terminated)
            packet += auth_plugin_data_part2 + b'\x00'

            # Auth plugin name (null-terminated)
            packet += auth_plugin_name

            # Add packet length and sequence number (3 bytes length + 1 byte seq)
            packet_length = len(packet)
            sequence_number = 0
            header = struct.pack('<I', packet_length)[
                :3] + bytes([sequence_number])

            return header + packet

        except Exception as e:
            logger.error(f"Failed to build MySQL greeting packet: {e}")
            return b""

    def _build_mysql_ok_packet(self, sequence_number: int, affected_rows: int = 0, last_insert_id: int = 0) -> bytes:
        """Build MySQL OK packet"""
        try:
            packet = b""

            # OK packet header (0x00)
            packet += bytes([OK_PACKET])

            # Affected rows (length-encoded integer)
            packet += self._encode_length_encoded_int(affected_rows)

            # Last insert ID (length-encoded integer)
            packet += self._encode_length_encoded_int(last_insert_id)

            # Status flags (2 bytes)
            packet += struct.pack('<H', MYSQL_DEFAULT_STATUS)

            # Warnings (2 bytes)
            packet += struct.pack('<H', 0)

            # Add packet length and sequence number
            packet_length = len(packet)
            header = struct.pack('<I', packet_length)[
                :3] + bytes([sequence_number])

            return header + packet

        except Exception as e:
            logger.error(f"Failed to build MySQL OK packet: {e}")
            return b""

    def _encode_length_encoded_int(self, value: int) -> bytes:
        """Encode an integer as MySQL length-encoded integer"""
        if value < 251:
            return bytes([value])
        elif value < 2**16:
            return b'\xfc' + struct.pack('<H', value)
        elif value < 2**24:
            return b'\xfd' + struct.pack('<I', value)[:3]
        else:
            return b'\xfe' + struct.pack('<Q', value)

    def start(self):
        """Start the virtual database server"""
        try:
            self.running = True

            if self.target_protocol == "mysql":
                self._start_mysql_server()
            elif self.target_protocol == "postgresql":
                self._start_postgresql_server()
            else:
                raise ValueError(
                    f"Unsupported protocol: {self.target_protocol}")

        except Exception as e:
            logger.error(f"Failed to start virtual database server: {e}")
            self.running = False
            raise

    def stop(self):
        """Stop the virtual database server"""
        logger.info("Stopping virtual database server...")
        self.running = False

        # Close all active connections (create a copy to avoid modification during iteration)
        for conn_id, conn_info in list(self.active_connections.items()):
            try:
                if 'socket' in conn_info:
                    conn_info['socket'].close()
            except:
                pass

        self.active_connections.clear()

        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass

        self.executor.shutdown(wait=True)
        logger.info("Virtual database server stopped")

    def _start_mysql_server(self):
        """Start MySQL protocol server"""
        if not PYMYSQL_AVAILABLE:
            raise ImportError("pymysql is required for MySQL protocol support")

        # Start MySQL wire protocol server
        self._start_mysql_wire_server()

    def _start_postgresql_server(self):
        """Start PostgreSQL protocol server"""
        if not PSYCOPG2_AVAILABLE:
            raise ImportError(
                "psycopg2 is required for PostgreSQL protocol support")

        self._start_tcp_proxy_server()

    def _start_mysql_wire_server(self):
        """Start MySQL wire protocol server"""
        try:
            self.server_socket = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)  # Non-blocking accept

            logger.info(
                f"MySQL virtual database server listening on {self.host}:{self.port}")

            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    logger.info(f"New MySQL connection from {client_address}")

                    # Handle connection in a separate thread
                    connection_id = self.connection_counter
                    self.connection_counter += 1

                    self.active_connections[connection_id] = {
                        'socket': client_socket,
                        'address': client_address,
                        'connected_at': time.time(),
                        'authenticated': False
                    }

                    self.executor.submit(
                        self._handle_mysql_connection, client_socket, connection_id)

                except socket.timeout:
                    continue  # Check if we should still be running
                except OSError:
                    break  # Socket was closed

        except Exception as e:
            logger.error(f"MySQL wire server error: {e}")
            raise

    def _start_tcp_proxy_server(self):
        """Start a TCP proxy server that handles database connections"""
        try:
            self.server_socket = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)  # Non-blocking accept

            logger.info(
                f"Virtual database server listening on {self.host}:{self.port}")

            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    logger.info(f"New connection from {client_address}")

                    # Handle connection in a separate thread
                    connection_id = self.connection_counter
                    self.connection_counter += 1

                    self.active_connections[connection_id] = {
                        'socket': client_socket,
                        'address': client_address,
                        'connected_at': time.time()
                    }

                    self.executor.submit(
                        self._handle_client_connection, client_socket, connection_id)

                except socket.timeout:
                    continue  # Check if we should still be running
                except OSError:
                    break  # Socket was closed

        except Exception as e:
            logger.error(f"TCP proxy server error: {e}")
            raise

    def _handle_mysql_connection(self, client_socket: socket.socket, connection_id: int):
        """Handle MySQL wire protocol connection"""
        try:
            logger.info(f"Handling MySQL connection {connection_id}")

            # Send greeting packet
            greeting_packet = self._build_mysql_greeting_packet()
            if not greeting_packet:
                logger.error("Failed to build greeting packet")
                return

            try:
                client_socket.send(greeting_packet)
                logger.info(
                    f"Sent MySQL greeting to connection {connection_id} (seq 0)")
            except Exception as e:
                logger.error(
                    f"Error sending greeting packet to connection {connection_id}: {e}")
                return

            # Handle handshake response first
            sequence_number = 1  # Greeting was sequence 0

            # Receive handshake response with improved error handling
            header = b""
            while len(header) < 4:
                chunk = client_socket.recv(4 - len(header))
                if not chunk:
                    logger.warning("Connection closed during handshake")
                    return
                header += chunk

            if len(header) != 4:
                logger.warning(
                    f"Incomplete handshake header: {len(header)} bytes")
                return

            packet_length = struct.unpack('<I', header[:3] + b'\x00')[0]
            packet_seq = header[3]
            logger.info(
                f"Received handshake response seq {packet_seq}, expected seq 1, length {packet_length}")
            logger.debug(f"Handshake header bytes: {header.hex()}")

            # Validate packet length
            if packet_length > 1024 * 1024:  # 1MB max for handshake
                logger.error(
                    f"Handshake packet too large: {packet_length} bytes")
                return

            packet_body = b""
            while len(packet_body) < packet_length:
                remaining = packet_length - len(packet_body)
                chunk = client_socket.recv(min(4096, remaining))
                if not chunk:
                    logger.warning(
                        f"Incomplete handshake packet: got {len(packet_body)} of {packet_length} bytes")
                    return
                packet_body += chunk

            if len(packet_body) != packet_length:
                logger.warning(
                    f"Handshake packet size mismatch: expected {packet_length}, got {len(packet_body)}")
                return

            # Process handshake response
            if not self._process_mysql_handshake_response(packet_body, connection_id):
                logger.error(
                    f"Handshake failed for connection {connection_id}")
                return

            # Send OK packet to acknowledge authentication
            # Sequence number should be incremented from the received packet
            sequence_number = (packet_seq + 1) % 256
            ok_packet = self._build_mysql_ok_packet(sequence_number)
            try:
                client_socket.send(ok_packet)
                logger.info(f"Sent auth OK packet with seq {sequence_number}")
            except Exception as e:
                logger.error(
                    f"Error sending auth OK packet to connection {connection_id}: {e}")
                return
            sequence_number = (sequence_number + 1) % 256

            # Mark as authenticated
            if connection_id in self.active_connections:
                self.active_connections[connection_id]['authenticated'] = True

            logger.info(
                f"Connection {connection_id} authenticated successfully")

            # Now handle subsequent packets (queries)
            while self.running:
                try:
                    # Receive packet header with improved error handling
                    header = b""
                    while len(header) < 4:
                        chunk = client_socket.recv(4 - len(header))
                        if not chunk:
                            logger.info("Connection closed by client")
                            break
                        header += chunk

                    if len(header) != 4:
                        logger.warning(
                            f"Incomplete packet header: {len(header)} bytes")
                        break

                    packet_length = struct.unpack(
                        '<I', header[:3] + b'\x00')[0]
                    packet_seq = header[3]

                    # Validate packet length
                    if packet_length > 16 * 1024 * 1024:  # 16MB max
                        logger.error(
                            f"Query packet too large: {packet_length} bytes")
                        break

                    # Update sequence number based on received packet
                    sequence_number = (packet_seq + 1) % 256

                    # Receive packet body
                    packet_body = b""
                    while len(packet_body) < packet_length:
                        remaining = packet_length - len(packet_body)
                        chunk = client_socket.recv(min(4096, remaining))
                        if not chunk:
                            logger.warning(
                                f"Incomplete packet body: got {len(packet_body)} of {packet_length} bytes")
                            break
                        packet_body += chunk

                    if len(packet_body) != packet_length:
                        logger.warning(
                            f"Packet size mismatch: expected {packet_length}, got {len(packet_body)}")
                        break

                    # Process packet based on first byte
                    if packet_body:
                        packet_type = packet_body[0]

                        if packet_type == COM_QUIT:
                            logger.info(
                                f"Client {connection_id} sent COM_QUIT")
                            break
                        elif packet_type == COM_QUERY:
                            # Handle SQL query
                            query = packet_body[1:].decode(
                                'utf-8', errors='ignore')
                            logger.info(
                                f"Query from {connection_id}: {query[:100]}...")

                            response_packets = self._process_mysql_query(
                                query, connection_id, sequence_number)
                            logger.debug(
                                f"Sending {len(response_packets)} response packets")
                            for i, packet in enumerate(response_packets):
                                logger.debug(
                                    f"Sending packet {i+1}: {len(packet)} bytes")
                                try:
                                    client_socket.send(packet)
                                except Exception as e:
                                    logger.error(
                                        f"Error sending response packet {i+1} to connection {connection_id}: {e}")
                                    break
                                sequence_number = (sequence_number + 1) % 256
                        else:
                            # Unknown or unhandled command - send OK for now
                            ok_packet = self._build_mysql_ok_packet(
                                sequence_number)
                            try:
                                client_socket.send(ok_packet)
                            except Exception as e:
                                logger.error(
                                    f"Error sending OK packet for unknown command to connection {connection_id}: {e}")
                                break
                            sequence_number = (sequence_number + 1) % 256

                except socket.error:
                    break

        except Exception as e:
            logger.error(
                f"Error handling MySQL connection {connection_id}: {e}")
        finally:
            # Cleanup connection
            try:
                client_socket.close()
            except:
                pass

            if connection_id in self.active_connections:
                del self.active_connections[connection_id]

            logger.info(f"MySQL connection {connection_id} closed")

    def _process_mysql_handshake_response(self, packet_body: bytes, connection_id: int) -> bool:
        """Process MySQL handshake response packet"""
        try:
            # For now, accept any handshake response (dummy authentication)
            # In a real implementation, you'd validate username/password
            logger.info(
                f"Processing handshake response for connection {connection_id}")
            return True

        except Exception as e:
            logger.error(f"Error processing handshake response: {e}")
            return False

    def _handle_client_connection(self, client_socket: socket.socket, connection_id: int):
        """Handle individual client connection"""
        try:
            logger.info(f"Handling connection {connection_id}")

            # For simplicity, we'll implement a basic text-based protocol
            # In production, this would need to implement the full database wire protocol

            # Send welcome message
            welcome_msg = f"Virtual CryptoPIX Database Server ({self.target_protocol.upper()}) ready.\n"
            try:
                client_socket.send(welcome_msg.encode())
            except Exception as e:
                logger.error(
                    f"Error sending welcome message to connection {connection_id}: {e}")
                return

            buffer = ""

            while self.running:
                try:
                    # Receive data
                    data = client_socket.recv(4096)
                    if not data:
                        break  # Connection closed

                    buffer += data.decode('utf-8', errors='ignore')

                    # Process complete commands (commands ending with semicolon)
                    while ';' in buffer:
                        command_end = buffer.find(';')
                        command = buffer[:command_end].strip()
                        buffer = buffer[command_end + 1:]

                        if command.upper() in ['QUIT', 'EXIT']:
                            logger.info(
                                f"Client {connection_id} requested disconnect")
                            break

                        if command:
                            # Process SQL command
                            response = self._process_sql_command(
                                command, connection_id)
                            try:
                                client_socket.send((response + "\n").encode())
                            except Exception as e:
                                logger.error(
                                    f"Error sending response to connection {connection_id}: {e}")
                                break

                except socket.error:
                    break

        except Exception as e:
            logger.error(f"Error handling connection {connection_id}: {e}")
        finally:
            # Cleanup connection
            try:
                client_socket.close()
            except:
                pass

            if connection_id in self.active_connections:
                del self.active_connections[connection_id]

            logger.info(f"Connection {connection_id} closed")

    def _process_mysql_query(self, query: str, connection_id: int, sequence_number: int) -> List[bytes]:
        """Process MySQL query and return response packets"""
        try:
            logger.info(
                f"Processing MySQL query from connection {connection_id}: {query[:100]}...")

            # Parse the command to determine if it's a query
            command_upper = query.strip().upper()

            if command_upper.startswith('SHOW'):
                # Handle SHOW commands properly
                result = self._handle_show_mysql_command(query, connection_id)
                if result.get("query_type") in ["SELECT", "SYSTEM"]:
                    return self._build_mysql_result_set_packets(result, sequence_number)
                else:
                    return [self._build_mysql_ok_packet(sequence_number)]
            elif command_upper.startswith('DESCRIBE') or command_upper.startswith('DESC'):
                # Handle DESCRIBE commands
                result = self._handle_explain_query(query, connection_id)
                if result.get("success") and result.get("rows"):
                    return self._build_mysql_result_set_packets(result, sequence_number)
                else:
                    return [self._build_mysql_error_packet(sequence_number, result.get("error", "DESCRIBE failed"))]
            elif command_upper.startswith('SELECT'):
                # Execute SELECT query and return result set
                result = self._execute_query(query, connection_id)
                return self._build_mysql_result_set_packets(result, sequence_number)
            elif command_upper.startswith(('INSERT', 'UPDATE', 'DELETE')):
                # Execute modification query
                result = self._execute_query(query, connection_id)
                affected_rows = result.get(
                    "affected_rows", 0) if result.get("success") else 0
                return [self._build_mysql_ok_packet(sequence_number, affected_rows)]
            elif command_upper.startswith(('CREATE', 'ALTER', 'DROP', 'TRUNCATE', 'RENAME')):
                # Handle DDL commands
                result = self._handle_ddl_query(query, connection_id)
                return [self._build_mysql_ok_packet(sequence_number)]
            elif command_upper.startswith(('BEGIN', 'START', 'COMMIT', 'ROLLBACK', 'SAVEPOINT')):
                # Handle transaction commands
                result = self._handle_transaction_query(query, connection_id)
                return [self._build_mysql_ok_packet(sequence_number)]
            elif command_upper.startswith(('GRANT', 'REVOKE')):
                # Handle privilege commands
                result = self._handle_privilege_query(query, connection_id)
                return [self._build_mysql_ok_packet(sequence_number)]
            elif command_upper.startswith(('LOCK', 'UNLOCK')):
                # Handle lock commands
                result = self._handle_lock_query(query, connection_id)
                return [self._build_mysql_ok_packet(sequence_number)]
            elif command_upper.startswith('EXPLAIN'):
                # Handle EXPLAIN commands
                result = self._handle_explain_query(query, connection_id)
                if result.get("success") and result.get("rows"):
                    return self._build_mysql_result_set_packets(result, sequence_number)
                else:
                    return [self._build_mysql_error_packet(sequence_number, result.get("error", "EXPLAIN failed"))]
            elif command_upper.startswith(('SET', 'SHOW')):
                # Handle system commands
                result = self._handle_system_query(query, connection_id)
                if result.get("success") and result.get("rows"):
                    return self._build_mysql_result_set_packets(result, sequence_number)
                else:
                    return [self._build_mysql_ok_packet(sequence_number)]
            elif 'INDEX' in command_upper:
                # Handle index commands
                result = self._handle_index_query(query, connection_id)
                return [self._build_mysql_ok_packet(sequence_number)]
            else:
                # For other commands, try to execute as passthrough
                result = self._execute_passthrough_query(query, connection_id)
                if result.get("success") and result.get("rows"):
                    return self._build_mysql_result_set_packets(result, sequence_number)
                else:
                    return [self._build_mysql_ok_packet(sequence_number)]

        except Exception as e:
            logger.error(f"Error processing MySQL query: {e}")
            # Return error packet
            return [self._build_mysql_error_packet(sequence_number, str(e))]

    def _build_mysql_result_set_packets(self, result: Dict[str, Any], start_sequence: int) -> List[bytes]:
        """Build MySQL result set packets (column definition + data rows)"""
        packets = []
        sequence_number = start_sequence

        try:
            if not result.get("success", False):
                # Return error packet
                return [self._build_mysql_error_packet(sequence_number, result.get("error", "Query failed"))]

            if result.get("query_type") == "SELECT":
                rows = result.get("rows", [])
                columns = result.get("columns", [])

                if not columns:
                    # No columns - return OK packet
                    packets.append(
                        self._build_mysql_ok_packet(sequence_number))
                    return packets

                # Column count packet
                column_count_packet = self._build_mysql_column_count_packet(
                    len(columns), sequence_number)
                packets.append(column_count_packet)
                sequence_number = (sequence_number + 1) % 256

                # Column definition packets
                for col_name in columns:
                    col_def_packet = self._build_mysql_column_definition_packet(
                        col_name, sequence_number)
                    packets.append(col_def_packet)
                    sequence_number = (sequence_number + 1) % 256

                # EOF packet after column definitions
                eof_packet = self._build_mysql_eof_packet(sequence_number)
                packets.append(eof_packet)
                sequence_number = (sequence_number + 1) % 256

                # Data row packets
                for row in rows:
                    row_packet = self._build_mysql_data_row_packet(
                        row, columns, sequence_number)
                    packets.append(row_packet)
                    sequence_number = (sequence_number + 1) % 256

                # Final EOF packet
                eof_packet = self._build_mysql_eof_packet(sequence_number)
                packets.append(eof_packet)

            else:
                # Non-SELECT query - return OK
                packets.append(self._build_mysql_ok_packet(sequence_number))

        except Exception as e:
            logger.error(f"Error building result set packets: {e}")
            return [self._build_mysql_error_packet(start_sequence, str(e))]

        return packets

    def _build_mysql_column_count_packet(self, column_count: int, sequence_number: int) -> bytes:
        """Build column count packet"""
        packet = self._encode_length_encoded_int(column_count)
        packet_length = len(packet)
        header = struct.pack('<I', packet_length)[
            :3] + bytes([sequence_number])
        return header + packet

    def _build_mysql_column_definition_packet(self, column_name: str, sequence_number: int) -> bytes:
        """Build column definition packet"""
        try:
            packet = b""

            # Catalog (length-encoded string)
            packet += self._encode_length_encoded_string("def")

            # Schema (length-encoded string)
            packet += self._encode_length_encoded_string("")

            # Table (length-encoded string)
            packet += self._encode_length_encoded_string("")

            # Org table (length-encoded string)
            packet += self._encode_length_encoded_string("")

            # Name (length-encoded string)
            packet += self._encode_length_encoded_string(column_name)

            # Org name (length-encoded string)
            packet += self._encode_length_encoded_string(column_name)

            # Length of fixed-length fields (1 byte)
            packet += b'\x0c'  # 12 bytes following

            # Character set (2 bytes)
            packet += struct.pack('<H', MYSQL_DEFAULT_CHARSET)

            # Column length (4 bytes)
            packet += struct.pack('<I', 255)  # Default length

            # Column type (1 byte) - VARCHAR
            packet += b'\xfd'  # MYSQL_TYPE_VAR_STRING

            # Flags (2 bytes)
            packet += struct.pack('<H', 0)

            # Decimals (1 byte)
            packet += b'\x00'

            # Filler (2 bytes)
            packet += b'\x00\x00'

            packet_length = len(packet)
            header = struct.pack('<I', packet_length)[
                :3] + bytes([sequence_number])
            return header + packet

        except Exception as e:
            logger.error(f"Error building column definition packet: {e}")
            return b""

    def _decrypt_value_for_vds(self, col_name: str, value: Any) -> str:
        """
        VDS DECRYPTION: Decrypt any encrypted data before sending to MySQL clients.
        This ensures VDS always returns plaintext data regardless of console service processing.
        """
        try:
            # Skip tag columns
            if col_name.startswith('tag_'):
                return ""

            # If value is None, return empty string
            if value is None:
                return ""

            # If value is already a string, check if it's actually encrypted hex data
            if isinstance(value, str):
                # Check if it's a hex string that represents encrypted data
                if len(value) > 100 and len(value) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in value):
                    try:
                        hex_bytes = bytes.fromhex(value)
                        if hex_bytes.startswith(b'RIFF') and b'WEBP' in hex_bytes[:20]:
                            logger.info(
                                f"VDS DECRYPT: Found encrypted hex WebP data in {col_name}")
                            decrypted_value = clwe_encryptor.decrypt_value(
                                hex_bytes, settings.CRYPTOPIX_DEFAULT_PASSWORD)
                            return str(decrypted_value)
                    except Exception as e:
                        logger.debug(
                            f"VDS DECRYPT: Hex string in {col_name} not encrypted")
                # Otherwise, it's already decrypted
                return value

            # If value is bytes, it needs decryption
            if isinstance(value, bytes):
                try:
                    logger.info(
                        f"VDS DECRYPT: Decrypting bytes data in {col_name} (size: {len(value)})")
                    decrypted_value = clwe_encryptor.decrypt_value(
                        value, settings.CRYPTOPIX_DEFAULT_PASSWORD)
                    logger.info(
                        f"VDS DECRYPT: Successfully decrypted {col_name}")
                    return str(decrypted_value)
                except Exception as e:
                    logger.error(
                        f"VDS DECRYPT: Failed to decrypt bytes in {col_name}: {e}")
                    # If decryption fails, it might not be encrypted - return as hex
                    return value.hex()

            # For any other type, convert to string
            return str(value)

        except Exception as e:
            logger.error(
                f"VDS DECRYPT: Critical error processing {col_name}: {e}")
            return f"<ERROR:{str(e)}>"

    def _get_column_variations(self, col_name: str) -> List[str]:
        """Get common variations of column names for matching"""
        variations = [col_name.lower()]

        # Common variations
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

        # Add underscores and remove them
        if '_' in col_name:
            variations.append(col_name.replace('_', ''))
        else:
            # Try adding underscores at common places
            import re
            underscored = re.sub(r'([a-z])([A-Z])', r'\1_\2', col_name)
            if underscored != col_name:
                variations.append(underscored.lower())

        return list(set(variations))  # Remove duplicates

    def _make_json_serializable(self, value) -> Any:
        """
        Convert any value to a JSON-serializable type
        """
        if isinstance(value, bytes):
            # Try to decode as UTF-8 string first (for decrypted values)
            try:
                return value.decode('utf-8')
            except UnicodeDecodeError:
                # If it can't be decoded as UTF-8, convert to hex string
                return value.hex()
        elif isinstance(value, (int, float, str, bool, type(None))):
            # Already JSON serializable
            return value
        elif hasattr(value, '__str__'):
            # Convert to string
            return str(value)
        else:
            # Fallback - convert to string representation
            return repr(value)

    def _build_mysql_data_row_packet(self, row: Dict[str, Any], columns: List[str], sequence_number: int) -> bytes:
        """Build data row packet with advanced decryption support using console service logic"""
        try:
            packet = b""

            for col_name in columns:
                value = row.get(col_name, None)

                # Handle NULL values
                if value is None:
                    # NULL is represented as 0xFB (251) in MySQL protocol
                    packet += b'\xfb'
                else:
                    # Use the same decryption logic as console service for consistency
                    str_value = self._decrypt_value_for_vds(col_name, value)

                    # Encode as UTF-8
                    encoded_value = str_value.encode('utf-8')

                    # Length-encoded: 1 byte length + data (for lengths < 251)
                    if len(encoded_value) < 251:
                        packet += bytes([len(encoded_value)]) + encoded_value
                    else:
                        # For longer strings, we'd need proper length encoding
                        # For now, truncate to avoid complexity
                        truncated = encoded_value[:250]
                        packet += bytes([len(truncated)]) + truncated

            packet_length = len(packet)
            header = struct.pack('<I', packet_length)[
                :3] + bytes([sequence_number])

            logger.debug(
                f"Built data row packet: seq={sequence_number}, content_length={packet_length}")
            return header + packet

        except Exception as e:
            logger.error(f"Error building data row packet: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return b""

    def _build_mysql_eof_packet(self, sequence_number: int) -> bytes:
        """Build EOF packet (simplified)"""
        # EOF packet: 0xfe + warning count (2 bytes) + status flags (2 bytes)
        # EOF + 2 bytes warnings + 2 bytes status
        packet = bytes([EOF_PACKET, 0x00, 0x00, 0x00, 0x00])
        packet_length = len(packet)
        header = struct.pack('<I', packet_length)[
            :3] + bytes([sequence_number])
        logger.debug(
            f"Built EOF packet: {packet_length} bytes content, seq {sequence_number}")
        return header + packet

    def _build_mysql_error_packet(self, sequence_number: int, error_message: str) -> bytes:
        """Build error packet"""
        try:
            packet = b""

            # Error packet header (0xff)
            packet += bytes([ERR_PACKET])

            # Error code (2 bytes)
            packet += struct.pack('<H', 2000)  # Custom error code

            # SQL state marker (#)
            packet += b'#'

            # SQL state (5 bytes)
            packet += b'42000'  # General error

            # Error message
            packet += error_message.encode('utf-8')

            packet_length = len(packet)
            header = struct.pack('<I', packet_length)[
                :3] + bytes([sequence_number])
            return header + packet

        except Exception as e:
            logger.error(f"Error building error packet: {e}")
            return b""

    def _encode_length_encoded_string(self, s: str) -> bytes:
        """Encode a string as MySQL length-encoded string"""
        encoded = s.encode('utf-8')
        return self._encode_length_encoded_int(len(encoded)) + encoded

    def _process_sql_command(self, command: str, connection_id: int) -> str:
        """Process SQL command and return response"""
        try:
            logger.info(
                f"Processing command from connection {connection_id}: {command[:100]}...")

            # Parse the command to determine if it's a query
            command_upper = command.strip().upper()

            if command_upper.startswith(('SELECT', 'INSERT', 'UPDATE', 'DELETE')):
                # Execute query
                result = self._execute_query(command, connection_id)
                return self._format_query_result(result)
            elif command_upper.startswith('SHOW'):
                # Handle SHOW commands
                return self._handle_show_command(command)
            elif command_upper.startswith(('CREATE', 'ALTER', 'DROP')):
                # Handle DDL commands
                return self._handle_ddl_command(command)
            else:
                return f"Command not supported: {command[:50]}..."

        except Exception as e:
            logger.error(f"Error processing command: {e}")
            return f"ERROR: {str(e)}"

    def _execute_query(self, query: str, connection_id: int) -> Dict[str, Any]:
        """Execute SQL query on encrypted database using console service for consistency"""
        try:
            logger.info(
                f"VDS executing query using console service: {query[:100]}...")

            # Use the console service for all query execution to ensure consistency
            # This provides the same processing as the query console for all SQL operations
            from app.services.console_service import console_service

            # Load migration state for the console service
            migration_state = self.migration_state or self._load_migration_state()

            # Execute the query using console service (same as query console)
            result = console_service.execute_command(
                query,
                user_id=f"virtual_client_{connection_id}",
                database_url=self.encrypted_db_url,
                migration_state=migration_state
            )

            logger.info(
                f"VDS query execution result: success={result.get('success')}, type={result.get('query_type')}")

            return result

        except Exception as e:
            logger.error(f"VDS query execution failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def _execute_direct_query(self, query: str, table_name: str) -> Dict[str, Any]:
        """Execute query directly on encrypted database (for unmapped tables)"""
        try:
            engine = create_engine(self.encrypted_db_url)

            with engine.connect() as conn:
                result = conn.execute(text(query))

                if query.strip().upper().startswith("SELECT"):
                    rows = result.fetchall()
                    column_names = result.keys()

                    # Convert to list of dicts
                    results = []
                    for row in rows:
                        row_dict = {}
                        for i, col_name in enumerate(column_names):
                            row_dict[col_name] = row[i]
                        results.append(row_dict)

                    return {
                        "success": True,
                        "query_type": "SELECT",
                        "rows": results,
                        "row_count": len(results),
                        "columns": list(column_names)
                    }
                else:
                    conn.commit()
                    return {
                        "success": True,
                        "query_type": "MODIFICATION",
                        "affected_rows": getattr(result, 'rowcount', 0)
                    }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def _extract_table_name(self, query: str) -> Optional[str]:
        """Extract table name from SQL query"""
        import re

        # For SHOW TABLES and similar commands, return a dummy table name
        query_upper = query.strip().upper()
        if query_upper.startswith(('SHOW', 'DESCRIBE', 'EXPLAIN')):
            return "system_tables"  # Dummy table name for system queries

        # Try different patterns
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
                return match.group(1)

        return None

    def _format_query_result(self, result: Dict[str, Any]) -> str:
        """Format query result for client response"""
        try:
            if not result.get("success", False):
                return f"ERROR: {result.get('error', 'Unknown error')}"

            if result.get("query_type") == "SELECT":
                rows = result.get("rows", [])
                columns = result.get("columns", [])

                if not rows:
                    return "Empty result set"

                # Format as simple text table
                output = []

                # Header
                output.append("| " + " | ".join(columns) + " |")
                output.append("|" + "|".join("-" * (len(col) + 2)
                              for col in columns) + "|")

                # Data rows
                for row in rows[:10]:  # Limit to first 10 rows for display
                    row_values = []
                    for col in columns:
                        value = row.get(col, "")
                        if value is None:
                            value = "NULL"
                        else:
                            value = str(value)[:50]  # Truncate long values
                        row_values.append(value)
                    output.append("| " + " | ".join(row_values) + " |")

                if len(rows) > 10:
                    output.append(f"... and {len(rows) - 10} more rows")

                return "\n".join(output)

            else:
                # Non-SELECT queries
                affected_rows = result.get("affected_rows", 0)
                return f"Query OK, {affected_rows} rows affected"

        except Exception as e:
            logger.error(f"Error formatting result: {e}")
            return f"ERROR: Failed to format result: {str(e)}"

    def _handle_show_mysql_command(self, command: str, connection_id: int) -> Dict[str, Any]:
        """Handle SHOW commands for MySQL protocol"""
        command_upper = command.upper()

        if "SHOW TABLES" in command_upper:
            # Get list of tables from encrypted database
            try:
                engine = create_engine(self.encrypted_db_url)
                inspector = inspect(engine)

                tables = inspector.get_table_names()
                engine.dispose()

                # Return as result set
                rows = [{"Tables_in_cryptopix": table} for table in tables]
                return {
                    "success": True,
                    "query_type": "SELECT",
                    "rows": rows,
                    "row_count": len(rows),
                    "columns": ["Tables_in_cryptopix"]
                }

            except Exception as e:
                return {
                    "success": False,
                    "error": str(e)
                }

        elif "SHOW DATABASES" in command_upper:
            return {
                "success": True,
                "query_type": "SELECT",
                "rows": [{"Database": "cryptopix_virtual_db"}],
                "row_count": 1,
                "columns": ["Database"]
            }

        else:
            return {
                "success": False,
                "error": f"SHOW command not fully supported: {command}"
            }

    def _handle_show_command(self, command: str, connection_id: int) -> Dict[str, Any]:
        """Handle SHOW commands for VDS"""
        try:
            command_upper = command.upper()

            if "SHOW TABLES" in command_upper:
                # Get list of tables from encrypted database
                engine = create_engine(self.encrypted_db_url)
                inspector = inspect(engine)

                tables = inspector.get_table_names()
                engine.dispose()

                # Return as result set
                rows = [{"Tables_in_cryptopix": table} for table in tables]
                return {
                    "success": True,
                    "query_type": "SYSTEM",
                    "rows": rows,
                    "row_count": len(rows),
                    "columns": ["Tables_in_cryptopix"]
                }

            elif "SHOW DATABASES" in command_upper:
                return {
                    "success": True,
                    "query_type": "SYSTEM",
                    "rows": [{"Database": "cryptopix_virtual_db"}],
                    "row_count": 1,
                    "columns": ["Database"]
                }

            elif "SHOW VARIABLES" in command_upper or "SHOW STATUS" in command_upper:
                # Return some basic system variables
                variables = [
                    {"Variable_name": "version", "Value": "CryptoPIX Bridge v3.0"},
                    {"Variable_name": "version_comment",
                        "Value": "Virtual Database Server"},
                    {"Variable_name": "protocol_version", "Value": "10"},
                    {"Variable_name": "autocommit", "Value": "ON"},
                    {"Variable_name": "character_set_client", "Value": "utf8mb4"},
                    {"Variable_name": "character_set_connection", "Value": "utf8mb4"},
                    {"Variable_name": "character_set_results", "Value": "utf8mb4"}
                ]
                return {
                    "success": True,
                    "query_type": "SYSTEM",
                    "rows": variables,
                    "row_count": len(variables),
                    "columns": ["Variable_name", "Value"]
                }

            elif "SHOW PROCESSLIST" in command_upper:
                # Return virtual connection info
                processes = [{
                    "Id": connection_id,
                    "User": "virtual_client",
                    "Host": "virtual_connection",
                    "db": "cryptopix_virtual_db",
                    "Command": "Query",
                    "Time": 0,
                    "State": "executing",
                    "Info": command[:100]
                }]
                return {
                    "success": True,
                    "query_type": "SYSTEM",
                    "rows": processes,
                    "row_count": len(processes),
                    "columns": ["Id", "User", "Host", "db", "Command", "Time", "State", "Info"]
                }

            else:
                return {
                    "success": False,
                    "error": f"SHOW command not fully supported: {command}",
                    "query_type": "SYSTEM"
                }

        except Exception as e:
            logger.error(f"Error handling SHOW command: {e}")
            return {
                "success": False,
                "error": str(e),
                "query_type": "SYSTEM"
            }

    def _describe_table(self, table_name: str, connection_id: int) -> Dict[str, Any]:
        """Handle DESCRIBE table command"""
        try:
            # Get table schema from encrypted database
            engine = create_engine(self.encrypted_db_url)
            inspector = inspect(engine)

            # Check if table exists
            if not inspector.has_table(table_name):
                engine.dispose()
                return {
                    "success": False,
                    "error": f"Table '{table_name}' doesn't exist",
                    "query_type": "EXPLAIN"
                }

            # Get column information
            columns = inspector.get_columns(table_name)
            engine.dispose()

            # Format as DESCRIBE result
            rows = []
            for col in columns:
                # Skip tag columns in output
                if col['name'].startswith('tag_'):
                    continue

                # Determine if column is encrypted based on migration state
                is_encrypted = False
                if self.migration_state and self.migration_state.get('table_configs'):
                    table_config = self.migration_state['table_configs'].get(
                        table_name, {})
                    if col['name'] in table_config and table_config[col['name']].get('type') == 'encrypt':
                        is_encrypted = True

                row = {
                    "Field": col['name'],
                    "Type": str(col['type']) + (" (ENCRYPTED)" if is_encrypted else ""),
                    "Null": "YES" if col.get('nullable', True) else "NO",
                    "Key": "",  # Would need more complex logic to determine keys
                    "Default": str(col.get('default', 'NULL')) if col.get('default') else 'NULL',
                    "Extra": ""
                }
                rows.append(row)

            return {
                "success": True,
                "query_type": "EXPLAIN",
                "rows": rows,
                "row_count": len(rows),
                "columns": ["Field", "Type", "Null", "Key", "Default", "Extra"]
            }

        except Exception as e:
            logger.error(f"Error describing table {table_name}: {e}")
            return {
                "success": False,
                "error": str(e),
                "query_type": "EXPLAIN"
            }

    def _handle_ddl_command(self, command: str) -> str:
        """Handle DDL commands by executing them directly"""
        try:
            logger.info(f"VDS executing DDL command: {command[:100]}...")

            # Execute DDL directly on encrypted database
            result = self._execute_direct_query(command, "system")

            if result.get("success"):
                return f"DDL command executed successfully"
            else:
                return f"DDL command failed: {result.get('error', 'Unknown error')}"

        except Exception as e:
            logger.error(f"Error executing DDL command: {e}")
            return f"ERROR: Failed to execute DDL command: {str(e)}"


class VirtualDatabaseClient:
    """
    Client for connecting to virtual database server
    Demonstrates how client applications can connect seamlessly
    """

    def __init__(self, host: str = "localhost", port: int = 3307):
        self.host = host
        self.port = port
        self.socket = None

    def connect(self) -> bool:
        """Connect to virtual database server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))

            # Receive welcome message
            welcome = self.socket.recv(1024).decode()
            print(f"Connected: {welcome.strip()}")

            self.connected = True
            return True

        except Exception as e:
            self.connected = False
            raise Exception(f"Failed to connect to virtual database: {e}")

    def execute(self, query: str) -> str:
        """Execute SQL query"""
        if not self.socket:
            raise Exception("Not connected to database")

        try:
            # Send query
            self.socket.send((query + ";").encode())

            # Receive response
            response = b""
            while True:
                chunk = self.socket.recv(4096)
                if not chunk:
                    break
                response += chunk

                # Check if response is complete (simple check)
                if response.endswith(b"\n"):
                    break

            return response.decode()

        except Exception as e:
            raise Exception(f"Query execution failed: {e}")

    def close(self):
        """Close connection"""
        if self.socket:
            try:
                self.socket.send(b"QUIT;")
                self.socket.close()
            except:
                pass
            self.socket = None


# Global VDS instance
virtual_db_server = None


def start_virtual_server(host: str = "0.0.0.0",
                         port: int = 4406,
                         encrypted_db_url: str = None,
                         protocol: str = "mysql",
                         table_mappings: Dict[str, Any] = None,
                         max_connections: int = 100) -> VirtualDatabaseServer:
    """
    Start Virtual Database Server (VDS)

    The VDS acts as a smart intermediary that allows client applications to interact
    with fully encrypted databases exactly as if they were communicating with a normal database.

    Args:
        host: Host to bind to
        port: Port to listen on (default 4406 for VDS)
        encrypted_db_url: URL of the underlying encrypted database
        protocol: Database protocol to emulate (mysql, postgresql, sqlite)
        table_mappings: Schema mappings for encrypted columns
        max_connections: Maximum concurrent connections

    Returns:
        VirtualDatabaseServer instance
    """
    global virtual_db_server

    if virtual_db_server and virtual_db_server.running:
        logger.warning("Virtual Database Server already running")
        return virtual_db_server

    virtual_db_server = VirtualDatabaseServer(
        host=host,
        port=port,
        encrypted_db_url=encrypted_db_url,
        target_protocol=protocol,
        table_mappings=table_mappings,
        max_connections=max_connections
    )

    # Start the server (it handles its own threading)
    virtual_db_server.start()

    logger.info(f"Virtual Database Server (VDS) started successfully")
    logger.info(
        f"Clients can now connect using: {protocol}://{host}:{port}/database")
    logger.info(
        f"VDS provides transparent encryption/decryption for encrypted database access")

    return virtual_db_server


def stop_virtual_server():
    """Stop Virtual Database Server"""
    global virtual_db_server

    if virtual_db_server:
        virtual_db_server.stop()
        virtual_db_server = None
        logger.info("Virtual Database Server stopped")


def create_client_example():
    """Example of how clients can connect to virtual database"""
    print("""
# Example: Client Application Connection

from app.virtual_db_server import VirtualDatabaseClient

# Instead of connecting directly to encrypted database:
# conn = pymysql.connect(host="encrypted-server", user="user", password="pass", database="mydb")

# Connect to virtual database server:
client = VirtualDatabaseClient(host="127.0.0.1", port=3307)
client.connect()

# Execute queries normally - encryption/decryption happens transparently
result = client.execute("SELECT name, email FROM users WHERE age > 30")
print(result)

result = client.execute("INSERT INTO users (name, email) VALUES ('John Doe', 'john@example.com')")
print(result)

client.close()
""")


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)

    # Start server
    server = start_virtual_server(port=3307)

    try:
        # Keep running
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
        stop_virtual_server()
