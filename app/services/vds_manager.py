"""
VDS Manager Service
Manages multiple Virtual Database Server instances
"""

import logging
import threading
from typing import Dict, Optional, Any, Tuple
from pathlib import Path

from app.virtual_db_server import VDSInstance
from app.services.database_registry import database_registry
from app.core.encryption import clwe_encryptor
from app.config import settings
from sqlalchemy import create_engine, text, inspect
import json
import re

logger = logging.getLogger(__name__)


class VDSManager:
    """
    Manages multiple independent VDS instances keyed by (host, port).
    Each instance owns its own socket, console_service, threads, DB connection, and running flag.
    Provides thread-safe operations for starting, stopping, and monitoring VDS instances.
    """

    def __init__(self):
        """Initialize the VDS manager"""
        # Key: (host, port) tuple, Value: VDSInstance
        self.vds_instances: Dict[Tuple[str, int], VDSInstance] = {}
        self.lock = threading.Lock()
        logger.info("VDS Manager initialized with (host, port) keying")
        self._sync_registry_status()

    def _sync_registry_status(self):
        """Sync registry status on startup (mark all as stopped since we just started)"""
        try:
            dbs = database_registry.list_databases()
            count = 0
            for db in dbs:
                for vds in db.get("vds_instances", []):
                    if vds.get("status") == "running":
                        logger.info(
                            f"Resetting VDS {vds['id']} status to 'stopped' on startup")
                        database_registry.update_vds_status(
                            db["id"], vds["id"], "stopped")
                        count += 1
            if count > 0:
                logger.info(f"Reset {count} VDS instances to stopped state")
        except Exception as e:
            logger.error(f"Failed to sync registry status: {e}")

    def create_vds_instance(self,
                            db_id: str,
                            host: str,
                            port: int,
                            protocol: str = "mysql") -> Optional[str]:
        """
        Create a new VDS instance for a database.

        Args:
            db_id: Database ID
            host: Host to bind VDS to
            port: Port to bind VDS to
            protocol: Database protocol (mysql, postgresql, etc.)

        Returns:
            VDS instance ID if successful, None otherwise
        """
        with self.lock:
            try:
                # Check if (host, port) combination is already in use
                instance_key = (host, port)
                if instance_key in self.vds_instances:
                    logger.error(f"VDS instance already exists for {host}:{port}")
                    return None

                # Get database information
                database = database_registry.get_database(db_id)
                if not database:
                    logger.error(f"Database {db_id} not found")
                    return None

                # Check if port is already in use by registry
                if database_registry.is_port_in_use(port):
                    logger.error(f"Port {port} is already in use")
                    return None

                # Add VDS instance to database registry
                vds_instance = database_registry.add_vds_instance(
                    db_id=db_id,
                    host=host,
                    port=port,
                    protocol=protocol
                )

                if not vds_instance:
                    logger.error(f"Failed to add VDS instance to registry")
                    return None

                logger.info(
                    f"Created VDS instance {vds_instance['id']} for database {db_id} on {host}:{port}")
                return vds_instance['id']

            except Exception as e:
                logger.error(f"Failed to create VDS instance: {e}")
                return None

    def start_vds(self, db_id: str, vds_id: str) -> tuple[bool, str]:
        """
        Start a VDS instance.

        Args:
            db_id: Database ID
            vds_id: VDS instance ID

        Returns:
            Tuple (success, message)
        """
        with self.lock:
            try:
                # Get VDS instance info from registry
                vds_info = database_registry.get_vds_instance(db_id, vds_id)
                if not vds_info:
                    logger.error(
                        f"VDS instance {vds_id} not found in database {db_id}")
                    return False, "VDS instance not found"

                # Check if already running (memory check using (host, port) key)
                instance_key = (vds_info["host"], vds_info["port"])
                if instance_key in self.vds_instances:
                    if self.vds_instances[instance_key].running:
                        logger.warning(
                            f"VDS instance {vds_id} is already running on {vds_info['host']}:{vds_info['port']}")
                        return True, "VDS is already running"

                # Check if port is in use
                if database_registry.is_port_in_use(vds_info["port"], exclude_vds_id=vds_id):
                    return False, f"Port {vds_info['port']} is already configured for another VDS instance"

                # Get database information
                database = database_registry.get_database(db_id)
                if not database:
                    logger.error(f"Database {db_id} not found")
                    return False, "Database definition not found"

                # Load table mappings and migration state from schema folder
                schema_folder = Path(database["schema_folder"])
                mappings_file = schema_folder / "mappings.json"
                migration_state_file = schema_folder / "migration_state.json"

                table_mappings = {}
                migration_state = None

                # Load mappings first to check for needed repairs
                mappings_data = None
                if mappings_file.exists():
                    try:
                        with open(mappings_file, 'r') as f:
                            mappings_data = json.load(f)
                    except Exception as e:
                        logger.error(f"Failed to load mappings file: {e}")

                # Auto-repair hashed passwords if needed
                if mappings_data and self._repair_hashed_passwords(database["encrypted_db_url"], mappings_file, mappings_data):
                     # Reload if repaired
                     try:
                        with open(mappings_file, 'r') as f:
                            mappings_data = json.load(f)
                     except Exception as e:
                        logger.error(f"Failed to reload mappings after repair: {e}")

                if mappings_data:
                    table_mappings = mappings_data.get("table_mappings", {})

                # Legacy/Redundant block removed by update
                if migration_state_file.exists():
                    import json
                    with open(migration_state_file, 'r') as f:
                        migration_state = json.load(f)

                # Create VDSInstance with dedicated per-instance resources
                # Each instance owns its own socket, console_service, threads, DB connection, and running flag
                vds = VDSInstance(
                    host=vds_info["host"],
                    port=vds_info["port"],
                    encrypted_db_url=database["encrypted_db_url"],
                    target_protocol=vds_info["protocol"],
                    table_mappings=table_mappings,
                    max_connections=100,
                    migration_state=migration_state
                )

                vds.start()

                # Store VDS instance keyed by (host, port) tuple
                self.vds_instances[instance_key] = vds

                # Update status in registry
                database_registry.update_vds_status(db_id, vds_id, "running")

                logger.info(
                    f"Started independent VDS instance {vds_id} for database {db_id} on {vds_info['host']}:{vds_info['port']}")
                logger.info(f"Instance owns dedicated resources: socket, console_service, threads, DB connection")
                return True, f"VDS started on {vds_info['host']}:{vds_info['port']}"

            except Exception as e:
                logger.error(f"Failed to start VDS instance: {e}")
                # Update status to error
                database_registry.update_vds_status(db_id, vds_id, "error")
                return False, str(e)

    def stop_vds(self, db_id: str, vds_id: str) -> bool:
        """
        Stop a VDS instance.

        Args:
            db_id: Database ID
            vds_id: VDS instance ID

        Returns:
            True if successful, False otherwise
        """
        with self.lock:
            try:
                # Get VDS instance info to find the (host, port) key
                vds_info = database_registry.get_vds_instance(db_id, vds_id)
                if not vds_info:
                    logger.warning(f"VDS instance {vds_id} not found in registry")
                    return False

                instance_key = (vds_info["host"], vds_info["port"])

                if instance_key not in self.vds_instances:
                    logger.warning(f"VDS instance {vds_id} is not running (no instance found for {instance_key})")
                    # Update status anyway
                    database_registry.update_vds_status(
                        db_id, vds_id, "stopped")
                    return True

                # Stop VDS instance with timeout
                vds = self.vds_instances[instance_key]
                vds.stop(timeout=5.0)  # Use timeout for proper shutdown

                # Remove from active instances
                del self.vds_instances[instance_key]

                # Update status in registry
                database_registry.update_vds_status(db_id, vds_id, "stopped")

                logger.info(
                    f"Stopped independent VDS instance {vds_id} for database {db_id} on {vds_info['host']}:{vds_info['port']}")
                return True

            except Exception as e:
                logger.error(f"Failed to stop VDS instance: {e}")
                return False

    def get_vds_status(self, db_id: str, vds_id: str) -> Optional[str]:
        """
        Get the status of a VDS instance.

        Args:
            db_id: Database ID
            vds_id: VDS instance ID

        Returns:
            Status string (running, stopped, error) or None if not found
        """
        vds_info = database_registry.get_vds_instance(db_id, vds_id)
        if vds_info:
            return vds_info["status"]
        return None

    def is_vds_running(self, db_id: str, vds_id: str) -> bool:
        """
        Check if a VDS instance is running.

        Args:
            db_id: Database ID
            vds_id: VDS instance ID

        Returns:
            True if running, False otherwise
        """
        # Get VDS instance info to find the (host, port) key
        vds_info = database_registry.get_vds_instance(db_id, vds_id)
        if not vds_info:
            return False

        instance_key = (vds_info["host"], vds_info["port"])
        if instance_key in self.vds_instances:
            return self.vds_instances[instance_key].running
        return False

    def stop_all_vds(self) -> int:
        """
        Stop all running VDS instances.

        Returns:
            Number of instances stopped
        """
        with self.lock:
            count = 0
            instance_keys = list(self.vds_instances.keys())

            for instance_key in instance_keys:
                try:
                    # Find the VDS instance in registry by host/port
                    host, port = instance_key
                    # We need to find the db_id and vds_id for this instance
                    # This is a bit complex, so we'll iterate through all databases
                    found = False
                    for db in database_registry.list_databases():
                        for vds in db.get("vds_instances", []):
                            if vds.get("host") == host and vds.get("port") == port:
                                if self.stop_vds(db["id"], vds["id"]):
                                    count += 1
                                found = True
                                break
                        if found:
                            break
                except Exception as e:
                    logger.error(
                        f"Failed to stop VDS instance {instance_key}: {e}")

            logger.info(f"Stopped {count} independent VDS instances")
            return count

    def get_running_instances(self) -> Dict[str, Any]:
        """
        Get information about all running VDS instances.

        Returns:
            Dictionary mapping instance keys to VDS info
        """
        with self.lock:
            running = {}
            for instance_key, vds in self.vds_instances.items():
                if vds.running:
                    host, port = instance_key
                    # Find the corresponding registry entry
                    db_id = None
                    vds_id = None
                    for db in database_registry.list_databases():
                        for vds_info in db.get("vds_instances", []):
                            if vds_info.get("host") == host and vds_info.get("port") == port:
                                db_id = db["id"]
                                vds_id = vds_info["id"]
                                break
                        if db_id:
                            break

                    running[f"{host}:{port}"] = {
                        "db_id": db_id,
                        "vds_id": vds_id,
                        "host": vds.host,
                        "port": vds.port,
                        "protocol": vds.target_protocol,
                        "active_connections": len(vds.active_connections),
                        "instance_type": "VDSInstance"
                    }
            return running

    def get_vds_instance_by_host_port(self, host: str, port: int) -> Optional[VDSInstance]:
        """
        Get a VDS instance directly by host and port.

        Args:
            host: Host address
            port: Port number

        Returns:
            VDSInstance if found, None otherwise
        """
        instance_key = (host, port)
        return self.vds_instances.get(instance_key)

    def is_host_port_available(self, host: str, port: int) -> bool:
        """
        Check if a host/port combination is available for a new VDS instance.

        Args:
            host: Host address
            port: Port number

        Returns:
            True if available, False if already in use
        """
        instance_key = (host, port)
        return instance_key not in self.vds_instances

    def get_vds_instances_count(self) -> int:
        """
        Get the total number of VDS instances (running or not).

        Returns:
            Number of VDS instances
        """
        return len(self.vds_instances)

    def get_running_vds_count(self) -> int:
        """
        Get the number of currently running VDS instances.

        Returns:
            Number of running VDS instances
        """
        return sum(1 for vds in self.vds_instances.values() if vds.running)

    def get_vds_uptime(self, db_id: str, vds_id: str) -> Optional[Dict[str, Any]]:
        """
        Get uptime information for a VDS instance.
        
        Args:
            db_id: Database ID
            vds_id: VDS instance ID
            
        Returns:
            Dictionary with uptime information or None if not found
        """
        try:
            from datetime import datetime, timezone, timedelta
            
            # Get VDS instance info from registry
            vds_info = database_registry.get_vds_instance(db_id, vds_id)
            if not vds_info:
                return None
            
            # Check if VDS is currently running
            instance_key = (vds_info["host"], vds_info["port"])
            is_running = instance_key in self.vds_instances and self.vds_instances[instance_key].running
            
            if not is_running:
                return {
                    "status": "stopped",
                    "uptime_seconds": 0,
                    "uptime_formatted": "0h 0m 0s",
                    "last_started": vds_info.get("last_started"),
                    "last_stopped": vds_info.get("last_stopped")
                }
            
            # Calculate uptime from last_started
            last_started_str = vds_info.get("last_started")
            if not last_started_str:
                return {
                    "status": "running",
                    "uptime_seconds": 0,
                    "uptime_formatted": "0h 0m 0s",
                    "last_started": None,
                    "last_stopped": vds_info.get("last_stopped")
                }
            
            # Parse the timestamp (it's in IST format)
            last_started = datetime.fromisoformat(last_started_str)
            
            # Get current IST time
            IST = timezone(timedelta(hours=5, minutes=30))
            now = datetime.now(IST)
            
            # Calculate uptime
            uptime_delta = now - last_started
            uptime_seconds = int(uptime_delta.total_seconds())
            
            # Format uptime
            days = uptime_seconds // 86400
            hours = (uptime_seconds % 86400) // 3600
            minutes = (uptime_seconds % 3600) // 60
            seconds = uptime_seconds % 60
            
            if days > 0:
                uptime_formatted = f"{days}d {hours}h {minutes}m"
            elif hours > 0:
                uptime_formatted = f"{hours}h {minutes}m {seconds}s"
            else:
                uptime_formatted = f"{minutes}m {seconds}s"
            
            return {
                "status": "running",
                "uptime_seconds": uptime_seconds,
                "uptime_formatted": uptime_formatted,
                "uptime_days": days,
                "uptime_hours": hours,
                "uptime_minutes": minutes,
                "uptime_seconds_remaining": seconds,
                "last_started": last_started_str,
                "last_stopped": vds_info.get("last_stopped")
            }
            
        except Exception as e:
            logger.error(f"Failed to get VDS uptime: {e}")
            return None

    def list_vds_instances(self, db_id: str) -> list:
        """
        List all VDS instances for a specific database.
        
        Args:
            db_id: Database ID
            
        Returns:
            List of VDS instance dictionaries
        """
        try:
            database = database_registry.get_database(db_id)
            if not database:
                return []
            
            return database.get("vds_instances", [])
        except Exception as e:
            logger.error(f"Failed to list VDS instances for db {db_id}: {e}")
            return []

    def remove_vds_instance(self, db_id: str, vds_id: str) -> bool:
        """
        Remove a VDS instance (stops it first if running).

        Args:
            db_id: Database ID
            vds_id: VDS instance ID

        Returns:
            True if successful, False otherwise
        """
        try:
            # Stop VDS if running
            if self.is_vds_running(db_id, vds_id):
                self.stop_vds(db_id, vds_id)

            # Get instance info to remove from our instances dict
            vds_info = database_registry.get_vds_instance(db_id, vds_id)
            if vds_info:
                instance_key = (vds_info["host"], vds_info["port"])
                if instance_key in self.vds_instances:
                    del self.vds_instances[instance_key]

            # Remove from registry
            return database_registry.remove_vds_instance(db_id, vds_id)

        except Exception as e:
            logger.error(f"Failed to remove VDS instance: {e}")
            return False

    def _repair_hashed_passwords(self, db_url: str, mappings_file: Path, mappings_data: Dict[str, Any]) -> bool:
        """
        Check for and repair likely hashed password columns that are wrongly encrypted.
        Returns True if repairs were made.
        """
        try:
            repaired = False
            table_mappings = mappings_data.get("table_mappings", {})
            
            for table_name, table_info in table_mappings.items():
                encrypted_cols = table_info.get("encrypted_columns", {})
                
                # Identify password columns that are encrypted
                cols_to_fix = []
                for col_name, col_data in encrypted_cols.items():
                    # Check for "password", "pwd", "hash" in column name
                    if any(s in col_name.lower() for s in ['password', 'pwd', '_hash']):
                        cols_to_fix.append(col_name)
                
                if not cols_to_fix:
                    continue
                    
                logger.info(f"Auto-repair: Found potential hashed password columns in '{table_name}': {cols_to_fix}")
                
                # Connect to DB
                engine_url = db_url
                if engine_url.startswith('mysql://'):
                    engine_url = engine_url.replace('mysql://', 'mysql+pymysql://', 1)
                
                try:
                    engine = create_engine(engine_url)
                    inspector = inspect(engine)
                    constraints = inspector.get_pk_constraint(table_name)
                    pk_columns = constraints.get('constrained_columns', []) if constraints else []
                    
                    if not pk_columns:
                        # Try to blindly guess id? No, safer to skip
                        logger.warning(f"Skipping table '{table_name}' - no PK found.")
                        continue
                    pk_col = pk_columns[0]
                    
                    with engine.connect() as conn:
                        for col_name in cols_to_fix:
                            col_info = encrypted_cols[col_name]
                            encrypted_col_name = col_info.get("encrypted_name", col_name)
                            
                            # Decrypt data
                            select_query = text(f"SELECT {pk_col}, {encrypted_col_name} FROM {table_name}")
                            rows = conn.execute(select_query).fetchall()
                            
                            updated_count = 0
                            for row in rows:
                                row_pk = row[0]
                                enc_val = row[1]
                                if enc_val:
                                    try:
                                        # Attempt decryption
                                        decrypted_val = clwe_encryptor.decrypt_value(enc_val, settings.CRYPTOPIX_DEFAULT_PASSWORD)
                                        # Update back
                                        update_stmt = text(f"UPDATE {table_name} SET {encrypted_col_name} = :val WHERE {pk_col} = :pk")
                                        conn.execute(update_stmt, {"val": decrypted_val, "pk": row_pk})
                                        updated_count += 1
                                    except Exception as e:
                                        pass # Failed to decrypt, might already be plaintext
                                        
                            conn.commit()
                            logger.info(f"Repaired {updated_count} rows for column '{col_name}' in '{table_name}'")
                            
                            # Update Mapping
                            # Mark key for deletion (using separate list to avoid runtime error)
                            
                            # Add to non_encrypted_columns
                            non_enc = table_info.get("non_encrypted_columns", [])
                            if encrypted_col_name not in non_enc:
                                non_enc.append(encrypted_col_name)
                            table_info["non_encrypted_columns"] = non_enc
                            
                            repaired = True
                        
                        # Clean up encrypted_cols dict after iteration
                        for col in cols_to_fix:
                             if col in encrypted_cols:
                                 del encrypted_cols[col]

                except Exception as e:
                    logger.error(f"Error during DB repair for table {table_name}: {e}")
            
            if repaired:
                # Save updated mappings
                with open(mappings_file, 'w') as f:
                    json.dump(mappings_data, f, indent=4)
                logger.info("Updated mappings.json with password repairs.")
                
            return repaired
            
        except Exception as e:
            logger.error(f"Auto-repair failed: {e}")
            return False


# Global VDS manager instance
vds_manager = VDSManager()
