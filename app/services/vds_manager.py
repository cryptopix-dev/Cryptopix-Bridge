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

logger = logging.getLogger(__name__)


class VDSManager:
    """
    Manages multiple independent VDS instances keyed by (host, port).
    Each instance owns its own socket, console_service, threads, DB connection, and running flag.
    Provides thread-safe operations for starting, stopping, and monitoring VDS instances.
    """

    def __init__(self):
        """Initialize the VDS manager"""
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
                instance_key = (host, port)
                if instance_key in self.vds_instances:
                    logger.error(f"VDS instance already exists for {host}:{port}")
                    return None

                database = database_registry.get_database(db_id)
                if not database:
                    logger.error(f"Database {db_id} not found")
                    return None

                if database_registry.is_port_in_use(port):
                    logger.error(f"Port {port} is already in use")
                    return None

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
                vds_info = database_registry.get_vds_instance(db_id, vds_id)
                if not vds_info:
                    logger.error(
                        f"VDS instance {vds_id} not found in database {db_id}")
                    return False, "VDS instance not found"

                instance_key = (vds_info["host"], vds_info["port"])
                if instance_key in self.vds_instances:
                    if self.vds_instances[instance_key].running:
                        logger.warning(
                            f"VDS instance {vds_id} is already running on {vds_info['host']}:{vds_info['port']}")
                        return True, "VDS is already running"

                if database_registry.is_port_in_use(vds_info["port"], exclude_vds_id=vds_id):
                    return False, f"Port {vds_info['port']} is already configured for another VDS instance"

                database = database_registry.get_database(db_id)
                if not database:
                    logger.error(f"Database {db_id} not found")
                    return False, "Database definition not found"

                schema_folder = Path(database["schema_folder"])
                mappings_file = schema_folder / "mappings.json"
                migration_state_file = schema_folder / "migration_state.json"

                table_mappings = {}
                migration_state = None

                if mappings_file.exists():
                    import json
                    with open(mappings_file, 'r') as f:
                        mappings_data = json.load(f)
                        table_mappings = mappings_data.get(
                            "table_mappings", {})

                if migration_state_file.exists():
                    import json
                    with open(migration_state_file, 'r') as f:
                        migration_state = json.load(f)

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

                self.vds_instances[instance_key] = vds

                database_registry.update_vds_status(db_id, vds_id, "running")

                logger.info(
                    f"Started independent VDS instance {vds_id} for database {db_id} on {vds_info['host']}:{vds_info['port']}")
                logger.info(f"Instance owns dedicated resources: socket, console_service, threads, DB connection")
                return True, f"VDS started on {vds_info['host']}:{vds_info['port']}"

            except Exception as e:
                logger.error(f"Failed to start VDS instance: {e}")
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
                vds_info = database_registry.get_vds_instance(db_id, vds_id)
                if not vds_info:
                    logger.warning(f"VDS instance {vds_id} not found in registry")
                    return False

                instance_key = (vds_info["host"], vds_info["port"])

                if instance_key not in self.vds_instances:
                    logger.warning(f"VDS instance {vds_id} is not running (no instance found for {instance_key})")
                    database_registry.update_vds_status(
                        db_id, vds_id, "stopped")
                    return True

                vds = self.vds_instances[instance_key]
                vds.stop(timeout=5.0)  # Use timeout for proper shutdown

                del self.vds_instances[instance_key]

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
                    host, port = instance_key
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
            if self.is_vds_running(db_id, vds_id):
                self.stop_vds(db_id, vds_id)

            vds_info = database_registry.get_vds_instance(db_id, vds_id)
            if vds_info:
                instance_key = (vds_info["host"], vds_info["port"])
                if instance_key in self.vds_instances:
                    del self.vds_instances[instance_key]

            return database_registry.remove_vds_instance(db_id, vds_id)

        except Exception as e:
            logger.error(f"Failed to remove VDS instance: {e}")
            return False


vds_manager = VDSManager()
