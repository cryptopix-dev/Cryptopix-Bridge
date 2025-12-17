"""
Database Registry Service
Manages multiple database migrations and their configurations
"""

import json
import threading
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging
import uuid

logger = logging.getLogger(__name__)


class DatabaseRegistry:
    """
    Manages the registry of all migrated databases.
    Provides thread-safe operations for registering, updating, and querying databases.
    """

    def __init__(self, registry_file: str = "schemas/databases.json"):
        """
        Initialize the database registry.
        
        Args:
            registry_file: Path to the registry JSON file
        """
        self.registry_file = Path(registry_file)
        self.lock = threading.Lock()
        self._ensure_registry_exists()

    def _ensure_registry_exists(self):
        """Ensure the registry file and schemas directory exist"""
        try:
            self.registry_file.parent.mkdir(parents=True, exist_ok=True)
            
            if not self.registry_file.exists():
                self._write_registry({"databases": [], "version": "1.0"})
                logger.info(f"Created new database registry at {self.registry_file}")
            else:
                logger.info(f"Using existing database registry at {self.registry_file}")
        except Exception as e:
            logger.error(f"Failed to ensure registry exists: {e}")
            raise

    def _read_registry(self) -> Dict[str, Any]:
        """Read the registry file (thread-safe)"""
        try:
            with open(self.registry_file, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Registry file corrupted: {e}. Creating new registry.")
            return {"databases": [], "version": "1.0"}
        except Exception as e:
            logger.error(f"Failed to read registry: {e}")
            return {"databases": [], "version": "1.0"}

    def _write_registry(self, data: Dict[str, Any]):
        """Write to the registry file (thread-safe)"""
        try:
            with open(self.registry_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to write registry: {e}")
            raise

    def register_database(self, 
                         name: str,
                         source_db_url: str,
                         encrypted_db_url: str,
                         schema_folder: str = None,
                         db_id: str = None) -> Dict[str, Any]:
        """
        Register a new database in the registry.
        
        Args:
            name: Human-readable database name
            source_db_url: Source database URL
            encrypted_db_url: Encrypted database URL
            schema_folder: Path to schema folder (auto-generated if not provided)
            db_id: Database ID (auto-generated if not provided)
            
        Returns:
            Dictionary containing the registered database information
        """
        with self.lock:
            try:
                registry = self._read_registry()
                
                if not db_id:
                    db_id = f"db_{uuid.uuid4().hex[:8]}"
                
                if not schema_folder:
                    import re
                    safe_name = re.sub(r'[<>:"/\\|?*]', '_', name.lower().replace(' ', '_'))
                    schema_folder = f"schemas/{safe_name}"
                
                for db in registry["databases"]:
                    if db["id"] == db_id:
                        logger.warning(f"Database with ID {db_id} already exists")
                        return db
                    if db["name"] == name:
                        logger.warning(f"Database with name '{name}' already exists")
                        return db
                
                database = {
                    "id": db_id,
                    "name": name,
                    "source_db_url": source_db_url,
                    "encrypted_db_url": encrypted_db_url,
                    "schema_folder": schema_folder,
                    "created_at": datetime.utcnow().isoformat(),
                    "updated_at": datetime.utcnow().isoformat(),
                    "migration_complete": False,
                    "vds_instances": []
                }
                
                registry["databases"].append(database)
                self._write_registry(registry)
                
                Path(schema_folder).mkdir(parents=True, exist_ok=True)
                
                logger.info(f"Registered database '{name}' with ID {db_id}")
                return database
                
            except Exception as e:
                logger.error(f"Failed to register database: {e}")
                raise

    def get_database(self, db_id: str) -> Optional[Dict[str, Any]]:
        """
        Get database information by ID.
        
        Args:
            db_id: Database ID
            
        Returns:
            Database dictionary or None if not found
        """
        with self.lock:
            registry = self._read_registry()
            for db in registry["databases"]:
                if db["id"] == db_id:
                    return db
            return None

    def get_database_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Get database information by name.
        
        Args:
            name: Database name
            
        Returns:
            Database dictionary or None if not found
        """
        with self.lock:
            registry = self._read_registry()
            for db in registry["databases"]:
                if db["name"] == name:
                    return db
            return None

    def list_databases(self) -> List[Dict[str, Any]]:
        """
        List all registered databases.
        
        Returns:
            List of database dictionaries
        """
        with self.lock:
            registry = self._read_registry()
            return registry["databases"]

    def update_database(self, db_id: str, updates: Dict[str, Any]) -> bool:
        """
        Update database information.
        
        Args:
            db_id: Database ID
            updates: Dictionary of fields to update
            
        Returns:
            True if successful, False otherwise
        """
        with self.lock:
            try:
                registry = self._read_registry()
                
                for i, db in enumerate(registry["databases"]):
                    if db["id"] == db_id:
                        for key, value in updates.items():
                            if key != "id":  # Don't allow ID changes
                                db[key] = value
                        
                        db["updated_at"] = datetime.utcnow().isoformat()
                        
                        registry["databases"][i] = db
                        self._write_registry(registry)
                        
                        logger.info(f"Updated database {db_id}")
                        return True
                
                logger.warning(f"Database {db_id} not found for update")
                return False
                
            except Exception as e:
                logger.error(f"Failed to update database: {e}")
                return False

    def delete_database(self, db_id: str, delete_files: bool = False) -> bool:
        """
        Delete a database from the registry.
        
        Args:
            db_id: Database ID
            delete_files: If True, also delete schema files
            
        Returns:
            True if successful, False otherwise
        """
        with self.lock:
            try:
                registry = self._read_registry()
                
                for i, db in enumerate(registry["databases"]):
                    if db["id"] == db_id:
                        if delete_files:
                            schema_path = Path(db["schema_folder"])
                            if schema_path.exists():
                                import shutil
                                shutil.rmtree(schema_path)
                                logger.info(f"Deleted schema folder: {schema_path}")
                        
                        registry["databases"].pop(i)
                        self._write_registry(registry)
                        
                        logger.info(f"Deleted database {db_id}")
                        return True
                
                logger.warning(f"Database {db_id} not found for deletion")
                return False
                
            except Exception as e:
                logger.error(f"Failed to delete database: {e}")
                return False

    def add_vds_instance(self, db_id: str, host: str, port: int, protocol: str = "mysql") -> Optional[Dict[str, Any]]:
        """
        Add a VDS instance to a database.
        
        Args:
            db_id: Database ID
            host: VDS host
            port: VDS port
            protocol: Database protocol (mysql, postgresql, etc.)
            
        Returns:
            VDS instance dictionary or None if failed
        """
        with self.lock:
            try:
                if self.is_port_in_use(port):
                    logger.error(f"Port {port} is already in use by another VDS instance")
                    return None
                
                registry = self._read_registry()
                
                for db in registry["databases"]:
                    if db["id"] == db_id:
                        vds_id = f"vds_{uuid.uuid4().hex[:8]}"
                        
                        vds_instance = {
                            "id": vds_id,
                            "host": host,
                            "port": port,
                            "protocol": protocol,
                            "status": "stopped",
                            "created_at": datetime.utcnow().isoformat(),
                            "last_started": None,
                            "last_stopped": None
                        }
                        
                        db["vds_instances"].append(vds_instance)
                        db["updated_at"] = datetime.utcnow().isoformat()
                        
                        self._write_registry(registry)
                        
                        logger.info(f"Added VDS instance {vds_id} to database {db_id}")
                        return vds_instance
                
                logger.warning(f"Database {db_id} not found")
                return None
                
            except Exception as e:
                logger.error(f"Failed to add VDS instance: {e}")
                return None

    def update_vds_status(self, db_id: str, vds_id: str, status: str) -> bool:
        """
        Update VDS instance status.
        
        Args:
            db_id: Database ID
            vds_id: VDS instance ID
            status: New status (running, stopped, error)
            
        Returns:
            True if successful, False otherwise
        """
        with self.lock:
            try:
                registry = self._read_registry()
                
                for db in registry["databases"]:
                    if db["id"] == db_id:
                        for vds in db["vds_instances"]:
                            if vds["id"] == vds_id:
                                vds["status"] = status
                                
                                if status == "running":
                                    vds["last_started"] = datetime.utcnow().isoformat()
                                elif status == "stopped":
                                    vds["last_stopped"] = datetime.utcnow().isoformat()
                                
                                db["updated_at"] = datetime.utcnow().isoformat()
                                self._write_registry(registry)
                                
                                logger.info(f"Updated VDS {vds_id} status to {status}")
                                return True
                
                logger.warning(f"VDS instance {vds_id} not found in database {db_id}")
                return False
                
            except Exception as e:
                logger.error(f"Failed to update VDS status: {e}")
                return False

    def remove_vds_instance(self, db_id: str, vds_id: str) -> bool:
        """
        Remove a VDS instance from a database.
        
        Args:
            db_id: Database ID
            vds_id: VDS instance ID
            
        Returns:
            True if successful, False otherwise
        """
        with self.lock:
            try:
                registry = self._read_registry()
                
                for db in registry["databases"]:
                    if db["id"] == db_id:
                        for i, vds in enumerate(db["vds_instances"]):
                            if vds["id"] == vds_id:
                                db["vds_instances"].pop(i)
                                db["updated_at"] = datetime.utcnow().isoformat()
                                self._write_registry(registry)
                                
                                logger.info(f"Removed VDS instance {vds_id} from database {db_id}")
                                return True
                
                logger.warning(f"VDS instance {vds_id} not found in database {db_id}")
                return False
                
            except Exception as e:
                logger.error(f"Failed to remove VDS instance: {e}")
                return False

    def get_vds_instance(self, db_id: str, vds_id: str) -> Optional[Dict[str, Any]]:
        """
        Get VDS instance information.
        
        Args:
            db_id: Database ID
            vds_id: VDS instance ID
            
        Returns:
            VDS instance dictionary or None if not found
        """
        with self.lock:
            registry = self._read_registry()
            
            for db in registry["databases"]:
                if db["id"] == db_id:
                    for vds in db["vds_instances"]:
                        if vds["id"] == vds_id:
                            return vds
            
            return None

    def is_port_in_use(self, port: int, exclude_vds_id: str = None) -> bool:
        """
        Check if a port is already in use by any VDS instance.
        
        Args:
            port: Port number to check
            exclude_vds_id: VDS ID to exclude from check (optional)
            
        Returns:
            True if port is in use, False otherwise
        """
        registry = self._read_registry()
        
        for db in registry["databases"]:
            for vds in db["vds_instances"]:
                if vds["port"] == port:
                    if exclude_vds_id and vds["id"] == exclude_vds_id:
                        continue
                    return True
        
        return False

    def migrate_legacy_database(self) -> bool:
        """
        Migrate existing single database setup to multi-database registry.
        Checks for old schema files and creates a database entry.
        
        Returns:
            True if migration was performed, False otherwise
        """
        with self.lock:
            try:
                registry = self._read_registry()
                if len(registry["databases"]) > 0:
                    logger.info("Databases already registered, skipping legacy migration")
                    return False
                
                schemas_dir = Path("schemas")
                if not schemas_dir.exists():
                    return False
                
                state_files = list(schemas_dir.glob("*_migration_state.json"))
                
                if not state_files:
                    logger.info("No legacy migration state files found")
                    return False
                
                latest_state_file = max(state_files, key=lambda f: f.stat().st_mtime)
                
                with open(latest_state_file, 'r') as f:
                    migration_state = json.load(f)
                
                db_name = latest_state_file.stem.replace('_migration_state', '')
                
                database = self.register_database(
                    name=db_name,
                    source_db_url=migration_state.get("source_db_url", ""),
                    encrypted_db_url=migration_state.get("encrypted_db_url", ""),
                    schema_folder=f"schemas/{db_name}"
                )
                
                if migration_state.get("migration_complete"):
                    self.update_database(database["id"], {"migration_complete": True})
                
                logger.info(f"Migrated legacy database '{db_name}' to new registry")
                return True
                
            except Exception as e:
                logger.error(f"Failed to migrate legacy database: {e}")
                return False


database_registry = DatabaseRegistry()
