"""
Helper functions for multi-database support
"""

from pathlib import Path
import json
import logging

logger = logging.getLogger(__name__)


def load_migration_state_for_database(db_id: str) -> dict:
    """
    Load migration state for a specific database by ID.
    
    Args:
        db_id: Database ID
        
    Returns:
        Dictionary containing migration state
    """
    try:
        from app.services.database_registry import database_registry
        
        database = database_registry.get_database(db_id)
        if not database:
            logger.warning(f"Database {db_id} not found in registry")
            return {}
        
        schema_folder = Path(database["schema_folder"])
        state_file = schema_folder / "migration_state.json"
        
        if not state_file.exists():
            logger.warning(f"Migration state file not found for database {db_id} at {state_file}")
            return {}
        
        with open(state_file, 'r') as f:
            state_data = json.load(f)
        
        logger.info(f"Loaded migration state for database {db_id}")
        return state_data
        
    except Exception as e:
        logger.error(f"Failed to load migration state for database {db_id}: {e}")
        return {}


def get_all_databases_with_states() -> list:
    """
    Get all databases with their migration states.
    
    Returns:
        List of dictionaries containing database info and migration state
    """
    try:
        from app.services.database_registry import database_registry
        
        databases = database_registry.list_databases()
        result = []
        
        for db in databases:
            db_with_state = db.copy()
            migration_state = load_migration_state_for_database(db["id"])
            db_with_state["migration_state"] = migration_state
            result.append(db_with_state)
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to get databases with states: {e}")
        return []
