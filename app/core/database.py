"""
CryptoPIX Bridge v3.0 - Database Session Management
Provides SQLAlchemy session management for encrypted and source databases
"""

from contextlib import contextmanager
from typing import Any, Generator
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import QueuePool
import os

from app.config import settings

_engines = {}
_session_factories = {}

def _get_database_url(db_type: str = "encrypted") -> str:
    """Get database URL for the specified type"""
    if db_type == "encrypted":
        try:
            from pathlib import Path
            import json

            schemas_dir = Path("schemas")
            if schemas_dir.exists():
                state_files = list(schemas_dir.glob("*_migration_state.json"))
                if state_files:
                    completed_states = []
                    for state_file in state_files:
                        try:
                            with open(state_file, 'r') as f:
                                state_data = json.load(f)
                                if state_data.get('migration_complete', False):
                                    completed_states.append((state_file, state_data))
                        except Exception:
                            continue

                    if completed_states:
                        latest_state_file, migration_state = max(completed_states, key=lambda x: x[0].stat().st_mtime)
                        encrypted_url = migration_state.get('encrypted_db_url')
                        if encrypted_url:
                            print(f"Using encrypted DB URL from migration state: {encrypted_url}")
                            if encrypted_url.startswith('mysql://'):
                                encrypted_url = encrypted_url.replace('mysql://', 'mysql+pymysql://', 1)
                            return encrypted_url

                    state_files = list(schemas_dir.glob("*_migration_state.json"))
                    if state_files:
                        latest_state = max(state_files, key=lambda f: f.stat().st_mtime)
                        with open(latest_state, 'r') as f:
                            state_data = json.load(f)
                            encrypted_url = state_data.get('encrypted_db_url')
                            if encrypted_url:
                                print(f"Using encrypted DB URL from latest migration state: {encrypted_url}")
                                if encrypted_url.startswith('mysql://'):
                                    encrypted_url = encrypted_url.replace('mysql://', 'mysql+pymysql://', 1)
                                return encrypted_url
        except Exception as e:
            print(f"Failed to load encrypted DB URL from migration state: {e}")

        encrypted_url = settings.ENCRYPTED_DB_URL
        print(f"Using encrypted DB URL from settings: {encrypted_url}")
        if encrypted_url.startswith('mysql://'):
            encrypted_url = encrypted_url.replace('mysql://', 'mysql+pymysql://', 1)
        return encrypted_url
    elif db_type == "source":
        try:
            from pathlib import Path
            import json

            schemas_dir = Path("schemas")
            if schemas_dir.exists():
                state_files = list(schemas_dir.glob("*_migration_state.json"))
                if state_files:
                    latest_state = max(state_files, key=lambda f: f.stat().st_mtime)
                    with open(latest_state, 'r') as f:
                        state_data = json.load(f)
                        source_url = state_data.get('source_db_url')
                        if source_url:
                            if source_url.startswith('mysql://'):
                                source_url = source_url.replace('mysql://', 'mysql+pymysql://', 1)
                            return source_url
        except Exception:
            pass  # Fall back to settings

        source_url = settings.SOURCE_DB_URL
        if source_url.startswith('mysql://'):
            source_url = source_url.replace('mysql://', 'mysql+pymysql://', 1)
        return source_url
    else:
        raise ValueError(f"Unknown database type: {db_type}")

def _get_engine(db_type: str = "encrypted"):
    """Get or create SQLAlchemy engine for the specified database type"""
    if db_type not in _engines:
        db_url = _get_database_url(db_type)
        _engines[db_type] = create_engine(
            db_url,
            poolclass=QueuePool,
            pool_size=10,
            max_overflow=20,
            pool_pre_ping=True,
            echo=False  # Set to True for debugging
        )
    return _engines[db_type]

def _get_session_factory(db_type: str = "encrypted"):
    """Get or create session factory for the specified database type"""
    if db_type not in _session_factories:
        engine = _get_engine(db_type)
        _session_factories[db_type] = sessionmaker(bind=engine)
    return _session_factories[db_type]

@contextmanager
def get_db_session(db_type: str = "encrypted") -> Generator[Session, None, None]:
    """
    Get SQLAlchemy session context manager

    Args:
        db_type: "encrypted" or "source"

    Returns:
        Context manager yielding SQLAlchemy session
    """
    session_factory = _get_session_factory(db_type)
    session = session_factory()
    try:
        yield session
    finally:
        session.close()

def execute_query(db_type: str, query: str, params: dict = None) -> Any:
    """
    Execute a raw SQL query

    Args:
        db_type: "encrypted" or "source"
        query: SQL query string
        params: Query parameters

    Returns:
        Query result
    """
    with get_db_session(db_type) as session:
        result = session.execute(text(query), params or {})
        session.commit()
        return result

def test_connection(db_type: str = "encrypted") -> bool:
    """Test database connection"""
    try:
        with get_db_session(db_type) as session:
            session.execute(text("SELECT 1"))
        return True
    except Exception as e:
        print(f"Database connection test failed for {db_type}: {e}")
        return False