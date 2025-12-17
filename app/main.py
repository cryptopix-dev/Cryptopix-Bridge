"""
CryptoPIX Bridge v3.0 - Main Application
Streamlined web application for database encryption workflow
"""

from flask import Flask, render_template, request, redirect, url_for, flash, session
import os
import sqlite3
from typing import List, Dict, Any, Set
import json
import requests
from functools import wraps
import threading
import time

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    psutil = None

from sqlalchemy import create_engine, text, inspect
from sqlalchemy.engine import Engine

from app.config import settings
from app.services.console_service import console_service
from app.middleware.sql_interceptor import sql_interceptor
from app.core.encryption import clwe_encryptor
from app.services.database_registry import database_registry
from app.services.vds_manager import vds_manager
import logging
import datetime
logger = logging.getLogger(__name__)

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Configure Flask app with correct template folder
app = Flask(__name__, template_folder='../templates',
            static_folder='../static')
app.secret_key = settings.SECRET_KEY

# Increase max content length to handle large database schemas (100MB)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB

# Migration state will be loaded from files as needed


def load_migration_state_from_files(encrypted_db_url: str = None, db_id: str = None) -> dict:
    """Load migration state from schema and mapping files, or migration state files"""
    try:
        import os
        from pathlib import Path
        import json

        schemas_dir = Path("schemas")
        if not schemas_dir.exists():
            return {}

        migration_state = {
            "source_db_url": None,
            "encrypted_db_url": None,  # Start with None, will be updated from files
            "selected_db_type": None,
            "selected_tables": [],
            "table_configs": {},
            "migration_complete": False
        }

        # If encrypted_db_url parameter is provided and not None, use it
        if encrypted_db_url is not None:
            migration_state["encrypted_db_url"] = encrypted_db_url

        # NEW: Try to load from database-specific folder first
        state_file = None
        if db_id:
            # Load specific database by ID
            from app.services.database_registry import database_registry
            database = database_registry.get_database(db_id)
            if database:
                # Update schemas_dir to specific folder
                if database.get("schema_folder"):
                    schemas_dir = Path(database["schema_folder"])
                
                state_file = schemas_dir / "migration_state.json"
                
                # Pre-populate URLs from registry as reliable fallback
                if database.get("encrypted_db_url"):
                    migration_state["encrypted_db_url"] = database["encrypted_db_url"]
                if database.get("source_db_url"):
                    migration_state["source_db_url"] = database["source_db_url"]
        else:
            # Find the most recent database folder
            db_folders = [d for d in schemas_dir.iterdir(
            ) if d.is_dir() and d.name != "__pycache__"]
            if db_folders:
                # Get the most recently modified folder
                latest_folder = max(
                    db_folders, key=lambda f: f.stat().st_mtime)
                state_file = latest_folder / "migration_state.json"

        # Load from database-specific folder
        if state_file and state_file.exists():
            try:
                logger.info(f"Loading migration state from: {state_file}")
                with open(state_file, 'r') as f:
                    state_data = json.load(f)
                migration_state.update(state_data)
                logger.info(
                    f"Loaded migration state successfully: source_url exists={bool(migration_state.get('source_db_url'))}")
                return migration_state
            except json.JSONDecodeError as e:
                logger.warning(
                    f"Corrupted migration state file {state_file}: {e}")

        # First try to find the standardized mappings file (post-migration)
        mappings_file = schemas_dir / "mappings.json"
        if mappings_file.exists():
            with open(mappings_file, 'r') as f:
                mapping_data = json.load(f)

            migration_state["source_db_url"] = mapping_data.get("database_url")
            migration_state["table_configs"] = mapping_data.get(
                "table_mappings", {})
            migration_state["selected_tables"] = list(
                migration_state["table_configs"].keys())

            # Determine database type from URL
            if migration_state["source_db_url"]:
                if "mysql" in migration_state["source_db_url"].lower():
                    migration_state["selected_db_type"] = "mysql"
                elif "postgresql" in migration_state["source_db_url"].lower():
                    migration_state["selected_db_type"] = "postgresql"
                elif "sqlite" in migration_state["source_db_url"].lower():
                    migration_state["selected_db_type"] = "sqlite"
                elif "mssql" in migration_state["source_db_url"].lower():
                    migration_state["selected_db_type"] = "mssql"

            # Try to get encrypted_db_url from migration state files since mappings.json doesn't contain it
            state_files = list(schemas_dir.glob("*_migration_state.json"))
            if state_files:
                # Load the most recent migration state file
                latest_state = max(
                    state_files, key=lambda f: f.stat().st_mtime)

                try:
                    logger.info(
                        f"Loading migration state from: {latest_state}")
                    with open(latest_state, 'r') as f:
                        state_data = json.load(f)

                    # Update with all fields from migration state
                    migration_state.update(state_data)

                except json.JSONDecodeError as e:
                    logger.warning(
                        f"Corrupted migration state file {latest_state}: {e}. Ignoring.")
        else:
            # No mappings file found, try to load from migration state files (during setup)
            state_files = list(schemas_dir.glob("*_migration_state.json"))
            if state_files:
                # Load the most recent migration state file
                latest_state = max(
                    state_files, key=lambda f: f.stat().st_mtime)

                try:
                    logger.info(
                        f"Loading migration state from: {latest_state}")
                    with open(latest_state, 'r') as f:
                        state_data = json.load(f)

                    # Copy all fields from the saved state
                    migration_state.update(state_data)
                except json.JSONDecodeError as e:
                    logger.warning(
                        f"Corrupted migration state file {latest_state}: {e}. Ignoring and using defaults.")
                    # File is corrupted, continue with defaults

        # Check if migration is complete by checking if encrypted database exists and has data
        if encrypted_db_url or migration_state.get("encrypted_db_url"):
            db_url = encrypted_db_url or migration_state.get(
                "encrypted_db_url")
            try:
                from sqlalchemy import create_engine
                engine = create_engine(db_url)
                with engine.connect() as conn:
                    # Check if any tables exist
                    from sqlalchemy.engine import reflection
                    inspector = reflection.Inspector.from_engine(engine)
                    tables = inspector.get_table_names()

                    # Also check if tables have the expected encrypted schema (tag columns)
                    migration_complete = len(tables) > 0
                    if migration_complete and migration_state.get("table_configs"):
                        # Verify that encrypted tables have tag columns
                        for table_name, config in migration_state["table_configs"].items():
                            if table_name in tables:
                                try:
                                    columns = inspector.get_columns(table_name)
                                    column_names = [col['name']
                                                    for col in columns]

                                    # Check if encrypted columns have corresponding tag columns
                                    for col_name, col_config in config.items():
                                        if col_config.get('type') == 'encrypt':
                                            tag_col = f"tag_{col_name}"
                                            if tag_col not in column_names:
                                                logger.warning(
                                                    f"Tag column {tag_col} missing from {table_name}, migration incomplete")
                                                migration_complete = False
                                                break
                                except Exception as e:
                                    logger.warning(
                                        f"Could not verify schema for {table_name}: {e}")
                                    migration_complete = False

                    migration_state["migration_complete"] = migration_complete
                engine.dispose()
            except:
                migration_state["migration_complete"] = False

        return migration_state

    except Exception as e:
        logger.error(f"Failed to load migration state from files: {e}")
        return {}


def save_migration_state_to_files(migration_state: dict, db_id: str = None):
    """Save migration state to files in database-specific folder"""
    try:
        import json
        from pathlib import Path

        # Extract database name from URL for filename
        db_name = "unknown"
        if migration_state.get("source_db_url"):
            if "sqlite" in migration_state["source_db_url"]:
                db_name = migration_state["source_db_url"].split(
                    "/")[-1].split(".")[0]
            elif "mysql" in migration_state["source_db_url"] or "postgresql" in migration_state["source_db_url"]:
                # Split by '/' and get the last part before any query parameters
                parts = migration_state["source_db_url"].split('/')
                for part in reversed(parts):
                    if part and '?' not in part:
                        db_name = part
                        break
                    elif '?' in part:
                        db_name = part.split('?')[0]
                        break

        # Sanitize db_name to remove invalid filename characters (Windows)
        import re as re_module
        db_name = re_module.sub(r'[<>:"/\\|?*]', '_', db_name)

        # Register or get database from registry
        existing_db = database_registry.get_database_by_name(db_name)
        if existing_db:
            db_id = existing_db["id"]
            schema_folder = existing_db["schema_folder"]
        else:
            # Register new database
            database = database_registry.register_database(
                name=db_name,
                source_db_url=migration_state.get("source_db_url", ""),
                encrypted_db_url=migration_state.get("encrypted_db_url", ""),
                db_id=db_id
            )
            db_id = database["id"]
            schema_folder = database["schema_folder"]

        # Create database-specific schema folder
        schemas_dir = Path(schema_folder)
        schemas_dir.mkdir(parents=True, exist_ok=True)

        # Create a serializable copy of the migration state
        serializable_state = {}
        for key, value in migration_state.items():
            if key == "table_configs":
                # Handle table_configs specially to convert SQLAlchemy types to strings
                serializable_configs = {}
                for table_name, table_config in value.items():
                    serializable_configs[table_name] = {}
                    for col_name, col_info in table_config.items():
                        serializable_configs[table_name][col_name] = {
                            "type": col_info.get("type"),
                            # Convert SQLAlchemy types to string
                            "data_type": str(col_info.get("data_type", "TEXT"))
                        }
                serializable_state[key] = serializable_configs
            else:
                serializable_state[key] = value

        # Add database ID to migration state
        serializable_state["db_id"] = db_id

        # Save migration state as JSON in database-specific folder
        state_file = schemas_dir / "migration_state.json"
        with open(state_file, 'w') as f:
            json.dump(serializable_state, f, indent=2)

        logger.info(
            f"Saved migration state to {state_file} for database {db_id}")

        # Return db_id for use in migration flow
        return db_id

    except Exception as e:
        logger.error(f"Failed to save migration state to files: {e}")
        return None


# Global system logs storage with memory management
system_logs = []
system_logs_lock = threading.Lock()
MAX_MEMORY_LOGS = 1000  # Maximum logs to keep in memory
LOG_RETENTION_DAYS = 30  # Days to keep logs in database

# Global migration progress tracking
migration_progress = {
    'status': 'idle',  # idle, running, completed, failed
    'progress': 0,     # 0-100
    'current_table': '',
    'total_tables': 0,
    'completed_tables': 0,
    'message': '',
    'error': None,
    'start_time': None,
    'end_time': None
}
migration_progress_lock = threading.Lock()


def init_system_logs_table():
    """Initialize system logs table in SQLite database"""
    try:
        conn = sqlite3.connect('system_logs.db')
        cursor = conn.cursor()

        # Create system_logs table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                level TEXT NOT NULL,
                message TEXT NOT NULL,
                source TEXT,
                user_id TEXT,
                session_id TEXT,
                ip_address TEXT,
                details TEXT
            )
        ''')

        # Create indexes for better performance
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS idx_timestamp ON system_logs(timestamp)')
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS idx_level ON system_logs(level)')
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS idx_source ON system_logs(source)')

        conn.commit()
        conn.close()
        logger.info("System logs table initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize system logs table: {e}")


def cleanup_old_logs():
    """Clean up old logs from database based on retention policy"""
    try:
        cutoff_date = (datetime.datetime.utcnow() -
                       datetime.timedelta(days=LOG_RETENTION_DAYS)).isoformat()

        conn = sqlite3.connect('system_logs.db')
        cursor = conn.cursor()

        # Count logs before cleanup
        cursor.execute(
            "SELECT COUNT(*) FROM system_logs WHERE timestamp < ?", (cutoff_date,))
        deleted_count = cursor.fetchone()[0]

        # Delete old logs
        cursor.execute(
            "DELETE FROM system_logs WHERE timestamp < ?", (cutoff_date,))
        conn.commit()
        conn.close()

        if deleted_count > 0:
            log_system_event(
                'INFO', f'Cleaned up {deleted_count} old logs older than {LOG_RETENTION_DAYS} days', source='system_maintenance')

    except Exception as e:
        logger.error(f"Failed to cleanup old logs: {e}")


def log_system_event(level, message, source="system", user_id=None, session_id=None, ip_address=None, details=None):
    """Log a system event to both memory and database with memory management"""
    from flask import has_request_context

    timestamp = datetime.datetime.utcnow().isoformat()

    # Handle request context safely
    if has_request_context():
        # We're inside a request context, safe to access session and request
        current_user_id = user_id or session.get('user_email', 'anonymous')
        current_session_id = session_id or session.get(
            'license_key', 'unknown')
        current_ip = ip_address or request.remote_addr
    else:
        # Outside of request context (background thread)
        current_user_id = user_id or 'system'
        current_session_id = session_id or 'background'
        current_ip = ip_address or None

    log_entry = {
        "id": len(system_logs) + 1,
        "timestamp": timestamp,
        "level": level.upper(),
        "message": message,
        "source": source,
        "user_id": current_user_id,
        "session_id": current_session_id,
        "ip_address": current_ip,
        "details": json.dumps(details) if details else None
    }

    # Add to memory with size management
    with system_logs_lock:
        system_logs.append(log_entry)
        if len(system_logs) > MAX_MEMORY_LOGS:
            system_logs.pop(0)

    # Save to database
    try:
        conn = sqlite3.connect('system_logs.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO system_logs (timestamp, level, message, source, user_id, session_id, ip_address, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            log_entry["timestamp"],
            log_entry["level"],
            log_entry["message"],
            log_entry["source"],
            log_entry["user_id"],
            log_entry["session_id"],
            log_entry["ip_address"],
            log_entry["details"]
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to save log to database: {e}")

    # Periodic cleanup (run cleanup every 1000 logs)
    if len(system_logs) % 1000 == 0:
        threading.Thread(target=cleanup_old_logs, daemon=True).start()


def start_system_monitor():
    """Background thread to monitor critical system conditions only"""
    def monitor_application():
        while True:
            try:
                # Only monitor for critical system conditions that require immediate attention
                if PSUTIL_AVAILABLE and psutil:
                    memory = psutil.virtual_memory()
                    memory_percent = memory.percent

                    cpu_percent = psutil.cpu_percent(interval=0.1)
                    disk = psutil.disk_usage('/')
                    disk_percent = disk.percent

                    # Only log CRITICAL errors when system resources are dangerously high
                    # These should be rare and indicate real problems
                    if memory_percent > 98:
                        log_system_event(
                            'ERROR', f'Critical memory usage: {memory_percent:.1f}% - System stability at risk', source='system_monitor')
                    elif memory_percent > 95:
                        log_system_event(
                            'WARNING', f'High memory usage: {memory_percent:.1f}% - Consider freeing resources', source='system_monitor')

                    if cpu_percent > 98:
                        log_system_event(
                            'ERROR', f'Critical CPU usage: {cpu_percent:.1f}% - System performance severely impacted', source='system_monitor')
                    elif cpu_percent > 95:
                        log_system_event(
                            'WARNING', f'High CPU usage: {cpu_percent:.1f}% - System may be slow', source='system_monitor')

                    if disk_percent > 99:
                        log_system_event(
                            'ERROR', f'Critical disk usage: {disk_percent:.1f}% - No disk space available', source='system_monitor')
                    elif disk_percent > 98:
                        log_system_event(
                            'WARNING', f'High disk usage: {disk_percent:.1f}% - Disk space critically low', source='system_monitor')

            except Exception as e:
                logger.error(f"Error in system monitor: {e}")

            # Check every 10 minutes (reduced frequency for critical monitoring only)
            time.sleep(600)

    thread = threading.Thread(target=monitor_application, daemon=True)
    thread.start()


# Initialize system logs when module is imported
init_system_logs_table()
start_system_monitor()

# Authentication decorator


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'license_token' not in session:
            return redirect(url_for('login'))

        # Validate token on each request
        if not validate_token_on_load():
            flash('Your session has expired. Please login again.')
            return redirect(url_for('login'))

        return f(*args, **kwargs)
    return decorated_function

# Authentication functions


def authenticate_user(email: str, license_key: str) -> dict:
    """Authenticate user with license server"""
    try:
        response = requests.post(
            f"{settings.LICENSE_SERVER_URL}/login",
            headers={'Content-Type': 'application/json'},
            json={
                'email': email,
                'license_key': license_key
            }
        )

        if response.status_code == 200:
            data = response.json()
            if 'token' in data:
                return {'success': True, 'token': data['token'], 'user': data.get('user', {})}
            else:
                return {'success': False, 'error': 'Invalid response from license server'}
        else:
            return {'success': False, 'error': f'Authentication failed: {response.status_code}'}

    except requests.RequestException as e:
        return {'success': False, 'error': f'Connection error: {str(e)}'}


def validate_license(license_key: str) -> dict:
    """Validate license with server"""
    try:
        response = requests.post(
            f"{settings.LICENSE_SERVER_URL}/validate",
            headers={'Content-Type': 'application/json'},
            json={'license_key': license_key}
        )

        if response.status_code == 200:
            data = response.json()
            return {'valid': data.get('valid', False), 'user': data.get('user', {})}
        else:
            return {'valid': False, 'error': f'Validation failed: {response.status_code}'}

    except requests.RequestException as e:
        return {'valid': False, 'error': f'Connection error: {str(e)}'}


def validate_token_on_load():
    """Validate stored token on app load"""
    if 'license_token' in session:
        try:
            token = session['license_token']
            response = requests.get(
                f"{settings.LICENSE_SERVER_URL}/me",
                headers={
                    'Authorization': f'Bearer {token}'
                }
            )

            if response.status_code == 200:
                user_data = response.json()
                session['user_info'] = user_data
                return True
            else:
                # Token invalid, clear session
                session.clear()
                return False

        except requests.RequestException:
            # Connection error, allow access but don't clear session
            return True
    return False


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        email = request.form.get('email')
        license_key = request.form.get('license_key')

        if not email or not license_key:
            flash('Please provide both email and license key')
            log_system_event('WARNING', 'Login attempt failed - missing credentials',
                             source='authentication', ip_address=request.remote_addr)
            return render_template('login.html')

        # Authenticate with license server
        auth_result = authenticate_user(email, license_key)

        if auth_result['success']:
            # Store token in session
            session['license_token'] = auth_result['token']
            session['user_email'] = email
            session['license_key'] = license_key
            session['user_info'] = auth_result.get('user', {})

            log_system_event('INFO', f'User {email} logged in successfully',
                             source='authentication', user_id=email, ip_address=request.remote_addr)
            flash('Login successful!')
            return redirect(url_for('index'))
        else:
            log_system_event(
                'WARNING', f'Login failed for {email}: {auth_result["error"]}', source='authentication', user_id=email, ip_address=request.remote_addr)
            flash(f'Login failed: {auth_result["error"]}')
            return render_template('login.html')

    # GET request - show login form
    return render_template('login.html')


@app.route('/logout')
def logout():
    """Logout user"""
    user_email = session.get('user_email', 'unknown')
    log_system_event('INFO', f'User {user_email} logged out',
                     source='authentication', user_id=user_email, ip_address=request.remote_addr)
    session.clear()
    flash('You have been logged out successfully')
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    """Main dashboard with comprehensive statistics"""
    # Get all dashboard statistics
    dashboard_stats = get_dashboard_stats()

    return render_template('index.html', stats=dashboard_stats)


@app.route('/select_db_type', methods=['POST'])
@login_required
def select_db_type():
    """Handle database type selection"""
    db_type = request.form.get('db_type')
    if not db_type:
        flash('Please select a database type')
        log_system_event(
            'WARNING', 'Database type selection failed - no type provided', source='migration')
        return redirect(url_for('index'))

    # Load current migration state and update it
    migration_state = load_migration_state_from_files()
    migration_state["selected_db_type"] = db_type

    # Save updated state back to files and get db_id
    db_id = save_migration_state_to_files(migration_state)
    if db_id:
        migration_state["db_id"] = db_id

    log_system_event('INFO', f'Database type selected: {db_type}', source='migration', details={
                     'db_type': db_type})

    return redirect(url_for('migration_setup'))


@app.route('/migration')
@login_required
def migration():
    """Redirect to migration setup"""
    return redirect(url_for('migration_setup'))


@app.route('/migration_setup')
@login_required
def migration_setup():
    """Migration setup - Enter source and encrypted database URLs"""
    return render_template('migration_setup.html')


@app.route('/configure_migration', methods=['POST'])
@login_required
def configure_migration():
    """Handle migration configuration"""

    # Debug: Log all form data
    log_system_event(
        'DEBUG', f'All form data: {dict(request.form)}', source='migration')

    source_url = request.form.get('source_url', '').strip()
    encrypted_url = request.form.get('encrypted_url', '').strip()

    # Get encryption password and security level
    encryption_password = request.form.get('encryption_password', '').strip()
    encryption_password_confirm = request.form.get(
        'encryption_password_confirm', '').strip()
    security_level = request.form.get('security_level', 'Medium').strip()

    # Check for URLs in generated fields if manual fields are empty
    if not source_url:
        source_url = request.form.get('source_url_generated', '').strip()
    if not encrypted_url:
        encrypted_url = request.form.get('encrypted_url_generated', '').strip()

    # Debug logging
    log_system_event(
        'DEBUG', f'Final URLs - source_url: "{source_url}", encrypted_url: "{encrypted_url}"', source='migration')
    log_system_event(
        'DEBUG', f'Raw form fields - source_url: "{request.form.get("source_url", "")}", encrypted_url: "{request.form.get("encrypted_url", "")}"', source='migration')
    log_system_event(
        'DEBUG', f'Generated fields - source_generated: "{request.form.get("source_url_generated", "")}", encrypted_generated: "{request.form.get("encrypted_url_generated", "")}"', source='migration')

    # Validate encryption password with intelligent fallbacks
    if not encryption_password:
        # Check if there's already a password in .env file
        existing_password = os.getenv("CRYPTOPIX_DEFAULT_PASSWORD")

        if existing_password and existing_password != "default_password_123":
            # Use existing password from .env
            encryption_password = existing_password
            encryption_password_confirm = existing_password
            flash('⚠️ Using existing encryption password from configuration. For security, consider setting a new password.', 'warning')
            log_system_event(
                'WARNING', 'Migration proceeding with existing encryption password from .env', source='migration')
        else:
            # Generate a secure random password
            import secrets
            import string

            # Generate a strong random password
            alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
            encryption_password = ''.join(
                secrets.choice(alphabet) for _ in range(16))
            # Ensure it meets all requirements
            encryption_password = 'Auto' + encryption_password + '123!'
            encryption_password_confirm = encryption_password

            # Warn user about auto-generated password
            flash(
                '⚠️ CRITICAL: Auto-generated encryption password. SAVE THIS PASSWORD IMMEDIATELY!', 'error')
            flash(
                f'🔑 Your encryption password: {encryption_password}', 'warning')
            flash(
                '⚠️ Store this password in a secure location. You will need it to decrypt your data!', 'error')

            log_system_event('WARNING', 'Auto-generated encryption password for user', source='migration',
                             details={'reason': 'no_password_provided', 'password_length': len(encryption_password)})

            # Store the generated password in session for display on next page
            session['generated_encryption_password'] = encryption_password

    if encryption_password != encryption_password_confirm:
        flash('Encryption passwords do not match')
        log_system_event(
            'ERROR', 'Migration configuration failed - password mismatch', source='migration')
        return redirect(url_for('migration_setup'))

    # Validate password strength
    import re
    password_requirements = {
        'length': len(encryption_password) >= 12,
        'uppercase': bool(re.search(r'[A-Z]', encryption_password)),
        'lowercase': bool(re.search(r'[a-z]', encryption_password)),
        'number': bool(re.search(r'[0-9]', encryption_password)),
        'special': bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', encryption_password))
    }

    if not all(password_requirements.values()):
        flash('Encryption password does not meet security requirements')
        log_system_event(
            'ERROR', 'Migration configuration failed - weak password', source='migration')
        return redirect(url_for('migration_setup'))

    if not source_url:
        flash('Please provide a source database URL')
        log_system_event(
            'ERROR', 'Migration configuration failed - missing source URL', source='migration')
        return redirect(url_for('migration_setup'))

    if not encrypted_url:
        flash('Please provide an encrypted database URL')
        log_system_event(
            'ERROR', 'Migration configuration failed - missing encrypted URL', source='migration')
        return redirect(url_for('migration_setup'))

    # Update settings with user's encryption password and database URLs
    settings.CRYPTOPIX_DEFAULT_PASSWORD = encryption_password
    settings.default_security_level = security_level
    settings.SOURCE_DB_URL = source_url
    settings.ENCRYPTED_DB_URL = encrypted_url

    # Update .env file with new encryption password, security level, and database URLs
    try:
        env_path = settings.BASE_DIR / '.env'
        if env_path.exists():
            with open(env_path, 'r') as f:
                env_lines = f.readlines()

            # Update or add encryption password, security level, and database URLs
            password_found = False
            security_found = False
            source_url_found = False
            encrypted_url_found = False

            for i, line in enumerate(env_lines):
                if line.startswith('CRYPTOPIX_DEFAULT_PASSWORD=') or line.startswith('CRYPTOPIX_PASSWORD='):
                    env_lines[i] = f'CRYPTOPIX_DEFAULT_PASSWORD={encryption_password}\n'
                    password_found = True
                elif line.startswith('DEFAULT_SECURITY_LEVEL=') or line.startswith('SECURITY_LEVEL='):
                    env_lines[i] = f'DEFAULT_SECURITY_LEVEL={security_level}\n'
                    security_found = True
                elif line.startswith('SOURCE_DB_URL='):
                    env_lines[i] = f'SOURCE_DB_URL={source_url}\n'
                    source_url_found = True
                elif line.startswith('ENCRYPTED_DB_URL='):
                    env_lines[i] = f'ENCRYPTED_DB_URL={encrypted_url}\n'
                    encrypted_url_found = True

            # Add if not found
            if not password_found:
                env_lines.append(
                    f'\nCRYPTOPIX_DEFAULT_PASSWORD={encryption_password}\n')
            if not security_found:
                env_lines.append(f'DEFAULT_SECURITY_LEVEL={security_level}\n')
            if not source_url_found:
                env_lines.append(f'SOURCE_DB_URL={source_url}\n')
            if not encrypted_url_found:
                env_lines.append(f'ENCRYPTED_DB_URL={encrypted_url}\n')

            with open(env_path, 'w') as f:
                f.writelines(env_lines)

            log_system_event(
                'INFO', 'Database URLs, encryption password and security level updated in .env file', source='migration')
    except Exception as e:
        log_system_event(
            'WARNING', f'Could not update .env file: {str(e)}', source='migration')

    # Create fresh migration state (don't load old one to avoid null values)
    migration_state = {
        "source_db_url": source_url,
        "encrypted_db_url": encrypted_url,
        "selected_db_type": "mysql",  # Default, will be updated
        "selected_tables": [],
        "table_configs": {},
        "migration_complete": False,
        "security_level": security_level,
        "encryption_configured": True
    }

    # Determine database type from source URL
    if "mysql" in source_url.lower():
        migration_state["selected_db_type"] = "mysql"
    elif "postgresql" in source_url.lower():
        migration_state["selected_db_type"] = "postgresql"
    elif "sqlite" in source_url.lower():
        migration_state["selected_db_type"] = "sqlite"
    elif "mssql" in source_url.lower():
        migration_state["selected_db_type"] = "mssql"

    # Save fresh migration state to files
    db_id = save_migration_state_to_files(migration_state)
    if db_id:
        migration_state["db_id"] = db_id

    log_system_event('INFO', 'Migration configuration complete with encryption password', source='migration',
                     details={'source_url': source_url, 'encrypted_url': encrypted_url, 'security_level': security_level})

    # Get tables from source database
    tables = get_tables_from_source(source_url)
    if not tables:
        flash('Could not retrieve tables from source database')
        log_system_event('ERROR', 'Failed to retrieve tables from source database',
                         source='migration', details={'source_url': source_url})
        return redirect(url_for('migration_setup'))

    log_system_event('INFO', f'Retrieved {len(tables)} tables from source database',
                     source='migration', details={'table_count': len(tables)})

    flash(
        f'Encryption password configured successfully with {security_level} security level')
    return render_template('table_selection.html', tables=tables)


@app.route('/select_tables', methods=['GET', 'POST'])
@login_required
def select_tables():
    """Handle table selection and column configuration"""
    if request.method == 'POST':
        # Handle table selection from table_selection.html
        selected_tables = request.form.getlist('tables')
        if not selected_tables:
            flash('Please select at least one table')
            log_system_event(
                'WARNING', 'Table selection failed - no tables selected', source='migration')
            return redirect(url_for('configure_migration'))

        # Load current migration state and update it
        migration_state = load_migration_state_from_files()
        migration_state["selected_tables"] = selected_tables

        # Save updated state back to files and get db_id
        db_id = save_migration_state_to_files(migration_state)
        if db_id:
            migration_state["db_id"] = db_id

        log_system_event('INFO', f'Selected {len(selected_tables)} tables for migration', source='migration', details={
                         'selected_tables': selected_tables})

        # Get detailed information for each selected table
        table_info_list = []
        for table in selected_tables:
            table_info = get_table_info_for_config(
                migration_state["source_db_url"], table)
            table_info_list.append(table_info)
            log_system_event('INFO', f'Analyzed {len(table_info["columns"])} columns for table {table}', source='migration', details={
                             'table': table, 'column_count': len(table_info["columns"])})

        return render_template('column_config.html', table_info_list=table_info_list)

    else:  # GET request
        # Load saved migration state and show column configuration page
        log_system_event(
            'DEBUG', 'GET request to /select_tables - loading migration state', source='migration')
        try:
            migration_state = load_migration_state_from_files()
            log_system_event(
                'DEBUG', f'Migration state loaded: source_url={migration_state.get("source_db_url")}, encrypted_url={migration_state.get("encrypted_db_url")}, tables={len(migration_state.get("selected_tables", []))}', source='migration')
        except Exception as e:
            log_system_event(
                'ERROR', f'Failed to load migration state: {str(e)}', source='migration')
            flash('Failed to load migration configuration. Please try again.')
            return redirect(url_for('migration_setup'))

        if not migration_state.get("source_db_url") or not migration_state.get("encrypted_db_url"):
            log_system_event(
                'WARNING', 'No migration configured yet. Redirecting to setup.', source='migration')
            flash('Please configure your database URLs first.')
            return redirect(url_for('migration_setup'))

        if not migration_state.get("selected_tables"):
            log_system_event(
                'WARNING', 'No tables selected yet. Redirecting to table selection.', source='migration')
            flash('Please select tables to migrate first.')
            return redirect(url_for('configure_migration'))

        log_system_event(
            'DEBUG', f'Proceeding with migration state validation passed', source='migration')

        # Check if table configurations already exist
        if not migration_state.get("table_configs"):
            # Auto-configure columns if not configured yet
            log_system_event(
                'INFO', 'Auto-configuring columns for migration', source='migration')

            try:
                table_configs = {}

                # Get columns that should never be encrypted from database schema
                log_system_event(
                    'DEBUG', f'Getting never-encrypt columns for tables: {migration_state["selected_tables"]}', source='migration')
                never_encrypt_columns = get_never_encrypt_columns(
                    migration_state["source_db_url"], migration_state["selected_tables"])
                log_system_event(
                    'DEBUG', f'Never encrypt columns: {never_encrypt_columns}', source='migration')

                for table in migration_state.get("selected_tables", []):
                    log_system_event(
                        'DEBUG', f'Auto-configuring table: {table}', source='migration')
                    columns = get_columns_from_table(
                        migration_state["source_db_url"], table)
                    log_system_event(
                        'DEBUG', f'Found {len(columns)} columns in {table}: {columns[:3] if columns else "None"}', source='migration')
                    table_config = {}

                    for column in columns:
                        # Get column data type from database
                        column_info = get_column_info(
                            migration_state["source_db_url"], table, column)
                        data_type = column_info.get(
                            'type', 'TEXT') if column_info else 'TEXT'

                        # Never encrypt primary keys, auto-increment columns, unique constraint columns, and foreign keys
                        should_encrypt = column not in never_encrypt_columns

                        if should_encrypt:
                            table_config[column] = {
                                'type': 'encrypt', 'data_type': data_type}
                        else:
                            table_config[column] = {
                                'type': 'normal', 'data_type': data_type}

                    table_configs[table] = table_config

                # Save the auto-configured table configs
                migration_state["table_configs"] = table_configs
                db_id = save_migration_state_to_files(migration_state)
                if db_id:
                    migration_state["db_id"] = db_id

                log_system_event(
                    'INFO', f'Auto-configured {sum(len(config) for config in table_configs.values())} columns across {len(table_configs)} tables', source='migration')
            except Exception as e:
                log_system_event(
                    'ERROR', f'Auto-configuration failed: {str(e)}', source='migration')
                flash(f'Auto-configuration failed: {str(e)}')
                return redirect(url_for('configure_migration'))

        # Get detailed information for each selected table from saved state
        try:
            table_info_list = []
            for table in migration_state["selected_tables"]:
                log_system_event(
                    'DEBUG', f'Getting table info for: {table}', source='migration')
                table_info = get_table_info_for_config(
                    migration_state["source_db_url"], table)
                table_info_list.append(table_info)
                log_system_event(
                    'DEBUG', f'Table {table}: analyzed {len(table_info["columns"])} columns', source='migration')

            log_system_event(
                'INFO', f'Loaded column configuration page for {len(migration_state["selected_tables"])} tables', source='migration')

            return render_template('column_config.html', table_info_list=table_info_list)
        except Exception as e:
            log_system_event(
                'ERROR', f'Failed to get table info for configuration: {str(e)}', source='migration')
            flash(f'Failed to load table configuration: {str(e)}')
            return redirect(url_for('configure_migration'))


@app.route('/configure_columns', methods=['POST'])
@login_required
def configure_columns():
    """Handle manual column configuration"""
    # Load current migration state from files
    migration_state = load_migration_state_from_files()

    # Validate that we have the required configuration
    if not migration_state.get("source_db_url"):
        flash('Source database URL not configured. Please set up migration first.')
        return redirect(url_for('migration_setup'))

    if not migration_state.get("encrypted_db_url"):
        flash('Encrypted database URL not configured. Please set up migration first.')
        return redirect(url_for('migration_setup'))

    if not migration_state.get("selected_tables"):
        flash('No tables selected. Please select tables first.')
        return redirect(url_for('configure_migration'))

    table_configs = {}

    # Get columns that should never be encrypted from database schema (for validation)
    never_encrypt_columns = get_never_encrypt_columns(
        migration_state["source_db_url"], migration_state["selected_tables"])

    log_system_event(
        'DEBUG', f'Never encrypt columns: {never_encrypt_columns}', source='migration')

    for table in migration_state["selected_tables"]:
        try:
            # Get detailed table information
            table_info = get_table_info_for_config(
                migration_state["source_db_url"], table)
            table_config = {}

            for column_info in table_info['columns']:
                column_name = column_info['name']

                # Get user selection from form
                form_key = f"{table}_{column_name}"
                # Default to normal if not specified
                user_selection = request.form.get(form_key, 'normal')

                log_system_event(
                    'DEBUG', f'Column {table}.{column_name}: form_key="{form_key}", user_selection="{user_selection}", is_protected={column_info["is_protected"]}', source='migration')

                # Validate that protected columns are not set to encrypt
                if column_info['is_protected'] and user_selection == 'encrypt':
                    logger.warning(
                        f"User attempted to encrypt protected column {table}.{column_name}, forcing to normal")
                    user_selection = 'normal'
                    log_system_event(
                        'WARNING', f'Forced {table}.{column_name} to normal (protected column)', source='migration')

                # Get column data type
                data_type = column_info['data_type']

                # Set configuration based on user selection
                table_config[column_name] = {
                    'type': user_selection, 'data_type': data_type}
                log_system_event(
                    'DEBUG', f'Configured {table}.{column_name} as {user_selection}', source='migration')

            table_configs[table] = table_config
        except Exception as e:
            logger.error(f"Error configuring columns for table {table}: {e}")
            flash(f'Error configuring columns for table {table}: {str(e)}')
            continue

    # Save the table configs to migration state
    migration_state["table_configs"] = table_configs
    db_id = save_migration_state_to_files(migration_state)
    if db_id:
        migration_state["db_id"] = db_id

    # Log the final configuration
    for table_name, config in table_configs.items():
        encrypted_cols = [col for col, cfg in config.items()
                          if cfg.get('type') == 'encrypt']
        normal_cols = [col for col,
                       cfg in config.items() if cfg.get('type') == 'normal']
        log_system_event(
            'INFO', f'Configured {table_name}: {len(encrypted_cols)} encrypted ({encrypted_cols}), {len(normal_cols)} normal ({normal_cols})', source='migration')

    log_system_event(
        'INFO', f'Column configuration completed for {len(table_configs)} tables', source='migration')

    return render_template('migration_confirm.html',
                           source_url=migration_state["source_db_url"],
                           encrypted_url=migration_state["encrypted_db_url"],
                           selected_tables=migration_state["selected_tables"],
                           table_configs=table_configs)


def save_schema_and_mappings(source_db_url: str, table_configs: Dict[str, Any], db_id: str = None):
    """Save schema and table mappings to files for AI assistant"""
    try:
        import json
        import os
        from pathlib import Path

        # Get database-specific folder from registry
        if db_id:
            from app.services.database_registry import database_registry
            database = database_registry.get_database(db_id)
            if database:
                schemas_dir = Path(database["schema_folder"])
            else:
                # Fallback to root schemas folder
                schemas_dir = Path("schemas")
        else:
            # Fallback to root schemas folder
            schemas_dir = Path("schemas")

        schemas_dir.mkdir(parents=True, exist_ok=True)

        # Extract database name from URL for metadata
        db_name = "unknown"
        if "sqlite" in source_db_url:
            db_name = source_db_url.split("/")[-1].split(".")[0]
        elif "mysql" in source_db_url or "postgresql" in source_db_url:
            # Split by '/' and get the last part before any query parameters
            parts = source_db_url.split('/')
            for part in reversed(parts):
                if part and '?' not in part:
                    db_name = part
                    break
                elif '?' in part:
                    db_name = part.split('?')[0]
                    break

        # Save table schemas (column information) as original_schema.json
        schema_file = schemas_dir / "original_schema.json"
        schema_data = {
            "database_url": source_db_url,
            "database_name": db_name,
            "tables": {},
            "created_at": datetime.datetime.utcnow().isoformat()
        }

        # Get detailed column information from source database
        engine = create_engine(source_db_url)
        inspector = inspect(engine)

        for table_name in table_configs.keys():
            try:
                columns = inspector.get_columns(table_name)
                schema_data["tables"][table_name] = {
                    "columns": [
                        {
                            "name": col["name"],
                            "type": str(col["type"]),
                            "nullable": col.get("nullable", True),
                            "default": str(col.get("default")) if col.get("default") else None,
                            "primary_key": col.get("primary_key", False)
                        }
                        for col in columns
                    ]
                }
            except Exception as e:
                logger.warning(
                    f"Could not get schema for table {table_name}: {e}")

        # Save schema file
        with open(schema_file, 'w') as f:
            json.dump(schema_data, f, indent=2)

        # Save table mappings (encryption configuration) as mappings.json
        mappings_file = schemas_dir / "mappings.json"
        mappings_data = {
            "database_url": source_db_url,
            "database_name": db_name,
            "table_mappings": {},
            "created_at": datetime.datetime.utcnow().isoformat()
        }

        # Convert table configs to AI assistant format
        for table_name, config in table_configs.items():
            from app.services.ai_assistant import TableMapping, ColumnMapping

            encrypted_columns = {}
            non_encrypted_columns = []

            for col_name, col_config in config.items():
                if col_config['type'] == 'encrypt':
                    encrypted_columns[col_name] = {
                        "original_name": col_name,
                        "encrypted_name": col_name,
                        "tag_name": f"tag_{col_name}",
                        "is_encrypted": True,
                        "is_hashed": False,
                        "data_type": col_config['data_type'],
                        "supports_ordering": True,
                        "supports_ranges": True
                    }
                else:
                    non_encrypted_columns.append(col_name)

            mappings_data["table_mappings"][table_name] = {
                "original_name": table_name,
                "encrypted_columns": encrypted_columns,
                "primary_key": "id",  # Default primary key
                "non_encrypted_columns": non_encrypted_columns
            }

        # Save mappings file
        with open(mappings_file, 'w') as f:
            json.dump(mappings_data, f, indent=2)

        logger.info(
            f"Saved schema and mappings for database {db_name} to {schemas_dir}")

    except Exception as e:
        logger.error(f"Failed to save schema and mappings: {e}")
        raise e


def save_empty_database_schema(db_url: str, db_type: str, table_configs: Dict[str, Any] = None, db_id: str = None):
    """Save empty database schema (structure only, no data) to JSON file"""
    try:
        import json
        from pathlib import Path

        # Get database-specific folder from registry
        if db_id:
            from app.services.database_registry import database_registry
            database = database_registry.get_database(db_id)
            if database:
                schemas_dir = Path(database["schema_folder"])
            else:
                # Fallback to root schemas folder
                schemas_dir = Path("schemas")
        else:
            # Fallback to root schemas folder
            schemas_dir = Path("schemas")

        schemas_dir.mkdir(parents=True, exist_ok=True)

        # Use standardized schema names
        if db_type == "source":
            schema_filename = "original_schema.json"
        elif db_type == "encrypted":
            schema_filename = "encrypted_schema.json"
        else:
            schema_filename = f"{db_type}_schema.json"

        # Extract database name from URL for metadata
        db_name = "unknown"
        if "sqlite" in db_url:
            db_name = db_url.split("/")[-1].split(".")[0]
        elif "mysql" in db_url or "postgresql" in db_url:
            # Split by '/' and get the last part before any query parameters
            parts = db_url.split('/')
            for part in reversed(parts):
                if part and '?' not in part:
                    db_name = part
                    break
                elif '?' in part:
                    db_name = part.split('?')[0]
                    break

        # Connect to database and get schema information
        engine = create_engine(db_url)
        inspector = inspect(engine)

        # Get all tables
        tables = inspector.get_table_names()

        schema_data = {
            "database_url": db_url,
            "database_name": db_name,
            "database_type": db_type,
            "tables": {},
            "created_at": datetime.datetime.utcnow().isoformat(),
            "migration_timestamp": datetime.datetime.utcnow().isoformat()
        }

        for table_name in tables:
            try:
                # Get table columns
                columns = inspector.get_columns(table_name)

                # Get table primary keys
                primary_keys = inspector.get_pk_constraint(table_name)
                pk_columns = primary_keys.get(
                    'constrained_columns', []) if primary_keys else []

                # Get table foreign keys
                foreign_keys = inspector.get_foreign_keys(table_name)

                # Get table indexes
                indexes = inspector.get_indexes(table_name)

                # Get table constraints (check constraints, unique constraints)
                try:
                    check_constraints = inspector.get_check_constraints(
                        table_name)
                except:
                    check_constraints = []

                try:
                    unique_constraints = inspector.get_unique_constraints(
                        table_name)
                except:
                    unique_constraints = []

                # Build table schema
                table_schema = {
                    "name": table_name,
                    "columns": [],
                    "primary_keys": pk_columns,
                    "foreign_keys": foreign_keys,
                    "indexes": indexes,
                    "check_constraints": check_constraints,
                    "unique_constraints": unique_constraints
                }

                # Process columns
                for col in columns:
                    column_info = {
                        "name": col["name"],
                        "type": str(col["type"]),
                        "nullable": col.get("nullable", True),
                        "default": str(col.get("default")) if col.get("default") else None,
                        "primary_key": col.get("primary_key", False),
                        "autoincrement": getattr(col.get("type", None), "autoincrement", False) if hasattr(col.get("type", None), "autoincrement") else False
                    }

                    # Add encryption information if available
                    if table_configs and table_name in table_configs:
                        col_config = table_configs[table_name].get(col["name"])
                        if col_config:
                            column_info["encryption_type"] = col_config.get(
                                "type", "normal")
                            column_info["data_type"] = col_config.get(
                                "data_type", str(col["type"]))

                    table_schema["columns"].append(column_info)

                schema_data["tables"][table_name] = table_schema

            except Exception as e:
                logger.warning(
                    f"Could not get schema for table {table_name}: {e}")
                schema_data["tables"][table_name] = {"error": str(e)}

        engine.dispose()

        # Save schema file with standardized name
        schema_file = schemas_dir / schema_filename

        with open(schema_file, 'w') as f:
            json.dump(schema_data, f, indent=2, default=str)

        logger.info(f"Saved empty {db_type} database schema to {schema_file}")
        return schema_file

    except Exception as e:
        logger.error(f"Failed to save empty {db_type} database schema: {e}")
        raise e


@app.route('/api/migration_progress')
@login_required
def get_migration_progress():
    """Get current migration progress as JSON"""
    with migration_progress_lock:
        return {
            'status': migration_progress['status'],
            'progress': migration_progress['progress'],
            'current_table': migration_progress['current_table'],
            'total_tables': migration_progress['total_tables'],
            'completed_tables': migration_progress['completed_tables'],
            'message': migration_progress['message'],
            'error': migration_progress['error'],
            'start_time': migration_progress['start_time'],
            'end_time': migration_progress['end_time']
        }


@app.route('/api/vds_status')
@login_required
def get_vds_status():
    """Get Virtual Database Server status"""
    try:
        # Load migration state to get VDS details
        migration_state = load_migration_state_from_files()

        # Check if VDS is running (this is a simplified check)
        vds_info = {
            'host': '0.0.0.0',
            'port': 4406,
            'protocol': migration_state.get('selected_db_type', 'mysql'),
            'table_count': len(migration_state.get('table_configs', {})),
            'status': 'running' if migration_state.get('migration_complete') else 'stopped'
        }

        return {'success': True, 'vds': vds_info}
    except Exception as e:
        logger.error(f"Error getting VDS status: {e}")
        return {'success': False, 'error': str(e)}, 500


@app.route('/migration_progress')
@login_required
def migration_progress_page():
    """Show migration progress page"""
    return render_template('migration_progress.html')


@app.route('/start_migration', methods=['POST'])
@login_required
def start_migration():
    """Start the migration process asynchronously"""
    # Load migration state from files
    migration_state = load_migration_state_from_files()

    # Check if table configurations exist
    if not migration_state.get("table_configs"):
        flash('Column configuration is required before migration. Please configure which columns to encrypt.', 'error')
        log_system_event(
            'ERROR', 'Migration attempted without column configuration', source='migration')
        return redirect(url_for('select_tables'))

    # Check if migration is already running
    with migration_progress_lock:
        if migration_progress['status'] == 'running':
            flash(
                'Migration is already running. Please wait for it to complete.', 'warning')
            return redirect(url_for('migration_progress_page'))

    log_system_event('INFO', 'Migration process started asynchronously', source='migration', details={
                     'tables': migration_state.get('selected_tables', [])})

    # Start migration in background thread
    def run_migration():
        try:
            with migration_progress_lock:
                migration_progress.update({
                    'status': 'running',
                    'progress': 0,
                    'current_table': '',
                    'total_tables': len(migration_state.get('table_configs', {})),
                    'completed_tables': 0,
                    'message': 'Initializing migration...',
                    'error': None,
                    'start_time': datetime.datetime.utcnow().isoformat(),
                    'end_time': None
                })

            # Save empty source database schema
            with migration_progress_lock:
                migration_progress['message'] = 'Saving source database schema...'
            log_system_event(
                'INFO', 'Saving source database schema', source='migration')
            source_schema_file = save_empty_database_schema(
                migration_state["source_db_url"],
                "source",
                migration_state.get("table_configs"),
                migration_state.get("db_id")
            )
            log_system_event(
                'INFO', f'Source database schema saved to {source_schema_file}', source='migration')

            # Create encrypted schema
            with migration_progress_lock:
                migration_progress['message'] = 'Creating encrypted database schema...'
            log_system_event(
                'INFO', 'Creating encrypted database schema', source='migration')
            try:
                create_encrypted_schema()
                log_system_event(
                    'INFO', 'Encrypted schema created successfully', source='migration')
            except Exception as e:
                with migration_progress_lock:
                    migration_progress.update({
                        'status': 'failed',
                        'error': f"Failed to create encrypted schema: {str(e)}",
                        'end_time': datetime.datetime.utcnow().isoformat()
                    })
                log_system_event(
                    'ERROR', f'Failed to create encrypted schema: {str(e)}', source='migration')
                return

            # Save empty encrypted database schema
            with migration_progress_lock:
                migration_progress['message'] = 'Saving encrypted database schema...'
            log_system_event(
                'INFO', 'Saving encrypted database schema', source='migration')
            encrypted_schema_file = save_empty_database_schema(
                migration_state["encrypted_db_url"],
                "encrypted",
                migration_state.get("table_configs"),
                migration_state.get("db_id")
            )
            log_system_event(
                'INFO', f'Encrypted database schema saved to {encrypted_schema_file}', source='migration')

            # Perform bulk migration with progress tracking
            with migration_progress_lock:
                migration_progress['message'] = 'Starting data migration...'
            log_system_event('INFO', 'Starting data migration',
                             source='migration')
            migration_result = migrate_data_with_progress(migration_state)
            if migration_result and migration_result.get('success') == False:
                with migration_progress_lock:
                    migration_progress.update({
                        'status': 'failed',
                        'error': migration_result.get("error", "Unknown error"),
                        'end_time': datetime.datetime.utcnow().isoformat()
                    })
                log_system_event(
                    'ERROR', f'Data migration failed: {migration_result.get("error", "Unknown error")}', source='migration')
                return

            log_system_event(
                'INFO', 'Data migration completed successfully', source='migration')

            # Save schema and mappings after successful migration
            with migration_progress_lock:
                migration_progress['message'] = 'Saving migration state...'

            # Update migration state file to mark as complete and get db_id
            migration_state["migration_complete"] = True
            db_id = save_migration_state_to_files(migration_state)
            if db_id:
                migration_state["db_id"] = db_id

                # Update database registry to mark migration as complete
                database_registry.update_database(db_id, {"migration_complete": True})

            # Now save schema and mappings with db_id
            with migration_progress_lock:
                migration_progress['message'] = 'Saving schema and mappings...'
            log_system_event(
                'INFO', 'Saving schema and mappings after successful migration', source='migration')
            save_schema_and_mappings(
                migration_state["source_db_url"], migration_state["table_configs"], db_id)
            log_system_event(
                'INFO', 'Schema and mappings saved successfully', source='migration')

            # Mark migration as completed before starting VDS
            with migration_progress_lock:
                migration_progress.update({
                    'status': 'completed',
                    'progress': 100,
                    'message': 'Migration completed successfully!',
                    'end_time': datetime.datetime.utcnow().isoformat()
                })

            # VDS auto-start disabled - users must manually start VDS from Settings page
            # Commented out auto-start logic:
            # try:
            #     from app.virtual_db_server import start_virtual_server
            #     vds = start_virtual_server(
            #         host=settings.VDS_HOST if hasattr(settings, 'VDS_HOST') else "0.0.0.0",
            #         port=settings.VDS_PORT if hasattr(settings, 'VDS_PORT') else 4406,
            #         encrypted_db_url=migration_state["encrypted_db_url"],
            #         protocol=migration_state.get("selected_db_type", "mysql"),
            #         table_mappings=migration_state.get("table_configs", {})
            #     )
            #     log_system_event('INFO', f'Virtual Database Server started automatically on port {vds.port}', source='migration')
            #
            #     # Update message with VDS info
            #     with migration_progress_lock:
            #         migration_progress['message'] = f'Migration completed successfully! Virtual Database Server running on port {vds.port}'
            # except Exception as e:
            #     log_system_event('WARNING', f'Failed to start Virtual Database Server: {str(e)}', source='migration')
            #
            #     # Update message even if VDS failed
            #     with migration_progress_lock:
            #         migration_progress['message'] = 'Migration completed successfully! (Virtual Database Server failed to start)'

            log_system_event(
                'SUCCESS', 'Migration completed successfully', source='migration')

        except Exception as e:
            with migration_progress_lock:
                migration_progress.update({
                    'status': 'failed',
                    'error': str(e),
                    'end_time': datetime.datetime.utcnow().isoformat()
                })
            log_system_event('ERROR', f'Migration failed: {str(e)}', source='migration', details={
                             'error': str(e)})

    # Start migration thread
    migration_thread = threading.Thread(target=run_migration, daemon=True)
    migration_thread.start()

    # Return progress page immediately
    return redirect(url_for('migration_progress_page'))


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings_page():
    """Comprehensive settings page for database configuration"""
    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'update_encrypted_database_config':
            return update_encrypted_database_config()
        elif action == 'reconfigure_encrypted_database':
            return reconfigure_encrypted_database()
        elif action == 'demigrate_database':
            return demigrate_database()

    # Get all registered databases for the list
    databases_list = database_registry.list_databases()

    # Load migration state from files (default or specific)
    selected_db_id = request.args.get('db_id')
    if selected_db_id:
        migration_state = load_migration_state_from_files(db_id=selected_db_id)
    else:
        migration_state = load_migration_state_from_files()

    # Get current settings for display
    current_settings = {
        'source_db_url': migration_state.get('source_db_url', ''),
        'encrypted_db_url': migration_state.get('encrypted_db_url', ''),
        'selected_db_type': migration_state.get('selected_db_type', ''),
        'table_configs': migration_state.get('table_configs', {}),
        'migration_complete': migration_state.get('migration_complete', False)
    }

    # Get available tables for column configuration
    available_tables = []
    if migration_state.get('encrypted_db_url'):
        try:
            engine = create_engine(migration_state['encrypted_db_url'])
            inspector = inspect(engine)

            for table_name in inspector.get_table_names():
                try:
                    columns = inspector.get_columns(table_name)
                    column_info = []

                    # Track which columns we've already processed to avoid duplicates
                    processed_columns = set()

                    for col in columns:
                        # Determine current encryption status using table mapping
                        col_name = col['name']

                        # Skip tag columns - they're internal CLWE metadata
                        if col_name.startswith('tag_'):
                            continue

                        # Check if this column is encrypted based on migration state
                        status = 'normal'
                        original_name = col_name

                        # Look up the column in table configs to determine status
                        if migration_state.get('table_configs') and table_name in migration_state['table_configs']:
                            table_config = migration_state['table_configs'][table_name]
                            if col_name in table_config:
                                config = table_config[col_name]
                                status = config.get('type', 'normal')
                                original_name = col_name

                        # Only add if we haven't processed this column yet
                        if original_name not in processed_columns:
                            processed_columns.add(original_name)
                            column_info.append({
                                'name': original_name,
                                'type': str(col['type']),
                                'current_status': status
                            })

                    available_tables.append({
                        'name': table_name,
                        'columns': column_info
                    })
                except Exception as e:
                    logger.warning(
                        f"Error getting columns for table {table_name}: {e}")

            engine.dispose()
        except Exception as e:
            logger.error(f"Error connecting to encrypted database: {e}")

    # Get Virtual Database Server status
    virtual_server_status = {
        'running': False,
        'active_connections': 0,
        'port': 4406,
        'protocol': 'mysql',
        'host': '0.0.0.0'
    }

    # Check if VDS is running
    try:
        from app.virtual_db_server import virtual_db_server
        if virtual_db_server and hasattr(virtual_db_server, 'running') and virtual_db_server.running:
            virtual_server_status.update({
                'running': True,
                'active_connections': len(getattr(virtual_db_server, 'active_connections', {})),
                'port': getattr(virtual_db_server, 'port', 4406),
                'protocol': getattr(virtual_db_server, 'target_protocol', 'mysql'),
                'host': getattr(virtual_db_server, 'host', '0.0.0.0')
            })
    except Exception as e:
        logger.warning(f"Could not get VDS status: {e}")

    return render_template('settings.html',
                           settings=current_settings,
                           available_tables=available_tables,
                           migration_state=migration_state,
                           virtual_server_status=virtual_server_status,
                           databases=databases_list)


@app.route('/test_encryption')
@login_required
def test_encryption():
    """Test CLWE encryption/decryption functionality"""
    try:
        # Test basic encryption/decryption
        test_data = "Hello World 123"
        encrypted = clwe_encryptor.encrypt_value(
            test_data, settings.CRYPTOPIX_DEFAULT_PASSWORD)
        decrypted = clwe_encryptor.decrypt_value(
            encrypted, settings.CRYPTOPIX_DEFAULT_PASSWORD)

        result = {
            "test_data": test_data,
            "encrypted_size": len(encrypted),
            "decryption_success": decrypted == test_data,
            "decrypted_value": decrypted,
            "password_used": settings.CRYPTOPIX_DEFAULT_PASSWORD,
            "encrypted_hex_preview": encrypted.hex()[:100] + "..." if encrypted else "None"
        }

        return render_template('query_result.html', result={
            "success": True,
            "query_type": "ENCRYPTION_TEST",
            "rows": [result],
            "row_count": 1,
            "columns": ["test_data", "encrypted_size", "decryption_success", "decrypted_value", "password_used", "encrypted_hex_preview"],
            "decrypted": True
        })

    except Exception as e:
        return render_template('query_result.html', result={
            "success": False,
            "error": f"Encryption test failed: {str(e)}"
        })


@app.route('/test_real_decryption')
@login_required
def test_real_decryption():
    """Test decryption with real encrypted data from database"""
    # Load migration state from files
    migration_state = load_migration_state_from_files()

    try:
        if not migration_state.get("migration_complete"):
            return render_template('query_result.html', result={
                "success": False,
                "error": "Migration not completed yet"
            })

        # Get a sample of real encrypted data
        engine = create_engine(migration_state["encrypted_db_url"])

        with engine.connect() as conn:
            # Get first row from first table
            result = conn.execute(text("SELECT * FROM patients LIMIT 1"))
            row = result.fetchone()
            columns = result.keys()

            if row:
                test_results = []
                for i, col in enumerate(columns):
                    value = row[i]
                    # Check if this column is encrypted based on migration state
                    is_encrypted = False
                    if migration_state.get('table_configs') and 'patients' in migration_state['table_configs']:
                        table_config = migration_state['table_configs']['patients']
                        if col in table_config and table_config[col].get('type') == 'encrypt':
                            is_encrypted = True

                    if is_encrypted and isinstance(value, bytes):
                        # Try to decrypt this real data
                        try:
                            decrypted = clwe_encryptor.decrypt_value(
                                value, settings.CRYPTOPIX_DEFAULT_PASSWORD)
                            test_results.append({
                                "column": col,
                                "original_size": len(value),
                                "hex_preview": value.hex()[:100] + "...",
                                "decryption_success": True,
                                "decrypted_value": decrypted,
                                "password_used": settings.CRYPTOPIX_DEFAULT_PASSWORD
                            })
                        except Exception as e:
                            test_results.append({
                                "column": col,
                                "original_size": len(value),
                                "hex_preview": value.hex()[:100] + "...",
                                "decryption_success": False,
                                "error": str(e),
                                "password_used": settings.CRYPTOPIX_DEFAULT_PASSWORD
                            })

                return render_template('query_result.html', result={
                    "success": True,
                    "query_type": "REAL_DECRYPTION_TEST",
                    "rows": test_results,
                    "row_count": len(test_results),
                    "columns": ["column", "original_size", "hex_preview", "decryption_success", "decrypted_value", "error", "password_used"],
                    "decrypted": True
                })
            else:
                return render_template('query_result.html', result={
                    "success": False,
                    "error": "No data found in database"
                })

    except Exception as e:
        return render_template('query_result.html', result={
            "success": False,
            "error": f"Real decryption test failed: {str(e)}"
        })


@app.route('/debug_migration_state')
@login_required
def debug_migration_state():
    """Debug endpoint to check current migration state"""
    # Load migration state from files
    migration_state = load_migration_state_from_files()

    # Also test database connections and get table info
    source_connection_ok = False
    encrypted_connection_ok = False
    source_tables = []
    encrypted_tables = []

    if migration_state.get('source_db_url'):
        try:
            engine = create_engine(migration_state['source_db_url'])
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            source_connection_ok = True

            # Get tables from source database
            inspector = inspect(engine)
            source_tables = inspector.get_table_names()
            engine.dispose()
        except Exception as e:
            logger.error(f"Source database connection failed: {e}")

    if migration_state.get('encrypted_db_url'):
        try:
            engine = create_engine(migration_state['encrypted_db_url'])
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            encrypted_connection_ok = True

            # Get tables from encrypted database
            inspector = inspect(engine)
            encrypted_tables = inspector.get_table_names()
            engine.dispose()
        except Exception as e:
            logger.error(f"Encrypted database connection failed: {e}")

    # Test column retrieval for selected tables
    column_test_results = {}
    if migration_state.get('selected_tables') and migration_state.get('source_db_url'):
        for table in migration_state['selected_tables']:
            try:
                columns = get_columns_from_table(
                    migration_state['source_db_url'], table)
                column_test_results[table] = {
                    'column_count': len(columns),
                    'columns': columns[:5] if columns else []
                }
            except Exception as e:
                column_test_results[table] = {
                    'error': str(e),
                    'column_count': 0,
                    'columns': []
                }

    return {
        'migration_state': migration_state,
        'source_db_url': migration_state.get('source_db_url'),
        'encrypted_db_url': migration_state.get('encrypted_db_url'),
        'migration_complete': migration_state.get('migration_complete'),
        'source_connection_ok': source_connection_ok,
        'encrypted_connection_ok': encrypted_connection_ok,
        'source_tables': source_tables,
        'encrypted_tables': encrypted_tables,
        'selected_tables': migration_state.get('selected_tables', []),
        'table_configs': migration_state.get('table_configs', {}),
        'column_test_results': column_test_results
    }


@app.route('/debug_database')
@login_required
def debug_database():
    """Debug endpoint to see raw database data"""
    # Load migration state from files
    migration_state = load_migration_state_from_files()

    try:
        if not migration_state.get("migration_complete"):
            return render_template('query_result.html', result={
                "success": False,
                "error": "Migration not completed yet"
            })

        # Query raw data from encrypted database
        engine = create_engine(migration_state["encrypted_db_url"])

        with engine.connect() as conn:
            # Get all tables
            from sqlalchemy.engine import reflection
            inspector = reflection.Inspector.from_engine(engine)
            tables = inspector.get_table_names()

            debug_info = []
            for table in tables[:3]:  # Limit to first 3 tables
                try:
                    result = conn.execute(
                        text(f"SELECT * FROM {table} LIMIT 2"))
                    rows = result.fetchall()
                    columns = result.keys()

                    table_info = {
                        "table_name": table,
                        "columns": list(columns),
                        "row_count": len(rows),
                        "sample_data": []
                    }

                    for row in rows:
                        row_data = {}
                        for i, col in enumerate(columns):
                            value = row[i]
                            if isinstance(value, bytes):
                                # Show first 100 bytes as hex for debugging
                                hex_preview = value.hex()[:100]
                                row_data[col] = f"BYTES[{len(value)}]: {hex_preview}..."
                            else:
                                # Limit string length
                                row_data[col] = str(value)[:100]
                        table_info["sample_data"].append(row_data)

                    debug_info.append(table_info)

                except Exception as e:
                    debug_info.append({
                        "table_name": table,
                        "error": str(e)
                    })

        return render_template('query_result.html', result={
            "success": True,
            "query_type": "DEBUG_INFO",
            "rows": debug_info,
            "row_count": len(debug_info),
            "columns": ["table_name", "columns", "row_count", "sample_data", "error"],
            "decrypted": False
        })

    except Exception as e:
        return render_template('query_result.html', result={
            "success": False,
            "error": f"Debug failed: {str(e)}"
        })


@app.route('/manual_decrypt_test')
@login_required
def manual_decrypt_test():
    """Manually test decryption with the provided sample data"""
    try:
        # Use the exact sample data provided by the user
        sample_data = b'RIFF6\x00\x00\x00WEBPVP8L*\x00\x00\x00/\x03\x00\x00\x00\x1f !S6\xc8ZB\x01\x04 \xff\x1bT$!\x10\x08P\x8ckP\xb8\xeb\xcc\xfcG\xbe\x01\xf4\x83\x1aG\xf4?\x00'

        # Try to decrypt with different passwords
        passwords_to_try = [
            settings.CRYPTOPIX_DEFAULT_PASSWORD,
            "default_password_123",
            "cryptopix",
            "password",
            "admin"
        ]

        test_results = []

        for password in passwords_to_try:
            try:
                decrypted = clwe_encryptor.decrypt_value(sample_data, password)
                test_results.append({
                    "password": password,
                    "success": True,
                    "decrypted_value": decrypted,
                    "length": len(decrypted) if decrypted else 0
                })
            except Exception as e:
                test_results.append({
                    "password": password,
                    "success": False,
                    "error": str(e),
                    "length": 0
                })

        # Also test if CLWE library is working at all
        try:
            test_encrypt = clwe_encryptor.encrypt_value(
                "test", settings.CRYPTOPIX_DEFAULT_PASSWORD)
            test_decrypt = clwe_encryptor.decrypt_value(
                test_encrypt, settings.CRYPTOPIX_DEFAULT_PASSWORD)
            clwe_working = test_decrypt == "test"
        except:
            clwe_working = False

        test_results.append({
            "password": "CLWE_LIBRARY_TEST",
            "success": clwe_working,
            "decrypted_value": "CLWE library working" if clwe_working else "CLWE library not working",
            "length": 0
        })

        return render_template('query_result.html', result={
            "success": True,
            "query_type": "MANUAL_DECRYPT_TEST",
            "rows": test_results,
            "row_count": len(test_results),
            "columns": ["password", "success", "decrypted_value", "error", "length"],
            "decrypted": True
        })

    except Exception as e:
        return render_template('query_result.html', result={
            "success": False,
            "error": f"Manual decrypt test failed: {str(e)}"
        })


def get_tables_from_source(db_url: str) -> List[str]:
    """Get table names from source database"""
    try:
        engine = create_engine(db_url)
        inspector = inspect(engine)

        # Get all table names
        tables = inspector.get_table_names()

        # Filter out system tables (basic filtering)
        filtered_tables = []
        for table in tables:
            # Skip common system tables
            if not table.startswith(('sqlite_', 'pg_', 'information_schema', 'mysql', 'sys')):
                filtered_tables.append(table)

        engine.dispose()
        return filtered_tables

    except Exception as e:
        print(f"Error getting tables: {e}")
        flash(f"Could not connect to source database: {str(e)}")
        return []


def get_columns_from_table(db_url: str, table: str) -> List[str]:
    """Get column names from a table"""
    try:
        logger.debug(f"Connecting to database: {db_url}")
        engine = create_engine(db_url)
        inspector = inspect(engine)

        logger.debug(f"Getting columns for table: {table}")
        # Get column information for the table
        columns = inspector.get_columns(table)

        # Extract column names
        column_names = [col['name'] for col in columns]

        logger.debug(
            f"Found {len(column_names)} columns for table {table}: {column_names[:3] if column_names else 'None'}")
        engine.dispose()
        return column_names

    except Exception as e:
        logger.error(f"Error getting columns for table {table}: {e}")
        flash(f"Could not get columns for table {table}: {str(e)}")
        return []


def get_column_info(db_url: str, table: str, column: str) -> Dict[str, Any]:
    """Get detailed information about a specific column"""
    try:
        engine = create_engine(db_url)
        inspector = inspect(engine)

        # Get column information for the table
        columns = inspector.get_columns(table)

        # Find the specific column
        for col in columns:
            if col['name'] == column:
                engine.dispose()
                return col

        engine.dispose()
        return {}

    except Exception as e:
        print(f"Error getting column info for {table}.{column}: {e}")
        return {}


def get_never_encrypt_columns(db_url: str, tables: List[str]) -> Set[str]:
    """Get all columns that should never be encrypted based on database schema constraints"""
    never_encrypt = set()

    try:
        engine = create_engine(db_url)
        inspector = inspect(engine)

        for table in tables:
            try:
                # Get primary key columns
                pk_constraint = inspector.get_pk_constraint(table)
                if pk_constraint and 'constrained_columns' in pk_constraint:
                    never_encrypt.update(pk_constraint['constrained_columns'])

                # Get unique constraints
                unique_constraints = inspector.get_unique_constraints(table)
                for constraint in unique_constraints:
                    if 'column_names' in constraint:
                        never_encrypt.update(constraint['column_names'])

                # Get foreign key columns
                foreign_keys = inspector.get_foreign_keys(table)
                for fk in foreign_keys:
                    if 'constrained_columns' in fk:
                        never_encrypt.update(fk['constrained_columns'])

                # Get columns with auto-increment
                columns = inspector.get_columns(table)
                for col in columns:
                    # Check for auto-increment (different databases have different ways)
                    if col.get('autoincrement', False) or getattr(col.get('type', None), 'autoincrement', False):
                        never_encrypt.add(col['name'])

                    # Also check for common auto-increment column names
                    col_name = col['name'].lower()
                    if col_name in {'id', 'pk', 'primary_key'} or col_name.endswith('_id'):
                        # Additional check - if it's an integer primary key, likely auto-increment
                        if col.get('primary_key', False) and 'INTEGER' in str(col.get('type', '')).upper():
                            never_encrypt.add(col['name'])

            except Exception as e:
                logger.warning(
                    f"Error getting constraints for table {table}: {e}")
                continue

        engine.dispose()

        logger.info(
            f"Found {len(never_encrypt)} columns that should never be encrypted: {sorted(never_encrypt)}")
        return never_encrypt

    except Exception as e:
        logger.error(f"Error getting never-encrypt columns: {e}")
        # Fallback to basic column names that are commonly primary keys
        return {'id', 'pk', 'primary_key'}


def analyze_column_for_encryption(column_name: str, column_info: Dict[str, Any], sample_data: Any = None) -> Dict[str, Any]:
    """Analyze a column and provide encryption recommendation"""
    col_name_lower = column_name.lower()
    data_type = str(column_info.get('type', 'TEXT')).upper()

    # Check if column should never be encrypted
    protected_columns = {
        'id', 'pk', 'primary_key', 'uuid', 'guid',
        'created_at', 'updated_at', 'created_date', 'updated_date', 'timestamp',
        'version', 'lock_version'
    }

    # Check for foreign key patterns
    if col_name_lower.endswith('_id') and col_name_lower != 'id':
        is_protected = True
        reason = "Foreign key column"
    elif col_name_lower in protected_columns:
        is_protected = True
        reason = "System/metadata column"
    elif column_info.get('primary_key', False):
        is_protected = True
        reason = "Primary key column"
    elif column_info.get('autoincrement', False) or getattr(column_info.get('type', None), 'autoincrement', False):
        is_protected = True
        reason = "Auto-increment column"
    else:
        is_protected = False
        reason = None

    # Provide recommendations for non-protected columns
    if is_protected:
        recommendation = 'normal'
    else:
        # Analyze based on column name patterns
        sensitive_patterns = [
            'name', 'first_name', 'last_name', 'full_name', 'username', 'email', 'phone',
            'address', 'city', 'state', 'zip', 'postal', 'ssn', 'social_security',
            'credit_card', 'card_number', 'account', 'password', 'secret', 'token',
            'personal', 'private', 'confidential', 'sensitive'
        ]

        # Check for sensitive data patterns in column name
        is_sensitive_name = any(
            pattern in col_name_lower for pattern in sensitive_patterns)

        # Analyze data type
        text_types = ['TEXT', 'VARCHAR', 'CHAR', 'NVARCHAR', 'CLOB']
        is_text_type = any(t in data_type for t in text_types)

        # Analyze sample data if available
        contains_pii = False
        if sample_data:
            sample_str = str(sample_data).lower()
            # Check for email patterns
            if '@' in sample_str and '.' in sample_str:
                contains_pii = True
            # Check for phone patterns
            elif any(char.isdigit() for char in sample_str) and ('-' in sample_str or '(' in sample_str):
                contains_pii = True

        # Make recommendation
        if is_sensitive_name or (is_text_type and contains_pii):
            recommendation = 'encrypt'
        elif is_text_type and len(str(sample_data or '')) > 50:  # Long text fields
            recommendation = 'encrypt'
        elif data_type in ['BLOB', 'BYTEA', 'VARBINARY']:  # Binary data
            recommendation = 'encrypt'
        else:
            recommendation = 'encrypt'  # Default to encrypt for all non-protected columns

    return {
        'name': column_name,
        'data_type': data_type,
        'is_protected': is_protected,
        'reason': reason,
        'recommendation': recommendation
    }


def get_table_info_for_config(db_url: str, table_name: str) -> Dict[str, Any]:
    """Get detailed table information for column configuration"""
    try:
        engine = create_engine(db_url)
        inspector = inspect(engine)

        # Get column information
        columns = inspector.get_columns(table_name)
        
        # Get primary key constraint to identify primary key columns
        pk_constraint = inspector.get_pk_constraint(table_name)
        primary_key_columns = set(pk_constraint.get('constrained_columns', [])) if pk_constraint else set()
        
        logger.info(f"Primary key columns for {table_name}: {primary_key_columns}")

        # Get a sample row for data analysis (optional)
        sample_data = None
        try:
            with engine.connect() as conn:
                result = conn.execute(
                    text(f"SELECT * FROM {table_name} LIMIT 1"))
                row = result.fetchone()
                if row:
                    sample_data = dict(zip(result.keys(), row))
        except:
            pass  # Ignore if we can't get sample data

        # Analyze each column
        analyzed_columns = []
        for col in columns:
            col_name = col['name']
            
            # Mark column as primary key if it's in the primary key constraint
            if col_name in primary_key_columns:
                col['primary_key'] = True
                logger.info(f"Marking {table_name}.{col_name} as primary key (will not be encrypted)")
            
            sample_value = sample_data.get(col_name) if sample_data else None
            analysis = analyze_column_for_encryption(
                col_name, col, sample_value)
            analyzed_columns.append(analysis)

        engine.dispose()

        return {
            'name': table_name,
            'columns': analyzed_columns
        }

    except Exception as e:
        logger.error(f"Error getting table info for {table_name}: {e}")
        return {
            'name': table_name,
            'columns': []
        }


def create_table_mapping(table_name: str, config: Dict[str, Any]):
    """Create TableMapping from configuration using AI assistant classes"""
    from app.services.ai_assistant import TableMapping, ColumnMapping

    encrypted_columns = {}
    non_encrypted_columns = []

    for col_name, col_config in config.items():
        if col_config['type'] == 'encrypt':
            encrypted_columns[col_name] = ColumnMapping(
                original_name=col_name,
                encrypted_name=col_name,  # Use original name for encrypted columns
                tag_name=f"tag_{col_name}",  # Tag column for searching
                is_encrypted=True,
                is_hashed=False,
                data_type=col_config['data_type'],
                supports_ordering=True,  # Enable ordering for encrypted columns
                supports_ranges=True     # Enable range queries for encrypted columns
            )
        else:
            non_encrypted_columns.append(col_name)

    return TableMapping(
        original_name=table_name,
        encrypted_columns=encrypted_columns,
        primary_key='id',
        non_encrypted_columns=non_encrypted_columns
    )


def create_encrypted_schema():
    """Create encrypted database schema based on source database structure with original column names and constraints"""
    # Load migration state from files
    migration_state = load_migration_state_from_files()

    # Validate that we have the required URLs
    if not migration_state.get("source_db_url"):
        raise Exception("Source database URL not configured")
    if not migration_state.get("encrypted_db_url"):
        raise Exception("Encrypted database URL not configured")

    # Determine target database type from encrypted URL
    target_db_type = "mysql"  # default
    if "postgresql" in migration_state["encrypted_db_url"].lower():
        target_db_type = "postgresql"
    elif "sqlite" in migration_state["encrypted_db_url"].lower():
        target_db_type = "sqlite"
    elif "mssql" in migration_state["encrypted_db_url"].lower():
        target_db_type = "mssql"

    try:
        # Connect to source database to get column types and constraints
        source_engine = create_engine(migration_state["source_db_url"])
        inspector = inspect(source_engine)

        # Connect to encrypted database
        encrypted_engine = create_engine(migration_state["encrypted_db_url"])

        for table_name, config in migration_state["table_configs"].items():
            # Get source column information
            source_columns = inspector.get_columns(table_name)
            source_column_types = {col['name']: col['type']
                                   for col in source_columns}

            # Get constraints from source database
            pk_constraint = inspector.get_pk_constraint(table_name)
            unique_constraints = inspector.get_unique_constraints(table_name)

            # Build encrypted table schema with original column names
            columns = []
            primary_keys = []
            unique_indexes = []

            for col_name, col_config in config.items():
                if col_config['type'] == 'encrypt':
                    # Safety check: encrypted columns should never be primary keys
                    if pk_constraint and col_name in pk_constraint.get('constrained_columns', []):
                        error_msg = (
                            f"ERROR: Column '{col_name}' in table '{table_name}' is configured for encryption "
                            f"but it is a PRIMARY KEY. Primary keys cannot be encrypted because they must be "
                            f"searchable and indexable. Please reconfigure this column as 'normal' type."
                        )
                        logger.error(error_msg)
                        raise Exception(error_msg)
                    
                    # Encrypted columns: use appropriate BLOB type for target database
                    if target_db_type == "postgresql":
                        blob_type = "BYTEA"
                    else:
                        blob_type = "BLOB"

                    columns.append(f"{col_name} {blob_type}")
                    columns.append(f"tag_{col_name} TEXT")


                else:
                    # Normal columns: preserve original type and auto-increment
                    source_type_obj = source_column_types.get(col_name)
                    if source_type_obj is not None:
                        # Handle ENUM types specially to include enum values
                        if hasattr(source_type_obj, 'enums') and source_type_obj.enums:
                            # This is an ENUM type - include the enum values
                            enum_values = ', '.join(
                                f"'{enum_val}'" for enum_val in source_type_obj.enums)
                            source_type = f"ENUM({enum_values})"
                        else:
                            source_type = str(source_type_obj)
                    else:
                        source_type = 'TEXT'

                    # Check if source column was auto-increment
                    source_col_info = None
                    for col in source_columns:
                        if col['name'] == col_name:
                            source_col_info = col
                            break

                    is_auto_increment = False
                    if source_col_info and getattr(source_col_info.get('type', None), 'autoincrement', False):
                        is_auto_increment = True

                    # Also add auto-increment for single-column primary key integer columns
                    if (pk_constraint and
                        col_name in pk_constraint.get('constrained_columns', []) and
                        len(pk_constraint.get('constrained_columns', [])) == 1 and
                            'INT' in str(source_type).upper()):
                        is_auto_increment = True

                    # Apply database-specific auto-increment syntax
                    if is_auto_increment:
                        if target_db_type == "postgresql":
                            # For PostgreSQL, use SERIAL instead of INTEGER AUTO_INCREMENT
                            if 'INTEGER' in source_type.upper() or 'INT' in source_type.upper():
                                source_type = 'SERIAL'
                            else:
                                source_type = 'SERIAL'  # fallback for other types
                        elif target_db_type == "mysql":
                            source_type += ' AUTO_INCREMENT'
                        elif target_db_type == "sqlite":
                            source_type += ' AUTOINCREMENT'
                        # For MSSQL, IDENTITY is handled differently, skip for now

                    columns.append(f"{col_name} {source_type}")

                    # Preserve primary key constraints for normal columns
                    if pk_constraint and col_name in pk_constraint.get('constrained_columns', []):
                        primary_keys.append(col_name)

                    # Preserve unique constraints for normal columns
                    for unique_constraint in unique_constraints:
                        if col_name in unique_constraint.get('column_names', []):
                            unique_indexes.append(
                                f"CREATE UNIQUE INDEX idx_{table_name}_{col_name} ON {table_name}({col_name})")

            # Add primary key constraint if any
            if primary_keys:
                columns.append(f"PRIMARY KEY ({', '.join(primary_keys)})")

            # Drop table if it exists to ensure clean schema
            drop_sql = f"DROP TABLE IF EXISTS {table_name}"
            with encrypted_engine.begin() as conn:
                conn.execute(text(drop_sql))

            # Create table in encrypted database
            create_sql = f"CREATE TABLE {table_name} ({', '.join(columns)})"
            logger.info(f"Creating table {table_name} with SQL: {create_sql}")

            with encrypted_engine.begin() as conn:
                conn.execute(text(create_sql))

                # Create unique indexes for normal columns that had unique constraints
                for unique_sql in unique_indexes:
                    try:
                        conn.execute(text(unique_sql))
                    except Exception as e:
                        logger.warning(f"Failed to create unique index: {e}")

            logger.info(
                f"Created encrypted schema for table: {table_name} with {len(primary_keys)} primary keys and {len(unique_indexes)} unique constraints")

        source_engine.dispose()
        encrypted_engine.dispose()

    except Exception as e:
        logger.error(f"Error creating encrypted schema: {e}")
        raise e


def migrate_data_with_progress(migration_state):
    """Perform bulk data migration from source to encrypted database with progress tracking"""
    logger.info(
        "🔄 MIGRATE_DATA_WITH_PROGRESS FUNCTION CALLED - Starting data migration process")
    log_system_event(
        'INFO', 'MIGRATE_DATA_WITH_PROGRESS function called - starting migration process', source='migration')

    try:
        # Check if we have table configurations
        if not migration_state.get("table_configs"):
            return {"success": False, "error": "No table configurations found. Please configure columns before migration."}

        # Connect to source database
        source_engine = create_engine(migration_state["source_db_url"])

        # Connect to encrypted database
        encrypted_engine = create_engine(migration_state["encrypted_db_url"])

        total_migrated = 0
        total_tables = len(migration_state["table_configs"])

        log_system_event(
            'INFO', f'Starting migration of {total_tables} tables', source='migration')

        for table_index, (table_name, config) in enumerate(migration_state["table_configs"].items()):
            with migration_progress_lock:
                migration_progress.update({
                    'current_table': table_name,
                    'completed_tables': table_index,
                    'message': f'Migrating table: {table_name}'
                })

            log_system_event(
                'INFO', f'Migrating table: {table_name}', source='migration')

            # Count encrypted vs normal columns
            encrypted_cols = [
                col for col, cfg in config.items() if cfg.get('type') == 'encrypt']
            normal_cols = [col for col, cfg in config.items()
                           if cfg.get('type') == 'normal']
            log_system_event(
                'INFO', f'{table_name}: {len(encrypted_cols)} encrypted columns ({encrypted_cols}), {len(normal_cols)} normal columns ({normal_cols})', source='migration')

            try:
                # Read all data from source table
                with source_engine.connect() as source_conn:
                    result = source_conn.execute(
                        text(f"SELECT * FROM {table_name}"))
                    rows = result.fetchall()
                    column_names = result.keys()

                log_system_event(
                    'INFO', f'Found {len(rows)} rows in {table_name}', source='migration')

                # Process rows in batches for bulk encryption
                batch_size = 100  # Process 100 rows at a time
                total_rows = len(rows)

                for i in range(0, total_rows, batch_size):
                    batch_rows = rows[i:i + batch_size]
                    batch_progress = (i + len(batch_rows)) / total_rows

                    # Update progress for current table
                    table_progress = (
                        table_index + batch_progress) / total_tables * 100
                    with migration_progress_lock:
                        migration_progress.update({
                            'progress': round(table_progress, 1),
                            'message': f'Migrating {table_name}: {i + len(batch_rows)}/{total_rows} rows'
                        })

                    # Prepare batch data for bulk operations
                    encrypted_batch = []

                    for row in batch_rows:
                        # Convert row to dict
                        row_dict = dict(zip(column_names, row))

                        # Prepare encrypted row data using original column names
                        enc_row_data = {}

                        for col_name, value in row_dict.items():
                            if col_name in config:
                                col_config = config[col_name]

                                if col_config['type'] == 'encrypt':
                                    # Encrypt individual value and store in original column name
                                    encrypted_blob = clwe_encryptor.encrypt_value(
                                        value, settings.CRYPTOPIX_DEFAULT_PASSWORD)
                                    enc_row_data[col_name] = encrypted_blob

                                    # Generate unified tag for searching and store in tag column
                                    str_value = str(
                                        value) if value is not None else ''
                                    unified_tag = clwe_encryptor.generate_unified_tag(
                                        str_value, col_config['data_type'])
                                    enc_row_data[f"tag_{col_name}"] = unified_tag

                                else:  # normal
                                    # Normal column - store as-is
                                    enc_row_data[col_name] = value

                        encrypted_batch.append(enc_row_data)

                    # Bulk insert the encrypted batch
                    if encrypted_batch:
                        # Build column list and named placeholders
                        all_columns = list(encrypted_batch[0].keys())
                        placeholders = ', '.join(
                            [f':{col}' for col in all_columns])
                        insert_sql = f"INSERT INTO {table_name} ({', '.join(all_columns)}) VALUES ({placeholders})"

                        # Insert each row individually for BLOB compatibility
                        with encrypted_engine.begin() as enc_conn:
                            for row_data in encrypted_batch:
                                enc_conn.execute(text(insert_sql), row_data)

                total_migrated += total_rows
                log_system_event(
                    'INFO', f'Migrated {total_rows} rows from {table_name}', source='migration')

                # Update progress after completing table
                with migration_progress_lock:
                    migration_progress['completed_tables'] = table_index + 1

            except Exception as e:
                log_system_event(
                    'ERROR', f'Failed to migrate table {table_name}: {str(e)}', source='migration')
                source_engine.dispose()
                encrypted_engine.dispose()
                return {"success": False, "error": f"Failed to migrate table {table_name}: {str(e)}"}

        source_engine.dispose()
        encrypted_engine.dispose()

        log_system_event(
            'INFO', f'Total migrated: {total_migrated} rows across {total_tables} tables', source='migration')

        return {"success": True, "total_migrated": total_migrated, "total_tables": total_tables}

    except Exception as e:
        log_system_event(
            'ERROR', f'Migration error: {str(e)}', source='migration')
        return {"success": False, "error": f"Migration failed: {str(e)}"}


def migrate_data():
    """Perform bulk data migration from source to encrypted database using original column names"""
    logger.info(
        "🔄 MIGRATE_DATA FUNCTION CALLED - Starting data migration process")
    log_system_event(
        'INFO', 'MIGRATE_DATA function called - starting migration process', source='migration')

    # Load migration state from files
    migration_state = load_migration_state_from_files()
    log_system_event(
        'INFO', f'Loaded migration state for migration: encrypted_db={migration_state.get("encrypted_db_url")}, tables={len(migration_state.get("table_configs", {}))}', source='migration')
    logger.info(
        f"📋 Migration state loaded: {migration_state.get('encrypted_db_url')}")

    try:
        # Check if we have table configurations
        if not migration_state.get("table_configs"):
            return {"success": False, "error": "No table configurations found. Please configure columns before migration."}

        # Connect to source database
        source_engine = create_engine(migration_state["source_db_url"])

        # Connect to encrypted database
        encrypted_engine = create_engine(migration_state["encrypted_db_url"])

        total_migrated = 0
        total_tables = len(migration_state["table_configs"])

        log_system_event(
            'INFO', f'Starting migration of {total_tables} tables', source='migration')

        for table_name, config in migration_state["table_configs"].items():
            log_system_event(
                'INFO', f'Migrating table: {table_name}', source='migration')
            log_system_event(
                'INFO', f'Column configuration for {table_name}: {config}', source='migration')

            # Count encrypted vs normal columns
            encrypted_cols = [
                col for col, cfg in config.items() if cfg.get('type') == 'encrypt']
            normal_cols = [col for col, cfg in config.items()
                           if cfg.get('type') == 'normal']
            log_system_event(
                'INFO', f'{table_name}: {len(encrypted_cols)} encrypted columns ({encrypted_cols}), {len(normal_cols)} normal columns ({normal_cols})', source='migration')

            try:
                # Read all data from source table
                with source_engine.connect() as source_conn:
                    result = source_conn.execute(
                        text(f"SELECT * FROM {table_name}"))
                    rows = result.fetchall()
                    column_names = result.keys()

                log_system_event(
                    'INFO', f'Found {len(rows)} rows in {table_name}', source='migration')

                # Process rows in batches for bulk encryption
                batch_size = 100  # Process 100 rows at a time

                for i in range(0, len(rows), batch_size):
                    batch_rows = rows[i:i + batch_size]
                    log_system_event(
                        'DEBUG', f'Processing batch {i//batch_size + 1} with {len(batch_rows)} rows for table {table_name}', source='migration')

                    # Prepare batch data for bulk operations
                    encrypted_batch = []

                    for row in batch_rows:
                        # Convert row to dict
                        row_dict = dict(zip(column_names, row))

                        # Prepare encrypted row data using original column names
                        enc_row_data = {}

                        for col_name, value in row_dict.items():
                            if col_name in config:
                                col_config = config[col_name]

                                if col_config['type'] == 'encrypt':
                                    # Encrypt individual value and store in original column name
                                    log_system_event(
                                        'DEBUG', f'Encrypting column {table_name}.{col_name} with value type {type(value)}', source='migration')
                                    encrypted_blob = clwe_encryptor.encrypt_value(
                                        value, settings.CRYPTOPIX_DEFAULT_PASSWORD)
                                    enc_row_data[col_name] = encrypted_blob
                                    log_system_event(
                                        'DEBUG', f'Encrypted {table_name}.{col_name} to binary data of size {len(encrypted_blob)} bytes', source='migration')

                                    # Generate unified tag for searching and store in tag column
                                    str_value = str(
                                        value) if value is not None else ''
                                    unified_tag = clwe_encryptor.generate_unified_tag(
                                        str_value, col_config['data_type'])
                                    enc_row_data[f"tag_{col_name}"] = unified_tag
                                    log_system_event(
                                        'DEBUG', f'Generated tag for {table_name}.{col_name}: {unified_tag}', source='migration')

                                else:  # normal
                                    # Normal column - store as-is
                                    log_system_event(
                                        'DEBUG', f'Storing {table_name}.{col_name} as normal data (type: {col_config["type"]})', source='migration')
                                    enc_row_data[col_name] = value

                        encrypted_batch.append(enc_row_data)

                    # Bulk insert the encrypted batch
                    if encrypted_batch:
                        # Build column list and named placeholders
                        all_columns = list(encrypted_batch[0].keys())
                        placeholders = ', '.join(
                            [f':{col}' for col in all_columns])
                        insert_sql = f"INSERT INTO {table_name} ({', '.join(all_columns)}) VALUES ({placeholders})"

                        # Insert each row individually for BLOB compatibility
                        with encrypted_engine.begin() as enc_conn:
                            for row_data in encrypted_batch:
                                enc_conn.execute(text(insert_sql), row_data)

                total_migrated += len(rows)
                log_system_event(
                    'INFO', f'Migrated {len(rows)} rows from {table_name}', source='migration')

            except Exception as e:
                log_system_event(
                    'ERROR', f'Failed to migrate table {table_name}: {str(e)}', source='migration')
                source_engine.dispose()
                encrypted_engine.dispose()
                return {"success": False, "error": f"Failed to migrate table {table_name}: {str(e)}"}

        source_engine.dispose()
        encrypted_engine.dispose()

        log_system_event(
            'INFO', f'Total migrated: {total_migrated} rows across {total_tables} tables', source='migration')

        return {"success": True, "total_migrated": total_migrated, "total_tables": total_tables}

    except Exception as e:
        log_system_event(
            'ERROR', f'Migration error: {str(e)}', source='migration')
        return {"success": False, "error": f"Migration failed: {str(e)}"}


def get_database_size(db_url: str) -> dict:
    """Get database file size and basic statistics for all supported database types"""
    try:
        logger.info(f"Getting database size for URL: {db_url}")

        if db_url.startswith('sqlite:///'):
            # SQLite database - get file size
            db_path = db_url.replace('sqlite:///', '')
            logger.info(f"SQLite database path: {db_path}")
            if os.path.exists(db_path):
                size_bytes = os.path.getsize(db_path)
                size_mb = size_bytes / (1024 * 1024)
                size_gb = size_bytes / (1024 * 1024 * 1024)
                logger.info(f"SQLite database size: {size_mb:.2f} MB")
                return {
                    'size_bytes': size_bytes,
                    'size_mb': round(size_mb, 2),
                    'size_gb': round(size_gb, 2),
                    'size_formatted': f"{size_mb:.2f} MB" if size_mb < 1024 else f"{size_gb:.2f} GB",
                    'exists': True,
                    'database_type': 'SQLite'
                }
            else:
                logger.warning(
                    f"SQLite database file does not exist: {db_path}")
                return {
                    'size_bytes': 0,
                    'size_mb': 0,
                    'size_gb': 0,
                    'size_formatted': '0 MB',
                    'exists': False,
                    'database_type': 'SQLite'
                }

        # For remote databases, get actual database size
        logger.info(f"Connecting to remote database: {db_url}")
        engine = create_engine(db_url)

        with engine.connect() as conn:
            logger.info("Successfully connected to database")
            total_size_bytes = 0
            database_type = "Unknown"

            if 'mysql+pymysql' in db_url.lower() or 'mysql+mysqldb' in db_url.lower() or 'mysql' in db_url.lower():
                logger.info("Detected MySQL database")
                database_type = "MySQL"
                try:
                    # Get MySQL database size
                    result = conn.execute(text("""
                        SELECT
                            ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) as size_mb,
                            SUM(data_length + index_length) as size_bytes
                        FROM information_schema.tables
                        WHERE table_schema = DATABASE()
                    """))
                    row = result.fetchone()
                    if row and row[1]:
                        size_mb = float(row[0] or 0)
                        size_bytes = int(row[1] or 0)
                        size_gb = size_bytes / (1024 * 1024 * 1024)
                    else:
                        size_mb = 0
                        size_bytes = 0
                        size_gb = 0
                except Exception as e:
                    logger.warning(f"MySQL size calculation failed: {e}")
                    size_mb = 0
                    size_bytes = 0
                    size_gb = 0

            elif 'postgresql' in db_url.lower():
                database_type = "PostgreSQL"
                try:
                    # Get PostgreSQL database size
                    result = conn.execute(text("""
                        SELECT
                            pg_size_pretty(pg_database_size(current_database())) as size_formatted,
                            pg_database_size(current_database()) as size_bytes
                    """))
                    row = result.fetchone()
                    if row:
                        size_formatted = row[0]
                        size_bytes = int(row[1])
                        size_mb = size_bytes / (1024 * 1024)
                        size_gb = size_bytes / (1024 * 1024 * 1024)
                    else:
                        size_mb = 0
                        size_bytes = 0
                        size_gb = 0
                        size_formatted = "0 MB"
                except Exception as e:
                    logger.warning(f"PostgreSQL size calculation failed: {e}")
                    size_mb = 0
                    size_bytes = 0
                    size_gb = 0
                    size_formatted = "Error"

            elif 'mssql' in db_url.lower() or 'sqlserver' in db_url.lower():
                database_type = "SQL Server"
                try:
                    # Get SQL Server database size
                    result = conn.execute(text("""
                        SELECT
                            SUM(size * 8.0 / 1024 / 1024) as size_mb,
                            SUM(size * 8.0) as size_kb
                        FROM sys.master_files
                        WHERE database_id = DB_ID()
                    """))
                    row = result.fetchone()
                    if row and row[1]:
                        size_kb = float(row[1])
                        size_bytes = size_kb * 1024
                        size_mb = size_kb / 1024
                        size_gb = size_mb / 1024
                    else:
                        size_mb = 0
                        size_bytes = 0
                        size_gb = 0
                except Exception as e:
                    logger.warning(f"SQL Server size calculation failed: {e}")
                    size_mb = 0
                    size_bytes = 0
                    size_gb = 0

            elif 'oracle' in db_url.lower():
                database_type = "Oracle"
                try:
                    # Get Oracle database size
                    result = conn.execute(text("""
                        SELECT
                            ROUND(SUM(bytes) / 1024 / 1024, 2) as size_mb,
                            SUM(bytes) as size_bytes
                        FROM dba_data_files
                    """))
                    row = result.fetchone()
                    if row and row[1]:
                        size_mb = float(row[0] or 0)
                        size_bytes = int(row[1] or 0)
                        size_gb = size_bytes / (1024 * 1024 * 1024)
                    else:
                        size_mb = 0
                        size_bytes = 0
                        size_gb = 0
                except Exception as e:
                    logger.warning(f"Oracle size calculation failed: {e}")
                    size_mb = 0
                    size_bytes = 0
                    size_gb = 0

            elif 'mongodb' in db_url.lower():
                database_type = "MongoDB"
                try:
                    # For MongoDB, we'd need different handling
                    # This is a placeholder - MongoDB size calculation would require pymongo
                    size_mb = 0
                    size_bytes = 0
                    size_gb = 0
                except Exception as e:
                    logger.warning(f"MongoDB size calculation failed: {e}")
                    size_mb = 0
                    size_bytes = 0
                    size_gb = 0

            else:
                database_type = "Unknown"
                # Generic fallback
                try:
                    result = conn.execute(text("SELECT 1"))
                    size_mb = 0
                    size_bytes = 0
                    size_gb = 0
                except:
                    size_mb = 0
                    size_bytes = 0
                    size_gb = 0

        engine.dispose()

        # Format the size
        if size_mb >= 1024:
            size_formatted = f"{size_gb:.2f} GB"
        elif size_mb > 0:
            size_formatted = f"{size_mb:.2f} MB"
        else:
            size_formatted = "0 MB"

        return {
            'size_bytes': size_bytes,
            'size_mb': round(size_mb, 2),
            'size_gb': round(size_gb, 2),
            'size_formatted': size_formatted,
            'exists': True,
            'database_type': database_type
        }

    except Exception as e:
        logger.error(f"Database size calculation failed: {e}")
        return {
            'size_bytes': 0,
            'size_mb': 0,
            'size_gb': 0,
            'size_formatted': 'Error',
            'exists': False,
            'database_type': 'Unknown',
            'error': str(e)
        }


def get_database_stats(db_url: str, db_type: str = "source") -> dict:
    """Get comprehensive database statistics"""
    # Load migration state from files
    migration_state = load_migration_state_from_files()

    try:
        engine = create_engine(db_url)
        stats = {
            'type': db_type,
            'connection_status': 'connected',
            'tables': [],
            'total_rows': 0,
            'encrypted_columns': 0,
            'hashed_columns': 0
        }

        with engine.connect() as conn:
            # Get table information
            if 'sqlite' in db_url:
                # SQLite specific
                result = conn.execute(text(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"))
                tables = [row[0] for row in result.fetchall()]
            else:
                # Other databases
                try:
                    if 'mysql' in db_url:
                        result = conn.execute(text("SHOW TABLES"))
                    elif 'postgresql' in db_url:
                        result = conn.execute(
                            text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'"))
                    else:
                        result = conn.execute(text(
                            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'dbo'"))
                    tables = [row[0] for row in result.fetchall()]
                except Exception as e:
                    logger.warning(f"Error getting tables for {db_url}: {e}")
                    tables = []

            # Get stats for each table
            for table in tables:
                try:
                    # Get row count
                    result = conn.execute(
                        text(f"SELECT COUNT(*) FROM {table}"))
                    row_count = result.fetchone()[0]

                    # Get column info
                    if 'sqlite' in db_url:
                        result = conn.execute(
                            text(f"PRAGMA table_info({table})"))
                        columns = result.fetchall()
                        column_names = [col[1] for col in columns]
                    else:
                        try:
                            if 'mysql' in db_url:
                                result = conn.execute(
                                    text(f"DESCRIBE {table}"))
                                column_names = [row[0]
                                                for row in result.fetchall()]
                            elif 'postgresql' in db_url:
                                result = conn.execute(text(
                                    f"SELECT column_name FROM information_schema.columns WHERE table_name = '{table}' AND table_schema = 'public'"))
                                column_names = [row[0]
                                                for row in result.fetchall()]
                            else:
                                # SQL Server and others
                                result = conn.execute(text(
                                    f"SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = '{table}'"))
                                column_names = [row[0]
                                                for row in result.fetchall()]
                        except Exception as e:
                            logger.warning(
                                f"Error getting columns for table {table}: {e}")
                            column_names = []

                    # Count encrypted/hashed columns based on migration state
                    enc_cols = 0
                    hash_cols = 0

                    if migration_state.get('table_configs') and table in migration_state['table_configs']:
                        table_config = migration_state['table_configs'][table]
                        for col_config in table_config.values():
                            if col_config.get('type') == 'encrypt':
                                enc_cols += 1
                            elif col_config.get('type') == 'hashed':
                                hash_cols += 1

                    stats['tables'].append({
                        'name': table,
                        'rows': row_count,
                        'columns': len(column_names),
                        'encrypted_columns': enc_cols,
                        'hashed_columns': hash_cols
                    })

                    stats['total_rows'] += row_count
                    stats['encrypted_columns'] += enc_cols
                    stats['hashed_columns'] += hash_cols

                except Exception as e:
                    stats['tables'].append({
                        'name': table,
                        'rows': 0,
                        'columns': 0,
                        'encrypted_columns': 0,
                        'hashed_columns': 0,
                        'error': str(e)
                    })

        engine.dispose()
        return stats

    except Exception as e:
        return {
            'type': db_type,
            'connection_status': 'disconnected',
            'error': str(e),
            'tables': [],
            'total_rows': 0,
            'encrypted_columns': 0,
            'hashed_columns': 0
        }


def get_system_stats() -> dict:
    """Get system and application statistics"""
    import datetime

    if not PSUTIL_AVAILABLE or psutil is None:
        return {
            'memory': {'total': 0, 'used': 0, 'percent': 0},
            'cpu': 0,
            'disk': {'total': 0, 'used': 0, 'free': 0, 'percent': 0},
            'uptime': "N/A",
            'timestamp': datetime.datetime.now().isoformat(),
            'psutil_available': False
        }

    try:
        # Memory usage
        memory = psutil.virtual_memory()
        memory_usage = {
            'total': round(memory.total / (1024**3), 2),  # GB
            'used': round(memory.used / (1024**3), 2),    # GB
            'percent': memory.percent
        }

        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)

        # Disk usage
        disk = psutil.disk_usage('/')
        disk_usage = {
            'total': round(disk.total / (1024**3), 2),  # GB
            'used': round(disk.used / (1024**3), 2),    # GB
            'free': round(disk.free / (1024**3), 2),    # GB
            'percent': disk.percent
        }

        return {
            'memory': memory_usage,
            'cpu': cpu_percent,
            'disk': disk_usage,
            'uptime': "N/A",  # Would need to track app start time
            'timestamp': datetime.datetime.now().isoformat(),
            'psutil_available': True
        }

    except Exception as e:
        return {
            'error': str(e),
            'memory': {'total': 0, 'used': 0, 'percent': 0},
            'cpu': 0,
            'disk': {'total': 0, 'used': 0, 'free': 0, 'percent': 0},
            'psutil_available': False
        }


def get_migration_progress() -> dict:
    """Get detailed migration progress and statistics"""
    # Load migration state from files
    migration_state = load_migration_state_from_files()

    if not migration_state.get("selected_tables"):
        return {'status': 'not_started', 'progress': 0}

    total_tables = len(migration_state["selected_tables"])
    completed_tables = 0

    if migration_state.get("migration_complete"):
        completed_tables = total_tables

    progress_percent = (completed_tables / total_tables *
                        100) if total_tables > 0 else 0

    return {
        'status': 'completed' if migration_state.get("migration_complete") else 'in_progress',
        'progress': round(progress_percent, 1),
        'total_tables': total_tables,
        'completed_tables': completed_tables,
        'source_db': migration_state.get("source_db_url", "Not set"),
        'encrypted_db': migration_state.get("encrypted_db_url", "Not set"),
        'table_configs': migration_state.get("table_configs", {}),
        'selected_db_type': migration_state.get("selected_db_type", "Not selected")
    }


def update_database_config():
    """Update database configuration settings"""
    try:
        source_url = request.form.get('source_db_url', '').strip()
        encrypted_url = request.form.get('encrypted_db_url', '').strip()
        db_type = request.form.get('db_type', '').strip()

        # Validate inputs
        if not source_url or not encrypted_url:
            flash('Both source and encrypted database URLs are required', 'error')
            return redirect(url_for('settings_page'))

        # Test connections
        try:
            source_engine = create_engine(source_url)
            with source_engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            source_engine.dispose()
        except Exception as e:
            flash(f'Source database connection failed: {str(e)}', 'error')
            return redirect(url_for('settings_page'))

        try:
            encrypted_engine = create_engine(encrypted_url)
            with encrypted_engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            encrypted_engine.dispose()
        except Exception as e:
            flash(f'Encrypted database connection failed: {str(e)}', 'error')
            return redirect(url_for('settings_page'))

        # Load current migration state and update it
        migration_state = load_migration_state_from_files()
        migration_state["source_db_url"] = source_url
        migration_state["encrypted_db_url"] = encrypted_url
        migration_state["selected_db_type"] = db_type

        # Save updated state back to files
        db_id = save_migration_state_to_files(migration_state)
        if db_id:
            migration_state["db_id"] = db_id

        flash('Database configuration updated successfully!', 'success')
        return redirect(url_for('settings_page'))

    except Exception as e:
        logger.error(f"Database config update failed: {e}")
        flash(f'Failed to update database configuration: {str(e)}', 'error')
        return redirect(url_for('settings_page'))


def update_column_config():
    """Update column encryption configuration"""
    try:
        table_configs = {}

        # Get all form data for column configurations
        for key, value in request.form.items():
            if key.startswith('column_') and key.endswith('_config'):
                # Parse the key: column_tablename_columnname_config
                parts = key.split('_')
                if len(parts) >= 4:
                    table_name = parts[1]
                    # Handle column names with underscores
                    column_name = '_'.join(parts[2:-1])

                    if table_name not in table_configs:
                        table_configs[table_name] = {}

                    # Get column data type from the form
                    data_type_key = f"datatype_{table_name}_{column_name}"
                    data_type = request.form.get(data_type_key, 'text')

                    table_configs[table_name][column_name] = {
                        'type': value,  # 'encrypted', 'hashed', or 'normal'
                        'data_type': data_type
                    }

        # Load current migration state and update it
        migration_state = load_migration_state_from_files()
        migration_state["table_configs"] = table_configs

        # Save updated state back to files
        db_id = save_migration_state_to_files(migration_state)
        if db_id:
            migration_state["db_id"] = db_id

        flash('Column configuration updated successfully!', 'success')
        return redirect(url_for('settings_page'))

    except Exception as e:
        logger.error(f"Column config update failed: {e}")
        flash(f'Failed to update column configuration: {str(e)}', 'error')
        return redirect(url_for('settings_page'))


def regenerate_schema():
    """Regenerate database schema based on new column configurations"""
    try:
        # Load migration state from files
        migration_state = load_migration_state_from_files()

        if not migration_state.get("encrypted_db_url"):
            flash('No encrypted database configured', 'error')
            return redirect(url_for('settings_page'))

        if not migration_state.get("table_configs"):
            flash('No column configurations found', 'error')
            return redirect(url_for('settings_page'))

        # Connect to encrypted database
        encrypted_engine = create_engine(migration_state["encrypted_db_url"])

        # Regenerate schema for each table
        for table_name, config in migration_state["table_configs"].items():
            # Get current columns from database
            inspector = inspect(encrypted_engine)
            try:
                current_columns = inspector.get_columns(table_name)
                current_column_names = [col['name'] for col in current_columns]

                # Build new schema based on configuration
                columns = []

                for col_name, col_config in config.items():
                    if col_config['type'] == 'encrypt':
                        # Encrypted columns: store as BLOB with tag
                        columns.extend(
                            [f"{col_name}_enc BLOB", f"tag_{col_name} TEXT"])
                    elif col_config['type'] == 'hashed':
                        # Hashed columns: use original name, store as TEXT (no tag column)
                        columns.append(f"{col_name} TEXT")
                    else:
                        # Normal columns: preserve original type
                        # Try to get original type from current schema
                        original_type = 'TEXT'  # Default
                        for curr_col in current_columns:
                            if curr_col['name'] == col_name:
                                # Handle ENUM types specially to include enum values
                                if hasattr(curr_col.type, 'enums') and curr_col.type.enums:
                                    # This is an ENUM type - include the enum values
                                    enum_values = ', '.join(
                                        f"'{enum_val}'" for enum_val in curr_col.type.enums)
                                    original_type = f"ENUM({enum_values})"
                                else:
                                    original_type = str(curr_col.type)
                                break
                            elif curr_col['name'] == f"{col_name}_enc":
                                # If it was previously encrypted, get the original type
                                # Handle ENUM types specially to include enum values
                                if hasattr(curr_col.type, 'enums') and curr_col.type.enums:
                                    # This is an ENUM type - include the enum values
                                    enum_values = ', '.join(
                                        f"'{enum_val}'" for enum_val in curr_col.type.enums)
                                    original_type = f"ENUM({enum_values})"
                                else:
                                    original_type = str(curr_col.type)
                                break
                            elif curr_col['name'] == f"{col_name}_enc":
                                # If it was previously encrypted, get the original type
                                # Handle ENUM types specially to include enum values
                                if hasattr(curr_col.type, 'enums') and curr_col.type.enums:
                                    # This is an ENUM type - include the enum values
                                    enum_values = ', '.join(
                                        f"'{enum_val}'" for enum_val in curr_col.type.enums)
                                    original_type = f"ENUM({enum_values})"
                                else:
                                    original_type = str(curr_col.type)
                                break
                        columns.append(f"{col_name} {original_type}")

                # Create new table with updated schema
                new_table_name = f"{table_name}_new"
                create_sql = f"CREATE TABLE {new_table_name} ({', '.join(columns)})"

                with encrypted_engine.begin() as conn:
                    conn.execute(text(create_sql))

                # Migrate data from old table to new table
                # This is a simplified version - in production you'd need more sophisticated migration
                if current_columns:
                    # Build migration query
                    source_cols = []
                    target_cols = []

                    for col_name, col_config in config.items():
                        if col_config['type'] == 'encrypt':
                            # Find original data in old schema
                            if col_name in current_column_names:
                                source_cols.append(col_name)
                                target_cols.append(col_name)
                            # Data is already encrypted, copy as-is (no _enc suffix now)
                        else:  # normal
                            if col_name in current_column_names:
                                source_cols.append(col_name)
                                target_cols.append(col_name)

                    if source_cols and target_cols:
                        migrate_sql = f"INSERT INTO {new_table_name} ({', '.join(target_cols)}) SELECT {', '.join(source_cols)} FROM {table_name}"
                        with encrypted_engine.begin() as conn:
                            conn.execute(text(migrate_sql))

                # Drop old table and rename new table
                with encrypted_engine.begin() as conn:
                    conn.execute(text(f"DROP TABLE {table_name}"))
                    conn.execute(
                        text(f"ALTER TABLE {new_table_name} RENAME TO {table_name}"))

                logger.info(f"Schema regenerated for table: {table_name}")

            except Exception as e:
                logger.error(
                    f"Error regenerating schema for table {table_name}: {e}")
                continue

        encrypted_engine.dispose()

        flash('Database schema regenerated successfully!', 'success')
        return redirect(url_for('settings_page'))

    except Exception as e:
        logger.error(f"Schema regeneration failed: {e}")
        flash(f'Failed to regenerate schema: {str(e)}', 'error')
        return redirect(url_for('settings_page'))


def update_encrypted_database_config():
    """Update encrypted database configuration settings"""
    try:
        encrypted_url = request.form.get('encrypted_db_url', '').strip()
        db_type = request.form.get('db_type', '').strip()

        # Validate inputs
        if not encrypted_url:
            flash('Encrypted database URL is required', 'error')
            return redirect(url_for('settings_page'))

        # Test connection
        try:
            test_engine = create_engine(encrypted_url)
            with test_engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            test_engine.dispose()
        except Exception as e:
            flash(f'Encrypted database connection failed: {str(e)}', 'error')
            return redirect(url_for('settings_page'))

        # Load current migration state and update it
        migration_state = load_migration_state_from_files()
        migration_state["encrypted_db_url"] = encrypted_url
        migration_state["selected_db_type"] = db_type

        # Save updated state back to files
        db_id = save_migration_state_to_files(migration_state)
        if db_id:
            migration_state["db_id"] = db_id

        flash('Encrypted database configuration updated successfully!', 'success')
        return redirect(url_for('settings_page'))

    except Exception as e:
        logger.error(f"Encrypted database config update failed: {e}")
        flash(
            f'Failed to update encrypted database configuration: {str(e)}', 'error')
        return redirect(url_for('settings_page'))


def reconfigure_encrypted_database():
    """Reconfigure encrypted database schema and column settings"""
    try:
        # Load migration state from files
        migration_state = load_migration_state_from_files()

        if not migration_state.get("encrypted_db_url"):
            flash(
                'No encrypted database configured. Please configure encrypted database first.', 'error')
            return redirect(url_for('settings_page'))

        # Parse column configurations from form
        new_table_configs = {}

        for key, value in request.form.items():
            if key.startswith('column_') and key.endswith('_config'):
                # Parse the key: column_tablename_columnname_config
                parts = key.replace('column_', '').replace(
                    '_config', '').split('_', 1)
                if len(parts) >= 2:
                    table_name = parts[0]
                    column_name = parts[1]

                    if table_name not in new_table_configs:
                        new_table_configs[table_name] = {}

                    # Get column data type from the form
                    data_type_key = f"datatype_{table_name}_{column_name}"
                    data_type = request.form.get(data_type_key, 'TEXT')

                    new_table_configs[table_name][column_name] = {
                        'type': value,  # 'encrypt' or 'normal'
                        'data_type': data_type
                    }

        if not new_table_configs:
            flash(
                'No column configurations found. Please select encryption settings for columns.', 'error')
            return redirect(url_for('settings_page'))

        # Get old configuration for comparison
        old_table_configs = migration_state.get("table_configs", {})

        # Log the reconfiguration
        log_system_event(
            'INFO', f'Starting database reconfiguration with {len(new_table_configs)} tables', source='reconfiguration')

        # Perform reconfiguration with data migration
        reconfigure_schema_and_data(
            migration_state, old_table_configs, new_table_configs)

        # Update migration state with new configuration
        migration_state["table_configs"] = new_table_configs

        # Save updated state back to files
        db_id = save_migration_state_to_files(migration_state)
        if db_id:
            migration_state["db_id"] = db_id

        flash('Database reconfiguration completed successfully! Columns have been re-encrypted according to new settings.', 'success')
        log_system_event(
            'INFO', 'Database reconfiguration completed successfully', source='reconfiguration')
        return redirect(url_for('settings_page'))

    except Exception as e:
        logger.error(f"Encrypted database reconfiguration failed: {e}")
        log_system_event(
            'ERROR', f'Database reconfiguration failed: {str(e)}', source='reconfiguration')
        flash(f'Failed to reconfigure encrypted database: {str(e)}', 'error')
        return redirect(url_for('settings_page'))


def reconfigure_schema_and_data(migration_state, old_configs, new_configs):
    """Reconfigure schema and migrate data according to new encryption settings"""
    try:
        encrypted_engine = create_engine(migration_state["encrypted_db_url"])
        inspector = inspect(encrypted_engine)

        # Connect to source database to get original data types if needed
        source_engine = None
        source_inspector = None
        if migration_state.get("source_db_url"):
            try:
                source_engine = create_engine(migration_state["source_db_url"])
                source_inspector = inspect(source_engine)
            except:
                pass  # Source DB might not be available

        # Determine target database type
        target_db_type = "mysql"
        if "postgresql" in migration_state["encrypted_db_url"].lower():
            target_db_type = "postgresql"
        elif "sqlite" in migration_state["encrypted_db_url"].lower():
            target_db_type = "sqlite"

        for table_name, new_config in new_configs.items():
            log_system_event(
                'INFO', f'Reconfiguring table: {table_name}', source='reconfiguration')

            # Get old config for this table
            old_config = old_configs.get(table_name, {})

            # Get original column types from source database if available
            source_column_types = {}
            if source_inspector:
                try:
                    source_columns = source_inspector.get_columns(table_name)
                    source_column_types = {col['name']: str(
                        col['type']) for col in source_columns}
                except:
                    pass  # Table might not exist in source

            # Read all existing data from the table
            with encrypted_engine.connect() as conn:
                result = conn.execute(text(f"SELECT * FROM {table_name}"))
                rows = result.fetchall()
                column_names = result.keys()

            log_system_event(
                'INFO', f'Found {len(rows)} rows in {table_name}', source='reconfiguration')

            # Create new table with updated schema
            new_table_name = f"{table_name}_reconfig"
            columns = []
            primary_keys = []

            # Get primary key info
            pk_constraint = inspector.get_pk_constraint(table_name)

            for col_name, col_config in new_config.items():
                if col_config['type'] == 'encrypt':
                    # Encrypted columns: use BLOB type
                    if target_db_type == "postgresql":
                        blob_type = "BYTEA"
                    else:
                        blob_type = "BLOB"

                    columns.append(f"{col_name} {blob_type}")
                    columns.append(f"tag_{col_name} TEXT")

                    # Preserve primary key
                    if pk_constraint and col_name in pk_constraint.get('constrained_columns', []):
                        primary_keys.append(col_name)

                else:  # normal
                    # Get the original data type with multiple fallbacks
                    # Priority: 1) old config, 2) source database, 3) default TEXT
                    old_col_config = old_config.get(col_name, {})

                    if old_col_config.get('type') == 'encrypt':
                        # Was encrypted, try to get original data_type from old config
                        data_type = old_col_config.get('data_type', None)

                        # If not in old config, try source database
                        if not data_type or 'BLOB' in str(data_type).upper() or 'BYTEA' in str(data_type).upper():
                            data_type = source_column_types.get(
                                col_name, 'TEXT')
                    else:
                        # Was normal, use current data_type
                        data_type = col_config.get('data_type', 'TEXT')

                        # If it's BLOB, try source database
                        if 'BLOB' in str(data_type).upper() or 'BYTEA' in str(data_type).upper():
                            data_type = source_column_types.get(
                                col_name, 'TEXT')

                    # Final cleanup - ensure no BLOB types for normal columns
                    data_type_upper = str(data_type).upper()
                    if 'BLOB' in data_type_upper or 'BYTEA' in data_type_upper:
                        # Default to TEXT if we somehow still got a BLOB type
                        data_type = 'TEXT'
                        log_system_event(
                            'WARNING', f'Column {col_name} had BLOB type, defaulting to TEXT', source='reconfiguration')

                    # Check for auto-increment
                    is_pk = pk_constraint and col_name in pk_constraint.get(
                        'constrained_columns', [])
                    if is_pk and len(pk_constraint.get('constrained_columns', [])) == 1 and 'INT' in str(data_type).upper():
                        if target_db_type == "postgresql":
                            data_type = 'SERIAL'
                        elif target_db_type == "mysql":
                            data_type += ' AUTO_INCREMENT'
                        elif target_db_type == "sqlite":
                            data_type += ' AUTOINCREMENT'

                    columns.append(f"{col_name} {data_type}")
                    log_system_event(
                        'DEBUG', f'Column {col_name} will use data type: {data_type}', source='reconfiguration')

                    if is_pk:
                        primary_keys.append(col_name)

            # Add primary key constraint
            if primary_keys:
                columns.append(f"PRIMARY KEY ({', '.join(primary_keys)})")

            # Create new table
            create_sql = f"CREATE TABLE {new_table_name} ({', '.join(columns)})"
            log_system_event(
                'INFO', f'Creating new table with SQL: {create_sql}', source='reconfiguration')

            with encrypted_engine.begin() as conn:
                conn.execute(text(create_sql))

            # Migrate and transform data
            for row in rows:
                row_dict = dict(zip(column_names, row))
                new_row_data = {}

                for col_name, col_config in new_config.items():
                    old_col_config = old_config.get(
                        col_name, {'type': 'normal'})
                    old_type = old_col_config.get('type', 'normal')
                    new_type = col_config['type']

                    # Get the value from old row
                    value = None
                    if col_name in row_dict:
                        value = row_dict[col_name]
                    elif f"tag_{col_name}" in row_dict:  # Was encrypted before
                        value = row_dict[col_name]

                    # Transform data based on old and new types
                    if old_type == 'encrypt' and new_type == 'encrypt':
                        # Already encrypted, keep as is
                        new_row_data[col_name] = value
                        if f"tag_{col_name}" in row_dict:
                            new_row_data[f"tag_{col_name}"] = row_dict[f"tag_{col_name}"]

                    elif old_type == 'encrypt' and new_type == 'normal':
                        # Decrypt the data and convert to proper type
                        if value:
                            try:
                                decrypted_value = clwe_encryptor.decrypt_value(
                                    value, settings.CRYPTOPIX_DEFAULT_PASSWORD)

                                # Convert bytes to appropriate type based on data_type
                                if isinstance(decrypted_value, bytes):
                                    # Decode bytes to string
                                    decrypted_str = decrypted_value.decode(
                                        'utf-8')

                                    # Try to convert to original data type
                                    data_type = col_config.get(
                                        'data_type', 'TEXT').upper()

                                    if 'INT' in data_type or 'SERIAL' in data_type:
                                        # Convert to integer
                                        try:
                                            new_row_data[col_name] = int(
                                                decrypted_str)
                                        except:
                                            new_row_data[col_name] = decrypted_str
                                    elif 'FLOAT' in data_type or 'DOUBLE' in data_type or 'DECIMAL' in data_type or 'NUMERIC' in data_type:
                                        # Convert to float
                                        try:
                                            new_row_data[col_name] = float(
                                                decrypted_str)
                                        except:
                                            new_row_data[col_name] = decrypted_str
                                    elif 'BOOL' in data_type:
                                        # Convert to boolean
                                        new_row_data[col_name] = decrypted_str.lower() in (
                                            'true', '1', 'yes')
                                    else:
                                        # Keep as string for TEXT, VARCHAR, CHAR, etc.
                                        new_row_data[col_name] = decrypted_str
                                else:
                                    # Already in proper format
                                    new_row_data[col_name] = decrypted_value
                            except Exception as e:
                                logger.warning(
                                    f"Failed to decrypt column {col_name}: {e}")
                                new_row_data[col_name] = None
                        else:
                            new_row_data[col_name] = None

                    elif old_type == 'normal' and new_type == 'encrypt':
                        # Encrypt the data
                        if value is not None:
                            encrypted_blob = clwe_encryptor.encrypt_value(
                                value, settings.CRYPTOPIX_DEFAULT_PASSWORD)
                            new_row_data[col_name] = encrypted_blob

                            # Generate tag
                            str_value = str(value)
                            unified_tag = clwe_encryptor.generate_unified_tag(
                                str_value, col_config['data_type'])
                            new_row_data[f"tag_{col_name}"] = unified_tag
                        else:
                            new_row_data[col_name] = None
                            new_row_data[f"tag_{col_name}"] = None

                    elif old_type == 'normal' and new_type == 'normal':
                        # Keep as normal
                        new_row_data[col_name] = value

                # Insert into new table
                if new_row_data:
                    all_columns = list(new_row_data.keys())
                    placeholders = ', '.join(
                        [f':{col}' for col in all_columns])
                    insert_sql = f"INSERT INTO {new_table_name} ({', '.join(all_columns)}) VALUES ({placeholders})"

                    with encrypted_engine.begin() as conn:
                        conn.execute(text(insert_sql), new_row_data)

            # Drop old table and rename new table
            with encrypted_engine.begin() as conn:
                conn.execute(text(f"DROP TABLE {table_name}"))
                conn.execute(
                    text(f"ALTER TABLE {new_table_name} RENAME TO {table_name}"))

            log_system_event(
                'INFO', f'Successfully reconfigured table: {table_name}', source='reconfiguration')

        encrypted_engine.dispose()
        if source_engine:
            source_engine.dispose()

    except Exception as e:
        logger.error(f"Schema reconfiguration failed: {e}")
        raise e


def demigrate_database():
    """Demigrate encrypted database back to regular database"""
    try:
        confirmation = request.form.get('confirm_demigration', '').strip()
        target_db_url = request.form.get('target_db_url', '').strip()

        if confirmation != 'DEMIGRATE':
            flash('Please type "DEMIGRATE" to confirm the operation', 'error')
            return redirect(url_for('settings_page'))

        if not target_db_url:
            flash('Target database URL is required', 'error')
            return redirect(url_for('settings_page'))

        db_id = request.form.get('db_id')

        # Load migration state from files
        migration_state = load_migration_state_from_files(db_id=db_id)

        if not migration_state.get("encrypted_db_url"):
            flash('No encrypted database configured', 'error')
            return redirect(url_for('settings_page'))

        # Perform demigration
        perform_demigration(target_db_url, db_id=db_id)

        flash('Database demigration completed successfully! Your data has been decrypted.', 'success')
        return redirect(url_for('settings_page'))

    except Exception as e:
        logger.error(f"Database demigration failed: {e}")
        flash(f'Failed to demigrate database: {str(e)}', 'error')
        return redirect(url_for('settings_page'))


def regenerate_encrypted_schema_with_cleanup():
    """Regenerate encrypted database schema based on new column configurations with tag cleanup"""
    try:
        # Load migration state from files
        migration_state = load_migration_state_from_files()

        if not migration_state.get("encrypted_db_url"):
            raise Exception("No encrypted database configured")

        if not migration_state.get("table_configs"):
            raise Exception("No column configurations found")

        # Determine target database type from encrypted URL
        target_db_type = "mysql"  # default
        if "postgresql" in migration_state["encrypted_db_url"].lower():
            target_db_type = "postgresql"
        elif "sqlite" in migration_state["encrypted_db_url"].lower():
            target_db_type = "sqlite"
        elif "mssql" in migration_state["encrypted_db_url"].lower():
            target_db_type = "mssql"

        # Connect to encrypted database
        encrypted_engine = create_engine(migration_state["encrypted_db_url"])

        # Get current schema to identify tag columns that need cleanup
        inspector = inspect(encrypted_engine)
        current_schema = {}

        for table_name in migration_state["table_configs"].keys():
            try:
                current_schema[table_name] = inspector.get_columns(table_name)
            except Exception as e:
                logger.warning(
                    f"Could not get schema for table {table_name}: {e}")
                current_schema[table_name] = []

        # Regenerate schema for each table
        for table_name, config in migration_state["table_configs"].items():
            try:
                current_columns = current_schema.get(table_name, [])
                current_column_names = [col['name'] for col in current_columns]

                # Identify columns being changed from encrypted to normal (need tag cleanup)
                columns_changing_from_encrypted = []
                for col_name, col_config in config.items():
                    if col_config['type'] == 'normal':  # New config is normal
                        # Check if it was previously encrypted (using migration state)
                        if migration_state.get('table_configs') and table_name in migration_state['table_configs']:
                            old_config = migration_state['table_configs'][table_name]
                            if col_name in old_config and old_config[col_name].get('type') == 'encrypt':
                                columns_changing_from_encrypted.append(
                                    col_name)

                # Build new schema based on configuration
                columns = []

                for col_name, col_config in config.items():
                    if col_config['type'] == 'encrypt':
                        # Encrypted columns: use appropriate BLOB type for target database
                        if target_db_type == "postgresql":
                            blob_type = "BYTEA"
                        else:
                            blob_type = "BLOB"

                        columns.extend(
                            [f"{col_name} {blob_type}", f"tag_{col_name} TEXT"])
                    else:
                        # Normal columns: preserve original type
                        # Try to get original type from current schema
                        original_type = 'TEXT'  # Default
                        for curr_col in current_columns:
                            if curr_col['name'] == col_name:
                                # Handle ENUM types specially to include enum values
                                if hasattr(curr_col.type, 'enums') and curr_col.type.enums:
                                    # This is an ENUM type - include the enum values
                                    enum_values = ', '.join(
                                        f"'{enum_val}'" for enum_val in curr_col.type.enums)
                                    original_type = f"ENUM({enum_values})"
                                else:
                                    original_type = str(curr_col.type)
                                break
                        columns.append(f"{col_name} {original_type}")

                # Create new table with updated schema
                new_table_name = f"{table_name}_reconfig"
                create_sql = f"CREATE TABLE {new_table_name} ({', '.join(columns)})"

                with encrypted_engine.begin() as conn:
                    conn.execute(text(create_sql))

                # Migrate data from old table to new table
                if current_columns:
                    # Build migration query
                    source_cols = []
                    target_cols = []

                    for col_name, col_config in config.items():
                        if col_config['type'] == 'encrypt':
                            # Find original data in old schema
                            if col_name in current_column_names:
                                source_cols.append(col_name)
                                target_cols.append(col_name)
                            # Data is already encrypted, copy as-is (no _enc suffix now)
                        else:  # normal
                            if col_name in current_column_names:
                                source_cols.append(col_name)
                                target_cols.append(col_name)

                    if source_cols and target_cols:
                        migrate_sql = f"INSERT INTO {new_table_name} ({', '.join(target_cols)}) SELECT {', '.join(source_cols)} FROM {table_name}"
                        with encrypted_engine.begin() as conn:
                            conn.execute(text(migrate_sql))

                            # If there are columns changing from encrypted to normal, decrypt the data
                            if columns_changing_from_encrypted:
                                for changing_col in columns_changing_from_encrypted:
                                    # Decrypt data in the new table
                                    decrypt_sql = f"""
                                        UPDATE {new_table_name}
                                        SET {changing_col} = ?
                                        WHERE {changing_col} IS NOT NULL
                                    """
                                    # Note: In a real implementation, you'd need to decrypt each value individually
                                    # This is a simplified version for demonstration
                                    logger.info(
                                        f"Would decrypt column {changing_col} in table {new_table_name}")

                # Drop old table and rename new table
                with encrypted_engine.begin() as conn:
                    conn.execute(text(f"DROP TABLE {table_name}"))
                    conn.execute(
                        text(f"ALTER TABLE {new_table_name} RENAME TO {table_name}"))

                logger.info(f"Schema reconfigured for table: {table_name}")

            except Exception as e:
                logger.error(
                    f"Error reconfiguring schema for table {table_name}: {e}")
                continue

        encrypted_engine.dispose()

    except Exception as e:
        logger.error(f"Schema reconfiguration with cleanup failed: {e}")
        raise e


def regenerate_encrypted_schema():
    """Regenerate encrypted database schema based on new column configurations"""
    try:
        # Load migration state from files
        migration_state = load_migration_state_from_files()

        if not migration_state.get("encrypted_db_url"):
            raise Exception("No encrypted database configured")

        if not migration_state.get("table_configs"):
            raise Exception("No column configurations found")

        # Determine target database type from encrypted URL
        target_db_type = "mysql"  # default
        if "postgresql" in migration_state["encrypted_db_url"].lower():
            target_db_type = "postgresql"
        elif "sqlite" in migration_state["encrypted_db_url"].lower():
            target_db_type = "sqlite"
        elif "mssql" in migration_state["encrypted_db_url"].lower():
            target_db_type = "mssql"

        # Connect to encrypted database
        encrypted_engine = create_engine(migration_state["encrypted_db_url"])

        # Regenerate schema for each table
        for table_name, config in migration_state["table_configs"].items():
            # Get current columns from database
            inspector = inspect(encrypted_engine)
            try:
                current_columns = inspector.get_columns(table_name)
                current_column_names = [col['name'] for col in current_columns]

                # Build new schema based on configuration
                columns = []

                for col_name, col_config in config.items():
                    if col_config['type'] == 'encrypt':
                        # Encrypted columns: use appropriate BLOB type for target database
                        if target_db_type == "postgresql":
                            blob_type = "BYTEA"
                        else:
                            blob_type = "BLOB"

                        columns.extend(
                            [f"{col_name} {blob_type}", f"tag_{col_name} TEXT"])
                    else:
                        # Normal columns: preserve original type
                        # Try to get original type from current schema
                        original_type = 'TEXT'  # Default
                        for curr_col in current_columns:
                            if curr_col['name'] == col_name:
                                # Handle ENUM types specially to include enum values
                                if hasattr(curr_col.type, 'enums') and curr_col.type.enums:
                                    # This is an ENUM type - include the enum values
                                    enum_values = ', '.join(
                                        f"'{enum_val}'" for enum_val in curr_col.type.enums)
                                    original_type = f"ENUM({enum_values})"
                                else:
                                    original_type = str(curr_col.type)
                                break
                        columns.append(f"{col_name} {original_type}")

                # Create new table with updated schema
                new_table_name = f"{table_name}_reconfig"
                create_sql = f"CREATE TABLE {new_table_name} ({', '.join(columns)})"

                with encrypted_engine.begin() as conn:
                    conn.execute(text(create_sql))

                # Migrate data from old table to new table
                if current_columns:
                    # Build migration query
                    source_cols = []
                    target_cols = []

                    for col_name, col_config in config.items():
                        if col_config['type'] == 'encrypt':
                            # Find original data in old schema
                            if col_name in current_column_names:
                                source_cols.append(col_name)
                                target_cols.append(col_name)
                        elif col_config['type'] == 'hashed':
                            if col_name in current_column_names:
                                source_cols.append(col_name)
                                target_cols.append(f"{col_name}_hash")
                            elif f"{col_name}_hash" in current_column_names:
                                source_cols.append(f"{col_name}_hash")
                                target_cols.append(f"{col_name}_hash")
                        else:  # normal
                            if col_name in current_column_names:
                                source_cols.append(col_name)
                                target_cols.append(col_name)

                    if source_cols and target_cols:
                        migrate_sql = f"INSERT INTO {new_table_name} ({', '.join(target_cols)}) SELECT {', '.join(source_cols)} FROM {table_name}"
                        with encrypted_engine.begin() as conn:
                            conn.execute(text(migrate_sql))

                # Drop old table and rename new table
                with encrypted_engine.begin() as conn:
                    conn.execute(text(f"DROP TABLE {table_name}"))
                    conn.execute(
                        text(f"ALTER TABLE {new_table_name} RENAME TO {table_name}"))

                logger.info(f"Schema reconfigured for table: {table_name}")

            except Exception as e:
                logger.error(
                    f"Error reconfiguring schema for table {table_name}: {e}")
                continue

        encrypted_engine.dispose()

    except Exception as e:
        logger.error(f"Schema reconfiguration failed: {e}")
        raise e


def perform_demigration(target_db_url: str, db_id: str = None):
    """Perform demigration from encrypted to regular database"""
    # Load migration state from files
    migration_state = load_migration_state_from_files(db_id=db_id)

    try:
        if not migration_state.get("encrypted_db_url"):
            raise Exception("No encrypted database configured")

        # Connect to encrypted database
        encrypted_engine = create_engine(migration_state["encrypted_db_url"])
        # Connect to target database
        target_engine = create_engine(target_db_url)

        # Get all tables from encrypted database
        inspector = inspect(encrypted_engine)
        table_names = inspector.get_table_names()

        for table_name in table_names:
            try:
                # Get table structure
                columns = inspector.get_columns(table_name)

                # Build regular table schema (remove enc_/tag_/hash_ prefixes)
                regular_columns = []
                column_mapping = {}  # Maps encrypted column names to regular names

                for col in columns:
                    col_name = col['name']
                    if col_name.startswith('tag_'):
                        # Tag column - skip (not needed in regular database)
                        continue
                    else:
                        # Check if this column is encrypted based on migration state
                        is_encrypted = False
                        if migration_state.get('table_configs') and table_name in migration_state['table_configs']:
                            table_config = migration_state['table_configs'][table_name]
                            if col_name in table_config and table_config[col_name].get('type') == 'encrypt':
                                is_encrypted = True

                        if is_encrypted:
                            # Encrypted column - convert to regular column
                            # Use TEXT for decrypted data
                            regular_columns.append(f"{col_name} TEXT")
                            column_mapping[col_name] = col_name
                        else:
                            # Normal column - keep as-is
                            regular_columns.append(f"{col_name} {col['type']}")
                            column_mapping[col_name] = col_name

                # Create regular table
                create_sql = f"CREATE TABLE IF NOT EXISTS {table_name} ({', '.join(regular_columns)})"
                with target_engine.begin() as conn:
                    conn.execute(text(create_sql))

                # Migrate and decrypt data
                with encrypted_engine.connect() as enc_conn:
                    result = enc_conn.execute(
                        text(f"SELECT * FROM {table_name}"))
                    rows = result.fetchall()
                    column_names = result.keys()

                # Process rows in batches
                batch_size = 100
                for i in range(0, len(rows), batch_size):
                    batch_rows = rows[i:i + batch_size]

                    for row in batch_rows:
                        # Convert row to dict
                        row_dict = dict(zip(column_names, row))

                        # Prepare decrypted row data
                        decrypted_row_data = {}

                        for col_name, value in row_dict.items():
                            if col_name in column_mapping:
                                regular_name = column_mapping[col_name]

                                # Check if this column is encrypted based on migration state
                                is_encrypted = False
                                if migration_state.get('table_configs') and table_name in migration_state['table_configs']:
                                    table_config = migration_state['table_configs'][table_name]
                                    if col_name in table_config and table_config[col_name].get('type') == 'encrypt':
                                        is_encrypted = True

                                if is_encrypted:
                                    decrypted_value = None
                                    try:
                                        if isinstance(value, bytes) and value:
                                            # Direct bytes data
                                            decrypted_value = clwe_encryptor.decrypt_value(
                                                value, settings.CRYPTOPIX_DEFAULT_PASSWORD)
                                        elif isinstance(value, str) and value.startswith('\\x') and len(value) > 2:
                                            # PostgreSQL BYTEA hex format: \x52494646...
                                            # Remove \x prefix
                                            hex_part = value[2:]
                                            if len(hex_part) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in hex_part):
                                                hex_bytes = bytes.fromhex(
                                                    hex_part)
                                                decrypted_value = clwe_encryptor.decrypt_value(
                                                    hex_bytes, settings.CRYPTOPIX_DEFAULT_PASSWORD)
                                        elif isinstance(value, str) and len(value) > 50:
                                            # String containing binary data (latin-1 encoded)
                                            try:
                                                binary_data = value.encode(
                                                    'latin-1')
                                                if binary_data.startswith(b'RIFF') and b'WEBP' in binary_data[:20]:
                                                    decrypted_value = clwe_encryptor.decrypt_value(
                                                        binary_data, settings.CRYPTOPIX_DEFAULT_PASSWORD)
                                            except UnicodeEncodeError:
                                                pass  # Not valid latin-1, skip

                                        if decrypted_value is not None:
                                            decrypted_row_data[regular_name] = decrypted_value
                                        else:
                                            # No decryption applied, use original value
                                            decrypted_row_data[regular_name] = value

                                    except Exception as e:
                                        logger.warning(
                                            f"Failed to decrypt {col_name}: {e}")
                                        decrypted_row_data[regular_name] = str(
                                            value)  # Fallback to string representation
                                else:
                                    # Normal data - keep as-is
                                    decrypted_row_data[regular_name] = value

                        # Insert decrypted row
                        if decrypted_row_data:
                            placeholders = ', '.join(
                                [f':{col}' for col in decrypted_row_data.keys()])
                            insert_sql = f"INSERT INTO {table_name} ({', '.join(decrypted_row_data.keys())}) VALUES ({placeholders})"

                            with target_engine.begin() as conn:
                                conn.execute(text(insert_sql),
                                             decrypted_row_data)

                logger.info(f"Demigrated table: {table_name}")

            except Exception as e:
                logger.error(f"Error demigrating table {table_name}: {e}")
                continue

        # Note: Migration state files are not modified during demigration
        # The application will detect the lack of encrypted database tables

        encrypted_engine.dispose()
        target_engine.dispose()

    except Exception as e:
        logger.error(f"Demigration failed: {e}")
        raise e


def get_log_analytics(hours=24):
    """Get comprehensive log analytics and statistics"""
    try:
        conn = sqlite3.connect('system_logs.db')
        cursor = conn.cursor()

        # Calculate time range
        cutoff_time = (datetime.datetime.utcnow() -
                       datetime.timedelta(hours=hours)).isoformat()

        analytics = {
            'time_range': f'{hours} hours',
            'total_logs': 0,
            'logs_by_level': {},
            'logs_by_source': {},
            'logs_by_hour': {},
            'top_messages': [],
            'error_rate': 0,
            'warning_rate': 0,
            'recent_errors': [],
            'system_health': {}
        }

        # Total logs in time range
        cursor.execute(
            "SELECT COUNT(*) FROM system_logs WHERE timestamp >= ?", (cutoff_time,))
        analytics['total_logs'] = cursor.fetchone()[0]

        # Logs by level
        cursor.execute("""
            SELECT level, COUNT(*) as count
            FROM system_logs
            WHERE timestamp >= ?
            GROUP BY level
            ORDER BY count DESC
        """, (cutoff_time,))
        analytics['logs_by_level'] = {row[0]: row[1]
                                      for row in cursor.fetchall()}

        # Logs by source
        cursor.execute("""
            SELECT source, COUNT(*) as count
            FROM system_logs
            WHERE timestamp >= ?
            GROUP BY source
            ORDER BY count DESC
            LIMIT 10
        """, (cutoff_time,))
        analytics['logs_by_source'] = {row[0]: row[1]
                                       for row in cursor.fetchall()}

        # Logs by hour (last 24 hours)
        cursor.execute("""
            SELECT strftime('%H', timestamp) as hour, COUNT(*) as count
            FROM system_logs
            WHERE timestamp >= ?
            GROUP BY hour
            ORDER BY hour
        """, (cutoff_time,))
        analytics['logs_by_hour'] = {
            f"{int(row[0]):02d}:00": row[1] for row in cursor.fetchall()}

        # Top messages
        cursor.execute("""
            SELECT message, COUNT(*) as count
            FROM system_logs
            WHERE timestamp >= ?
            GROUP BY message
            ORDER BY count DESC
            LIMIT 10
        """, (cutoff_time,))
        analytics['top_messages'] = [
            {'message': row[0], 'count': row[1]} for row in cursor.fetchall()]

        # Recent errors
        cursor.execute("""
            SELECT timestamp, message, source
            FROM system_logs
            WHERE timestamp >= ? AND level = 'ERROR'
            ORDER BY timestamp DESC
            LIMIT 5
        """, (cutoff_time,))
        analytics['recent_errors'] = [{
            'timestamp': row[0],
            'message': row[1],
            'source': row[2]
        } for row in cursor.fetchall()]

        # Calculate rates
        total_logs = analytics['total_logs']
        if total_logs > 0:
            analytics['error_rate'] = round(
                (analytics['logs_by_level'].get('ERROR', 0) / total_logs) * 100, 2)
            analytics['warning_rate'] = round(
                (analytics['logs_by_level'].get('WARNING', 0) / total_logs) * 100, 2)

        # System health indicators
        analytics['system_health'] = {
            'memory_usage': get_system_stats().get('memory', {}).get('percent', 0),
            'cpu_usage': get_system_stats().get('cpu', 0),
            'disk_usage': get_system_stats().get('disk', {}).get('percent', 0),
            'log_retention_days': LOG_RETENTION_DAYS,
            'memory_logs_limit': MAX_MEMORY_LOGS
        }

        conn.close()
        return analytics

    except Exception as e:
        logger.error(f"Failed to get log analytics: {e}")
        return {
            'error': str(e),
            'total_logs': 0,
            'logs_by_level': {},
            'logs_by_source': {},
            'logs_by_hour': {},
            'top_messages': [],
            'error_rate': 0,
            'warning_rate': 0,
            'recent_errors': [],
            'system_health': {}
        }


def get_dashboard_stats() -> dict:
    """Get all dashboard statistics"""
    # Load migration state from files
    migration_state = load_migration_state_from_files()

    stats = {
        'migration': get_migration_progress(),
        'system': get_system_stats(),
        'source_db': None,
        'encrypted_db': None,
        'encryption_status': 'inactive'
    }

    # Get source database stats
    if migration_state.get("source_db_url"):
        stats['source_db'] = get_database_stats(
            migration_state["source_db_url"], "source")
        stats['source_db']['size'] = get_database_size(
            migration_state["source_db_url"])

    # Get encrypted database stats
    if migration_state.get("encrypted_db_url"):
        stats['encrypted_db'] = get_database_stats(
            migration_state["encrypted_db_url"], "encrypted")
        stats['encrypted_db']['size'] = get_database_size(
            migration_state["encrypted_db_url"])
        stats['encryption_status'] = 'active'

    # Calculate additional metrics
    if stats['source_db'] and stats['encrypted_db']:
        try:
            source_size = stats['source_db']['size']['size_bytes']
            encrypted_size = stats['encrypted_db']['size']['size_bytes']

            if source_size > 0:
                stats['size_ratio'] = round((encrypted_size / source_size), 2)
            else:
                stats['size_ratio'] = 1.0

            stats['compression_efficiency'] = round(
                ((source_size - encrypted_size) / source_size * 100), 1) if source_size > 0 else 0
        except:
            stats['size_ratio'] = 1.0
            stats['compression_efficiency'] = 0

    return stats


@app.route('/systemlog')
@login_required
def systemlog():
    """System logs page"""
    return render_template('systemlog.html')


@app.route('/api/system_logs')
@login_required
def get_system_logs():
    """Get system logs with pagination and filtering"""
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        level = request.args.get('level', '').upper()
        source = request.args.get('source', '')
        search = request.args.get('search', '')
        time_range = request.args.get('time_range', '')

        # Get logs from database
        conn = sqlite3.connect('system_logs.db')
        cursor = conn.cursor()

        # Build query with filters
        query = "SELECT * FROM system_logs WHERE 1=1"
        params = []

        if level:
            query += " AND level = ?"
            params.append(level)

        if source:
            query += " AND source LIKE ?"
            params.append(f"%{source}%")

        if search:
            query += " AND (message LIKE ? OR details LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%"])

        if time_range:
            hours_ago = datetime.datetime.utcnow() - datetime.timedelta(hours=int(time_range))
            query += " AND timestamp >= ?"
            params.append(hours_ago.isoformat())

        # Get total count
        count_query = query.replace("SELECT *", "SELECT COUNT(*)")
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()[0]

        # Add ordering and pagination
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([per_page, (page - 1) * per_page])

        cursor.execute(query, params)
        rows = cursor.fetchall()

        # Convert to dict format
        logs = []
        for row in rows:
            logs.append({
                "id": row[0],
                "timestamp": row[1],
                "level": row[2],
                "message": row[3],
                "source": row[4],
                "user_id": row[5],
                "session_id": row[6],
                "ip_address": row[7],
                "details": row[8]
            })

        conn.close()

        # Calculate pagination info
        total_pages = (total_count + per_page - 1) // per_page
        page_start = ((page - 1) * per_page) + 1
        page_end = min(page * per_page, total_count)

        return {
            "success": True,
            "logs": logs,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total_count,
                "pages": total_pages,
                "has_prev": page > 1,
                "has_next": page < total_pages,
                "page_start": page_start,
                "page_end": page_end
            }
        }

    except Exception as e:
        logger.error(f"Error fetching system logs: {e}")
        return {"success": False, "error": str(e)}, 500


@app.route('/api/system_logs/live')
@login_required
def get_live_logs():
    """Get recent logs for real-time updates"""
    try:
        limit = int(request.args.get('limit', 10))

        with system_logs_lock:
            recent_logs = system_logs[-limit:] if len(
                system_logs) >= limit else system_logs[:]

        return {
            "success": True,
            "logs": recent_logs
        }

    except Exception as e:
        logger.error(f"Error fetching live logs: {e}")
        return {"success": False, "error": str(e)}, 500


@app.route('/api/system_logs/<int:log_id>')
@login_required
def get_log_details(log_id):
    """Get detailed information for a specific log entry"""
    try:
        conn = sqlite3.connect('system_logs.db')
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM system_logs WHERE id = ?", (log_id,))
        row = cursor.fetchone()
        conn.close()

        if row:
            log_details = {
                "id": row[0],
                "timestamp": row[1],
                "level": row[2],
                "message": row[3],
                "source": row[4],
                "user_id": row[5],
                "session_id": row[6],
                "ip_address": row[7],
                "details": row[8]
            }
            return {"success": True, "log": log_details}
        else:
            return {"success": False, "error": "Log not found"}, 404

    except Exception as e:
        logger.error(f"Error fetching log details: {e}")
        return {"success": False, "error": str(e)}, 500


@app.route('/api/system_logs/download/json')
@login_required
def download_logs_json():
    """Download system logs as JSON"""
    try:
        # Get filtered logs
        level = request.args.get('level', '').upper()
        source = request.args.get('source', '')
        start_date = request.args.get('start_date', '')
        end_date = request.args.get('end_date', '')

        conn = sqlite3.connect('system_logs.db')
        cursor = conn.cursor()

        query = "SELECT * FROM system_logs WHERE 1=1"
        params = []

        if level:
            query += " AND level = ?"
            params.append(level)

        if source:
            query += " AND source LIKE ?"
            params.append(f"%{source}%")

        if start_date:
            query += " AND timestamp >= ?"
            params.append(start_date)

        if end_date:
            query += " AND timestamp <= ?"
            params.append(end_date + "T23:59:59")

        query += " ORDER BY timestamp DESC"

        cursor.execute(query, params)
        rows = cursor.fetchall()

        # Convert to dict format
        logs = []
        for row in rows:
            logs.append({
                "id": row[0],
                "timestamp": row[1],
                "level": row[2],
                "message": row[3],
                "source": row[4],
                "user_id": row[5],
                "session_id": row[6],
                "ip_address": row[7],
                "details": row[8]
            })

        conn.close()

        # Return as JSON
        from flask import Response, jsonify
        response = jsonify(logs)
        response.headers['Content-Disposition'] = 'attachment; filename=system_logs.json'
        return response

    except Exception as e:
        logger.error(f"Error downloading logs as JSON: {e}")
        return {"success": False, "error": str(e)}, 500


@app.route('/api/system_logs/download')
@login_required
def download_logs():
    """Download system logs as CSV"""
    try:
        # Get filtered logs
        level = request.args.get('level', '').upper()
        source = request.args.get('source', '')
        start_date = request.args.get('start_date', '')
        end_date = request.args.get('end_date', '')

        conn = sqlite3.connect('system_logs.db')
        cursor = conn.cursor()

        query = "SELECT timestamp, level, message, source, user_id, ip_address FROM system_logs WHERE 1=1"
        params = []

        if level:
            query += " AND level = ?"
            params.append(level)

        if source:
            query += " AND source LIKE ?"
            params.append(f"%{source}%")

        if start_date:
            query += " AND timestamp >= ?"
            params.append(start_date)

        if end_date:
            query += " AND timestamp <= ?"
            params.append(end_date + "T23:59:59")

        query += " ORDER BY timestamp DESC"

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        # Create CSV content
        csv_content = "Timestamp,Level,Message,Source,User ID,IP Address\n"
        for row in rows:
            # Escape commas and quotes in fields
            escaped_row = []
            for field in row:
                field_str = str(field) if field is not None else ""
                if ',' in field_str or '"' in field_str or '\n' in field_str:
                    field_str = f'"{field_str.replace(chr(34), chr(34) + chr(34))}"'
                escaped_row.append(field_str)
            csv_content += ','.join(escaped_row) + '\n'

        # Return as downloadable file
        from flask import Response
        response = Response(
            csv_content,
            mimetype='text/csv',
            headers={
                'Content-Disposition': 'attachment; filename=system_logs.csv'
            }
        )
        return response

    except Exception as e:
        logger.error(f"Error downloading logs: {e}")
        return {"success": False, "error": str(e)}, 500


@app.route('/api/system_logs/analytics')
@login_required
def get_log_analytics_api():
    """Get log analytics data for dashboard"""
    try:
        hours = int(request.args.get('hours', 24))
        analytics = get_log_analytics(hours)
        return {"success": True, "analytics": analytics}
    except Exception as e:
        logger.error(f"Error fetching log analytics: {e}")
        return {"success": False, "error": str(e)}, 500


@app.route('/api/system_logs/share/<int:log_id>')
@login_required
def share_log(log_id):
    """Generate a shareable link for a specific log entry"""
    try:
        # In a real implementation, you might generate a temporary share token
        # For now, just return the log details
        conn = sqlite3.connect('system_logs.db')
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM system_logs WHERE id = ?", (log_id,))
        row = cursor.fetchone()
        conn.close()

        if row:
            log_data = {
                "id": row[0],
                "timestamp": row[1],
                "level": row[2],
                "message": row[3],
                "source": row[4],
                "user_id": row[5],
                "session_id": row[6],
                "ip_address": row[7],
                "details": row[8]
            }

            # Create a shareable summary
            share_text = f"System Log - {log_data['level']}: {log_data['message']} (at {log_data['timestamp']})"

            return {
                "success": True,
                "share_text": share_text,
                "log_data": log_data
            }
        else:
            return {"success": False, "error": "Log not found"}, 404

    except Exception as e:
        logger.error(f"Error sharing log: {e}")
        return {"success": False, "error": str(e)}, 500


@app.route('/api/system_logs/sources')
@login_required
def get_log_sources():
    """Get all available log sources"""
    try:
        conn = sqlite3.connect('system_logs.db')
        cursor = conn.cursor()

        cursor.execute(
            "SELECT DISTINCT source FROM system_logs WHERE source IS NOT NULL ORDER BY source")
        rows = cursor.fetchall()
        conn.close()

        sources = [row[0] for row in rows if row[0]]

        return {"success": True, "sources": sources}

    except Exception as e:
        logger.error(f"Error fetching log sources: {e}")
        return {"success": False, "error": str(e)}, 500


@app.route('/api/system_logs/download/txt')
@login_required
def download_logs_txt():
    """Download system logs as plain text"""
    try:
        # Get filtered logs
        level = request.args.get('level', '').upper()
        source = request.args.get('source', '')
        time_range = request.args.get('time_range', '24')

        conn = sqlite3.connect('system_logs.db')
        cursor = conn.cursor()

        query = "SELECT timestamp, level, message, source, user_id, ip_address FROM system_logs WHERE 1=1"
        params = []

        if level:
            query += " AND level = ?"
            params.append(level)

        if source:
            query += " AND source LIKE ?"
            params.append(f"%{source}%")

        if time_range:
            hours_ago = datetime.datetime.utcnow() - datetime.timedelta(hours=int(time_range))
            query += " AND timestamp >= ?"
            params.append(hours_ago.isoformat())

        query += " ORDER BY timestamp DESC"

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        # Create text content
        text_content = "CryptoPIX Bridge System Logs\n"
        text_content += "=" * 50 + "\n\n"

        for row in rows:
            timestamp, level, message, source, user_id, ip_address = row
            text_content += f"[{timestamp}] {level} - {source or 'system'}\n"
            text_content += f"Message: {message}\n"
            if user_id:
                text_content += f"User: {user_id}\n"
            if ip_address:
                text_content += f"IP: {ip_address}\n"
            text_content += "-" * 30 + "\n\n"

        # Return as downloadable file
        from flask import Response
        response = Response(
            text_content,
            mimetype='text/plain',
            headers={
                'Content-Disposition': 'attachment; filename=system_logs.txt'
            }
        )
        return response

    except Exception as e:
        logger.error(f"Error downloading logs as text: {e}")
        return {"success": False, "error": str(e)}, 500


@app.route('/query_console')
@login_required
def query_console_page():
    """Query Console page"""
    databases = database_registry.list_databases()
    return render_template('query_console.html', databases=databases)


@app.route('/api/console/execute', methods=['POST'])
@login_required
def execute_console_command():
    """Execute a command in the query console"""
    try:
        data = request.get_json()
        if not data or 'command' not in data:
            logger.error("No command provided in request data")
            return {"success": False, "error": "No command provided"}, 400

        command = data['command'].strip()
        user_id = session.get('user_email', 'anonymous')
        db_id = data.get('db_id')

        logger.info(f"Console command received: {command[:100]}...")
        logger.info(f"User ID: {user_id}, DB ID: {db_id}")

        # Log the command execution
        log_system_event(
            'INFO', f'Console command executed: {command[:100]}...', source='query_console', user_id=user_id)

        # Load migration state from files
        logger.info(f"Loading migration state for db_id: {db_id}")
        migration_state = load_migration_state_from_files(
            db_id=db_id) if db_id else load_migration_state_from_files()

        logger.info(f"Migration state loaded: {bool(migration_state)}")
        if migration_state:
            logger.info(
                f"Encrypted DB URL: {migration_state.get('encrypted_db_url', 'None')}")
            logger.info(
                f"Migration complete: {migration_state.get('migration_complete', False)}")
            logger.info(
                f"Table configs count: {len(migration_state.get('table_configs', {}))}")

        # Execute the command
        logger.info("Calling console_service.execute_command")
        result = console_service.execute_command(
            command, user_id, migration_state=migration_state)

        logger.info(f"Console service result: success={result.get('success')}")
        if not result.get('success'):
            logger.error(f"Console command failed: {result.get('error')}")

        # Log the result
        if result.get('success'):
            log_system_event('INFO', f'Console command completed successfully',
                             source='query_console', user_id=user_id)
        else:
            log_system_event(
                'WARNING', f'Console command failed: {result.get("error", "Unknown error")}', source='query_console', user_id=user_id)

        return result

    except Exception as e:
        logger.error(f"Console execution error: {e}")
        log_system_event('ERROR', f'Console execution error: {str(e)}', source='query_console', user_id=session.get(
            'user_email', 'anonymous'))
        return {"success": False, "error": f"Execution failed: {str(e)}"}, 500


@app.route('/api/console/suggestions', methods=['POST'])
@login_required
def get_ai_suggestions():
    """Get AI-powered suggestions for SQL queries"""
    try:
        data = request.get_json()
        if not data or 'query' not in data:
            return {"success": False, "error": "No query provided"}, 400

        partial_query = data['query']
        cursor_position = data.get('cursor_position', len(partial_query))

        # Get AI suggestions
        # Get AI suggestions
        db_id = data.get('db_id')
        migration_state = load_migration_state_from_files(
            db_id=db_id) if db_id else load_migration_state_from_files()
        suggestions = console_service.get_ai_suggestions(
            partial_query, cursor_position, migration_state=migration_state)

        return {"success": True, "suggestions": suggestions}

    except Exception as e:
        logger.error(f"AI suggestions error: {e}")
        return {"success": False, "error": f"Failed to get suggestions: {str(e)}"}, 500


@app.route('/api/console/explain', methods=['POST'])
@login_required
def explain_query():
    """Get AI explanation of a SQL query"""
    try:
        data = request.get_json()
        if not data or 'query' not in data:
            return {"success": False, "error": "No query provided"}, 400

        query = data['query'].strip()

        # Get AI explanation
        # Get AI explanation
        db_id = data.get('db_id')
        migration_state = load_migration_state_from_files(
            db_id=db_id) if db_id else load_migration_state_from_files()
        explanation = console_service.explain_query(
            query, migration_state=migration_state)

        return {"success": True, "explanation": explanation}

    except Exception as e:
        logger.error(f"Query explanation error: {e}")
        return {"success": False, "error": f"Failed to explain query: {str(e)}"}, 500


@app.route('/api/console/natural_language', methods=['POST'])
@login_required
def natural_language_to_sql():
    """Convert natural language to SQL query"""
    try:
        data = request.get_json()
        if not data or 'query' not in data:
            return {"success": False, "error": "No natural language query provided"}, 400

        natural_query = data['query'].strip()

        # Convert natural language to SQL
        # Convert natural language to SQL
        db_id = data.get('db_id')
        migration_state = load_migration_state_from_files(
            db_id=db_id) if db_id else load_migration_state_from_files()
        result = console_service.natural_language_to_sql(
            natural_query, migration_state=migration_state)

        return {"success": True, "result": result}

    except Exception as e:
        logger.error(f"Natural language to SQL error: {e}")
        return {"success": False, "error": f"Failed to convert natural language to SQL: {str(e)}"}, 500


@app.route('/start_virtual_server', methods=['POST'])
@login_required
def start_virtual_server():
    """Start a Virtual Database Server instance"""
    try:
        # Get form data
        db_id = request.form.get('db_id')
        host = request.form.get('host', '0.0.0.0')
        port = int(request.form.get('port', 4406))
        protocol = request.form.get('protocol', 'mysql')

        if not db_id:
            # Fallback logic for backward compatibility
            migration_state = load_migration_state_from_files()
            if migration_state.get('db_id'):
                db_id = migration_state['db_id']
            else:
                flash('Database ID is required to start VDS', 'error')
                return redirect(url_for('settings_page'))

        # Ensure VDS instance is created in registry
        vds_id = vds_manager.create_vds_instance(db_id, host, port, protocol)
        if not vds_id:
            # Check if it already exists (port re-use for same DB config?)
            db_info = database_registry.get_database(db_id)
            if db_info and db_info.get('vds_instances'):
                for vds in db_info['vds_instances']:
                    if vds['port'] == port:
                        vds_id = vds['id']
                        break

        if not vds_id:
            flash(f'Failed to create Virtual Database Server instance', 'error')
            return redirect(url_for('settings_page'))

        # Start it
        success, message = vds_manager.start_vds(db_id, vds_id)
        if success:
            flash(message, 'success')
            log_system_event(
                'INFO', f'Started VDS for DB {db_id} on {host}:{port}', source='vds')
        else:
            flash(
                f'Failed to start Virtual Database Server: {message}', 'error')

    except Exception as e:
        logger.error(f"Failed to start Virtual Database Server: {e}")
        flash(f'Failed to start Virtual Database Server: {str(e)}', 'error')

    return redirect(url_for('settings_page'))


@app.route('/stop_virtual_server', methods=['POST'])
@login_required
def stop_virtual_server():
    """Stop a Virtual Database Server instance"""
    try:
        db_id = request.form.get('db_id')
        vds_id = request.form.get('vds_id')

        if not db_id or not vds_id:
            flash('Database ID and VDS ID are required to stop server', 'error')
            return redirect(url_for('settings_page'))

        if vds_manager.stop_vds(db_id, vds_id):
            flash('Virtual Database Server stopped successfully', 'success')
            log_system_event(
                'INFO', f'Stopped VDS {vds_id} for DB {db_id}', source='vds')
        else:
            flash('Failed to stop Virtual Database Server', 'error')

    except Exception as e:
        logger.error(f"Failed to stop Virtual Database Server: {e}")
        flash(f'Failed to stop Virtual Database Server: {str(e)}', 'error')

    return redirect(url_for('settings_page'))


@app.route('/password_rotation')
@login_required
def password_rotation_page():
    """Password rotation page"""
    return render_template('password_rotation.html')


@app.route('/rotate_password', methods=['POST'])
@login_required
def rotate_password():
    """Handle password rotation request"""
    try:
        old_password = request.form.get('old_password', '').strip()
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        # Validate inputs
        if not old_password:
            flash('Current encryption password is required', 'danger')
            return redirect(url_for('password_rotation_page'))

        if not new_password:
            flash('New encryption password is required', 'danger')
            return redirect(url_for('password_rotation_page'))

        if new_password != confirm_password:
            flash('New passwords do not match', 'danger')
            return redirect(url_for('password_rotation_page'))

        # Validate password strength
        import re
        password_requirements = {
            'length': len(new_password) >= 12,
            'uppercase': bool(re.search(r'[A-Z]', new_password)),
            'lowercase': bool(re.search(r'[a-z]', new_password)),
            'number': bool(re.search(r'[0-9]', new_password)),
            'special': bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', new_password))
        }

        if not all(password_requirements.values()):
            flash('New password does not meet security requirements', 'danger')
            return redirect(url_for('password_rotation_page'))

        # Get encrypted database URL
        migration_state = load_migration_state_from_files()
        encrypted_db_url = migration_state.get('encrypted_db_url')

        if not encrypted_db_url:
            flash(
                'No encrypted database configured. Please run migration first.', 'danger')
            return redirect(url_for('password_rotation_page'))

        log_system_event('INFO', 'Starting password rotation', source='password_rotation',
                         user_id=session.get('user_email'))

        # Import password rotation service
        from app.services.password_rotation import PasswordRotationService

        # Create rotation service
        rotation_service = PasswordRotationService(
            encrypted_db_url=encrypted_db_url,
            clwe_encryptor=clwe_encryptor,
            old_password=old_password,
            new_password=new_password
        )

        # Perform rotation
        results = rotation_service.rotate_password_for_database()

        if results["status"] == "success":
            # Verify rotation
            if rotation_service.verify_password_rotation():
                # Update settings
                settings.CRYPTOPIX_DEFAULT_PASSWORD = new_password

                # Update .env file
                try:
                    env_path = settings.BASE_DIR / '.env'
                    if env_path.exists():
                        with open(env_path, 'r') as f:
                            env_lines = f.readlines()

                        password_found = False
                        for i, line in enumerate(env_lines):
                            if line.startswith('CRYPTOPIX_DEFAULT_PASSWORD=') or line.startswith('CRYPTOPIX_PASSWORD='):
                                env_lines[i] = f'CRYPTOPIX_DEFAULT_PASSWORD={new_password}\n'
                                password_found = True
                                break

                        if not password_found:
                            env_lines.append(
                                f'\nCRYPTOPIX_DEFAULT_PASSWORD={new_password}\n')

                        with open(env_path, 'w') as f:
                            f.writelines(env_lines)

                        log_system_event(
                            'INFO', 'Updated .env file with new password', source='password_rotation')
                except Exception as e:
                    log_system_event(
                        'WARNING', f'Could not update .env file: {str(e)}', source='password_rotation')

                flash(
                    f'✅ Password rotation successful! Processed {results["total_rows_processed"]:,} rows across {results["tables_processed"]} tables.', 'success')
                flash(
                    '⚠️ Please restart the application for changes to take full effect.', 'warning')

                log_system_event('INFO', f'Password rotation completed successfully: {results["total_rows_processed"]} rows processed',
                                 source='password_rotation', user_id=session.get('user_email'))
            else:
                flash(
                    '❌ Password rotation verification failed. Please check logs and restore from backup if necessary.', 'danger')
                log_system_event(
                    'ERROR', 'Password rotation verification failed', source='password_rotation')
        else:
            error_msg = results.get('error', 'Unknown error')
            flash(f'❌ Password rotation failed: {error_msg}', 'danger')
            log_system_event(
                'ERROR', f'Password rotation failed: {error_msg}', source='password_rotation')

    except Exception as e:
        logger.error(f"Password rotation error: {e}")
        flash(f'❌ Password rotation failed: {str(e)}', 'danger')
        log_system_event(
            'ERROR', f'Password rotation exception: {str(e)}', source='password_rotation')

    return redirect(url_for('password_rotation_page'))


# ============================================================================
# API Endpoints for Multi-Database and VDS Management
# ============================================================================

@app.route('/api/databases', methods=['GET'])
@login_required
def api_list_databases():
    """List all registered databases"""
    try:
        databases = database_registry.list_databases()
        return json.dumps({"success": True, "databases": databases}), 200, {'ContentType': 'application/json'}
    except Exception as e:
        logger.error(f"Failed to list databases: {e}")
        return json.dumps({"success": False, "error": str(e)}), 500, {'ContentType': 'application/json'}


@app.route('/api/databases/<db_id>', methods=['GET'])
@login_required
def api_get_database(db_id):
    """Get database details"""
    try:
        database = database_registry.get_database(db_id)
        if database:
            return json.dumps({"success": True, "database": database}), 200, {'ContentType': 'application/json'}
        else:
            return json.dumps({"success": False, "error": "Database not found"}), 404, {'ContentType': 'application/json'}
    except Exception as e:
        logger.error(f"Failed to get database: {e}")
        return json.dumps({"success": False, "error": str(e)}), 500, {'ContentType': 'application/json'}


@app.route('/api/databases/<db_id>/vds/create', methods=['POST'])
@login_required
def api_create_vds(db_id):
    """Create a new VDS instance for a database"""
    try:
        data = request.get_json()
        host = data.get('host', '127.0.0.1')
        port = data.get('port')
        protocol = data.get('protocol', 'mysql')

        if not port:
            return json.dumps({"success": False, "error": "Port is required"}), 400, {'ContentType': 'application/json'}

        # Validate port
        try:
            port = int(port)
            if port < 1024 or port > 65535:
                return json.dumps({"success": False, "error": "Port must be between 1024 and 65535"}), 400, {'ContentType': 'application/json'}
        except ValueError:
            return json.dumps({"success": False, "error": "Invalid port number"}), 400, {'ContentType': 'application/json'}

        # Create VDS instance
        vds_id = vds_manager.create_vds_instance(db_id, host, port, protocol)

        if vds_id:
            log_system_event(
                'INFO', f'Created VDS instance {vds_id} for database {db_id}', source='vds_management')
            return json.dumps({"success": True, "vds_id": vds_id}), 200, {'ContentType': 'application/json'}
        else:
            return json.dumps({"success": False, "error": "Failed to create VDS instance"}), 500, {'ContentType': 'application/json'}

    except Exception as e:
        logger.error(f"Failed to create VDS instance: {e}")
        return json.dumps({"success": False, "error": str(e)}), 500, {'ContentType': 'application/json'}


@app.route('/api/databases/<db_id>/vds/<vds_id>/start', methods=['POST'])
@login_required
def api_start_vds(db_id, vds_id):
    """Start a VDS instance"""
    try:
        success, message = vds_manager.start_vds(db_id, vds_id)

        if success:
            vds_info = database_registry.get_vds_instance(db_id, vds_id)
            log_system_event(
                'INFO', f'Started VDS instance {vds_id} on port {vds_info["port"]}', source='vds_management')
            return json.dumps({
                "success": True,
                "message": message
            }), 200, {'ContentType': 'application/json'}
        else:
            return json.dumps({"success": False, "error": message}), 500, {'ContentType': 'application/json'}

    except Exception as e:
        logger.error(f"Failed to start VDS instance: {e}")
        return json.dumps({"success": False, "error": str(e)}), 500, {'ContentType': 'application/json'}


@app.route('/api/databases/<db_id>/vds/<vds_id>/stop', methods=['POST'])
@login_required
def api_stop_vds(db_id, vds_id):
    """Stop a VDS instance"""
    try:
        success = vds_manager.stop_vds(db_id, vds_id)

        if success:
            log_system_event(
                'INFO', f'Stopped VDS instance {vds_id}', source='vds_management')
            return json.dumps({"success": True, "message": "VDS stopped successfully"}), 200, {'ContentType': 'application/json'}
        else:
            return json.dumps({"success": False, "error": "Failed to stop VDS instance"}), 500, {'ContentType': 'application/json'}

    except Exception as e:
        logger.error(f"Failed to stop VDS instance: {e}")
        return json.dumps({"success": False, "error": str(e)}), 500, {'ContentType': 'application/json'}


@app.route('/api/databases/<db_id>/vds/<vds_id>/status', methods=['GET'])
@login_required
def api_vds_status(db_id, vds_id):
    """Get VDS instance status"""
    try:
        status = vds_manager.get_vds_status(db_id, vds_id)
        is_running = vds_manager.is_vds_running(db_id, vds_id)

        if status:
            return json.dumps({
                "success": True,
                "status": status,
                "is_running": is_running
            }), 200, {'ContentType': 'application/json'}
        else:
            return json.dumps({"success": False, "error": "VDS instance not found"}), 404, {'ContentType': 'application/json'}

    except Exception as e:
        logger.error(f"Failed to get VDS status: {e}")
        return json.dumps({"success": False, "error": str(e)}), 500, {'ContentType': 'application/json'}


@app.route('/api/databases/<db_id>/vds', methods=['GET'])
@login_required
def api_list_vds_instances(db_id):
    """List all VDS instances for a database"""
    try:
        database = database_registry.get_database(db_id)
        if database:
            return json.dumps({
                "success": True,
                "vds_instances": database.get("vds_instances", [])
            }), 200, {'ContentType': 'application/json'}
        else:
            return json.dumps({"success": False, "error": "Database not found"}), 404, {'ContentType': 'application/json'}

    except Exception as e:
        logger.error(f"Failed to list VDS instances: {e}")
        return json.dumps({"success": False, "error": str(e)}), 500, {'ContentType': 'application/json'}


@app.route('/api/databases/<db_id>/vds/<vds_id>/delete', methods=['DELETE'])
@login_required
def api_delete_vds(db_id, vds_id):
    """Delete a VDS instance"""
    try:
        success = vds_manager.remove_vds_instance(db_id, vds_id)

        if success:
            log_system_event(
                'INFO', f'Deleted VDS instance {vds_id}', source='vds_management')
            return json.dumps({"success": True, "message": "VDS instance deleted"}), 200, {'ContentType': 'application/json'}
        else:
            return json.dumps({"success": False, "error": "Failed to delete VDS instance"}), 500, {'ContentType': 'application/json'}

    except Exception as e:
        logger.error(f"Failed to delete VDS instance: {e}")
        return json.dumps({"success": False, "error": str(e)}), 500, {'ContentType': 'application/json'}


@app.route('/api/vds/running', methods=['GET'])
@login_required
def api_running_vds():
    """Get all running VDS instances"""
    try:
        running = vds_manager.get_running_instances()
        return json.dumps({"success": True, "running_instances": running}), 200, {'ContentType': 'application/json'}
    except Exception as e:
        logger.error(f"Failed to get running VDS instances: {e}")
        return json.dumps({"success": False, "error": str(e)}), 500, {'ContentType': 'application/json'}


if __name__ == '__main__':
    logger.info("CryptoPIX Bridge starting...")

    # VDS auto-start disabled - users must manually start VDS from Settings page
    # This gives users full control over when the virtual server runs
    # To start VDS, go to Settings and click "Start Virtual Server"
    logger.info(
        "Virtual Database Server will not auto-start. Start it manually from Settings page.")

    # Commented out auto-start logic:
    # try:
    #     migration_state = load_migration_state_from_files()
    #     if migration_state.get('encrypted_db_url') and migration_state.get('table_configs'):
    #         logger.info("Migration state found, starting Virtual Database Server...")
    #         from app.virtual_db_server import start_virtual_server
    #         vds = start_virtual_server(
    #             host=getattr(settings, 'VDS_HOST', '0.0.0.0'),
    #             port=getattr(settings, 'VDS_PORT', 4406),
    #             encrypted_db_url=migration_state['encrypted_db_url'],
    #             protocol=migration_state.get('selected_db_type', 'mysql'),
    #             table_mappings=migration_state.get('table_configs', {})
    #         )
    #         logger.info(f"Virtual Database Server started automatically on port {vds.port}")
    #     else:
    #         logger.info("No migration state found, Virtual Database Server not started")
    # except Exception as e:
    #     logger.error(f"Failed to auto-start Virtual Database Server: {e}")

    app.run(host=settings.APP_HOST, port=settings.APP_PORT, debug=settings.DEBUG)
