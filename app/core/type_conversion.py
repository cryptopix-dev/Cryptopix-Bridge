"""
CryptoPIX Bridge v3.0 - Original Database Type Conversion Module

This module dynamically restores decrypted data to its native database schema types
before transmission to the client. It intercepts decrypted string outputs from the VDS
and references the original database schema to identify and enforce precise type casting.
"""

import logging
import datetime
import decimal
from typing import Any, Dict, Optional, Union
from enum import Enum

from app.config import settings

logger = logging.getLogger(__name__)


class SQLDataType(Enum):
    """SQL data types supported for conversion"""
    INT = "INT"
    BIGINT = "BIGINT"
    SMALLINT = "SMALLINT"
    TINYINT = "TINYINT"
    BOOLEAN = "BOOLEAN"
    FLOAT = "FLOAT"
    DOUBLE = "DOUBLE"
    DECIMAL = "DECIMAL"
    NUMERIC = "NUMERIC"
    DATE = "DATE"
    DATETIME = "DATETIME"
    TIMESTAMP = "TIMESTAMP"
    TIME = "TIME"
    VARCHAR = "VARCHAR"
    CHAR = "CHAR"
    TEXT = "TEXT"
    BLOB = "BLOB"
    JSON = "JSON"
    NULL = "NULL"


class TypeConversionError(Exception):
    """Custom exception for type conversion errors"""
    pass


class OriginalTypeConverter:
    """
    Original Database Type Conversion Module
    
    This module intercepts decrypted string outputs from the VDS and restores
    them to their native database schema types before transmission to the client.
    """
    
    def __init__(self):
        self.schema_cache = {}
        self.migration_state = None
        self.conversion_metrics = {
            'total_conversions': 0,
            'successful_conversions': 0,
            'failed_conversions': 0,
            'fallback_to_varchar': 0,
            'null_values_handled': 0,
            'latency_ms': 0.0
        }
    
    def set_migration_state(self, migration_state: Dict):
        """Set the migration state to use for schema lookups"""
        self.migration_state = migration_state
        # Clear cache when migration state changes
        self.schema_cache.clear()
        
    def intercept_and_convert(self, 
                             decrypted_value: Any, 
                             column_name: str, 
                             table_name: str, 
                             schema_type: Optional[Any] = None,
                             migration_state: Optional[Dict] = None) -> Any:
        """
        Intercept decrypted string output and convert to original database type
        
        Args:
            decrypted_value: The decrypted value (typically string)
            column_name: Name of the column
            table_name: Name of the table
            schema_type: Optional explicit schema type (already retrieved)
            migration_state: Optional migration state for this specific lookup
            
        Returns:
            Value converted to its original database type
        """
        import time
        start_time = time.perf_counter()
        self.conversion_metrics['total_conversions'] += 1
        
        try:
            # Handle NULL values
            if decrypted_value is None:
                self.conversion_metrics['null_values_handled'] += 1
                return None
                
            # Skip tag columns
            if column_name.lower().startswith('tag_'):
                return decrypted_value
            
            # 1. Use provided schema_type if available
            original_type = schema_type
            
            # 2. Otherwise look in cache
            if not original_type:
                cache_key = f"{table_name}.{column_name}"
                original_type = self.schema_cache.get(cache_key)
            
            # 3. Use provided migration_state or global migration_state
            m_state = migration_state or self.migration_state
            
            # 4. Otherwise look in migration state
            if not original_type and m_state:
                original_type = self._get_type_from_migration_state(table_name, column_name, m_state)
                if original_type:
                    self.schema_cache[f"{table_name}.{column_name}"] = original_type

            # 5. If still no type, try to load it (fallback)
            if not original_type:
                original_type = self._get_original_column_type(column_name, table_name)
            
            if not original_type:
                # No schema information available, return as-is
                return decrypted_value
            
            # Convert to the original type
            converted_value = self._convert_to_original_type(decrypted_value, original_type)
            
            self.conversion_metrics['successful_conversions'] += 1
            
            # Performance tracking
            end_time = time.perf_counter()
            latency = (end_time - start_time) * 1000
            self.conversion_metrics['latency_ms'] += latency
            
            if latency > 5:
                logger.warning(f"Type conversion took {latency:.2f}ms for {table_name}.{column_name} (type: {original_type})")
            
            return converted_value
            
        except Exception as e:
            self.conversion_metrics['failed_conversions'] += 1
            logger.error(f"Type conversion failed for {table_name}.{column_name}: {e}")
            return decrypted_value
    
    def _get_type_from_migration_state(self, table_name: str, column_name: str, migration_state: Optional[Dict] = None) -> Optional[str]:
        """Look up type in provided or current migration state"""
        state = migration_state or self.migration_state
        if not state:
            return None
            
        # Try table_configs (used in VDS)
        table_configs = state.get('table_configs', {})
        if table_name in table_configs:
            columns = table_configs[table_name].get('columns', {})
            if column_name in columns:
                return columns[column_name].get('type') or columns[column_name].get('original_type')
        
        # Try tables (alternative format)
        tables = state.get('tables', {})
        if table_name in tables:
            columns = tables[table_name].get('columns', {})
            if column_name in columns:
                return columns[column_name].get('type') or columns[column_name].get('original_type')
                
        return None

    def _get_original_column_type(self, column_name: str, table_name: str) -> Optional[str]:
        """Fallback to load schema from files if not available in memory"""
        try:
            from pathlib import Path
            import json
            
            # Common locations for migration state
            schemas_dir = Path("schemas")
            if not schemas_dir.exists():
                # Try app/../schemas
                schemas_dir = Path(__file__).parent.parent.parent / "schemas"
                
            if schemas_dir.exists():
                state_files = list(schemas_dir.glob("*_migration_state.json"))
                if state_files:
                    latest_state = max(state_files, key=lambda f: f.stat().st_mtime)
                    with open(latest_state, 'r') as f:
                        state = json.load(f)
                        self.migration_state = state # Update memory
                        return self._get_type_from_migration_state(table_name, column_name)
        except Exception:
            pass
        return None
    
    def _convert_to_original_type(self, value: Any, original_type: Any) -> Any:
        """Type casting logic with robust error handling"""
        if value is None:
            return None
            
        # If original_type is already a SQLAlchemy type or similar, stringify it for normalization
        type_str = str(original_type).upper()
        type_base = type_str.split('(')[0].strip()
        
        try:
            # Boolean
            if any(t in type_base for t in ('BOOL', 'BOOLEAN', 'TINYINT(1)')):
                if isinstance(value, bool): return value
                val_str = str(value).lower()
                if val_str in ('true', '1', 't', 'y', 'yes', 'on'): return True
                if val_str in ('false', '0', 'f', 'n', 'no', 'off'): return False
                return bool(value)

            # Integer
            if any(t in type_base for t in ('INT', 'INTEGER', 'BIGINT', 'SMALLINT', 'TINYINT', 'MEDIUMINT', 'YEAR')):
                try:
                    return int(float(value)) if isinstance(value, (str, float)) else int(value)
                except (ValueError, TypeError):
                    return 0

            # Float / Double
            if any(t in type_base for t in ('FLOAT', 'DOUBLE', 'REAL')):
                try:
                    return float(value)
                except (ValueError, TypeError):
                    return 0.0

            # Decimal
            if any(t in type_base for t in ('DECIMAL', 'NUMERIC', 'MONEY')):
                try:
                    return decimal.Decimal(str(value))
                except:
                    return float(value)

            # Date / DateTime
            if 'DATE' in type_base or 'TIMESTAMP' in type_base:
                if isinstance(value, (datetime.datetime, datetime.date)):
                    return value
                val_str = str(value)
                # Try common formats
                for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d', '%Y-%m-%dT%H:%M:%S'):
                    try:
                        dt = datetime.datetime.strptime(val_str, fmt)
                        if type_base == 'DATE': return dt.date()
                        return dt
                    except ValueError:
                        continue
                return value

            # JSON
            if 'JSON' in type_base:
                if not isinstance(value, str): return value
                try:
                    import json
                    return json.loads(value)
                except:
                    return value

            # Binary
            if any(t in type_base for t in ('BLOB', 'BINARY', 'VARBINARY')):
                if isinstance(value, bytes): return value
                try:
                    return bytes.fromhex(str(value))
                except:
                    return str(value).encode('utf-8')

            # Default: Return as-is (catches VARCHAR, TEXT, etc.)
            return value

        except Exception as e:
            logger.debug(f"Casting error for type {original_type}: {e}")
            self.conversion_metrics['fallback_to_varchar'] += 1
            return value

    def get_conversion_metrics(self) -> Dict:
        """Get flattened metrics for reporting"""
        metrics = self.conversion_metrics.copy()
        if metrics['total_conversions'] > 0:
            metrics['avg_latency_ms'] = metrics['latency_ms'] / metrics['total_conversions']
        return metrics

# Global instance
type_converter = OriginalTypeConverter()


def convert_to_original_type(value: Any, column_name: str, table_name: str, schema_type: Optional[Any] = None) -> Any:
    """
    Convenience function to convert a value to its original database type
    
    Args:
        value: The decrypted value
        column_name: Name of the column
        table_name: Name of the table
        schema_type: Optional explicit schema type
        
    Returns:
        Value converted to its original database type
    """
    return type_converter.intercept_and_convert(value, column_name, table_name, schema_type=schema_type)