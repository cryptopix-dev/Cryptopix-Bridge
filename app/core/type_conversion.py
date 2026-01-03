"""
Original Database Type Conversion Model

This model handles the conversion of decrypted string data back to the original database schema-based data types.
"""

import logging
from typing import Dict, Any, Optional
from decimal import Decimal
from datetime import datetime, date, time
import re

logger = logging.getLogger(__name__)


class EnhancedOriginalDatabaseTypeConverter:
    """
    Enhanced converter for precise type casting based on original database schema.
    Intercepts decrypted string outputs and converts to original database types with
    support for schema versioning, comprehensive error handling, and performance monitoring.
    """
    
    def __init__(self, migration_state: Optional[Dict[str, Any]] = None, schema_version: Optional[str] = None):
        """
        Initialize the enhanced type converter with migration state and schema version.
        
        Args:
            migration_state: The migration state containing original database schema information.
            schema_version: Optional schema version identifier for version-specific type conversion.
        """
        self.migration_state = migration_state or {}
        self.schema_version = schema_version or self._get_schema_version()
        self.type_cache = {}  # Schema version aware cache: "version:table.column" -> type
        self.performance_metrics = {
            'total_conversions': 0,
            'successful': 0,
            'failed': 0,
            'avg_latency_ms': 0,
            'max_latency_ms': 0,
            'last_100_latencies': []
        }
        self.fallback_log = []  # Log for fallback cases
        self._initialize_cache()
    
    def _initialize_cache(self):
        """Initialize cache with current schema version."""
        if self.migration_state and 'tables' in self.migration_state:
            for table_name, table_info in self.migration_state['tables'].items():
                if 'columns' in table_info:
                    for col_name, col_info in table_info['columns'].items():
                        if 'type' in col_info:
                            cache_key = self._get_cache_key(table_name, col_name)
                            self.type_cache[cache_key] = col_info['type']
    
    def _get_cache_key(self, table_name: str, column_name: str) -> str:
        """Generate cache key with schema version awareness."""
        return f"{self.schema_version or 'current'}:{table_name}.{column_name}"
    
    def set_migration_state(self, migration_state: Dict[str, Any], schema_version: Optional[str] = None):
        """
        Set or update the migration state and optionally the schema version.
        
        Args:
            migration_state: The migration state containing original database schema information.
            schema_version: Optional schema version identifier.
        """
        self.migration_state = migration_state
        if schema_version:
            self.schema_version = schema_version
        else:
            self.schema_version = self._get_schema_version()
        self._initialize_cache()
    
    def set_schema_version(self, schema_version: str):
        """
        Set the active schema version for type conversion.
        
        Args:
            schema_version: Schema version identifier.
        """
        self.schema_version = schema_version
        self._initialize_cache()  # Reinitialize cache with new version
    
    def get_available_schema_versions(self) -> List[str]:
        """
        Get list of available schema versions from migration state.
        
        Returns:
            List of available schema version identifiers.
        """
        if not self.migration_state or 'schema_versions' not in self.migration_state:
            return [self.schema_version or 'current']
        return list(self.migration_state['schema_versions'].keys())
         
    def set_migration_state(self, migration_state: Dict[str, Any]):
        """
        Set or update the migration state.
        
        Args:
            migration_state: The migration state containing original database schema information.
        """
        self.migration_state = migration_state
        self.schema_version = self._get_schema_version()
        self._clear_cache()
         
    def _get_schema_version(self) -> Optional[str]:
        """
        Get the schema version from migration state.
        
        Returns:
            Schema version string or None if not available.
        """
        if self.migration_state and 'schema_version' in self.migration_state:
            return self.migration_state['schema_version']
        return None
         
    def _clear_cache(self):
        """Clear the column type cache."""
        self.column_type_cache = {}
        
    def get_original_column_type(self, table_name: str, column_name: str, schema_version: Optional[str] = None) -> Optional[str]:
        """
        Get the original column type from the migration state with schema version awareness.
        
        Args:
            table_name: Name of the table.
            column_name: Name of the column.
            schema_version: Optional schema version identifier.
            
        Returns:
            Original column type as string, or None if not found.
        """
        # Use provided schema version or fall back to instance version
        effective_version = schema_version or self.schema_version
        cache_key = self._get_cache_key(table_name, column_name)
        
        # Check cache first
        if cache_key in self.type_cache:
            return self.type_cache[cache_key]
        
        # Fetch from migration state
        if not self.migration_state or 'tables' not in self.migration_state:
            return None
        
        # Try to get version-specific schema first
        if effective_version and 'schema_versions' in self.migration_state:
            versioned_tables = self.migration_state['schema_versions'].get(effective_version, {}).get('tables', {})
            if table_name in versioned_tables:
                table_info = versioned_tables[table_name]
                if 'columns' in table_info:
                    column_info = table_info['columns'].get(column_name)
                    if column_info and 'type' in column_info:
                        column_type = column_info['type']
                        self.type_cache[cache_key] = column_type
                        return column_type
        
        # Fall back to current schema
        table_info = self.migration_state['tables'].get(table_name)
        if not table_info or 'columns' not in table_info:
            return None
        
        column_info = table_info['columns'].get(column_name)
        if not column_info or 'type' not in column_info:
            return None
        
        # Cache the result
        column_type = column_info['type']
        self.type_cache[cache_key] = column_type
        return column_type
    
    def convert_decrypted_value(self, value: Any, table_name: str, column_name: str, schema_version: Optional[str] = None) -> Any:
        """
        Main entry point for type conversion after decryption.
        Converts decrypted string values to their original database types with performance tracking.
        
        Args:
            value: The decrypted value (usually a string).
            table_name: Name of the table.
            column_name: Name of the column.
            schema_version: Optional schema version identifier.
            
        Returns:
            Value converted to its original database type.
        """
        import time
        start_time = time.time()
        
        self.performance_metrics['total_conversions'] += 1
        
        # Handle NULL values explicitly
        if value is None:
            latency = time.time() - start_time
            self._record_latency(latency)
            return None
        
        # Use provided schema version or fall back to instance version
        effective_version = schema_version or self.schema_version
        
        # Get the original column type with version awareness
        original_type = self.get_original_column_type(table_name, column_name, effective_version)
        
        if not original_type:
            # If type information is not available, log fallback and return as-is
            self._log_fallback(f"No type info for {table_name}.{column_name}", value, effective_version)
            latency = time.time() - start_time
            self._record_latency(latency)
            return value
        
        # Convert based on the original type
        try:
            converted_value = self._convert_value_by_type(value, original_type)
            self.performance_metrics['successful'] += 1
            latency = time.time() - start_time
            self._record_latency(latency)
            return converted_value
        except Exception as e:
            self.performance_metrics['failed'] += 1
            self._log_fallback(f"Conversion failed for {table_name}.{column_name}: {str(e)}", value, effective_version)
            logger.warning(f"Failed to convert value '{value}' to type {original_type}: {e}")
            latency = time.time() - start_time
            self._record_latency(latency)
            return value
    
    def convert_to_original_type(self, value: Any, table_name: str, column_name: str) -> Any:
        """
        Convert a decrypted value to its original database type with performance tracking.
        This method is kept for backward compatibility.
        
        Args:
            value: The decrypted value (usually a string).
            table_name: Name of the table.
            column_name: Name of the column.
            
        Returns:
            Value converted to its original database type.
        """
        return self.convert_decrypted_value(value, table_name, column_name)
    
    def _convert_value_by_type(self, value: Any, type_string: str) -> Any:
        """
        Convert a value based on the type string from the migration state.
        
        Args:
            value: The value to convert.
            type_string: The original column type string.
            
        Returns:
            Converted value.
        """
        if value is None:
            return None
        
        # Convert to string if not already
        if not isinstance(value, str):
            value = str(value)
        
        # Normalize type string
        type_upper = type_string.upper().split('(')[0].strip()
        
        # Integer types
        if type_upper in ('BIGINT', 'BIGINTEGER', 'INTEGER', 'INT', 'SMALLINT', 'TINYINT'):
            return self._convert_to_int(value, type_upper)
        
        # Boolean type
        if type_upper in ('BOOLEAN', 'BOOL'):
            return self._convert_to_bool(value)
        
        # Decimal/Numeric types
        if type_upper in ('DECIMAL', 'NUMERIC', 'DEC'):
            return self._convert_to_decimal(value, type_string)
        
        # Float types
        if type_upper in ('FLOAT', 'DOUBLE', 'REAL'):
            return self._convert_to_float(value, type_upper)
        
        # Date/Time types
        if type_upper == 'DATE':
            return self._convert_to_date(value)
        
        if type_upper == 'DATETIME':
            return self._convert_to_datetime(value)
        
        if type_upper == 'TIME':
            return self._convert_to_time(value)
        
        if type_upper == 'TIMESTAMP':
            return self._convert_to_timestamp(value)
        
        # String types - return as-is
        if type_upper in ('VARCHAR', 'NVARCHAR', 'CHAR', 'NCHAR', 'TEXT', 'TINYTEXT', 'MEDIUMTEXT', 'LONGTEXT'):
            return value
        
        # Binary types - return as-is (already decrypted)
        if type_upper in ('BLOB', 'TINYBLOB', 'MEDIUMBLOB', 'LONGBLOB', 'BINARY', 'VARBINARY'):
            return value
        
        # JSON type - return as-is
        if type_upper == 'JSON':
            return value
        
        # Default: return as-is
        return value
    
    def _convert_to_int(self, value: str, type_upper: str) -> int:
        """Convert value to integer."""
        try:
            return int(value)
        except ValueError:
            # For TINYINT(1), also check for boolean-like strings
            if type_upper == 'TINYINT' and value.lower() in ('true', 't', 'yes', 'y', 'on', '1'):
                return 1
            if type_upper == 'TINYINT' and value.lower() in ('false', 'f', 'no', 'n', 'off', '0'):
                return 0
            return 0
    
    def _convert_to_bool(self, value: str) -> bool:
        """Convert value to boolean."""
        if value.lower() in ('true', 't', 'yes', 'y', 'on', '1'):
            return True
        if value.lower() in ('false', 'f', 'no', 'n', 'off', '0'):
            return False
        return bool(int(value)) if value.isdigit() else False
    
    def _convert_to_decimal(self, value: str, type_string: str) -> Decimal:
        """Convert value to Decimal."""
        try:
            return Decimal(value)
        except:
            return Decimal('0')
    
    def _convert_to_float(self, value: str, type_upper: str) -> float:
        """Convert value to float."""
        try:
            return float(value)
        except ValueError:
            return 0.0
    
    def _convert_to_date(self, value: str) -> date:
        """Convert value to date."""
        try:
            return datetime.strptime(value, '%Y-%m-%d').date()
        except ValueError:
            # Try other common date formats
            for fmt in ['%Y/%m/%d', '%d-%m-%Y', '%d/%m/%Y']:
                try:
                    return datetime.strptime(value, fmt).date()
                except ValueError:
                    continue
            return date.today()
    
    def _convert_to_datetime(self, value: str) -> datetime:
        """Convert value to datetime."""
        try:
            return datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            # Try other common datetime formats
            for fmt in ['%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S', '%Y/%m/%d %H:%M:%S']:
                try:
                    return datetime.strptime(value, fmt)
                except ValueError:
                    continue
            return datetime.now()
    
    def _convert_to_time(self, value: str) -> time:
        """Convert value to time."""
        try:
            return datetime.strptime(value, '%H:%M:%S').time()
        except ValueError:
            # Try other common time formats
            for fmt in ['%H:%M', '%H:%M:%S.%f']:
                try:
                    return datetime.strptime(value, fmt).time()
                except ValueError:
                    continue
            return time(0, 0, 0)
    
    def _convert_to_timestamp(self, value: str) -> datetime:
        """Convert value to timestamp (datetime)."""
        return self._convert_to_datetime(value)
    
    def _record_latency(self, latency_seconds: float):
        """
        Record conversion latency for performance monitoring.
        
        Args:
            latency_seconds: Latency in seconds.
        """
        latency_ms = latency_seconds * 1000  # Convert to milliseconds
        
        # Keep track of last 100 latencies for moving average
        self.performance_metrics['last_100_latencies'].append(latency_ms)
        if len(self.performance_metrics['last_100_latencies']) > 100:
            self.performance_metrics['last_100_latencies'].pop(0)
        
        # Calculate moving average
        if self.performance_metrics['last_100_latencies']:
            avg_latency = sum(self.performance_metrics['last_100_latencies']) / len(self.performance_metrics['last_100_latencies'])
            self.performance_metrics['avg_latency_ms'] = avg_latency
    
    def _log_fallback(self, reason: str, value: Any, schema_version: Optional[str] = None):
        """
        Log fallback cases for debugging and monitoring with schema version awareness.
        
        Args:
            reason: Reason for fallback.
            value: The value that triggered the fallback.
            schema_version: Schema version where fallback occurred.
        """
        effective_version = schema_version or self.schema_version
        fallback_entry = {
            'timestamp': datetime.now().isoformat(),
            'reason': reason,
            'value': str(value)[:100],  # Limit value length
            'schema_version': effective_version,
            'table_column': reason.split(' for ')[-1] if ' for ' in reason else 'unknown'
        }
        
        # Keep only the last 1000 fallback entries to limit memory usage
        self.fallback_log.append(fallback_entry)
        if len(self.fallback_log) > 1000:
            self.fallback_log.pop(0)
        
        logger.debug(f"Type conversion fallback [{effective_version}]: {reason}")
    
    def _record_latency(self, latency_seconds: float):
        """
        Record conversion latency for performance monitoring with enhanced metrics.
        
        Args:
            latency_seconds: Latency in seconds.
        """
        latency_ms = latency_seconds * 1000  # Convert to milliseconds
        
        # Update max latency
        if latency_ms > self.performance_metrics['max_latency_ms']:
            self.performance_metrics['max_latency_ms'] = latency_ms
        
        # Keep track of last 100 latencies for moving average
        self.performance_metrics['last_100_latencies'].append(latency_ms)
        if len(self.performance_metrics['last_100_latencies']) > 100:
            self.performance_metrics['last_100_latencies'].pop(0)
        
        # Calculate moving average
        if self.performance_metrics['last_100_latencies']:
            avg_latency = sum(self.performance_metrics['last_100_latencies']) / len(self.performance_metrics['last_100_latencies'])
            self.performance_metrics['avg_latency_ms'] = avg_latency
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """
        Get comprehensive performance summary including success rate and latency metrics.
        
        Returns:
            Dictionary containing comprehensive performance metrics.
        """
        summary = self.performance_metrics.copy()
        summary['success_rate'] = (summary['successful'] / summary['total_conversions']) * 100 if summary['total_conversions'] > 0 else 100.0
        summary['failure_rate'] = (summary['failed'] / summary['total_conversions']) * 100 if summary['total_conversions'] > 0 else 0.0
        summary['cache_size'] = len(self.type_cache)
        summary['fallback_count'] = len(self.fallback_log)
        return summary
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """
        Get performance metrics for monitoring.
        
        Returns:
            Dictionary containing performance metrics.
        """
        return self.performance_metrics.copy()
    
    def get_fallback_log(self) -> List[Dict[str, Any]]:
        """
        Get the fallback log for debugging.
        
        Returns:
            List of fallback log entries.
        """
        return self.fallback_log.copy()
    
    def clear_fallback_log(self):
        """Clear the fallback log."""
        self.fallback_log.clear()
    
    def handle_unsupported_type(self, value: Any, type_string: str) -> Any:
        """
        Handle unsupported data types with graceful fallback.
        
        Args:
            value: The value to handle.
            type_string: The unsupported type string.
            
        Returns:
            Value with appropriate fallback handling.
        """
        self._log_fallback(f"Unsupported type: {type_string}", value)
        
        # For unsupported types, return as VARCHAR (string)
        if value is None:
            return None
        return str(value)
    
    def handle_schema_mismatch(self, value: Any, table_name: str, column_name: str) -> Any:
        """
        Handle schema mismatches gracefully.
        
        Args:
            value: The value to handle.
            table_name: Name of the table.
            column_name: Name of the column.
            
        Returns:
            Value with appropriate fallback handling.
        """
        self._log_fallback(f"Schema mismatch for {table_name}.{column_name}", value)
        
        # For schema mismatches, return as VARCHAR (string)
        if value is None:
            return None
        return str(value)
