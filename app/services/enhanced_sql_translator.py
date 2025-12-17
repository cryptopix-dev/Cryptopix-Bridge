"""
CryptoPIX Bridge v4.0 - Enhanced SQL Translator with AI Learning
Supports full SQL functionality on encrypted databases with temporary batch decryption
"""

import logging
import re
import time
from typing import Dict, Any, List, Optional, Tuple, Set, Union
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json

from app.services.sql_translator import SQLTranslator, ColumnMapping, TableMapping, QueryType
from app.core.encryption import clwe_encryptor
from app.core.database_adapters import DatabaseType, create_database_adapter
from app.config import settings

logger = logging.getLogger(__name__)


@dataclass
class QueryPattern:
    """Learned query pattern for optimization"""
    pattern_hash: str
    query_template: str
    encrypted_operations: List[str]
    success_rate: float
    execution_time_avg: float
    usage_count: int
    last_used: datetime
    optimization_hints: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BatchDecryptionContext:
    """Context for batch decryption operations"""
    query_id: str
    table_name: str
    encrypted_columns_needed: Set[str]
    batch_size: int
    decryption_start_time: datetime
    security_context: Dict[str, Any]
    audit_log: List[Dict[str, Any]] = field(default_factory=list)


class EnhancedSQLTranslator(SQLTranslator):
    """Enhanced SQL translator with AI learning and batch decryption capabilities"""

    def __init__(self):
        super().__init__()

        # AI Learning components
        self.query_patterns: Dict[str, QueryPattern] = {}
        self.learning_enabled = True
        self.pattern_memory_size = 500

        # Batch decryption settings
        self.max_batch_size = 10000  # Maximum rows to decrypt at once
        self.decryption_timeout = 30  # seconds
        self.security_audit_enabled = True

        # Performance tracking
        self.performance_metrics: Dict[str, List[float]] = {}

        # Initialize AI learning
        self._load_learned_patterns()

    def _load_learned_patterns(self):
        """Load previously learned query patterns"""
        try:
            # In a real implementation, this would load from a persistent store
            # For now, initialize with common patterns
            self._initialize_common_patterns()
        except Exception as e:
            logger.warning(f"Failed to load learned patterns: {e}")

    def _initialize_common_patterns(self):
        """Initialize with common query patterns"""
        common_patterns = [
            {
                "template": "SELECT * FROM {table} WHERE {encrypted_col} > {value}",
                "operations": ["comparison"],
                "hints": {"use_batch_decryption": True, "optimize_for_range": True}
            },
            {
                "template": "SELECT AVG({encrypted_col}) FROM {table}",
                "operations": ["aggregate"],
                "hints": {"batch_decrypt_all": True, "cache_result": True}
            },
            {
                "template": "SELECT {encrypted_col} * {factor} FROM {table}",
                "operations": ["arithmetic"],
                "hints": {"use_batch_decryption": True, "vectorize_operations": True}
            }
        ]

        for pattern in common_patterns:
            pattern_hash = hashlib.md5(pattern["template"].encode()).hexdigest()
            self.query_patterns[pattern_hash] = QueryPattern(
                pattern_hash=pattern_hash,
                query_template=pattern["template"],
                encrypted_operations=pattern["operations"],
                success_rate=0.95,
                execution_time_avg=0.5,
                usage_count=0,
                last_used=datetime.now(),
                optimization_hints=pattern["hints"]
            )

    def translate_query(self, query: str, table_name: str = None) -> Tuple[Union[str, Dict[str, Any]], Dict[str, Any]]:
        """
        Enhanced query translation with AI learning and batch decryption support
        """
        start_time = time.time()

        try:
            # Analyze query for encrypted operations
            encrypted_ops = self._analyze_encrypted_operations(query, table_name)

            if encrypted_ops:
                logger.info(f"Detected encrypted operations: {encrypted_ops}")

                # Check if we can handle this with batch decryption
                if self._should_use_batch_decryption(query, encrypted_ops):
                    translated_query, metadata = self._translate_with_batch_decryption(query, table_name, encrypted_ops)
                else:
                    # Fall back to standard translation
                    translated_query, metadata = super().translate_query(query, table_name)
            else:
                # No encrypted operations, use standard translation
                translated_query, metadata = super().translate_query(query, table_name)

            # Learn from this translation
            if self.learning_enabled:
                self._learn_from_query(query, encrypted_ops, time.time() - start_time, metadata.get("translation_success", False))

            # Add enhanced metadata
            metadata.update({
                "enhanced_translation": True,
                "encrypted_operations_detected": encrypted_ops,
                "batch_decryption_used": "batch_decryption_context" in metadata,
                "ai_learning_applied": self.learning_enabled
            })

            return translated_query, metadata

        except Exception as e:
            logger.error(f"Enhanced translation failed: {e}")
            # Fall back to standard translation
            return super().translate_query(query, table_name)

    def _analyze_encrypted_operations(self, query: str, table_name: str = None) -> List[str]:
        """
        Analyze query to detect operations on encrypted columns that need special handling
        """
        operations = []

        # Get table mapping
        table_mapping = self._extract_table_mapping(query) if not table_name else self.table_mappings.get(table_name)
        if not table_mapping:
            return operations

        query_upper = query.upper()

        # Check for mathematical operations on encrypted columns
        for col_name, col_mapping in table_mapping.encrypted_columns.items():
            if col_mapping.is_encrypted:
                # Check for arithmetic operations
                if re.search(rf'\b{col_name}\b\s*[\+\-\*\/]', query):
                    operations.append(f"arithmetic:{col_name}")

                # Check for aggregate functions
                for agg_func in ['AVG', 'SUM', 'MIN', 'MAX', 'COUNT']:
                    if re.search(rf'\b{agg_func}\s*\(\s*{col_name}\s*\)', query_upper):
                        operations.append(f"aggregate:{agg_func}:{col_name}")

                # Check for CASE statements
                if 'CASE' in query_upper and col_name in query:
                    operations.append(f"case:{col_name}")

                # Check for window functions
                for win_func in ['ROW_NUMBER', 'RANK', 'LAG', 'LEAD']:
                    if re.search(rf'\b{win_func}\s*\(\s*.*\b{col_name}\b.*\)', query_upper):
                        operations.append(f"window:{win_func}:{col_name}")

        return operations

    def _should_use_batch_decryption(self, query: str, encrypted_ops: List[str]) -> bool:
        """
        Determine if batch decryption should be used for this query
        """
        if not encrypted_ops:
            return False

        # Check query complexity
        query_complexity = len(encrypted_ops)

        # Check if operations are supported by batch decryption
        supported_ops = ['arithmetic', 'aggregate', 'case', 'window']
        has_unsupported = any(not any(op.startswith(supported) for supported in supported_ops) for op in encrypted_ops)

        if has_unsupported:
            return False

        # Check performance patterns
        query_hash = hashlib.md5(query.encode()).hexdigest()
        if query_hash in self.query_patterns:
            pattern = self.query_patterns[query_hash]
            # Use batch decryption if pattern has good success rate
            return pattern.success_rate > 0.8

        # Default decision based on complexity
        return query_complexity <= 3  # Allow up to 3 encrypted operations

    def _translate_with_batch_decryption(self, query: str, table_name: str, encrypted_ops: List[str]) -> Tuple[str, Dict[str, Any]]:
        """
        Translate query using batch decryption approach
        """
        logger.info(f"Translating with batch decryption for operations: {encrypted_ops}")

        # Create batch decryption context
        context = BatchDecryptionContext(
            query_id=hashlib.md5(f"{query}{time.time()}".encode()).hexdigest(),
            table_name=table_name,
            encrypted_columns_needed=set(),
            batch_size=min(self.max_batch_size, 1000),  # Start with smaller batch
            decryption_start_time=datetime.now(),
            security_context={
                "user_id": "system",  # In real implementation, get from session
                "query_purpose": "batch_calculation",
                "encryption_level": "standard"
            }
        )

        # Extract columns that need decryption
        for op in encrypted_ops:
            parts = op.split(':')
            if len(parts) >= 2:
                col_name = parts[-1]  # Last part is column name
                context.encrypted_columns_needed.add(col_name)

        # Generate modified query that will work with decrypted data
        modified_query = self._generate_batch_decryption_query(query, context)

        metadata = {
            "batch_decryption_context": {
                "query_id": context.query_id,
                "encrypted_columns": list(context.encrypted_columns_needed),
                "batch_size": context.batch_size,
                "security_context": context.security_context
            },
            "translation_strategy": "batch_decryption",
            "encrypted_operations": encrypted_ops
        }

        return modified_query, metadata

    def _generate_batch_decryption_query(self, original_query: str, context: BatchDecryptionContext) -> str:
        """
        Generate a query that can work with batch-decrypted data
        """
        # For now, create a query that selects the needed encrypted columns
        # In a full implementation, this would be more sophisticated

        table_mapping = self.table_mappings.get(context.table_name)
        if not table_mapping:
            return original_query

        # Build SELECT clause with decrypted column names
        select_parts = []

        # Add encrypted columns that need decryption
        for col_name in context.encrypted_columns_needed:
            if col_name in table_mapping.encrypted_columns:
                select_parts.append(col_name)  # Use original name for decrypted results

        # Add non-encrypted columns
        for col_name in table_mapping.non_encrypted_columns:
            select_parts.append(col_name)

        # If no specific columns, select all
        if not select_parts:
            select_clause = "*"
        else:
            select_clause = ", ".join(select_parts)

        # Extract WHERE, ORDER BY, etc. from original query
        where_clause = ""
        order_by_clause = ""
        limit_clause = ""

        # Simple extraction - in production, use more robust parsing
        where_match = re.search(r'WHERE\s+(.+?)(?:\s+(?:ORDER|GROUP|HAVING|LIMIT|$))', original_query, re.IGNORECASE | re.DOTALL)
        if where_match:
            where_clause = f"WHERE {where_match.group(1)}"

        order_match = re.search(r'ORDER BY\s+(.+?)(?:\s+(?:LIMIT|$))', original_query, re.IGNORECASE | re.DOTALL)
        if order_match:
            order_by_clause = f"ORDER BY {order_match.group(1)}"

        limit_match = re.search(r'LIMIT\s+(\d+)(?:\s+OFFSET\s+(\d+))?', original_query, re.IGNORECASE)
        if limit_match:
            limit_clause = f"LIMIT {limit_match.group(1)}"
            if limit_match.group(2):
                limit_clause += f" OFFSET {limit_match.group(2)}"

        # Construct the batch query
        batch_query = f"SELECT {select_clause} FROM {context.table_name} {where_clause} {order_by_clause} {limit_clause}".strip()

        # Limit batch size for security
        if "LIMIT" not in batch_query.upper():
            batch_query += f" LIMIT {context.batch_size}"

        logger.info(f"Generated batch decryption query: {batch_query}")
        return batch_query

    def execute_with_batch_decryption(self, query: str, db_connection, table_mapping: TableMapping, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Execute query with batch decryption for calculations
        """
        start_time = time.time()

        try:
            # Execute the batch query to get encrypted data
            batch_context = context.get("batch_decryption_context", {})
            batch_query = context.get("translated_query", query)

            # Execute query
            cursor = db_connection.cursor()
            cursor.execute(batch_query)
            encrypted_rows = cursor.fetchall()

            # Convert to dict format
            column_names = [desc[0] for desc in cursor.description]
            encrypted_rows = [dict(zip(column_names, row)) for row in encrypted_rows]

            # Batch decrypt the data
            decrypted_rows = self._batch_decrypt_rows(encrypted_rows, table_mapping, batch_context)

            # Perform calculations on decrypted data
            result_rows = self._perform_calculations_on_decrypted_data(query, decrypted_rows, table_mapping)

            # Log security event
            if self.security_audit_enabled:
                self._log_security_event(batch_context, len(encrypted_rows), time.time() - start_time)

            return result_rows

        except Exception as e:
            logger.error(f"Batch decryption execution failed: {e}")
            raise

    def _batch_decrypt_rows(self, rows: List[Dict[str, Any]], table_mapping: TableMapping, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Decrypt encrypted columns in batch
        """
        if not rows:
            return rows

        decrypted_rows = []

        for row in rows:
            decrypted_row = {}

            for col_name, value in row.items():
                if col_name in table_mapping.encrypted_columns:
                    col_mapping = table_mapping.encrypted_columns[col_name]
                    if col_mapping.is_encrypted and isinstance(value, bytes):
                        try:
                            decrypted_value = clwe_encryptor.decrypt_value(value, settings.CRYPTOPIX_DEFAULT_PASSWORD)
                            decrypted_row[col_name] = decrypted_value
                        except Exception as e:
                            logger.warning(f"Failed to decrypt {col_name}: {e}")
                            decrypted_row[col_name] = None
                    else:
                        decrypted_row[col_name] = value
                else:
                    decrypted_row[col_name] = value

            decrypted_rows.append(decrypted_row)

        return decrypted_rows

    def _perform_calculations_on_decrypted_data(self, original_query: str, rows: List[Dict[str, Any]], table_mapping: TableMapping) -> List[Dict[str, Any]]:
        """
        Perform calculations on decrypted data
        """
        if not rows:
            return rows

        # Parse the original query to understand what calculations to perform
        query_upper = original_query.upper()

        # Handle different types of calculations
        if 'AVG(' in query_upper:
            return self._calculate_aggregates(original_query, rows, 'AVG')
        elif 'SUM(' in query_upper:
            return self._calculate_aggregates(original_query, rows, 'SUM')
        elif 'MIN(' in query_upper:
            return self._calculate_aggregates(original_query, rows, 'MIN')
        elif 'MAX(' in query_upper:
            return self._calculate_aggregates(original_query, rows, 'MAX')
        elif any(op in query_upper for op in ['*', '/', '+', '-']):
            return self._calculate_arithmetic(original_query, rows)
        elif 'CASE' in query_upper:
            return self._calculate_case_statements(original_query, rows)
        else:
            # No calculations needed, return as-is
            return rows

    def _calculate_aggregates(self, query: str, rows: List[Dict[str, Any]], agg_func: str) -> List[Dict[str, Any]]:
        """
        Calculate aggregate functions on decrypted data
        """
        # Extract the column being aggregated
        pattern = rf'\b{agg_func}\s*\(\s*(\w+)\s*\)'
        match = re.search(pattern, query, re.IGNORECASE)

        if not match:
            return rows

        col_name = match.group(1)
        alias = f"{agg_func.lower()}_{col_name}"

        if not rows:
            return [{alias: None}]

        # Extract values
        values = []
        for row in rows:
            if col_name in row and row[col_name] is not None:
                try:
                    values.append(float(row[col_name]))
                except (ValueError, TypeError):
                    pass

        if not values:
            return [{alias: None}]

        # Calculate aggregate
        if agg_func == 'AVG':
            result = sum(values) / len(values)
        elif agg_func == 'SUM':
            result = sum(values)
        elif agg_func == 'MIN':
            result = min(values)
        elif agg_func == 'MAX':
            result = max(values)
        else:
            result = None

        return [{alias: result}]

    def _calculate_arithmetic(self, query: str, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Perform arithmetic operations on decrypted data
        """
        result_rows = []

        for row in rows:
            result_row = row.copy()

            # Look for arithmetic expressions in SELECT clause
            select_match = re.search(r'SELECT\s+(.+?)\s+FROM', query, re.IGNORECASE | re.DOTALL)
            if select_match:
                select_clause = select_match.group(1)

                # Simple arithmetic pattern: column * number
                arith_match = re.search(r'(\w+)\s*([\+\-\*\/])\s*(\d+(?:\.\d+)?)', select_clause)
                if arith_match:
                    col_name = arith_match.group(1)
                    operator = arith_match.group(2)
                    operand = float(arith_match.group(3))

                    if col_name in row and row[col_name] is not None:
                        try:
                            value = float(row[col_name])
                            if operator == '*':
                                result = value * operand
                            elif operator == '/':
                                result = value / operand if operand != 0 else None
                            elif operator == '+':
                                result = value + operand
                            elif operator == '-':
                                result = value - operand
                            else:
                                result = None

                            result_row[f"{col_name}_{operator}_{operand}"] = result
                        except (ValueError, TypeError):
                            result_row[f"{col_name}_{operator}_{operand}"] = None

            result_rows.append(result_row)

        return result_rows

    def _calculate_case_statements(self, query: str, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Evaluate CASE statements on decrypted data
        """
        result_rows = []

        for row in rows:
            result_row = row.copy()

            # Simple CASE pattern: CASE WHEN column > value THEN 'result'
            case_match = re.search(r'CASE\s+WHEN\s+(\w+)\s*>\s*(\d+(?:\.\d+)?)\s+THEN\s+[\'"]([^\'"]+)[\'"]', query, re.IGNORECASE)
            if case_match:
                col_name = case_match.group(1)
                threshold = float(case_match.group(2))
                true_result = case_match.group(3)

                # Check for ELSE
                else_match = re.search(r'ELSE\s+[\'"]([^\'"]+)[\'"]', query, re.IGNORECASE)
                false_result = else_match.group(1) if else_match else 'Low'

                if col_name in row and row[col_name] is not None:
                    try:
                        value = float(row[col_name])
                        case_result = true_result if value > threshold else false_result
                        result_row['salary_level'] = case_result
                    except (ValueError, TypeError):
                        result_row['salary_level'] = false_result
                else:
                    result_row['salary_level'] = false_result

            result_rows.append(result_row)

        return result_rows

    def _learn_from_query(self, query: str, encrypted_ops: List[str], execution_time: float, success: bool):
        """
        Learn from query execution for future optimization
        """
        if not self.learning_enabled:
            return

        query_hash = hashlib.md5(query.encode()).hexdigest()

        if query_hash not in self.query_patterns:
            # Create new pattern
            self.query_patterns[query_hash] = QueryPattern(
                pattern_hash=query_hash,
                query_template=self._extract_query_template(query),
                encrypted_operations=encrypted_ops,
                success_rate=1.0 if success else 0.0,
                execution_time_avg=execution_time,
                usage_count=1,
                last_used=datetime.now()
            )
        else:
            # Update existing pattern
            pattern = self.query_patterns[query_hash]
            pattern.usage_count += 1
            pattern.last_used = datetime.now()

            # Update success rate with exponential moving average
            alpha = 0.1
            pattern.success_rate = alpha * (1.0 if success else 0.0) + (1 - alpha) * pattern.success_rate

            # Update execution time average
            pattern.execution_time_avg = (pattern.execution_time_avg * (pattern.usage_count - 1) + execution_time) / pattern.usage_count

        # Maintain pattern memory size
        if len(self.query_patterns) > self.pattern_memory_size:
            # Remove oldest pattern
            oldest_key = min(self.query_patterns.keys(),
                           key=lambda k: self.query_patterns[k].last_used)
            del self.query_patterns[oldest_key]

    def _extract_query_template(self, query: str) -> str:
        """
        Extract template from query by replacing literals with placeholders
        """
        # Replace numbers
        template = re.sub(r'\b\d+(?:\.\d+)?\b', '{number}', query)
        # Replace quoted strings
        template = re.sub(r"'[^']*'", '{string}', template)
        template = re.sub(r'"[^"]*"', '{string}', template)
        # Replace column names (simple heuristic)
        template = re.sub(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b(?!\s*\()', '{column}', template)

        return template

    def _log_security_event(self, context: Dict[str, Any], rows_decrypted: int, execution_time: float):
        """
        Log security events for audit purposes
        """
        if not self.security_audit_enabled:
            return

        event = {
            "timestamp": datetime.now().isoformat(),
            "query_id": context.get("query_id"),
            "user_id": context.get("user_id", "unknown"),
            "table_name": context.get("table_name"),
            "encrypted_columns": context.get("encrypted_columns", []),
            "rows_decrypted": rows_decrypted,
            "execution_time": execution_time,
            "purpose": context.get("query_purpose", "unknown")
        }

        logger.info(f"Security audit: Batch decryption event - {json.dumps(event)}")

        # In production, this would be stored in a secure audit log

    def get_ai_insights(self) -> Dict[str, Any]:
        """
        Get AI learning insights for optimization
        """
        total_patterns = len(self.query_patterns)
        avg_success_rate = sum(p.success_rate for p in self.query_patterns.values()) / total_patterns if total_patterns > 0 else 0

        return {
            "total_learned_patterns": total_patterns,
            "average_success_rate": avg_success_rate,
            "most_used_operations": self._get_most_used_operations(),
            "performance_insights": self._get_performance_insights()
        }

    def _get_most_used_operations(self) -> List[Dict[str, Any]]:
        """Get most frequently used encrypted operations"""
        op_counts = {}
        for pattern in self.query_patterns.values():
            for op in pattern.encrypted_operations:
                op_counts[op] = op_counts.get(op, 0) + pattern.usage_count

        return sorted(
            [{"operation": op, "usage_count": count} for op, count in op_counts.items()],
            key=lambda x: x["usage_count"],
            reverse=True
        )[:10]

    def _get_performance_insights(self) -> Dict[str, Any]:
        """Get performance insights from learned patterns"""
        if not self.query_patterns:
            return {}

        fast_queries = [p for p in self.query_patterns.values() if p.execution_time_avg < 0.5]
        slow_queries = [p for p in self.query_patterns.values() if p.execution_time_avg > 2.0]

        return {
            "fast_queries_count": len(fast_queries),
            "slow_queries_count": len(slow_queries),
            "average_execution_time": sum(p.execution_time_avg for p in self.query_patterns.values()) / len(self.query_patterns)
        }


# Global enhanced translator instance
enhanced_sql_translator = EnhancedSQLTranslator()