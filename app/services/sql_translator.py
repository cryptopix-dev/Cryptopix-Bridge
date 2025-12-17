"""
CryptoPIX Bridge v3.0 - SQL Translator Service
Translates client SQL queries to work with encrypted database schema
"""

import logging
import re
from typing import Dict, Any, List, Optional, Tuple, Set, Union
from dataclasses import dataclass
from enum import Enum

from app.config import settings
from app.core.encryption import clwe_encryptor
from app.core.database_adapters import DatabaseType, create_database_adapter

logger = logging.getLogger(__name__)


class QueryType(Enum):
    """SQL query types"""
    SELECT = "SELECT"
    INSERT = "INSERT"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    CREATE = "CREATE"
    ALTER = "ALTER"
    DROP = "DROP"
    TRUNCATE = "TRUNCATE"
    MERGE = "MERGE"
    REPLACE = "REPLACE"
    SHOW = "SHOW"
    DESCRIBE = "DESCRIBE"
    EXPLAIN = "EXPLAIN"
    TRANSACTION = "TRANSACTION"
    DCL = "DCL"
    CALL = "CALL"
    USE = "USE"

@dataclass
class ColumnMapping:
    """Column mapping information with unified tagging"""
    original_name: str
    encrypted_name: str  # Same as original_name for encrypted columns
    tag_name: Optional[str]  # Tag column for HMAC values
    is_encrypted: bool
    is_hashed: bool  # Always False now
    data_type: str
    supports_ordering: bool = True
    supports_ranges: bool = True


@dataclass
class TableMapping:
    """Table mapping information"""
    original_name: str
    encrypted_columns: Dict[str, ColumnMapping]
    primary_key: Optional[str]
    non_encrypted_columns: Set[str]


class SQLTranslationError(Exception):
    """Custom exception for SQL translation errors"""
    pass


class SQLTranslator:
    """Universal SQL query translator for encrypted databases with intelligent rules"""

    def __init__(self):
        self.table_mappings: Dict[str, TableMapping] = {}
        self.database_type: Optional[str] = None

        self.translation_cache: Dict[str, Tuple[str, Dict[str, Any]]] = {}
        self.cache_max_size = 1000  # Maximum cache entries

        self._compile_regex_patterns()

        self.translation_strategies: Dict[str, str] = {}

    def _analyze_query_context(self, query: str, table_mapping: TableMapping) -> Dict[str, Any]:
        """
        Analyze query context to determine optimal translation strategy for encrypted columns

        Returns:
            Dict with strategy decisions for each encrypted column
        """
        if not table_mapping:
            return {}

        context = {
            'needs_decryption': False,
            'needs_tags': False,
            'can_use_encrypted_data': True,
            'select_strategies': {},  # Strategies for SELECT clause
            'filter_strategies': {}   # Strategies for WHERE/ORDER BY/GROUP BY
        }

        query_upper = query.upper()

        if 'SELECT' in query_upper:
            select_match = re.search(r'SELECT\s+(.+?)\s+FROM', query, re.IGNORECASE | re.DOTALL)
            if select_match:
                select_clause = select_match.group(1)
                if select_clause.strip() == '*':
                    context['needs_decryption'] = True
                else:
                    for col_name, col_mapping in table_mapping.encrypted_columns.items():
                        if col_mapping.is_encrypted:
                            if col_name in select_clause or f'{col_name},' in select_clause:
                                context['needs_decryption'] = True
                                break

        if 'WHERE' in query_upper:
            context['needs_tags'] = True
            for col_name, col_mapping in table_mapping.encrypted_columns.items():
                if col_mapping.is_encrypted and col_mapping.tag_name:
                    if re.search(rf'\b{col_name}\b', query):
                        context['filter_strategies'][col_name] = 'use_tags'

        if 'ORDER BY' in query_upper:
            for col_name, col_mapping in table_mapping.encrypted_columns.items():
                if col_mapping.is_encrypted and col_mapping.tag_name and col_mapping.supports_ordering:
                    if re.search(rf'\b{col_name}\b', query):
                        context['filter_strategies'][col_name] = 'use_tags'

        if 'GROUP BY' in query_upper:
            for col_name, col_mapping in table_mapping.encrypted_columns.items():
                if col_mapping.is_encrypted and col_mapping.tag_name:
                    if re.search(rf'\b{col_name}\b', query):
                        context['filter_strategies'][col_name] = 'use_tags'

        context['can_use_encrypted_data'] = not context['needs_decryption']

        for col_name, col_mapping in table_mapping.encrypted_columns.items():
            if col_mapping.is_encrypted:
                if context['needs_decryption']:
                    context['select_strategies'][col_name] = 'decrypt'
                    logger.debug(f"Set SELECT strategy 'decrypt' for column {col_name}")
                elif context['can_use_encrypted_data']:
                    context['select_strategies'][col_name] = 'use_encrypted_data'
                    logger.debug(f"Set SELECT strategy 'use_encrypted_data' for column {col_name}")
                else:
                    context['select_strategies'][col_name] = 'decrypt'
                    logger.debug(f"Set SELECT strategy 'decrypt' (fallback) for column {col_name}")

        context['column_strategies'] = context['filter_strategies']

        logger.debug(f"Query context analysis: needs_decryption={context['needs_decryption']}, select_strategies={context['select_strategies']}, filter_strategies={context['filter_strategies']}")
        return context

    def _compile_regex_patterns(self):
        """Pre-compile regex patterns for better performance"""
        self.patterns = {
            'union_split': re.compile(r'\s+(UNION\s+(?:ALL|DISTINCT)?)\s+', re.IGNORECASE),
            'intersect_split': re.compile(r'\s+INTERSECT\s+', re.IGNORECASE),
            'except_split': re.compile(r'\s+(EXCEPT|MINUS)\s+', re.IGNORECASE),
            'select_from': re.compile(r'\bFROM\s+([^\s,()]+)', re.IGNORECASE),
            'insert_into': re.compile(r'\bINSERT\s+INTO\s+([^\s(]+)', re.IGNORECASE),
            'update_table': re.compile(r'\bUPDATE\s+([^\s]+)', re.IGNORECASE),
            'delete_from': re.compile(r'\bDELETE\s+FROM\s+([^\s]+)', re.IGNORECASE),
            'values_clause': re.compile(r'VALUES\s*\(([^)]+)\)', re.IGNORECASE),
            'where_clause': re.compile(r'WHERE\s+(.+?)(?:\s+(?:ORDER|GROUP|HAVING|LIMIT|$))', re.IGNORECASE | re.DOTALL),
            'group_by': re.compile(r'GROUP BY\s+(.+?)(?:\s+(?:HAVING|ORDER|LIMIT|$))', re.IGNORECASE | re.DOTALL),
            'having_clause': re.compile(r'HAVING\s+(.+?)(?:\s+(?:ORDER|LIMIT|$))', re.IGNORECASE | re.DOTALL),
            'order_by': re.compile(r'ORDER BY\s+(.+?)(?:\s+(?:GROUP|HAVING|LIMIT|$))', re.IGNORECASE | re.DOTALL),
            'join_clause': re.compile(r'(INNER\s+JOIN|LEFT\s+JOIN|RIGHT\s+JOIN|FULL\s+OUTER\s+JOIN|CROSS\s+JOIN|JOIN)\s+(\w+)\s+ON\s+(.+?)(?:\s+(?:WHERE|GROUP|ORDER|LIMIT|$))', re.IGNORECASE | re.DOTALL),
            'function_call': re.compile(r'\b(\w+)\s*\('),
            'column_reference': re.compile(r'\b\w+\b'),
            'quoted_string': re.compile(r"'([^']*)'"),
            'cte_with': re.compile(r'\bWITH\b', re.IGNORECASE),
            'pivot_unpivot': re.compile(r'\b(PIVOT|UNPIVOT)\b', re.IGNORECASE),
        }

        self.math_functions = {
            'ABS', 'ROUND', 'CEIL', 'FLOOR', 'POWER', 'SQRT', 'EXP', 'LN', 'LOG', 'LOG10', 'LOG2',
            'SIN', 'COS', 'TAN', 'ASIN', 'ACOS', 'ATAN', 'ATAN2', 'COT', 'SEC', 'CSC',
            'MOD', 'PI', 'SIGN', 'TRUNC', 'GREATEST', 'LEAST', 'RADIANS', 'DEGREES',
            'RAND', 'RANDOM', 'CBRT', 'FACTORIAL', 'GCD', 'LCM'
        }

        self.string_functions = {
            'CONCAT', 'CONCAT_WS', 'SUBSTRING', 'SUBSTR', 'LEFT', 'RIGHT', 'MID',
            'LENGTH', 'CHAR_LENGTH', 'LEN', 'UPPER', 'LOWER', 'UCASE', 'LCASE',
            'TRIM', 'LTRIM', 'RTRIM', 'BTRIM', 'REPLACE', 'TRANSLATE', 'STUFF',
            'POSITION', 'LOCATE', 'INSTR', 'CHARINDEX', 'REPEAT', 'SPACE', 'REPLICATE',
            'REVERSE', 'INITCAP', 'PROPER', 'SOUNDEX', 'DIFFERENCE', 'ASCII', 'CHAR',
            'UNICODE', 'NCHAR', 'STR', 'FORMAT', 'QUOTENAME', 'PARSENAME'
        }

        self.datetime_functions = {
            'NOW', 'CURRENT_TIMESTAMP', 'CURRENT_DATE', 'CURRENT_TIME',
            'DATE', 'TIME', 'YEAR', 'MONTH', 'DAY', 'HOUR', 'MINUTE', 'SECOND',
            'DATE_ADD', 'DATE_SUB', 'DATEDIFF', 'DATE_FORMAT', 'STR_TO_DATE',
            'DAYOFWEEK', 'DAYOFMONTH', 'DAYOFYEAR', 'WEEK', 'QUARTER'
        }

        self.aggregate_functions = {
            'COUNT', 'SUM', 'AVG', 'MIN', 'MAX', 'STDDEV', 'VARIANCE', 'STDDEV_POP', 'STDDEV_SAMP',
            'VAR_POP', 'VAR_SAMP', 'GROUP_CONCAT', 'STRING_AGG', 'LISTAGG', 'ARRAY_AGG',
            'BOOL_AND', 'BOOL_OR', 'BIT_AND', 'BIT_OR', 'BIT_XOR', 'JSON_ARRAYAGG', 'JSON_OBJECTAGG'
        }

        self.window_functions = {
            'ROW_NUMBER', 'RANK', 'DENSE_RANK', 'PERCENT_RANK', 'CUME_DIST', 'NTILE',
            'LAG', 'LEAD', 'FIRST_VALUE', 'LAST_VALUE', 'NTH_VALUE',
            'SUM', 'AVG', 'MIN', 'MAX', 'COUNT', 'STDDEV', 'VARIANCE'  # These can be used as window functions too
        }

        self.conditional_functions = {
            'CASE', 'COALESCE', 'NULLIF', 'IFNULL', 'NVL', 'ISNULL'
        }

    def set_database_type(self, db_url: str):
        """Set the database type"""
        adapter = create_database_adapter(db_url)
        self.database_type = adapter.db_type
        logger.info(f"SQL Translator configured for database type: {self.database_type}")

    def register_table_mapping(self, table_name: str, mapping: TableMapping):
        """Register table mapping for translation"""
        self.table_mappings[table_name] = mapping
        logger.info(f"Registered table mapping for: {table_name}")

    def _translate_union_query(self, query: str) -> Tuple[str, Dict[str, Any]]:
        """Translate UNION queries"""
        union_parts = self.patterns['union_split'].split(query)

        translated_parts = []
        union_keywords = []

        i = 0
        while i < len(union_parts):
            if re.match(r'UNION', union_parts[i], re.IGNORECASE):
                translated_parts.append(union_parts[i])
                union_keywords.append(union_parts[i].strip())
                i += 1
            else:
                select_query = union_parts[i]
                try:
                    table_mapping = self._extract_table_mapping(select_query)

                    if table_mapping:
                        translated_select, _ = self._translate_select(select_query, table_mapping)
                        translated_parts.append(translated_select)
                    else:
                        translated_parts.append(select_query)
                except Exception as e:
                    logger.warning(f"Failed to translate UNION part: {e}")
                    translated_parts.append(select_query)
                i += 1

        translated_query = ' '.join(translated_parts)
        metadata = {
            "union_operations": union_keywords,
            "query_type": "UNION"
        }
        return translated_query, metadata

    def _translate_cte_query(self, query: str) -> Tuple[str, Dict[str, Any]]:
        """Translate Common Table Expression (CTE) queries"""
        select_start = re.search(r'\bSELECT\b', query[query.upper().find('WITH'):], re.IGNORECASE)
        if select_start:
            with_part = query[:query.upper().find('WITH') + select_start.start()]
            select_part = query[query.upper().find('WITH') + select_start.start():]

            translated_select, metadata = self.translate_query(select_part)

            translated_query = f"{with_part}{translated_select}"
            metadata.update({"has_cte": True, "cte_definition": with_part.strip()})

            return translated_query, metadata
        else:
            return self.translate_query(query)

    def _get_cache_key(self, query: str, table_name: str = None) -> str:
        """Generate cache key for query translation"""
        table_part = f":{table_name}" if table_name else ""
        return f"{query.strip().upper()}{table_part}"

    def _get_cached_translation(self, cache_key: str) -> Optional[Tuple[str, Dict[str, Any]]]:
        """Get cached translation if available"""
        return self.translation_cache.get(cache_key)

    def _cache_translation(self, cache_key: str, translated_query: str, metadata: Dict[str, Any]):
        """Cache translation result"""
        if len(self.translation_cache) >= self.cache_max_size:
            oldest_key = next(iter(self.translation_cache))
            del self.translation_cache[oldest_key]

        self.translation_cache[cache_key] = (translated_query, metadata)

    def clear_cache(self):
        """Clear translation cache"""
        self.translation_cache.clear()

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return {
            "cache_size": len(self.translation_cache),
            "max_cache_size": self.cache_max_size,
            "cache_hit_ratio": 0.0  # Would need hit/miss counters for this
        }

    def translate_query(self, query: str, table_name: str = None) -> Tuple[Union[str, Dict[str, Any]], Dict[str, Any]]:
        """
        Translate SQL query to work with encrypted schema

        Args:
            query: Original SQL query
            table_name: Target table name (optional)

        Returns:
            Tuple of (translated_query, metadata)
        """
        try:
            cache_key = self._get_cache_key(query, table_name)
            cached_result = self._get_cached_translation(cache_key)
            if cached_result:
                translated_query, metadata = cached_result
                metadata = metadata.copy()  # Don't modify cached metadata
                metadata["cached"] = True
                return translated_query, metadata
            query_upper = query.strip().upper()

            if 'UNION' in query_upper:
                return self._translate_union_query(query)
            elif 'INTERSECT' in query_upper:
                return self._translate_intersect_query(query)
            elif 'EXCEPT' in query_upper or 'MINUS' in query_upper:
                return self._translate_except_query(query)
            elif query_upper.startswith('WITH'):
                return self._translate_cte_query(query)
            elif 'PIVOT' in query_upper or 'UNPIVOT' in query_upper:
                return self._translate_pivot_query(query)

            query_type = self._determine_query_type(query)

            if table_name and table_name in self.table_mappings:
                table_mapping = self.table_mappings[table_name]
            else:
                table_mapping = self._extract_table_mapping(query)

            if query_type == QueryType.SELECT:
                translated_query, metadata = self._translate_select(query, table_mapping)
            elif query_type == QueryType.INSERT:
                translated_query, metadata = self._translate_insert(query, table_mapping)
            elif query_type == QueryType.UPDATE:
                translated_query, metadata = self._translate_update(query, table_mapping)
            elif query_type == QueryType.DELETE:
                translated_query, metadata = self._translate_delete(query, table_mapping)
            elif query_type in [QueryType.CREATE, QueryType.ALTER, QueryType.DROP, QueryType.TRUNCATE, QueryType.MERGE, QueryType.REPLACE]:
                translated_query, metadata = self._translate_ddl(query, query_type)
            elif query_type in [QueryType.SHOW, QueryType.DESCRIBE, QueryType.EXPLAIN]:
                translated_query, metadata = self._translate_utility(query, query_type)
            elif query_type in [QueryType.TRANSACTION, QueryType.DCL, QueryType.CALL, QueryType.USE]:
                translated_query = query
                metadata = {"query_type": query_type.value, "passthrough": True}
            else:
                raise SQLTranslationError(f"Unsupported query type: {query_type}")

            metadata.update({
                "original_query": query,
                "query_type": query_type.value,
                "table_name": table_name,
                "database_type": self.database_type.value if self.database_type else None,
                "translation_success": True,
                "cached": False
            })

            self._cache_translation(cache_key, translated_query, metadata)

            logger.info(f"✅ Query translated: {query_type.value} on {table_name}")
            return translated_query, metadata

        except Exception as e:
            logger.error(f"❌ Query translation failed: {e}")
            raise SQLTranslationError(f"Translation failed: {str(e)}")

    def _determine_query_type(self, query: str) -> QueryType:
        """Determine the type of SQL query"""
        query_upper = query.strip().upper()

        if query_upper.startswith("SELECT"):
            return QueryType.SELECT
        elif query_upper.startswith("INSERT"):
            return QueryType.INSERT
        elif query_upper.startswith("UPDATE"):
            return QueryType.UPDATE
        elif query_upper.startswith("DELETE"):
            return QueryType.DELETE
        elif query_upper.startswith("CREATE"):
            return QueryType.CREATE
        elif query_upper.startswith("ALTER"):
            return QueryType.ALTER
        elif query_upper.startswith("DROP"):
            return QueryType.DROP
        elif query_upper.startswith("TRUNCATE"):
            return QueryType.TRUNCATE
        elif query_upper.startswith("MERGE"):
            return QueryType.MERGE
        elif query_upper.startswith("REPLACE"):
            return QueryType.REPLACE
        elif query_upper.startswith("SHOW"):
            return QueryType.SHOW
        elif query_upper.startswith("DESCRIBE"):
            return QueryType.DESCRIBE
        elif query_upper.startswith("EXPLAIN"):
            return QueryType.EXPLAIN
        elif query_upper.startswith(("START", "COMMIT", "ROLLBACK", "SAVEPOINT")):
            return QueryType.TRANSACTION
        elif query_upper.startswith(("GRANT", "REVOKE")):
            return QueryType.DCL
        elif query_upper.startswith("CALL"):
            return QueryType.CALL
        elif query_upper.startswith("USE"):
            return QueryType.USE
        else:
            raise SQLTranslationError(f"Unable to determine query type for: {query[:50]}...")

    def _extract_table_mapping(self, query: str) -> Optional[TableMapping]:
        """Extract table name from query and get mapping"""
        query_upper = query.upper()
        logger.debug(f"Extracting table name from query: {query}")

        if query_upper.startswith('SELECT'):
            from_match = self.patterns['select_from'].search(query)
            if from_match:
                table_name = from_match.group(1).strip('`')
                logger.debug(f"Extracted table name: {table_name}")
                mapping = self.table_mappings.get(table_name)
                logger.debug(f"Found table mapping: {mapping is not None}")
                return mapping
            else:
                logger.debug("No FROM clause found in SELECT query")
        elif query_upper.startswith(('INSERT', 'UPDATE', 'DELETE')):
            if 'INSERT' in query_upper:
                match = self.patterns['insert_into'].search(query)
            elif 'UPDATE' in query_upper:
                match = self.patterns['update_table'].search(query)
            elif 'DELETE' in query_upper:
                match = self.patterns['delete_from'].search(query)

            if match:
                table_name = match.group(1).strip('`')
                logger.debug(f"Extracted table name: {table_name}")
                mapping = self.table_mappings.get(table_name)
                logger.debug(f"Found table mapping: {mapping is not None}")
                return mapping
            else:
                logger.debug("No table name found in INSERT/UPDATE/DELETE query")

        return None

    def _translate_select(self, query: str, table_mapping: TableMapping) -> Tuple[str, Dict[str, Any]]:
        """Translate SELECT query with intelligent encrypted data handling"""
        translated_query = query

        if table_mapping:
            context = self._analyze_query_context(query, table_mapping)

            self.translation_strategies[query] = context

            translated_query = self._translate_select_columns_intelligent(translated_query, table_mapping, context)

            translated_query = self._translate_subqueries_in_query(translated_query, table_mapping)

            if any(join_type in query.upper() for join_type in ['JOIN', 'INNER JOIN', 'LEFT JOIN', 'RIGHT JOIN', 'FULL OUTER JOIN', 'CROSS JOIN']):
                translated_query = self._translate_join_clauses(translated_query, table_mapping)

            if 'WHERE' in query.upper():
                translated_query = self._translate_where_clause_intelligent(translated_query, table_mapping, context)

            if 'GROUP BY' in query.upper():
                translated_query = self._translate_group_by_clause_intelligent(translated_query, table_mapping, context)

            if 'HAVING' in query.upper():
                translated_query = self._translate_having_clause_intelligent(translated_query, table_mapping, context)

            if 'ORDER BY' in query.upper():
                translated_query = self._translate_order_by_clause_intelligent(translated_query, table_mapping, context)

        metadata = {
            "columns_selected": self._extract_columns_from_select(query),
            "has_where_clause": 'WHERE' in query.upper(),
            "has_group_by": 'GROUP BY' in query.upper(),
            "has_having": 'HAVING' in query.upper(),
            "has_order_by": 'ORDER BY' in query.upper(),
            "has_join": any(join_type in query.upper() for join_type in ['JOIN', 'INNER JOIN', 'LEFT JOIN', 'RIGHT JOIN', 'FULL OUTER JOIN', 'CROSS JOIN']),
            "translation_strategy": self.translation_strategies.get(query, {}),
            "needs_decryption": self.translation_strategies.get(query, {}).get('needs_decryption', False),
            "uses_tags": self.translation_strategies.get(query, {}).get('needs_tags', False)
        }

        return translated_query, metadata

    def _parse_values_clause(self, values_part: str) -> List[List[str]]:
        """
        Parse VALUES clause to extract individual rows and values
        
        Args:
            values_part: The VALUES clause content (e.g., "(val1, val2), (val3, val4)")
            
        Returns:
            List of rows, where each row is a list of values
        """
        try:
            values_part = values_part.strip()
            
            if values_part.endswith(';'):
                values_part = values_part[:-1].strip()
            
            rows = []
            current_pos = 0
            
            while current_pos < len(values_part):
                start_paren = values_part.find('(', current_pos)
                if start_paren == -1:
                    break
                
                paren_count = 1
                pos = start_paren + 1
                while pos < len(values_part) and paren_count > 0:
                    if values_part[pos] == '(':
                        paren_count += 1
                    elif values_part[pos] == ')':
                        paren_count -= 1
                    pos += 1
                
                if paren_count == 0:
                    row_content = values_part[start_paren + 1:pos - 1]
                    
                    row_values = self._parse_row_values(row_content)
                    rows.append(row_values)
                    
                    current_pos = pos
                else:
                    logger.warning(f"Unmatched parentheses in VALUES clause: {values_part}")
                    break
            
            return rows
            
        except Exception as e:
            logger.error(f"Failed to parse VALUES clause: {e}")
            return []
    
    def _parse_row_values(self, row_content: str) -> List[str]:
        """
        Parse individual values from a row
        
        Args:
            row_content: Content of a single row (e.g., "val1, val2, val3")
            
        Returns:
            List of individual values
        """
        values = []
        current_value = ""
        in_quotes = False
        quote_char = None
        paren_depth = 0
        
        for i, char in enumerate(row_content):
            if char in ("'", '"') and (i == 0 or row_content[i-1] != '\\'):
                if not in_quotes:
                    in_quotes = True
                    quote_char = char
                elif char == quote_char:
                    in_quotes = False
                    quote_char = None
                current_value += char
            elif char == '(' and not in_quotes:
                paren_depth += 1
                current_value += char
            elif char == ')' and not in_quotes:
                paren_depth -= 1
                current_value += char
            elif char == ',' and not in_quotes and paren_depth == 0:
                values.append(current_value.strip().strip("'\""))
                current_value = ""
            else:
                current_value += char
        
        if current_value.strip():
            values.append(current_value.strip().strip("'\""))
        
        return values

    def _translate_insert(self, query: str, table_mapping: TableMapping) -> Tuple[str, Dict[str, Any]]:
        """Translate INSERT query with encryption for encrypted columns"""
        self.clear_cache()

        translated_query = query
        metadata = {}

        if table_mapping:
            insert_match = re.search(r'INSERT\s+INTO\s+(\w+)\s*\(([^)]+)\)\s*VALUES\s*(.+)', query, re.IGNORECASE | re.DOTALL)
            if insert_match:
                table_name = insert_match.group(1).strip()
                columns_str = insert_match.group(2).strip()
                values_part = insert_match.group(3).strip()

                original_columns = [col.strip() for col in columns_str.split(',')]

                values_rows = self._parse_values_clause(values_part)

                if not values_rows:
                    logger.warning("Could not parse VALUES clause in INSERT")
                    return query, metadata

                if len(original_columns) != len(values_rows[0]):
                    logger.warning(f"Column count ({len(original_columns)}) doesn't match value count ({len(values_rows[0])}) in first VALUES row")
                    return query, metadata

                final_columns = original_columns.copy()
                encrypted_columns_map = {}

                for col in original_columns:
                    if col in table_mapping.encrypted_columns:
                        col_mapping = table_mapping.encrypted_columns[col]
                        if col_mapping.is_encrypted and col_mapping.tag_name:
                            final_columns.append(col_mapping.tag_name)
                            encrypted_columns_map[col] = col_mapping

                translated_rows = []
                encryption_metadata = {}

                for row_values in values_rows:
                    main_values = []
                    tag_values = []

                    for i, val in enumerate(row_values):
                        col = original_columns[i]

                        if col in encrypted_columns_map:
                            col_mapping = encrypted_columns_map[col]

                            encrypted_blob = clwe_encryptor.encrypt_value(val, settings.CRYPTOPIX_DEFAULT_PASSWORD)
                            encrypted_hex = encrypted_blob.hex()

                            if self.database_type and self.database_type.value == 'postgresql':
                                main_values.append(f"decode('{encrypted_hex}', 'hex')")
                            else:
                                main_values.append(f"X'{encrypted_hex}'")

                            try:
                                tag_value = clwe_encryptor.generate_unified_tag(val, "text")
                                tag_values.append(f"'{tag_value}'")
                                logger.info(f"Added tag for INSERT column '{col}': {tag_value}")
                            except Exception as e:
                                logger.error(f"Failed to generate tag for INSERT on column '{col}': {e}")
                                fallback_tag = "0" * 20
                                tag_values.append(f"'{fallback_tag}'")
                                logger.warning(f"Using fallback tag for INSERT on column '{col}': {fallback_tag}")

                            logger.info(f"Encrypted INSERT column '{col}' value '{val[:20]}...' -> {len(encrypted_hex)} bytes")

                            if col not in encryption_metadata:
                                encryption_metadata[col] = {
                                    "type": "encrypted",
                                    "original_value": val,
                                    "encrypted_value": encrypted_hex,
                                    "tag_value": tag_value if 'tag_value' in locals() else fallback_tag
                                }
                        else:
                            if val.replace('.', '').replace('-', '').isdigit():
                                main_values.append(val)  # Numeric value
                            else:
                                main_values.append(f"'{val}'")  # String value

                    translated_values = main_values + tag_values

                    translated_rows.append(f"({', '.join(translated_values)})")

                columns_str = ', '.join(final_columns)
                values_str = ', '.join(translated_rows)
                translated_query = f"INSERT INTO {table_name} ({columns_str}) VALUES {values_str}"

                metadata["encryption_metadata"] = encryption_metadata if encryption_metadata else {}

        return translated_query, metadata

    def _translate_update(self, query: str, table_mapping: TableMapping) -> Tuple[str, Dict[str, Any]]:
        """Translate UPDATE query"""
        translated_query = query

        if table_mapping:
            translated_query = self._translate_subqueries_in_query(translated_query, table_mapping)

            set_match = re.search(r'SET\s+(.+?)(?:\s+WHERE|$)', query, re.IGNORECASE | re.DOTALL)
            if set_match:
                set_clause = set_match.group(1)
                assignments = [a.strip() for a in set_clause.split(',')]

                translated_assignments = []
                encryption_metadata = {}

                for assignment in assignments:
                    if '=' in assignment:
                        parts = assignment.split('=', 1)
                        col = parts[0].strip()
                        val_expr = parts[1].strip()

                        val_expr = self._translate_function_calls(val_expr, table_mapping)

                        val = val_expr.strip("'\"")

                        if col in table_mapping.encrypted_columns:
                            col_mapping = table_mapping.encrypted_columns[col]
                            if col_mapping.is_encrypted:
                                encrypted_blob = clwe_encryptor.encrypt_value(val, settings.CRYPTOPIX_DEFAULT_PASSWORD)
                                encrypted_hex = encrypted_blob.hex()

                                if self.database_type and self.database_type.value == 'postgresql':
                                    translated_assignments.append(f"{col_mapping.encrypted_name} = decode('{encrypted_hex}', 'hex')")
                                else:
                                    translated_assignments.append(f"{col_mapping.encrypted_name} = X'{encrypted_hex}'")

                                try:
                                    tag_value = clwe_encryptor.generate_unified_tag(val, "text")
                                    translated_assignments.append(f"{col_mapping.tag_name} = '{tag_value}'")
                                    logger.info(f"Updated tag for column '{col}': {tag_value}")
                                except Exception as e:
                                    logger.error(f"Failed to generate tag for UPDATE on column '{col}': {e}")
                                    fallback_tag = "0" * 20
                                    translated_assignments.append(f"{col_mapping.tag_name} = '{fallback_tag}'")
                                    logger.warning(f"Using fallback tag for UPDATE on column '{col}': {fallback_tag}")

                                logger.info(f"Encrypted column '{col}' value '{val[:20]}...' -> {len(encrypted_hex)} bytes, tag: {tag_value}")

                                encryption_metadata[col] = {
                                    "type": "encrypted",
                                    "original_value": val,
                                    "encrypted_value": encrypted_hex,
                                    "tag_value": tag_value
                                }
                            else:
                                translated_assignments.append(f"{col} = {val_expr}")
                        else:
                            translated_assignments.append(f"{col} = {val_expr}")

                new_set_clause = ', '.join(translated_assignments)
                translated_query = re.sub(r'SET\s+.+?(?=\s+WHERE|$)', f'SET {new_set_clause}', translated_query, flags=re.IGNORECASE | re.DOTALL)

            if 'WHERE' in query.upper():
                translated_query = self._translate_where_clause_intelligent(translated_query, table_mapping, {})

        context = self._analyze_query_context(query, table_mapping)
        uses_tags = context.get('needs_tags', False)

        metadata = {
            "encryption_metadata": encryption_metadata if 'encryption_metadata' in locals() else {},
            "has_where_clause": 'WHERE' in query.upper(),
            "uses_tags": uses_tags
        }

        return translated_query, metadata

    def _translate_delete(self, query: str, table_mapping: TableMapping) -> Tuple[str, Dict[str, Any]]:
        """Translate DELETE query"""
        translated_query = query

        if table_mapping:
            translated_query = self._translate_subqueries_in_query(translated_query, table_mapping)

            if 'WHERE' in query.upper():
                translated_query = self._translate_where_clause_intelligent(translated_query, table_mapping, {})

        context = self._analyze_query_context(query, table_mapping)
        uses_tags = context.get('needs_tags', False)

        metadata = {
            "has_where_clause": 'WHERE' in query.upper(),
            "uses_tags": uses_tags
        }

        return translated_query, metadata

    def _translate_ddl(self, query: str, query_type: QueryType) -> Tuple[str, Dict[str, Any]]:
        """Translate DDL queries (CREATE, ALTER, DROP, TRUNCATE, MERGE, REPLACE)"""
        translated_query = query

        if query_type == QueryType.TRUNCATE:
            truncate_match = re.search(r'TRUNCATE\s+TABLE\s+(\w+)', query, re.IGNORECASE)
            if truncate_match:
                table_name = truncate_match.group(1)
                translated_query = f"DELETE FROM {table_name}"
                query_type = QueryType.DELETE  # Change type to DELETE for proper handling

        metadata = {
            "ddl_operation": query_type.value,
            "note": "DDL operations may require schema synchronization"
        }

        return translated_query, metadata

    def _translate_utility(self, query: str, query_type: QueryType) -> Tuple[str, Dict[str, Any]]:
        """Translate utility queries (SHOW, DESCRIBE, EXPLAIN)"""
        translated_query = query

        metadata = {
            "utility_operation": query_type.value,
            "note": "Utility operations provide database information"
        }

        return translated_query, metadata

    def _translate_function_calls(self, expression: str, table_mapping: TableMapping) -> str:
        """Translate function calls in expressions (SELECT, WHERE, etc.)"""
        if not table_mapping:
            return expression

        for func in self.math_functions:
            pattern = rf'\b{func}\s*\('
            expression = re.sub(pattern, f'{func}(', expression, flags=re.IGNORECASE)

        for func in self.string_functions:
            pattern = rf'\b{func}\s*\('
            expression = re.sub(pattern, f'{func}(', expression, flags=re.IGNORECASE)

        for func in self.datetime_functions:
            pattern = rf'\b{func}\s*\('
            expression = re.sub(pattern, f'{func}(', expression, flags=re.IGNORECASE)

        for func in self.aggregate_functions:
            pattern = rf'\b{func}\s*\('
            expression = re.sub(pattern, f'{func}(', expression, flags=re.IGNORECASE)

        for func in self.conditional_functions:
            pattern = rf'\b{func}\s*\('
            expression = re.sub(pattern, f'{func}(', expression, flags=re.IGNORECASE)

        for func in self.window_functions:
            pattern = rf'\b{func}\s*\('
            expression = re.sub(pattern, f'{func}(', expression, flags=re.IGNORECASE)

        expression = self._translate_column_references(expression, table_mapping)

        return expression

    def _translate_column_references(self, expression: str, table_mapping: TableMapping) -> str:
        """Translate column references in expressions"""
        if not table_mapping:
            return expression

        for col_name, col_mapping in table_mapping.encrypted_columns.items():
            if col_mapping.is_encrypted:
                pattern = rf'\b{re.escape(col_name)}\b'
                expression = re.sub(pattern, col_mapping.encrypted_name, expression)

        return expression

    def _translate_select_columns_intelligent(self, query: str, table_mapping: TableMapping, context: Dict[str, Any]) -> str:
        """Translate column names in SELECT clause with intelligent encrypted data handling"""
        if not table_mapping:
            return query

        select_start = re.search(r'\bSELECT\s+', query, re.IGNORECASE)
        if not select_start:
            return query

        pos = select_start.end()
        paren_depth = 0
        from_pos = -1

        while pos < len(query):
            char = query[pos]
            if char == '(':
                paren_depth += 1
            elif char == ')':
                paren_depth -= 1
            elif paren_depth == 0 and query[pos:pos+4].upper() == 'FROM':
                from_pos = pos
                break
            pos += 1

        if from_pos == -1:
            return query

        select_clause = query[select_start.end():from_pos].strip()

        if select_clause.upper() == '*':
            all_columns = []
            for col_name, col_mapping in table_mapping.encrypted_columns.items():
                if col_mapping.is_encrypted:
                    if context.get('needs_decryption', False):
                        all_columns.append(col_mapping.encrypted_name)
                    else:
                        all_columns.append(col_mapping.encrypted_name)
                else:
                    all_columns.append(col_name)
            all_columns.extend(table_mapping.non_encrypted_columns)

            new_select_clause = ', '.join(all_columns)
        else:
            columns = self._split_select_columns(select_clause)

            translated_columns = []
            for col in columns:
                col = col.strip()
                if not col:
                    continue

                if re.search(r'\w+\s*\(', col):
                    translated_col = self._translate_function_calls(col, table_mapping)
                    translated_columns.append(translated_col)
                else:
                    translated_col = self._translate_column_references_intelligent(col, table_mapping, context, use_select_strategies=True)
                    translated_columns.append(translated_col)

            new_select_clause = ', '.join(translated_columns)

        old_select = query[select_start.start():from_pos]
        new_select = f"SELECT {new_select_clause} "
        query = query.replace(old_select, new_select, 1)

        return query

    def _translate_column_references_intelligent(self, expression: str, table_mapping: TableMapping, context: Dict[str, Any], use_select_strategies: bool = False) -> str:
        """Translate column references with intelligent encrypted data handling"""
        if not table_mapping:
            return expression

        strategies = context.get('select_strategies' if use_select_strategies else 'filter_strategies', {})

        for col_name, col_mapping in table_mapping.encrypted_columns.items():
            if col_mapping.is_encrypted:
                pattern = rf'\b{re.escape(col_name)}\b'

                strategy = strategies.get(col_name, 'use_encrypted_data')

                if strategy == 'use_tags' and col_mapping.tag_name:
                    expression = re.sub(pattern, col_mapping.tag_name, expression)
                    logger.debug(f"Using tags for column {col_name} -> {col_mapping.tag_name}")
                elif strategy == 'decrypt':
                    expression = re.sub(pattern, col_mapping.encrypted_name, expression)
                    logger.debug(f"Will decrypt column {col_name} -> {col_mapping.encrypted_name} (encrypted_name: {col_mapping.encrypted_name})")
                else:
                    expression = re.sub(pattern, col_mapping.encrypted_name, expression)
                    logger.debug(f"Using encrypted data directly for column {col_name} -> {col_mapping.encrypted_name}")

        return expression

    def _translate_subqueries(self, clause: str, table_mapping: TableMapping) -> str:
        """Recursively translate subqueries within a clause"""
        if not table_mapping:
            return clause

        subquery_pattern = r'\(\s*SELECT\s+.*?\s+FROM\s+.*?\)'

        def replace_subquery(match):
            subquery = match.group(0)
            logger.debug(f"Processing subquery: {subquery}")

            inner_subquery = subquery.strip('()')

            try:
                from_match = re.search(r'\bFROM\s+([^\s,()]+)', inner_subquery, re.IGNORECASE)
                if from_match:
                    subquery_table = from_match.group(1).strip('`')
                    logger.debug(f"Subquery table: {subquery_table}")

                    if subquery_table in self.table_mappings:
                        subquery_mapping = self.table_mappings[subquery_table]
                        translated_inner = self._translate_select_query(inner_subquery, subquery_mapping)
                        return f"({translated_inner})"
                    else:
                        logger.debug(f"No table mapping found for subquery table: {subquery_table}")
                        return subquery
                else:
                    logger.debug(f"Could not extract table name from subquery: {inner_subquery}")
                    return subquery
            except Exception as e:
                logger.warning(f"Failed to translate subquery {subquery}: {e}")
                return subquery

        translated_clause = re.sub(subquery_pattern, replace_subquery, clause, flags=re.IGNORECASE | re.DOTALL)

        return translated_clause

    def _translate_subqueries_in_query(self, query: str, table_mapping: TableMapping) -> str:
        """Translate subqueries throughout the entire query"""
        if not table_mapping:
            return query

        return self._translate_subqueries(query, table_mapping)

    def _translate_select_query(self, query: str, table_mapping: TableMapping) -> str:
        """Translate a SELECT subquery"""
        translated_query = query

        if table_mapping:
            translated_query = self._translate_subqueries_in_query(translated_query, table_mapping)

            if 'WHERE' in query.upper():
                translated_query = self._translate_where_clause_in_subquery(translated_query, table_mapping)

        return translated_query

    def _translate_where_clause_in_subquery(self, query: str, table_mapping: TableMapping) -> str:
        """Translate WHERE clause within a subquery"""
        if not table_mapping:
            return query

        where_match = re.search(r'WHERE\s+(.+?)(?:\s+(?:ORDER|GROUP|HAVING|LIMIT|$))', query, re.IGNORECASE | re.DOTALL)
        if not where_match:
            where_match = re.search(r'WHERE\s+(.+?)$', query, re.IGNORECASE | re.DOTALL)

        if where_match:
            where_clause = where_match.group(1)

            where_clause = self._translate_subqueries(where_clause, table_mapping)

            original_where = where_clause

            for col_name, col_mapping in table_mapping.encrypted_columns.items():
                if col_mapping.is_encrypted and col_mapping.tag_name:
                    pattern = rf'\b{col_name}\s*=\s*(?:([\'"]([^\'"]+)[\'"])|\b([^\'"\s]+)\b)'

                    def replace_func(match):
                        if match.group(2):  # Quoted value
                            value = match.group(2)
                        else:  # Unquoted value
                            value = match.group(3)
                        tag_value = clwe_encryptor.generate_unified_tag(str(value), "text")
                        return f"{col_mapping.tag_name} = '{tag_value}'"

                    where_clause = re.sub(pattern, replace_func, where_clause)

            if where_clause != original_where:
                query = query.replace(f"WHERE {original_where}", f"WHERE {where_clause}")

        return query

    def _translate_where_clause_intelligent(self, query: str, table_mapping: TableMapping, context: Dict[str, Any]) -> str:
        """Translate WHERE clause with intelligent tag usage for encrypted columns"""
        if not table_mapping:
            return query

        logger.debug(f"Translating WHERE clause for table with encrypted columns: {list(table_mapping.encrypted_columns.keys())}")

        where_match = self.patterns['where_clause'].search(query)
        if not where_match:
            where_match = re.search(r'WHERE\s+(.+?)$', query, re.IGNORECASE | re.DOTALL)

        if where_match:
            where_clause = where_match.group(1)
            logger.debug(f"Found WHERE clause: '{where_clause}'")

            original_where = where_clause

            where_clause = self._translate_function_calls(where_clause, table_mapping)

            for col_name, col_mapping in table_mapping.encrypted_columns.items():
                if col_mapping.is_encrypted and col_mapping.tag_name:
                    strategy = context.get('column_strategies', {}).get(col_name, 'use_tags')

                    if strategy == 'use_tags':
                        logger.debug(f"Using tags for WHERE filtering on column {col_name}")

                        eq_pattern = rf'\b{col_name}\s*=\s*(?:([\'"]([^\'"]+)[\'"])|\b([^\'"\s]+)\b)'

                        def replace_eq_func(match):
                            if match.group(2):  # Quoted value
                                value = match.group(2)
                            else:  # Unquoted value
                                value = match.group(3)
                            tag_value = clwe_encryptor.generate_unified_tag(str(value), "text")
                            return f"{col_mapping.tag_name} = '{tag_value}'"

                        where_clause = re.sub(eq_pattern, replace_eq_func, where_clause)

                        like_pattern = rf'\b{col_name}\s+LIKE\s+([\'"]([^\'"]*)[\'"])'

                        def replace_like_func(match):
                            pattern = match.group(2)
                            if '%' not in pattern and '_' not in pattern:
                                tag_value = clwe_encryptor.generate_unified_tag(pattern, "text")
                                return f"{col_mapping.tag_name} = '{tag_value}'"
                            else:
                                logger.warning(f"LIKE with wildcards on encrypted column {col_name} - using direct comparison (less secure)")
                                return f"{col_mapping.encrypted_name} LIKE {match.group(1)}"

                        where_clause = re.sub(like_pattern, replace_like_func, where_clause, flags=re.IGNORECASE)

                        in_pattern = rf'\b{col_name}\s+IN\s*\(\s*([^)]+)\s*\)'

                        def replace_in_func(match):
                            values_str = match.group(1)
                            values = []
                            for val in values_str.split(','):
                                val = val.strip().strip("'\"")
                                if val:
                                    tag_value = clwe_encryptor.generate_unified_tag(val, "text")
                                    values.append(f"'{tag_value}'")

                            if values:
                                return f"{col_mapping.tag_name} IN ({', '.join(values)})"
                            return match.group(0)

                        where_clause = re.sub(in_pattern, replace_in_func, where_clause, flags=re.IGNORECASE)

                        between_pattern = rf'\b{col_name}\s+BETWEEN\s+(.+?)\s+AND\s+(.+?)(?:\s|$)'

                        def replace_between_func(match):
                            val1 = match.group(1).strip().strip("'\"")
                            val2 = match.group(2).strip().strip("'\"")
                            tag1 = clwe_encryptor.generate_unified_tag(val1, "text")
                            tag2 = clwe_encryptor.generate_unified_tag(val2, "text")
                            return f"{col_mapping.tag_name} BETWEEN '{tag1}' AND '{tag2}'"

                        where_clause = re.sub(between_pattern, replace_between_func, where_clause, flags=re.IGNORECASE)

                        for op in ['>', '<', '>=', '<=', '!=', '<>']:
                            range_pattern = rf'\b{col_name}\s*{re.escape(op)}\s*(?:([\'"]([^\'"]+)[\'"])|\b([^\'"\s]+)\b)'

                            def replace_range_func(match, operator=op):
                                if match.group(2):  # Quoted value
                                    value = match.group(2)
                                else:  # Unquoted value
                                    value = match.group(3)
                                tag_value = clwe_encryptor.generate_unified_tag(str(value), "text")
                                return f"{col_mapping.tag_name} {operator} '{tag_value}'"

                            where_clause = re.sub(range_pattern, replace_range_func, where_clause)

                        null_pattern = rf'\b{col_name}\s+IS\s+(NOT\s+)?NULL'

                        def replace_null_func(match):
                            not_null = match.group(1)
                            if not_null:
                                return f"{col_mapping.encrypted_name} IS NOT NULL"
                            else:
                                return f"{col_mapping.encrypted_name} IS NULL"

                        where_clause = re.sub(null_pattern, replace_null_func, where_clause, flags=re.IGNORECASE)
                    else:
                        logger.debug(f"Not using tags for WHERE on column {col_name}, strategy: {strategy}")

            where_clause = self._translate_subqueries(where_clause, table_mapping)

            if where_clause != original_where:
                query = query.replace(f"WHERE {original_where}", f"WHERE {where_clause}")
        else:
            logger.debug(f"No WHERE clause match found in query: {query}")

        return query

    def _translate_group_by_clause_intelligent(self, query: str, table_mapping: TableMapping, context: Dict[str, Any]) -> str:
        """Translate GROUP BY clause with intelligent encrypted column handling"""
        if not table_mapping:
            return query

        group_match = re.search(r'GROUP BY\s+(.+?)(?:\s+(?:HAVING|ORDER|LIMIT|$))', query, re.IGNORECASE | re.DOTALL)
        if group_match:
            group_clause = group_match.group(1)

            group_clause = self._translate_column_references_intelligent(group_clause, table_mapping, context, use_select_strategies=False)

            query = re.sub(r'GROUP BY\s+.+?(?=\s+(?:HAVING|ORDER|LIMIT|$))', f'GROUP BY {group_clause}', query, flags=re.IGNORECASE | re.DOTALL)

        return query

    def _translate_having_clause_intelligent(self, query: str, table_mapping: TableMapping, context: Dict[str, Any]) -> str:
        """Translate HAVING clause with intelligent encrypted column handling"""
        if not table_mapping:
            return query

        having_match = re.search(r'HAVING\s+(.+?)(?:\s+(?:ORDER|LIMIT|$))', query, re.IGNORECASE | re.DOTALL)
        if having_match:
            having_clause = having_match.group(1)

            having_clause = self._translate_function_calls(having_clause, table_mapping)

            for col_name, col_mapping in table_mapping.encrypted_columns.items():
                if col_mapping.is_encrypted and col_mapping.tag_name:
                    filter_strategy = context.get('filter_strategies', {}).get(col_name, 'use_tags')

                    if filter_strategy == 'use_tags':
                        eq_pattern = rf'\b{col_name}\s*=\s*(?:([\'"]([^\'"]+)[\'"])|\b([^\'"\s]+)\b)'

                        def replace_eq_func(match):
                            if match.group(2):  # Quoted value
                                value = match.group(2)
                            else:  # Unquoted value
                                value = match.group(3)
                            tag_value = clwe_encryptor.generate_unified_tag(str(value), "text")
                            return f"{col_mapping.tag_name} = '{tag_value}'"

                        having_clause = re.sub(eq_pattern, replace_eq_func, having_clause)

            query = re.sub(r'HAVING\s+.+?(?=\s+(?:ORDER|LIMIT|$))', f'HAVING {having_clause}', query, flags=re.IGNORECASE | re.DOTALL)

        return query

    def _translate_join_clauses(self, query: str, table_mapping: TableMapping) -> str:
        """Translate JOIN clauses for encrypted columns"""
        if not table_mapping:
            return query

        join_pattern = r'(INNER\s+JOIN|LEFT\s+JOIN|RIGHT\s+JOIN|FULL\s+OUTER\s+JOIN|CROSS\s+JOIN|JOIN)\s+(\w+(?:\s+\w+)?)\s+ON\s+(.+?)(?:\s+(?:WHERE|GROUP|ORDER|LIMIT|$)|\s*$)'

        def replace_join(match):
            join_type = match.group(1)
            table_name = match.group(2)
            condition = match.group(3)

            condition = self._translate_column_references(condition, table_mapping)

            return f"{join_type} {table_name} ON {condition}"

        query = re.sub(join_pattern, replace_join, query, flags=re.IGNORECASE | re.DOTALL)

        return query

    def _translate_order_by_clause_intelligent(self, query: str, table_mapping: TableMapping, context: Dict[str, Any]) -> str:
        """Translate ORDER BY clause with intelligent encrypted column handling"""
        if not table_mapping:
            return query

        order_match = re.search(r'ORDER BY\s+(.+?)(?:\s+(?:GROUP|HAVING|LIMIT|$))', query, re.IGNORECASE | re.DOTALL)
        if not order_match:
            order_match = re.search(r'ORDER BY\s+(.+?)$', query, re.IGNORECASE | re.DOTALL)

        if order_match:
            order_clause = order_match.group(1)
            logger.debug(f"Translating ORDER BY clause: '{order_clause}'")

            order_parts = [part.strip() for part in order_clause.split(',')]
            translated_parts = []

            for part in order_parts:
                col_part = part
                direction = ""
                if part.upper().endswith(' ASC'):
                    col_part = part[:-4].strip()
                    direction = " ASC"
                elif part.upper().endswith(' DESC'):
                    col_part = part[:-5].strip()
                    direction = " DESC"
                elif part.upper().endswith(' NULLS FIRST'):
                    col_part = part[:-12].strip()
                    direction = " NULLS FIRST"
                elif part.upper().endswith(' NULLS LAST'):
                    col_part = part[:-11].strip()
                    direction = " NULLS LAST"

                translated_col = col_part.strip()
                for col_name, col_mapping in table_mapping.encrypted_columns.items():
                    if col_mapping.is_encrypted and translated_col == col_name:
                        filter_strategy = context.get('filter_strategies', {}).get(col_name, 'use_tags')

                        if filter_strategy == 'use_tags' and col_mapping.tag_name and col_mapping.supports_ordering:
                            translated_col = col_mapping.tag_name
                            logger.debug(f"Using tags for ORDER BY on column {col_name}")
                        else:
                            translated_col = col_mapping.encrypted_name
                            logger.debug(f"Using encrypted data for ORDER BY on column {col_name}")
                        break

                translated_parts.append(f"{translated_col}{direction}")

            new_order_clause = ', '.join(translated_parts)

            original_query = query
            query = re.sub(r'ORDER BY\s+(.+?)$', f'ORDER BY {new_order_clause}', query, flags=re.IGNORECASE | re.DOTALL)

            if query == original_query:
                query = re.sub(r'ORDER BY\s+.+?(?=\s+(?:GROUP|HAVING|LIMIT|$))', f'ORDER BY {new_order_clause}', query, flags=re.IGNORECASE | re.DOTALL)

        return query

    def _translate_intersect_query(self, query: str) -> Tuple[str, Dict[str, Any]]:
        """Translate INTERSECT queries"""
        intersect_parts = re.split(r'\s+INTERSECT\s+', query, flags=re.IGNORECASE)

        translated_parts = []
        metadata = {"intersect_operations": []}

        for part in intersect_parts:
            part = part.strip()
            if part:
                try:
                    translated_part, part_metadata = self.translate_query(part)
                    translated_parts.append(translated_part)
                    metadata["intersect_operations"].append(part_metadata)
                except Exception as e:
                    logger.warning(f"Failed to translate INTERSECT part: {e}")
                    translated_parts.append(part)

        translated_query = ' INTERSECT '.join(translated_parts)
        return translated_query, metadata

    def _translate_except_query(self, query: str) -> Tuple[str, Dict[str, Any]]:
        """Translate EXCEPT/MINUS queries"""
        if 'EXCEPT' in query.upper():
            except_parts = re.split(r'\s+EXCEPT\s+', query, flags=re.IGNORECASE)
            operation = "EXCEPT"
        else:
            except_parts = re.split(r'\s+MINUS\s+', query, flags=re.IGNORECASE)
            operation = "MINUS"

        translated_parts = []
        metadata = {"except_operations": [], "operation_type": operation}

        for part in except_parts:
            part = part.strip()
            if part:
                try:
                    translated_part, part_metadata = self.translate_query(part)
                    translated_parts.append(translated_part)
                    metadata["except_operations"].append(part_metadata)
                except Exception as e:
                    logger.warning(f"Failed to translate EXCEPT part: {e}")
                    translated_parts.append(part)

        translated_query = f' {operation} '.join(translated_parts)
        return translated_query, metadata

    def _translate_pivot_query(self, query: str) -> Tuple[str, Dict[str, Any]]:
        """Translate PIVOT/UNPIVOT queries"""
        translated_query = query
        metadata = {
            "pivot_operation": True,
            "note": "PIVOT/UNPIVOT operations have limited translation support"
        }

        pivot_match = re.search(r'(SELECT.*?)(?:\s+PIVOT|\s+UNPIVOT)', query, re.IGNORECASE | re.DOTALL)
        if pivot_match:
            base_query = pivot_match.group(1)
            try:
                translated_base, base_metadata = self.translate_query(base_query)
                translated_query = query.replace(base_query, translated_base)
                metadata.update(base_metadata)
            except Exception as e:
                logger.warning(f"Failed to translate base query in PIVOT: {e}")

        return translated_query, metadata

    def _parse_values_clause(self, values_str: str) -> List[List[str]]:
        """Parse VALUES clause that can contain multiple rows like (val1, val2), (val3, val4)"""
        rows = []
        current_row = []
        current_value = ""
        in_quotes = False
        quote_char = None
        paren_depth = 0

        i = 0
        while i < len(values_str):
            char = values_str[i]

            if not in_quotes and char == '(':
                paren_depth += 1
                if paren_depth == 1:
                    current_row = []
                    current_value = ""
            elif not in_quotes and char == ')':
                paren_depth -= 1
                if paren_depth == 0:
                    if current_value.strip():
                        current_row.append(current_value.strip())
                    cleaned_row = []
                    for val in current_row:
                        val = val.strip()
                        if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                            val = val[1:-1]  # Remove quotes
                        cleaned_row.append(val)
                    rows.append(cleaned_row)
            elif paren_depth > 0:
                if not in_quotes and (char == '"' or char == "'"):
                    in_quotes = True
                    quote_char = char
                    current_value += char
                elif in_quotes and char == quote_char:
                    if i + 1 < len(values_str) and values_str[i + 1] == quote_char:
                        current_value += char + char
                        i += 1  # Skip next character
                    else:
                        in_quotes = False
                        current_value += char
                elif not in_quotes and char == ',':
                    current_row.append(current_value.strip())
                    current_value = ""
                else:
                    current_value += char

            i += 1

        return rows

    def _parse_csv_values(self, values_str: str) -> List[str]:
        """Parse comma-separated values handling quoted strings properly"""
        values = []
        current = ""
        in_quotes = False
        quote_char = None

        i = 0
        while i < len(values_str):
            char = values_str[i]

            if not in_quotes and (char == '"' or char == "'"):
                in_quotes = True
                quote_char = char
                current += char
            elif in_quotes and char == quote_char:
                if i + 1 < len(values_str) and values_str[i + 1] == quote_char:
                    current += char + char
                    i += 1  # Skip next character
                else:
                    in_quotes = False
                    current += char
            elif not in_quotes and char == ',':
                values.append(current.strip())
                current = ""
            else:
                current += char

            i += 1

        if current.strip():
            values.append(current.strip())

        cleaned_values = []
        for val in values:
            val = val.strip()
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                val = val[1:-1]  # Remove quotes
            cleaned_values.append(val)

        return cleaned_values

    def _split_select_columns(self, select_clause: str) -> List[str]:
        """Split SELECT clause columns properly handling parentheses"""
        columns = []
        current = ""
        paren_depth = 0

        i = 0
        while i < len(select_clause):
            char = select_clause[i]

            if char == '(':
                paren_depth += 1
                current += char
            elif char == ')':
                paren_depth -= 1
                current += char
            elif char == ',' and paren_depth == 0:
                if current.strip():
                    columns.append(current.strip())
                current = ""
            else:
                current += char

            i += 1

        if current.strip():
            columns.append(current.strip())

        return columns

    def _extract_columns_from_select(self, query: str) -> List[str]:
        """Extract column names from SELECT clause"""
        select_match = re.search(r'SELECT\s+(.+?)\s+FROM', query, re.IGNORECASE | re.DOTALL)
        if select_match:
            select_clause = select_match.group(1)
            if select_clause.upper().strip() == '*':
                return ['*']
            else:
                columns = [col.strip() for col in select_clause.split(',')]
                return columns
        return []

    def decrypt_query_results(self, rows: List[Dict[str, Any]], table_mapping: TableMapping) -> List[Dict[str, Any]]:
        """
        Decrypt encrypted columns in query results

        Args:
            rows: Raw rows from database
            table_mapping: Table mapping with encryption info

        Returns:
            List of decrypted rows with original column names
        """
        if not table_mapping:
            return rows

        decrypted_rows = []

        for row in rows:
            decrypted_row = {}

            for col_name, value in row.items():
                if col_name.startswith('tag_'):
                    continue

                if col_name in table_mapping.encrypted_columns:
                    col_mapping = table_mapping.encrypted_columns[col_name]
                    if col_mapping.is_encrypted:
                        decryption_bytes = None

                        if isinstance(value, bytes):
                            decryption_bytes = value
                        elif isinstance(value, str) and value.startswith('\\x') and len(value) > 2:
                            try:
                                hex_part = value[2:]  # Remove \x prefix
                                decryption_bytes = bytes.fromhex(hex_part)
                                logger.debug(f"Converted PostgreSQL BYTEA hex to bytes for {col_name}, size: {len(decryption_bytes)}")
                            except ValueError as e:
                                logger.warning(f"Failed to convert PostgreSQL BYTEA hex for {col_name}: {e}")
                                decrypted_row[col_name] = f"<INVALID_BYTEA_HEX:{str(value)[:20]}...>"
                                continue
                        elif isinstance(value, str) and len(value) > 10 and all(c in '0123456789abcdefABCDEF' for c in value):
                            try:
                                decryption_bytes = bytes.fromhex(value)
                                logger.debug(f"Converted hex string to bytes for {col_name}, size: {len(decryption_bytes)}")
                            except ValueError as e:
                                logger.warning(f"Failed to convert hex string for {col_name}: {e}")
                                decrypted_row[col_name] = f"<INVALID_HEX_STRING:{str(value)[:20]}...>"
                                continue
                        else:
                            decrypted_row[col_name] = f"<INVALID_ENCRYPTED_DATA:{str(value)[:20]}...>"
                            continue

                        if decryption_bytes is not None:
                            try:
                                decrypted_value = clwe_encryptor.decrypt_value(decryption_bytes, settings.CRYPTOPIX_DEFAULT_PASSWORD)
                                decrypted_row[col_name] = decrypted_value
                                logger.debug(f"Successfully decrypted {col_name}")
                            except Exception as e:
                                logger.warning(f"Failed to decrypt {col_name}: {e}")
                                decrypted_row[col_name] = f"<DECRYPTION_FAILED:{str(value)[:20]}...>"
                    else:
                        decrypted_row[col_name] = value
                else:
                    decrypted_row[col_name] = value

            decrypted_rows.append(decrypted_row)

        return decrypted_rows


sql_translator = SQLTranslator()