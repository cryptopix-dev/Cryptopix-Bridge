"""
CryptoPIX Bridge - Password Rotation Service
Handles secure password rotation for encrypted databases
"""

import logging
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker
from typing import Dict, List, Any
import json
from pathlib import Path

logger = logging.getLogger(__name__)


class PasswordRotationService:
    """Service to handle encryption password rotation"""
    
    def __init__(self, encrypted_db_url: str, clwe_encryptor, old_password: str, new_password: str):
        """
        Initialize password rotation service
        
        Args:
            encrypted_db_url: URL of the encrypted database
            clwe_encryptor: CLWE encryption service instance
            old_password: Current encryption password
            new_password: New encryption password
        """
        self.encrypted_db_url = encrypted_db_url
        self.clwe_encryptor = clwe_encryptor
        self.old_password = old_password
        self.new_password = new_password
        self.engine = create_engine(encrypted_db_url)
        
    def load_table_mappings(self) -> Dict[str, Any]:
        """Load table mappings from schemas/mappings.json"""
        try:
            mappings_file = Path("schemas/mappings.json")
            if not mappings_file.exists():
                raise FileNotFoundError("Table mappings not found. Please run migration first.")
            
            with open(mappings_file, 'r') as f:
                mappings_data = json.load(f)
            
            return mappings_data.get("table_mappings", {})
        except Exception as e:
            logger.error(f"Failed to load table mappings: {e}")
            raise
    
    def get_encrypted_columns(self, table_name: str, table_mappings: Dict) -> List[str]:
        """Get list of encrypted column names for a table"""
        if table_name not in table_mappings:
            return []
        
        table_mapping = table_mappings[table_name]
        encrypted_columns = table_mapping.get("encrypted_columns", {})
        
        return [col_info.get("encrypted_name", col_name) 
                for col_name, col_info in encrypted_columns.items()]
    
    def rotate_password_for_table(self, table_name: str, encrypted_columns: List[str], 
                                  progress_callback=None) -> Dict[str, Any]:
        """
        Rotate encryption password for a single table
        
        Args:
            table_name: Name of the table
            encrypted_columns: List of encrypted column names
            progress_callback: Optional callback function for progress updates
            
        Returns:
            Dictionary with rotation results
        """
        try:
            logger.info(f"Starting password rotation for table: {table_name}")
            
            if not encrypted_columns:
                logger.info(f"No encrypted columns in table {table_name}, skipping")
                return {
                    "table": table_name,
                    "status": "skipped",
                    "rows_processed": 0,
                    "message": "No encrypted columns"
                }
            
            inspector = inspect(self.engine)
            pk_columns = inspector.get_pk_constraint(table_name).get('constrained_columns', [])
            
            if not pk_columns:
                pk_columns = ['id']
            
            pk_column = pk_columns[0]
            
            with self.engine.connect() as conn:
                count_query = text(f"SELECT COUNT(*) FROM {table_name}")
                total_rows = conn.execute(count_query).scalar()
            
            logger.info(f"Table {table_name}: {total_rows} rows, {len(encrypted_columns)} encrypted columns")
            
            rows_processed = 0
            rows_failed = 0
            
            batch_size = 100
            offset = 0
            
            while offset < total_rows:
                try:
                    with self.engine.begin() as conn:
                        columns_str = f"{pk_column}, " + ", ".join(encrypted_columns)
                        select_query = text(f"""
                            SELECT {columns_str}
                            FROM {table_name}
                            LIMIT {batch_size} OFFSET {offset}
                        """)
                        
                        rows = conn.execute(select_query).fetchall()
                        
                        for row in rows:
                            try:
                                row_dict = dict(row._mapping)
                                pk_value = row_dict[pk_column]
                                
                                updates = []
                                params = {pk_column: pk_value}
                                
                                for col in encrypted_columns:
                                    encrypted_value = row_dict.get(col)
                                    
                                    if encrypted_value is not None:
                                        try:
                                            decrypted_value = self.clwe_encryptor.decrypt_value(
                                                encrypted_value, 
                                                self.old_password
                                            )
                                            
                                            new_encrypted_value = self.clwe_encryptor.encrypt_value(
                                                decrypted_value, 
                                                self.new_password
                                            )
                                            
                                            updates.append(f"{col} = :{col}")
                                            params[col] = new_encrypted_value
                                            
                                        except Exception as e:
                                            logger.error(f"Failed to rotate {table_name}.{col} for row {pk_value}: {e}")
                                            rows_failed += 1
                                            continue
                                
                                if updates:
                                    update_query = text(f"""
                                        UPDATE {table_name}
                                        SET {', '.join(updates)}
                                        WHERE {pk_column} = :{pk_column}
                                    """)
                                    
                                    conn.execute(update_query, params)
                                    rows_processed += 1
                                
                            except Exception as e:
                                logger.error(f"Failed to process row in {table_name}: {e}")
                                rows_failed += 1
                                continue
                        
                        if progress_callback:
                            progress = min(100, int((offset + len(rows)) / total_rows * 100))
                            progress_callback(table_name, progress, rows_processed, total_rows)
                    
                    offset += batch_size
                    
                except Exception as e:
                    logger.error(f"Batch processing failed for {table_name} at offset {offset}: {e}")
                    offset += batch_size  # Skip this batch and continue
                    continue
            
            logger.info(f"Completed password rotation for {table_name}: {rows_processed} rows processed, {rows_failed} failed")
            
            return {
                "table": table_name,
                "status": "success" if rows_failed == 0 else "partial",
                "rows_processed": rows_processed,
                "rows_failed": rows_failed,
                "total_rows": total_rows,
                "encrypted_columns": len(encrypted_columns)
            }
            
        except Exception as e:
            logger.error(f"Password rotation failed for table {table_name}: {e}")
            return {
                "table": table_name,
                "status": "failed",
                "error": str(e),
                "rows_processed": rows_processed
            }
    
    def rotate_password_for_database(self, progress_callback=None) -> Dict[str, Any]:
        """
        Rotate encryption password for entire database
        
        Args:
            progress_callback: Optional callback function for progress updates
            
        Returns:
            Dictionary with overall rotation results
        """
        try:
            logger.info("Starting database-wide password rotation")
            
            table_mappings = self.load_table_mappings()
            
            if not table_mappings:
                raise ValueError("No table mappings found. Cannot proceed with password rotation.")
            
            results = {
                "status": "in_progress",
                "total_tables": len(table_mappings),
                "tables_processed": 0,
                "tables_failed": 0,
                "total_rows_processed": 0,
                "table_results": []
            }
            
            for table_name in table_mappings.keys():
                try:
                    encrypted_columns = self.get_encrypted_columns(table_name, table_mappings)
                    
                    table_result = self.rotate_password_for_table(
                        table_name, 
                        encrypted_columns,
                        progress_callback
                    )
                    
                    results["table_results"].append(table_result)
                    
                    if table_result["status"] in ["success", "partial"]:
                        results["tables_processed"] += 1
                        results["total_rows_processed"] += table_result.get("rows_processed", 0)
                    else:
                        results["tables_failed"] += 1
                    
                except Exception as e:
                    logger.error(f"Failed to process table {table_name}: {e}")
                    results["tables_failed"] += 1
                    results["table_results"].append({
                        "table": table_name,
                        "status": "failed",
                        "error": str(e)
                    })
            
            if results["tables_failed"] == 0:
                results["status"] = "success"
            elif results["tables_processed"] > 0:
                results["status"] = "partial_success"
            else:
                results["status"] = "failed"
            
            logger.info(f"Password rotation completed: {results['status']}")
            
            return results
            
        except Exception as e:
            logger.error(f"Database password rotation failed: {e}")
            return {
                "status": "failed",
                "error": str(e)
            }
    
    def verify_password_rotation(self, sample_size: int = 10) -> bool:
        """
        Verify that password rotation was successful by testing decryption with new password
        
        Args:
            sample_size: Number of random rows to test per table
            
        Returns:
            True if verification successful, False otherwise
        """
        try:
            logger.info("Verifying password rotation...")
            
            table_mappings = self.load_table_mappings()
            
            for table_name in table_mappings.keys():
                encrypted_columns = self.get_encrypted_columns(table_name, table_mappings)
                
                if not encrypted_columns:
                    continue
                
                with self.engine.connect() as conn:
                    columns_str = ", ".join(encrypted_columns)
                    query = text(f"""
                        SELECT {columns_str}
                        FROM {table_name}
                        LIMIT {sample_size}
                    """)
                    
                    rows = conn.execute(query).fetchall()
                    
                    for row in rows:
                        row_dict = dict(row._mapping)
                        
                        for col in encrypted_columns:
                            encrypted_value = row_dict.get(col)
                            
                            if encrypted_value is not None:
                                try:
                                    decrypted = self.clwe_encryptor.decrypt_value(
                                        encrypted_value,
                                        self.new_password
                                    )
                                    
                                    logger.debug(f"Verified {table_name}.{col}")
                                    
                                except Exception as e:
                                    logger.error(f"Verification failed for {table_name}.{col}: {e}")
                                    return False
            
            logger.info("Password rotation verification successful!")
            return True
            
        except Exception as e:
            logger.error(f"Password rotation verification failed: {e}")
            return False
