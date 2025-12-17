"""
CryptoPIX Bridge v2.0 - CLWE Encryption Core
Handles CLWE (Color Lattice Learning with Errors) encryption operations
"""

import logging
import hashlib
from typing import Dict, Any, Optional, Union, List
import json

try:
    from clwe import ColorCipher
    CLWE_AVAILABLE = True
except ImportError:
    CLWE_AVAILABLE = False
    ColorCipher = None

from app.config import settings

logger = logging.getLogger(__name__)


class CLWEEncryptionError(Exception):
    """Custom exception for CLWE encryption errors"""
    pass


class CLWEEncryptor:
    """CLWE-based encryption service using Cryptopix-CLWE library"""

    def __init__(self):
        if not CLWE_AVAILABLE:
            raise CLWEEncryptionError("Cryptopix-CLWE library not available. Please install 'cryptopix-clwe' package.")

        self.cipher = ColorCipher()

        self.security_levels = {
            "Min": {
                "clwe_level": "Min",
                "lattice_dimension": 1536,
                "modulus_log2": 34,
                "error_bound": 8,
                "security_bits": 815,
                "description": "Minimum security (815+ bits)"
            },
            "Bal": {
                "clwe_level": "Bal",
                "lattice_dimension": 2048,
                "modulus_log2": 36,
                "error_bound": 10,
                "security_bits": 969,
                "description": "Balanced security (969+ bits)"
            },
            "Max": {
                "clwe_level": "Max",
                "lattice_dimension": 3072,
                "modulus_log2": 38,
                "error_bound": 12,
                "security_bits": 1221,
                "description": "Maximum security (1221+ bits)"
            }
        }
        self.default_level = settings.default_security_level or "Min"

    def encrypt_data(self,
                       data: Union[str, Dict, List],
                       password: str,
                       security_level: Optional[str] = None,
                       deterministic: bool = True) -> bytes:
        """
        Encrypt data using CLWE and return as encrypted BLOB

        Args:
            data: Data to encrypt (string, dict, or list)
            password: Encryption password
            security_level: Security level (Min, Bal, Max)
            deterministic: Use deterministic encryption for searchable data (default: True)

        Returns:
            Encrypted data as bytes (BLOB)
        """
        try:
            level = security_level or self.default_level
            if level not in self.security_levels:
                raise CLWEEncryptionError(f"Invalid security level: {level}")

            if isinstance(data, (dict, list)):
                data_str = json.dumps(data, separators=(',', ':'))
            else:
                data_str = str(data)

            if deterministic:
                webp_image_data = self.cipher.encrypt_to_image(data_str, password, mode="SOP")
                logger.info(f"✅ Data encrypted deterministically to WebP image successfully. Level: {level}, Size: {len(webp_image_data)} bytes")
            else:
                webp_image_data = self.cipher.encrypt_to_image(data_str, password)
                logger.info(f"✅ Data encrypted (variable output) to WebP image successfully. Level: {level}, Size: {len(webp_image_data)} bytes")
            return webp_image_data

        except Exception as e:
            logger.error(f"❌ CLWE encryption failed: {e}")
            raise CLWEEncryptionError(f"Encryption failed: {str(e)}")

    def encrypt_value(self, value: Any, password: str, security_level: Optional[str] = None, deterministic: bool = True) -> bytes:
        """
        Encrypt a single value and return as BLOB

        Args:
            value: Single value to encrypt
            password: Encryption password
            security_level: Security level (Min, Bal, Max)
            deterministic: Use deterministic encryption for searchable data (default: True)

        Returns:
            Encrypted value as bytes (BLOB)
        """
        if value is None:
            value_str = ""
        else:
            value_str = str(value)

        return self.encrypt_data(value_str, password, security_level, deterministic)

    def bulk_encrypt_values(self, values: List[Any], password: str, security_level: Optional[str] = None, deterministic: bool = True) -> List[bytes]:
        """
        Bulk encrypt multiple values

        Args:
            values: List of values to encrypt
            password: Encryption password
            security_level: Security level (Min, Bal, Max)
            deterministic: Use deterministic encryption for searchable data (default: True)

        Returns:
            List of encrypted values as BLOBs
        """
        encrypted_blobs = []
        for value in values:
            encrypted_blob = self.encrypt_value(value, password, security_level, deterministic)
            encrypted_blobs.append(encrypted_blob)

        logger.info(f"✅ Bulk encrypted {len(values)} values (deterministic: {deterministic})")
        return encrypted_blobs

    def decrypt_data(self, encrypted_blob: bytes, password: str) -> str:
        """
        Decrypt data from encrypted BLOB using CLWE

        Args:
            encrypted_blob: Encrypted data as bytes (BLOB)
            password: Decryption password

        Returns:
            Original decrypted data as string
        """
        try:
            decrypted_result = self.cipher.decrypt_from_image(encrypted_blob, password)
            logger.info("✅ Data decrypted from WebP image successfully")

            if isinstance(decrypted_result, str):
                return decrypted_result
            elif isinstance(decrypted_result, bytes):
                try:
                    return decrypted_result.decode('utf-8')
                except UnicodeDecodeError:
                    return decrypted_result.decode('latin-1')
            else:
                return str(decrypted_result)

        except Exception as e:
            logger.error(f"❌ CLWE decryption failed: {e}")
            raise CLWEEncryptionError(f"Decryption failed: {str(e)}")

    def decrypt_value(self, encrypted_blob: bytes, password: str) -> Any:
        """
        Decrypt a single value from BLOB

        Args:
            encrypted_blob: Encrypted value as bytes (BLOB)
            password: Decryption password

        Returns:
            Original decrypted value
        """
        decrypted_str = self.decrypt_data(encrypted_blob, password)

        try:
            return json.loads(decrypted_str)
        except (json.JSONDecodeError, TypeError):
            return decrypted_str

    def bulk_decrypt_values(self, encrypted_blobs: List[bytes], password: str) -> List[Any]:
        """
        Bulk decrypt multiple values from BLOBs

        Args:
            encrypted_blobs: List of encrypted values as BLOBs
            password: Decryption password

        Returns:
            List of decrypted values
        """
        decrypted_values = []
        for blob in encrypted_blobs:
            decrypted_value = self.decrypt_value(blob, password)
            decrypted_values.append(decrypted_value)

        logger.info(f"✅ Bulk decrypted {len(encrypted_blobs)} values")
        return decrypted_values


    def generate_unified_tag(self, data: Any, data_type: str = "text") -> str:
        """
        Generate unified multi-part tag containing query capabilities (reduced size)

        Tag Structure (20 characters total):
        - Bytes 0-7: Order-preserving encryption (8 chars)
        - Bytes 8-15: Partial match hash (8 chars)
        - Bytes 16-19: Type-specific metadata (4 chars)

        Args:
            data: Data to generate tag for
            data_type: Data type (text, integer, decimal, date)

        Returns:
            Unified 20-character tag string
        """
        try:
            if data is None:
                data_str = ""
            else:
                data_str = str(data)

            logger.debug(f"Generating unified tag for data: {data_str[:50]}..., type: {data_type}")

            ope_value = self._generate_order_preserving_value(data, data_type)[:8]
            logger.debug(f"OPE value: {ope_value}")

            partial_hash = self._generate_partial_hash(data_str)[:8]
            logger.debug(f"Partial hash: {partial_hash}")

            metadata = self._generate_type_metadata(data, data_type)[:4]
            logger.debug(f"Metadata: {metadata}")

            unified_tag = ope_value + partial_hash + metadata
            logger.debug(f"Combined tag before padding: {unified_tag} (length: {len(unified_tag)})")

            if len(unified_tag) < 20:
                unified_tag = unified_tag.ljust(20, '0')
            elif len(unified_tag) > 20:
                unified_tag = unified_tag[:20]

            logger.debug(f"Final unified tag: {unified_tag}")
            return unified_tag

        except Exception as e:
            logger.error(f"Unified tag generation failed for data: {data}, type: {data_type}, error: {e}")
            fallback_tag = "0" * 20
            logger.warning(f"Using fallback tag: {fallback_tag}")
            return fallback_tag

    def _generate_exact_hash(self, data: str) -> str:
        """Generate exact match hash component"""
        salt = getattr(settings, 'tag_salt', 'cryptopix_default_salt')
        salted_data = f"exact:{salt}:{data}"
        hash_obj = hashlib.sha256(salted_data.encode('utf-8'))
        return hash_obj.hexdigest()

    def _generate_order_preserving_value(self, data: Any, data_type: str) -> str:
        """Generate order-preserving encryption component"""
        if data is None:
            return "0" * 8

        data_str = str(data) if data is not None else ""

        if data_type in ['integer', 'decimal', 'numeric']:
            try:
                numeric_value = float(data)
                ope_value = int((numeric_value + 1000000) * 1000)  # Offset to handle negatives
                return f"{ope_value & 0xFFFFFFFF:08x}"  # 8-character hex
            except (ValueError, TypeError):
                hash_val = hash(data_str) % (2**64)
                return f"{hash_val & 0xFFFFFFFF:08x}"

        if data_type in ['text', 'varchar', 'char'] or isinstance(data, str):
            text_value = 0
            for i, char in enumerate(data_str[:8]):
                text_value += ord(char) * (256 ** i)
            return f"{text_value & 0xFFFFFFFF:08x}"

        if data_type == 'date' or 'date' in data_str.lower():
            import re
            date_match = re.search(r'(\d{4})-(\d{2})-(\d{2})', data_str)
            if date_match:
                year, month, day = map(int, date_match.groups())
                timestamp = year * 10000 + month * 100 + day
                return f"{timestamp & 0xFFFFFFFF:08x}"

        hash_val = hash(data_str) % (2**64)
        return f"{hash_val & 0xFFFFFFFF:08x}"

    def _generate_partial_hash(self, data: str) -> str:
        """Generate partial match hash for LIKE queries"""
        if not data:
            return "0" * 8

        partial_hashes = []
        max_prefix_length = min(len(data), 8)  # Support up to 8 characters
        for length in range(1, max_prefix_length + 1):  # Prefix lengths from 1 to max
            prefix = data[:length].lower()
            salt = getattr(settings, 'tag_salt', 'cryptopix_default_salt')
            salted_prefix = f"partial:{salt}:{prefix}:{length}"
            hash_obj = hashlib.sha256(salted_prefix.encode('utf-8'))
            partial_hashes.append(hash_obj.hexdigest()[:1])  # 1 char per prefix

        combined = "".join(partial_hashes)
        return combined.ljust(8, '0')[:8]

    def _generate_type_metadata(self, data: Any, data_type: str) -> str:
        """Generate type-specific metadata"""
        metadata = ""

        type_codes = {
            'text': 'T', 'varchar': 'V', 'char': 'C',
            'integer': 'I', 'bigint': 'B', 'smallint': 'S',
            'decimal': 'D', 'numeric': 'N', 'float': 'F', 'double': 'O',
            'date': 'A', 'datetime': 'M', 'timestamp': 'P',
            'boolean': 'L', 'blob': 'E', 'json': 'J'
        }
        metadata += type_codes.get(data_type.lower() if data_type else 'text', 'U')

        data_str = str(data) if data is not None else ""
        length = min(len(data_str), 255)  # Cap at 255
        metadata += f"{length:02x}"

        metadata += 'N' if data is None else 'V'

        if len(metadata) < 4:
            metadata = metadata.ljust(4, '0')
        elif len(metadata) > 4:
            metadata = metadata[:4]

        return metadata

    def parse_unified_tag(self, tag: str, component: str) -> str:
        """
        Parse specific component from unified tag

        Args:
            tag: 20-character unified tag
            component: Component to extract ('ope', 'partial', 'metadata')

        Returns:
            Extracted component value
        """
        if not tag or len(tag) != 20:
            return ""

        try:
            if component == 'ope':
                return tag[0:8]
            elif component == 'partial':
                return tag[8:16]
            elif component == 'metadata':
                return tag[16:20]
            else:
                return ""
        except:
            return ""

    def compare_ope_values(self, ope1: str, ope2: str) -> int:
        """
        Compare two OPE values for ordering

        Returns:
            -1 if ope1 < ope2
             0 if ope1 == ope2
             1 if ope1 > ope2
        """
        try:
            val1 = int(ope1, 16) if ope1 else 0
            val2 = int(ope2, 16) if ope2 else 0

            if val1 < val2:
                return -1
            elif val1 > val2:
                return 1
            else:
                return 0
        except:
            return 0

    def generate_tag(self,
                       data: str,
                       tag_type: str = "exact",
                       salt: Optional[str] = None) -> str:
        """
        Legacy tag generation method - supports exact separately since removed from unified
        """
        if tag_type == "exact":
            return self._generate_exact_hash(data)[:8]
        else:
            unified_tag = self.generate_unified_tag(data, "text")
            return self.parse_unified_tag(unified_tag, tag_type)

    def validate_security_level(self, level: str) -> bool:
        """Validate security level"""
        return level in self.security_levels

    def get_security_info(self, level: str) -> Dict[str, Any]:
        """Get security information for a level"""
        if level not in self.security_levels:
            raise CLWEEncryptionError(f"Invalid security level: {level}")
        return self.security_levels[level].copy()




try:
    clwe_encryptor = CLWEEncryptor()
except CLWEEncryptionError:
    clwe_encryptor = None


def encrypt_value(value: Any, password: str, security_level: str = None, deterministic: bool = True) -> bytes:
    """Convenience function to encrypt a single value as BLOB"""
    if clwe_encryptor is None:
        raise CLWEEncryptionError("CLWE encryption not available")
    return clwe_encryptor.encrypt_value(value, password, security_level, deterministic)


def decrypt_value(encrypted_blob: bytes, password: str) -> Any:
    """Convenience function to decrypt a single value from BLOB"""
    if clwe_encryptor is None:
        raise CLWEEncryptionError("CLWE encryption not available")
    return clwe_encryptor.decrypt_value(encrypted_blob, password)


def bulk_encrypt_values(values: List[Any], password: str, security_level: str = None, deterministic: bool = True) -> List[bytes]:
    """Convenience function for bulk encryption"""
    if clwe_encryptor is None:
        raise CLWEEncryptionError("CLWE encryption not available")
    return clwe_encryptor.bulk_encrypt_values(values, password, security_level, deterministic)


def bulk_decrypt_values(encrypted_blobs: List[bytes], password: str) -> List[Any]:
    """Convenience function for bulk decryption"""
    if clwe_encryptor is None:
        raise CLWEEncryptionError("CLWE encryption not available")
    return clwe_encryptor.bulk_decrypt_values(encrypted_blobs, password)


def generate_column_tag(value: str, tag_type: str = "exact") -> str:
    """Convenience function to generate a column tag"""
    if clwe_encryptor is None:
        raise CLWEEncryptionError("CLWE encryption not available")
    return clwe_encryptor.generate_tag(value, tag_type)

