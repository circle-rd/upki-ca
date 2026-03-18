"""
Private Key handling for uPKI CA Server.

This module provides the PrivateKey class for generating, loading,
and managing private keys.

Author: uPKI Team
License: MIT
"""

from __future__ import annotations

import io
from typing import Any, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
    BestAvailableEncryption,
    load_pem_private_key,
    load_der_private_key,
)
from cryptography.hazmat.primitives.serialization.ssh import (
    load_ssh_private_key,
)

from upkica.core.common import Common
from upkica.core.options import KeyTypes, KeyLen, DEFAULT_KEY_TYPE, DEFAULT_KEY_LENGTH
from upkica.core.upkiError import KeyError, ValidationError
from upkica.core.validators import CSRValidator


class PrivateKey(Common):
    """
    Handles private key generation and management.

    Supports RSA and DSA key types with various key lengths.
    """

    def __init__(self, key: Any = None) -> None:
        """
        Initialize a PrivateKey object.

        Args:
            key: Cryptography private key object (optional)
        """
        self._key = key

    @property
    def key(self) -> Any:
        """Get the underlying cryptography key object."""
        if self._key is None:
            raise KeyError("No private key loaded")
        return self._key

    @property
    def key_type(self) -> str:
        """Get the key type (rsa or dsa)."""
        if self._key is None:
            raise KeyError("No private key loaded")

        if isinstance(self._key, rsa.RSAPrivateKey):
            return "rsa"
        elif isinstance(self._key, dsa.DSAPrivateKey):
            return "dsa"
        return "unknown"

    @property
    def key_length(self) -> int:
        """Get the key length in bits."""
        if self._key is None:
            raise KeyError("No private key loaded")
        return self._key.key_size

    @property
    def public_key(self) -> Any:
        """Get the corresponding public key."""
        if self._key is None:
            raise KeyError("No private key loaded")
        return self._key.public_key()

    @classmethod
    def generate(
        cls,
        profile: dict[str, Any],
        key_type: str | None = None,
        key_len: int | None = None,
    ) -> PrivateKey:
        """
        Generate a new private key.

        Args:
            profile: Certificate profile with key parameters
            key_type: Key type (rsa or dsa). Defaults to profile or 'rsa'
            key_len: Key length in bits. Defaults to profile or 4096

        Returns:
            PrivateKey: Generated private key object

        Raises:
            KeyError: If key generation fails
            ValidationError: If parameters are invalid
        """
        # Get key type from parameters, profile, or default
        if key_type is None:
            key_type = profile.get("keyType", DEFAULT_KEY_TYPE)
        if key_type is None:
            key_type = DEFAULT_KEY_TYPE
        key_type = key_type.lower()

        if not key_type or key_type not in KeyTypes:
            raise ValidationError(f"Invalid key type: {key_type}. Allowed: {KeyTypes}")

        # Get key length from parameters, profile, or default
        if key_len is None:
            key_len = profile.get("keyLen", DEFAULT_KEY_LENGTH)
        if key_len is None:
            key_len = DEFAULT_KEY_LENGTH

        # Validate key length
        CSRValidator.validate_key_length(key_len)

        try:
            backend = default_backend()

            if key_type == "rsa":
                key = rsa.generate_private_key(
                    public_exponent=65537, key_size=key_len, backend=backend
                )
            elif key_type == "dsa":
                key = dsa.generate_private_key(key_size=key_len, backend=backend)
            else:
                raise KeyError(f"Unsupported key type: {key_type}")

            return cls(key)

        except Exception as e:
            raise KeyError(f"Failed to generate private key: {e}")

    @classmethod
    def load(cls, key_pem: str, password: bytes | None = None) -> PrivateKey:
        """
        Load a private key from PEM format.

        Args:
            key_pem: Private key in PEM format
            password: Optional password to decrypt the key

        Returns:
            PrivateKey: Loaded private key object

        Raises:
            KeyError: If key loading fails
        """
        try:
            key = load_pem_private_key(
                key_pem.encode("utf-8"), password=password, backend=default_backend()
            )
            return cls(key)
        except Exception as e:
            raise KeyError(f"Failed to load private key: {e}")

    @classmethod
    def load_from_file(cls, filepath: str, password: bytes | None = None) -> PrivateKey:
        """
        Load a private key from a file.

        Args:
            filepath: Path to the key file
            password: Optional password to decrypt the key

        Returns:
            PrivateKey: Loaded private key object

        Raises:
            KeyError: If key loading fails
        """
        try:
            with open(filepath, "rb") as f:
                key_data = f.read()

            key = load_pem_private_key(
                key_data, password=password, backend=default_backend()
            )
            return cls(key)
        except FileNotFoundError:
            raise KeyError(f"Key file not found: {filepath}")
        except Exception as e:
            raise KeyError(f"Failed to load private key from file: {e}")

    def export(self, encoding: str = "pem", password: bytes | None = None) -> bytes:
        """
        Export the private key.

        Args:
            encoding: Output encoding (pem, der, ssh)
            password: Optional password to encrypt the key

        Returns:
            bytes: Exported key data

        Raises:
            KeyError: If export fails
        """
        if self._key is None:
            raise KeyError("No private key to export")

        try:
            if encoding.lower() == "pem":
                if password:
                    encryption = BestAvailableEncryption(password)
                else:
                    encryption = NoEncryption()

                return self._key.private_bytes(
                    encoding=Encoding.PEM,
                    format=PrivateFormat.PKCS8,
                    encryption_algorithm=encryption,
                )
            elif encoding.lower() == "der":
                if password:
                    encryption = BestAvailableEncryption(password)
                else:
                    encryption = NoEncryption()

                return self._key.private_bytes(
                    encoding=Encoding.DER,
                    format=PrivateFormat.PKCS8,
                    encryption_algorithm=encryption,
                )
            elif encoding.lower() == "ssh":
                return self._key.private_bytes(
                    encoding=Encoding.PEM,
                    format=PrivateFormat.OpenSSH,
                    encryption_algorithm=NoEncryption(),
                )
            else:
                raise KeyError(f"Unsupported encoding: {encoding}")

        except Exception as e:
            raise KeyError(f"Failed to export private key: {e}")

    def export_to_file(
        self, filepath: str, encoding: str = "pem", password: bytes | None = None
    ) -> bool:
        """
        Export the private key to a file.

        Args:
            filepath: Path to save the key
            encoding: Output encoding (pem, der, ssh)
            password: Optional password to encrypt the key

        Returns:
            bool: True if successful

        Raises:
            KeyError: If export fails
        """
        try:
            # Ensure directory exists
            self.ensure_dir(filepath.rsplit("/", 1)[0])

            key_data = self.export(encoding=encoding, password=password)

            with open(filepath, "wb") as f:
                f.write(key_data)

            # Set restrictive permissions
            import os

            os.chmod(filepath, 0o600)

            return True
        except Exception as e:
            raise KeyError(f"Failed to export private key to file: {e}")

    def sign(self, data: bytes, digest: str = "sha256") -> bytes:
        """
        Sign data with the private key.

        Args:
            data: Data to sign
            digest: Hash algorithm to use

        Returns:
            bytes: Signature
        """
        if self._key is None:
            raise KeyError("No private key available for signing")

        try:
            hash_algorithm = getattr(hashes, digest.upper())()

            if isinstance(self._key, rsa.RSAPrivateKey):
                return self._key.sign(data, padding.PKCS1v15(), hash_algorithm)
            elif isinstance(self._key, dsa.DSAPrivateKey):
                return self._key.sign(data, hash_algorithm)
            else:
                raise KeyError(f"Signing not supported for key type: {self.key_type}")
        except Exception as e:
            raise KeyError(f"Failed to sign data: {e}")

    def __repr__(self) -> str:
        """Return string representation of the key."""
        if self._key is None:
            return "PrivateKey(not loaded)"
        return f"PrivateKey(type={self.key_type}, length={self.key_length})"
