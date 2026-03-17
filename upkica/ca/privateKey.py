# -*- coding:utf-8 -*-

"""
Private Key handling for uPKI.

This module provides the PrivateKey class for generating, loading,
and exporting private keys.
"""

from typing import Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa

import upkica
from upkica.core.common import Common


class PrivateKey(Common):
    """Private key handler.

    Handles generation, loading, parsing, and export of asymmetric private keys.

    Attributes:
        _config: Configuration object.
        _backend: Cryptography backend instance.

    Args:
        config: Configuration object with logger settings.

    Raises:
        Exception: If initialization fails.
    """

    def __init__(self, config: Any) -> None:
        """Initialize PrivateKey handler.

        Args:
            config: Configuration object with logger settings.

        Raises:
            Exception: If initialization fails.
        """
        try:
            super().__init__(config._logger)
        except Exception as err:
            raise Exception(f"Unable to initialize privateKey: {err}")

        self._config: Any = config

        # Private var
        self._PrivateKey__backend = default_backend()

    def generate(
        self,
        profile: dict,
        keyType: str | None = None,
        keyLen: int | None = None,
    ) -> Any:
        """Generate a private key based on profile.

        Args:
            profile: Profile dictionary containing keyLen and keyType.
            keyType: Override key type ('rsa' or 'dsa').
            keyLen: Override key length in bits.

        Returns:
            Private key object.

        Raises:
            Exception: If key generation fails.
            NotImplementedError: If key type is not supported.
        """
        if keyLen is None:
            keyLen = int(profile["keyLen"])
        if keyType is None:
            keyType = str(profile["keyType"])

        key_length: int = int(keyLen)  # Ensure it's an int

        if keyType == "rsa":
            try:
                pkey = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=key_length,
                    backend=self._PrivateKey__backend,
                )
            except Exception as err:
                raise Exception(err)
        elif keyType == "dsa":
            try:
                pkey = dsa.generate_private_key(
                    key_size=key_length,
                    backend=self._PrivateKey__backend,
                )
            except Exception as err:
                raise Exception(err)
        else:
            raise NotImplementedError(
                f"Private key generation only support {self._config._allowed.KeyTypes} key type"
            )

        return pkey

    def load(
        self, raw: bytes, password: bytes | None = None, encoding: str = "PEM"
    ) -> Any:
        """Load a private key from raw data.

        Args:
            raw: Raw private key bytes.
            password: Optional password to decrypt the key.
            encoding: Encoding format ('PEM', 'DER', 'PFX', 'P12').

        Returns:
            Private key object.

        Raises:
            Exception: If loading fails.
            NotImplementedError: If encoding is not supported.
        """
        pkey = None

        try:
            if encoding == "PEM":
                pkey = serialization.load_pem_private_key(
                    raw, password=password, backend=self._PrivateKey__backend
                )
            elif encoding in ["DER", "PFX", "P12"]:
                pkey = serialization.load_der_private_key(
                    raw, password=password, backend=self._PrivateKey__backend
                )
            else:
                raise NotImplementedError("Unsupported Private Key encoding")
        except Exception as err:
            raise Exception(err)

        return pkey

    def dump(
        self,
        pkey: Any,
        password: str | None = None,
        encoding: str = "PEM",
    ) -> bytes:
        """Export private key to bytes.

        Args:
            pkey: Private key object.
            password: Optional password to encrypt the key.
            encoding: Encoding format ('PEM', 'DER', 'PFX', 'P12').

        Returns:
            Encoded private key bytes.

        Raises:
            Exception: If export fails.
            NotImplementedError: If encoding is not supported.
        """
        data = None

        if encoding == "PEM":
            enc = serialization.Encoding.PEM
        elif encoding in ["DER", "PFX", "P12"]:
            enc = serialization.Encoding.DER
        else:
            raise NotImplementedError("Unsupported private key encoding")

        encryption = (
            serialization.NoEncryption()
            if password is None
            else serialization.BestAvailableEncryption(password.encode())
        )
        try:
            data = pkey.private_bytes(
                encoding=enc,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=encryption,
            )
        except Exception as err:
            raise Exception(err)

        return data

    def parse(
        self, raw: bytes, password: bytes | None = None, encoding: str = "PEM"
    ) -> dict:
        """Parse private key and return metadata.

        Args:
            raw: Raw private key bytes.
            password: Optional password to decrypt the key.
            encoding: Encoding format ('PEM', 'DER', 'PFX', 'P12').

        Returns:
            Dictionary with 'bits' and 'keyType' keys.

        Raises:
            Exception: If parsing fails.
            NotImplementedError: If encoding is not supported.
        """
        data = {}

        try:
            if encoding == "PEM":
                pkey = serialization.load_pem_private_key(
                    raw, password=password, backend=self._PrivateKey__backend
                )
            elif encoding in ["DER", "PFX", "P12"]:
                pkey = serialization.load_der_private_key(
                    raw, password=password, backend=self._PrivateKey__backend
                )
            else:
                raise NotImplementedError("Unsupported Private Key encoding")
        except Exception as err:
            raise Exception(err)

        data["bits"] = pkey.key_size
        data["keyType"] = "rsa"

        return data
