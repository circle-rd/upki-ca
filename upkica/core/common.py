"""
Common base class for all uPKI CA components.

This module provides the Common base class that all other classes
inherit from, providing common functionality and utilities.

Author: uPKI Team
License: MIT
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any


class Common:
    """
    Base class for all uPKI CA components.

    Provides common utilities for all classes in the project including
    timestamp generation, path handling, and common utilities.
    """

    @staticmethod
    def timestamp() -> str:
        """
        Generate a UTC timestamp in ISO 8601 format.

        Returns:
            str: Current UTC timestamp in ISO 8601 format
        """
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def ensure_dir(path: str) -> bool:
        """
        Ensure a directory exists, creating it if necessary.

        Args:
            path: Directory path to ensure exists

        Returns:
            bool: True if directory exists or was created successfully
        """
        try:
            os.makedirs(path, exist_ok=True)
            return True
        except OSError:
            return False

    @staticmethod
    def get_home_dir() -> str:
        """
        Get the user's home directory.

        Returns:
            str: User's home directory path
        """
        return os.path.expanduser("~")

    @staticmethod
    def get_upki_dir() -> str:
        """
        Get the uPKI configuration directory.

        Returns:
            str: uPKI directory path (~/.upki)
        """
        return os.path.join(Common.get_home_dir(), ".upki")

    @staticmethod
    def get_ca_dir() -> str:
        """
        Get the CA-specific directory.

        Returns:
            str: CA directory path (~/.upki/ca)
        """
        return os.path.join(Common.get_upki_dir(), "ca")

    @staticmethod
    def sanitize_dn(dn: str) -> str:
        """
        Sanitize a Distinguished Name by removing invalid characters.

        Args:
            dn: Distinguished Name to sanitize

        Returns:
            str: Sanitized Distinguished Name
        """
        # Remove any null bytes and control characters
        return "".join(char for char in dn if ord(char) >= 32 or char in "\n\r\t")

    @staticmethod
    def parse_dn(dn: str) -> dict[str, str]:
        """
        Parse a Distinguished Name into components.

        Args:
            dn: Distinguished Name string (e.g., "/C=FR/O=Company/CN=example.com")

        Returns:
            dict: Dictionary of DN components (C, ST, L, O, OU, CN, etc.)
        """
        result: dict[str, str] = {}

        # Remove leading slash if present
        dn = dn.lstrip("/")

        # Split by "/" and parse each component
        parts = dn.split("/")
        for part in parts:
            if "=" in part:
                key, value = part.split("=", 1)
                result[key.strip()] = value.strip()

        return result

    @staticmethod
    def build_dn(components: dict[str, str]) -> str:
        """
        Build a Distinguished Name from components.

        Args:
            components: Dictionary of DN components (C, ST, L, O, OU, CN)

        Returns:
            str: Formatted Distinguished Name
        """
        parts = [f"{k}={v}" for k, v in components.items()]
        return "/" + "/".join(parts)

    @staticmethod
    def validate_key_type(key_type: str) -> bool:
        """
        Validate if a key type is supported.

        Args:
            key_type: Key type to validate (rsa, dsa)

        Returns:
            bool: True if key type is supported
        """
        return key_type.lower() in ("rsa", "dsa")

    @staticmethod
    def validate_key_length(key_len: int) -> bool:
        """
        Validate if a key length is acceptable.

        Args:
            key_len: Key length in bits

        Returns:
            bool: True if key length is acceptable (1024, 2048, or 4096)
        """
        return key_len in (1024, 2048, 4096)

    @staticmethod
    def validate_digest(digest: str) -> bool:
        """
        Validate if a digest algorithm is supported.

        Args:
            digest: Digest algorithm name

        Returns:
            bool: True if digest is supported
        """
        return digest.lower() in ("md5", "sha1", "sha256", "sha512")

    @classmethod
    def get_config_path(cls, filename: str) -> str:
        """
        Get the full path to a configuration file.

        Args:
            filename: Configuration filename

        Returns:
            str: Full path to configuration file
        """
        return os.path.join(cls.get_ca_dir(), filename)

    @classmethod
    def get_cert_path(cls, cn: str | None = None) -> str:
        """
        Get the path to store certificates.

        Args:
            cn: Common Name for certificate filename (optional)

        Returns:
            str: Path to certificates directory or specific certificate
        """
        cert_dir = os.path.join(cls.get_ca_dir(), "certs")
        cls.ensure_dir(cert_dir)
        if cn:
            return os.path.join(cert_dir, f"{cn}.crt")
        return cert_dir

    @classmethod
    def get_key_path(cls, cn: str | None = None) -> str:
        """
        Get the path to store private keys.

        Args:
            cn: Common Name for key filename (optional)

        Returns:
            str: Path to private keys directory or specific key
        """
        key_dir = os.path.join(cls.get_ca_dir(), "private")
        cls.ensure_dir(key_dir)
        if cn:
            return os.path.join(key_dir, f"{cn}.key")
        return key_dir

    @classmethod
    def get_csr_path(cls, cn: str | None = None) -> str:
        """
        Get the path to store certificate signing requests.

        Args:
            cn: Common Name for CSR filename (optional)

        Returns:
            str: Path to CSR directory or specific CSR
        """
        csr_dir = os.path.join(cls.get_ca_dir(), "reqs")
        cls.ensure_dir(csr_dir)
        if cn:
            return os.path.join(csr_dir, f"{cn}.csr")
        return csr_dir

    @classmethod
    def get_profile_path(cls, name: str | None = None) -> str:
        """
        Get the path to certificate profiles.

        Args:
            name: Profile name (optional)

        Returns:
            str: Path to profiles directory or specific profile
        """
        profile_dir = os.path.join(cls.get_ca_dir(), "profiles")
        cls.ensure_dir(profile_dir)
        if name:
            return os.path.join(profile_dir, f"{name}.yml")
        return profile_dir
