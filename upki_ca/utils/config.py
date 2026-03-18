"""
Configuration management for uPKI CA Server.

This module provides the Config class for loading and managing
configuration settings.

Author: uPKI Team
License: MIT
"""

from __future__ import annotations

import os
from typing import Any

import yaml

from upki_ca.core.common import Common
from upki_ca.core.options import DEFAULT_DIGEST, DEFAULT_KEY_LENGTH, ClientModes
from upki_ca.core.upki_error import ConfigurationError


class Config(Common):
    """
    Configuration manager for uPKI CA Server.

    Configuration file: ~/.upki/ca/ca.config.yml

    Default configuration:
        ---
        company: "Company Name"
        domain: "example.com"
        host: "127.0.0.1"
        port: 5000
        clients: "register"  # all, register, manual
        password: null       # Private key password
        seed: null          # RA registration seed
    """

    DEFAULT_CONFIG: dict[str, Any] = {
        "company": "Company Name",
        "domain": "example.com",
        "host": "127.0.0.1",
        "port": 5000,
        "clients": "register",
        "password": None,
        "seed": None,
        "key_type": "rsa",
        "key_length": DEFAULT_KEY_LENGTH,
        "digest": DEFAULT_DIGEST,
        "crl_validity": 7,  # days
    }

    def __init__(self, config_path: str | None = None) -> None:
        """
        Initialize Config.

        Args:
            config_path: Path to configuration file
        """
        if config_path:
            self._config_path = config_path
        else:
            self._config_path = self.get_config_path("ca.config.yml")

        self._config: dict[str, Any] = {}

    @property
    def config(self) -> dict[str, Any]:
        """Get the configuration."""
        return self._config

    def load(self) -> bool:
        """
        Load configuration from file.

        Returns:
            bool: True if successful
        """
        # Start with defaults
        self._config = dict(self.DEFAULT_CONFIG)

        # Try to load from file
        if os.path.exists(self._config_path):
            try:
                with open(self._config_path) as f:
                    file_config = yaml.safe_load(f) or {}
                self._config.update(file_config)
            except Exception as e:
                raise ConfigurationError(f"Failed to load config: {e}") from e

        return True

    def save(self) -> bool:
        """
        Save configuration to file.

        Returns:
            bool: True if successful
        """
        try:
            self.ensure_dir(os.path.dirname(self._config_path))
            with open(self._config_path, "w") as f:
                yaml.safe_dump(self._config, f, default_flow_style=False)
            return True
        except Exception as e:
            raise ConfigurationError(f"Failed to save config: {e}") from e

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value.

        Args:
            key: Configuration key
            default: Default value if key not found

        Returns:
            Any: Configuration value
        """
        return self._config.get(key, default)

    def set(self, key: str, value: Any) -> bool:
        """
        Set a configuration value.

        Args:
            key: Configuration key
            value: Configuration value

        Returns:
            bool: True if successful
        """
        self._config[key] = value
        return True

    def validate(self) -> bool:
        """
        Validate the configuration.

        Returns:
            bool: True if valid

        Raises:
            ConfigurationError: If configuration is invalid
        """
        # Validate host
        host = self._config.get("host", "")
        if not host:
            raise ConfigurationError("Host is required")

        # Validate port
        port = self._config.get("port", 0)
        if not isinstance(port, int) or port < 1 or port > 65535:
            raise ConfigurationError("Invalid port number")

        # Validate clients mode
        clients = self._config.get("clients", "")
        if clients not in ClientModes:
            raise ConfigurationError(f"Invalid clients mode: {clients}. Allowed: {ClientModes}")

        # Validate key type
        key_type = self._config.get("key_type", "rsa")
        if key_type not in ["rsa", "dsa"]:
            raise ConfigurationError(f"Invalid key type: {key_type}")

        # Validate key length
        key_length = self._config.get("key_length", DEFAULT_KEY_LENGTH)
        if key_length not in [1024, 2048, 4096]:
            raise ConfigurationError(f"Invalid key length: {key_length}")

        # Validate digest
        digest = self._config.get("digest", "sha256")
        if digest not in ["md5", "sha1", "sha256", "sha512"]:
            raise ConfigurationError(f"Invalid digest: {digest}")

        return True

    def get_company(self) -> str:
        """Get the company name."""
        return self._config.get("company", "Company Name")

    def get_domain(self) -> str:
        """Get the default domain."""
        return self._config.get("domain", "example.com")

    def get_host(self) -> str:
        """Get the listening host."""
        return self._config.get("host", "127.0.0.1")

    def get_port(self) -> int:
        """Get the listening port."""
        return self._config.get("port", 5000)

    def get_clients_mode(self) -> str:
        """Get the clients mode."""
        return self._config.get("clients", "register")

    def get_password(self) -> bytes | None:
        """Get the private key password."""
        password = self._config.get("password")
        if password:
            return password.encode("utf-8")
        return None

    def get_seed(self) -> str | None:
        """Get the RA registration seed."""
        return self._config.get("seed")

    def set_seed(self, seed: str) -> bool:
        """Set the RA registration seed."""
        return self.set("seed", seed)

    def __repr__(self) -> str:
        """Return string representation of the config."""
        return f"Config(host={self.get_host()}, port={self.get_port()})"
