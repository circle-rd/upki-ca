"""
File-based storage implementation for uPKI CA Server.

This module provides the FileStorage class that stores certificates,
keys, CSRs, and profiles using the filesystem and TinyDB.

Author: uPKI Team
License: MIT
"""

from __future__ import annotations

import os
from typing import Any, cast

import yaml
from tinydb import Query, TinyDB

from upki_ca.core.common import Common
from upki_ca.core.upki_error import StorageError
from upki_ca.storage.abstract_storage import AbstractStorage


class FileStorage(AbstractStorage, Common):
    """
    File-based storage using TinyDB and filesystem.

    Storage Structure:
        ~/.upki/ca/
        ├── .serials.json          # Serial number database
        ├── .nodes.json            # Node/certificate database
        ├── .admins.json           # Admin database
        ├── ca.config.yml          # Configuration
        ├── ca.key                 # CA private key (PEM)
        ├── ca.crt                 # CA certificate (PEM)
        ├── profiles/              # Certificate profiles
        │   ├── ca.yml
        │   ├── ra.yml
        │   ├── server.yml
        │   └── user.yml
        ├── certs/                 # Issued certificates
        ├── reqs/                  # Certificate requests
        └── private/              # Private keys
    """

    def __init__(self, base_path: str | None = None) -> None:
        """
        Initialize FileStorage.

        Args:
            base_path: Base path for storage (defaults to ~/.upki/ca)
        """
        if base_path:
            self._base_path = base_path
        else:
            self._base_path = self.get_ca_dir()

        # Database files
        self._serials_db: TinyDB | None = None
        self._nodes_db: TinyDB | None = None
        self._admins_db: TinyDB | None = None

        # Directory paths
        self._certs_dir = os.path.join(self._base_path, "certs")
        self._reqs_dir = os.path.join(self._base_path, "reqs")
        self._private_dir = os.path.join(self._base_path, "private")
        self._profiles_dir = os.path.join(self._base_path, "profiles")

    @property
    def base_path(self) -> str:
        """Get the base path."""
        return self._base_path

    def _get_cn(self, dn: str) -> str:
        """
        Extract CN from DN.

        Args:
            dn: Distinguished Name

        Returns:
            str: Common Name
        """
        # Parse DN and extract CN
        parts = dn.split("/")
        for part in parts:
            if "=" in part:
                key, value = part.split("=", 1)
                if key.strip() == "CN":
                    return value.strip()
        return dn

    def _mkdir_p(self, path: str) -> bool:
        """
        Create directory and parents if they don't exist.

        Args:
            path: Directory path

        Returns:
            bool: True if successful
        """
        try:
            os.makedirs(path, exist_ok=True)
            return True
        except OSError as e:
            raise StorageError(f"Failed to create directory {path}: {e}") from e

    def _parse_yaml(self, filepath: str) -> dict[str, Any]:
        """
        Parse a YAML file.

        Args:
            filepath: Path to YAML file

        Returns:
            dict: Parsed YAML data
        """
        try:
            with open(filepath) as f:
                return yaml.safe_load(f) or {}
        except FileNotFoundError:
            return {}
        except Exception as e:
            raise StorageError(f"Failed to parse YAML {filepath}: {e}") from e

    def _store_yaml(self, filepath: str, data: dict[str, Any]) -> bool:
        """
        Store data to a YAML file.

        Args:
            filepath: Path to YAML file
            data: Data to store

        Returns:
            bool: True if successful
        """
        try:
            self._mkdir_p(os.path.dirname(filepath))
            with open(filepath, "w") as f:
                yaml.safe_dump(data, f, default_flow_style=False)
            return True
        except Exception as e:
            raise StorageError(f"Failed to store YAML {filepath}: {e}") from e

    def initialize(self) -> bool:
        """
        Initialize the storage.

        Returns:
            bool: True if successful
        """
        try:
            # Create base directory
            self._mkdir_p(self._base_path)

            # Create subdirectories
            self._mkdir_p(self._certs_dir)
            self._mkdir_p(self._reqs_dir)
            self._mkdir_p(self._private_dir)
            self._mkdir_p(self._profiles_dir)

            # Initialize TinyDB databases
            self._serials_db = TinyDB(os.path.join(self._base_path, ".serials.json"))
            self._nodes_db = TinyDB(os.path.join(self._base_path, ".nodes.json"))
            self._admins_db = TinyDB(os.path.join(self._base_path, ".admins.json"))

            return True
        except Exception as e:
            raise StorageError(f"Failed to initialize storage: {e}") from e

    def connect(self) -> bool:
        """
        Connect to storage.

        Returns:
            bool: True if successful
        """
        # For file storage, this is the same as initialize
        if self._serials_db is None:
            return self.initialize()
        return True

    def disconnect(self) -> bool:
        """
        Disconnect from storage.

        Returns:
            bool: True if successful
        """
        # Close TinyDB databases
        if self._serials_db:
            self._serials_db.close()
        if self._nodes_db:
            self._nodes_db.close()
        if self._admins_db:
            self._admins_db.close()

        self._serials_db = None
        self._nodes_db = None
        self._admins_db = None

        return True

    # Serial Number Operations

    def serial_exists(self, serial: int) -> bool:
        """Check if a serial number exists."""
        if self._serials_db is None:
            raise StorageError("Database not initialized")

        serials = Query()
        return self._serials_db.contains(serials.serial == serial)

    def store_serial(self, serial: int, dn: str) -> bool:
        """Store a serial number."""
        if self._serials_db is None:
            raise StorageError("Database not initialized")

        self._serials_db.insert({"serial": serial, "dn": dn, "revoked": False, "revoke_reason": ""})
        return True

    def get_serial(self, serial: int) -> dict[str, Any] | None:
        """Get serial information."""
        if self._serials_db is None:
            raise StorageError("Database not initialized")

        serials = Query()
        result = self._serials_db.get(serials.serial == serial)
        return cast(dict[str, Any] | None, result if result else None)

    # Private Key Operations

    def store_key(self, pkey: bytes, name: str) -> bool:
        """Store a private key."""
        try:
            key_path = os.path.join(self._private_dir, f"{name}.key")
            with open(key_path, "wb") as f:
                f.write(pkey)

            # Set restrictive permissions
            os.chmod(key_path, 0o600)
            return True
        except Exception as e:
            raise StorageError(f"Failed to store key: {e}") from e

    def get_key(self, name: str) -> bytes | None:
        """Get a private key."""
        try:
            key_path = os.path.join(self._private_dir, f"{name}.key")
            if os.path.exists(key_path):
                with open(key_path, "rb") as f:
                    return f.read()
            return None
        except Exception as e:
            raise StorageError(f"Failed to get key: {e}") from e

    def delete_key(self, name: str) -> bool:
        """Delete a private key."""
        try:
            key_path = os.path.join(self._private_dir, f"{name}.key")
            if os.path.exists(key_path):
                os.remove(key_path)
            return True
        except Exception as e:
            raise StorageError(f"Failed to delete key: {e}") from e

    # Certificate Operations

    def store_cert(self, cert: bytes, name: str, serial: int) -> bool:
        """Store a certificate."""
        try:
            # Save certificate file
            cert_path = os.path.join(self._certs_dir, f"{name}.crt")
            with open(cert_path, "wb") as f:
                f.write(cert)

            # Update nodes database
            if self._nodes_db:
                nodes = Query()
                node_data = {
                    "dn": name if "/" in name else f"/CN={name}",
                    "cn": name,
                    "serial": serial,
                    "state": "issued",
                }

                # Update or insert
                if self._nodes_db.contains(nodes.cn == name):
                    self._nodes_db.update(node_data, nodes.cn == name)
                else:
                    self._nodes_db.insert(node_data)

            # Store serial number
            self.store_serial(serial, name)

            return True
        except Exception as e:
            raise StorageError(f"Failed to store certificate: {e}") from e

    def get_cert(self, name: str) -> bytes | None:
        """Get a certificate by name."""
        try:
            cert_path = os.path.join(self._certs_dir, f"{name}.crt")
            if os.path.exists(cert_path):
                with open(cert_path, "rb") as f:
                    return f.read()
            return None
        except Exception as e:
            raise StorageError(f"Failed to get certificate: {e}") from e

    def get_cert_by_serial(self, serial: int) -> bytes | None:
        """Get a certificate by serial number."""
        # Find certificate by serial in nodes database
        if self._nodes_db:
            nodes = Query()
            result = self._nodes_db.get(nodes.serial == serial)
            if result and isinstance(result, dict):
                return self.get_cert(result.get("cn", ""))
        return None

    def delete_cert(self, name: str) -> bool:
        """Delete a certificate."""
        try:
            cert_path = os.path.join(self._certs_dir, f"{name}.crt")
            if os.path.exists(cert_path):
                os.remove(cert_path)

            # Update nodes database
            if self._nodes_db:
                nodes = Query()
                self._nodes_db.remove(nodes.cn == name)

            return True
        except Exception as e:
            raise StorageError(f"Failed to delete certificate: {e}") from e

    def list_certs(self) -> list[str]:
        """List all certificates."""
        try:
            certs = []
            for filename in os.listdir(self._certs_dir):
                if filename.endswith(".crt"):
                    certs.append(filename[:-4])  # Remove .crt extension
            return certs
        except Exception as e:
            raise StorageError(f"Failed to list certificates: {e}") from e

    # CSR Operations

    def store_csr(self, csr: bytes, name: str) -> bool:
        """Store a CSR."""
        try:
            csr_path = os.path.join(self._reqs_dir, f"{name}.csr")
            with open(csr_path, "wb") as f:
                f.write(csr)
            return True
        except Exception as e:
            raise StorageError(f"Failed to store CSR: {e}") from e

    def get_csr(self, name: str) -> bytes | None:
        """Get a CSR."""
        try:
            csr_path = os.path.join(self._reqs_dir, f"{name}.csr")
            if os.path.exists(csr_path):
                with open(csr_path, "rb") as f:
                    return f.read()
            return None
        except Exception as e:
            raise StorageError(f"Failed to get CSR: {e}") from e

    def delete_csr(self, name: str) -> bool:
        """Delete a CSR."""
        try:
            csr_path = os.path.join(self._reqs_dir, f"{name}.csr")
            if os.path.exists(csr_path):
                os.remove(csr_path)
            return True
        except Exception as e:
            raise StorageError(f"Failed to delete CSR: {e}") from e

    # Node Operations

    def exists(self, dn: str) -> bool:
        """Check if a DN exists."""
        if self._nodes_db is None:
            raise StorageError("Database not initialized")

        nodes = Query()
        cn = self._get_cn(dn)
        return self._nodes_db.contains(nodes.cn == cn)

    def store_node(self, dn: str, data: dict[str, Any]) -> bool:
        """Store node information."""
        if self._nodes_db is None:
            raise StorageError("Database not initialized")

        cn = self._get_cn(dn)
        node_data = {"dn": dn, "cn": cn, **data}

        nodes = Query()
        if self._nodes_db.contains(nodes.cn == cn):
            self._nodes_db.update(node_data, nodes.cn == cn)
        else:
            self._nodes_db.insert(node_data)

        return True

    def get_node(self, dn: str) -> dict[str, Any] | None:
        """Get node information."""
        if self._nodes_db is None:
            raise StorageError("Database not initialized")

        cn = self._get_cn(dn)
        nodes = Query()
        return cast(dict[str, Any] | None, self._nodes_db.get(nodes.cn == cn))

    def list_nodes(self) -> list[str]:
        """List all nodes."""
        if self._nodes_db is None:
            raise StorageError("Database not initialized")

        return [node["cn"] for node in self._nodes_db.all()]

    def update_node(self, dn: str, data: dict[str, Any]) -> bool:
        """Update node information."""
        if self._nodes_db is None:
            raise StorageError("Database not initialized")

        cn = self._get_cn(dn)
        nodes = Query()

        if self._nodes_db.contains(nodes.cn == cn):
            self._nodes_db.update(data, nodes.cn == cn)
            return True
        return False

    # Profile Operations

    def list_profiles(self) -> dict[str, dict[str, Any]]:
        """List all profiles."""
        profiles = {}

        try:
            for filename in os.listdir(self._profiles_dir):
                if filename.endswith(".yml") or filename.endswith(".yaml"):
                    profile_name = filename.rsplit(".", 1)[0]
                    profile_path = os.path.join(self._profiles_dir, filename)
                    profiles[profile_name] = self._parse_yaml(profile_path)
        except Exception as e:
            raise StorageError(f"Failed to list profiles: {e}") from e

        return profiles

    def store_profile(self, name: str, data: dict[str, Any]) -> bool:
        """Store a profile."""
        try:
            profile_path = os.path.join(self._profiles_dir, f"{name}.yml")
            return self._store_yaml(profile_path, data)
        except Exception as e:
            raise StorageError(f"Failed to store profile: {e}") from e

    def get_profile(self, name: str) -> dict[str, Any] | None:
        """Get a profile."""
        try:
            profile_path = os.path.join(self._profiles_dir, f"{name}.yml")
            if os.path.exists(profile_path):
                return self._parse_yaml(profile_path)
            return None
        except Exception as e:
            raise StorageError(f"Failed to get profile: {e}") from e

    def delete_profile(self, name: str) -> bool:
        """Delete a profile."""
        try:
            profile_path = os.path.join(self._profiles_dir, f"{name}.yml")
            if os.path.exists(profile_path):
                os.remove(profile_path)
            return True
        except Exception as e:
            raise StorageError(f"Failed to delete profile: {e}") from e

    # Admin Operations

    def list_admins(self) -> list[str]:
        """List all administrators."""
        if self._admins_db is None:
            raise StorageError("Database not initialized")

        return [admin["dn"] for admin in self._admins_db.all()]

    def add_admin(self, dn: str) -> bool:
        """Add an administrator."""
        if self._admins_db is None:
            raise StorageError("Database not initialized")

        self._admins_db.insert({"dn": dn})
        return True

    def remove_admin(self, dn: str) -> bool:
        """Remove an administrator."""
        if self._admins_db is None:
            raise StorageError("Database not initialized")

        admins = Query()
        self._admins_db.remove(admins.dn == dn)
        return True

    # CRL Operations

    def store_crl(self, name: str, crl: bytes) -> bool:
        """
        Store a CRL.

        Args:
            name: CRL name (usually 'ca')
            crl: CRL data in DER format

        Returns:
            bool: True if successful
        """
        try:
            crl_dir = os.path.join(self._base_path, "crls")
            self._mkdir_p(crl_dir)
            crl_path = os.path.join(crl_dir, f"{name}.crl")
            with open(crl_path, "wb") as f:
                f.write(crl)
            return True
        except Exception as e:
            raise StorageError(f"Failed to store CRL: {e}") from e

    def get_crl(self, name: str) -> bytes | None:
        """
        Get a CRL.

        Args:
            name: CRL name

        Returns:
            bytes: CRL data in DER format or None if not found
        """
        try:
            crl_path = os.path.join(self._base_path, "crls", f"{name}.crl")
            if os.path.exists(crl_path):
                with open(crl_path, "rb") as f:
                    return f.read()
            return None
        except Exception as e:
            raise StorageError(f"Failed to get CRL: {e}") from e
