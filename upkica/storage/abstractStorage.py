"""
Abstract Storage Interface for uPKI CA Server.

This module defines the AbstractStorage interface that all storage
backends must implement.

Author: uPKI Team
License: MIT
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class AbstractStorage(ABC):
    """
    Abstract base class defining the storage interface.

    All storage backends must implement this interface to provide
    consistent storage operations for certificates, keys, CSRs, and profiles.
    """

    @abstractmethod
    def initialize(self) -> bool:
        """
        Initialize the storage backend.

        Returns:
            bool: True if initialization successful
        """
        pass

    @abstractmethod
    def connect(self) -> bool:
        """
        Connect to the storage backend.

        Returns:
            bool: True if connection successful
        """
        pass

    @abstractmethod
    def disconnect(self) -> bool:
        """
        Disconnect from the storage backend.

        Returns:
            bool: True if disconnection successful
        """
        pass

    # Serial Number Operations

    @abstractmethod
    def serial_exists(self, serial: int) -> bool:
        """
        Check if a serial number exists in storage.

        Args:
            serial: Certificate serial number

        Returns:
            bool: True if serial exists
        """
        pass

    @abstractmethod
    def store_serial(self, serial: int, dn: str) -> bool:
        """
        Store a serial number with its DN.

        Args:
            serial: Certificate serial number
            dn: Distinguished Name

        Returns:
            bool: True if successful
        """
        pass

    @abstractmethod
    def get_serial(self, serial: int) -> dict[str, Any] | None:
        """
        Get serial number information.

        Args:
            serial: Certificate serial number

        Returns:
            dict: Serial information or None if not found
        """
        pass

    # Private Key Operations

    @abstractmethod
    def store_key(self, pkey: bytes, name: str) -> bool:
        """
        Store a private key.

        Args:
            pkey: Private key data in bytes
            name: Key name (usually CN or 'ca')

        Returns:
            bool: True if successful
        """
        pass

    @abstractmethod
    def get_key(self, name: str) -> bytes | None:
        """
        Get a private key.

        Args:
            name: Key name

        Returns:
            bytes: Private key data or None if not found
        """
        pass

    @abstractmethod
    def delete_key(self, name: str) -> bool:
        """
        Delete a private key.

        Args:
            name: Key name

        Returns:
            bool: True if successful
        """
        pass

    # Certificate Operations

    @abstractmethod
    def store_cert(self, cert: bytes, name: str, serial: int) -> bool:
        """
        Store a certificate.

        Args:
            cert: Certificate data in bytes
            name: Certificate name (usually CN)
            serial: Certificate serial number

        Returns:
            bool: True if successful
        """
        pass

    @abstractmethod
    def get_cert(self, name: str) -> bytes | None:
        """
        Get a certificate by name.

        Args:
            name: Certificate name (usually CN)

        Returns:
            bytes: Certificate data or None if not found
        """
        pass

    @abstractmethod
    def get_cert_by_serial(self, serial: int) -> bytes | None:
        """
        Get a certificate by serial number.

        Args:
            serial: Certificate serial number

        Returns:
            bytes: Certificate data or None if not found
        """
        pass

    @abstractmethod
    def delete_cert(self, name: str) -> bool:
        """
        Delete a certificate.

        Args:
            name: Certificate name

        Returns:
            bool: True if successful
        """
        pass

    @abstractmethod
    def list_certs(self) -> list[str]:
        """
        List all certificates.

        Returns:
            list: List of certificate names
        """
        pass

    # CSR Operations

    @abstractmethod
    def store_csr(self, csr: bytes, name: str) -> bool:
        """
        Store a CSR.

        Args:
            csr: CSR data in bytes
            name: CSR name (usually CN)

        Returns:
            bool: True if successful
        """
        pass

    @abstractmethod
    def get_csr(self, name: str) -> bytes | None:
        """
        Get a CSR.

        Args:
            name: CSR name

        Returns:
            bytes: CSR data or None if not found
        """
        pass

    @abstractmethod
    def delete_csr(self, name: str) -> bool:
        """
        Delete a CSR.

        Args:
            name: CSR name

        Returns:
            bool: True if successful
        """
        pass

    # Node/Entity Operations

    @abstractmethod
    def exists(self, dn: str) -> bool:
        """
        Check if a DN exists in storage.

        Args:
            dn: Distinguished Name

        Returns:
            bool: True if exists
        """
        pass

    @abstractmethod
    def store_node(self, dn: str, data: dict[str, Any]) -> bool:
        """
        Store node/entity information.

        Args:
            dn: Distinguished Name
            data: Node data

        Returns:
            bool: True if successful
        """
        pass

    @abstractmethod
    def get_node(self, dn: str) -> dict[str, Any] | None:
        """
        Get node information.

        Args:
            dn: Distinguished Name

        Returns:
            dict: Node data or None if not found
        """
        pass

    @abstractmethod
    def list_nodes(self) -> list[str]:
        """
        List all nodes.

        Returns:
            list: List of node DNs
        """
        pass

    @abstractmethod
    def update_node(self, dn: str, data: dict[str, Any]) -> bool:
        """
        Update node information.

        Args:
            dn: Distinguished Name
            data: Node data to update

        Returns:
            bool: True if successful
        """
        pass

    # Profile Operations

    @abstractmethod
    def list_profiles(self) -> dict[str, dict[str, Any]]:
        """
        List all profiles.

        Returns:
            dict: Dictionary of profile names to profile data
        """
        pass

    @abstractmethod
    def store_profile(self, name: str, data: dict[str, Any]) -> bool:
        """
        Store a profile.

        Args:
            name: Profile name
            data: Profile data

        Returns:
            bool: True if successful
        """
        pass

    @abstractmethod
    def get_profile(self, name: str) -> dict[str, Any] | None:
        """
        Get a profile.

        Args:
            name: Profile name

        Returns:
            dict: Profile data or None if not found
        """
        pass

    @abstractmethod
    def delete_profile(self, name: str) -> bool:
        """
        Delete a profile.

        Args:
            name: Profile name

        Returns:
            bool: True if successful
        """
        pass

    # Admin Operations

    @abstractmethod
    def list_admins(self) -> list[str]:
        """
        List all administrators.

        Returns:
            list: List of admin DNs
        """
        pass

    @abstractmethod
    def add_admin(self, dn: str) -> bool:
        """
        Add an administrator.

        Args:
            dn: Admin DN

        Returns:
            bool: True if successful
        """
        pass

    @abstractmethod
    def remove_admin(self, dn: str) -> bool:
        """
        Remove an administrator.

        Args:
            dn: Admin DN

        Returns:
            bool: True if successful
        """
        pass

    # CRL Operations

    @abstractmethod
    def store_crl(self, name: str, crl: bytes) -> bool:
        """
        Store a CRL.

        Args:
            name: CRL name (usually 'ca')
            crl: CRL data in DER format

        Returns:
            bool: True if successful
        """
        pass

    @abstractmethod
    def get_crl(self, name: str) -> bytes | None:
        """
        Get a CRL.

        Args:
            name: CRL name

        Returns:
            bytes: CRL data in DER format or None if not found
        """
        pass
