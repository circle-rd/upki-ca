# -*- coding:utf-8 -*-

"""
Abstract storage base class for uPKI.

This module defines the AbstractStorage class which provides the interface
for all storage backends (file, MongoDB, etc.).
"""

from abc import abstractmethod
from typing import Any

import upkica
from upkica.core.common import Common
from upkica.core.upkiLogger import UpkiLogger


class AbstractStorage(Common):
    """Abstract storage base class.

    Defines the interface that all storage implementations must follow.
    Provides common functionality and defines abstract methods that
    subclasses must implement.

    Attributes:
        _logger: Logger instance for output.

    Args:
        logger: UpkiLogger instance for logging.

    Raises:
        Exception: If initialization fails.
    """

    def __init__(self, logger: UpkiLogger) -> None:
        """Initialize AbstractStorage.

        Args:
            logger: UpkiLogger instance for logging.

        Raises:
            Exception: If initialization fails.
        """
        try:
            super().__init__(logger)
        except Exception as err:
            raise Exception(err)

    @abstractmethod
    def _is_initialized(self) -> bool:
        """Check if storage is initialized.

        Returns:
            True if storage is initialized, False otherwise.
        """
        raise NotImplementedError()

    @abstractmethod
    def initialize(self) -> bool:
        """Initialize storage backend.

        Returns:
            True if initialization successful.

        Raises:
            NotImplementedError: Must be implemented by subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def connect(self) -> bool:
        """Connect to storage backend.

        Returns:
            True if connection successful.

        Raises:
            NotImplementedError: Must be implemented by subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def serial_exists(self, serial: int) -> bool:
        """Check if serial number exists in storage.

        Args:
            serial: Certificate serial number to check.

        Returns:
            True if serial exists, False otherwise.

        Raises:
            NotImplementedError: Must be implemented by subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def store_key(
        self,
        pkey: bytes,
        nodename: str,
        ca: bool = False,
        encoding: str = "PEM",
    ) -> str:
        """Store private key in storage.

        Args:
            pkey: Private key bytes to store.
            nodename: Name identifier for the key.
            ca: Whether this is a CA key (default: False).
            encoding: Key encoding format (default: "PEM").

        Returns:
            Path where key was stored.

        Raises:
            NotImplementedError: Must be implemented by subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def store_request(
        self,
        req: bytes,
        nodename: str,
        ca: bool = False,
        encoding: str = "PEM",
    ) -> str:
        """Store certificate request in storage.

        Args:
            req: Certificate request bytes to store.
            nodename: Name identifier for the request.
            ca: Whether this is a CA request (default: False).
            encoding: Request encoding format (default: "PEM").

        Returns:
            Path where request was stored.

        Raises:
            NotImplementedError: Must be implemented by subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def delete_request(
        self,
        nodename: str,
        ca: bool = False,
        encoding: str = "PEM",
    ) -> bool:
        """Delete certificate request from storage.

        Args:
            nodename: Name identifier for the request.
            ca: Whether this is a CA request (default: False).
            encoding: Request encoding format (default: "PEM").

        Returns:
            True if deletion successful.

        Raises:
            NotImplementedError: Must be implemented by subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def store_public(
        self,
        crt: bytes,
        nodename: str,
        ca: bool = False,
        encoding: str = "PEM",
    ) -> str:
        """Store public certificate in storage.

        Args:
            crt: Certificate bytes to store.
            nodename: Name identifier for the certificate.
            ca: Whether this is a CA certificate (default: False).
            encoding: Certificate encoding format (default: "PEM").

        Returns:
            Path where certificate was stored.

        Raises:
            NotImplementedError: Must be implemented by subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def download_public(self, nodename: str, encoding: str = "PEM") -> str:
        """Download public certificate from storage.

        Args:
            nodename: Name identifier for the certificate.
            encoding: Certificate encoding format (default: "PEM").

        Returns:
            Certificate data as string.

        Raises:
            NotImplementedError: Must be implemented by subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def delete_public(
        self,
        nodename: str,
        ca: bool = False,
        encoding: str = "PEM",
    ) -> bool:
        """Delete public certificate from storage.

        Args:
            nodename: Name identifier for the certificate.
            ca: Whether this is a CA certificate (default: False).
            encoding: Certificate encoding format (default: "PEM").

        Returns:
            True if deletion successful.

        Raises:
            NotImplementedError: Must be implemented by subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def store_crl(self, crl_pem: Any) -> bool:
        """Store CRL in storage.

        Args:
            crl_pem: CRL bytes to store (PEM encoded).

        Returns:
            True if storage successful.

        Raises:
            NotImplementedError: Must be implemented by subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def terminate(self) -> bool:
        """Terminate and clean up storage.

        Returns:
            True if termination successful.

        Raises:
            NotImplementedError: Must be implemented by subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def exists(
        self, name: str, profile: str | None = None, uid: int | None = None
    ) -> bool:
        """Check if node exists in storage.

        Args:
            name: DN (if profile is None) or CN (if profile is set).
            profile: Optional profile name.
            uid: Optional document ID.

        Returns:
            True if node exists, False otherwise.

        Raises:
            NotImplementedError: Must be implemented by subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def get_ca(self) -> str | None:
        """Get CA certificate information.

        Returns:
            Dictionary with CA certificate data or None if not found.

        Raises:
            NotImplementedError: Must be implemented by subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def get_crl(self) -> str | None:
        """Get CRL information.

        Returns:
            Dictionary with CRL data or None if not found.

        Raises:
            NotImplementedError: Must be implemented by subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def register_node(
        self,
        dn: str,
        profile_name: str,
        profile_data: dict,
        sans: list | None = None,
        keyType: str | None = None,
        keyLen: int | None = None,
        digest: str | None = None,
        duration: int | None = None,
        local: bool = False,
    ) -> dict:
        """Register a new node in storage.

        Args:
            dn: Distinguished Name.
            profile_name: Profile name to use.
            profile_data: Profile configuration data.
            sans: Optional list of Subject Alternative Names.
            keyType: Optional key type override.
            bits: Optional key size override.
            digest: Optional digest algorithm override.
            duration: Optional validity duration override.
            local: Whether this is a local node (default: False).

        Returns:
            Dictionary with registered node information.

        Raises:
            NotImplementedError: Must be implemented by subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def get_node(
        self,
        name: str,
        profile: str | None = None,
        uid: int | None = None,
    ) -> dict | None:
        """Get node information from storage.

        Args:
            name: DN or CN of the node.
            profile: Optional profile name filter.
            uid: Optional document ID.

        Returns:
            Dictionary with node data or None if not found.

        Raises:
            NotImplementedError: Must be implemented by subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def list_nodes(self) -> list:
        """List all nodes in storage.

        Returns:
            List of node dictionaries.

        Raises:
            NotImplementedError: Must be implemented by subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def get_revoked(self) -> list:
        """Get list of revoked certificates.

        Returns:
            List of revoked certificate dictionaries.

        Raises:
            NotImplementedError: Must be implemented by subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def activate_node(self, dn: str) -> bool:
        """Activate a pending node.

        Args:
            dn: Distinguished Name of node to activate.

        Returns:
            True if activation successful.

        Raises:
            NotImplementedError: Must be implemented by subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def certify_node(self, dn: Any, cert: Any, internal: bool = False) -> bool:
        """Certify a node with a certificate.

        Args:
            dn: Distinguished Name of the node.
            cert: Certificate object to use for certification.
            internal: Whether this is an internal certification (default: False).

        Returns:
            True if certification successful.

        Raises:
            NotImplementedError: Must be implemented by subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def expire_node(self, dn: str) -> bool:
        """Mark a node as expired.

        Args:
            dn: Distinguished Name of node to expire.

        Returns:
            True if expiration successful.

        Raises:
            NotImplementedError: Must be implemented by subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def renew_node(
        self,
        serial: int,
        dn: str,
        cert: object,
    ) -> bool:
        """Renew a node's certificate.

        Args:
            serial: Old certificate serial number.
            dn: Distinguished Name of node to renew.
            cert: New certificate object.

        Returns:
            True if renewal successful.

        Raises:
            NotImplementedError: Must be implemented by subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def revoke_node(
        self,
        dn: str,
        reason: str = "unspecified",
    ) -> bool:
        """Revoke a node's certificate.

        Args:
            dn: Distinguished Name of node to revoke.
            reason: Revocation reason (default: "unspecified").

        Returns:
            True if revocation successful.

        Raises:
            NotImplementedError: Must be implemented by subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def unrevoke_node(self, dn: str) -> bool:
        """Unrevoke a node's certificate.

        Args:
            dn: Distinguished Name of node to unrevoke.

        Returns:
            True if unrevocation successful.

        Raises:
            NotImplementedError: Must be implemented by subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def delete_node(self, dn: str, serial: int) -> bool:
        """Delete a node from storage.

        Args:
            dn: Distinguished Name of node to delete.
            serial: Certificate serial number.

        Returns:
            True if deletion successful.

        Raises:
            NotImplementedError: Must be implemented by subclass.
        """
        raise NotImplementedError()
