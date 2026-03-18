"""
ZMQ Listener for uPKI CA Server.

This module provides the ZMQListener class that handles all
ZMQ-based CA operations.

Author: uPKI Team
License: MIT
"""

from __future__ import annotations

from typing import Any

from upki_ca.ca.authority import Authority
from upki_ca.connectors.listener import Listener
from upki_ca.core.upki_error import AuthorityError, CommunicationError
from upki_ca.core.upki_logger import UpkiLogger
from upki_ca.storage.abstract_storage import AbstractStorage
from upki_ca.utils.profiles import Profiles


class ZMQListener(Listener):
    """
    ZMQ listener for CA operations.

    Handles all CA operations via ZMQ including:
    - get_ca: Get CA certificate
    - get_crl: Get CRL
    - generate_crl: Generate new CRL
    - register: Register a new node
    - generate: Generate certificate
    - sign: Sign CSR
    - renew: Renew certificate
    - revoke: Revoke certificate
    - unrevoke: Unrevoke certificate
    - delete: Delete certificate
    - view: View certificate details
    - ocsp_check: Check OCSP status
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 5000,
        storage: AbstractStorage | None = None,
    ) -> None:
        """
        Initialize the ZMQListener.

        Args:
            host: Host to bind to
            port: Port to bind to
            storage: Storage backend
        """
        super().__init__(host, port)

        self._authority: Authority | None = None
        self._storage = storage
        self._profiles: Profiles | None = None
        self._admins: list[str] = []
        self._logger = UpkiLogger.get_logger("zmq_listener")

    def initialize_authority(self) -> bool:
        """
        Initialize the Authority.

        Returns:
            bool: True if successful
        """
        try:
            # Get Authority instance
            self._authority = Authority.get_instance()

            # Initialize Authority
            if not self._authority.is_initialized:
                self._authority.initialize(storage=self._storage)

            # Load profiles
            self._profiles = self._authority.profiles

            # Load admins
            self._admins = self._authority.list_admins()

            return True
        except Exception as e:
            raise AuthorityError(f"Failed to initialize Authority: {e}") from e

    def _handle_task(self, task: str, params: dict[str, Any]) -> Any:
        """
        Handle a specific task.

        Args:
            task: Task name
            params: Task parameters

        Returns:
            Any: Task result
        """
        handlers = {
            "get_ca": self._upki_get_ca,
            "get_crl": self._upki_get_crl,
            "generate_crl": self._upki_generate_crl,
            "register": self._upki_register,
            "generate": self._upki_generate,
            "sign": self._upki_sign,
            "renew": self._upki_renew,
            "revoke": self._upki_revoke,
            "unrevoke": self._upki_unrevoke,
            "delete": self._upki_delete,
            "view": self._upki_view,
            "ocsp_check": self._upki_ocsp_check,
            "list_profiles": self._upki_list_profiles,
            "get_profile": self._upki_get_profile,
            "list_admins": self._upki_list_admins,
            "add_admin": self._upki_add_admin,
            "remove_admin": self._upki_remove_admin,
        }

        handler = handlers.get(task)
        if handler is None:
            raise CommunicationError(f"Unknown task: {task}")

        return handler(params)

    # Admin Management

    def _upki_list_admins(self, params: dict[str, Any]) -> list[str]:
        """List all administrators."""
        return self._admins

    def _upki_add_admin(self, params: dict[str, Any]) -> bool:
        """Add an administrator."""
        dn = params.get("dn", "")
        if not dn:
            raise CommunicationError("Missing dn parameter")

        if self._authority:
            return self._authority.add_admin(dn)

        # Also add to local list
        if dn not in self._admins:
            self._admins.append(dn)
        return True

    def _upki_remove_admin(self, params: dict[str, Any]) -> bool:
        """Remove an administrator."""
        dn = params.get("dn", "")
        if not dn:
            raise CommunicationError("Missing dn parameter")

        if self._authority:
            return self._authority.remove_admin(dn)

        # Also remove from local list
        if dn in self._admins:
            self._admins.remove(dn)
        return True

    # Profile Management

    def _upki_list_profiles(self, params: dict[str, Any]) -> list[str]:
        """List all profiles."""
        if self._profiles:
            return self._profiles.list()
        return []

    def _upki_get_profile(self, params: dict[str, Any]) -> dict[str, Any]:
        """Get a profile."""
        name = params.get("profile", "")
        if not name:
            raise CommunicationError("Missing profile parameter")

        if self._profiles:
            return self._profiles.get(name)
        raise CommunicationError("Profiles not initialized")

    # CA Operations

    def _upki_get_ca(self, params: dict[str, Any]) -> str:
        """Get CA certificate."""
        if not self._authority:
            raise AuthorityError("Authority not initialized")

        return self._authority.get_ca_certificate()

    def _upki_get_crl(self, params: dict[str, Any]) -> str:
        """Get CRL."""
        if not self._authority:
            raise AuthorityError("Authority not initialized")

        crl = self._authority.get_crl()
        if crl:
            # Return as base64
            import base64

            return base64.b64encode(crl).decode("utf-8")
        return ""

    def _upki_generate_crl(self, params: dict[str, Any]) -> str:
        """Generate new CRL."""
        if not self._authority:
            raise AuthorityError("Authority not initialized")

        crl = self._authority.generate_crl()
        # Return as base64
        import base64

        return base64.b64encode(crl).decode("utf-8")

    # Node Registration

    def _upki_register(self, params: dict[str, Any]) -> dict[str, Any]:
        """Register a new node."""
        seed = params.get("seed", "")
        cn = params.get("cn", "")
        profile = params.get("profile", "server")
        sans = params.get("sans", [])

        if not seed:
            raise CommunicationError("Missing seed parameter")

        if not cn:
            raise CommunicationError("Missing cn parameter")

        if not self._authority:
            raise AuthorityError("Authority not initialized")

        # Generate certificate
        cert = self._authority.generate_certificate(cn=cn, profile_name=profile, sans=sans)

        return {
            "dn": f"/CN={cn}",
            "certificate": cert.export(),
            "serial": cert.serial_number,
        }

    # Certificate Generation

    def _upki_generate(self, params: dict[str, Any]) -> dict[str, Any]:
        """Generate a certificate."""
        cn = params.get("cn", "")
        profile = params.get("profile", "server")
        sans = params.get("sans", [])
        local = params.get("local", True)

        if not cn:
            raise CommunicationError("Missing cn parameter")

        if not self._authority:
            raise AuthorityError("Authority not initialized")

        # Generate certificate
        cert = self._authority.generate_certificate(cn=cn, profile_name=profile, sans=sans)

        result = {
            "dn": f"/CN={cn}",
            "certificate": cert.export(),
            "serial": cert.serial_number,
        }

        # Optionally include private key
        if local and self._authority.ca_key:
            pass

            # Note: For local generation, we'd need to generate a key first
            # This is a simplified implementation

        return result

    # CSR Signing

    def _upki_sign(self, params: dict[str, Any]) -> dict[str, Any]:
        """Sign a CSR."""
        csr = params.get("csr", "")
        profile = params.get("profile", "server")

        if not csr:
            raise CommunicationError("Missing csr parameter")

        if not self._authority:
            raise AuthorityError("Authority not initialized")

        # Sign CSR
        cert = self._authority.sign_csr(csr_pem=csr, profile_name=profile)

        return {"certificate": cert.export(), "serial": cert.serial_number}

    # Certificate Renewal

    def _upki_renew(self, params: dict[str, Any]) -> dict[str, Any]:
        """Renew a certificate."""
        dn = params.get("dn", "")
        duration = params.get("duration")

        if not dn:
            raise CommunicationError("Missing dn parameter")

        if not self._authority:
            raise AuthorityError("Authority not initialized")

        # Renew certificate
        cert, serial = self._authority.renew_certificate(dn, duration)

        return {"certificate": cert.export(), "serial": serial}

    # Certificate Revocation

    def _upki_revoke(self, params: dict[str, Any]) -> bool:
        """Revoke a certificate."""
        dn = params.get("dn", "")
        reason = params.get("reason", "unspecified")

        if not dn:
            raise CommunicationError("Missing dn parameter")

        if not self._authority:
            raise AuthorityError("Authority not initialized")

        return self._authority.revoke_certificate(dn, reason)

    def _upki_unrevoke(self, params: dict[str, Any]) -> bool:
        """Unrevoke a certificate."""
        dn = params.get("dn", "")

        if not dn:
            raise CommunicationError("Missing dn parameter")

        if not self._authority:
            raise AuthorityError("Authority not initialized")

        return self._authority.unrevoke_certificate(dn)

    # Certificate Deletion

    def _upki_delete(self, params: dict[str, Any]) -> bool:
        """Delete a certificate."""
        dn = params.get("dn", "")

        if not dn:
            raise CommunicationError("Missing dn parameter")

        if not self._authority:
            raise AuthorityError("Authority not initialized")

        return self._authority.delete_certificate(dn)

    # Certificate Viewing

    def _upki_view(self, params: dict[str, Any]) -> dict[str, Any]:
        """View certificate details."""
        dn = params.get("dn", "")

        if not dn:
            raise CommunicationError("Missing dn parameter")

        if not self._authority:
            raise AuthorityError("Authority not initialized")

        return self._authority.view_certificate(dn)

    # OCSP Check

    def _upki_ocsp_check(self, params: dict[str, Any]) -> dict[str, Any]:
        """Check OCSP status."""
        cert_pem = params.get("cert", "")

        if not cert_pem:
            raise CommunicationError("Missing cert parameter")

        if not self._authority:
            raise AuthorityError("Authority not initialized")

        # Get CA certificate
        ca_cert = self._authority.get_ca_certificate()

        return self._authority.ocsp_check(cert_pem, ca_cert)
