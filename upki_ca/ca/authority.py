"""
Main CA Authority class for uPKI CA Server.

This module provides the Authority class which handles all PKI operations
including certificate issuance, RA management, and certificate lifecycle.

Author: uPKI Team
License: MIT
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization

from upki_ca.ca.cert_request import CertRequest
from upki_ca.ca.private_key import PrivateKey
from upki_ca.ca.public_cert import PublicCert
from upki_ca.core.common import Common
from upki_ca.core.options import (
    BUILTIN_PROFILES,
    DEFAULT_DURATION,
)
from upki_ca.core.upki_error import (
    AuthorityError,
    CertificateError,
    ProfileError,
)
from upki_ca.core.upki_logger import UpkiLogger, UpkiLoggerAdapter
from upki_ca.storage.abstract_storage import AbstractStorage
from upki_ca.utils.profiles import Profiles


class Authority(Common):
    """
    Main CA class for handling PKI operations.

    Responsibilities:
    - CA keychain generation/import
    - Certificate issuance
    - RA registration server management
    - CRL and OCSP support
    """

    # Singleton instance
    _instance: Authority | None = None

    def __init__(self) -> None:
        """Initialize an Authority instance."""
        self._initialized = False
        self._storage: AbstractStorage | None = None
        self._ca_key: PrivateKey | None = None
        self._ca_cert: PublicCert | None = None
        self._profiles: Profiles | None = None
        self._logger: UpkiLoggerAdapter = UpkiLogger.get_logger("authority")

        # CRL state
        self._crl: list[dict[str, Any]] = []
        self._crl_last_update: datetime | None = None

    @classmethod
    def get_instance(cls) -> Authority:
        """
        Get the singleton Authority instance.

        Returns:
            Authority: The Authority instance
        """
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton instance."""
        cls._instance = None

    @property
    def is_initialized(self) -> bool:
        """Check if the Authority is initialized."""
        return self._initialized

    @property
    def ca_cert(self) -> PublicCert | None:
        """Get the CA certificate."""
        return self._ca_cert

    @property
    def ca_key(self) -> PrivateKey | None:
        """Get the CA private key."""
        return self._ca_key

    @property
    def storage(self) -> AbstractStorage | None:
        """Get the storage backend."""
        return self._storage

    @property
    def profiles(self) -> Profiles | None:
        """Get the profiles manager."""
        return self._profiles

    def initialize(
        self,
        keychain: str | None = None,
        storage: AbstractStorage | None = None,
        import_key: str | None = None,
        import_cert: str | None = None,
        import_password: bytes | None = None,
    ) -> bool:
        """
        Initialize the CA Authority.

        Args:
            keychain: Path to CA keychain directory or None for default
            storage: Storage backend to use
            import_key: Path to an existing CA private key (PEM) to import.
            import_cert: Path to an existing CA certificate (PEM) to import.
            import_password: Optional password to decrypt the imported CA private key.

        Returns:
            bool: True if initialization successful

        Raises:
            AuthorityError: If initialization fails
        """
        try:
            self._logger.info("Initializing Authority...")

            # Set up storage
            if storage is not None:
                self._storage = storage
            else:
                from upki_ca.storage.file_storage import FileStorage

                self._storage = FileStorage()

            # Initialize storage
            if not self._storage.initialize():
                raise AuthorityError("Failed to initialize storage")

            # Connect to storage
            if not self._storage.connect():
                raise AuthorityError("Failed to connect to storage")

            # Initialize profiles and load defaults + any stored overrides
            self._profiles = Profiles(self._storage)
            self._profiles.load()

            # Load or generate CA keychain
            dest = keychain or self.get_ca_dir()
            if import_key and import_cert:
                self._import_keychain(import_key, import_cert, dest, import_password)
            else:
                self._load_keychain(dest)

            # Load CRL from storage
            self._load_crl()

            self._initialized = True
            self._logger.info("Authority initialized successfully")

            return True

        except Exception as e:
            self._logger.error("Authority: %s", e)
            raise AuthorityError(f"Failed to initialize Authority: {e}") from e

    def load(self) -> bool:
        """
        Load the CA from storage.

        Returns:
            bool: True if loading successful
        """
        try:
            if self._storage is None:
                raise AuthorityError("Storage not initialized")

            # Load CA certificate
            ca_cert_data = self._storage.get_cert("ca")
            if ca_cert_data:
                self._ca_cert = PublicCert.load(ca_cert_data.decode("utf-8"))

            # Load CA key
            ca_key_data = self._storage.get_key("ca")
            if ca_key_data:
                self._ca_key = PrivateKey.load(ca_key_data.decode("utf-8"))

            # Load profiles
            if self._profiles:
                self._profiles.load()

            # Load CRL
            self._load_crl()

            return True

        except Exception as e:
            raise AuthorityError(f"Failed to load Authority: {e}") from e

    def _import_keychain(
        self,
        key_path: str,
        cert_path: str,
        dest_path: str,
        password: bytes | None = None,
    ) -> None:
        """
        Import an existing CA keychain from disk.

        The private key and certificate are loaded, their correspondence is
        verified, and both files are copied to the managed keychain directory
        and persisted in the storage backend.

        Args:
            key_path: Path to the CA private key file (PEM, optionally encrypted).
            cert_path: Path to the CA certificate file (PEM).
            dest_path: Destination directory where the CA files will be stored.
            password: Optional password to decrypt the private key.

        Raises:
            AuthorityError: If a file is missing, cannot be parsed, or the key
                and certificate public keys do not match.
        """
        if not os.path.exists(key_path):
            raise AuthorityError(f"CA private key file not found: {key_path}")
        if not os.path.exists(cert_path):
            raise AuthorityError(f"CA certificate file not found: {cert_path}")

        self._logger.info(f"Importing CA keychain from {key_path} and {cert_path}")

        self._ca_key = PrivateKey.load_from_file(key_path, password=password)
        self._ca_cert = PublicCert.load_from_file(cert_path)

        # Verify that the private key corresponds to the certificate's public key
        key_pub = self._ca_key.public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        cert_pub = self._ca_cert.cert.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if key_pub != cert_pub:
            raise AuthorityError(
                "CA private key and certificate do not match: their public keys differ"
            )

        # Copy to the managed keychain directory (unencrypted, consistent with _generate_ca)
        self.ensure_dir(dest_path)
        self._ca_key.export_to_file(os.path.join(dest_path, "ca.key"))
        self._ca_cert.export_to_file(os.path.join(dest_path, "ca.crt"))

        # Persist in the storage backend
        if self._storage:
            self._storage.store_key(self._ca_key.export(), "ca")
            self._storage.store_cert(
                self._ca_cert.export().encode("utf-8"),
                "ca",
                self._ca_cert.serial_number,
            )

        self._logger.info(f"CA imported successfully – subject: {self._ca_cert.subject_cn}")

    def _load_keychain(self, path: str) -> None:
        """
        Load or generate CA keychain.

        Args:
            path: Path to keychain directory
        """
        ca_key_path = os.path.join(path, "ca.key")
        ca_cert_path = os.path.join(path, "ca.crt")

        # Check if CA exists
        if os.path.exists(ca_key_path) and os.path.exists(ca_cert_path):
            self._logger.info(f"Loading existing CA from {path}")

            # Load existing CA
            self._ca_key = PrivateKey.load_from_file(ca_key_path)
            self._ca_cert = PublicCert.load_from_file(ca_cert_path)

        else:
            self._logger.info(f"Generating new CA in {path}")

            # Generate new CA
            self._generate_ca(path)

    def _generate_ca(self, path: str) -> None:
        """
        Generate a new CA certificate.

        Args:
            path: Path to save CA files
        """
        # Generate CA profile
        ca_profile = {
            "keyType": "rsa",
            "keyLen": 4096,
            "duration": 3650,  # 10 years
            "digest": "sha256",
            "subject": {"C": "FR", "O": "uPKI", "OU": "CA", "CN": "uPKI Root CA"},
            "keyUsage": ["keyCertSign", "cRLSign"],
            "extendedKeyUsage": [],
            "certType": "sslCA",
        }

        # Generate CA key
        self._ca_key = PrivateKey.generate(ca_profile)

        # Create a self-signed CA certificate
        # First create a dummy CSR for the CA
        ca_csr = CertRequest.generate(self._ca_key, "uPKI Root CA", ca_profile)

        # Generate self-signed CA certificate
        # For self-signed, use the CSR (will use subject as issuer)
        self._ca_cert = PublicCert.generate(
            ca_csr,
            None,  # type: ignore[arg-type]  # issuer_cert - handled in generate() for self_signed
            self._ca_key,
            ca_profile,
            ca=True,
            self_signed=True,
            duration=ca_profile["duration"],
            digest=ca_profile["digest"],
        )

        # Save CA key and certificate
        self.ensure_dir(path)

        # Export CA key (with encryption)
        self._ca_key.export_to_file(
            os.path.join(path, "ca.key"),
            password=None,  # No password for now
        )

        # Export CA certificate
        self._ca_cert.export_to_file(os.path.join(path, "ca.crt"))

        # Store in storage
        if self._storage:
            self._storage.store_key(self._ca_key.export(), "ca")
            self._storage.store_cert(
                self._ca_cert.export().encode("utf-8"),
                "ca",
                self._ca_cert.serial_number,
            )

        self._logger.info("CA generated successfully")

    def _load_crl(self) -> None:
        """Load CRL from storage."""
        try:
            # Try to load CRL data from storage
            if self._storage:
                crl_data = self._storage.get_crl("ca")
                if crl_data:
                    # Parse CRL and load revoked certificates
                    crl = x509.load_der_x509_crl(crl_data, default_backend())
                    for revoked in crl:
                        self._crl.append(
                            {
                                "serial": revoked.serial_number,
                                "revoke_date": revoked.revocation_date.isoformat(),
                                "reason": "unknown",  # CRL doesn't store reason
                                "dn": None,  # We'll need to look this up
                            }
                        )
                    self._crl_last_update = crl.last_update
        except Exception as e:
            self._logger.warning(f"Failed to load CRL: {e}")

    def connect_storage(self) -> bool:
        """
        Connect to the storage backend.

        Returns:
            bool: True if connection successful
        """
        if self._storage is None:
            raise AuthorityError("Storage not initialized")

        return self._storage.connect()

    # Profile Management

    def add_profile(self, name: str, data: dict) -> bool:
        """
        Add a new certificate profile.

        Args:
            name: Profile name
            data: Profile data

        Returns:
            bool: True if successful
        """
        if self._profiles is None:
            raise AuthorityError("Profiles not initialized")

        return self._profiles.add(name, data)

    def remove_profile(self, name: str) -> bool:
        """
        Remove a certificate profile.

        Args:
            name: Profile name

        Returns:
            bool: True if successful
        """
        if self._profiles is None:
            raise AuthorityError("Profiles not initialized")

        # Don't allow removing built-in profiles
        if name in BUILTIN_PROFILES:
            raise ProfileError(f"Cannot remove built-in profile: {name}")

        return self._profiles.remove(name)

    def get_profile(self, name: str) -> dict:
        """
        Get a certificate profile.

        Args:
            name: Profile name

        Returns:
            dict: Profile data
        """
        if self._profiles is None:
            raise AuthorityError("Profiles not initialized")

        return self._profiles.get(name)

    def list_profiles(self) -> list[str]:
        """
        List all available profiles.

        Returns:
            list: List of profile names
        """
        if self._profiles is None:
            raise AuthorityError("Profiles not initialized")

        return self._profiles.list()

    # Certificate Operations

    def generate_certificate(
        self,
        cn: str,
        profile_name: str,
        sans: list[dict[str, str]] | None = None,
        duration: int | None = None,
    ) -> PublicCert:
        """
        Generate a new certificate.

        Args:
            cn: Common Name
            profile_name: Profile name to use
            sans: Subject Alternative Names
            duration: Certificate validity in days

        Returns:
            PublicCert: Generated certificate
        """
        if not self._initialized:
            raise AuthorityError("Authority not initialized")

        if self._ca_cert is None or self._ca_key is None:
            raise AuthorityError("CA not loaded")

        # Get profile
        profile = self.get_profile(profile_name)

        # Generate key pair
        key = PrivateKey.generate(profile)

        # Generate CSR
        csr = CertRequest.generate(key, cn, profile, sans)

        # A certificate is a CA cert if and only if its profile grants the key-signing
        # key usage (keyCertSign).  This drives BasicConstraints(ca=True/False).
        is_ca = "keyCertSign" in profile.get("keyUsage", [])

        # Generate certificate
        cert = PublicCert.generate(csr, self._ca_cert, self._ca_key, profile, ca=is_ca, duration=duration)

        # Store key and certificate so they can be retrieved later (e.g. for sub-CA use)
        if self._storage:
            self._storage.store_key(key.export(), cn)
            self._storage.store_cert(cert.export().encode("utf-8"), cn, cert.serial_number)

        # Log the certificate issuance
        self._logger.audit(
            "authority",
            "CERTIFICATE_ISSUED",
            cn,
            "SUCCESS",
            profile=profile_name,
            serial=cert.serial_number,
        )

        return cert

    def sign_csr(self, csr_pem: str, profile_name: str, duration: int | None = None) -> PublicCert:
        """
        Sign a CSR.

        Args:
            csr_pem: CSR in PEM format
            profile_name: Profile name to use
            duration: Certificate validity in days

        Returns:
            PublicCert: Signed certificate
        """
        if not self._initialized:
            raise AuthorityError("Authority not initialized")

        if self._ca_cert is None or self._ca_key is None:
            raise AuthorityError("CA not loaded")

        # Load CSR
        csr = CertRequest.load(csr_pem)

        # Get CN from CSR
        cn = csr.subject_cn
        if not cn:
            raise CertificateError("CSR has no Common Name")

        # Get profile
        profile = self.get_profile(profile_name)

        # Get SANs from CSR
        sans = csr.sans

        # Generate certificate
        cert = PublicCert.generate(
            csr,
            self._ca_cert,
            self._ca_key,
            profile,
            ca=False,
            duration=duration,
            sans=sans,
        )

        # Store certificate
        if self._storage:
            self._storage.store_cert(cert.export().encode("utf-8"), cn, cert.serial_number)

        # Log the certificate issuance
        self._logger.audit(
            "authority",
            "CERTIFICATE_SIGNED",
            cn,
            "SUCCESS",
            profile=profile_name,
            serial=cert.serial_number,
        )

        return cert

    def revoke_certificate(self, dn: str, reason: str) -> bool:
        """
        Revoke a certificate.

        Args:
            dn: Distinguished Name of the certificate
            reason: Revocation reason

        Returns:
            bool: True if successful
        """
        if not self._initialized:
            raise AuthorityError("Authority not initialized")
        if self._storage is None:
            raise AuthorityError("Storage not initialized")

        # Load certificate
        cert_data = self._storage.get_cert(dn)
        if not cert_data:
            raise CertificateError(f"Certificate not found: {dn}")

        cert = PublicCert.load(cert_data.decode("utf-8"))

        # Revoke the certificate
        cert.revoke(reason)

        # Add to CRL
        revoke_entry = {
            "serial": cert.serial_number,
            "revoke_date": datetime.now(UTC).isoformat(),
            "reason": reason,
            "dn": dn,
        }
        self._crl.append(revoke_entry)

        # Store revocation info in node storage
        node_data = self._storage.get_node(dn) or {}
        node_data["revoked"] = True
        node_data["revoke_date"] = revoke_entry["revoke_date"]
        node_data["revoke_reason"] = reason
        node_data["revoke_serial"] = cert.serial_number
        self._storage.store_node(dn, node_data)

        # Store CRL in storage
        crl_data = self.generate_crl()
        self._storage.store_crl("ca", crl_data)

        # Log revocation
        self._logger.audit(
            "authority",
            "CERTIFICATE_REVOKED",
            dn,
            "SUCCESS",
            reason=reason,
            serial=cert.serial_number,
        )

        return True

    def unrevoke_certificate(self, dn: str) -> bool:
        """
        Remove revocation status from a certificate.

        Args:
            dn: Distinguished Name of the certificate

        Returns:
            bool: True if successful
        """
        if not self._initialized:
            raise AuthorityError("Authority not initialized")
        if self._storage is None:
            raise AuthorityError("Storage not initialized")

        # Load certificate
        cert_data = self._storage.get_cert(dn)
        if not cert_data:
            raise CertificateError(f"Certificate not found: {dn}")

        cert = PublicCert.load(cert_data.decode("utf-8"))

        # Unrevoke the certificate
        cert.unrevoke()

        # Remove from CRL
        self._crl = [entry for entry in self._crl if entry.get("dn") != dn]

        # Update node storage to remove revocation status
        node_data = self._storage.get_node(dn)
        if node_data:
            node_data["revoked"] = False
            node_data.pop("revoke_date", None)
            node_data.pop("revoke_reason", None)
            node_data.pop("revoke_serial", None)
            self._storage.store_node(dn, node_data)

        # Regenerate and store CRL
        crl_data = self.generate_crl()
        self._storage.store_crl("ca", crl_data)

        # Log unrevocation
        self._logger.audit("authority", "CERTIFICATE_UNREVOKED", dn, "SUCCESS")

        return True

    def renew_certificate(self, dn: str, duration: int | None = None) -> tuple[PublicCert, int]:
        """
        Renew a certificate.

        Args:
            dn: Distinguished Name of the certificate
            duration: New validity duration in days

        Returns:
            tuple: (new certificate, new serial number)
        """
        if not self._initialized:
            raise AuthorityError("Authority not initialized")
        if self._storage is None:
            raise AuthorityError("Storage not initialized")

        if self._ca_cert is None or self._ca_key is None:
            raise AuthorityError("CA not loaded")

        # Load old certificate
        cert_data = self._storage.get_cert(dn)
        if not cert_data:
            raise CertificateError(f"Certificate not found: {dn}")

        old_cert = PublicCert.load(cert_data.decode("utf-8"))

        # Get old certificate's profile
        profile_name = "server"  # Default
        profile = self.get_profile(profile_name)

        # Get subject info
        subject_dict = {}
        for attr in old_cert.subject:
            subject_dict[attr.oid._name] = attr.value

        cn = subject_dict.get("CN")
        if not cn:
            raise CertificateError("Old certificate has no Common Name")

        # Revoke old certificate first
        self.revoke_certificate(dn, "superseded")

        # Generate new key
        new_key = PrivateKey.generate(profile)

        # Generate new CSR
        new_csr = CertRequest.generate(new_key, cn, profile, old_cert.sans)

        # Generate new certificate
        new_cert = PublicCert.generate(
            new_csr,
            self._ca_cert,
            self._ca_key,
            profile,
            ca=False,
            duration=duration or profile.get("duration", DEFAULT_DURATION),
            sans=old_cert.sans,
        )

        # Store new certificate
        if self._storage:
            self._storage.store_cert(new_cert.export().encode("utf-8"), cn, new_cert.serial_number)

            # Update node data with new certificate info
            node_data = self._storage.get_node(dn) or {}
            node_data["new_cert_serial"] = new_cert.serial_number
            node_data["new_cert_data"] = new_cert.export()
            node_data["renewed"] = True
            node_data["renewal_date"] = datetime.now(UTC).isoformat()
            self._storage.store_node(dn, node_data)

        # Log renewal
        self._logger.audit(
            "authority",
            "CERTIFICATE_RENEWED",
            dn,
            "SUCCESS",
            old_serial=old_cert.serial_number,
            new_serial=new_cert.serial_number,
        )

        return new_cert, new_cert.serial_number

    def view_certificate(self, dn: str) -> dict[str, Any]:
        """
        View certificate details.

        Args:
            dn: Distinguished Name of the certificate

        Returns:
            dict: Certificate details including revocation status
        """
        if self._storage is None:
            raise AuthorityError("Storage not initialized")

        cert_data = self._storage.get_cert(dn)
        if not cert_data:
            raise CertificateError(f"Certificate not found: {dn}")

        cert = PublicCert.load(cert_data.decode("utf-8"))
        cert_info = cert.parse()

        # Get revocation status from node storage
        node_data = self._storage.get_node(dn)
        if node_data:
            cert_info["revoked"] = node_data.get("revoked", False)
            cert_info["revoke_date"] = node_data.get("revoke_date")
            cert_info["revoke_reason"] = node_data.get("revoke_reason")
            cert_info["deleted"] = node_data.get("deleted", False)
            cert_info["renewed"] = node_data.get("renewed", False)

        # Check if in CRL
        for entry in self._crl:
            if entry.get("dn") == dn:
                cert_info["revoked"] = True
                cert_info["revoke_date"] = entry.get("revoke_date")
                cert_info["revoke_reason"] = entry.get("reason")
                break

        return cert_info

    def delete_certificate(self, dn: str) -> bool:
        """
        Delete a certificate.

        Args:
            dn: Distinguished Name of the certificate

        Returns:
            bool: True if successful
        """
        if not self._initialized:
            raise AuthorityError("Authority not initialized")
        if self._storage is None:
            raise AuthorityError("Storage not initialized")

        # Check if certificate exists
        cert_data = self._storage.get_cert(dn)
        if not cert_data:
            raise CertificateError(f"Certificate not found: {dn}")

        cert = PublicCert.load(cert_data.decode("utf-8"))

        # Revoke first for audit purposes
        self.revoke_certificate(dn, "cessationOfOperation")

        # Extract CN from DN
        cn = dn.split("CN=")[-1] if "CN=" in dn else dn

        # Delete private key if exists
        self._storage.delete_key(cn)

        # Mark node as deleted in storage
        node_data = self._storage.get_node(dn)
        if node_data:
            node_data["deleted"] = True
            node_data["delete_date"] = datetime.now(UTC).isoformat()
            self._storage.store_node(dn, node_data)

        # Log deletion
        self._logger.audit(
            "authority",
            "CERTIFICATE_DELETED",
            dn,
            "SUCCESS",
            serial=cert.serial_number,
        )

        return True

    # CRL Operations

    def generate_crl(self) -> bytes:
        """
        Generate a new CRL.

        Returns:
            bytes: CRL in DER format
        """
        if self._ca_cert is None or self._ca_key is None:
            raise AuthorityError("CA not loaded")

        # Build CRL
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self._ca_cert.subject)
            .last_update(datetime.now(UTC))
            .next_update(datetime.now(UTC) + timedelta(days=7))
        )

        # Add revoked certificates
        for entry in self._crl:
            revoked_cert = (
                x509.RevokedCertificateBuilder()
                .serial_number(entry["serial"])
                .revocation_date(datetime.fromisoformat(entry["revoke_date"]))
                .build(default_backend())
            )
            builder = builder.add_revoked_certificate(revoked_cert)

        # Sign CRL
        crl = builder.sign(self._ca_key.key, hashes.SHA256(), default_backend())

        self._crl_last_update = datetime.now(UTC)

        # Store CRL in storage
        crl_data = crl.public_bytes(serialization.Encoding.DER)
        if self._storage:
            self._storage.store_crl("ca", crl_data)

        return crl_data

    def get_crl(self) -> bytes | None:
        """
        Get the current CRL.

        Returns:
            bytes: CRL in DER format, or None if no CRL exists
        """
        # Try to load from storage first
        if self._storage:
            crl_data = self._storage.get_crl("ca")
            if crl_data:
                return crl_data

        # Generate new CRL if none exists
        return self.generate_crl()

    # OCSP Support

    def ocsp_check(self, cert_pem: str, issuer_pem: str) -> dict[str, Any]:
        """
        Check OCSP status of a certificate.

        Args:
            cert_pem: Certificate in PEM format
            issuer_pem: Issuer certificate in PEM format

        Returns:
            dict: OCSP status information
        """
        # Load certificate
        cert = PublicCert.load(cert_pem)
        issuer = PublicCert.load(issuer_pem)

        # Verify certificate is issued by issuer
        cert.verify(issuer)

        # Check if revoked
        result = {"status": "good", "serial": cert.serial_number, "cn": cert.subject_cn}

        # Check against CRL
        for entry in self._crl:
            if entry["serial"] == cert.serial_number:
                result["status"] = "revoked"
                result["revoke_reason"] = entry["reason"]
                result["revoke_date"] = entry["revoke_date"]
                break

        # Check expiration
        if not cert.is_valid:
            result["status"] = "expired"

        return result

    # Admin Management

    def list_admins(self) -> list[str]:
        """
        List all administrators.

        Returns:
            list: List of admin DNs
        """
        if self._storage is None:
            return []

        # Get admins from storage
        return self._storage.list_admins()

    def add_admin(self, dn: str) -> bool:
        """
        Add an administrator.

        Args:
            dn: Administrator DN

        Returns:
            bool: True if successful
        """
        if self._storage is None:
            raise AuthorityError("Storage not initialized")

        # Store admin in storage
        result = self._storage.add_admin(dn)

        self._logger.audit("authority", "ADMIN_ADDED", dn, "SUCCESS")
        return result

    def remove_admin(self, dn: str) -> bool:
        """
        Remove an administrator.

        Args:
            dn: Administrator DN

        Returns:
            bool: True if successful
        """
        if self._storage is None:
            raise AuthorityError("Storage not initialized")

        # Remove admin from storage
        result = self._storage.remove_admin(dn)

        self._logger.audit("authority", "ADMIN_REMOVED", dn, "SUCCESS")
        return result

    def get_ca_certificate(self) -> str:
        """
        Get the CA certificate in PEM format.

        Returns:
            str: CA certificate in PEM format
        """
        if self._ca_cert is None:
            raise AuthorityError("CA not loaded")

        return self._ca_cert.export()

    def __repr__(self) -> str:
        """Return string representation of the Authority."""
        if not self._initialized:
            return "Authority(not initialized)"

        ca_cn = self._ca_cert.subject_cn if self._ca_cert else "unknown"
        return f"Authority(cn={ca_cn}, initialized={self._initialized})"
