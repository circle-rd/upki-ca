"""
Public Certificate handling for uPKI CA Server.

This module provides the PublicCert class for generating, loading,
and managing X.509 certificates.

Author: uPKI Team
License: MIT
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

from upki_ca.ca.cert_request import CertRequest
from upki_ca.ca.private_key import PrivateKey
from upki_ca.core.common import Common
from upki_ca.core.options import DEFAULT_DIGEST, DEFAULT_DURATION
from upki_ca.core.upki_error import CertificateError
from upki_ca.core.validators import DNValidator, RevokeReasonValidator, SANValidator


class PublicCert(Common):
    """
    Handles X.509 certificate operations.
    """

    def __init__(self, cert: x509.Certificate | None = None) -> None:
        """
        Initialize a PublicCert object.

        Args:
            cert: Cryptography Certificate object (optional)
        """
        self._cert = cert
        self._revoked = False
        self._revoke_reason = ""
        self._revoke_date: datetime | None = None

    @property
    def cert(self) -> x509.Certificate:
        """Get the underlying cryptography Certificate object."""
        if self._cert is None:
            raise CertificateError("No certificate loaded")
        return self._cert

    @property
    def serial_number(self) -> int:
        """Get the certificate serial number."""
        if self._cert is None:
            raise CertificateError("No certificate loaded")
        return self._cert.serial_number

    @property
    def subject(self) -> x509.Name:
        """Get the certificate subject."""
        if self._cert is None:
            raise CertificateError("No certificate loaded")
        return self._cert.subject

    @property
    def issuer(self) -> x509.Name:
        """Get the certificate issuer."""
        if self._cert is None:
            raise CertificateError("No certificate loaded")
        return self._cert.issuer

    @property
    def subject_cn(self) -> str:
        """Get the Common Name from the subject."""
        if self._cert is None:
            raise CertificateError("No certificate loaded")

        try:
            cn_attr = self._cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if cn_attr:
                return str(cn_attr[0].value)
        except Exception:
            pass
        return ""

    @property
    def issuer_cn(self) -> str:
        """Get the Common Name from the issuer."""
        if self._cert is None:
            raise CertificateError("No certificate loaded")

        try:
            cn_attr = self._cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            if cn_attr:
                return str(cn_attr[0].value)
        except Exception:
            pass
        return ""

    @property
    def not_valid_before(self) -> datetime:
        """Get the certificate validity start."""
        if self._cert is None:
            raise CertificateError("No certificate loaded")
        return self._cert.not_valid_before_utc

    @property
    def not_valid_after(self) -> datetime:
        """Get the certificate validity end."""
        if self._cert is None:
            raise CertificateError("No certificate loaded")
        return self._cert.not_valid_after_utc

    @property
    def is_valid(self) -> bool:
        """Check if the certificate is currently valid."""
        if self._cert is None:
            raise CertificateError("No certificate loaded")

        now = datetime.now(UTC)
        return self.not_valid_before <= now <= self.not_valid_after

    @property
    def is_revoked(self) -> bool:
        """Check if the certificate is revoked."""
        return self._revoked

    @property
    def revoke_reason(self) -> str:
        """Get the revocation reason."""
        return self._revoke_reason

    @property
    def revoke_date(self) -> datetime | None:
        """Get the revocation date."""
        return self._revoke_date

    @property
    def fingerprint(self) -> str:
        """Get the certificate fingerprint (SHA-256)."""
        if self._cert is None:
            raise CertificateError("No certificate loaded")

        return self._cert.fingerprint(hashes.SHA256()).hex()

    @property
    def key_usage(self) -> dict[str, bool]:
        """Get the key usage extensions."""
        if self._cert is None:
            raise CertificateError("No certificate loaded")

        try:
            ext = self._cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            # Access specific KeyUsage attributes - type ignore needed due to cryptography type stubs
            return {
                "digital_signature": ext.value.digital_signature,  # type: ignore[attr-defined]
                "content_commitment": ext.value.content_commitment,  # type: ignore[attr-defined]
                "key_encipherment": ext.value.key_encipherment,  # type: ignore[attr-defined]
                "data_encipherment": ext.value.data_encipherment,  # type: ignore[attr-defined]
                "key_agreement": ext.value.key_agreement,  # type: ignore[attr-defined]
                "key_cert_sign": ext.value.key_cert_sign,  # type: ignore[attr-defined]
                "crl_sign": ext.value.crl_sign,  # type: ignore[attr-defined]
            }
        except x509.ExtensionNotFound:
            return {}

    @property
    def sans(self) -> list[dict[str, str]]:
        """Get the Subject Alternative Names."""
        if self._cert is None:
            raise CertificateError("No certificate loaded")

        result = []
        try:
            san_ext = self._cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            # Iterate over the SAN values - type ignore needed as ExtensionType value isn't properly typed
            for san in san_ext.value:  # type: ignore[iterable]
                if isinstance(san, x509.DNSName):
                    result.append({"type": "DNS", "value": san.value})
                elif isinstance(san, x509.IPAddress):
                    result.append({"type": "IP", "value": str(san.value)})
                elif isinstance(san, x509.RFC822Name):
                    result.append({"type": "EMAIL", "value": san.value})
                elif isinstance(san, x509.UniformResourceIdentifier):
                    result.append({"type": "URI", "value": san.value})
        except x509.ExtensionNotFound:
            pass

        return result

    @property
    def basic_constraints(self) -> dict[str, Any]:
        """Get the basic constraints extension."""
        if self._cert is None:
            raise CertificateError("No certificate loaded")

        try:
            ext = self._cert.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            )
            # Access specific BasicConstraints attributes - type ignore needed due to cryptography type stubs
            return {"ca": ext.value.ca, "path_length": ext.value.path_length}  # type: ignore[attr-defined]
        except x509.ExtensionNotFound:
            return {"ca": False, "path_length": None}

    @property
    def is_ca(self) -> bool:
        """Check if the certificate is a CA certificate."""
        return self.basic_constraints.get("ca", False)

    @classmethod
    def generate(
        cls,
        csr: CertRequest,
        issuer_cert: PublicCert,
        issuer_key: PrivateKey,
        profile: dict[str, Any],
        ca: bool = False,
        self_signed: bool = False,
        start: datetime | None = None,
        duration: int | None = None,
        digest: str | None = None,
        sans: list[dict[str, str]] | None = None,
    ) -> PublicCert:
        """
        Generate a new certificate from a CSR.

        Args:
            csr: Certificate Signing Request
            issuer_cert: Issuer certificate (for CA, can be self)
            issuer_key: Issuer private key
            profile: Certificate profile
            ca: Whether this is a CA certificate
            self_signed: Whether this is a self-signed certificate
            start: Validity start time (default: now)
            duration: Validity duration in days
            digest: Hash algorithm to use
            sans: Subject Alternative Names

        Returns:
            PublicCert: Generated certificate object

        Raises:
            CertificateError: If certificate generation fails
        """
        # Get parameters
        if start is None:
            start = datetime.now(UTC)

        if duration is None:
            duration = profile.get("duration", DEFAULT_DURATION)

        if digest is None:
            digest = profile.get("digest", DEFAULT_DIGEST)

        # Calculate end date
        duration_val = duration if duration is not None else DEFAULT_DURATION
        end = start + timedelta(days=duration_val)

        # Build subject from CSR
        subject = csr.subject

        # Build issuer
        issuer = subject if self_signed else issuer_cert.subject
        # For self-signed, the issuer is the subject itself
        # (no need to store the public key separately)

        # Get subject from CSR for DN validation
        subject_dict = {}
        for attr in subject:
            subject_dict[attr.oid._name] = attr.value

        if "CN" in subject_dict:
            DNValidator.validate_cn(subject_dict["CN"])

        # Build certificate builder
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(start)
            .not_valid_after(end)
        )

        # Add basic constraints
        if ca:
            # pathLen=None means unlimited chain depth (suitable for a root CA).
            # Sub-CAs generated with a profile that specifies pathLen=0 can only
            # sign leaf certificates, not further CAs.
            path_len: int | None = profile.get("pathLen")
            builder = builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=path_len), critical=True
            )
        else:
            builder = builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )

        # Add key usage
        key_usages = profile.get("keyUsage", [])
        if key_usages:
            ku = x509.KeyUsage(
                digital_signature="digitalSignature" in key_usages,
                content_commitment="nonRepudiation" in key_usages,
                key_encipherment="keyEncipherment" in key_usages,
                data_encipherment="dataEncipherment" in key_usages,
                key_agreement="keyAgreement" in key_usages,
                key_cert_sign="keyCertSign" in key_usages,
                crl_sign="cRLSign" in key_usages,
                encipher_only=False,
                decipher_only=False,
            )
            builder = builder.add_extension(ku, critical=True)

        # Add extended key usage
        eku_list = profile.get("extendedKeyUsage", [])
        if eku_list:
            eku_oids = []
            for eku in eku_list:
                if eku == "serverAuth":
                    eku_oids.append(ExtendedKeyUsageOID.SERVER_AUTH)
                elif eku == "clientAuth":
                    eku_oids.append(ExtendedKeyUsageOID.CLIENT_AUTH)
                elif eku == "codeSigning":
                    eku_oids.append(ExtendedKeyUsageOID.CODE_SIGNING)
                elif eku == "emailProtection":
                    eku_oids.append(ExtendedKeyUsageOID.EMAIL_PROTECTION)
                elif eku == "timeStamping":
                    eku_oids.append(ExtendedKeyUsageOID.TIME_STAMPING)

            if eku_oids:
                builder = builder.add_extension(
                    x509.ExtendedKeyUsage(eku_oids), critical=False
                )

        # Add SANs from CSR or parameters
        all_sans = []

        # First, add SANs from CSR
        csr_sans = csr.parse().get("sans", [])
        all_sans.extend(csr_sans)

        # Then, add SANs from parameters (these take precedence)
        if sans:
            SANValidator.validate_list(sans)
            # Merge, avoiding duplicates
            existing = {san.get("value", "") for san in all_sans}
            for san in sans:
                if san.get("value", "") not in existing:
                    all_sans.append(san)

        if all_sans:
            san_entries = []
            for san in all_sans:
                san_type = san.get("type", "").upper()
                value = san.get("value", "")

                if san_type == "DNS":
                    san_entries.append(x509.DNSName(value))
                elif san_type == "IP":
                    san_entries.append(x509.IPAddress(ipaddress.ip_address(value)))
                elif san_type == "EMAIL":
                    san_entries.append(x509.RFC822Name(value))
                elif san_type == "URI":
                    san_entries.append(x509.UniformResourceIdentifier(value))

            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_entries), critical=False
            )

        # Sign the certificate
        try:
            digest_val = digest if digest is not None else DEFAULT_DIGEST
            hash_algorithm = getattr(hashes, digest_val.upper())()

            # Use issuer_key.key (the private key) for signing
            cert = builder.sign(issuer_key.key, hash_algorithm, default_backend())

            return cls(cert)
        except Exception as e:
            raise CertificateError(f"Failed to generate certificate: {e}") from e

    @classmethod
    def load(cls, cert_pem: str) -> PublicCert:
        """
        Load a certificate from PEM format.

        Args:
            cert_pem: Certificate in PEM format

        Returns:
            PublicCert: Loaded certificate object

        Raises:
            CertificateError: If certificate loading fails
        """
        try:
            cert = x509.load_pem_x509_certificate(
                cert_pem.encode("utf-8"), default_backend()
            )
            return cls(cert)
        except Exception as e:
            raise CertificateError(f"Failed to load certificate: {e}") from e

    @classmethod
    def load_from_file(cls, filepath: str) -> PublicCert:
        """
        Load a certificate from a file.

        Args:
            filepath: Path to the certificate file

        Returns:
            PublicCert: Loaded certificate object

        Raises:
            CertificateError: If certificate loading fails
        """
        try:
            with open(filepath) as f:
                cert_pem = f.read()
            return cls.load(cert_pem)
        except FileNotFoundError:
            raise CertificateError(f"Certificate file not found: {filepath}") from None
        except Exception as e:
            raise CertificateError(f"Failed to load certificate from file: {e}") from e

    def export(
        self, cert: x509.Certificate | None = None, encoding: str = "pem"
    ) -> str:
        """
        Export the certificate.

        Args:
            cert: Certificate to export (optional, uses self if not provided)
            encoding: Output encoding (pem or der)

        Returns:
            str: Certificate in PEM format

        Raises:
            CertificateError: If export fails
        """
        if cert is None:
            cert = self._cert

        if cert is None:
            raise CertificateError("No certificate to export")

        try:
            if encoding.lower() == "pem":
                return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
            elif encoding.lower() == "der":
                return cert.public_bytes(serialization.Encoding.DER).decode("latin-1")
            else:
                raise CertificateError(f"Unsupported encoding: {encoding}")
        except Exception as e:
            raise CertificateError(f"Failed to export certificate: {e}") from e

    def export_to_file(self, filepath: str, encoding: str = "pem") -> bool:
        """
        Export the certificate to a file.

        Args:
            filepath: Path to save the certificate
            encoding: Output encoding (pem or der)

        Returns:
            bool: True if successful

        Raises:
            CertificateError: If export fails
        """
        try:
            cert_pem = self.export(encoding=encoding)
            with open(filepath, "w") as f:
                f.write(cert_pem)
            return True
        except Exception as e:
            raise CertificateError(f"Failed to export certificate to file: {e}") from e

    def verify(
        self, issuer_cert: PublicCert | None = None, issuer_public_key: Any = None
    ) -> bool:
        """
        Verify the certificate signature.

        Args:
            issuer_cert: Issuer certificate (optional)
            issuer_public_key: Issuer public key (optional, used if issuer_cert not provided)

        Returns:
            bool: True if signature is valid

        Raises:
            CertificateError: If verification fails
        """
        if self._cert is None:
            raise CertificateError("No certificate to verify")

        try:
            if issuer_public_key is None and issuer_cert is not None:
                issuer_public_key = issuer_cert.cert.public_key

            if issuer_public_key is None:
                # Self-signed verification
                issuer_public_key = self._cert.public_key

            # Verify the certificate signature
            issuer_public_key.verify(
                self._cert.signature,
                self._cert.tbs_certificate_bytes,
                self._cert.signature_algorithm_parameters,
            )
            return True
        except Exception as e:
            raise CertificateError(f"Certificate verification failed: {e}") from e

    def revoke(self, reason: str, date: datetime | None = None) -> bool:
        """
        Mark the certificate as revoked.

        Args:
            reason: Revocation reason
            date: Revocation date (default: now)

        Returns:
            bool: True if successful

        Raises:
            ValidationError: If reason is invalid
        """
        RevokeReasonValidator.validate(reason)

        self._revoked = True
        self._revoke_reason = reason
        self._revoke_date = date if date is not None else datetime.now(UTC)

        return True

    def unrevoke(self) -> bool:
        """
        Remove revocation status from the certificate.

        Returns:
            bool: True if successful
        """
        self._revoked = False
        self._revoke_reason = ""
        self._revoke_date = None

        return True

    def parse(self) -> dict[str, Any]:
        """
        Parse the certificate and extract all information.

        Returns:
            dict: Dictionary with all certificate details

        Raises:
            CertificateError: If parsing fails
        """
        if self._cert is None:
            raise CertificateError("No certificate to parse")

        result: dict[str, Any] = {
            "subject": {},
            "issuer": {},
            "extensions": {},
            "sans": self.sans,
            "key_usage": self.key_usage,
            "basic_constraints": self.basic_constraints,
            "serial_number": self.serial_number,
            "fingerprint": self.fingerprint,
            "not_valid_before": self.not_valid_before.isoformat(),
            "not_valid_after": self.not_valid_after.isoformat(),
            "is_valid": self.is_valid,
            "is_revoked": self._revoked,
            "revoke_reason": self._revoke_reason,
            "is_ca": self.is_ca,
        }

        # Parse subject
        for attr in self._cert.subject:
            oid_str = attr.oid._name
            result["subject"][oid_str] = attr.value

        # Parse issuer
        for attr in self._cert.issuer:
            oid_str = attr.oid._name
            result["issuer"][oid_str] = attr.value

        # Parse extensions
        for ext in self._cert.extensions:
            oid_str = ext.oid._name
            result["extensions"][oid_str] = str(ext.value)

        return result

    def __repr__(self) -> str:
        """Return string representation of the certificate."""
        if self._cert is None:
            return "PublicCert(not loaded)"

        status = "REVOKED" if self._revoked else "VALID" if self.is_valid else "EXPIRED"
        return f"PublicCert(cn={self.subject_cn}, status={status})"
