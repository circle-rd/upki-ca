# -*- coding:utf-8 -*-

"""
Certificate Request (CSR) handling for uPKI.

This module provides the CertRequest class for generating, loading,
and parsing X.509 Certificate Signing Requests.
"""

from typing import Any

import ipaddress
import validators
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

import upkica
from upkica.core.common import Common


class CertRequest(Common):
    """Certificate Signing Request handler.

    Handles generation, loading, parsing, and export of X.509 CSRs.

    Attributes:
        _config: Configuration object.
        _backend: Cryptography backend instance.

    Args:
        config: Configuration object with logger settings.

    Raises:
        Exception: If initialization fails.
    """

    def __init__(self, config: Any) -> None:
        """Initialize CertRequest handler.

        Args:
            config: Configuration object with logger settings.

        Raises:
            Exception: If initialization fails.
        """
        try:
            super().__init__(config._logger)
        except Exception as err:
            raise Exception(f"Unable to initialize certRequest: {err}")

        self._config: Any = config

        # Private var
        self._CertRequest__backend = default_backend()

    def generate(
        self,
        pkey: Any,
        cn: str,
        profile: dict,
        sans: list | None = None,
    ) -> Any:
        """Generate a CSR based on private key, common name, and profile.

        Args:
            pkey: Private key object for signing the CSR.
            cn: Common Name for the certificate.
            profile: Profile dictionary containing subject, altnames, certType, etc.
            sans: Optional list of Subject Alternative Names.

        Returns:
            CertificateSigningRequest object.

        Raises:
            Exception: If CSR generation fails.
            NotImplementedError: If digest algorithm is not supported.
        """
        subject = []
        # Extract subject from profile
        try:
            for entry in profile["subject"]:
                for subj, value in entry.items():
                    subj = subj.upper()
                    if subj == "C":
                        subject.append(x509.NameAttribute(NameOID.COUNTRY_NAME, value))
                    elif subj == "ST":
                        subject.append(
                            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, value)
                        )
                    elif subj == "L":
                        subject.append(x509.NameAttribute(NameOID.LOCALITY_NAME, value))
                    elif subj == "O":
                        subject.append(
                            x509.NameAttribute(NameOID.ORGANIZATION_NAME, value)
                        )
                    elif subj == "OU":
                        subject.append(
                            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, value)
                        )
        except Exception as err:
            raise Exception(f"Unable to extract subject: {err}")

        try:
            # Append cn at the end
            subject.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
        except Exception as err:
            raise Exception(f"Unable to setup subject name: {err}")

        try:
            builder = x509.CertificateSigningRequestBuilder().subject_name(
                x509.Name(subject)
            )
        except Exception as err:
            raise Exception(f"Unable to create structure: {err}")

        subject_alt = []
        # Best practices wants to include FQDN in SANS for servers
        if profile["altnames"]:
            # Add IPAddress for Goland compliance
            if validators.ipv4(cn):
                subject_alt.append(x509.DNSName(cn))
                subject_alt.append(x509.IPAddress(ipaddress.ip_address(cn)))
            elif validators.domain(cn):
                subject_alt.append(x509.DNSName(cn))
            elif validators.email(cn):
                subject_alt.append(x509.RFC822Name(cn))
            elif validators.url(cn):
                subject_alt.append(x509.UniformResourceIdentifier(cn))
            else:
                if "server" in profile["certType"]:
                    self.output(
                        f"ADD ALT NAMES {cn}.{profile['domain']} FOR SERVER SERVICE"
                    )
                    subject_alt.append(x509.DNSName(f"{cn}.{profile['domain']}"))
                if "email" in profile["certType"]:
                    subject_alt.append(x509.RFC822Name(f"{cn}@{profile['domain']}"))

        # Add alternate names if needed
        if isinstance(sans, list) and len(sans):
            for entry in sans:
                # Add IPAddress for Goland compliance
                if validators.ipv4(entry):
                    if x509.DNSName(entry) not in subject_alt:
                        subject_alt.append(x509.DNSName(entry))
                    if x509.IPAddress(ipaddress.ip_address(entry)) not in subject_alt:
                        subject_alt.append(x509.IPAddress(ipaddress.ip_address(entry)))
                elif validators.domain(entry) and (
                    x509.DNSName(entry) not in subject_alt
                ):
                    subject_alt.append(x509.DNSName(entry))
                elif validators.email(entry) and (
                    x509.RFC822Name(entry) not in subject_alt
                ):
                    subject_alt.append(x509.RFC822Name(entry))

        if len(subject_alt):
            try:
                builder = builder.add_extension(
                    x509.SubjectAlternativeName(subject_alt), critical=False
                )
            except Exception as err:
                raise Exception(f"Unable to add alternate name: {err}")

        if profile["digest"] == "md5":
            digest = hashes.MD5()
        elif profile["digest"] == "sha1":
            digest = hashes.SHA1()
        elif profile["digest"] == "sha256":
            digest = hashes.SHA256()
        elif profile["digest"] == "sha512":
            digest = hashes.SHA512()
        else:
            raise NotImplementedError(
                f"Private key only support {self._allowed.Digest} digest signatures"
            )

        try:
            csr = builder.sign(
                private_key=pkey, algorithm=digest, backend=self._CertRequest__backend
            )
        except Exception as err:
            raise Exception(f"Unable to sign certificate request: {err}")

        return csr

    def load(self, raw: bytes, encoding: str = "PEM") -> Any:
        """Load a CSR from raw data.

        Args:
            raw: Raw CSR data bytes.
            encoding: Encoding format ('PEM', 'DER', 'PFX', 'P12').

        Returns:
            CertificateSigningRequest object.

        Raises:
            Exception: If loading fails.
            NotImplementedError: If encoding is not supported.
        """
        csr = None
        try:
            if encoding == "PEM":
                csr = x509.load_pem_x509_csr(raw, backend=self._CertRequest__backend)
            elif encoding in ["DER", "PFX", "P12"]:
                csr = x509.load_der_x509_csr(raw, backend=self._CertRequest__backend)
            else:
                raise NotImplementedError("Unsupported certificate request encoding")
        except Exception as err:
            raise Exception(err)

        return csr

    def dump(self, csr: Any, encoding: str = "PEM") -> bytes:
        """Export CSR to bytes.

        Args:
            csr: CertificateSigningRequest object.
            encoding: Encoding format ('PEM', 'DER', 'PFX', 'P12').

        Returns:
            Encoded CSR bytes.

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
            raise NotImplementedError("Unsupported certificate request encoding")

        try:
            data = csr.public_bytes(enc)
        except Exception as err:
            raise Exception(err)

        return data

    def parse(self, raw: bytes, encoding: str = "PEM") -> dict:
        """Parse CSR and return dictionary with extracted values.

        Args:
            raw: Raw CSR data bytes.
            encoding: Encoding format ('PEM', 'DER', 'PFX', 'P12').

        Returns:
            Dictionary with 'subject', 'digest', and 'signature' keys.

        Raises:
            Exception: If parsing fails.
            NotImplementedError: If encoding is not supported.
        """
        data = {}

        try:
            if encoding == "PEM":
                csr = x509.load_pem_x509_csr(raw, backend=self._CertRequest__backend)
            elif encoding in ["DER", "PFX", "P12"]:
                csr = x509.load_der_x509_csr(raw, backend=self._CertRequest__backend)
            else:
                raise NotImplementedError("Unsupported certificate request encoding")
        except Exception as err:
            raise Exception(err)

        data["subject"] = csr.subject
        data["digest"] = csr.signature_hash_algorithm
        data["signature"] = csr.signature

        return data
