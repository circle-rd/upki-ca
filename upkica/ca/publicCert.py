# -*- coding:utf-8 -*-

"""
Public Certificate handling for uPKI.

This module provides the PublicCert class for generating, loading,
parsing, and exporting X.509 certificates.
"""

import sys
import datetime
import ipaddress
from typing import Any

import validators
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID, ExtendedKeyUsageOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

import upkica
from upkica.core.common import Common


class PublicCert(Common):
    """Public certificate handler.

    Handles generation, loading, parsing, and export of X.509 certificates.

    Attributes:
        _config: Configuration object.
        _backend: Cryptography backend instance.

    Args:
        config: Configuration object with logger settings.

    Raises:
        Exception: If initialization fails.
    """

    def __init__(self, config: Any) -> None:
        """Initialize PublicCert handler.

        Args:
            config: Configuration object with logger settings.

        Raises:
            Exception: If initialization fails.
        """
        try:
            super().__init__(config._logger)
        except Exception as err:
            raise Exception(f"Unable to initialize publicCert: {err}")

        self._config: Any = config

        # Private var
        self._PublicCert__backend = default_backend()

    def _generate_serial(self) -> int:
        """Generate a unique certificate serial number.

        Generates a random serial number and ensures it doesn't already
        exist in the storage.

        Returns:
            A unique serial number for the certificate.

        Raises:
            Exception: If serial number generation fails.
        """
        serial = x509.random_serial_number()
        while self._config.storage.serial_exists(serial):
            serial = x509.random_serial_number()
        return serial

    def generate(
        self,
        csr: Any,
        issuer_crt: Any,
        issuer_key: Any,
        profile: dict,
        ca: bool = False,
        selfSigned: bool = False,
        start: float | None = None,
        duration: int | None = None,
        digest: str | None = None,
        sans: list | None = None,
    ) -> Any:
        """Generate a certificate from a CSR.

        Args:
            csr: Certificate Signing Request object.
            issuer_crt: Issuer's certificate (or self for self-signed).
            issuer_key: Issuer's private key.
            profile: Profile dictionary with certificate settings.
            ca: Whether this is a CA certificate (default: False).
            selfSigned: Whether this is self-signed (default: False).
            start: Optional start timestamp (default: now).
            duration: Optional validity duration in days.
            digest: Optional digest algorithm override.
            sans: Optional list of Subject Alternative Names.

        Returns:
            Certificate object.

        Raises:
            Exception: If certificate generation fails.
            NotImplementedError: If digest algorithm is not supported.
        """
        if sans is None:
            sans = []

        # Retrieve subject from csr
        subject = csr.subject
        self.output(f"Subject found: {subject.rfc4514_string()}", level="DEBUG")
        dn = self._get_dn(subject)
        self.output(f"DN found is {dn}", level="DEBUG")

        try:
            alt_names = None
            alt_names = csr.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            self.output(f"Subject alternate found: {alt_names}", level="DEBUG")
        except x509.ExtensionNotFound:
            pass

        # Force default if necessary
        now = (
            datetime.datetime.utcnow()
            if start is None
            else datetime.datetime.fromtimestamp(start)
        )
        duration = profile["duration"] if duration is None else duration

        # Generate serial number
        try:
            serial_number = self._generate_serial()
        except Exception as err:
            raise Exception(f"Error during serial number generation: {err}")

        # For self-signed certificate issuer is certificate itself
        issuer_name = subject if selfSigned else issuer_crt.issuer
        issuer_serial = serial_number if selfSigned else issuer_crt.serial_number

        try:
            # Define basic constraints
            if ca:
                basic_constraints = x509.BasicConstraints(ca=True, path_length=0)
            else:
                basic_constraints = x509.BasicConstraints(ca=False, path_length=None)
            builder = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer_name)
                .public_key(csr.public_key())
                .serial_number(serial_number)
                .not_valid_before(now)
                .not_valid_after(now + datetime.timedelta(days=duration))
                .add_extension(basic_constraints, critical=True)
            )
        except Exception as err:
            raise Exception(f"Unable to build structure: {err}")

        # We never trust CSR extensions - they may have been altered by the user
        try:
            # Due to uPKI design (TLS for renew), digital_signature MUST be setup
            digital_signature = True
            # Initialize key usage
            content_commitment = False
            key_encipherment = False
            data_encipherment = False
            key_agreement = False
            key_cert_sign = False
            crl_sign = False
            encipher_only = False
            decipher_only = False

            # Build Key Usages from profile
            for usage in profile["keyUsage"]:
                if usage == "digitalSignature":
                    digital_signature = True
                elif usage == "nonRepudiation":
                    content_commitment = True
                elif usage == "keyEncipherment":
                    key_encipherment = True
                elif usage == "dataEncipherment":
                    data_encipherment = True
                elif usage == "keyAgreement":
                    key_agreement = True
                elif usage == "keyCertSign":
                    key_cert_sign = True
                elif usage == "cRLSign":
                    crl_sign = True
                elif usage == "encipherOnly":
                    encipher_only = True
                elif usage == "decipherOnly":
                    decipher_only = True

            # Setup X509 Key Usages
            key_usages = x509.KeyUsage(
                digital_signature=digital_signature,
                content_commitment=content_commitment,
                key_encipherment=key_encipherment,
                data_encipherment=data_encipherment,
                key_agreement=key_agreement,
                key_cert_sign=key_cert_sign,
                crl_sign=crl_sign,
                encipher_only=encipher_only,
                decipher_only=decipher_only,
            )
            builder = builder.add_extension(key_usages, critical=True)
        except KeyError:
            # If no Key Usages are set, that's strange
            raise Exception("No Key Usages set.")
        except Exception as err:
            raise Exception(f"Unable to set Key Usages: {err}")

        try:
            # Build Key Usages extended based on profile
            key_usages_extended = []
            for eusage in profile["extendedKeyUsage"]:
                if eusage == "serverAuth":
                    key_usages_extended.append(ExtendedKeyUsageOID.SERVER_AUTH)
                elif eusage == "clientAuth":
                    key_usages_extended.append(ExtendedKeyUsageOID.CLIENT_AUTH)
                elif eusage == "codeSigning":
                    key_usages_extended.append(ExtendedKeyUsageOID.CODE_SIGNING)
                elif eusage == "emailProtection":
                    key_usages_extended.append(ExtendedKeyUsageOID.EMAIL_PROTECTION)
                elif eusage == "timeStamping":
                    key_usages_extended.append(ExtendedKeyUsageOID.TIME_STAMPING)
                elif eusage == "OCSPSigning":
                    key_usages_extended.append(ExtendedKeyUsageOID.OCSP_SIGNING)

            # Always add 'clientAuth' for automatic renewal
            if not ca and (ExtendedKeyUsageOID.CLIENT_AUTH not in key_usages_extended):
                key_usages_extended.append(ExtendedKeyUsageOID.CLIENT_AUTH)

            # Set Key Usages if needed
            if len(key_usages_extended):
                builder = builder.add_extension(
                    x509.ExtendedKeyUsage(key_usages_extended), critical=False
                )
        except KeyError:
            # If no extended key usages are set, do nothing
            pass
        except Exception as err:
            raise Exception(f"Unable to set Extended Key Usages: {err}")

        # Add alternate names if found in CSR
        if alt_names is not None:
            # Verify each time that SANS entry was registered
            # We can NOT trust CSR data (client manipulation)
            subject_alt = []

            for entry in alt_names.value.get_values_for_type(x509.IPAddress):
                if entry not in sans:
                    continue
                subject_alt.append(x509.IPAddress(ipaddress.ip_address(entry)))

            for entry in alt_names.value.get_values_for_type(x509.DNSName):
                if entry not in sans:
                    continue
                subject_alt.append(x509.DNSName(entry))

            for entry in alt_names.value.get_values_for_type(x509.RFC822Name):
                if entry not in sans:
                    continue
                subject_alt.append(x509.RFC822Name(entry))

            for entry in alt_names.value.get_values_for_type(
                x509.UniformResourceIdentifier
            ):
                if entry not in sans:
                    continue
                subject_alt.append(x509.UniformResourceIdentifier(entry))

            try:
                # Add all alternates to certificate
                builder = builder.add_extension(
                    x509.SubjectAlternativeName(subject_alt), critical=False
                )
            except Exception as err:
                raise Exception(f"Unable to set alternatives name: {err}")

        try:
            # Register signing authority
            issuer_key_id = x509.SubjectKeyIdentifier.from_public_key(
                issuer_key.public_key()
            )
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier(
                    issuer_key_id.digest,
                    [x509.DNSName(issuer_name.rfc4514_string())],
                    issuer_serial,
                ),
                critical=False,
            )
        except Exception as err:
            raise Exception(f"Unable to setup Authority Identifier: {err}")

        ca_endpoints = []
        try:
            # Default value if not set in profile
            ca_url = (
                profile["ca"]
                if profile["ca"]
                else f"https://certificates.{profile['domain']}/certs/ca.crt"
            )
        except KeyError:
            ca_url = None
        try:
            # Default value if not set in profile
            ocsp_url = (
                profile["ocsp"]
                if profile["ocsp"]
                else f"https://certificates.{profile['domain']}/ocsp"
            )
        except KeyError:
            ocsp_url = None

        try:
            # Add CA certificate distribution point and OCSP validation url
            if ca_url:
                ca_endpoints.append(
                    x509.AccessDescription(
                        x509.oid.AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier(ca_url),
                    )
                )
            if ocsp_url:
                ca_endpoints.append(
                    x509.AccessDescription(
                        x509.oid.AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier(ocsp_url),
                    )
                )
            builder = builder.add_extension(
                x509.AuthorityInformationAccess(ca_endpoints), critical=False
            )
        except Exception as err:
            raise Exception(f"Unable to setup OCSP/CA endpoint: {err}")

        try:
            # Add CRL distribution point
            crl_endpoints = []
            # Default value if not set in profile
            url = f"https://certificates.{profile['domain']}/certs/crl.pem"
            try:
                if profile["csr"]:
                    url = profile["csr"]
            except KeyError:
                pass
            crl_endpoints.append(
                x509.DistributionPoint(
                    [x509.UniformResourceIdentifier(url)],
                    None,
                    None,
                    [x509.DNSName(issuer_name.rfc4514_string())],
                )
            )
            builder = builder.add_extension(
                x509.CRLDistributionPoints(crl_endpoints), critical=False
            )
        except Exception as err:
            raise Exception(f"Unable to setup CRL endpoints: {err}")

        try:
            # Only CA know its private key
            if ca:
                builder = builder.add_extension(
                    x509.SubjectKeyIdentifier(issuer_key_id.digest),
                    critical=False,
                )
        except Exception as err:
            raise Exception(f"Unable to add Subject Key Identifier extension: {err}")

        if digest is None:
            digest = profile["digest"]

        if digest == "md5":
            digest = hashes.MD5()
        elif digest == "sha1":
            digest = hashes.SHA1()
        elif digest == "sha256":
            digest = hashes.SHA256()
        elif digest == "sha512":
            digest = hashes.SHA512()
        else:
            raise NotImplementedError(
                f"Private key only support {self._allowed.Digest} digest signatures"
            )

        try:
            pub_crt = builder.sign(
                private_key=issuer_key,
                algorithm=digest,
                backend=self._PublicCert__backend,
            )
        except Exception as err:
            raise Exception(f"Unable to sign certificate: {err}")

        return pub_crt

    def load(self, raw: bytes, encoding: str = "PEM") -> Any:
        """Load a certificate from raw data.

        Args:
            raw: Raw certificate bytes.
            encoding: Encoding format ('PEM', 'DER', 'PFX', 'P12').

        Returns:
            Certificate object.

        Raises:
            Exception: If loading fails.
            NotImplementedError: If encoding is not supported.
        """
        crt = None
        try:
            if encoding == "PEM":
                crt = x509.load_pem_x509_certificate(
                    raw, backend=self._PublicCert__backend
                )
            elif encoding in ["DER", "PFX", "P12"]:
                crt = x509.load_der_x509_certificate(
                    raw, backend=self._PublicCert__backend
                )
            else:
                raise NotImplementedError("Unsupported certificate encoding")
        except Exception as err:
            raise Exception(err)

        return crt

    def dump(self, crt: Any, encoding: str = "PEM") -> bytes:
        """Export certificate to bytes.

        Args:
            crt: Certificate object.
            encoding: Encoding format ('PEM', 'DER', 'PFX', 'P12').

        Returns:
            Encoded certificate bytes.

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
            raise NotImplementedError("Unsupported public certificate encoding")

        try:
            data = crt.public_bytes(enc)
        except Exception as err:
            raise Exception(err)

        return data

    def parse(self, raw: bytes, encoding: str = "PEM") -> dict:
        """Parse certificate and return dictionary with extracted values.

        Args:
            raw: Raw certificate bytes.
            encoding: Encoding format ('PEM', 'DER', 'PFX', 'P12').

        Returns:
            Dictionary with certificate metadata.

        Raises:
            Exception: If parsing fails.
            NotImplementedError: If encoding is not supported.
        """
        data = {}

        try:
            if encoding == "PEM":
                crt = x509.load_pem_x509_certificate(
                    raw, backend=self._PublicCert__backend
                )
            elif encoding in ["DER", "PFX", "P12"]:
                crt = x509.load_der_x509_certificate(
                    raw, backend=self._PublicCert__backend
                )
            else:
                raise NotImplementedError("Unsupported certificate encoding")
        except Exception as err:
            raise Exception(err)

        try:
            serial_number = f"{crt.serial_number:x}"
        except Exception:
            raise Exception("Unable to parse serial number")

        try:
            data["version"] = crt.version
            data["fingerprint"] = crt.fingerprint(crt.signature_hash_algorithm)
            data["subject"] = crt.subject
            data["serial"] = serial_number
            data["issuer"] = crt.issuer
            data["not_before"] = crt.not_valid_before
            data["not_after"] = crt.not_valid_after
            data["signature"] = crt.signature
            data["bytes"] = crt.public_bytes(serialization.Encoding.PEM)
            data["constraints"] = crt.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            )
            data["keyUsage"] = crt.extensions.get_extension_for_oid(
                ExtensionOID.KEY_USAGE
            )
        except Exception as err:
            raise Exception(err)
        try:
            data["extendedKeyUsage"] = crt.extensions.get_extension_for_oid(
                ExtensionOID.EXTENDED_KEY_USAGE
            )
        except x509.ExtensionNotFound:
            pass
        except Exception as err:
            raise Exception(err)
        try:
            data["CRLDistribution"] = crt.extensions.get_extension_for_oid(
                ExtensionOID.CRL_DISTRIBUTION_POINTS
            )
        except x509.ExtensionNotFound:
            pass
        except Exception as err:
            raise Exception(err)
        try:
            data["OCSPNOcheck"] = crt.extensions.get_extension_for_oid(
                ExtensionOID.OCSP_NO_CHECK
            )
        except x509.ExtensionNotFound:
            pass
        except Exception as err:
            raise Exception(err)

        return data
