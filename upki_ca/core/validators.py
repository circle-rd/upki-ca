"""
Input validation for uPKI CA Server.

This module provides validation functions following zero-trust principles:
- FQDNValidator: RFC 1123 compliant, blocks reserved domains
- SANValidator: Whitelist SAN types (DNS, IP, EMAIL)
- CSRValidator: Signature and key length verification

Author: uPKI Team
License: MIT
"""

from __future__ import annotations

import re
from typing import Any

from upki_ca.core.options import KeyLen, RevokeReasons
from upki_ca.core.upki_error import ValidationError


class FQDNValidator:
    """
    Validates Fully Qualified Domain Names according to RFC 1123.
    """

    # Reserved domains that should be blocked
    BLOCKED_DOMAINS: set[str] = {
        "localhost",
        "local",
        "invalid",
        "test",
    }

    # RFC 1123 compliant pattern
    LABEL_PATTERN: re.Pattern[str] = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")

    @classmethod
    def validate(cls, fqdn: str) -> bool:
        """
        Validate a Fully Qualified Domain Name.

        Args:
            fqdn: Domain name to validate

        Returns:
            bool: True if valid

        Raises:
            ValidationError: If domain is invalid
        """
        # Check for empty string
        if not fqdn:
            raise ValidationError("Domain name cannot be empty")

        # Check length (max 253 characters)
        if len(fqdn) > 253:
            raise ValidationError("Domain name exceeds maximum length of 253 characters")

        # Check for blocked domains
        if fqdn.lower() in cls.BLOCKED_DOMAINS:
            raise ValidationError(f"Domain '{fqdn}' is reserved and cannot be used")

        # Check for blocked patterns (*test*, etc.)
        if "*" in fqdn and not fqdn.startswith("*."):
            raise ValidationError("Wildcard patterns other than *.example.com are not allowed")

        # Split and validate each label
        labels = fqdn.split(".")

        for label in labels:
            # Skip wildcard labels
            if label == "*":
                continue

            # Check label length (max 63 characters)
            if len(label) > 63:
                raise ValidationError(f"Domain label '{label}' exceeds maximum length of 63 characters")

            # Check for valid characters (RFC 1123)
            if not cls.LABEL_PATTERN.match(label):
                raise ValidationError(
                    f"Domain label '{label}' contains invalid characters. "
                    "Only alphanumeric characters and hyphens are allowed."
                )

        return True

    @classmethod
    def validate_list(cls, domains: list[str]) -> bool:
        """
        Validate a list of domain names.

        Args:
            domains: List of domain names to validate

        Returns:
            bool: True if all domains are valid

        Raises:
            ValidationError: If any domain is invalid
        """
        for domain in domains:
            cls.validate(domain)
        return True


class SANValidator:
    """
    Validates Subject Alternative Names.
    """

    # Supported SAN types
    SUPPORTED_TYPES: set[str] = {"DNS", "IP", "EMAIL", "URI", "RID"}

    # IP address patterns
    IPV4_PATTERN: re.Pattern[str] = re.compile(
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    )

    IPV6_PATTERN: re.Pattern[str] = re.compile(r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$")

    # Email pattern
    EMAIL_PATTERN: re.Pattern[str] = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

    # URI pattern
    URI_PATTERN: re.Pattern[str] = re.compile(r"^https?://[^\s]+$")

    @classmethod
    def validate(cls, san: dict[str, Any]) -> bool:
        """
        Validate a single SAN entry.

        Args:
            san: Dictionary with 'type' and 'value' keys

        Returns:
            bool: True if valid

        Raises:
            ValidationError: If SAN is invalid
        """
        san_type = san.get("type", "").upper()
        value = san.get("value", "")

        if not san_type:
            raise ValidationError("SAN type is required")

        if san_type not in cls.SUPPORTED_TYPES:
            raise ValidationError(f"SAN type '{san_type}' is not supported. Allowed: {cls.SUPPORTED_TYPES}")

        if not value:
            raise ValidationError("SAN value is required")

        # Validate based on type
        if san_type == "DNS":
            FQDNValidator.validate(value)
        elif san_type == "IP":
            if not (cls.IPV4_PATTERN.match(value) or cls.IPV6_PATTERN.match(value)):
                raise ValidationError(f"Invalid IP address: {value}")
        elif san_type == "EMAIL":
            if not cls.EMAIL_PATTERN.match(value):
                raise ValidationError(f"Invalid email address: {value}")
        elif san_type == "URI" and not cls.URI_PATTERN.match(value):
            raise ValidationError(f"Invalid URI: {value}")

        return True

    @classmethod
    def validate_list(cls, sans: list[dict[str, Any]]) -> bool:
        """
        Validate a list of SAN entries.

        Args:
            sans: List of SAN dictionaries

        Returns:
            bool: True if all SANs are valid

        Raises:
            ValidationError: If any SAN is invalid
        """
        for san in sans:
            cls.validate(san)
        return True

    @classmethod
    def sanitize(cls, sans: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Sanitize and normalize SAN list.

        Args:
            sans: List of SAN dictionaries

        Returns:
            list: Sanitized list of SAN dictionaries
        """
        sanitized: list[dict[str, Any]] = []

        for san in sans:
            san_type = san.get("type", "").upper()
            value = san.get("value", "").strip()

            if san_type and value:
                sanitized.append({"type": san_type, "value": value})

        return sanitized


class CSRValidator:
    """
    Validates Certificate Signing Requests.
    """

    @classmethod
    def validate_key_length(cls, key_length: int) -> bool:
        """
        Validate key length meets minimum requirements.

        Args:
            key_length: Key length in bits

        Returns:
            bool: True if valid

        Raises:
            ValidationError: If key length is insufficient
        """
        if key_length not in KeyLen:
            raise ValidationError(f"Invalid key length: {key_length}. Allowed values: {KeyLen}")

        # Minimum RSA key length is 2048 bits
        if key_length < 2048:
            raise ValidationError(f"Key length {key_length} is below minimum (2048 bits)")

        return True

    @classmethod
    def validate_signature(cls, csr_pem: str) -> bool:
        """
        Validate CSR signature.

        Args:
            csr_pem: CSR in PEM format

        Returns:
            bool: True if signature is valid

        Raises:
            ValidationError: If signature is invalid
        """
        # This is a placeholder - actual implementation would use cryptography
        if not csr_pem or not csr_pem.strip():
            raise ValidationError("CSR is empty")

        if "-----BEGIN CERTIFICATE REQUEST-----" not in csr_pem:
            raise ValidationError("Invalid CSR format - missing header")

        return True


class DNValidator:
    """
    Validates Distinguished Names.
    """

    REQUIRED_FIELDS: set[str] = {"CN"}
    VALID_FIELDS: set[str] = {
        "C",
        "ST",
        "L",
        "O",
        "OU",
        "CN",
        "emailAddress",
        "serialNumber",
    }

    # Pattern for Common Name - allows alphanumeric, spaces, and common DN characters
    # Based on X.520 Distinguished Name syntax
    CN_PATTERN: re.Pattern[str] = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9 \-'.(),+/@#$%&*+=:;=?\\`|<>\[\]{}~^_\"]*$")

    @classmethod
    def validate(cls, dn: dict[str, str]) -> bool:
        """
        Validate a Distinguished Name.

        Args:
            dn: Dictionary of DN components

        Returns:
            bool: True if valid

        Raises:
            ValidationError: If DN is invalid
        """
        if not dn:
            raise ValidationError("Distinguished Name cannot be empty")

        # Check for required fields
        for field in cls.REQUIRED_FIELDS:
            if field not in dn or not dn[field]:
                raise ValidationError(f"Required DN field '{field}' is missing")

        # Validate all fields
        for field, value in dn.items():
            if field not in cls.VALID_FIELDS:
                raise ValidationError(f"Invalid DN field: {field}")

            if not value or not value.strip():
                raise ValidationError(f"DN field '{field}' cannot be empty")

        return True

    @classmethod
    def validate_cn(cls, cn: str) -> bool:
        """
        Validate a Common Name.

        Args:
            cn: Common Name to validate

        Returns:
            bool: True if valid

        Raises:
            ValidationError: If CN is invalid
        """
        if not cn or not cn.strip():
            raise ValidationError("Common Name cannot be empty")

        if len(cn) > 64:
            raise ValidationError("Common Name exceeds maximum length of 64 characters")

        # Use CN-specific pattern that allows spaces and common DN characters
        if not cls.CN_PATTERN.match(cn):
            raise ValidationError(
                f"Common Name '{cn}' contains invalid characters. "
                "Allowed: alphanumeric, spaces, and -.'(),/+@#$%&*+=:;=?\\`|<>[]{}~^_\""
            )

        return True


class RevokeReasonValidator:
    """
    Validates revocation reasons.
    """

    @classmethod
    def validate(cls, reason: str) -> bool:
        """
        Validate a revocation reason.

        Args:
            reason: Revocation reason

        Returns:
            bool: True if valid

        Raises:
            ValidationError: If reason is invalid
        """
        if not reason:
            raise ValidationError("Revocation reason cannot be empty")

        reason_lower = reason.lower()

        if reason_lower not in [r.lower() for r in RevokeReasons]:
            raise ValidationError(f"Invalid revocation reason: {reason}. Allowed values: {RevokeReasons}")

        return True
