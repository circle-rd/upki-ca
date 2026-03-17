# -*- coding:utf-8 -*-

"""
Configuration options for uPKI certificate operations.

This module defines the Options class that contains all allowed values
and validation rules for certificate parameters used throughout uPKI.
"""

import json


class Options:
    """Configuration options for uPKI certificate operations.

    This class contains all allowed values and defaults for various
    certificate parameters including key types, key lengths, digest
    algorithms, certificate types, and X.509 fields.

    Attributes:
        KeyLen: List of allowed RSA key lengths in bits.
        CertTypes: List of allowed certificate types.
        Digest: List of allowed hash digest algorithms.
        ExtendedUsages: List of allowed extended key usage OIDs.
        Fields: List of allowed X.509 subject field names.
        KeyTypes: List of allowed asymmetric key algorithms.
        Types: List of allowed certificate usage types.
        Usages: List of allowed key usage flags.

    Example:
        >>> options = Options()
        >>> print(options.KeyLen)
        [1024, 2048, 4096]
    """

    def __init__(self) -> None:
        """Initialize default options with allowed values."""
        self.KeyLen: list[int] = [1024, 2048, 4096]
        self.CertTypes: list[str] = ["user", "server", "email", "sslCA"]
        self.Digest: list[str] = ["md5", "sha1", "sha256", "sha512"]
        self.ExtendedUsages: list[str] = [
            "serverAuth",
            "clientAuth",
            "codeSigning",
            "emailProtection",
            "timeStamping",
            "OCSPSigning",
        ]
        self.Fields: list[str] = ["C", "ST", "L", "O", "OU", "CN", "emailAddress"]
        self.KeyTypes: list[str] = ["rsa", "dsa"]
        self.Types: list[str] = [
            "server",
            "client",
            "email",
            "objsign",
            "sslCA",
            "emailCA",
        ]
        self.Usages: list[str] = [
            "digitalSignature",
            "nonRepudiation",
            "keyEncipherment",
            "dataEncipherment",
            "keyAgreement",
            "keyCertSign",
            "cRLSign",
            "encipherOnly",
            "decipherOnly",
        ]

    def __str__(self) -> str:
        """Return JSON representation of options.

        Returns:
            JSON string with pretty indentation (4 spaces).
        """
        return json.dumps(vars(self), sort_keys=True, indent=4)

    def json(self, minimize: bool = False) -> str:
        """Return JSON representation of options.

        Args:
            minimize: If True, return compact JSON without indentation or newlines.

        Returns:
            JSON string representation of options.
        """
        indent = None if minimize else 4
        return json.dumps(vars(self), sort_keys=True, indent=indent)

    def clean(self, data: int | str, field: str) -> int | str:
        """Validate and return a value against allowed options.

        Args:
            data: The value to validate.
            field: The field name to check against allowed values.

        Returns:
            The validated data if it exists in allowed values.

        Raises:
            ValueError: If data is None or field is None.
            NotImplementedError: If field is not a valid option field.
            ValueError: If data is not in the allowed values for the field.
        """
        if data is None:
            raise ValueError("Null data")
        if field is None:
            raise ValueError("Null field")

        if field not in vars(self).keys():
            raise NotImplementedError("Unsupported field")

        allowed = getattr(self, field)
        if data not in allowed:
            raise ValueError("Invalid value")

        return data
