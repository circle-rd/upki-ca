"""
Allowed options and values for uPKI CA Server.

This module defines the allowed values for various certificate
and configuration options.

Author: uPKI Team
License: MIT
"""

from typing import Final

# Key length options
KeyLen: Final[list[int]] = [1024, 2048, 4096]

# Key types
KeyTypes: Final[list[str]] = ["rsa", "dsa"]

# Digest algorithms
Digest: Final[list[str]] = ["md5", "sha1", "sha256", "sha512"]

# Certificate types
CertTypes: Final[list[str]] = ["user", "server", "email", "sslCA"]

# Profile types
Types: Final[list[str]] = ["server", "client", "email", "objsign", "sslCA", "emailCA"]

# Key usage extensions
Usages: Final[list[str]] = [
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

# Extended key usage extensions
ExtendedUsages: Final[list[str]] = [
    "serverAuth",
    "clientAuth",
    "codeSigning",
    "emailProtection",
    "timeStamping",
    "OCSPSigning",
]

# DN field types
Fields: Final[list[str]] = ["C", "ST", "L", "O", "OU", "CN", "emailAddress"]

# SAN types allowed
SanTypes: Final[list[str]] = ["DNS", "IP", "EMAIL", "URI", "RID"]

# Revocation reasons
RevokeReasons: Final[list[str]] = [
    "unspecified",
    "keyCompromise",
    "cACompromise",
    "affiliationChanged",
    "superseded",
    "cessationOfOperation",
    "certificateHold",
    "removeFromCRL",
    "privilegeWithdrawn",
    "aACompromise",
]

# Certificate states
CertStates: Final[list[str]] = ["pending", "issued", "revoked", "expired", "renewed"]

# Client modes
ClientModes: Final[list[str]] = ["all", "register", "manual"]

# Default configuration values
DEFAULT_KEY_TYPE: Final[str] = "rsa"
DEFAULT_KEY_LENGTH: Final[int] = 4096
DEFAULT_DIGEST: Final[str] = "sha256"
DEFAULT_DURATION: Final[int] = 365  # days

# Built-in profile names
BUILTIN_PROFILES: Final[list[str]] = ["ca", "ra", "server", "user", "admin"]

# Profile to certificate type mapping
PROFILE_CERT_TYPES: Final[dict[str, str]] = {
    "ca": "sslCA",
    "ra": "sslCA",
    "server": "server",
    "user": "user",
    "admin": "user",
}

# Default durations by profile (in days)
PROFILE_DURATIONS: Final[dict[str, int]] = {
    "ca": 3650,  # 10 years
    "ra": 365,  # 1 year
    "server": 365,  # 1 year
    "user": 30,  # 30 days
    "admin": 365,  # 1 year
}
