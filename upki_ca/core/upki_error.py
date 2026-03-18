"""
uPKI Error classes.

This module defines custom exceptions for the uPKI CA Server.

Author: uPKI Team
License: MIT
"""


class UpkiError(Exception):
    """Base exception class for all uPKI errors."""

    def __init__(self, message: str = "An error occurred", code: int = 1) -> None:
        """
        Initialize an UpkiError.

        Args:
            message: Error message
            code: Error code for programmatic error handling
        """
        super().__init__(message)
        self.message = message
        self.code = code

    def __str__(self) -> str:
        """Return string representation of the error."""
        return f"[{self.code}] {self.message}"


class StorageError(UpkiError):
    """Exception raised for storage-related errors."""

    def __init__(self, message: str = "Storage error occurred") -> None:
        """Initialize a StorageError."""
        super().__init__(message, code=100)


class ValidationError(UpkiError):
    """Exception raised for validation errors."""

    def __init__(self, message: str = "Validation error occurred") -> None:
        """Initialize a ValidationError."""
        super().__init__(message, code=200)


class CertificateError(UpkiError):
    """Exception raised for certificate-related errors."""

    def __init__(self, message: str = "Certificate error occurred") -> None:
        """Initialize a CertificateError."""
        super().__init__(message, code=300)


class KeyError(UpkiError):
    """Exception raised for key-related errors."""

    def __init__(self, message: str = "Key error occurred") -> None:
        """Initialize a KeyError."""
        super().__init__(message, code=400)


class ProfileError(UpkiError):
    """Exception raised for profile-related errors."""

    def __init__(self, message: str = "Profile error occurred") -> None:
        """Initialize a ProfileError."""
        super().__init__(message, code=500)


class AuthorityError(UpkiError):
    """Exception raised for CA authority errors."""

    def __init__(self, message: str = "Authority error occurred") -> None:
        """Initialize an AuthorityError."""
        super().__init__(message, code=600)


class CommunicationError(UpkiError):
    """Exception raised for communication errors."""

    def __init__(self, message: str = "Communication error occurred") -> None:
        """Initialize a CommunicationError."""
        super().__init__(message, code=700)


class ConfigurationError(UpkiError):
    """Exception raised for configuration errors."""

    def __init__(self, message: str = "Configuration error occurred") -> None:
        """Initialize a ConfigurationError."""
        super().__init__(message, code=800)


class RevocationError(UpkiError):
    """Exception raised for revocation-related errors."""

    def __init__(self, message: str = "Revocation error occurred") -> None:
        """Initialize a RevocationError."""
        super().__init__(message, code=900)
