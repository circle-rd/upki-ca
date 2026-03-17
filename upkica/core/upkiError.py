# -*- coding: utf-8 -*-

"""
Custom exception classes for uPKI operations.

This module defines the base exception class used throughout the uPKI
project for handling and reporting errors.
"""

from typing import Any


class UPKIError(Exception):
    """Custom exception class for uPKI errors.

    Attributes:
        code: Numeric error code identifying the error type.
        reason: Human-readable description of the error.

    Args:
        code: Numeric error code (default 0).
        reason: Error message describing what went wrong (will be converted to string).

    Raises:
        ValueError: If code is not a valid integer.

    Example:
        >>> raise UPKIError(404, "Certificate not found")
    """

    def __init__(self, code: int = 0, reason: Any = None) -> None:
        if not isinstance(code, int):
            raise ValueError("Invalid error code")
        self.code: int = code
        self.reason: str = str(reason) if reason is not None else ""

    def __str__(self) -> str:
        return f"Error [{self.code}]: {self.reason}"

    def __repr__(self) -> str:
        return f"UPKIError(code={self.code}, reason={self.reason!r})"
