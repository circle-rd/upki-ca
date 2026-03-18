"""
uPKI Logger module.

This module provides logging functionality for the uPKI CA Server.

Author: uPKI Team
License: MIT
"""

from __future__ import annotations

import logging
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from upki_ca.core.common import Common


class UpkiLoggerAdapter(logging.Logger):
    """
    Extended Logger class for uPKI operations.

    Provides an audit method for structured audit logging in addition
    to standard logging capabilities.
    """

    def audit(
        self,
        logger_name: str,
        action: str,
        subject: str,
        result: str,
        **details: Any,
    ) -> None:
        """
        Log an audit event.

        Args:
            logger_name: Name of the audit logger
            action: Action performed (e.g., "CERTIFICATE_ISSUED")
            subject: Subject of the action (e.g., DN, CN)
            result: Result of the action ("SUCCESS" or "FAILURE")
            **details: Additional audit details
        """
        timestamp = datetime.now(UTC).isoformat()
        details_str = " ".join(f"{k}={v}" for k, v in details.items()) if details else ""

        message = f"AUDIT | {timestamp} | {action} | {subject} | {result} | {details_str}"
        self.info(message)


class UpkiLogger:
    """
    Logger class for uPKI CA operations.

    Provides structured logging with timestamps and various log levels
    for audit and debugging purposes.
    """

    _loggers: dict[str, UpkiLoggerAdapter] = {}
    _log_dir: str = ""
    _log_level: int = logging.INFO

    @classmethod
    def initialize(cls, log_dir: str | None = None, level: int = logging.INFO) -> None:
        """
        Initialize the logger system.

        Args:
            log_dir: Directory for log files (defaults to ~/.upki/ca/logs)
            level: Logging level (default: INFO)
        """
        if log_dir:
            cls._log_dir = log_dir
        else:
            cls._log_dir = str(Path(Common.get_ca_dir()) / "logs")

        # Ensure log directory exists
        Common.ensure_dir(cls._log_dir)

        cls._log_level = level

    @classmethod
    def get_logger(cls, name: str) -> UpkiLoggerAdapter:
        """
        Get or create a logger with the specified name.

        Args:
            name: Logger name

        Returns:
            UpkiLoggerAdapter: Configured logger instance with audit support
        """
        if name in cls._loggers:
            return cls._loggers[name]  # type: ignore[return-value]

        # Use the custom adapter class
        logger = logging.getLogger(name)
        # Set the logger class to our adapter
        logger.__class__ = UpkiLoggerAdapter
        logger.setLevel(cls._log_level)

        # Clear any existing handlers
        logger.handlers.clear()

        # Create console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(cls._log_level)

        # Create formatter
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        console_handler.setFormatter(formatter)

        logger.addHandler(console_handler)

        # Add file handler if log directory is set
        if cls._log_dir:
            log_file = Path(cls._log_dir) / f"{name}.log"
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(cls._log_level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

        cls._loggers[name] = logger  # type: ignore[assignment]
        return logger  # type: ignore[return-value]

    @classmethod
    def log_event(
        cls,
        logger_name: str,
        event_type: str,
        message: str,
        level: int = logging.INFO,
        **kwargs: Any,
    ) -> None:
        """
        Log an event with structured data.

        Args:
            logger_name: Name of the logger to use
            event_type: Type of event (e.g., "CERT_ISSUED", "KEY_GENERATED")
            message: Log message
            level: Log level
            **kwargs: Additional event data to log
        """
        logger = cls.get_logger(logger_name)

        # Build structured message
        extra_data = " ".join(f"{k}={v}" for k, v in kwargs.items()) if kwargs else ""
        full_message = f"[{event_type}] {message} {extra_data}".strip()

        logger.log(level, full_message)

    @classmethod
    def audit(cls, logger_name: str, action: str, subject: str, result: str, **details: Any) -> None:
        """
        Log an audit event.

        Args:
            logger_name: Name of the audit logger
            action: Action performed (e.g., "CERTIFICATE_ISSUED")
            subject: Subject of the action (e.g., DN, CN)
            result: Result of the action ("SUCCESS" or "FAILURE")
            **details: Additional audit details
        """
        logger = cls.get_logger(logger_name)

        timestamp = datetime.now(UTC).isoformat()
        details_str = " ".join(f"{k}={v}" for k, v in details.items()) if details else ""

        message = f"AUDIT | {timestamp} | {action} | {subject} | {result} | {details_str}"
        logger.info(message)

    @classmethod
    def error(cls, logger_name: str, error: Exception, context: str = "") -> None:
        """
        Log an error with context.

        Args:
            logger_name: Name of the logger
            error: Exception to log
            context: Additional context about the error
        """
        logger = cls.get_logger(logger_name)

        context_str = f" [{context}]" if context else ""
        message = f"ERROR{context_str}: {type(error).__name__}: {str(error)}"

        logger.error(message, exc_info=True)

    @classmethod
    def set_level(cls, level: int) -> None:
        """
        Set the logging level for all loggers.

        Args:
            level: Logging level (e.g., logging.DEBUG, logging.INFO)
        """
        cls._log_level = level
        for logger in cls._loggers.values():
            logger.setLevel(level)
            for handler in logger.handlers:
                handler.setLevel(level)


# Default logger instance
def get_logger(name: str = "upki") -> UpkiLoggerAdapter:
    """
    Get a logger instance.

    Args:
        name: Logger name

    Returns:
        UpkiLoggerAdapter: Logger instance with audit support
    """
    return UpkiLogger.get_logger(name)
