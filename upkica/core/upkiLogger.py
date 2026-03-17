# -*- coding: utf-8 -*-

"""
Logging utilities for uPKI operations.

This module provides the UpkiLogger class for configurable logging
to both file and console with support for log rotation and colored output.
"""

import os
import errno
import sys
import logging
import logging.handlers
from typing import Any


class UpkiLogger:
    """Logging class for uPKI operations.

    Provides configurable logging to file with rotation and optional
    console output with colored formatting. Supports different log
    levels and can forward logs to a syslog server.

    Attributes:
        logger: The underlying Python logging.Logger instance.
        level: Current logging level.
        verbose: Whether to output colored messages to console.

    Args:
        filename: Path to the log file.
        level: Logging level (default: logging.WARNING).
        proc_name: Process name for logging (default: module name).
        verbose: Enable colored console output (default: False).
        backup: Number of backup log files to keep (default: 3).
        when: Log rotation interval (default: "midnight").
        syshost: Syslog server hostname (optional).
        sysport: Syslog server port (default: 514).

    Raises:
        Exception: If log directory cannot be created or log file is not writable.
        SystemExit: If unable to write to log file.

    Example:
        >>> logger = UpkiLogger("/var/log/upki/upki.log", verbose=True)
        >>> logger.info("Server started successfully")
    """

    def __init__(
        self,
        filename: str,
        level: int | str = logging.WARNING,
        proc_name: str | None = None,
        verbose: bool = False,
        backup: int = 3,
        when: str = "midnight",
        syshost: str | None = None,
        sysport: int = 514,
    ) -> None:
        if proc_name is None:
            proc_name = __name__

        try:
            self.level = int(level)  # type: ignore[arg-type]
        except ValueError:
            self.level = logging.INFO

        self.logger = logging.getLogger(proc_name)

        try:
            os.makedirs(os.path.dirname(filename))
        except OSError as err:
            if (err.errno != errno.EEXIST) or not os.path.isdir(
                os.path.dirname(filename)
            ):
                raise Exception(err)

        try:
            handler = logging.handlers.TimedRotatingFileHandler(
                filename, when=when, backupCount=backup
            )
        except IOError:
            sys.stderr.write(f"[!] Unable to write to log file: {filename}\n")
            sys.exit(1)

        formatter = logging.Formatter("%(asctime)s %(levelname)-8s %(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(self.level)

        self.verbose: bool = verbose

    def debug(
        self, msg: Any, color: str | None = None, light: bool | None = None
    ) -> None:
        """Log a debug message.

        Args:
            msg: The message to log.
            color: Optional color name for console output.
            light: Use light/bold formatting for console output.
        """
        self.write(msg, level=logging.DEBUG, color=color, light=light)

    def info(
        self, msg: Any, color: str | None = None, light: bool | None = None
    ) -> None:
        """Log an info message.

        Args:
            msg: The message to log.
            color: Optional color name for console output.
            light: Use light/bold formatting for console output.
        """
        self.write(msg, level=logging.INFO, color=color, light=light)

    def warning(
        self, msg: Any, color: str | None = None, light: bool | None = None
    ) -> None:
        """Log a warning message.

        Args:
            msg: The message to log.
            color: Optional color name for console output.
            light: Use light/bold formatting for console output.
        """
        self.write(msg, level=logging.WARNING, color=color, light=light)

    def error(
        self, msg: Any, color: str | None = None, light: bool | None = None
    ) -> None:
        """Log an error message.

        Args:
            msg: The message to log.
            color: Optional color name for console output.
            light: Use light/bold formatting for console output.
        """
        self.write(msg, level=logging.ERROR, color=color, light=light)

    def critical(
        self, msg: Any, color: str | None = None, light: bool | None = None
    ) -> None:
        """Log a critical message.

        Args:
            msg: The message to log.
            color: Optional color name for console output.
            light: Use light/bold formatting for console output.
        """
        self.write(msg, level=logging.CRITICAL, color=color, light=light)

    def write(
        self,
        message: Any,
        level: int | str | None = None,
        color: str | None = None,
        light: bool | None = None,
    ) -> None:
        """Write a log message with specified level.

        Accepts log message with level set as string or logging integer.
        Outputs to file and optionally to console with color formatting.

        Args:
            message: The message to log.
            level: Log level (int or string like "DEBUG", "INFO", etc.).
            color: Optional color name for console output.
            light: Use light/bold formatting for console output.

        Raises:
            Exception: If an invalid log level is provided.
        """
        # Clean message
        message = str(message).rstrip()

        # Only log if there is a message (not just a new line)
        if message == "":
            return

        # Autoset level if necessary
        if level is None:
            level = self.level

        # Convert string level to logging int
        if isinstance(level, str):
            level_upper = level.upper()
            if level_upper == "DEBUG":
                level = logging.DEBUG
            elif level_upper in ["INFO", "INFOS"]:
                level = logging.INFO
            elif level_upper == "WARNING":
                level = logging.WARNING
            elif level_upper == "ERROR":
                level = logging.ERROR
            elif level_upper == "CRITICAL":
                level = logging.CRITICAL
            else:
                level = self.level

        # Output with correct level
        if level == logging.DEBUG:
            def_color = "BLUE"
            def_light = True
            prefix = "*"
            self.logger.debug(message)
        elif level == logging.INFO:
            def_color = "GREEN"
            def_light = False
            prefix = "+"
            self.logger.info(message)
        elif level == logging.WARNING:
            def_color = "YELLOW"
            def_light = False
            prefix = "-"
            self.logger.warning(message)
        elif level == logging.ERROR:
            def_color = "RED"
            def_light = False
            prefix = "!"
            self.logger.error(message)
        elif level == logging.CRITICAL:
            def_color = "RED"
            def_light = True
            prefix = "!"
            self.logger.critical(message)
        else:
            raise Exception("Invalid log level")

        if color is None:
            color = def_color
        if light is None:
            light = def_light

        # Output to CLI if verbose flag is set
        if self.verbose:
            color_upper = color.upper()
            # Position color based on level if not forced
            c = "\033[1" if light else "\033[0"
            if color_upper == "BLACK":
                c += ";30m"
            elif color_upper == "BLUE":
                c += ";34m"
            elif color_upper == "GREEN":
                c += ";32m"
            elif color_upper == "CYAN":
                c += ";36m"
            elif color_upper == "RED":
                c += ";31m"
            elif color_upper == "PURPLE":
                c += ";35m"
            elif color_upper == "YELLOW":
                c += ";33m"
            elif color_upper == "WHITE":
                c += ";37m"
            else:
                # No Color
                c += "m"

            if level >= self.level:
                try:
                    sys.stdout.write(f"{c}[{prefix}] {message}\033[0m\n")
                except UnicodeDecodeError:
                    sys.stdout.write("Cannot print message, check your logs...")
                sys.stdout.flush()
