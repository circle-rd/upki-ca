# -*- coding:utf-8 -*-

"""
Common utility functions and classes for uPKI operations.

This module provides the Common class which contains shared functionality
used across the uPKI project including YAML file handling, profile validation,
directory creation, and interactive CLI prompts.
"""

import os
import re
import sys
import yaml
import validators
from typing import Any

import upkica
from upkica.core.options import Options
from upkica.core.upkiLogger import UpkiLogger


class Common:
    """Common utility methods for uPKI operations.

    Provides shared functionality including YAML file operations, profile
    validation, directory creation, DN/CN extraction, and interactive prompts.

    Attributes:
        _logger: Logger instance for output.
        _fuzz: Whether to skip validation during fuzzing.
        _allowed: Options instance containing allowed values.

    Args:
        logger: UpkiLogger instance for logging output.
        fuzz: Enable fuzzing mode to skip validation (default: False).

    Example:
        >>> logger = UpkiLogger("/var/log/upki.log")
        >>> common = Common(logger)
        >>> common.output("Operation completed", level="INFO")
    """

    def __init__(self, logger: UpkiLogger, fuzz: bool = False) -> None:
        """Initialize Common utility with logger.

        Args:
            logger: UpkiLogger instance for logging.
            fuzz: Enable fuzzing mode (default: False).
        """
        self._logger: UpkiLogger = logger
        self._fuzz: bool = fuzz
        self._allowed: Options = Options()

    def output(
        self,
        msg: Any,
        level: str | None = None,
        color: str | None = None,
        light: bool = False,
    ) -> None:
        """Generate output to CLI and log file.

        Args:
            msg: The message to output.
            level: Log level (default: None uses logger default).
            color: Optional color for console output.
            light: Use light/bold formatting (default: False).
        """
        try:
            self._logger.write(msg, level=level, color=color, light=light)
        except Exception as err:
            sys.stdout.write(f"Unable to log: {err}")

    def _storeYAML(self, yaml_file: str, data: dict) -> bool:
        """Store data in YAML file.

        Args:
            yaml_file: Path to the YAML file to write.
            data: Dictionary data to serialize to YAML.

        Returns:
            True if successful.

        Raises:
            IOError: If file cannot be written.
        """
        with open(yaml_file, "wt") as raw:
            raw.write(yaml.safe_dump(data, default_flow_style=False, indent=4))
        return True

    def _parseYAML(self, yaml_file: str) -> dict:
        """Parse YAML file and return data as dictionary.

        Args:
            yaml_file: Path to the YAML file to read.

        Returns:
            Dictionary containing parsed YAML data.

        Raises:
            IOError: If file cannot be read.
            yaml.YAMLError: If YAML is invalid.
        """
        with open(yaml_file, "rt") as stream:
            cfg = yaml.safe_load(stream.read())
        return cfg

    def _check_profile(self, data: dict) -> dict:
        """Validate and normalize certificate profile data.

        Validates all required fields in a certificate profile including
        key type, key length, duration, digest, certificate type, subject,
        key usage, and extended key usage.

        Args:
            data: Dictionary containing profile configuration.

        Returns:
            Dictionary with validated and normalized profile data.

        Raises:
            KeyError: If required fields are missing.
            ValueError: If field values are invalid.
            NotImplementedError: If key type, length, or digest is not supported.
        """
        data["keyType"] = data["keyType"].lower()
        data["keyLen"] = int(data["keyLen"])
        data["duration"] = int(data["duration"])
        data["digest"] = data["digest"].lower()
        data["certType"] = data["certType"]
        data["subject"]
        data["keyUsage"]

        # Auto-setup optional values
        if "altnames" not in data:
            data["altnames"] = False

        if "crl" not in data:
            data["crl"] = None

        if "ocsp" not in data:
            data["ocsp"] = None

        # Start building clean object
        clean: dict = {}
        clean["altnames"] = data["altnames"]
        clean["crl"] = data["crl"]
        clean["ocsp"] = data["ocsp"]

        if "domain" in data:
            if not validators.domain(data["domain"]):
                raise ValueError("Domain is invalid")
            clean["domain"] = data["domain"]
        else:
            clean["domain"] = None

        if "extendedKeyUsage" not in data:
            data["extendedKeyUsage"] = []

        if data["keyType"] not in self._allowed.KeyTypes:
            raise NotImplementedError(
                f"Private key only support {self._allowed.KeyTypes} key type"
            )
        clean["keyType"] = data["keyType"]

        if data["keyLen"] not in self._allowed.KeyLen:
            raise NotImplementedError(
                f"Private key only support {self._allowed.KeyLen} key size"
            )
        clean["keyLen"] = data["keyLen"]

        if not validators.between(data["duration"], 1, 36500):
            raise ValueError("Duration is invalid")
        clean["duration"] = data["duration"]

        if data["digest"] not in self._allowed.Digest:
            raise NotImplementedError(
                f"Hash signing only support {self._allowed.Digest}"
            )
        clean["digest"] = data["digest"]

        if not isinstance(data["certType"], list):
            raise ValueError("Certificate type values are incorrect")
        for value in data["certType"]:
            if value not in self._allowed.CertTypes:
                raise NotImplementedError(
                    f"Profiles only support {self._allowed.CertTypes} certificate types"
                )
        clean["certType"] = data["certType"]

        if not isinstance(data["subject"], list):
            raise ValueError("Subject values are incorrect")
        if not len(data["subject"]):
            raise ValueError("Subject values can not be empty")
        if len(data["subject"]) < 4:
            raise ValueError(
                "Subject seems too short (minimum 4 entries: /C=XX/ST=XX/L=XX/O=XX)"
            )
        clean["subject"] = []
        # Set required keys
        required = ["C", "ST", "L", "O"]
        for subj in data["subject"]:
            if not isinstance(subj, dict):
                raise ValueError("Subject entries are incorrect")
            try:
                key = list(subj.keys())[0]
                value = subj[key]
            except IndexError:
                continue
            key = key.upper()
            if key not in self._allowed.Fields:
                raise ValueError(
                    f"Subject only support fields from {self._allowed.Fields}"
                )
            clean["subject"].append({key: value})
            # Allow multiple occurrences
            if key in required:
                required.remove(key)
        if required:
            raise ValueError(
                "Subject fields required at least presence of: C (country), ST (state), L (locality), O (organisation)"
            )

        if not isinstance(data["keyUsage"], list):
            raise ValueError("Key values are incorrect")
        clean["keyUsage"] = []
        for kuse in data["keyUsage"]:
            if kuse not in self._allowed.Usages:
                raise ValueError(
                    f"Key usage only support fields from {self._allowed.Usages}"
                )
            clean["keyUsage"].append(kuse)

        if not isinstance(data["extendedKeyUsage"], list):
            raise ValueError("Extended Key values are incorrect")
        clean["extendedKeyUsage"] = []
        for ekuse in data["extendedKeyUsage"]:
            if ekuse not in self._allowed.ExtendedUsages:
                raise ValueError(
                    f"Extended Key usage only support fields from {self._allowed.ExtendedUsages}"
                )
            clean["extendedKeyUsage"].append(ekuse)

        return clean

    def _check_node(self, params: dict, profile: dict) -> dict:
        """Check and normalize certificate request parameters.

        Validates parameters from a certificate request node against a profile,
        applying profile defaults for missing values.

        Args:
            params: Dictionary of request parameters.
            profile: Dictionary of profile defaults.

        Returns:
            Dictionary with validated and normalized parameters.
        """
        clean: dict = {}
        try:
            if isinstance(params["sans"], list):
                clean["sans"] = params["sans"]
            elif isinstance(params["sans"], str):
                clean["sans"] = [san.strip() for san in params["sans"].split(",")]
        except KeyError:
            clean["sans"] = []

        try:
            clean["keyType"] = self._allowed.clean(params["keyType"], "KeyTypes")
        except KeyError:
            clean["keyType"] = profile["keyType"]

        try:
            clean["keyLen"] = self._allowed.clean(int(params["keyLen"]), "KeyLen")
        except (KeyError, ValueError):
            clean["keyLen"] = profile["keyLen"]

        try:
            clean["duration"] = int(params["duration"])
            if 0 >= clean["duration"] <= 36500:
                clean["duration"] = profile["duration"]
        except (KeyError, ValueError):
            clean["duration"] = profile["duration"]

        try:
            clean["digest"] = self._allowed.clean(params["digest"], "Digest")
        except KeyError:
            clean["digest"] = profile["digest"]

        return clean

    def _mkdir_p(self, path: str) -> bool:
        """Create directories from path if they don't exist.

        Creates all intermediate directories in the path, similar to
        mkdir -p in shell.

        Args:
            path: File or directory path to create.

        Returns:
            True if directories were created or already exist.

        Raises:
            OSError: If directory creation fails for reasons other than existing.
        """
        # Extract directory from path if filename
        path = os.path.dirname(path)

        self.output(f"Create {path} directory...", level="DEBUG")
        try:
            os.makedirs(path)
        except OSError as err:
            if err.errno == 17 and os.path.isdir(path):  # EEXIST
                pass
            else:
                raise OSError(err)

        return True

    def _get_dn(self, subject: Any) -> str:
        """Convert x509 subject object to standard DN string.

        Args:
            subject: x509 Subject object.

        Returns:
            DN string in format /C=XX/ST=XX/L=XX/O=XX/CN=xxx.
        """
        rdn = []
        for n in subject.rdns:
            rdn.append(n.rfc4514_string())
        dn = "/".join(rdn)
        return "/" + dn

    def _get_cn(self, dn: str) -> str:
        """Extract CN value from Distinguished Name string.

        Args:
            dn: Distinguished Name string (e.g., /C=US/O=Org/CN=example.com).

        Returns:
            The CN value extracted from the DN.

        Raises:
            ValueError: If CN cannot be found or is invalid.
        """
        try:
            cn = str(dn).split("CN=")[1]
        except Exception as e:
            raise ValueError(f"Unable to get CN from DN string: {e}")

        # Ensure cn is valid
        if cn is None or not len(cn):
            raise ValueError("Empty CN option")
        if not re.match(r"^[\w\-_\.\s@]+$", cn):
            raise ValueError("Invalid CN")

        return cn

    def _prettify(
        self, serial: int | None, group: int = 2, separator: str = ":"
    ) -> str | None:
        """Format serial number as hex string with separators.

        Converts a serial number (integer or bytes) to a formatted hex string
        with separators between groups of characters.

        Args:
            serial: Serial number as integer or bytes.
            group: Number of hex characters per group (default: 2).
            separator: Separator between groups (default: ":").

        Returns:
            Formatted string like "XX:XX:XX:XX:XX" or None if serial is None.

        Raises:
            ValueError: If serial cannot be converted.
        """
        if serial is None:
            return None

        try:
            human_serial = f"{serial:2x}".upper()
            return separator.join(
                human_serial[i : i + group] for i in range(0, len(human_serial), group)
            )
        except Exception as e:
            raise ValueError(f"Unable to convert serial number: {e}")

    def _ask(
        self,
        msg: str,
        default: str | None = None,
        regex: str | None = None,
        mandatory: bool = True,
    ) -> str:
        """Prompt user for input in CLI with validation.

        Displays a prompt to the user and optionally validates the input
        against a regex pattern or known validation rules.

        Args:
            msg: Prompt message to display.
            default: Default value if user presses enter without input.
            regex: Validation pattern (or special values: "domain", "email", "ipv4", "ipv6", "port").
            mandatory: Whether input is required (default: True).

        Returns:
            User input string.

        Raises:
            ValueError: If mandatory input is empty or invalid.
        """
        while True:
            if default is not None:
                rep = input(f"{msg} [{default}]: ")
            else:
                rep = input(f"{msg}: ")

            if len(rep) == 0:
                if default is None and mandatory:
                    self.output("Sorry this value is mandatory.", level="ERROR")
                    continue
                rep = default

            # Do not check anything while fuzzing
            if not self._fuzz and regex is not None:
                regex_lower = regex.lower()
                if regex_lower == "domain" and not validators.domain(rep):
                    self.output("Sorry this value is invalid.", level="ERROR")
                    continue
                elif regex_lower == "email" and not validators.email(rep):
                    self.output("Sorry this value is invalid.", level="ERROR")
                    continue
                elif regex_lower == "ipv4" and not validators.ipv4(rep):
                    self.output("Sorry this value is invalid.", level="ERROR")
                    continue
                elif regex_lower == "ipv6" and not validators.ipv6(rep):
                    self.output("Sorry this value is invalid.", level="ERROR")
                    continue
                elif regex_lower == "port" and not validators.between(
                    rep, min=1, max=65535
                ):
                    self.output("Sorry this value is invalid.", level="ERROR")
                    continue
                elif regex is not None and not re.match(regex, rep):  # type: ignore[arg-type]
                    self.output("Sorry this value is invalid.", level="ERROR")
                    continue

            break

        return rep if rep is not None else ""
