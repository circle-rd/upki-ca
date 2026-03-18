"""
Certificate Profile management for uPKI CA Server.

This module provides the Profiles class for managing certificate
profiles and templates.

Author: uPKI Team
License: MIT
"""

from __future__ import annotations

from typing import Any, Optional

from upkica.core.common import Common
from upkica.core.options import (
    BUILTIN_PROFILES,
    DEFAULT_DIGEST,
    DEFAULT_DURATION,
    DEFAULT_KEY_LENGTH,
    DEFAULT_KEY_TYPE,
    PROFILE_DURATIONS,
)
from upkica.core.upkiError import ProfileError
from upkica.core.validators import DNValidator, FQDNValidator
from upkica.storage.abstractStorage import AbstractStorage


class Profiles(Common):
    """
    Manages certificate profiles.

    Profiles define certificate parameters and constraints such as
    key type, key length, validity period, and extensions.
    """

    # Built-in default profiles
    DEFAULT_PROFILES: dict[str, dict[str, Any]] = {
        "ca": {
            "keyType": "rsa",
            "keyLen": 4096,
            "duration": PROFILE_DURATIONS["ca"],
            "digest": DEFAULT_DIGEST,
            "altnames": False,
            "subject": {"C": "FR", "O": "uPKI", "OU": "CA", "CN": "uPKI Root CA"},
            "keyUsage": ["keyCertSign", "cRLSign"],
            "extendedKeyUsage": [],
            "certType": "sslCA",
        },
        "ra": {
            "keyType": "rsa",
            "keyLen": 4096,
            "duration": PROFILE_DURATIONS["ra"],
            "digest": DEFAULT_DIGEST,
            "altnames": True,
            "subject": {"C": "FR", "O": "uPKI", "OU": "RA", "CN": "uPKI RA"},
            "keyUsage": ["digitalSignature", "keyEncipherment"],
            "extendedKeyUsage": ["serverAuth", "clientAuth"],
            "certType": "sslCA",
        },
        "server": {
            "keyType": "rsa",
            "keyLen": DEFAULT_KEY_LENGTH,
            "duration": PROFILE_DURATIONS["server"],
            "digest": DEFAULT_DIGEST,
            "altnames": True,
            "domain": "",
            "subject": {"C": "FR", "O": "Company", "OU": "Servers", "CN": ""},
            "keyUsage": ["digitalSignature", "keyEncipherment"],
            "extendedKeyUsage": ["serverAuth"],
            "certType": "server",
        },
        "user": {
            "keyType": "rsa",
            "keyLen": 2048,
            "duration": PROFILE_DURATIONS["user"],
            "digest": DEFAULT_DIGEST,
            "altnames": True,
            "subject": {"C": "FR", "O": "Company", "OU": "Users", "CN": ""},
            "keyUsage": ["digitalSignature", "nonRepudiation"],
            "extendedKeyUsage": ["clientAuth"],
            "certType": "user",
        },
        "admin": {
            "keyType": "rsa",
            "keyLen": DEFAULT_KEY_LENGTH,
            "duration": PROFILE_DURATIONS["admin"],
            "digest": DEFAULT_DIGEST,
            "altnames": True,
            "subject": {"C": "FR", "O": "Company", "OU": "Admins", "CN": ""},
            "keyUsage": ["digitalSignature", "nonRepudiation"],
            "extendedKeyUsage": ["clientAuth"],
            "certType": "user",
        },
    }

    def __init__(self, storage: AbstractStorage | None = None) -> None:
        """
        Initialize Profiles.

        Args:
            storage: Storage backend to use
        """
        self._storage = storage
        self._profiles: dict[str, dict[str, Any]] = {}

    @property
    def profiles(self) -> dict[str, dict[str, Any]]:
        """Get all profiles."""
        return self._profiles

    def load(self) -> bool:
        """
        Load profiles from storage.

        Returns:
            bool: True if successful
        """
        # Load default profiles first
        self._profiles = dict(self.DEFAULT_PROFILES)

        # Load custom profiles from storage
        if self._storage:
            try:
                stored_profiles = self._storage.list_profiles()
                self._profiles.update(stored_profiles)
            except Exception:
                pass

        return True

    def get(self, name: str) -> dict[str, Any]:
        """
        Get a profile by name.

        Args:
            name: Profile name

        Returns:
            dict: Profile data

        Raises:
            ProfileError: If profile not found
        """
        if name not in self._profiles:
            # Try to load from storage
            if self._storage:
                profile = self._storage.get_profile(name)
                if profile:
                    self._profiles[name] = profile
                    return profile

        if name not in self._profiles:
            raise ProfileError(f"Profile not found: {name}")

        return self._profiles[name]

    def add(self, name: str, data: dict[str, Any]) -> bool:
        """
        Add a new profile.

        Args:
            name: Profile name
            data: Profile data

        Returns:
            bool: True if successful
        """
        # Validate profile name
        if not name or not name.strip():
            raise ProfileError("Profile name cannot be empty")

        if name in BUILTIN_PROFILES:
            raise ProfileError(f"Cannot override built-in profile: {name}")

        # Validate profile data
        self._validate_profile(data)

        # Store profile
        self._profiles[name] = data

        # Save to storage
        if self._storage:
            self._storage.store_profile(name, data)

        return True

    def remove(self, name: str) -> bool:
        """
        Remove a profile.

        Args:
            name: Profile name

        Returns:
            bool: True if successful
        """
        # Don't allow removing built-in profiles
        if name in BUILTIN_PROFILES:
            raise ProfileError(f"Cannot remove built-in profile: {name}")

        if name not in self._profiles:
            raise ProfileError(f"Profile not found: {name}")

        # Remove from memory
        del self._profiles[name]

        # Remove from storage
        if self._storage:
            self._storage.delete_profile(name)

        return True

    def list(self) -> list[str]:
        """
        List all available profiles.

        Returns:
            list: List of profile names
        """
        return list(self._profiles.keys())

    def update(self, name: str, data: dict[str, Any]) -> bool:
        """
        Update a profile.

        Args:
            name: Profile name
            data: Updated profile data

        Returns:
            bool: True if successful
        """
        # Don't allow updating built-in profiles directly
        if name in BUILTIN_PROFILES:
            raise ProfileError(f"Cannot update built-in profile: {name}")

        if name not in self._profiles:
            raise ProfileError(f"Profile not found: {name}")

        # Validate profile data
        self._validate_profile(data)

        # Update profile
        self._profiles[name] = data

        # Save to storage
        if self._storage:
            self._storage.store_profile(name, data)

        return True

    def _validate_profile(self, data: dict[str, Any]) -> bool:
        """
        Validate profile data.

        Args:
            data: Profile data to validate

        Returns:
            bool: True if valid

        Raises:
            ProfileError: If validation fails
        """
        # Validate key type
        key_type = data.get("keyType", DEFAULT_KEY_TYPE).lower()
        if key_type not in ["rsa", "dsa"]:
            raise ProfileError(f"Invalid key type: {key_type}")

        # Validate key length
        key_len = data.get("keyLen", DEFAULT_KEY_LENGTH)
        if key_len not in [1024, 2048, 4096]:
            raise ProfileError(f"Invalid key length: {key_len}")

        # Validate digest
        digest = data.get("digest", DEFAULT_DIGEST).lower()
        if digest not in ["md5", "sha1", "sha256", "sha512"]:
            raise ProfileError(f"Invalid digest: {digest}")

        # Validate duration
        duration = data.get("duration", DEFAULT_DURATION)
        if duration < 1:
            raise ProfileError(f"Invalid duration: {duration}")

        # Validate subject
        subject = data.get("subject", {})
        if not subject:
            raise ProfileError("Subject is required")

        # Validate CN if provided
        cn = subject.get("CN", "")
        if cn:
            DNValidator.validate_cn(cn)

        # Validate key usage if provided
        key_usage = data.get("keyUsage", [])
        valid_usages = [
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
        for usage in key_usage:
            if usage not in valid_usages:
                raise ProfileError(f"Invalid key usage: {usage}")

        # Validate extended key usage if provided
        eku = data.get("extendedKeyUsage", [])
        valid_eku = [
            "serverAuth",
            "clientAuth",
            "codeSigning",
            "emailProtection",
            "timeStamping",
            "OCSPSigning",
        ]
        for usage in eku:
            if usage not in valid_eku:
                raise ProfileError(f"Invalid extended key usage: {usage}")

        return True

    def create_from_template(
        self, name: str, template: str, overrides: dict[str, Any] | None = None
    ) -> bool:
        """
        Create a new profile from a template.

        Args:
            name: New profile name
            template: Template to use
            overrides: Profile data to override

        Returns:
            bool: True if successful
        """
        # Get template profile
        base_profile = self.get(template).copy()

        # Apply overrides
        if overrides:
            base_profile.update(overrides)

        # Create new profile
        return self.add(name, base_profile)

    def export_profile(self, name: str) -> str:
        """
        Export a profile as YAML.

        Args:
            name: Profile name

        Returns:
            str: Profile as YAML string
        """
        import yaml

        profile = self.get(name)
        return yaml.safe_dump(profile, default_flow_style=False)

    def import_profile(self, name: str, yaml_data: str) -> bool:
        """
        Import a profile from YAML.

        Args:
            name: Profile name
            yaml_data: Profile as YAML string

        Returns:
            bool: True if successful
        """
        import yaml

        try:
            data = yaml.safe_load(yaml_data)
            return self.add(name, data)
        except Exception as e:
            raise ProfileError(f"Failed to import profile: {e}")
