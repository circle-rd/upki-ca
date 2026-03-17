# -*- coding:utf-8 -*-

"""
Profile management for uPKI.

This module provides the Profiles class for managing certificate profiles.
"""

import re
from typing import Any

import upkica


class Profiles(upkica.core.Common):
    """Profile manager for uPKI.

    This class handles the management of certificate profiles,
    including listing, loading, storing, updating, and deleting profiles.

    Attributes:
        _storage: Storage backend instance.
        _profiles_list: Dictionary of available profiles.
        _allowed: Allowed option values (from Options).

    Args:
        logger: Logger instance for output.
        storage: Storage backend instance.

    Raises:
        Exception: If initialization fails.
    """

    def __init__(self, logger: Any, storage: Any) -> None:
        """Initialize Profiles manager.

        Args:
            logger: Logger instance for output.
            storage: Storage backend instance.

        Raises:
            Exception: If initialization fails.
        """
        try:
            super(Profiles, self).__init__(logger)
        except Exception as err:
            raise Exception(err)

        self._storage = storage

        # Import Options for allowed values
        self._allowed = upkica.core.Options()

        try:
            # Detect all profiles
            self._profiles_list = self._storage.list_profiles()
        except Exception as err:
            raise Exception("Unable to list profiles: {e}".format(e=err))

    def exists(self, name: str) -> bool:
        """Check if a profile exists.

        Args:
            name: Name of the profile to check.

        Returns:
            True if profile exists, False otherwise.
        """
        return bool(name in self._profiles_list.keys())

    def list(self) -> dict:
        """List all profiles (excluding system profiles).

        Returns:
            Dictionary of public profile names to their configuration.
            System profiles (admin, ca, ra) are excluded.
        """
        results = dict(self._profiles_list)

        # Avoid disclosing system profiles
        for name in ["admin", "ca", "ra"]:
            try:
                del results[name]
            except KeyError:
                pass

        return results

    def load(self, name: str) -> dict:
        """Load a specific profile.

        Args:
            name: Name of the profile to load.

        Returns:
            Validated profile configuration data.

        Raises:
            Exception: If profile doesn't exist or validation fails.
        """
        if name not in self._profiles_list.keys():
            raise Exception("Profile does not exists")

        try:
            data = self._storage.load_profile(name)
        except Exception as err:
            raise Exception(err)

        try:
            clean = self._check_profile(data)
            self.output("Profile {p} loaded".format(p=name), level="DEBUG")
        except Exception as err:
            raise Exception(err)

        return clean

    def store(self, name: str, data: dict) -> dict:
        """Store a new profile.

        Validates data before pushing to storage.

        Args:
            name: Name of the profile to store.
            data: Profile configuration data.

        Returns:
            Validated profile configuration data.

        Raises:
            Exception: If profile name is reserved, invalid, or validation fails.
        """
        if name in ["ca", "ra", "admin"]:
            raise Exception("Sorry this name is reserved")

        if not (re.match("^[\w\-_\(\)]+$", name) is not None):
            raise Exception("Invalid profile name")

        try:
            clean = self._check_profile(data)
            self.output("New Profile {p} verified".format(p=name), level="DEBUG")
        except Exception as err:
            raise Exception(err)

        try:
            self._storage.store_profile(name, clean)
        except Exception as err:
            raise Exception(err)

        # Update values if exists
        self._profiles_list[name] = clean

        return clean

    def update(self, original: str, name: str, data: dict) -> dict:
        """Update an existing profile.

        Validates data before pushing to storage.

        Args:
            original: Original profile name.
            name: New profile name.
            data: Updated profile configuration data.

        Returns:
            Validated profile configuration data.

        Raises:
            Exception: If profile name is reserved, invalid, or update fails.
        """
        if name in ["ca", "ra", "admin"]:
            raise Exception("Sorry this name is reserved")

        if not (re.match("^[\w\-_\(\)]+$", name) is not None):
            raise Exception("Invalid profile name")

        if not original in self._profiles_list.keys():
            raise Exception("This profile did not exists")

        if (original != name) and (name in self._profiles_list.keys()):
            raise Exception("Duplicate profile name")

        try:
            clean = self._check_profile(data)
            self.output(
                "Modified profile {o} -> {p} verified".format(o=original, p=name),
                level="DEBUG",
            )
        except Exception as err:
            raise Exception(err)

        try:
            self._storage.update_profile(original, name, clean)
        except Exception as err:
            raise Exception(err)

        # Update values if exists
        self._profiles_list[name] = clean

        # Take care of original if needed
        if original != name:
            try:
                self.delete(original)
            except Exception as err:
                raise Exception(err)

        return clean

    def delete(self, name: str) -> bool:
        """Delete a profile.

        Args:
            name: Name of the profile to delete.

        Returns:
            True if deletion successful.

        Raises:
            Exception: If profile name is reserved or invalid.
        """
        if name in ["ca", "ra", "admin"]:
            raise Exception("Sorry this name is reserved")

        if not (re.match("^[\w\-_\(\)]+$", name) is not None):
            raise Exception("Invalid profile name")

        try:
            self._storage.delete_profile(name)
        except Exception as err:
            raise Exception(err)

        try:
            # Update values if exists
            del self._profiles_list[name]
        except KeyError as err:
            pass

        return True
