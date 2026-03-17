# -*- coding:utf-8 -*-

"""
Administrator management for uPKI.

This module provides the Admins class for managing administrator accounts.
"""

from typing import Any

import upkica


class Admins(upkica.core.Common):
    """Administrator manager for uPKI.

    This class handles the management of administrator accounts,
    including listing, adding, and removing administrators.

    Attributes:
        _storage: Storage backend instance.
        _admins_list: List of administrator records.

    Args:
        logger: Logger instance for output.
        storage: Storage backend instance.

    Raises:
        Exception: If initialization fails.
    """

    def __init__(self, logger: Any, storage: Any) -> None:
        """Initialize Admins manager.

        Args:
            logger: Logger instance for output.
            storage: Storage backend instance.

        Raises:
            Exception: If initialization fails.
        """
        try:
            super(Admins, self).__init__(logger)
        except Exception as err:
            raise Exception(err)

        self._storage = storage

        self.list()

    def exists(self, dn: str) -> bool:
        """Check if an admin exists.

        Args:
            dn: Distinguished Name of the admin to check.

        Returns:
            True if admin exists, False otherwise.
        """
        for i, adm in enumerate(self._admins_list):
            if adm["dn"] == dn:
                return True
        return False

    def list(self) -> list:
        """List all administrators.

        Returns:
            List of administrator records.

        Raises:
            Exception: If listing admins fails.
        """
        try:
            # Detect all admins
            self._admins_list = self._storage.list_admins()
        except Exception as err:
            raise Exception("Unable to list admins: {e}".format(e=err))
        return self._admins_list

    def store(self, dn: str) -> str:
        """Add an administrator.

        Args:
            dn: Distinguished Name of the admin to add.

        Returns:
            DN of the added admin.

        Raises:
            Exception: If admin already exists or storage operation fails.
        """
        if self.exists(dn):
            raise Exception("Already admin.")
        try:
            self._storage.add_admin(dn)
        except Exception as err:
            raise Exception(err)

        return dn

    def delete(self, dn: str) -> str:
        """Remove an administrator.

        Args:
            dn: Distinguished Name of the admin to remove.

        Returns:
            DN of the removed admin.

        Raises:
            Exception: If storage operation fails.
        """
        try:
            self._storage.delete_admin(dn)
        except Exception as err:
            raise Exception(err)

        return dn
