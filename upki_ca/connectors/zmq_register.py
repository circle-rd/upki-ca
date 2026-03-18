"""
ZMQ Registration Listener for uPKI CA Server.

This module provides the ZMQRegister class for handling
RA server registration in clear mode.

Author: uPKI Team
License: MIT
"""

from __future__ import annotations

from typing import Any

from upki_ca.connectors.listener import Listener
from upki_ca.core.upki_error import CommunicationError
from upki_ca.core.upki_logger import UpkiLogger


class ZMQRegister(Listener):
    """
    ZMQ listener for RA registration.

    Handles RA registration in clear mode (unencrypted)
    for initial RA setup.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 5001, seed: str | None = None) -> None:
        """
        Initialize the ZMQRegister.

        Args:
            host: Host to bind to
            port: Port to bind to
            seed: Registration seed for validation
        """
        super().__init__(host, port)

        self._seed = seed or "default_seed"
        self._logger = UpkiLogger.get_logger("zmq_register")
        self._registered_nodes: dict[str, dict[str, Any]] = {}

    def _handle_task(self, task: str, params: dict[str, Any]) -> Any:
        """
        Handle a specific task.

        Args:
            task: Task name
            params: Task parameters

        Returns:
            Any: Task result
        """
        if task == "register":
            return self._register_node(params)
        elif task == "status":
            return self._get_status(params)
        else:
            raise CommunicationError(f"Unknown task: {task}")

    def _register_node(self, params: dict[str, Any]) -> dict[str, Any]:
        """
        Register a new RA node.

        Args:
            params: Registration parameters

        Returns:
            dict: Registration result
        """
        seed = params.get("seed", "")
        cn = params.get("cn", "")
        profile = params.get("profile", "ra")

        # Validate seed
        if seed != self._seed:
            raise CommunicationError("Invalid registration seed")

        if not cn:
            raise CommunicationError("Missing cn parameter")

        # Store registered node
        self._registered_nodes[cn] = {
            "cn": cn,
            "profile": profile,
            "registered_at": self.timestamp(),
        }

        self._logger.info(f"Registered RA node: {cn}")

        return {"status": "registered", "cn": cn, "profile": profile}

    def _get_status(self, params: dict[str, Any]) -> dict[str, Any]:
        """
        Get registration status.

        Args:
            params: Status parameters

        Returns:
            dict: Status information
        """
        cn = params.get("cn", "")

        if cn in self._registered_nodes:
            return {"status": "registered", "node": self._registered_nodes[cn]}

        return {"status": "not_registered"}

    def list_registered(self) -> list[str]:
        """
        List all registered nodes.

        Returns:
            list: List of registered node CNs
        """
        return list(self._registered_nodes.keys())
