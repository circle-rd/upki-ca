"""
Base Listener class for uPKI CA Server.

This module provides the base Listener class for handling
ZMQ-based communication.

Author: uPKI Team
License: MIT
"""

from __future__ import annotations

import json
import threading
from abc import ABC, abstractmethod
from typing import Any

import zmq

from upki_ca.core.common import Common
from upki_ca.core.upki_error import CommunicationError
from upki_ca.core.upki_logger import UpkiLogger


class Listener(Common, ABC):
    """
    Base listener class for ZMQ communication.

    This class provides the base functionality for listening
    and responding to requests.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 5000, timeout: int = 5000) -> None:
        """
        Initialize the Listener.

        Args:
            host: Host to bind to
            port: Port to bind to
            timeout: Socket timeout in milliseconds
        """
        self._host = host
        self._port = port
        self._timeout = timeout
        self._zmq_context: zmq.Context | None = None
        self._socket: zmq.Socket | None = None
        self._running = False
        self._thread: threading.Thread | None = None
        self._logger = UpkiLogger.get_logger("listener")

    @property
    def is_running(self) -> bool:
        """Check if the listener is running."""
        return self._running

    @property
    def address(self) -> str:
        """Get the listener address."""
        return f"tcp://{self._host}:{self._port}"

    def initialize(self) -> bool:
        """
        Initialize the ZMQ context and socket.

        Returns:
            bool: True if successful
        """
        try:
            self._zmq_context = zmq.Context()
            self._socket = self._zmq_context.socket(zmq.REP)
            if self._socket is None:
                raise CommunicationError("Failed to create ZMQ socket")
            self._socket.setsockopt(zmq.RCVTIMEO, self._timeout)
            self._socket.setsockopt(zmq.SNDTIMEO, self._timeout)

            return True
        except Exception as e:
            raise CommunicationError(f"Failed to initialize listener: {e}") from e

    def bind(self) -> bool:
        """
        Bind the socket to the address.

        Returns:
            bool: True if successful
        """
        if self._socket is None:
            raise CommunicationError("Listener not initialized")

        try:
            self._socket.bind(self.address)
            self._logger.info(f"Listener bound to {self.address}")
            return True
        except Exception as e:
            raise CommunicationError(f"Failed to bind to {self.address}: {e}") from e

    def start(self) -> bool:
        """
        Start the listener in a background thread.

        Returns:
            bool: True if successful
        """
        if self._running:
            return True

        self._running = True
        self._thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._thread.start()

        self._logger.info("Listener started")
        return True

    def stop(self) -> bool:
        """
        Stop the listener.

        Returns:
            bool: True if successful
        """
        self._running = False

        if self._thread:
            self._thread.join(timeout=5)

        if self._socket:
            self._socket.close()

        if self._zmq_context:
            self._zmq_context.term()

        self._logger.info("Listener stopped")
        return True

    def _listen_loop(self) -> None:
        """Main listening loop."""
        while self._running:
            try:
                if self._socket is None:
                    break

                # Receive message
                message = self._socket.recv_string()

                # Process message
                response = self._process_message(message)

                # Send response
                self._socket.send_string(response)

            except zmq.Again:
                # Timeout - continue
                continue
            except Exception as e:
                self._logger.error("Listener", e)
                continue

    def _process_message(self, message: str) -> str:
        """
        Process an incoming message.

        Args:
            message: Raw message string

        Returns:
            str: Response message
        """
        try:
            data = json.loads(message)
            task = data.get("TASK", "")
            params = data.get("params", {})

            # Call the appropriate handler
            result = self._handle_task(task, params)

            # Build response
            response = {"EVENT": "ANSWER", "DATA": result}

            return json.dumps(response)

        except json.JSONDecodeError as e:
            return json.dumps({"EVENT": "UPKI ERROR", "MSG": f"Invalid JSON: {e}"})
        except Exception as e:
            return json.dumps({"EVENT": "UPKI ERROR", "MSG": str(e)})

    @abstractmethod
    def _handle_task(self, task: str, params: dict[str, Any]) -> Any:
        """
        Handle a specific task.

        Args:
            task: Task name
            params: Task parameters

        Returns:
            Any: Task result
        """
        pass

    def send_request(self, address: str, data: dict[str, Any]) -> dict[str, Any]:
        """
        Send a request to another endpoint.

        Args:
            address: Target address
            data: Request data

        Returns:
            dict: Response data
        """
        try:
            context = zmq.Context()
            socket = context.socket(zmq.REQ)
            socket.connect(address)

            socket.send_string(json.dumps(data))
            response = socket.recv_string()

            socket.close()
            context.term()

            return json.loads(response)
        except Exception as e:
            raise CommunicationError(f"Failed to send request: {e}") from e
