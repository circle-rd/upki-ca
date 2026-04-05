"""
Unit tests for CAServer.start().

Tests the auto-bootstrap behaviour introduced for Docker deployment.
All ZMQ, Authority, and storage interactions are mocked so that no
real PKI operations or network sockets are required.

Author: uPKI Team
License: MIT
"""

import contextlib
import os
import shutil
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from ca_server import CAServer


class TestCAServerStart:
    """Unit tests for CAServer.start() auto-bootstrap method."""

    @pytest.fixture(autouse=True)
    def setup_teardown(self):
        """Create a temporary data directory and wire up the server."""
        self.temp_dir = tempfile.mkdtemp()
        self.server = CAServer()
        self.server._storage_path = self.temp_dir
        yield
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _run_start(self, env_seed: str | None = None, env_host: str = "0.0.0.0"):
        """Run CAServer.start() with mocked listeners that stop the loop.

        ZMQListener.start is patched to raise SystemExit after being called
        so that the infinite ``while True: time.sleep(1)`` loop exits cleanly
        during tests.
        """
        mock_storage = MagicMock()
        mock_authority = MagicMock()
        mock_authority.storage = mock_storage

        mock_register = MagicMock()
        mock_listener = MagicMock()
        # Make ZMQListener.start raise SystemExit so the loop terminates.
        mock_listener.start.side_effect = SystemExit(0)

        with (
            patch("ca_server.FileStorage", return_value=mock_storage),
            patch("ca_server.Authority") as mock_auth_cls,
            patch("ca_server.ZMQRegister", return_value=mock_register),
            patch("ca_server.ZMQListener", return_value=mock_listener),
            patch("ca_server.time") as mock_time,
        ):
            mock_auth_cls.get_instance.return_value = mock_authority
            mock_time.sleep.side_effect = SystemExit(0)

            with contextlib.suppress(SystemExit):
                self.server.start(env_seed=env_seed, env_host=env_host)

            return {
                "storage": mock_storage,
                "authority": mock_authority,
                "register": mock_register,
                "listener": mock_listener,
                "auth_cls": mock_auth_cls,
            }

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    def test_should_inject_env_seed_when_config_has_no_seed(self):
        """Test that env_seed is written to config when no seed exists yet."""
        # Arrange — no pre-existing config file, so seed starts as None
        env_seed = "my-bootstrap-seed-value"

        # Act
        self._run_start(env_seed=env_seed)

        # Assert — config on disk must now contain the seed
        from upki_ca.utils.config import Config

        config = Config(os.path.join(self.temp_dir, "ca.config.yml"))
        config.load()
        assert config.get_seed() == env_seed

    def test_should_not_override_existing_seed(self):
        """Test that a pre-existing config seed is never overwritten."""
        # Arrange — write a config with an existing seed first
        from upki_ca.utils.config import Config

        existing_seed = "existing-seed-must-not-change"
        config = Config(os.path.join(self.temp_dir, "ca.config.yml"))
        config.load()
        config.set_seed(existing_seed)
        config.save()

        # Act — pass a different seed via env
        self._run_start(env_seed="new-seed-should-be-ignored")

        # Assert
        reloaded = Config(os.path.join(self.temp_dir, "ca.config.yml"))
        reloaded.load()
        assert reloaded.get_seed() == existing_seed

    def test_should_use_env_host_for_zmq_binding(self):
        """Test that both ZMQ sockets bind to env_host, not 127.0.0.1."""
        # Arrange
        custom_host = "0.0.0.0"

        mock_storage = MagicMock()
        mock_authority = MagicMock()
        mock_authority.storage = mock_storage
        mock_register = MagicMock()
        mock_listener = MagicMock()
        mock_listener.start.side_effect = SystemExit(0)

        with (
            patch("ca_server.FileStorage", return_value=mock_storage),
            patch("ca_server.Authority") as mock_auth_cls,
            patch("ca_server.ZMQRegister", return_value=mock_register) as mock_reg_cls,
            patch("ca_server.ZMQListener", return_value=mock_listener) as mock_lst_cls,
            patch("ca_server.time"),
        ):
            mock_auth_cls.get_instance.return_value = mock_authority
            with contextlib.suppress(SystemExit):
                self.server.start(env_seed="seed", env_host=custom_host)

            # ZMQRegister must be created with custom_host
            reg_call_kwargs = mock_reg_cls.call_args
            assert reg_call_kwargs.kwargs["host"] == custom_host

            # ZMQListener must be created with custom_host
            lst_call_kwargs = mock_lst_cls.call_args
            assert lst_call_kwargs.kwargs["host"] == custom_host

    def test_should_call_init_pki_on_every_startup(self):
        """Test that init_pki() is called each time start() runs (idempotent check)."""
        # Act
        with patch.object(self.server, "init_pki", return_value=False) as mock_init:
            self.server.start(env_seed="seed")

        # Assert — init_pki must have been called exactly once
        mock_init.assert_called_once()

    def test_should_start_both_listeners(self):
        """Test that both the registration and CA listeners are started."""
        # Arrange
        mock_storage = MagicMock()
        mock_authority = MagicMock()
        mock_authority.storage = mock_storage
        mock_register = MagicMock()
        mock_listener = MagicMock()
        mock_listener.start.side_effect = SystemExit(0)

        with (
            patch("ca_server.FileStorage", return_value=mock_storage),
            patch("ca_server.Authority") as mock_auth_cls,
            patch("ca_server.ZMQRegister", return_value=mock_register),
            patch("ca_server.ZMQListener", return_value=mock_listener),
            patch("ca_server.time"),
        ):
            mock_auth_cls.get_instance.return_value = mock_authority
            with contextlib.suppress(SystemExit):
                self.server.start(env_seed="seed")

        # Assert
        mock_register.start.assert_called_once()
        mock_listener.start.assert_called_once()
