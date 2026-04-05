"""
Unit tests for Config.set_host().

Author: uPKI Team
License: MIT
"""

import os
import shutil
import tempfile

import pytest

from upki_ca.utils.config import Config


class TestConfigSetHost:
    """Tests for Config.set_host() method."""

    @pytest.fixture(autouse=True)
    def setup_teardown(self):
        """Create and clean up a temporary directory for each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.temp_dir, "ca.config.yml")
        yield
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_should_set_host_and_get_host_returns_new_value(self):
        """Test that set_host updates the value returned by get_host."""
        # Arrange
        config = Config(self.config_path)
        config.load()

        # Act
        config.set_host("0.0.0.0")

        # Assert
        assert config.get_host() == "0.0.0.0"

    def test_should_return_true_on_success(self):
        """Test that set_host returns True on successful update."""
        # Arrange
        config = Config(self.config_path)
        config.load()

        # Act
        result = config.set_host("0.0.0.0")

        # Assert
        assert result is True

    def test_should_override_default_host(self):
        """Test that set_host overrides the default value of 127.0.0.1."""
        # Arrange
        config = Config(self.config_path)
        config.load()
        assert config.get_host() == "127.0.0.1"

        # Act
        config.set_host("10.0.0.1")

        # Assert
        assert config.get_host() == "10.0.0.1"

    def test_should_persist_host_after_save_and_reload(self):
        """Test that the host value survives a save/reload cycle."""
        # Arrange
        config = Config(self.config_path)
        config.load()

        # Act
        config.set_host("0.0.0.0")
        config.save()

        reloaded = Config(self.config_path)
        reloaded.load()

        # Assert
        assert reloaded.get_host() == "0.0.0.0"
