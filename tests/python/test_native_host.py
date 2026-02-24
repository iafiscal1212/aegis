"""Tests for AEGIS native messaging host."""

import json
import struct
import io
import sys
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# Add the python source to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "python"))

from aegis.browser.native_host import (
    read_message,
    send_message,
    handle_check_url,
    handle_check_package,
    handle_get_status,
    handle_get_threat_db_stats,
    get_native_host_manifest,
    install_native_host,
)


class TestNativeMessagingProtocol:
    """Test the native messaging read/write protocol."""

    def test_read_message_valid(self, monkeypatch):
        """Test reading a valid native messaging message."""
        payload = json.dumps({"type": "ping"}).encode("utf-8")
        data = struct.pack("=I", len(payload)) + payload
        monkeypatch.setattr("sys.stdin", MagicMock(buffer=io.BytesIO(data)))

        result = read_message()
        assert result == {"type": "ping"}

    def test_read_message_empty_stdin(self, monkeypatch):
        """Test reading from empty stdin returns None."""
        monkeypatch.setattr("sys.stdin", MagicMock(buffer=io.BytesIO(b"")))
        result = read_message()
        assert result is None

    def test_read_message_short_header(self, monkeypatch):
        """Test reading truncated header returns None."""
        monkeypatch.setattr("sys.stdin", MagicMock(buffer=io.BytesIO(b"\x01\x02")))
        result = read_message()
        assert result is None

    def test_read_message_too_large(self, monkeypatch):
        """Test messages over 1MB are rejected."""
        huge_length = struct.pack("=I", 2 * 1024 * 1024)
        monkeypatch.setattr("sys.stdin", MagicMock(buffer=io.BytesIO(huge_length)))
        result = read_message()
        assert result is None

    def test_send_message(self, monkeypatch):
        """Test sending a native messaging message."""
        buf = io.BytesIO()
        monkeypatch.setattr("sys.stdout", MagicMock(buffer=buf))

        send_message({"pong": True})

        buf.seek(0)
        length = struct.unpack("=I", buf.read(4))[0]
        payload = json.loads(buf.read(length))
        assert payload == {"pong": True}

    def test_roundtrip(self, monkeypatch):
        """Test write then read gives back same message."""
        original = {"type": "test", "data": {"key": "value", "num": 42}}

        # Write
        write_buf = io.BytesIO()
        monkeypatch.setattr("sys.stdout", MagicMock(buffer=write_buf))
        send_message(original)

        # Read back
        write_buf.seek(0)
        monkeypatch.setattr("sys.stdin", MagicMock(buffer=write_buf))
        result = read_message()
        assert result == original


class TestMessageHandlers:
    """Test individual message handlers."""

    def test_handle_check_url_empty(self):
        """Test check_url with empty URL."""
        result = handle_check_url({})
        assert result["safe"] is True

    def test_handle_check_url_with_url(self):
        """Test check_url with a valid URL."""
        result = handle_check_url({"url": "https://example.com"})
        assert "safe" in result

    def test_handle_check_package_empty(self):
        """Test check_package with no name."""
        result = handle_check_package({})
        assert "error" in result

    @patch("aegis.browser.native_host.check_install_command", create=True)
    def test_handle_check_package_valid(self, mock_check):
        """Test check_package with valid name."""
        # The import might fail if aegis.monitor.terminal is not available,
        # but the function should handle the error gracefully
        result = handle_check_package({"name": "requests", "ecosystem": "python"})
        assert isinstance(result, dict)

    def test_handle_get_status(self, tmp_path):
        """Test get_status returns status info."""
        with patch("aegis.browser.native_host.get_config_dir", return_value=tmp_path, create=True):
            result = handle_get_status()
            assert isinstance(result, dict)

    def test_handle_get_threat_db_stats(self):
        """Test get_threat_db_stats."""
        result = handle_get_threat_db_stats()
        # May error if DB doesn't exist, but should return dict
        assert isinstance(result, dict)


class TestNativeHostManifest:
    """Test manifest generation and installation."""

    def test_chrome_manifest(self):
        """Test Chrome native host manifest."""
        manifest = get_native_host_manifest("chrome")
        assert manifest["name"] == "com.aegis.browser_guardian"
        assert manifest["type"] == "stdio"
        assert "allowed_origins" in manifest

    def test_firefox_manifest(self):
        """Test Firefox native host manifest."""
        manifest = get_native_host_manifest("firefox")
        assert manifest["name"] == "com.aegis.browser_guardian"
        assert "allowed_extensions" in manifest
        assert "aegis-browser-guardian@aegis-security" in manifest["allowed_extensions"]

    def test_install_native_host(self, tmp_path):
        """Test installing native host manifest creates the file."""
        with patch("aegis.browser.native_host.Path.home", return_value=tmp_path):
            # Patch platform.system for consistent test
            with patch("aegis.browser.native_host.platform.system", return_value="Linux"):
                path = install_native_host("chrome", "test-extension-id")
                assert Path(path).exists()
                manifest = json.loads(Path(path).read_text())
                assert manifest["name"] == "com.aegis.browser_guardian"
                assert f"chrome-extension://test-extension-id/" in manifest["allowed_origins"]


class TestBrowserExtensionFiles:
    """Verify all required browser extension files exist."""

    EXTENSION_DIR = Path(__file__).parent.parent.parent / "aegis-browser"

    def test_manifest_exists(self):
        assert (self.EXTENSION_DIR / "manifest.json").exists()

    def test_manifest_valid_json(self):
        manifest = json.loads((self.EXTENSION_DIR / "manifest.json").read_text())
        assert manifest["manifest_version"] == 3
        assert manifest["version"] == "0.1.0"

    def test_manifest_permissions(self):
        manifest = json.loads((self.EXTENSION_DIR / "manifest.json").read_text())
        required = ["storage", "downloads", "notifications", "declarativeNetRequest", "alarms", "webNavigation"]
        for perm in required:
            assert perm in manifest["permissions"], f"Missing permission: {perm}"

    def test_background_js_exists(self):
        assert (self.EXTENSION_DIR / "background.js").exists()

    def test_content_detector_exists(self):
        assert (self.EXTENSION_DIR / "content" / "detector.js").exists()

    def test_content_overlay_css_exists(self):
        assert (self.EXTENSION_DIR / "content" / "overlay.css").exists()

    def test_popup_files_exist(self):
        assert (self.EXTENSION_DIR / "popup" / "popup.html").exists()
        assert (self.EXTENSION_DIR / "popup" / "popup.js").exists()
        assert (self.EXTENSION_DIR / "popup" / "popup.css").exists()

    def test_blocked_page_exists(self):
        assert (self.EXTENSION_DIR / "popup" / "blocked.html").exists()

    def test_options_files_exist(self):
        assert (self.EXTENSION_DIR / "options" / "options.html").exists()
        assert (self.EXTENSION_DIR / "options" / "options.js").exists()

    def test_blocklist_json_exists(self):
        assert (self.EXTENSION_DIR / "rules" / "blocklist.json").exists()

    def test_blocklist_valid_json(self):
        bl = json.loads((self.EXTENSION_DIR / "rules" / "blocklist.json").read_text())
        assert "malvertising" in bl
        assert "scareware" in bl
        assert "fake_software" in bl
        assert "crypto_scam" in bl
        assert "phishing_patterns" in bl

    def test_blocklist_rules_exists(self):
        assert (self.EXTENSION_DIR / "rules" / "blocklist_rules.json").exists()

    def test_blocklist_rules_valid(self):
        rules = json.loads((self.EXTENSION_DIR / "rules" / "blocklist_rules.json").read_text())
        assert isinstance(rules, list)
        assert len(rules) > 0
        # Each rule should have id, priority, action, condition
        for rule in rules:
            assert "id" in rule
            assert "action" in rule
            assert "condition" in rule

    def test_official_sites_exists(self):
        assert (self.EXTENSION_DIR / "rules" / "official_sites.json").exists()

    def test_official_sites_valid(self):
        sites = json.loads((self.EXTENSION_DIR / "rules" / "official_sites.json").read_text())
        assert "putty" in sites
        assert "vlc" in sites
        assert isinstance(sites["putty"], list)

    def test_icons_exist(self):
        for size in [16, 48, 128]:
            assert (self.EXTENSION_DIR / "icons" / f"icon{size}.png").exists()

    def test_locales_exist(self):
        for lang in ["en", "es"]:
            path = self.EXTENSION_DIR / "_locales" / lang / "messages.json"
            assert path.exists()
            messages = json.loads(path.read_text())
            assert "extName" in messages
            assert "extDescription" in messages


class TestBackgroundJSLogic:
    """Test the logic in background.js by analyzing its content."""

    BACKGROUND_JS = Path(__file__).parent.parent.parent / "aegis-browser" / "background.js"

    def test_has_download_listener(self):
        content = self.BACKGROUND_JS.read_text()
        assert "chrome.downloads.onCreated.addListener" in content

    def test_has_navigation_listener(self):
        content = self.BACKGROUND_JS.read_text()
        assert "chrome.webNavigation.onBeforeNavigate.addListener" in content

    def test_has_message_listener(self):
        content = self.BACKGROUND_JS.read_text()
        assert "chrome.runtime.onMessage.addListener" in content

    def test_handles_scareware_detected(self):
        content = self.BACKGROUND_JS.read_text()
        assert 'message.type === "scareware_detected"' in content

    def test_has_native_messaging(self):
        content = self.BACKGROUND_JS.read_text()
        assert "chrome.runtime.connectNative" in content
        assert "com.aegis.browser_guardian" in content

    def test_has_double_extension_check(self):
        content = self.BACKGROUND_JS.read_text()
        assert "double extension" in content.lower()

    def test_has_official_source_check(self):
        content = self.BACKGROUND_JS.read_text()
        assert "checkOfficialSource" in content

    def test_has_phishing_pattern_check(self):
        content = self.BACKGROUND_JS.read_text()
        assert "phishing_patterns" in content

    def test_has_badge_update(self):
        content = self.BACKGROUND_JS.read_text()
        assert "setBadgeText" in content
        assert "updateBadge" in content


class TestDetectorJSLogic:
    """Test the content script detector logic."""

    DETECTOR_JS = Path(__file__).parent.parent.parent / "aegis-browser" / "content" / "detector.js"

    def test_has_scareware_patterns(self):
        content = self.DETECTOR_JS.read_text()
        assert "SCAREWARE_TEXT_PATTERNS" in content
        assert "your (computer|pc|device|system)" in content.lower() or "your.*computer" in content.lower()

    def test_has_phone_detection(self):
        content = self.DETECTOR_JS.read_text()
        assert "PHONE_NUMBER_PATTERN" in content

    def test_has_fullscreen_detection(self):
        content = self.DETECTOR_JS.read_text()
        assert "checkFullscreenLock" in content
        assert "fullscreenElement" in content

    def test_has_audio_detection(self):
        content = self.DETECTOR_JS.read_text()
        assert "checkAudioAbuse" in content

    def test_has_warning_overlay(self):
        content = self.DETECTOR_JS.read_text()
        assert "showWarningOverlay" in content
        assert "aegis-warning-overlay" in content

    def test_has_mutation_observer(self):
        content = self.DETECTOR_JS.read_text()
        assert "MutationObserver" in content

    def test_threshold_is_3(self):
        content = self.DETECTOR_JS.read_text()
        assert "indicators.length >= 3" in content

    def test_sends_message_to_background(self):
        content = self.DETECTOR_JS.read_text()
        assert "chrome.runtime.sendMessage" in content
        assert "scareware_detected" in content
