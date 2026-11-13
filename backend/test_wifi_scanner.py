"""Focused unit tests for Wi-Fi scanner monitor-mode initialization, restoration, and cleanup."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure backend/scanner is in sys.path
scanner_dir = Path(__file__).resolve().parent / "scanner"
if str(scanner_dir) not in sys.path:
    sys.path.insert(0, str(scanner_dir))

import wifi_scanner


def test_successful_monitor_interface_creation():
    """Test successful monitor interface creation and parsing."""
    airmon_stdout = (
        "PHY\tInterface\tDriver\t\tChipset\n"
        "phy0\twlan0\t\tath9k_htc\tQualcomm Atheros\n\n"
        "\t\t(mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)\n"
        "\t\t(mac80211 station mode vif disabled for [phy0]wlan0)\n"
    )

    with patch("wifi_scanner._require_command"), \
         patch("wifi_scanner._run_command") as mock_run, \
         patch("wifi_scanner._verify_monitor_mode") as mock_verify:

        mock_run.side_effect = [
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),  # airmon-ng check kill
            subprocess.CompletedProcess(args=[], returncode=0, stdout=airmon_stdout, stderr=""),  # airmon-ng start
        ]

        result = wifi_scanner.enable_monitor_mode("wlan0")
        assert result == "wlan0mon"
        mock_verify.assert_called_once_with("wlan0mon")


def test_verification_failure_after_interface_creation_cleans_up():
    """Test that if airmon-ng start creates a monitor interface but verification fails,
    the interface is identified, cleaned up, and the name is retained on the exception.
    """
    airmon_stdout = (
        "(mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)\n"
    )

    with patch("wifi_scanner._require_command"), \
         patch("wifi_scanner._run_command") as mock_run, \
         patch("wifi_scanner._verify_monitor_mode") as mock_verify, \
         patch("wifi_scanner.restore_managed_mode") as mock_restore:

        mock_run.side_effect = [
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),  # airmon-ng check kill
            subprocess.CompletedProcess(args=[], returncode=0, stdout=airmon_stdout, stderr=""),  # airmon-ng start
        ]
        mock_verify.side_effect = RuntimeError(
            "Interface wlan0mon is not in monitor mode (detected type: managed)."
        )

        with pytest.raises(RuntimeError) as exc_info:
            wifi_scanner.enable_monitor_mode("wlan0")

        assert "not in monitor mode" in str(exc_info.value)
        # Ensure the monitor interface was identified and passed to restore_managed_mode
        mock_restore.assert_called_once_with("wlan0mon", original_interface="wlan0")
        # Ensure the monitor interface was not lost on the exception
        assert getattr(exc_info.value, "monitor_interface", None) == "wlan0mon"


def test_successful_automatic_restoration():
    """Test successful restore_managed_mode verifying state via iw dev."""
    iw_dev_output = (
        "phy#0\n"
        "\tInterface wlan0\n"
        "\t\tifindex 3\n"
        "\t\twdev 0x1\n"
        "\t\taddr 00:c0:ca:97:5a:d4\n"
        "\t\ttype managed\n"
        "\t\ttxpower 20.00 dBm\n"
    )

    with patch("wifi_scanner._run_command") as mock_run, \
         patch("wifi_scanner._restart_network_services") as mock_restart:

        def run_cmd(cmd, **kwargs):
            if cmd[:2] == ["airmon-ng", "stop"]:
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="Interface wlan0mon stopped", stderr="")
            if cmd == ["iw", "dev"]:
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=iw_dev_output, stderr="")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        mock_run.side_effect = run_cmd

        # Should complete without error
        wifi_scanner.restore_managed_mode("wlan0mon", original_interface="wlan0")
        mock_restart.assert_called_once()


def test_monitor_interface_remaining_after_failed_restoration():
    """Test that if the monitor interface is still present after airmon-ng stop,
    restore_managed_mode raises a RuntimeError with diagnostic details.
    """
    iw_dev_output = (
        "phy#0\n"
        "\tInterface wlan0mon\n"
        "\t\ttype monitor\n"
        "\tInterface wlan0\n"
        "\t\ttype managed\n"
    )

    with patch("wifi_scanner._run_command") as mock_run, \
         patch("wifi_scanner._restart_network_services"):

        def run_cmd(cmd, **kwargs):
            if cmd[:2] == ["airmon-ng", "stop"]:
                return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="Device or resource busy")
            if cmd == ["iw", "dev"]:
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=iw_dev_output, stderr="")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        mock_run.side_effect = run_cmd

        with pytest.raises(RuntimeError) as exc_info:
            wifi_scanner.restore_managed_mode("wlan0mon", original_interface="wlan0")

        err_msg = str(exc_info.value)
        assert "Automatic restoration failed" in err_msg
        assert "Device or resource busy" in err_msg
        assert "wlan0mon=monitor" in err_msg or "wlan0mon" in err_msg


def test_original_interface_not_managed_after_restoration():
    """Test that if original interface does not return to managed mode, restoration fails."""
    iw_dev_output = (
        "phy#0\n"
        "\tInterface wlan0\n"
        "\t\ttype monitor\n"
    )

    with patch("wifi_scanner._run_command") as mock_run, \
         patch("wifi_scanner._restart_network_services"):

        def run_cmd(cmd, **kwargs):
            if cmd[:2] == ["airmon-ng", "stop"]:
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="Stopped", stderr="")
            if cmd == ["iw", "dev"]:
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=iw_dev_output, stderr="")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        mock_run.side_effect = run_cmd

        with pytest.raises(RuntimeError) as exc_info:
            wifi_scanner.restore_managed_mode("wlan0mon", original_interface="wlan0")

        assert "Automatic restoration failed" in str(exc_info.value)
        assert "wlan0=monitor" in str(exc_info.value)


def test_main_cleanup_errors_without_hiding_original_scanner_exception():
    """Test that a cleanup exception in finally does not mask or replace the original scanner exception."""
    with tempfile.TemporaryDirectory() as tmpdir:
        csv_path = Path(tmpdir) / "scan.csv"
        status_path = Path(tmpdir) / "scanner_status.json"

        with patch("wifi_scanner._parse_args") as mock_args, \
             patch("wifi_scanner.enable_monitor_mode", return_value="wlan0mon"), \
             patch("wifi_scanner.get_enabled_channels", return_value=[1, 6]), \
             patch("wifi_scanner.scan_networks", side_effect=RuntimeError("Hardware link dropped")), \
             patch("wifi_scanner.restore_managed_mode", side_effect=RuntimeError("airmon-ng stop timed out")), \
             patch("sys.stderr.write"):

            mock_args.return_value = MagicMock(
                interface="wlan0",
                output=str(csv_path),
                no_monitor_setup=False,
            )

            exit_code = wifi_scanner.main()
            assert exit_code == 1

            assert status_path.exists()
            status_data = json.loads(status_path.read_text(encoding="utf-8"))
            assert status_data["state"] == "error"
            # Since cleanup failed, monitor interface remains identified
            assert status_data["interface"] == "wlan0mon"


def test_main_cleanup_failure_reports_error_and_does_not_claim_success():
    """Test that if the scanner finishes cleanly but cleanup fails, main exits with 1 and does not claim success."""
    with tempfile.TemporaryDirectory() as tmpdir:
        csv_path = Path(tmpdir) / "scan.csv"
        status_path = Path(tmpdir) / "scanner_status.json"

        with patch("wifi_scanner._parse_args") as mock_args, \
             patch("wifi_scanner.enable_monitor_mode", return_value="wlan0mon"), \
             patch("wifi_scanner.get_enabled_channels", return_value=[1]), \
             patch("wifi_scanner.scan_networks", return_value={}), \
             patch("wifi_scanner.restore_managed_mode", side_effect=RuntimeError("Cleanup verification failed")), \
             patch("builtins.print") as mock_print:

            mock_args.return_value = MagicMock(
                interface="wlan0",
                output=str(csv_path),
                no_monitor_setup=False,
            )

            with patch("wifi_scanner.save_to_csv"):
                # Simulate Ctrl+C triggering stop_requested
                def trigger_stop(*args, **kwargs):
                    import signal
                    handlers = signal.getsignal(signal.SIGINT)
                    if callable(handlers):
                        handlers(signal.SIGINT, None)
                    return {}

                with patch("wifi_scanner.scan_networks", side_effect=trigger_stop):
                    exit_code = wifi_scanner.main()

            assert exit_code == 1
            # Ensure "Latest CSV saved successfully" was NOT printed
            printed_messages = [call.args[0] for call in mock_print.call_args_list if call.args]
            assert not any("Scanner stopped. Latest CSV saved successfully." in str(m) for m in printed_messages)

            # Check status file
            status_data = json.loads(status_path.read_text(encoding="utf-8"))
            assert status_data["state"] == "error"
            assert status_data["interface"] == "wlan0mon"
