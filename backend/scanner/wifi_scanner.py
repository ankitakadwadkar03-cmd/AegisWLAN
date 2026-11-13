"""Real-time WiFi network scanner for Kali Linux.

Run with root privileges on a wireless adapter that supports monitor mode:
    sudo python3 scanner/wifi_scanner.py --interface wlan0
"""

from __future__ import annotations

import argparse
import json
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from scapy.all import AsyncSniffer, conf

from csv_logger import save_to_csv
from network_parser import extract_network_details


DEFAULT_CSV_PATH = Path("backend/data/scan_results/wifi_scan_results.csv")
DEFAULT_CHANNELS_2GHZ = list(range(1, 12))
CHANNEL_DWELL_SECONDS = 1.5

def _run_command(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
def set_channel(interface: str, channel: int) -> bool:
    """Switch the wireless interface to a WiFi channel."""
    result = _run_command(
        ["iw", "dev", interface, "set", "channel", str(channel)],
        check=False,
    )

    if result.returncode != 0:
        error_message = (
            result.stderr.strip()
            or result.stdout.strip()
            or "unknown channel-switch error"
        )

        print(
            f"Warning: unable to switch {interface} "
            f"to channel {channel}: {error_message}",
            file=sys.stderr,
            flush=True,
        )
        return False

    return True


def get_enabled_channels(interface: str) -> list[int]:
    """Return enabled WiFi channels reported by Linux for this adapter."""
    try:
        interface_info = _run_command(
            ["iw", "dev", interface, "info"]
        )
    except subprocess.CalledProcessError:
        return DEFAULT_CHANNELS_2GHZ.copy()

    phy_name = None

    for raw_line in interface_info.stdout.splitlines():
        line = raw_line.strip()

        if line.startswith("wiphy "):
            phy_number = line.split(" ", 1)[1].strip()
            phy_name = f"phy{phy_number}"
            break

    if not phy_name:
        return DEFAULT_CHANNELS_2GHZ.copy()

    try:
        phy_info = _run_command(
            ["iw", "phy", phy_name, "info"]
        )
    except subprocess.CalledProcessError:
        return DEFAULT_CHANNELS_2GHZ.copy()

    channels: list[int] = []

    for raw_line in phy_info.stdout.splitlines():
        line = raw_line.strip()

        if "MHz [" not in line:
            continue

        if "(disabled)" in line.lower():
            continue

        try:
            channel_text = (
                line.split("[", 1)[1]
                .split("]", 1)[0]
                .strip()
            )
            channel = int(channel_text)
        except (IndexError, ValueError):
            continue

        if channel not in channels:
            channels.append(channel)

    return channels or DEFAULT_CHANNELS_2GHZ.copy()


def _require_command(command_name: str) -> None:
    if shutil.which(command_name) is None:
        raise RuntimeError(f"Required command not found: {command_name}")


def _restart_network_services() -> None:
    """Attempt to restart standard networking services stopped by airmon-ng."""
    for service_name in ("NetworkManager", "wpa_supplicant"):
        try:
            _run_command(
                ["systemctl", "start", service_name],
                check=False,
            )
        except Exception as exc:
            print(
                f"Warning: unable to restart {service_name}: {exc}",
                file=sys.stderr,
            )


def _get_interfaces_state() -> dict[str, str]:
    """Return a mapping of wireless interface names to their type (mode) from iw dev."""
    result = _run_command(["iw", "dev"], check=False)
    if result.returncode != 0:
        return {}

    interfaces: dict[str, str] = {}
    current_iface: str | None = None

    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("Interface "):
            current_iface = line.split(" ", 1)[1].strip()
            interfaces[current_iface] = "unknown"
        elif current_iface and line.startswith("type "):
            interfaces[current_iface] = line.split(" ", 1)[1].strip()

    return interfaces


def enable_monitor_mode(interface: str) -> str:
    """Enable monitor mode using airmon-ng and return the monitor interface name."""

    for command_name in ("airmon-ng", "iw"):
        _require_command(command_name)

    monitor_interface: str | None = None
    try:
        _run_command(["airmon-ng", "check", "kill"], check=False)
        result = _run_command(["airmon-ng", "start", interface])
        monitor_interface = _parse_monitor_interface(result.stdout, interface)
        _verify_monitor_mode(monitor_interface)
        return monitor_interface
    except subprocess.CalledProcessError as exc:
        details = (
            exc.stderr.strip()
            or exc.stdout.strip()
            or "command failed"
        )
        if exc.stdout:
            parsed = _parse_monitor_interface(exc.stdout, interface)
            if parsed != interface:
                monitor_interface = parsed
        if not monitor_interface and _interface_exists(f"{interface}mon"):
            monitor_interface = f"{interface}mon"

        cleaned = False
        if monitor_interface and monitor_interface != interface:
            try:
                restore_managed_mode(monitor_interface, original_interface=interface)
                cleaned = True
            except Exception as cleanup_err:
                print(
                    f"Warning: error cleaning up {monitor_interface}: {cleanup_err}",
                    file=sys.stderr,
                )
        else:
            _restart_network_services()

        error_msg = f"Could not enable monitor mode for {interface}: {details}"
        print(f"Error: {error_msg}", file=sys.stderr)
        err = RuntimeError(error_msg)
        if monitor_interface:
            err.monitor_interface = monitor_interface
        err.monitor_mode_cleaned = cleaned
        raise err from exc
    except Exception as exc:
        print(
            f"Error: could not enable monitor mode for {interface}: {exc}",
            file=sys.stderr,
        )
        cleanup_target = monitor_interface
        if not cleanup_target or cleanup_target == interface:
            if _interface_exists(f"{interface}mon"):
                cleanup_target = f"{interface}mon"

        cleaned = False
        if cleanup_target and cleanup_target != interface:
            try:
                restore_managed_mode(cleanup_target, original_interface=interface)
                cleaned = True
            except Exception as cleanup_err:
                print(
                    f"Warning: error cleaning up {cleanup_target}: {cleanup_err}",
                    file=sys.stderr,
                )
        else:
            _restart_network_services()

        exc.monitor_interface = cleanup_target
        exc.monitor_mode_cleaned = cleaned
        raise


def _parse_monitor_interface(airmon_output: str, interface: str) -> str:
    for line in airmon_output.splitlines():
        lowered = line.lower()
        if "monitor mode" in lowered and "enabled" in lowered:
            cleaned_line = (
                line.replace(")", " ")
                .replace("(", " ")
                .replace("[", " ")
                .replace("]", " ")
                .replace(":", " ")
                .replace(",", " ")
            )
            tokens = cleaned_line.split()
            for token in reversed(tokens):
                if token.startswith(interface) and token != interface:
                    return token

    candidate = f"{interface}mon"
    if _interface_exists(candidate):
        return candidate

    interfaces_state = _get_interfaces_state()
    for name, mode in interfaces_state.items():
        if mode == "monitor" and (name == candidate or (name.startswith(interface) and name != interface)):
            return name

    return interface


def _interface_exists(interface: str) -> bool:
    try:
        _run_command(["iw", "dev", interface, "info"])
        return True
    except subprocess.CalledProcessError:
        return False


def _verify_monitor_mode(interface: str) -> None:
    try:
        result = _run_command(["iw", "dev", interface, "info"])
    except subprocess.CalledProcessError as exc:
        details = (
            exc.stderr.strip()
            or exc.stdout.strip()
            or "command failed"
        )
        raise RuntimeError(
            f"Could not verify interface {interface}: {details}"
        ) from exc

    detected_type: str | None = None
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("type "):
            detected_type = line.split(" ", 1)[1].strip()
            break

    if detected_type != "monitor":
        type_str = detected_type if detected_type is not None else "unknown"
        raise RuntimeError(
            f"Interface {interface} is not in monitor mode (detected type: {type_str})."
        )


def restore_managed_mode(interface: str, original_interface: str | None = None) -> None:
    """Disable monitor mode, verify interface restoration with iw dev, and restart WiFi services."""
    if original_interface is None:
        if interface.endswith("mon"):
            original_interface = interface[:-3]
        else:
            original_interface = interface

    airmon_output = ""
    try:
        result = _run_command(
            ["airmon-ng", "stop", interface],
            check=False,
        )
        airmon_output = (result.stderr.strip() or result.stdout.strip() or "")
        if result.returncode != 0:
            print(
                f"Warning: could not restore {interface}: {airmon_output}",
                file=sys.stderr,
            )
    except Exception as exc:
        airmon_output = f"Execution error: {exc}"
        print(
            f"Warning: error stopping monitor interface {interface}: {exc}",
            file=sys.stderr,
        )
    finally:
        _restart_network_services()

    # Verify the resulting wireless interface state using iw dev
    verified = False
    interfaces_state: dict[str, str] = {}
    deadline = time.monotonic() + 1.5

    while True:
        interfaces_state = _get_interfaces_state()

        if interface != original_interface:
            monitor_removed = interface not in interfaces_state
        else:
            monitor_removed = interfaces_state.get(interface) != "monitor"

        orig_managed = interfaces_state.get(original_interface) == "managed"

        if monitor_removed and orig_managed:
            verified = True
            break

        if time.monotonic() >= deadline:
            break
        time.sleep(0.1)

    if not verified:
        state_repr = ", ".join(f"{k}={v}" for k, v in interfaces_state.items()) if interfaces_state else "none"
        diag_msg = (
            f"Automatic restoration failed for monitor interface '{interface}' (target managed: '{original_interface}'). "
            f"airmon-ng stop output: '{airmon_output}'. "
            f"Detected interface state: [{state_repr}]."
        )
        print(f"Error: {diag_msg}", file=sys.stderr)
        raise RuntimeError(diag_msg)


def scan_networks(
    interface: str,
    stop_check=None,
    channels: list[int] | None = None,
    progress_callback=None,
) -> dict[str, dict[str, str | int | None]]:
    """Scan enabled WiFi channels and return discovered access points."""

    networks: dict[str, dict[str, str | int | None]] = {}
    scan_channels = channels or get_enabled_channels(interface)
    total_channels = len(scan_channels)

    def handle_packet(packet: Any) -> None:
        details = extract_network_details(packet)
        if details is None:
            return
        networks[details.bssid] = details.as_dict()

    for channel_index, channel in enumerate(
        scan_channels,
        start=1,
    ):
        if stop_check and stop_check():
            break

        if not set_channel(interface, channel):
            if progress_callback:
                progress_callback(
                    channel,
                    channel_index,
                    total_channels,
                    set(networks),
                )
            continue

        if progress_callback:
            progress_callback(
                channel,
                channel_index - 1,
                total_channels,
                set(networks),
            )

        sniffer = AsyncSniffer(
            iface=interface,
            prn=handle_packet,
            store=False,
        )

        try:
            sniffer.start()

            dwell_deadline = (
                time.monotonic() + CHANNEL_DWELL_SECONDS
            )

            while time.monotonic() < dwell_deadline:
                if stop_check and stop_check():
                    break

                remaining = dwell_deadline - time.monotonic()
                time.sleep(min(0.1, max(remaining, 0)))
        finally:
            try:
                sniffer.stop()
            except Exception:
                pass

        if progress_callback:
            progress_callback(
                channel,
                channel_index,
                total_channels,
                set(networks),
            )

        if stop_check and stop_check():
            break

    return networks


def _write_scanner_status(
    status_path: Path,
    **values,
) -> None:
    """Atomically save runtime scanner progress for the API."""
    status_path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        **values,
    }

    temporary_path = status_path.with_suffix(
        status_path.suffix + ".tmp"
    )

    temporary_path.write_text(
        json.dumps(payload, indent=2),
        encoding="utf-8",
    )

    temporary_path.replace(status_path)


def _merge_networks(
    known_networks: dict[str, dict[str, str | int | None]],
    latest_networks: dict[str, dict[str, str | int | None]],
) -> None:
    for bssid, details in latest_networks.items():
        known_networks[bssid] = details


def _format_value(value: str | int | None, default: str = "Unknown") -> str:
    if value is None or value == "":
        return default
    return str(value)


def _print_table(networks: dict[str, dict[str, str | int | None]]) -> None:
    headers = ["SSID", "BSSID", "Channel", "Frequency", "Signal", "Encryption"]
    rows = [
        [
            _format_value(network.get("SSID"), "<hidden>"),
            _format_value(network.get("BSSID")),
            _format_value(network.get("Channel")),
            _format_value(network.get("Frequency")),
            _format_value(network.get("Signal")),
            _format_value(network.get("Encryption")),
        ]
        for network in sorted(
            networks.values(),
            key=lambda item: (item.get("Signal") is None, -(item.get("Signal") or -999)),
        )
    ]

    widths = [
        max(len(header), *(len(row[index]) for row in rows)) if rows else len(header)
        for index, header in enumerate(headers)
    ]

    line = "+-" + "-+-".join("-" * width for width in widths) + "-+"
    header_line = "| " + " | ".join(header.ljust(widths[index]) for index, header in enumerate(headers)) + " |"

    print("\033c", end="")
    print("WiFi Real-Time Security and Signal Analyzer - Network Scanner")
    print(f"Last update: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(line)
    print(header_line)
    print(line)

    if not rows:
        print("| " + "No networks detected yet.".ljust(sum(widths) + (3 * (len(headers) - 1))) + " |")
    else:
        for row in rows:
            print("| " + " | ".join(value.ljust(widths[index]) for index, value in enumerate(row)) + " |")

    print(line)
    print(f"Networks detected: {len(networks)}")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Real-time WiFi Network Scanner for Kali Linux")
    parser.add_argument(
        "-i",
        "--interface",
        required=True,
        help="Wireless adapter name, for example wlan0. Monitor mode will be enabled automatically.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=str(DEFAULT_CSV_PATH),
        help=f"CSV output path. Default: {DEFAULT_CSV_PATH}",
    )
    parser.add_argument(
        "--no-monitor-setup",
        action="store_true",
        help="Skip airmon-ng setup when the provided interface is already in monitor mode.",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    known_networks: dict[str, dict[str, str | int | None]] = {}
    stop_requested = False
    monitor_interface: str | None = None
    monitor_mode_created = False
    status_path = (
        Path(args.output).parent
        / "scanner_status.json"
    )
    scan_channels: list[int] = []
    sweep_number = 0
    last_sweep_completed_at: str | None = None
    scanner_exception: Exception | None = None
    cleanup_exception: Exception | None = None

    def request_stop(_signum: int, _frame: Any) -> None:
        nonlocal stop_requested
        stop_requested = True

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    try:
        conf.verb = 0

        if args.no_monitor_setup:
            monitor_interface = args.interface
        else:
            try:
                monitor_interface = enable_monitor_mode(args.interface)
                monitor_mode_created = True
            except Exception as init_exc:
                created_iface = getattr(init_exc, "monitor_interface", None)
                if not created_iface and _interface_exists(f"{args.interface}mon"):
                    created_iface = f"{args.interface}mon"
                if created_iface:
                    monitor_interface = created_iface
                    if not getattr(init_exc, "monitor_mode_cleaned", False):
                        monitor_mode_created = True
                raise

        print(f"Scanning on monitor interface: {monitor_interface}")

        scan_channels = get_enabled_channels(monitor_interface)

        _write_scanner_status(
            status_path,
            state="scanning",
            interface=monitor_interface,
            sweep_number=0,
            current_channel=None,
            channels_completed=0,
            total_channels=len(scan_channels),
            enabled_channels=scan_channels,
            session_network_count=0,
            last_sweep_completed_at=None,
        )

        while not stop_requested:
            sweep_number += 1

            def update_progress(
                channel,
                channels_completed,
                total_channels,
                sweep_bssids,
            ):
                _write_scanner_status(
                    status_path,
                    state="scanning",
                    interface=monitor_interface,
                    sweep_number=sweep_number,
                    current_channel=channel,
                    channels_completed=channels_completed,
                    total_channels=total_channels,
                    enabled_channels=scan_channels,
                    session_network_count=len(
                        set(known_networks) | set(sweep_bssids)
                    ),
                    last_sweep_completed_at=(
                        last_sweep_completed_at
                    ),
                )

            latest_networks = scan_networks(
                monitor_interface,
                stop_check=lambda: stop_requested,
                channels=scan_channels,
                progress_callback=update_progress,
            )

            _merge_networks(known_networks, latest_networks)
            save_to_csv(known_networks, args.output)

            if not stop_requested:
                last_sweep_completed_at = time.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

            _write_scanner_status(
                status_path,
                state=(
                    "stopping"
                    if stop_requested
                    else "scanning"
                ),
                interface=monitor_interface,
                sweep_number=sweep_number,
                current_channel=None,
                channels_completed=(
                    0
                    if stop_requested
                    else len(scan_channels)
                ),
                total_channels=len(scan_channels),
                enabled_channels=scan_channels,
                session_network_count=len(known_networks),
                last_sweep_completed_at=(
                    last_sweep_completed_at
                ),
            )

            _print_table(known_networks)

    except PermissionError as exc:
        scanner_exception = exc
        print(
            "Permission denied. Run this scanner with sudo/root privileges.",
            file=sys.stderr,
        )
        return 1
    except RuntimeError as exc:
        scanner_exception = exc
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt as exc:
        scanner_exception = exc
        print("\nScan interrupted by user.", file=sys.stderr)
        return 0
    except Exception as exc:
        scanner_exception = exc
        print(f"Unexpected error: {exc}", file=sys.stderr)
        return 1
    finally:
        if monitor_mode_created and monitor_interface:
            try:
                print(
                    f"Restoring {monitor_interface} to managed mode..."
                )
                restore_managed_mode(monitor_interface, original_interface=args.interface)
            except Exception as exc:
                cleanup_exception = exc
                print(
                    f"Warning: error restoring {monitor_interface}: {exc}",
                    file=sys.stderr,
                )

        try:
            status_state = "error" if (scanner_exception or cleanup_exception) else "stopped"
            status_interface = monitor_interface if cleanup_exception else None
            _write_scanner_status(
                status_path,
                state=status_state,
                interface=status_interface,
                sweep_number=sweep_number,
                current_channel=None,
                channels_completed=(
                    0 if stop_requested else len(scan_channels)
                ),
                total_channels=len(scan_channels),
                enabled_channels=scan_channels,
                session_network_count=len(known_networks),
                last_sweep_completed_at=last_sweep_completed_at,
            )
        except Exception as exc:
            print(
                f"Warning: unable to write final scanner status: {exc}",
                file=sys.stderr,
            )

    if cleanup_exception:
        print(
            f"Error: automatic monitor-mode cleanup failed for {monitor_interface}: {cleanup_exception}",
            file=sys.stderr,
        )
        return 1

    print("\nScanner stopped. Latest CSV saved successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
