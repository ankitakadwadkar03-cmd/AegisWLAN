"""Comprehensive regression and validation tests for AWID3 preprocessing and ML evaluation."""

from __future__ import annotations

import csv
import math
import os
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

_backend_dir = str(Path(__file__).resolve().parents[1])
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

from backend.ml.awid3_preprocessor import (
    CONFIRMED_AWID3_ATTACK_CATEGORIES,
    CONFIRMED_NORMAL_LABELS,
    OUTPUT_LABEL_COLUMN,
    _feature_row_for_window,
    awid3_label_to_binary,
    awid3_row_to_packet,
    process_awid3_csv_file,
    process_awid3_dataset,
)
from backend.ml.burst_features_v3 import BURST_FEATURE_NAMES, extract_burst_features
from backend.ml.evaluation_service import (
    ML_TEST_DATASETS_DIR,
    list_available_test_datasets,
    resolve_secure_dataset_path,
    validate_dataset_data,
)
from backend.ml.feature_extractor import extract_window_features, group_packets_by_time_window
from backend.ml.v3_feature_schema import V3_FEATURE_COUNT, V3_FEATURE_NAMES
from backend.ml.v3_feature_vector import features_to_v3_vector


AWID3_TEST_FIELDS = [
    "frame.time_epoch",
    "radiotap.dbm_antsignal",
    "wlan.bssid",
    "wlan.da",
    "wlan.ra",
    "wlan.sa",
    "wlan.fc.type",
    "wlan.fc.subtype",
    "wlan.fc.retry",
    "wlan.ssid",
    "Label",
]


def _row(
    timestamp: str,
    label: str,
    subtype: str = "8",
    frame_type: str = "0",
    retry: str = "0",
    signal: str = "-40",
    bssid: str = "00:11:22:33:44:55",
    sa: str = "66:77:88:99:aa:bb",
    da: str = "ff:ff:ff:ff:ff:ff",
    ssid: str = "TestNet",
) -> dict[str, str]:
    return {
        "frame.time_epoch": timestamp,
        "radiotap.dbm_antsignal": signal,
        "wlan.bssid": bssid,
        "wlan.da": da,
        "wlan.ra": "",
        "wlan.sa": sa,
        "wlan.fc.type": frame_type,
        "wlan.fc.subtype": subtype,
        "wlan.fc.retry": retry,
        "wlan.ssid": ssid,
        "Label": label,
    }


class AWID3PreprocessorTest(unittest.TestCase):
    def _write_rows_and_read_output(
        self,
        rows: list[dict[str, str]],
        chunk_rows: int = 2,
        label_mapping: dict[str, int] | None = None,
    ) -> tuple[int, list[dict[str, str]], list[str] | None]:
        with tempfile.TemporaryDirectory() as temp_dir:
            input_csv = Path(temp_dir) / "awid3.csv"
            output_csv = Path(temp_dir) / "features.csv"

            with input_csv.open("w", newline="", encoding="utf-8") as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=AWID3_TEST_FIELDS)
                writer.writeheader()
                writer.writerows(rows)

            window_count = process_awid3_dataset(
                input_csv,
                output_csv,
                chunk_rows=chunk_rows,
                label_mapping=label_mapping,
            )

            with output_csv.open("r", newline="", encoding="utf-8") as csv_file:
                reader = csv.DictReader(csv_file)
                output_rows = list(reader)
                fieldnames = reader.fieldnames

        return window_count, output_rows, fieldnames

    def test_processes_31_features_plus_label_and_canonical_ordering(self) -> None:
        """Verify output has exactly 31 features in V3_FEATURE_NAMES order + 1 label column (32 total)."""
        rows = [
            _row("100.0", "Normal", subtype="8"),
            _row("101.0", "Normal", subtype="4"),
            _row("105.0", "Normal", subtype="5"),
            _row("106.0", "Deauth", subtype="12", retry="1"),
        ]

        window_count, output_rows, fieldnames = self._write_rows_and_read_output(rows)

        self.assertEqual(window_count, 2)
        expected_fieldnames = [*V3_FEATURE_NAMES, OUTPUT_LABEL_COLUMN]
        self.assertEqual(fieldnames, expected_fieldnames)
        self.assertEqual(len(fieldnames), 32)
        self.assertEqual(len(output_rows), 2)

        # Check column count of each row
        self.assertEqual(len(output_rows[0]), 32)
        self.assertEqual(len(output_rows[1]), 32)

        # Labels
        self.assertEqual(output_rows[0][OUTPUT_LABEL_COLUMN], "0")
        self.assertEqual(output_rows[1][OUTPUT_LABEL_COLUMN], "1")

        # Basic packet counts
        self.assertEqual(float(output_rows[0]["total_packets"]), 2.0)
        self.assertEqual(float(output_rows[1]["total_packets"]), 2.0)
        self.assertEqual(float(output_rows[0]["beacon_count"]), 1.0)
        self.assertEqual(float(output_rows[1]["deauth_count"]), 1.0)
        self.assertEqual(float(output_rows[1]["retry_count"]), 1.0)

    def test_strict_feature_parity_with_production_v3_pipeline(self) -> None:
        """Strictly compare all 31 offline feature values against production V3 feature extraction."""
        rows = [
            _row("100.1", "Normal", subtype="8", frame_type="0"),  # Beacon
            _row("100.3", "Normal", subtype="4", frame_type="0"),  # Probe Request
            _row("100.5", "Normal", subtype="5", frame_type="0"),  # Probe Response
            _row("101.0", "Normal", subtype="11", frame_type="0"),  # Auth
            _row("101.2", "Deauth", subtype="12", frame_type="0", retry="1"),  # Deauth
            _row("101.4", "Deauth", subtype="12", frame_type="0", retry="1"),  # Deauth
            _row("102.0", "Normal", subtype="10", frame_type="0"),  # Disassoc
            _row("102.5", "Normal", subtype="0", frame_type="1"),  # Control
            _row("103.0", "Normal", subtype="0", frame_type="2"),  # Data
            _row("104.2", "Normal", subtype="2", frame_type="0"),  # Reassoc Req
        ]

        packets = [
            awid3_row_to_packet(r)
            for r in rows
            if awid3_row_to_packet(r) is not None
        ]

        # 1. Offline preprocessor window generation
        offline_row = _feature_row_for_window(packets, label=1, window_seconds=5.0)

        # 2. Production V3 online inference feature extraction
        base_features = extract_window_features(packets, window_seconds=5.0)
        burst_features = extract_burst_features(packets, window_seconds=5.0)
        combined_production = {**base_features, **burst_features}
        expected_v3_vector = features_to_v3_vector(combined_production)

        # Verify ordering and exact values
        feature_keys = [k for k in offline_row.keys() if k != OUTPUT_LABEL_COLUMN]
        self.assertEqual(feature_keys, V3_FEATURE_NAMES)
        self.assertEqual(len(feature_keys), V3_FEATURE_COUNT)

        for idx, feature_name in enumerate(V3_FEATURE_NAMES):
            offline_val = float(offline_row[feature_name])
            production_val = expected_v3_vector[idx]
            self.assertTrue(
                math.isclose(offline_val, production_val, rel_tol=1e-6, abs_tol=1e-6),
                f"Feature parity mismatch at index {idx} ({feature_name}): "
                f"offline={offline_val} vs production={production_val}",
            )

        self.assertEqual(offline_row[OUTPUT_LABEL_COLUMN], 1)

    def test_burst_features_calculations_in_window(self) -> None:
        """Verify calculations for all six burst features within a 5-second window."""
        rows = [
            # Second 0 (100.0 - 101.0): 3 deauths, 1 beacon = 4 packets
            _row("100.1", "Deauth", subtype="12", frame_type="0"),
            _row("100.2", "Deauth", subtype="12", frame_type="0"),
            _row("100.4", "Deauth", subtype="12", frame_type="0"),
            _row("100.8", "Normal", subtype="8", frame_type="0"),
            # Second 1 (101.0 - 102.0): 2 disassoc = 2 packets
            _row("101.1", "Normal", subtype="10", frame_type="0"),
            _row("101.5", "Normal", subtype="10", frame_type="0"),
            # Second 2 (102.0 - 103.0): 1 data = 1 packet
            _row("102.2", "Normal", subtype="0", frame_type="2"),
        ]

        packets = [awid3_row_to_packet(r) for r in rows if awid3_row_to_packet(r) is not None]
        offline_row = _feature_row_for_window(packets, label=1, window_seconds=5.0)

        total_packets = 7
        self.assertEqual(float(offline_row["max_packets_1s"]), 4.0)
        self.assertEqual(float(offline_row["max_deauth_1s"]), 3.0)
        self.assertEqual(float(offline_row["max_disassoc_1s"]), 2.0)
        self.assertAlmostEqual(float(offline_row["packet_burst_ratio"]), 4.0 / total_packets)
        self.assertAlmostEqual(float(offline_row["deauth_burst_ratio"]), 3.0 / total_packets)
        self.assertAlmostEqual(float(offline_row["disassoc_burst_ratio"]), 2.0 / total_packets)

    def test_binary_label_aggregation(self) -> None:
        """Verify window label aggregation: Normal+Normal -> 0, Normal+Attack -> 1, Attack+Attack -> 1."""
        rows = [
            _row("100.0", "Normal", subtype="8"),
            _row("101.0", "0", subtype="4"),
            _row("105.0", "Normal", subtype="8"),
            _row("106.0", "Deauth", subtype="12"),
            _row("110.0", "Disas", subtype="10"),
            _row("111.0", "RogueAP", subtype="8"),
        ]

        window_count, output_rows, _ = self._write_rows_and_read_output(rows)
        self.assertEqual(window_count, 3)
        self.assertEqual(output_rows[0][OUTPUT_LABEL_COLUMN], "0")
        self.assertEqual(output_rows[1][OUTPUT_LABEL_COLUMN], "1")
        self.assertEqual(output_rows[2][OUTPUT_LABEL_COLUMN], "1")

    def test_unknown_and_malformed_label_rejection(self) -> None:
        """Verify unknown, malformed, or empty labels are rejected and not guessed as attacks."""
        # Confirmed normal
        self.assertEqual(awid3_label_to_binary("Normal"), 0)
        self.assertEqual(awid3_label_to_binary("normal"), 0)
        self.assertEqual(awid3_label_to_binary("0"), 0)

        # Confirmed attacks
        self.assertEqual(awid3_label_to_binary("Deauth"), 1)
        self.assertEqual(awid3_label_to_binary("disas"), 1)
        self.assertEqual(awid3_label_to_binary("(Re)Assoc"), 1)
        self.assertEqual(awid3_label_to_binary("RogueAP"), 1)
        self.assertEqual(awid3_label_to_binary("Evil_Twin"), 1)
        self.assertEqual(awid3_label_to_binary("Attack"), 1)
        self.assertEqual(awid3_label_to_binary("1"), 1)

        # Unknown / unsupported labels must raise ValueError
        with self.assertRaises(ValueError):
            awid3_label_to_binary("UnknownAttack")

        with self.assertRaises(ValueError):
            awid3_label_to_binary("MaliciousTraffic")

        with self.assertRaises(ValueError):
            awid3_label_to_binary("")

        with self.assertRaises(ValueError):
            awid3_label_to_binary("   ")

        with self.assertRaises(ValueError):
            awid3_label_to_binary(None)

        # Explicit custom mapping allows overriding/extending
        custom_mapping = {"CustomSpecialAttack": 1, "CustomBenign": 0}
        self.assertEqual(
            awid3_label_to_binary("CustomSpecialAttack", label_mapping=custom_mapping),
            1,
        )
        self.assertEqual(
            awid3_label_to_binary("CustomBenign", label_mapping=custom_mapping),
            0,
        )

        # Invalid target in custom mapping raises ValueError
        with self.assertRaises(ValueError):
            awid3_label_to_binary("CustomSpecialAttack", label_mapping={"CustomSpecialAttack": 99})

    def test_out_of_order_rows_match_live_window_semantics(self) -> None:
        """Verify out-of-order packets are chronologically sorted into correct 5-second windows."""
        rows = [
            _row("106.0", "Deauth", subtype="12"),
            _row("100.0", "Normal", subtype="8"),
            _row("105.0", "Normal", subtype="5"),
            _row("101.0", "Normal", subtype="4"),
        ]

        window_count, output_rows, fieldnames = self._write_rows_and_read_output(
            rows,
            chunk_rows=2,
        )
        packets = [
            packet
            for packet in (awid3_row_to_packet(row) for row in rows)
            if packet is not None
        ]
        expected_windows = group_packets_by_time_window(packets)

        self.assertEqual(window_count, len(expected_windows))
        self.assertEqual(fieldnames, [*V3_FEATURE_NAMES, OUTPUT_LABEL_COLUMN])
        self.assertEqual(output_rows[0][OUTPUT_LABEL_COLUMN], "0")
        self.assertEqual(output_rows[1][OUTPUT_LABEL_COLUMN], "1")
        self.assertEqual(float(output_rows[0]["total_packets"]), 2.0)
        self.assertEqual(float(output_rows[1]["total_packets"]), 2.0)

    def test_missing_values_are_safe(self) -> None:
        """Verify missing optional values are handled safely without crash or NaN."""
        packet = awid3_row_to_packet(
            {
                "frame.time_epoch": "200.25",
                "radiotap.dbm_antsignal": "",
                "wlan.bssid": "",
                "wlan.da": "",
                "wlan.ra": "",
                "wlan.sa": "",
                "wlan.fc.type": "",
                "wlan.fc.subtype": "",
                "wlan.fc.retry": "",
                "Label": "Normal",
            }
        )

        self.assertIsNotNone(packet)
        self.assertEqual(packet["timestamp_epoch"], 200.25)
        self.assertEqual(packet["packet_type"], "Unknown")
        self.assertEqual(packet["frame_type"], "Unknown")
        self.assertEqual(packet["source_mac"], "Unknown")
        self.assertEqual(packet["destination_mac"], "Unknown")
        self.assertEqual(packet["bssid"], "Unknown")
        self.assertIsNone(packet["signal_strength"])
        self.assertEqual(packet["retry_flag"], 0)

        # Extract features for single packet with missing values
        features = _feature_row_for_window([packet], label=0, window_seconds=5.0)
        self.assertEqual(len(features), 32)
        for key, val in features.items():
            self.assertIsNotNone(val)
            self.assertFalse(math.isnan(float(val)))

    def test_capture_file_independence(self) -> None:
        """Verify separate capture CSV files do not merge windows across capture boundaries."""
        with tempfile.TemporaryDirectory() as temp_dir:
            file1 = Path(temp_dir) / "capture_1.csv"
            file2 = Path(temp_dir) / "capture_2.csv"
            output_csv = Path(temp_dir) / "output.csv"

            # Capture 1 ends at 104.0
            with file1.open("w", newline="", encoding="utf-8") as f1:
                w1 = csv.DictWriter(f1, fieldnames=AWID3_TEST_FIELDS)
                w1.writeheader()
                w1.writerow(_row("100.0", "Normal"))
                w1.writerow(_row("104.0", "Normal"))

            # Capture 2 starts at 104.5 (would be within 5s if merged, but should be independent)
            with file2.open("w", newline="", encoding="utf-8") as f2:
                w2 = csv.DictWriter(f2, fieldnames=AWID3_TEST_FIELDS)
                w2.writeheader()
                w2.writerow(_row("104.5", "Deauth", subtype="12"))

            total_windows = process_awid3_dataset([file1, file2], output_csv)
            self.assertEqual(total_windows, 2)

            with output_csv.open("r", newline="", encoding="utf-8") as out:
                rows = list(csv.DictReader(out))
                self.assertEqual(len(rows), 2)
                self.assertEqual(rows[0][OUTPUT_LABEL_COLUMN], "0")
                self.assertEqual(float(rows[0]["total_packets"]), 2.0)
                self.assertEqual(rows[1][OUTPUT_LABEL_COLUMN], "1")
                self.assertEqual(float(rows[1]["total_packets"]), 1.0)

    def test_evaluation_dataset_validation(self) -> None:
        """Verify strict dataset validation for ML Testing evaluation."""
        # 1. Valid DataFrame
        valid_data = {
            feat: [1.0, 2.0] for feat in V3_FEATURE_NAMES
        }
        valid_data["label"] = [0, 1]
        valid_df = pd.DataFrame(valid_data)
        is_valid, msg, label_col = validate_dataset_data(valid_df, "valid.csv")
        self.assertTrue(is_valid, f"Expected valid dataset, got: {msg}")
        self.assertEqual(label_col, "label")

        # 2. Empty dataset
        empty_df = pd.DataFrame()
        is_valid, msg, _ = validate_dataset_data(empty_df, "empty.csv")
        self.assertFalse(is_valid)
        self.assertIn("empty", msg.lower())

        # 3. Missing label column
        no_label_df = pd.DataFrame({feat: [1.0] for feat in V3_FEATURE_NAMES})
        is_valid, msg, _ = validate_dataset_data(no_label_df, "no_label.csv")
        self.assertFalse(is_valid)
        self.assertIn("missing a ground-truth 'label'", msg)

        # 4. Non-binary label column
        invalid_label_data = {feat: [1.0, 2.0] for feat in V3_FEATURE_NAMES}
        invalid_label_data["label"] = [0, 2]  # 2 is invalid
        invalid_label_df = pd.DataFrame(invalid_label_data)
        is_valid, msg, _ = validate_dataset_data(invalid_label_df, "invalid_label.csv")
        self.assertFalse(is_valid)
        self.assertIn("invalid class labels", msg)

        # 5. Non-finite / NaN feature values
        nan_data = {feat: [1.0, 2.0] for feat in V3_FEATURE_NAMES}
        nan_data["label"] = [0, 1]
        nan_data["total_packets"] = [1.0, np.nan]
        nan_df = pd.DataFrame(nan_data)
        is_valid, msg, _ = validate_dataset_data(nan_df, "nan_feature.csv")
        self.assertFalse(is_valid)
        self.assertIn("non-finite or missing", msg)

        # 6. Column count / schema mismatch
        incomplete_data = {feat: [1.0] for feat in V3_FEATURE_NAMES[:20]}
        incomplete_data["label"] = [0]
        incomplete_df = pd.DataFrame(incomplete_data)
        is_valid, msg, _ = validate_dataset_data(incomplete_df, "incomplete.csv")
        self.assertFalse(is_valid)
        self.assertIn("validation failed", msg)

        # 7. Ambiguous label columns (contains both 'label' and 'Label')
        ambiguous_data = {feat: [1.0, 2.0] for feat in V3_FEATURE_NAMES}
        ambiguous_data["label"] = [0, 1]
        ambiguous_data["Label"] = [0, 1]
        ambiguous_df = pd.DataFrame(ambiguous_data)
        is_valid, msg, _ = validate_dataset_data(ambiguous_df, "ambiguous.csv")
        self.assertFalse(is_valid)
        self.assertIn("Ambiguous label columns", msg)

        # 8. Single-class Normal-only dataset (missing Attack)
        normal_only_data = {feat: [1.0, 2.0] for feat in V3_FEATURE_NAMES}
        normal_only_data["label"] = [0, 0]
        normal_only_df = pd.DataFrame(normal_only_data)
        is_valid, msg, _ = validate_dataset_data(normal_only_df, "normal_only.csv")
        self.assertFalse(is_valid)
        self.assertIn("contains only one class", msg)
        self.assertIn("Normal (0)", msg)
        self.assertIn("missing: Attack (1)", msg)

        # 9. Single-class Attack-only dataset (missing Normal)
        attack_only_data = {feat: [1.0, 2.0] for feat in V3_FEATURE_NAMES}
        attack_only_data["label"] = [1, 1]
        attack_only_df = pd.DataFrame(attack_only_data)
        is_valid, msg, _ = validate_dataset_data(attack_only_df, "attack_only.csv")
        self.assertFalse(is_valid)
        self.assertIn("contains only one class", msg)
        self.assertIn("Attack (1)", msg)
        self.assertIn("missing: Normal (0)", msg)

    def test_secure_dataset_path_resolution(self) -> None:
        """Verify strict dataset path resolution inside ML_TEST_DATASETS_DIR."""
        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir) / "ml_test_datasets"
            base_dir.mkdir(parents=True, exist_ok=True)
            outside_dir = Path(temp_dir) / "outside"
            outside_dir.mkdir(parents=True, exist_ok=True)

            valid_file = base_dir / "valid_test.csv"
            valid_file.write_text("dummy", encoding="utf-8")

            outside_file = outside_dir / "secret.csv"
            outside_file.write_text("secret", encoding="utf-8")

            # 1. Valid filename inside directory
            resolved_1 = resolve_secure_dataset_path("valid_test.csv", base_dir=base_dir)
            self.assertEqual(resolved_1, valid_file.resolve())

            # 2. Absolute path inside directory
            resolved_2 = resolve_secure_dataset_path(valid_file, base_dir=base_dir)
            self.assertEqual(resolved_2, valid_file.resolve())

            # 3. Absolute path outside directory
            with self.assertRaises(ValueError) as ctx_outside:
                resolve_secure_dataset_path(outside_file, base_dir=base_dir)
            self.assertIn("Access denied", str(ctx_outside.exception))

            # 4. Traversal with ../
            with self.assertRaises(ValueError) as ctx_traversal:
                resolve_secure_dataset_path("../outside/secret.csv", base_dir=base_dir)
            self.assertIn("Access denied", str(ctx_traversal.exception))

            # 5. Symlink escape where supported by the OS
            symlink_path = base_dir / "symlink_escape.csv"
            try:
                os.symlink(outside_file, symlink_path)
                has_symlink = True
            except (OSError, NotImplementedError):
                has_symlink = False

            if has_symlink:
                with self.assertRaises(ValueError) as ctx_symlink:
                    resolve_secure_dataset_path(symlink_path, base_dir=base_dir)
                self.assertIn("Access denied", str(ctx_symlink.exception))


if __name__ == "__main__":
    unittest.main()
