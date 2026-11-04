"""ML Evaluation and Model Testing Module for NetShield ML WIDS.

Evaluates unseen test datasets against the frozen trained Random Forest model.
Validates the canonical 31-feature schema, generates comprehensive performance metrics,
confusion matrix, and per-class metrics without retraining or modifying the frozen model.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

try:
    from ml.feature_schema_validator import validate_feature_schema
    from ml.inference_service import PRODUCTION_MODEL_PATH
    from ml.v3_feature_schema import V3_FEATURE_COUNT, V3_FEATURE_NAMES
except ImportError:
    from backend.ml.feature_schema_validator import validate_feature_schema
    from backend.ml.inference_service import PRODUCTION_MODEL_PATH
    from backend.ml.v3_feature_schema import V3_FEATURE_COUNT, V3_FEATURE_NAMES


ML_TEST_DATASETS_DIR = Path(__file__).resolve().parents[1] / "data" / "ml_test_datasets"


def resolve_secure_dataset_path(
    dataset_path: str | Path,
    base_dir: Path = ML_TEST_DATASETS_DIR,
) -> Path:
    """Resolve and validate that a dataset path resides strictly inside base_dir.

    Prevents directory traversal, outside-directory access, and symlink escapes.
    Raises ValueError if the path escapes base_dir.
    """
    resolved_base = base_dir.resolve()
    raw_path = Path(dataset_path)

    # If raw_path is relative, anchor it to base_dir
    if not raw_path.is_absolute():
        candidate = (base_dir / raw_path).resolve()
    else:
        candidate = raw_path.resolve()

    # Verify that candidate is strictly within resolved_base
    try:
        candidate.relative_to(resolved_base)
    except ValueError as exc:
        raise ValueError(
            f"Access denied: dataset path '{dataset_path}' resolves outside the allowed directory "
            f"({resolved_base}). Directory traversal and outside paths are strictly rejected."
        ) from exc

    # Ensure it is not the directory itself
    if candidate == resolved_base:
        raise ValueError(f"Invalid dataset path: points to the directory itself ({resolved_base}).")

    return candidate


def validate_dataset_data(
    df: pd.DataFrame,
    filename: str = "dataset",
) -> tuple[bool, str, str | None]:
    """Validate that a dataset conforms to ML evaluation requirements.

    Checks:
    1. Dataset is not empty.
    2. Presence of exactly one label column ('label' or 'Label', rejecting ambiguous datasets with both).
    3. Exactly 31 canonical features matching V3_FEATURE_NAMES in exact order.
    4. Numeric binary labels strictly in {0, 1}, containing both classes 0 and 1.
    5. Numeric finite feature values across all 31 features (no NaN, inf, or unparseable).

    Returns:
        (is_valid, status_message, label_column_name)
    """
    if df.empty:
        return False, f"Test dataset is empty: {filename}", None

    has_lowercase = "label" in df.columns
    has_capitalized = "Label" in df.columns

    if has_lowercase and has_capitalized:
        return (
            False,
            f"Ambiguous label columns in {filename}: contains both 'label' and 'Label'. "
            "Exactly one label column must be present.",
            None,
        )

    if has_lowercase:
        label_col = "label"
    elif has_capitalized:
        label_col = "Label"
    else:
        return (
            False,
            f"Test dataset {filename} is missing a ground-truth 'label' column.",
            None,
        )

    feature_cols = [c for c in df.columns if c != label_col]
    is_valid_schema, status_msg, _ = validate_feature_schema(feature_cols)

    if not is_valid_schema:
        return (
            False,
            f"Feature schema validation failed for {filename}: {status_msg}. "
            f"Expected {V3_FEATURE_COUNT} features matching the authoritative training schema.",
            label_col,
        )

    # Validate label column has strictly numeric binary values
    try:
        y_numeric = pd.to_numeric(df[label_col], errors="coerce")
    except Exception:
        return False, f"Label column in {filename} contains non-numeric values.", label_col

    if y_numeric.isna().any():
        return False, f"Label column in {filename} contains missing or non-numeric values.", label_col

    unique_labels = set(y_numeric.unique())
    if not unique_labels.issubset({0, 1}):
        invalid_vals = sorted(unique_labels - {0, 1})
        return (
            False,
            f"Label column in {filename} contains invalid class labels: {invalid_vals}. "
            "Labels must be strictly binary (0=Normal, 1=Attack).",
            label_col,
        )

    # Must contain BOTH ground-truth classes: 0 and 1
    if unique_labels != {0, 1}:
        missing_class = "Attack (1)" if 1 not in unique_labels else "Normal (0)"
        present_class = "Normal (0)" if 0 in unique_labels else "Attack (1)"
        return (
            False,
            f"Dataset {filename} contains only one class ({present_class}). Full binary classification "
            f"evaluation requires both Normal (0) and Attack (1) samples; missing: {missing_class}.",
            label_col,
        )

    # Validate numeric finite feature values across all 31 canonical features
    for col in V3_FEATURE_NAMES:
        try:
            col_numeric = pd.to_numeric(df[col], errors="coerce")
        except Exception:
            return False, f"Feature column '{col}' in {filename} contains non-numeric values.", label_col

        if col_numeric.isna().any() or not np.isfinite(col_numeric).all():
            return (
                False,
                f"Feature column '{col}' in {filename} contains non-finite or missing values.",
                label_col,
            )

    return True, "Valid evaluation dataset (31 canonical features + binary label)", label_col


def list_available_test_datasets() -> list[dict[str, Any]]:
    """Scan backend/data/ml_test_datasets/ exclusively for CSV datasets and validate them."""
    datasets = []
    if not ML_TEST_DATASETS_DIR.exists():
        ML_TEST_DATASETS_DIR.mkdir(parents=True, exist_ok=True)
        return []

    for csv_path in sorted(ML_TEST_DATASETS_DIR.glob("*.csv")):
        try:
            full_df = pd.read_csv(csv_path)
            row_count = len(full_df)
            has_label = "label" in full_df.columns or "Label" in full_df.columns
            feature_cols = [c for c in full_df.columns if c.lower() != "label"]

            is_valid, status_msg, label_col = validate_dataset_data(full_df, csv_path.name)

            class_counts: dict[Any, int] = {}
            if label_col and has_label:
                try:
                    class_counts = full_df[label_col].value_counts().to_dict()
                except Exception:
                    pass

            datasets.append(
                {
                    "name": csv_path.name,
                    "filename": csv_path.name,
                    "filepath": str(csv_path),
                    "file_size_bytes": csv_path.stat().st_size,
                    "sample_count": row_count,
                    "has_label": has_label,
                    "feature_count": len(feature_cols),
                    "is_valid": is_valid,
                    "is_valid_schema": is_valid,
                    "schema_status": status_msg,
                    "normal_count": int(class_counts.get(0, 0)),
                    "attack_count": int(class_counts.get(1, 0)),
                }
            )
        except Exception as exc:
            datasets.append(
                {
                    "name": csv_path.name,
                    "filename": csv_path.name,
                    "filepath": str(csv_path),
                    "file_size_bytes": csv_path.stat().st_size if csv_path.exists() else 0,
                    "sample_count": 0,
                    "has_label": False,
                    "feature_count": 0,
                    "is_valid": False,
                    "is_valid_schema": False,
                    "schema_status": f"Unreadable CSV file: {str(exc)}",
                    "normal_count": 0,
                    "attack_count": 0,
                }
            )

    return datasets


def evaluate_test_dataset(
    dataset_path: str | Path,
    model_path: str | Path = PRODUCTION_MODEL_PATH,
) -> dict[str, Any]:
    """Evaluate an unseen test dataset against the trained model."""
    path = resolve_secure_dataset_path(dataset_path)

    if not path.exists():
        raise FileNotFoundError(f"Test dataset not found in {ML_TEST_DATASETS_DIR}: {path.name}")

    df = pd.read_csv(path)
    is_valid, error_msg, label_col = validate_dataset_data(df, path.name)
    if not is_valid:
        raise ValueError(error_msg)

    # Order features strictly by V3_FEATURE_NAMES
    X = df[V3_FEATURE_NAMES].astype(float)
    y_raw = df[label_col].astype(int)

    # Load trained model
    m_path = Path(model_path)
    if not m_path.exists():
        raise FileNotFoundError(f"Production model file not found: {m_path}")

    model = joblib.load(m_path)

    # Model metadata
    model_name = m_path.name
    model_type = type(model).__name__
    n_estimators = getattr(model, "n_estimators", None)

    # Predictions
    y_pred = model.predict(X)
    y_proba = model.predict_proba(X) if hasattr(model, "predict_proba") else None

    # Calculate metrics
    accuracy = float(accuracy_score(y_raw, y_pred))
    precision = float(precision_score(y_raw, y_pred, average="binary", zero_division=0))
    recall = float(recall_score(y_raw, y_pred, average="binary", zero_division=0))
    f1 = float(f1_score(y_raw, y_pred, average="binary", zero_division=0))

    cm = confusion_matrix(y_raw, y_pred, labels=[0, 1])
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])

    report_dict = classification_report(
        y_raw,
        y_pred,
        labels=[0, 1],
        target_names=["Normal (0)", "Attack (1)"],
        output_dict=True,
        zero_division=0,
    )

    total_samples = len(y_raw)
    correct_samples = int((y_raw == y_pred).sum())
    incorrect_samples = int((y_raw != y_pred).sum())

    normal_support = int((y_raw == 0).sum())
    attack_support = int((y_raw == 1).sum())

    per_class_metrics = {
        "normal": {
            "label": "Normal (0)",
            "precision": round(float(report_dict["Normal (0)"]["precision"]), 4),
            "recall": round(float(report_dict["Normal (0)"]["recall"]), 4),
            "f1_score": round(float(report_dict["Normal (0)"]["f1-score"]), 4),
            "support": int(report_dict["Normal (0)"]["support"]),
        },
        "attack": {
            "label": "Attack (1)",
            "precision": round(float(report_dict["Attack (1)"]["precision"]), 4),
            "recall": round(float(report_dict["Attack (1)"]["recall"]), 4),
            "f1_score": round(float(report_dict["Attack (1)"]["f1-score"]), 4),
            "support": int(report_dict["Attack (1)"]["support"]),
        },
    }

    # Samples breakdown (first 25 samples for UI inspection)
    sample_preview = []
    for i in range(min(total_samples, 25)):
        sample_preview.append(
            {
                "index": i,
                "actual": int(y_raw.iloc[i]),
                "actual_label": "Attack" if y_raw.iloc[i] == 1 else "Normal",
                "predicted": int(y_pred[i]),
                "predicted_label": "Attack" if y_pred[i] == 1 else "Normal",
                "is_correct": bool(y_raw.iloc[i] == y_pred[i]),
                "attack_probability": round(float(y_proba[i][1]), 4) if y_proba is not None else None,
                "normal_probability": round(float(y_proba[i][0]), 4) if y_proba is not None else None,
            }
        )

    now_iso = datetime.now(timezone.utc).isoformat()
    return {
        "status": "completed",
        "created_at": now_iso,
        "evaluated_at": now_iso,
        "dataset_name": path.name,
        "dataset_path": str(path),
        "model_name": model_name,
        "model_type": model_type,
        "n_estimators": n_estimators,
        "features_matched": V3_FEATURE_COUNT,
        "total_features_required": V3_FEATURE_COUNT,
        "schema_validation": {
            "status_text": "31 / 31 features matched",
            "matched": True,
            "feature_count": V3_FEATURE_COUNT,
            "features": V3_FEATURE_NAMES,
        },
        "total_samples": total_samples,
        "correct_samples": correct_samples,
        "incorrect_samples": incorrect_samples,
        "normal_support": normal_support,
        "attack_support": attack_support,
        "metrics": {
            "accuracy": round(accuracy * 100, 2),
            "precision": round(precision * 100, 2),
            "recall": round(recall * 100, 2),
            "f1_score": round(f1 * 100, 2),
        },
        "confusion_matrix": {
            "matrix": [[tn, fp], [fn, tp]],
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp,
        },
        "per_class": per_class_metrics,
        "classification_report": report_dict,
        "sample_preview": sample_preview,
    }
