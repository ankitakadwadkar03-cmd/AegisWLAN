"""Unit and integration tests for incident triage status persistence and PATCH API.

This suite tests the SQLite incident repository and Flask PATCH API with full test isolation,
ensuring tests operate in an isolated temporary database and never touch production data.
"""

import json
import sqlite3
import sys
from pathlib import Path
import pytest

# Ensure backend directory is in sys.path
backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

import data.incident_store as incident_store
from data.incident_store import (
    initialize_database,
    create_incident,
    get_incidents,
    get_incident_by_id,
    update_incident_status,
    VALID_INCIDENT_STATUSES,
)
from app import app


@pytest.fixture(autouse=True)
def isolated_test_db(tmp_path, monkeypatch):
    """Ensure every test executes against a fresh, temporary SQLite database.

    Monkeypatches incident_store.DB_PATH so both unit functions and Flask routes
    interact strictly with tmp_path and never touch backend/data/netshield.db.
    """
    temp_db = tmp_path / "isolated_test_netshield.db"
    monkeypatch.setattr(incident_store, "DB_PATH", temp_db)
    initialize_database()
    yield temp_db


@pytest.fixture
def client():
    """Flask test client fixture."""
    app.config["TESTING"] = True
    with app.test_client() as test_client:
        yield test_client


@pytest.fixture
def sample_incident_data():
    """Canonical test incident payload dictionary."""
    return {
        "prediction": 1,
        "label": "Attack",
        "attack_probability": 0.942,
        "normal_probability": 0.058,
        "total_packets": 128,
        "window_start": 1600000000.0,
        "window_end": 1600000005.0,
        "feature_count": 31,
        "severity": "High",
        "status": "New",
    }


@pytest.fixture
def sample_incident_id(sample_incident_data):
    """Create a test incident in the isolated database and return its integer ID."""
    return create_incident(sample_incident_data)


# ============================================================================
# Storage Layer Unit Tests
# ============================================================================


def test_update_incident_status_success(sample_incident_id):
    """Verify that update_incident_status updates status in database and returns the record."""
    updated = update_incident_status(sample_incident_id, "Investigating")
    assert updated is not None
    assert updated["id"] == sample_incident_id
    assert updated["status"] == "Investigating"

    # Verify directly via reload (database persistence)
    reloaded = get_incident_by_id(sample_incident_id)
    assert reloaded is not None
    assert reloaded["status"] == "Investigating"

    # Transition to Resolved
    resolved = update_incident_status(sample_incident_id, "Resolved")
    assert resolved["status"] == "Resolved"
    assert get_incident_by_id(sample_incident_id)["status"] == "Resolved"


def test_update_incident_status_trims_whitespace(sample_incident_id):
    """Verify that update_incident_status strips surrounding whitespace."""
    updated = update_incident_status(sample_incident_id, "   Investigating   \n")
    assert updated["status"] == "Investigating"

    reloaded = get_incident_by_id(sample_incident_id)
    assert reloaded["status"] == "Investigating"

    updated2 = update_incident_status(sample_incident_id, " \tResolved ")
    assert updated2["status"] == "Resolved"


def test_update_incident_status_type_validation(sample_incident_id):
    """Verify update_incident_status rejects non-string types with ValueError."""
    non_string_values = [
        None,
        123,
        45.67,
        True,
        False,
        ["Resolved"],
        {"status": "Resolved"},
        ("Investigating",),
    ]
    for val in non_string_values:
        with pytest.raises(ValueError, match="Status must be a string"):
            update_incident_status(sample_incident_id, val)

    # Verify status in database remains "New"
    assert get_incident_by_id(sample_incident_id)["status"] == "New"


def test_update_incident_status_invalid_value(sample_incident_id):
    """Verify that unsupported status strings raise ValueError."""
    with pytest.raises(ValueError, match="Invalid incident status 'Pending'"):
        update_incident_status(sample_incident_id, "Pending")

    with pytest.raises(ValueError, match="Invalid incident status 'Closed'"):
        update_incident_status(sample_incident_id, "Closed")

    # Verify status in database remains "New"
    assert get_incident_by_id(sample_incident_id)["status"] == "New"


def test_update_incident_status_nonexistent_id():
    """Verify update returns None for non-existent incident ID."""
    result = update_incident_status(99999999, "Resolved")
    assert result is None


# ============================================================================
# Flask API Integration Tests
# ============================================================================


def test_api_patch_incident_success(client, sample_incident_id):
    """Verify PATCH /api/incidents/<id> endpoint updates status and returns 200."""
    response = client.patch(
        f"/api/incidents/{sample_incident_id}",
        data=json.dumps({"status": "Investigating"}),
        content_type="application/json",
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["incident"]["id"] == sample_incident_id
    assert payload["incident"]["status"] == "Investigating"

    # Verify via GET /api/incidents
    get_res = client.get("/api/incidents")
    assert get_res.status_code == 200
    incidents = get_res.get_json()["incidents"]
    match = next((inc for inc in incidents if inc["id"] == sample_incident_id), None)
    assert match is not None
    assert match["status"] == "Investigating"


def test_api_patch_incident_trims_whitespace(client, sample_incident_id):
    """Verify PATCH endpoint trims whitespace from valid status strings."""
    response = client.patch(
        f"/api/incidents/{sample_incident_id}",
        data=json.dumps({"status": "  Resolved  \n"}),
        content_type="application/json",
    )
    assert response.status_code == 200
    assert response.get_json()["incident"]["status"] == "Resolved"

    reloaded = get_incident_by_id(sample_incident_id)
    assert reloaded["status"] == "Resolved"


def test_api_patch_field_preservation(client, sample_incident_id, sample_incident_data):
    """Verify that updating an incident's triage status preserves all other columns."""
    original = get_incident_by_id(sample_incident_id)

    response = client.patch(
        f"/api/incidents/{sample_incident_id}",
        data=json.dumps({"status": "Investigating"}),
        content_type="application/json",
    )
    assert response.status_code == 200

    updated = get_incident_by_id(sample_incident_id)
    assert updated["status"] == "Investigating"
    assert updated["id"] == original["id"]
    assert updated["prediction"] == original["prediction"] == sample_incident_data["prediction"]
    assert updated["label"] == original["label"] == sample_incident_data["label"]
    assert pytest.approx(updated["attack_probability"]) == original["attack_probability"] == sample_incident_data["attack_probability"]
    assert pytest.approx(updated["normal_probability"]) == original["normal_probability"] == sample_incident_data["normal_probability"]
    assert updated["total_packets"] == original["total_packets"] == sample_incident_data["total_packets"]
    assert pytest.approx(updated["window_start"]) == original["window_start"] == sample_incident_data["window_start"]
    assert pytest.approx(updated["window_end"]) == original["window_end"] == sample_incident_data["window_end"]
    assert updated["feature_count"] == original["feature_count"] == sample_incident_data["feature_count"]
    assert updated["severity"] == original["severity"] == sample_incident_data["severity"]
    assert updated["created_at"] == original["created_at"]


@pytest.mark.parametrize("invalid_type_payload", [
    {"status": None},
    {"status": 123},
    {"status": 45.67},
    {"status": True},
    {"status": False},
    {"status": ["Resolved"]},
    {"status": {"state": "Resolved"}},
])
def test_api_patch_rejects_non_string_types(client, sample_incident_id, invalid_type_payload):
    """Verify PATCH returns HTTP 400 for null, numbers, booleans, arrays and objects."""
    response = client.patch(
        f"/api/incidents/{sample_incident_id}",
        data=json.dumps(invalid_type_payload),
        content_type="application/json",
    )
    assert response.status_code == 400
    payload = response.get_json()
    assert "error" in payload
    assert "The 'status' field must be a string." in payload["error"]

    # Ensure database record is untouched
    current = get_incident_by_id(sample_incident_id)
    assert current["status"] == "New"


def test_api_patch_incident_invalid_status_string(client, sample_incident_id):
    """Verify PATCH returns 400 for unsupported status string values."""
    response = client.patch(
        f"/api/incidents/{sample_incident_id}",
        data=json.dumps({"status": "Ignored"}),
        content_type="application/json",
    )
    assert response.status_code == 400
    payload = response.get_json()
    assert "error" in payload
    assert "Invalid incident status 'Ignored'" in payload["error"]

    # Ensure database record is untouched
    assert get_incident_by_id(sample_incident_id)["status"] == "New"


def test_api_patch_incident_missing_status(client, sample_incident_id):
    """Verify PATCH returns 400 when body does not contain 'status'."""
    response = client.patch(
        f"/api/incidents/{sample_incident_id}",
        data=json.dumps({"other": "field"}),
        content_type="application/json",
    )
    assert response.status_code == 400
    payload = response.get_json()
    assert "Request body must be a JSON object containing 'status'." in payload["error"]
    assert get_incident_by_id(sample_incident_id)["status"] == "New"


def test_api_patch_malformed_json(client, sample_incident_id):
    """Verify PATCH returns 400 for malformed JSON bodies."""
    response = client.patch(
        f"/api/incidents/{sample_incident_id}",
        data="This is not valid JSON! {status: true",
        content_type="application/json",
    )
    assert response.status_code == 400
    payload = response.get_json()
    assert "Request body must be a JSON object containing 'status'." in payload["error"]
    assert get_incident_by_id(sample_incident_id)["status"] == "New"


def test_api_patch_empty_body(client, sample_incident_id):
    """Verify PATCH returns 400 for empty request body."""
    response = client.patch(
        f"/api/incidents/{sample_incident_id}",
        data="",
        content_type="application/json",
    )
    assert response.status_code == 400
    assert "Request body must be a JSON object containing 'status'." in response.get_json()["error"]
    assert get_incident_by_id(sample_incident_id)["status"] == "New"


def test_api_patch_incident_not_found(client):
    """Verify PATCH returns 404 for non-existent incident ID."""
    response = client.patch(
        "/api/incidents/99999999",
        data=json.dumps({"status": "Resolved"}),
        content_type="application/json",
    )
    assert response.status_code == 404
    assert "not found" in response.get_json()["error"].lower()
