import pytest
from fastapi.testclient import TestClient
from backend.app.main import app, _init_db, DB_PATH
import sqlite3
import os

@pytest.fixture
def client():
    _init_db()
    return TestClient(app)

@pytest.fixture(autouse=True)
def cleanup():
    yield
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

def test_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"

def test_list_cases_no_auth(client):
    resp = client.get("/api/cases")
    assert resp.status_code == 401  # requires API key

def test_upload_no_file(client):
    resp = client.post("/api/cases/upload", headers={"x-api-key": ""})
    assert resp.status_code in [400, 422]  # missing file

def test_upload_success(client, tmp_path):
    test_file = tmp_path / "test.mem"
    test_file.write_bytes(b"x" * (1024 * 1024 * 10))  # 10MB
    
    with open(test_file, "rb") as f:
        resp = client.post(
            "/api/cases/upload",
            files={"file": ("test.mem", f)},
            headers={"x-api-key": ""}
        )
    assert resp.status_code == 200
    data = resp.json()
    assert "case_id" in data
    assert data["message"] == "Upload received and analysis queued"

def test_get_case_not_found(client):
    resp = client.get("/api/cases/nonexistent", headers={"x-api-key": ""})
    assert resp.status_code == 404

def test_dashboard_not_ready(client):
    # Create a queued case and check dashboard
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO cases (case_id, filename, stored_path, uploaded_at, status) VALUES (?, ?, ?, ?, ?)",
        ("test123", "test.mem", "/tmp/test.mem", "2025-01-01T00:00:00", "queued")
    )
    conn.commit()
    conn.close()
    
    resp = client.get("/api/cases/test123/dashboard", headers={"x-api-key": ""})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "queued"
