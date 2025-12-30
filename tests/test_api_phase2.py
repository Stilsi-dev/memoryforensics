"""Extended test suite for Phase 2 features: IOCs, timeline, export."""
import pytest
import sqlite3
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient

# Import from backend/app/main.py
import sys
from pathlib import Path as PathlibPath
backend_dir = PathlibPath(__file__).resolve().parents[1] / "backend" / "app"
sys.path.insert(0, str(backend_dir))

from main import app, DB_PATH, _init_db

@pytest.fixture
def client():
    """TestClient with fresh test database."""
    test_db = Path(tempfile.gettempdir()) / "test_cases.db"
    test_db.unlink(missing_ok=True)
    
    # Monkey-patch DB_PATH
    import main
    original_db = main.DB_PATH
    main.DB_PATH = test_db
    
    _init_db()
    yield TestClient(app)
    
    # Cleanup
    main.DB_PATH = original_db
    test_db.unlink(missing_ok=True)

@pytest.fixture
def api_key():
    """Test API key."""
    return "test-api-key-12345"

@pytest.fixture(autouse=True)
def set_api_key(monkeypatch, api_key):
    """Set API key for all tests."""
    monkeypatch.setenv("API_KEY", api_key)

def test_health_check(client):
    """Test health endpoint."""
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"

def test_list_cases_unauthorized(client):
    """Test missing API key."""
    res = client.get("/api/cases")
    assert res.status_code == 401

def test_upload_without_file(client, api_key):
    """Test upload without file."""
    res = client.post("/api/cases/upload", headers={"x-api-key": api_key})
    assert res.status_code in [400, 422]

def test_upload_success(client, api_key):
    """Test successful upload."""
    content = b"test memory dump" * 100
    res = client.post(
        "/api/cases/upload",
        files={"file": ("test.mem", content)},
        headers={"x-api-key": api_key}
    )
    assert res.status_code == 200
    data = res.json()
    assert "case_id" in data
    return data["case_id"]

def test_get_case_not_found(client, api_key):
    """Test get non-existent case."""
    res = client.get("/api/cases/nonexistent", headers={"x-api-key": api_key})
    assert res.status_code == 404

def test_dashboard_queued_status(client, api_key):
    """Test dashboard with queued case."""
    # Upload first
    content = b"test memory dump" * 100
    res = client.post(
        "/api/cases/upload",
        files={"file": ("test.mem", content)},
        headers={"x-api-key": api_key}
    )
    case_id = res.json()["case_id"]
    
    # Get dashboard
    res = client.get(f"/api/cases/{case_id}/dashboard", headers={"x-api-key": api_key})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "queued"
    assert "threat_cards" in data
    assert "iocs" in data
    assert "timeline" in data

def test_process_tree_endpoint(client, api_key):
    """Test process tree endpoint."""
    # Upload first
    content = b"test memory dump" * 100
    res = client.post(
        "/api/cases/upload",
        files={"file": ("test.mem", content)},
        headers={"x-api-key": api_key}
    )
    case_id = res.json()["case_id"]
    
    # Get process tree
    res = client.get(f"/api/cases/{case_id}/process-tree", headers={"x-api-key": api_key})
    assert res.status_code == 200
    data = res.json()
    assert "tree" in data

def test_iocs_endpoint(client, api_key):
    """Test IOCs endpoint for ready case."""
    # Manually insert a ready case with IOCs
    from main import _connect, _serialize
    case_id = "test-case-iocs-123"
    iocs = {"hashes": ["abc123", "def456"], "ips": ["192.168.1.1"], "dlls": ["kernel32.dll"]}
    
    with _connect() as conn:
        conn.execute(
            "INSERT INTO cases (case_id, filename, stored_path, uploaded_at, status, iocs) VALUES (?, ?, ?, ?, ?, ?)",
            (case_id, "test.mem", "/tmp/test", "2024-01-01T00:00:00", "ready", _serialize(iocs))
        )
        conn.commit()
    
    # Test endpoint
    res = client.get(f"/api/cases/{case_id}/iocs", headers={"x-api-key": api_key})
    assert res.status_code == 200
    data = res.json()
    assert data["case_id"] == case_id
    assert "iocs" in data
    assert len(data["iocs"]["hashes"]) == 2
    assert len(data["iocs"]["ips"]) == 1
    assert len(data["iocs"]["dlls"]) == 1

def test_iocs_endpoint_not_ready(client, api_key):
    """Test IOCs endpoint for non-ready case."""
    # Upload first
    content = b"test memory dump" * 100
    res = client.post(
        "/api/cases/upload",
        files={"file": ("test.mem", content)},
        headers={"x-api-key": api_key}
    )
    case_id = res.json()["case_id"]
    
    # IOCs only available for ready cases
    res = client.get(f"/api/cases/{case_id}/iocs", headers={"x-api-key": api_key})
    assert res.status_code == 400

def test_timeline_endpoint(client, api_key):
    """Test timeline endpoint for ready case."""
    from main import _connect, _serialize
    case_id = "test-case-timeline-123"
    timeline = [
        {"timestamp": "2024-01-01T10:00:00", "pid": 1234, "process": "explorer.exe", "event": "Risk 75% - Code Injection"},
        {"timestamp": "2024-01-01T10:01:00", "pid": 5678, "process": "svchost.exe", "event": "Risk 45% - Anomaly"}
    ]
    
    with _connect() as conn:
        conn.execute(
            "INSERT INTO cases (case_id, filename, stored_path, uploaded_at, status, timeline) VALUES (?, ?, ?, ?, ?, ?)",
            (case_id, "test.mem", "/tmp/test", "2024-01-01T00:00:00", "ready", _serialize(timeline))
        )
        conn.commit()
    
    # Test endpoint
    res = client.get(f"/api/cases/{case_id}/timeline", headers={"x-api-key": api_key})
    assert res.status_code == 200
    data = res.json()
    assert data["case_id"] == case_id
    assert "events" in data
    assert len(data["events"]) == 2

def test_export_iocs_csv(client, api_key):
    """Test export IOCs as CSV."""
    from main import _connect, _serialize
    case_id = "test-case-export-123"
    iocs = {"hashes": ["abc123", "def456"], "ips": ["192.168.1.1"], "dlls": ["kernel32.dll"]}
    
    with _connect() as conn:
        conn.execute(
            "INSERT INTO cases (case_id, filename, stored_path, uploaded_at, status, iocs) VALUES (?, ?, ?, ?, ?, ?)",
            (case_id, "test.mem", "/tmp/test", "2024-01-01T00:00:00", "ready", _serialize(iocs))
        )
        conn.commit()
    
    # Test endpoint
    res = client.post(f"/api/cases/{case_id}/export-iocs", headers={"x-api-key": api_key})
    assert res.status_code == 200
    assert res.headers["content-type"] == "text/csv; charset=utf-8"
    
    # Verify CSV content
    csv_content = res.content.decode("utf-8")
    assert "type,value" in csv_content
    assert "hash,abc123" in csv_content
    assert "ip,192.168.1.1" in csv_content
    assert "dll,kernel32.dll" in csv_content

def test_case_metadata_endpoint(client, api_key):
    """Test case metadata endpoint."""
    from main import _connect, _serialize
    case_id = "test-case-meta-123"
    
    with _connect() as conn:
        conn.execute(
            "INSERT INTO cases (case_id, filename, stored_path, uploaded_at, status) VALUES (?, ?, ?, ?, ?)",
            (case_id, "test.mem", "/tmp/test", "2024-01-01T00:00:00", "ready")
        )
        conn.commit()
    
    # Test endpoint
    res = client.get(f"/api/cases/{case_id}", headers={"x-api-key": api_key})
    assert res.status_code == 200
    data = res.json()
    assert data["case_id"] == case_id
    assert data["filename"] == "test.mem"
    assert data["status"] == "ready"

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
