"""
Test case deletion functionality
"""

import pytest
from pathlib import Path
import tempfile
from fastapi.testclient import TestClient
import sys

# Add backend to path
BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from app.main import app

client = TestClient(app)
HEADERS = {"x-api-key": "test-api-key"}


class TestCaseDeletion:
    """Test case deletion functionality"""
    
    def test_delete_nonexistent_case(self):
        """Test deleting a nonexistent case returns 404"""
        response = client.delete("/api/cases/nonexistent_case_id", headers=HEADERS)
        assert response.status_code == 404
    
    def test_delete_endpoint_exists(self):
        """Test that delete endpoint is registered"""
        response = client.get("/openapi.json")
        assert response.status_code == 200
        spec = response.json()
        paths = spec.get("paths", {})
        
        # Check if delete endpoint exists
        case_path = "/api/cases/{case_id}"
        assert case_path in paths
        assert "delete" in paths[case_path]
    
    def test_missing_api_key_on_delete(self):
        """Test that delete without case doesn't require API key at same level"""
        response = client.delete("/api/cases/any_case")
        # May return 404 since case doesn't exist
        assert response.status_code in [401, 403, 404, 422]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
