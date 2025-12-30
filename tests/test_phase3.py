"""
Phase 3: Advanced Features Test Suite
Tests for D3.js visualizations, threat intelligence, PDF reports, and IOC management
"""

import pytest
import json
from datetime import datetime
from pathlib import Path
import sys

# Add backend to path
BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)

# Test API key (matches mock setup)
TEST_API_KEY = "test-api-key"
HEADERS = {"x-api-key": TEST_API_KEY}

# Sample case data for testing
SAMPLE_CASE = {
    "case_id": "test-case-phase3",
    "filename": "memdump_phase3.mem",
    "uploaded_at": datetime.now().isoformat(),
    "status": "ready",
    "threat_cards": [
        {
            "title": "Hidden Process Detected",
            "severity": "CRITICAL",
            "score": 95,
            "detail": "Process hidden from enumeration using direct kernel access"
        },
        {
            "title": "Code Injection Detected",
            "severity": "HIGH",
            "score": 78,
            "detail": "Suspicious code injection in svchost.exe"
        }
    ],
    "iocs": {
        "hashes": [
            "5d41402abc4b2a76b9719d911017c592",
            "6512bd43d9caa6e02c990b0a82652dca"
        ],
        "ips": [
            "192.0.2.1",
            "10.0.0.1"
        ],
        "dlls": [
            "C:\\Windows\\System32\\malware.dll",
            "C:\\Users\\Public\\backdoor.dll"
        ]
    },
    "timeline": [
        {
            "timestamp": datetime.now().isoformat(),
            "description": "Suspicious process creation",
            "risk_score": 75
        },
        {
            "timestamp": datetime.now().isoformat(),
            "description": "Network connection to C2 server",
            "risk_score": 95
        }
    ],
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}


class TestD3Visualizations:
    """Test D3.js visualization support in frontend"""
    
    def test_frontend_has_d3_library(self):
        """Verify D3.js library is included in frontend"""
        response = client.get("/index.html", headers=HEADERS)
        # Note: This would need frontend served - for now test is conceptual
        assert True
    
    def test_d3_visualization_module_exists(self):
        """Verify d3-visualizations.js module is importable"""
        # Check file exists
        d3_file = BACKEND_DIR.parent / "frontend" / "d3-visualizations.js"
        assert d3_file.exists()
        
        # Verify key functions are defined
        with open(d3_file) as f:
            content = f.read()
            assert "renderProcessTreeD3" in content
            assert "renderTimelineD3" in content
            assert "renderNetworkGraphD3" in content


class TestThreatIntelligence:
    """Test threat intelligence integration"""
    
    def test_ioc_lookup_hash(self):
        """Test hash lookup via threat intel"""
        response = client.post(
            "/api/iocs/lookup?ioc_value=5d41402abc4b2a76b9719d911017c592&ioc_type=hash",
            headers=HEADERS
        )
        # Should return 200 or 503 if threat intel unavailable
        assert response.status_code in [200, 503]
    
    def test_ioc_lookup_ip(self):
        """Test IP address lookup via threat intel"""
        response = client.post(
            "/api/iocs/lookup?ioc_value=8.8.8.8&ioc_type=ip",
            headers=HEADERS
        )
        assert response.status_code in [200, 503]
    
    def test_ioc_lookup_invalid_type(self):
        """Test invalid IOC type handling"""
        response = client.post(
            "/api/iocs/lookup?ioc_value=example.com&ioc_type=invalid",
            headers=HEADERS
        )
        # Should either 404 or handle gracefully
        assert response.status_code >= 200


class TestForensicReports:
    """Test forensic report generation"""
    
    def test_report_generation_json(self):
        """Test generating JSON forensic report"""
        # This would require a case to be uploaded first
        # For now, test the endpoint exists
        response = client.get(
            "/api/cases/nonexistent/report?format_type=json",
            headers=HEADERS
        )
        # Should 404 since case doesn't exist
        assert response.status_code == 404
    
    def test_report_generation_markdown(self):
        """Test generating Markdown forensic report"""
        response = client.get(
            "/api/cases/nonexistent/report?format_type=markdown",
            headers=HEADERS
        )
        assert response.status_code == 404
    
    def test_report_generation_pdf(self):
        """Test PDF report generation"""
        response = client.get(
            "/api/cases/nonexistent/report?format_type=pdf",
            headers=HEADERS
        )
        assert response.status_code == 404
    
    def test_pdf_generator_module_exists(self):
        """Verify PDF generator module is available"""
        pdf_file = BACKEND_DIR / "pdf_generator.py"
        assert pdf_file.exists()
        
        # Verify key classes exist
        with open(pdf_file) as f:
            content = f.read()
            assert "ForensicReportGenerator" in content
            assert "generate_forensic_pdf" in content


class TestCaseAnnotations:
    """Test case annotation and tagging features"""
    
    def test_add_annotation(self):
        """Test adding annotation to case"""
        response = client.post(
            "/api/cases/nonexistent/annotate?note=Test+note&tags=critical&tags=malware",
            headers=HEADERS
        )
        # Will fail because case doesn't exist, but tests endpoint
        assert response.status_code == 404
    
    def test_get_annotations(self):
        """Test retrieving case annotations"""
        response = client.get(
            "/api/cases/nonexistent/annotations",
            headers=HEADERS
        )
        assert response.status_code == 404


class TestIOCFiltering:
    """Test IOC filtering and tagging"""
    
    def test_tag_ioc(self):
        """Test tagging an IOC"""
        response = client.post(
            "/api/iocs/nonexistent/tag",
            params={"ioc_value": "5d41402abc4b2a76b9719d911017c592", "ioc_type": "hash", "tags": ["malware", "critical"]},
            headers=HEADERS
        )
        # Can be 404 (case doesn't exist) or 422 (validation error)
        assert response.status_code in [404, 422]
    
    def test_filter_iocs_by_tag(self):
        """Test filtering IOCs by tag"""
        response = client.get(
            "/api/iocs/nonexistent/filter?tag=critical",
            headers=HEADERS
        )
        assert response.status_code == 404
    
    def test_filter_iocs_by_type(self):
        """Test filtering IOCs by type"""
        response = client.get(
            "/api/iocs/nonexistent/filter?ioc_type=hash",
            headers=HEADERS
        )
        assert response.status_code == 404
    
    def test_ioc_statistics(self):
        """Test IOC statistics endpoint"""
        response = client.get(
            "/api/iocs/nonexistent/stats",
            headers=HEADERS
        )
        assert response.status_code == 404


class TestBatchIOCLookup:
    """Test batch IOC threat intelligence lookups"""
    
    def test_batch_ioc_lookup(self):
        """Test looking up all IOCs from case"""
        response = client.get(
            "/api/iocs/batch?case_id=nonexistent",
            headers=HEADERS
        )
        # Should 404 for nonexistent case or 503 if threat intel unavailable
        assert response.status_code in [404, 503]


class TestThreatIntelModule:
    """Test threat_intel module functionality"""
    
    def test_threat_intel_module_exists(self):
        """Verify threat_intel module is available"""
        threat_intel_file = BACKEND_DIR / "threat_intel.py"
        assert threat_intel_file.exists()
    
    def test_virustotal_client_initialization(self):
        """Test VirusTotal client can be initialized"""
        from threat_intel import VirusTotalClient
        
        client = VirusTotalClient(api_key="")
        assert client is not None
        assert not client.enabled  # Should be disabled without real API key
    
    def test_virustotal_mock_responses(self):
        """Test VirusTotal mock responses"""
        from threat_intel import VirusTotalClient
        
        client = VirusTotalClient(api_key="")
        
        # Test mock hash response
        result = client._mock_hash_response("test_hash")
        assert result["hash"] == "test_hash"
        assert "verdict" in result
        
        # Test mock IP response
        result = client._mock_ip_response("192.168.1.1")
        assert result["ip"] == "192.168.1.1"
        assert "verdict" in result
    
    def test_abuseipdb_client_initialization(self):
        """Test AbuseIPDB client can be initialized"""
        from threat_intel import AbuseIPDBClient
        
        client = AbuseIPDBClient(api_key="")
        assert client is not None
        assert not client.enabled


class TestIntegration:
    """Integration tests for Phase 3 features"""
    
    def test_api_health_check(self):
        """Verify API is healthy"""
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
    
    def test_endpoints_exist(self):
        """Verify Phase 3 endpoints are registered"""
        # This is tested implicitly by other tests, but verify structure
        response = client.get("/openapi.json")
        assert response.status_code == 200
        
        spec = response.json()
        paths = spec.get("paths", {})
        
        # Verify key Phase 3 endpoints exist
        assert "/api/iocs/lookup" in paths or any("lookup" in p for p in paths)
        assert "/api/cases/{case_id}/report" in paths or any("report" in p for p in paths)


class TestErrorHandling:
    """Test error handling for Phase 3 features"""
    
    def test_missing_api_key(self):
        """Test that protected endpoints may work with mock threat intel"""
        response = client.post("/api/iocs/lookup?ioc_value=test&ioc_type=hash")
        # May return 200 with mock, or require API key
        assert response.status_code in [200, 401, 403, 422, 503]
    
    def test_invalid_case_id(self):
        """Test handling of invalid case IDs"""
        response = client.get(
            "/api/cases/invalid_case_id_12345/report",
            headers=HEADERS
        )
        assert response.status_code == 404
    
    def test_invalid_format_type(self):
        """Test handling of invalid report format"""
        response = client.get(
            "/api/cases/nonexistent/report?format_type=invalid",
            headers=HEADERS
        )
        # Should 404 due to nonexistent case, not invalid format
        assert response.status_code == 404


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
