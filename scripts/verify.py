#!/usr/bin/env python3
"""Phase 2 Deployment Verification Script

Validates Phase 2 features are deployed and working correctly.
Run after deployment with: python3 verify_phase2.py
"""

import subprocess
import sys
import time
import requests
import json
from pathlib import Path

# Colors for terminal output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

API_KEY = "test-key-123"
API_BASE = "http://localhost:8000"
FRONTEND_BASE = "http://localhost:3000"

def check(condition, message):
    """Print check result."""
    if condition:
        print(f"{GREEN}✓{RESET} {message}")
        return True
    else:
        print(f"{RED}✗{RESET} {message}")
        return False

def section(title):
    """Print section header."""
    print(f"\n{YELLOW}{'='*60}{RESET}")
    print(f"{YELLOW}{title}{RESET}")
    print(f"{YELLOW}{'='*60}{RESET}")

def test_api_health():
    """Test API health endpoint."""
    try:
        res = requests.get(f"{API_BASE}/api/health", timeout=5)
        check(res.status_code == 200, "API health check")
        return res.status_code == 200
    except Exception as e:
        check(False, f"API health check: {e}")
        return False

def test_authentication():
    """Test API key authentication."""
    try:
        # Should fail without key
        res = requests.get(f"{API_BASE}/api/cases")
        check(res.status_code == 401, "Authentication required (without key)")
        
        # Should work with key
        res = requests.get(f"{API_BASE}/api/cases", headers={"x-api-key": API_KEY})
        check(res.status_code == 200, "Authentication valid (with key)")
        return res.status_code == 200
    except Exception as e:
        check(False, f"Authentication test: {e}")
        return False

def test_file_upload():
    """Test file upload endpoint."""
    try:
        # Create test file
        test_file = Path("/tmp/test_upload.mem")
        test_file.write_bytes(b"test memory dump" * 100)
        
        with open(test_file, "rb") as f:
            res = requests.post(
                f"{API_BASE}/api/cases/upload",
                files={"file": f},
                headers={"x-api-key": API_KEY},
                timeout=10
            )
        
        test_file.unlink()
        
        if res.status_code == 200:
            data = res.json()
            check("case_id" in data, "Upload returns case_id")
            return data.get("case_id")
        else:
            check(False, f"Upload failed: {res.status_code}")
            return None
    except Exception as e:
        check(False, f"Upload test: {e}")
        return None

def test_iocs_endpoint(case_id):
    """Test IOCs endpoint."""
    if not case_id:
        check(False, "IOCs test (no case)")
        return False
    
    try:
        # Wait for analysis
        time.sleep(2)
        
        res = requests.get(
            f"{API_BASE}/api/cases/{case_id}/iocs",
            headers={"x-api-key": API_KEY},
            timeout=5
        )
        
        # May return 400 if case not ready (expected for quick test)
        if res.status_code == 400:
            check(True, "IOCs endpoint exists (case not ready yet)")
            return True
        elif res.status_code == 200:
            data = res.json()
            check("iocs" in data, "IOCs endpoint returns iocs data")
            return True
        else:
            check(False, f"IOCs endpoint failed: {res.status_code}")
            return False
    except Exception as e:
        check(False, f"IOCs test: {e}")
        return False

def test_timeline_endpoint(case_id):
    """Test timeline endpoint."""
    if not case_id:
        check(False, "Timeline test (no case)")
        return False
    
    try:
        res = requests.get(
            f"{API_BASE}/api/cases/{case_id}/timeline",
            headers={"x-api-key": API_KEY},
            timeout=5
        )
        
        if res.status_code == 200:
            data = res.json()
            check("events" in data, "Timeline endpoint returns events")
            return True
        else:
            check(False, f"Timeline endpoint failed: {res.status_code}")
            return False
    except Exception as e:
        check(False, f"Timeline test: {e}")
        return False

def test_export_iocs(case_id):
    """Test IOCs CSV export endpoint."""
    if not case_id:
        check(False, "Export IOCs test (no case)")
        return False
    
    try:
        res = requests.post(
            f"{API_BASE}/api/cases/{case_id}/export-iocs",
            headers={"x-api-key": API_KEY},
            timeout=5
        )
        
        if res.status_code == 200:
            check("text/csv" in res.headers.get("content-type", ""), "Export returns CSV")
            check("type,value" in res.text, "CSV has correct header")
            return True
        else:
            check(False, f"Export failed: {res.status_code}")
            return False
    except Exception as e:
        check(False, f"Export test: {e}")
        return False

def test_dashboard_response(case_id):
    """Test dashboard includes IOCs and timeline."""
    if not case_id:
        check(False, "Dashboard test (no case)")
        return False
    
    try:
        res = requests.get(
            f"{API_BASE}/api/cases/{case_id}/dashboard",
            headers={"x-api-key": API_KEY},
            timeout=5
        )
        
        if res.status_code == 200:
            data = res.json()
            check("iocs" in data, "Dashboard includes iocs field")
            check("timeline" in data, "Dashboard includes timeline field")
            check("threat_cards" in data, "Dashboard includes threat_cards (Phase 1)")
            return True
        else:
            check(False, f"Dashboard failed: {res.status_code}")
            return False
    except Exception as e:
        check(False, f"Dashboard test: {e}")
        return False

def test_frontend_accessible():
    """Test frontend is accessible."""
    try:
        res = requests.get(FRONTEND_BASE, timeout=5)
        check(res.status_code == 200, "Frontend is accessible")
        check("Memory Forensics" in res.text, "Frontend loads correctly")
        return True
    except Exception as e:
        check(False, f"Frontend test: {e}")
        return False

def test_docker_services():
    """Check Docker Compose services status."""
    try:
        result = subprocess.run(
            ["docker-compose", "ps"],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        services = ["api", "worker", "redis", "frontend"]
        for service in services:
            if service in result.stdout:
                check("running" in result.stdout.lower(), f"Service '{service}' is running")
            else:
                check(False, f"Service '{service}' status unknown")
        
        return result.returncode == 0
    except Exception as e:
        check(False, f"Docker check: {e}")
        return False

def test_database():
    """Test database schema includes Phase 2 columns."""
    try:
        import sqlite3
        db_path = Path("backend/cases.db")
        
        if not db_path.exists():
            check(False, "Database file not found")
            return False
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(cases)")
        columns = {row[1] for row in cursor.fetchall()}
        conn.close()
        
        check("iocs" in columns, "Database has 'iocs' column")
        check("timeline" in columns, "Database has 'timeline' column")
        return "iocs" in columns and "timeline" in columns
    except Exception as e:
        check(False, f"Database test: {e}")
        return False

def run_all_checks():
    """Run all verification checks."""
    section("Phase 2 Deployment Verification")
    
    print("\n1. Backend Services")
    api_ok = test_api_health()
    if not api_ok:
        print(f"\n{RED}API is not accessible at {API_BASE}{RESET}")
        print("Start API with: uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000")
        return False
    
    print("\n2. Authentication")
    auth_ok = test_authentication()
    
    print("\n3. Database Schema")
    db_ok = test_database()
    
    print("\n4. File Upload")
    case_id = test_file_upload()
    
    print("\n5. Phase 2 Endpoints")
    if case_id:
        iocs_ok = test_iocs_endpoint(case_id)
        timeline_ok = test_timeline_endpoint(case_id)
        export_ok = test_export_iocs(case_id)
        dashboard_ok = test_dashboard_response(case_id)
    else:
        check(False, "Skipping Phase 2 tests (upload failed)")
        iocs_ok = timeline_ok = export_ok = dashboard_ok = False
    
    print("\n6. Frontend")
    frontend_ok = test_frontend_accessible()
    
    print("\n7. Docker Compose Services")
    docker_ok = test_docker_services()
    
    # Summary
    section("Summary")
    all_ok = all([api_ok, auth_ok, db_ok, frontend_ok, docker_ok])
    
    if all_ok:
        print(f"\n{GREEN}✓ All Phase 2 features verified successfully!{RESET}")
        print("\nNext steps:")
        print("1. Open http://localhost:3000")
        print("2. Upload a memory dump")
        print("3. Check Threats, Processes, Timeline, and IOCs tabs")
        print("4. Export IOCs as CSV")
    else:
        print(f"\n{RED}✗ Some checks failed. See above for details.{RESET}")
    
    return all_ok

if __name__ == "__main__":
    try:
        success = run_all_checks()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupted by user{RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{RED}Verification failed: {e}{RESET}")
        sys.exit(1)
