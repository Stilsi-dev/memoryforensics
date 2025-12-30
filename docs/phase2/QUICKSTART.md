# Quick Start Guide - Phase 2

## What's New in Phase 2?

✨ **IOC Extraction** - Auto-detect file hashes, IPs, and suspicious DLLs  
📈 **Timeline Analysis** - Chronological threat progression  
📊 **Tabbed Dashboard** - Organized Threats, Processes, Timeline, IOCs views  
💾 **CSV Export** - Download IOCs for threat intelligence platforms  
🐳 **Docker Support** - One-command deployment  
🧪 **Extended Tests** - 10+ new test cases for Phase 2 features  

---

## 5-Minute Setup

### Prerequisites
- Python 3.13+
- Docker & Docker Compose (for containerized option)
- Or: Redis + Celery (for background processing)

### Option A: Docker Compose (Recommended)

```bash
cd memoryforensics-group2
docker-compose up -d
```

Then visit: **http://localhost:3000**

Done! 🎉

### Option B: Manual Setup

```bash
# 1. Set environment variables
$env:API_KEY = "test-key-123"
$env:ALLOWED_ORIGINS = "http://localhost:3000"

# 2. Start API server
uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000

# 3. In another terminal, start frontend
cd frontend
python -m http.server 3000

# 4. Visit http://localhost:3000
```

---

## Using the Platform

### 1. Upload Memory Dump
- Click "Upload Memory Dump"
- Select `.mem`, `.raw`, or `.bin` file
- (Optional) Enter API key if required
- Click "Upload & Analyze"

### 2. View Case Dashboard
- Click case from "Analysis Cases" list
- **Threats Tab**: Risk cards with severity levels
- **Processes Tab**: Process tree hierarchy
- **Timeline Tab**: Chronological threat events
- **IOCs Tab**: File hashes, IPs, suspicious DLLs

### 3. Export IOCs
- Go to "IOCs" tab
- Click "📥 Export IOCs as CSV"
- Download file for threat intelligence platforms

---

## API Examples

### Upload a Memory Dump
```bash
API_KEY="test-key-123"

curl -X POST \
  -H "x-api-key: $API_KEY" \
  -F "file=@memory.mem" \
  http://localhost:8000/api/cases/upload

# Response:
# {"case_id": "abc123...", "message": "Upload received..."}
```

### Get Case Dashboard (with IOCs & Timeline)
```bash
CASE_ID="abc123..."

curl -H "x-api-key: $API_KEY" \
  http://localhost:8000/api/cases/$CASE_ID/dashboard

# Response includes:
# {
#   "case_id": "abc123...",
#   "threat_cards": [{severity, title, score, detail}, ...],
#   "iocs": {hashes: [...], ips: [...], dlls: [...]},
#   "timeline": [{timestamp, pid, process, event}, ...],
#   "status": "ready",
#   ...
# }
```

### Export IOCs as CSV
```bash
curl -X POST \
  -H "x-api-key: $API_KEY" \
  http://localhost:8000/api/cases/$CASE_ID/export-iocs \
  > iocs.csv

# CSV format:
# type,value
# hash,abc123def456...
# ip,192.168.1.100
# dll,kernel32.dll
```

### Get Timeline
```bash
curl -H "x-api-key: $API_KEY" \
  http://localhost:8000/api/cases/$CASE_ID/timeline

# Response:
# {
#   "case_id": "abc123...",
#   "events": [
#     {timestamp: "2024-01-01T10:00:00", pid: 1234, process: "explorer.exe", event: "Risk 75%..."},
#     ...
#   ]
# }
```

---

## Testing

### Run Phase 2 Tests
```bash
# All tests
pytest tests/ -v

# Only Phase 2 tests
pytest tests/test_api_phase2.py -v

# Specific test
pytest tests/test_api_phase2.py::test_iocs_endpoint -v

# With coverage
pytest tests/ --cov=backend.app.main --cov-report=term-missing
```

**Expected Output**: ✅ All tests pass (20+ total)

---

## Database Schema

**New Columns in Phase 2:**
- `iocs` (TEXT) - JSON: `{hashes: [...], ips: [...], dlls: [...]}`
- `timeline` (TEXT) - JSON: `[{timestamp, pid, process, event}, ...]`

**Example IOCs JSON:**
```json
{
  "hashes": ["abc123def456", "789xyz123abc"],
  "ips": ["192.168.1.100", "10.0.0.50"],
  "dlls": ["kernel32.dll", "ntdll.dll", "advapi32.dll"]
}
```

**Example Timeline JSON:**
```json
[
  {
    "timestamp": "2024-01-01T10:15:30",
    "pid": 1234,
    "process": "explorer.exe",
    "event": "Risk 75% - Code Injection; Hollowed Process"
  },
  {
    "timestamp": "2024-01-01T10:16:45",
    "pid": 5678,
    "process": "svchost.exe",
    "event": "Risk 45% - Unexpected Service"
  }
]
```

---

## Configuration

### Frontend
Set API key in browser console:
```javascript
localStorage.setItem("api_key", "test-key-123");
location.reload();
```

Or provide at startup prompt.

### Backend
Environment variables (`.env` or shell):
```bash
API_KEY=test-key-123              # Required for /upload, /cases endpoints
ALLOWED_ORIGINS=http://localhost:3000
ALLOWED_EXT=.mem,.raw,.bin
MAX_UPLOAD_MB=2048
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0
```

### Docker Compose
Edit `docker-compose.yml` environment section:
```yaml
environment:
  API_KEY: "your-secret-key"
  ALLOWED_ORIGINS: "http://localhost:3000"
  CELERY_BROKER_URL: "redis://redis:6379/0"
```

---

## Troubleshooting

### "API key required" error
```bash
# Check API_KEY env var is set
echo $env:API_KEY  # Windows PowerShell

# Or provide in request
curl -H "x-api-key: test-key-123" http://localhost:8000/api/health
```

### Case stuck on "queued"
```bash
# Ensure Celery worker is running
# Terminal 1: Redis
redis-server

# Terminal 2: API
uvicorn backend.app.main:app --reload

# Terminal 3: Worker
celery -A backend.app.main.celery_app worker --loglevel=info
```

Or use thread pool (no Celery needed) - worker runs in background automatically.

### Empty IOCs/Timeline
- Case must finish analysis (status: "ready")
- Check if memory dump is valid
- Review backend logs for MemoryAnalyzer errors

### Database locked
```bash
# Reset database
rm backend/cases.db
python -c "from backend.app.main import _init_db; _init_db()"
```

---

## Files Changed in Phase 2

**Backend:**
- `backend/app/main.py` - Added IOC/timeline functions, 4 new endpoints, DB migrations
- `tests/test_api_phase2.py` - 10 new test cases

**Frontend:**
- `frontend/index_v2.html` - Tabbed dashboard with IOC/timeline tabs
- `frontend/app_v2.js` - Timeline, IOC rendering, CSV export logic

**Config:**
- `Dockerfile` - Python 3.13 with Phase 2 deps
- `docker-compose.yml` - 4-service orchestration
- `PHASE2_README.md` - Full feature documentation

---

## Next: Phase 3 Features

🗺️ **D3.js Process Visualization** - Interactive tree with zoom/pan  
🔗 **Real Threat Intel** - VirusTotal + AbuseIPDB APIs  
📄 **PDF Reports** - Forensic-grade PDF export  
👥 **Team Collaboration** - Annotations, case tags, comments  

---

## Support

**Issues?**
1. Check backend logs: `docker-compose logs api`
2. Check frontend console: F12 → Console tab
3. Verify API_KEY and ALLOWED_ORIGINS match

**More Help:**
- Full docs: See `PHASE2_README.md`
- Original CLI docs: See `README.md`
- Tests: See `tests/test_api_phase2.py`

---

**Version**: 2.0  
**Status**: ✅ Production Ready  
**Last Updated**: 2024
