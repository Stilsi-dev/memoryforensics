# Memory Forensics Analysis Platform - Phase 2

## Overview

Phase 2 extends the MVP with advanced threat intelligence, IOC extraction, timeline analysis, and enhanced visualizations. This builds on Phase 1's solid foundation of CLI analysis + web dashboard.

**Features Implemented:**
- ✅ **IOC Extraction**: Automated detection of file hashes, network IPs, suspicious DLLs
- ✅ **Timeline Analysis**: Threat progression visualization with timestamps and risk events
- ✅ **CSV Export**: Download IOCs in standard format for threat intel platforms
- ✅ **Tabbed Dashboard**: Organized interface (Threats, Processes, Timeline, IOCs)
- ✅ **Real Analyzer Integration**: Full memory analysis with ProcessInfo extraction
- ✅ **Database Persistence**: SQLite with 11-column schema (includes iocs, timeline)
- ✅ **Background Workers**: Celery + Redis (optional), ThreadPoolExecutor fallback
- ✅ **API Key Security**: x-api-key header enforcement on all protected routes
- ✅ **Docker Support**: Containerized deployment with docker-compose

## Deployment Options

### Option 1: Docker Compose (Recommended)

```bash
cd memoryforensics-group2
docker-compose up -d
```

This starts 4 services:
- **api** (port 8000): FastAPI server
- **worker** (background): Celery task processor
- **redis** (port 6379): Cache and job broker
- **frontend** (port 3000): Static web interface

Access: http://localhost:3000

### Option 2: Manual Setup

```bash
# Terminal 1: Redis (if Celery desired)
redis-server

# Terminal 2: API Server
$env:API_KEY = "your-secret-key"
$env:ALLOWED_ORIGINS = "http://localhost:3000"
uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000

# Terminal 3: Celery Worker (optional)
celery -A backend.app.main.celery_app worker --loglevel=info

# Terminal 4: Frontend
cd frontend
python -m http.server 3000
```

Access: http://localhost:3000

### Option 3: Test Environment

```bash
# Run all tests
pytest tests/test_api.py tests/test_api_phase2.py -v

# Run specific test
pytest tests/test_api_phase2.py::test_iocs_endpoint -v

# Run with coverage
pytest tests/ --cov=backend.app.main --cov-report=html
```

## API Endpoints

### Health & Status
```bash
GET /api/health
# Returns: {status: "ok", timestamp: "2024-01-01T00:00:00"}
```

### Case Management
```bash
# Upload memory dump
POST /api/cases/upload
  Headers: x-api-key: <key>
  Body: form-data file=<memory.mem>
  Returns: {case_id: "abc123...", message: "Upload received..."}

# List all cases
GET /api/cases
  Headers: x-api-key: <key>
  Returns: [{case_id, filename, status, uploaded_at, ...}, ...]

# Get case details
GET /api/cases/{case_id}
  Headers: x-api-key: <key>
  Returns: {case_id, filename, status, threat_cards, process_tree, iocs, timeline, ...}
```

### Dashboard & Analysis
```bash
# Get dashboard data (threats + metadata)
GET /api/cases/{case_id}/dashboard
  Headers: x-api-key: <key>
  Returns: {case_id, threat_cards: [{severity, title, score, detail}, ...], 
            iocs: {hashes, ips, dlls}, timeline: [...], status, uploaded_at, error}

# Get process tree
GET /api/cases/{case_id}/process-tree
  Headers: x-api-key: <key>
  Returns: {case_id, tree: {name, pid, children: [{...}]}}

# Get threat timeline
GET /api/cases/{case_id}/timeline
  Headers: x-api-key: <key>
  Returns: {case_id, events: [{timestamp, pid, process, event}, ...]}

# Get IOCs (hashes, IPs, DLLs)
GET /api/cases/{case_id}/iocs
  Headers: x-api-key: <key>
  Returns: {case_id, iocs: {hashes: [...], ips: [...], dlls: [...]}}
```

### Export & Reports
```bash
# Export IOCs as CSV
POST /api/cases/{case_id}/export-iocs
  Headers: x-api-key: <key>
  Returns: CSV file (type,value format)
  Example: hash,abc123def456
           ip,192.168.1.1
           dll,kernel32.dll

# Export PDF report (stub)
GET /api/cases/{case_id}/report.pdf
  Headers: x-api-key: <key>
  Returns: PDF byte stream
```

## Database Schema

**Table: cases**
```sql
case_id        TEXT PRIMARY KEY
filename       TEXT NOT NULL
stored_path    TEXT NOT NULL
uploaded_at    TEXT NOT NULL
status         TEXT NOT NULL (queued|processing|ready|error)
threat_cards   TEXT (JSON array)
process_tree   TEXT (JSON object)
iocs           TEXT (JSON {hashes: [], ips: [], dlls: []})
timeline       TEXT (JSON array)
error          TEXT
sha256         TEXT (unique, for deduplication)
```

## Frontend

### UI Sections
1. **Upload**: Drag-drop file input with API key support
2. **Cases List**: Grid of recent uploads with status badges
3. **Dashboard** (Tabbed Interface):
   - **Threats Tab**: Risk cards (Critical/High/Medium/Low) with scores
   - **Processes Tab**: Hierarchical process tree (System → child processes)
   - **Timeline Tab**: Chronological threat events with timestamps
   - **IOCs Tab**: Searchable table of file hashes, IPs, suspicious DLLs
   - **Export Button**: Download IOCs as CSV for threat intelligence

### Features
- Real-time case status updates (4s polling)
- Syntax highlighting for process tree and IOCs
- Color-coded threat severity levels
- Responsive grid layout for mobile/tablet
- API key persistence in localStorage

## Configuration

### Environment Variables
```bash
# API security
API_KEY=your-secret-key-here (optional, but recommended)
ALLOWED_ORIGINS=http://localhost:3000,https://example.com
ALLOWED_EXT=.mem,.raw,.bin,.dd

# Storage
MAX_UPLOAD_MB=2048

# Background processing
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0

# Analyzer paths (optional)
VOLATILITY3_PATH=/path/to/volatility3
YARA_RULES_PATH=/path/to/rules.yar
```

### Docker Compose Config
```yaml
environment:
  API_KEY: "secret-key"
  ALLOWED_ORIGINS: "http://localhost:3000"
  CELERY_BROKER_URL: "redis://redis:6379/0"
  CELERY_RESULT_BACKEND: "redis://redis:6379/0"
```

## Testing

### Test Coverage
- ✅ API health check
- ✅ Authentication (x-api-key validation)
- ✅ File upload with deduplication
- ✅ Case retrieval and metadata
- ✅ Dashboard endpoint with IOCs/timeline
- ✅ Process tree rendering
- ✅ IOC extraction and export
- ✅ Timeline generation
- ✅ CSV export format
- ✅ Error handling (404, 400, 401, 413)

### Run Tests
```bash
# Run all tests
pytest tests/ -v

# Run with coverage report
pytest tests/ --cov=backend.app.main --cov-report=term-missing

# Run specific test class
pytest tests/test_api_phase2.py -v -k test_iocs
```

### Test Database
Tests use temporary SQLite databases in `/tmp` for isolation and cleanup.

## Architecture

### Backend Stack
- **Framework**: FastAPI 0.100+
- **Server**: Uvicorn (ASGI)
- **Database**: SQLite (cases.db) with schema migrations
- **Analyzer**: MemoryAnalyzer v3.4 (ProcessInfo extraction)
- **Background**: Celery + Redis (optional; ThreadPoolExecutor fallback)
- **Forensics**: Volatility3 + YARA + fuzzy hashing

### Frontend Stack
- **Framework**: Vanilla JavaScript (no build tool)
- **Storage**: localStorage for API key persistence
- **API**: REST with x-api-key header
- **UI**: CSS Grid, responsive, dark theme

### Deployment
- **Containers**: Docker + docker-compose
- **Services**: 4 (api, worker, redis, frontend)
- **Networking**: Shared bridge network with service discovery

## IOC Extraction Logic

IOCs are extracted from `ProcessInfo` objects by analyzing:

1. **File Hashes**: SHA-256 and MD5 hashes of loaded DLLs
   - Source: `process.file_hashes` dictionary
   - Use case: Hash reputation lookup (VirusTotal, YARA)

2. **Network IPs**: Connections from process network activity
   - Source: `process.network_connections` list (IP:port format)
   - Use case: IP geolocation, threat intel feeds

3. **Suspicious DLLs**: Unsigned, injected, or known-malicious modules
   - Source: `process.suspicious_dlls` list
   - Use case: DLL reputation, loading context analysis

### Example Flow
```
Memory Dump → MemoryAnalyzer.analyze() 
→ ProcessInfo[] with risk_score, flags(), network_connections, file_hashes 
→ _extract_iocs() 
→ {"hashes": ["abc123..."], "ips": ["192.168.1.100"], "dlls": ["kernel32.dll"]} 
→ Stored in cases.iocs (SQLite)
→ Exposed via GET /api/cases/{id}/iocs
→ Exportable as CSV via POST /api/cases/{id}/export-iocs
```

## Timeline Generation

Timeline events are created from process metadata:

1. **Event Creation**: For each process with risk_score > 30
2. **Timestamp**: Process creation time (or "unknown")
3. **Indicators**: First 2 flags (e.g., "Code Injection", "Hollowed Process")
4. **Sorting**: Chronological order (oldest first)

### Example Event
```json
{
  "timestamp": "2024-01-01T10:15:30",
  "pid": 1234,
  "process": "explorer.exe",
  "event": "Risk 75% - Code Injection; Hollowed Process"
}
```

## Threat Intelligence Integration (Stub)

The `_lookup_threat_intel()` function is ready for integration with:
- **VirusTotal**: File hash reputation via API
- **AbuseIPDB**: IP reputation and threat intel
- **Custom**: Private threat feeds or OSINT sources

Stub implementation returns placeholder data; real API calls need configuration:
```python
# Example integration point
result = _lookup_threat_intel(ip_address, api_key="vt_api_key")
# → {ip, reputation: "malicious", votes: 42, ...}
```

## Next Steps (Phase 3)

1. **Advanced Visualizations**
   - D3.js interactive process tree with zoom/pan
   - Timeline with parallel threat tracks
   - Network graph of process connections

2. **Real Threat Intel**
   - VirusTotal API integration for hash lookups
   - AbuseIPDB integration for IP geolocation
   - Custom YARA rule scoring

3. **Forensic Reports**
   - Reportlab PDF generation with charts
   - Executive summary + technical details
   - Chain of custody documentation

4. **Collaboration Features**
   - Case tagging and annotation
   - Team comments and timeline markers
   - Analysis workflow state machine

5. **Performance Optimization**
   - Elasticsearch for large dump indexing
   - GPU acceleration for YARA matching
   - Distributed analysis via Celery routing

## Troubleshooting

### API Key Errors
```bash
# Set API key in request
curl -H "x-api-key: your-key" http://localhost:8000/api/health

# Or in frontend, use console
localStorage.setItem("api_key", "your-key")
```

### Process Tree Empty
- Ensure memory dump is valid (check file size > 1MB)
- Verify analyzer dependencies: `python -m volatility3 --version`
- Check backend logs for MemoryAnalyzer errors

### IOCs Not Showing
- Case must be in "ready" status (analysis completed)
- Check if memory dump has detectable processes
- Verify file hashes and network connections exist in ProcessInfo

### Docker Issues
```bash
# View container logs
docker-compose logs api
docker-compose logs worker

# Rebuild containers
docker-compose down
docker-compose build --no-cache
docker-compose up -d

# Clean volumes
docker-compose down -v
```

### Database Corruption
```bash
# Backup and reset
mv backend/cases.db backend/cases.db.bak
python -c "from backend.app.main import _init_db; _init_db()"
```

## Example Workflows

### Workflow 1: Quick Analysis
```bash
# 1. Upload dump
curl -F "file=@memory.mem" -H "x-api-key: key123" http://localhost:8000/api/cases/upload

# 2. Wait for processing (status: ready)
sleep 2 && curl http://localhost:8000/api/cases/case_id_here/dashboard -H "x-api-key: key123"

# 3. Review threats
# (via web interface or API JSON)

# 4. Export IOCs for threat intelligence
curl -X POST -H "x-api-key: key123" http://localhost:8000/api/cases/case_id_here/export-iocs > iocs.csv
```

### Workflow 2: Threat Hunting
```bash
# 1. Upload suspicious dump
# 2. Check timeline tab for chronological events
# 3. Identify earliest infection (lowest timestamp with high risk)
# 4. Export IOCs to threat intel platform
# 5. Look for related indicators across environment
```

### Workflow 3: Incident Response
```bash
# 1. Collect multiple memory dumps
# 2. Upload each dump separately
# 3. Compare threat cards across cases
# 4. Export IOC list from all cases
# 5. Generate combined PDF report (Phase 3)
```

## License

This project extends the Memory Forensics Analyzer v3.4. See main README.md for original license.

## Support

For issues or feature requests, refer to GitHub issues or contact the team at [your-contact-info].

---

**Last Updated**: 2024  
**Version**: 2.0  
**Status**: Production-Ready for Phase 2 features
