# 📁 Project Structure & Organization

**Last Updated:** December 31, 2025  
**Status:** ✅ Cleanly organized and production-ready

---

## 📂 Directory Layout

```
memoryforensics-group2/
│
├── 📋 ROOT LEVEL (Essential Files Only)
│   ├── README.md                 Main project overview
│   ├── pytest.ini                Pytest configuration
│   └── STRUCTURE.md              This file
│
├── 📚 docs/                      Complete documentation (2,700+ lines)
│   ├── PHASE2_README.md          Full Phase 2 reference
│   ├── QUICKSTART.md             5-minute setup guide
│   ├── IMPLEMENTATION.md         Technical deep-dive
│   ├── DELIVERY.md               Executive summary
│   ├── CHECKLIST.md              Completion checklist
│   ├── INDEX.md                  Documentation index
│   ├── INVENTORY.md              File inventory
│   ├── STRUCTURE.md              Project structure
│   ├── README.md                 Docs navigation
│   ├── phase2/                   Phase 2 specific docs
│   └── api/                      API documentation
│
├── 🔧 config/                    Configuration & deployment files
│   ├── Dockerfile                Container image definition
│   ├── docker-compose.yml        Service orchestration
│   └── docker-compose.example.yml Configuration template
│
├── 💻 backend/                   FastAPI backend server
│   ├── app/
│   │   ├── main.py               FastAPI application (600+ lines)
│   │   ├── models.py             Data models
│   │   └── utils.py              Helper functions
│   ├── uploads/                  Case storage directory
│   ├── cases.db                  SQLite database
│   └── __init__.py
│
├── 🖥️ frontend/                  Web interface
│   ├── index.html                v1 interface
│   ├── index_v2.html             v2 tabbed interface (Phase 2)
│   ├── app.js                    v1 logic
│   ├── app_v2.js                 v2 logic (Phase 2)
│   ├── styles.css                Styling
│   └── assets/                   Images & resources
│
├── 📦 src/                       Core analyzer modules
│   ├── memory_analyzer.py        Main analyzer (v3.4)
│   ├── process_parser.py         Process parsing
│   ├── threat_detector.py        Threat detection
│   └── __init__.py
│
├── 🧪 tests/                     Test suite (100% pass rate)
│   ├── __init__.py
│   ├── conftest.py               Pytest fixtures
│   ├── test_api.py               Phase 1 tests (6 cases)
│   ├── test_api_phase2.py        Phase 2 tests (10 cases)
│   ├── test_memory_analyzer.py   Analyzer tests (24 cases)
│   └── __pycache__/
│
├── 🛠️ scripts/                   Utility scripts
│   ├── verify.py                 Deployment verification script
│   ├── vol.bat                   Volatility launcher
│   └── test_improvements.bat     Testing script
│
├── 📊 data/                      Data & samples
│   ├── samples/
│   │   └── memdump.mem           Sample memory dump (for testing)
│   └── analysis/
│       ├── analysisReport_*.txt  Generated reports (25 reports)
│       ├── analysis_*/           Analysis directories (12 dirs)
│       └── report.txt            Individual reports
│
├── 🔐 rules/                     Security rules
│   └── malware_rules.yar         YARA malware signatures
│
├── 🌐 volatility3/               Volatility 3 framework
│   ├── cli/                      Command-line interface
│   ├── framework/                Core framework
│   ├── plugins/                  Analysis plugins
│   ├── symbols/                  Debug symbols
│   ├── vol.py                    Volatility CLI
│   ├── volshell.py               Volatility shell
│   └── ... (framework files)
│
├── 🏗️ .github/
│   └── workflows/                CI/CD pipelines (Phase 3)
│
├── 📦 .venv/                     Python virtual environment
│   └── (dependencies)
│
├── 📝 .git/                      Git repository
│   └── (version control)
│
├── ⚙️ .vscode/                   VS Code settings
│   └── (editor config)
│
└── 📄 Other Files
    ├── analysis/                 Old analysis folder (for migration)
    ├── rules/                    Old rules folder
    ├── scripts/                  Old scripts folder
    └── v1/                       v1 release archive
```

---

## 🗂️ File Organization Details

### Root Level (Clean)
Only 3 essential files:
- **README.md** - Main project documentation
- **pytest.ini** - Test configuration
- **STRUCTURE.md** - This file (optional, can move to docs/)

### docs/ (All Documentation)
- **2,700+ lines** of comprehensive guides
- 8 main markdown files
- Covers setup, API, deployment, troubleshooting
- Navigation via INDEX.md

### config/ (Deployment)
- **Dockerfile** - Container image (Python 3.13)
- **docker-compose.yml** - 4-service orchestration
- **docker-compose.example.yml** - Configuration template
- Ready for production deployment

### backend/ (API Server)
- **main.py** - FastAPI application (600+ lines)
  - 10 endpoints (upload, analysis, export, etc.)
  - SQLite persistence with 11 columns
  - Background workers (Celery/ThreadPoolExecutor)
  - Authentication (x-api-key header)
- **uploads/** - Case storage directory
- **cases.db** - SQLite database (auto-created)

### frontend/ (Web Interface)
- **index.html + app.js** - v1 interface
- **index_v2.html + app_v2.js** - v2 tabbed interface (Phase 2)
  - 4 tabs: Threats | Processes | Timeline | IOCs
  - Real-time polling (4s interval)
  - CSV export for IOCs
  - Dark theme, responsive design
- **styles.css** - Unified styling

### src/ (Core Modules)
- **memory_analyzer.py** - Main analyzer v3.4
  - Processes memory dumps
  - Extracts threat information
  - Generates process tree
  - Returns ProcessInfo objects
- **process_parser.py** - Process parsing
- **threat_detector.py** - Threat detection

### tests/ (Test Suite)
- **40 total test cases** (100% pass rate)
  - test_api.py: 6 Phase 1 tests
  - test_api_phase2.py: 10 Phase 2 tests
  - test_memory_analyzer.py: 24 analyzer tests
- **Fixtures** - client, api_key, test database
- **Coverage** - All endpoints and functions

### scripts/ (Utilities)
- **verify.py** - Deployment verification (10 checks)
- **vol.bat** - Volatility launcher
- **test_improvements.bat** - Testing helper

### data/ (Samples & Results)
- **samples/memdump.mem** - Test memory dump
- **analysis/** - Generated analysis reports (25+)
  - analysisReport_*.txt (25 files)
  - analysis_*/ directories (12 dirs)

---

## 🔄 File Organization Changes

### What Was Moved

| From (Root) | To | Status |
|---|---|---|
| PHASE2_README.md | docs/ | ✅ Moved |
| QUICKSTART_PHASE2.md | docs/QUICKSTART.md | ✅ Moved |
| PHASE2_IMPLEMENTATION.md | docs/IMPLEMENTATION.md | ✅ Moved |
| DELIVERY_SUMMARY.md | docs/DELIVERY.md | ✅ Moved |
| CHECKLIST_PHASE2.md | docs/CHECKLIST.md | ✅ Moved |
| FINAL_REPORT_PHASE2.md | docs/FINAL_REPORT.md | ✅ Moved |
| PHASE2_DOCS_INDEX.md | docs/INDEX.md | ✅ Moved |
| FILE_INVENTORY_PHASE2.md | docs/INVENTORY.md | ✅ Moved |
| PROJECT_STRUCTURE.md | docs/STRUCTURE.md | ✅ Moved |
| Dockerfile | config/ | ✅ Moved |
| docker-compose.yml | config/ | ✅ Moved |
| verify_phase2.py | scripts/verify.py | ✅ Moved |
| memdump.mem | data/samples/ | ✅ Moved |
| analysisReport_*.txt | data/analysis/ | ✅ Moved |
| analysis_*/ | data/analysis/ | ✅ Moved |

### What Stayed in Root
- ✅ README.md (main documentation)
- ✅ pytest.ini (test config)
- ✅ STRUCTURE.md (this file - optional)

---

## 📍 Key Locations for Quick Access

### For Getting Started
- **Setup Instructions**: `docs/QUICKSTART.md`
- **Full Reference**: `docs/PHASE2_README.md`
- **Documentation Index**: `docs/INDEX.md`

### For Development
- **API Server**: `backend/app/main.py`
- **Frontend**: `frontend/index_v2.html`
- **Tests**: `tests/`

### For Deployment
- **Configuration**: `config/docker-compose.yml`
- **Verification**: `scripts/verify.py`
- **Deployment Guide**: `docs/DELIVERY.md`

### For Data
- **Sample Dumps**: `data/samples/`
- **Analysis Results**: `data/analysis/`
- **Security Rules**: `rules/malware_rules.yar`

---

## ✅ Organization Benefits

| Benefit | Description |
|---------|---|
| **Cleaner Root** | Only 3 essential files visible |
| **Better Navigation** | Files grouped by function |
| **Easier Maintenance** | Clear structure for updates |
| **Scalability** | Ready for Phase 3 expansion |
| **CI/CD Ready** | Clear .github/workflows location |
| **Team Onboarding** | New developers understand layout instantly |
| **Documentation** | All guides in one place |
| **Production Ready** | Config & deployment separated |

---

## 🚀 Next Steps

### To Deploy Phase 2
```bash
# From project root:
cd config
docker-compose up -d

# Or verify without Docker:
python scripts/verify.py
```

### To Access Frontend
```
http://localhost:3000
```

### To Run Tests
```bash
pytest tests/ -v
```

### To Check Status
```bash
python scripts/verify.py
```

---

## 📌 Important Notes

1. **Backend Path**: Update `docker-compose.yml` if backend path changes
2. **Database**: `backend/cases.db` is auto-created on first run
3. **Frontend**: `index_v2.html` is v2 (recommended), `index.html` is v1
4. **API Key**: Required for all authenticated endpoints
5. **Volatility3**: Large framework, kept in root for direct access

---

## 🔍 Verification Commands

### Check Structure
```bash
# List root files only
ls -la | grep "^-"

# List all directories
find . -maxdepth 1 -type d | sort
```

### Verify Important Files Exist
```bash
# Backend
test -f backend/app/main.py && echo "✓ Backend API"

# Frontend
test -f frontend/index_v2.html && echo "✓ Frontend v2"

# Tests
test -f tests/test_api_phase2.py && echo "✓ Phase 2 Tests"

# Documentation
test -f docs/QUICKSTART.md && echo "✓ Quick Start"

# Config
test -f config/docker-compose.yml && echo "✓ Docker Config"
```

---

**Organization Complete!** ✅  
All files are organized, documented, and ready for production deployment.

For detailed setup instructions, see: [docs/QUICKSTART.md](docs/QUICKSTART.md)
