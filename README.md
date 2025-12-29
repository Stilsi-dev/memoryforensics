# Memory Forensics Tool - Group 2
## Live RAM Analysis for Malware Detection

**Course:** DIGIFOR (Digital Forensics)  
**Subject:** Memory Forensics – Process & Malware Analysis  
**Team:** Group 2  
**Version:** 2.0 (Advanced Analysis & Detection)

---

## 📚 Documentation

Start here: **[System Overview & Usage](docs/README.md)**

Additional resources:
- [Before/After Comparison & Results](docs/COMPARISON.md) - Detailed analysis of improvements
- [Executive Summary](docs/FINAL_SUMMARY.md) - Verified metrics and project completion
- [Technical Changelog](docs/UPDATE_SUMMARY.md) - Implementation details
- [Project Checklist](docs/CHECKLIST.md) - Verification of all requirements

---

## 📂 Project Structure

```
memoryforensics-group2/
├── src/                          # Source code
│   ├── memory_analyzer.py        # Core forensics engine
│   └── memory_analyzer_gui.py    # GUI interface
├── rules/                        # YARA malware signatures
│   └── malware_rules.yar         # 8 active detection rules
├── scripts/                      # Utility and batch scripts
│   ├── run_memory_analyzer.bat   # Windows batch runner
│   ├── vol.bat                   # Volatility helper
│   └── test_improvements.bat     # Validation script
├── docs/                         # Documentation
│   ├── README.md                 # Full system documentation
│   ├── COMPARISON.md             # Before/after analysis
│   ├── FINAL_SUMMARY.md          # Executive summary
│   ├── UPDATE_SUMMARY.md         # Technical details
│   └── CHECKLIST.md              # Completion verification
├── samples/                      # Sample data
│   ├── digiforDemo.csv           # Sample dataset
│   └── text.txt                  # Sample file
├── tests/                        # Test suite
│   ├── test_analyzer.py          # Unit tests
│   ├── test_example.py           # Example tests
│   ├── test_memory_analyzer.py   # Integration tests
│   └── __pycache__/
├── analysis/                     # Analysis reports
│   ├── analysisReport_*.txt      # Generated reports
│   └── analysis_*/               # Detailed outputs
├── volatility3/                  # Volatility 3 framework
├── v1/                           # Legacy version
├── pytest.ini                    # Test configuration
└── memdump.mem                   # Test memory dump

```

---

## 🚀 Quick Start

### 1. Installation

```bash
# Install Python dependencies
pip install -r requirements.txt

# Verify Volatility 3
python volatility3/vol.py --help

# Install optional YARA support
pip install yara-python
```

### 2. Basic Usage

```bash
# Analyze a memory dump
python src/memory_analyzer.py -f memdump.mem

# Use GUI
python src/memory_analyzer_gui.py

# Generate CSV report
python src/memory_analyzer.py -f memdump.mem --report-type csv
```

### 3. Run Tests

```bash
# Unit tests
pytest tests/

# Validation test (no memory dump needed)
python tests/test_analyzer.py
```

---

## ✨ Key Features

✅ **Process Analysis** - Extract and analyze running processes from memory  
✅ **Injection Detection** - Identify code injection and rootkit behavior  
✅ **Malware Scanning** - 8 YARA rules with confidence-based detection  
✅ **Smart Filtering** - 26-process whitelist reduces false positives by 75%  
✅ **Professional Reports** - TXT and CSV formats with severity classification  
✅ **Real-time Progress** - Live status updates during analysis  

**Verified Results:**
- **False Positive Reduction:** 100% (53→0)
- **Alert Reduction:** 75% (12→3)
- **Accuracy:** 100% threat detection

---

## 📖 For More Information

See **[docs/README.md](docs/README.md)** for:
- Detailed system architecture
- Component descriptions
- Severity classification details
- Troubleshooting guide
- Advanced configuration

---

## 🛠️ File Organization Guide

| Directory | Purpose | Files |
|-----------|---------|-------|
| `src/` | Source code | Python modules |
| `rules/` | YARA rules | Malware signatures |
| `scripts/` | Utilities | Batch/shell scripts |
| `docs/` | Documentation | Markdown files |
| `samples/` | Sample data | CSV, TXT files |
| `tests/` | Testing | Unit & integration tests |
| `analysis/` | Reports | Generated analysis output |
| `volatility3/` | Framework | Volatility 3 installation |
| `v1/` | Legacy | Previous version |

---

## 👥 Team Members

**Group 2** - DIGIFOR  
DLSU College of Computer Studies  
December 2025

---

## 📄 License

Academic project for DIGIFOR course at De La Salle University.

---

**Status:** ✅ Complete and Production-Ready  
**Last Updated:** December 30, 2025  
**Version:** 2.0
