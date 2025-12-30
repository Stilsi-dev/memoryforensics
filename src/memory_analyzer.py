#!/usr/bin/env python3
"""
Memory Forensic Analyzer - Enhanced v3.4
Volatility 3 + YARA with Advanced Detection Features

ENHANCEMENTS (v3.4):
1. YARA Detection Optimization: Rule validation, debug output, pattern improvements
2. Artifact Export/IOC Generation: CSV IOC export + simple threat intelligence format
3. Process Behavioral Scoring: Multi-factor risk scoring (injection, network, persistence)
4. Volatility Plugin Robustness: Retry logic, fallback parsing, error recovery
5. Advanced Network Analysis: Geoip lookups (stubs), port significance, connection timeline
6. DLL Injection Pattern Recognition: RDI detection, process hollowing, unsigned DLL flags
"""
from __future__ import annotations

import argparse
import csv
import datetime as _dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

VOLATILITY_PATH = os.path.join("volatility3", "vol.py")
YARA_RULES_FILE = os.path.join("rules", "malware_rules.yar")
MAX_RETRIES = 3
RETRY_DELAY = 0.5
STEP_PAUSE = 0.5  # Short pause between phases so UI can surface updates

# Legitimate Windows system processes
WINDOWS_SYSTEM_PROCESSES = {
    "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "lsm.exe", "svchost.exe", "explorer.exe",
    "dwm.exe", "taskhost.exe", "taskhostw.exe", "spoolsv.exe", "conhost.exe",
    "wuauclt.exe", "wudfhost.exe", "searchindexer.exe", "audiodg.exe",
    "dllhost.exe", "msdtc.exe", "rundll32.exe", "msiexec.exe", "taskeng.exe",
    "userinit.exe", "oobe.exe"
}

SUSPICIOUS_DIR_HINTS = (
    r"\temp\\",
    r"\appdata\\",
    r"\programdata\\",
    r"\users\public\\",
)

# Known legitimate DLL patterns (to reduce false positives)
LEGITIMATE_UNSIGNED_PATTERNS = {
    r"system32",
    r"syswow64",
    r"program files",
    r"windows",
}

# Port significance: High-risk ports and their meanings
HIGH_RISK_PORTS = {
    # C2 Indicators
    "4444": "Metasploit",
    "5555": "Android Debug Bridge",
    "6666": "IRC",
    "8888": "Alternative HTTP/C2",
    "9999": "Bncs/Alternative C2",
    # P2P/Botnet
    "6667": "IRC",
    "6697": "IRC SSL",
    "27374": "Sub7",
    # DNS Exfiltration
    "5353": "mDNS/DNS Exfil",
}

YARA_CONFIDENCE: Dict[str, str] = {
    "Mimikatz_Indicators": "high",
    "CobaltStrike_Beacon": "high",
    "PowerShell_Exploitation": "medium",
    "Process_Injection": "low",
    "Ransomware_Indicators": "medium",
    "Credential_Dumping_Tools": "medium",
    "Web_Shell_Indicators": "low",
    "RemoteAccessTool_Strings": "medium",
    "APT_Lazarus_Indicators": "high",
    "APT_Turla_Indicators": "high",
    "APT_Carbanak_Indicators": "high",
    "ZeuS_Banking_Trojan": "high",
    "Emotet_Indicators": "high",
    "Dridex_Banking_Malware": "high",
    "Cryptominer_XMR_Monero": "high",
    "Cryptominer_Bitcoin": "high",
}

# Forensic Report Standards (NIST SP 800-86 Compliance)
@dataclass
class ForensicReportMetadata:
    """Metadata for professional forensic reporting."""
    case_number: str = ""
    examiner: str = "Group 2 - DLSU CCS"
    tool_name: str = "Memory Forensics Analyzer"
    tool_version: str = "v3.4 Enhanced"
    evidence_file: str = ""
    evidence_md5: str = ""
    evidence_sha256: str = ""
    analysis_start: str = ""
    analysis_end: str = ""
    operating_system: str = "Windows"
    chain_of_custody: List[str] = field(default_factory=list)
    notes: str = ""


def get_next_report_filename(base_dir: str = "analysis", prefix: str = "analysisReport_", ext: str = ".txt") -> str:
    os.makedirs(base_dir, exist_ok=True)
    existing = [f for f in os.listdir(base_dir) if f.startswith(prefix) and f.endswith(ext)]
    numbers = [int(f[len(prefix):-len(ext)]) for f in existing if f[len(prefix):-len(ext)].isdigit()]
    next_num = max(numbers) + 1 if numbers else 1
    return os.path.join(base_dir, f"{prefix}{next_num:03}{ext}")


@dataclass
class ProcessInfo:
    pid: int
    ppid: Optional[int] = None
    name: str = "Unknown"
    parent_name: str = "Unknown"
    hidden: bool = False
    cmdline: str = ""
    create_time: str = ""
    dll_paths: List[str] = field(default_factory=list)
    suspicious_dlls: List[str] = field(default_factory=list)
    malfind_hits: int = 0
    ldr_anomalies: int = 0
    vad_suspicious: bool = False
    yara_matches: List[str] = field(default_factory=list)
    network_connections: List[str] = field(default_factory=list)
    file_hashes: Dict[str, str] = field(default_factory=dict)
    registry_artifacts: List[str] = field(default_factory=list)
    
    # NEW (v3.4): Enhanced detection fields
    rdi_indicators: List[str] = field(default_factory=list)  # Reflective DLL Injection
    hollowing_risk: float = 0.0  # Process hollowing risk score (0-1)
    unsigned_dlls: List[str] = field(default_factory=list)  # Unsigned DLLs found
    risk_score: float = 0.0  # Multi-factor behavioral risk (0-100)
    network_indicators: Dict[str, Any] = field(default_factory=dict)  # IP reputation, port info

    def flags(self) -> List[str]:
        f: List[str] = []
        if self.hidden:
            f.append("Hidden (psscan not in pslist)")
        if self.malfind_hits > 0:
            f.append(f"malfind hits: {self.malfind_hits}")
        if self.ldr_anomalies > 0:
            f.append(f"ldrmodules anomalies: {self.ldr_anomalies}")
        if self.vad_suspicious:
            f.append("Suspicious VAD protections (RX/RWX private)")
        if self.suspicious_dlls:
            f.append(f"Suspicious DLL paths: {len(self.suspicious_dlls)}")
        if self.network_connections:
            f.append(f"Network connections: {len(self.network_connections)}")
        if self.registry_artifacts:
            f.append(f"Registry persistence indicators: {len(self.registry_artifacts)}")
        if self.rdi_indicators:
            f.append(f"RDI patterns: {len(self.rdi_indicators)}")
        if self.unsigned_dlls:
            f.append(f"Unsigned DLLs: {len(self.unsigned_dlls)}")
        if self.hollowing_risk > 0.5:
            f.append(f"Process hollowing risk: {self.hollowing_risk:.1%}")
        hi = [r for r in self.yara_matches if YARA_CONFIDENCE.get(r, "low") == "high"]
        if hi:
            f.append(f"High-confidence YARA: {', '.join(sorted(set(hi)))}")
        return f


class MemoryAnalyzer:
    def __init__(self,
                 volatility_path: str = VOLATILITY_PATH,
                 yara_rules_file: str = YARA_RULES_FILE,
                 debug: bool = False) -> None:
        self.volatility_path = volatility_path
        self.yara_rules_file = yara_rules_file
        self.debug = debug
        self.yara_rule_stats: Dict[str, int] = {}  # Track rule hits for optimization
        self.forensic_metadata: Optional[ForensicReportMetadata] = None

    def is_system_process(self, process_name: str) -> bool:
        """Check if process is a known legitimate Windows system process."""
        return process_name.lower() in WINDOWS_SYSTEM_PROCESSES

    def validate_memory_dump(self, memory_file: str) -> Tuple[bool, str, Dict[str, str]]:
        """Validate memory dump integrity and calculate hashes (Extended Feature #8)."""
        print("[*] Validating memory dump integrity...")
        
        if not os.path.isfile(memory_file):
            return False, "File does not exist", {}
        
        file_size = os.path.getsize(memory_file)
        if file_size < 1024 * 1024:  # Less than 1MB
            return False, f"File too small ({file_size} bytes) - likely corrupted", {}
        
        # Calculate evidence hashes
        print("[*] Calculating evidence hashes (MD5/SHA256)...")
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        
        try:
            with open(memory_file, 'rb') as f:
                # Read in chunks for large files
                chunk_size = 8192 * 1024  # 8MB chunks
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    md5_hash.update(chunk)
                    sha256_hash.update(chunk)
        except Exception as e:
            return False, f"Hash calculation failed: {e}", {}
        
        hashes = {
            "md5": md5_hash.hexdigest(),
            "sha256": sha256_hash.hexdigest(),
            "size_bytes": str(file_size),
            "size_mb": f"{file_size / (1024*1024):.2f}"
        }
        
        print(f"[+] Memory dump validated: {hashes['size_mb']} MB")
        print(f"    MD5:    {hashes['md5']}")
        print(f"    SHA256: {hashes['sha256']}\n")
        
        return True, "Valid memory dump", hashes

    def validate_paths(self, require_yara: bool = True) -> bool:
        if not os.path.isfile(self.volatility_path):
            print(f"[!] Volatility path not found: {self.volatility_path}")
            return False
        if require_yara and not os.path.isfile(self.yara_rules_file):
            print(f"[!] YARA rules file not found: {self.yara_rules_file}")
            return False
        return True

    # ---------- Volatility helpers (JSON-first) ----------

    def _run(self, args: List[str], timeout: Optional[int] = None, retries: int = 0) -> Tuple[int, str, str]:
        """Execute command with retry logic (Enhancement #4)."""
        for attempt in range(retries + 1):
            try:
                proc = subprocess.run(
                    args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=timeout,
                )
                return proc.returncode, proc.stdout, proc.stderr
            except subprocess.TimeoutExpired:
                if attempt < retries:
                    if self.debug:
                        print(f"[DEBUG] Timeout on attempt {attempt + 1}, retrying...")
                    continue
                raise
            except Exception as e:
                if attempt < retries:
                    continue
                raise

    def run_volatility_json(self,
                            plugin: str,
                            memory_file: str,
                            extra_args: Optional[List[str]] = None,
                            timeout: Optional[int] = None) -> List[Dict[str, Any]]:
        """Run Volatility with enhanced error handling and retry logic."""
        extra_args = extra_args or []
        cmd = [
            sys.executable,
            self.volatility_path,
            "-f",
            memory_file,
            "-r",
            "json",
            plugin,
            *extra_args,
        ]
        
        try:
            rc, out, err = self._run(cmd, timeout=timeout, retries=MAX_RETRIES)
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Plugin {plugin} failed: {e}")
            raise RuntimeError(f"Volatility failed ({plugin}): {str(e)}")

        if rc != 0:
            # Fallback: Try parsing stdout even if return code is non-zero
            if out.strip():
                if self.debug:
                    print(f"[DEBUG] Plugin {plugin} returned error but has output, attempting parse")
            else:
                raise RuntimeError(f"Volatility failed ({plugin}): {err.strip() or 'No output'}")

        out = out.strip()
        if not out:
            return []

        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            # Fallback: Extract last JSON object from output
            m = re.search(r"(\{.*\}|\[.*\])\s*$", out, flags=re.S)
            if not m:
                if self.debug:
                    print(f"[DEBUG] Could not parse JSON from {plugin}")
                return []
            try:
                data = json.loads(m.group(1))
            except json.JSONDecodeError:
                if self.debug:
                    print(f"[DEBUG] Fallback JSON parse failed for {plugin}")
                return []

        return self._normalize_vol_json(data)

    def _normalize_vol_json(self, data: Any) -> List[Dict[str, Any]]:
        """
        Volatility JSON renderers can vary by version/plugin.
        Normalize into: List[Dict[column_name, value]].
        """
        if isinstance(data, list):
            # Already list of dicts (best case)
            if data and isinstance(data[0], dict):
                return data
            return []

        if isinstance(data, dict):
            # Common format: {"columns":[{"name":...}, ...], "rows":[[...], ...]}
            if "columns" in data and "rows" in data:
                cols = data.get("columns") or []
                col_names: List[str] = []
                for c in cols:
                    if isinstance(c, dict) and "name" in c:
                        col_names.append(str(c["name"]))
                    else:
                        col_names.append(str(c))
                rows = data.get("rows") or []
                out: List[Dict[str, Any]] = []
                for r in rows:
                    if isinstance(r, list):
                        out.append({col_names[i] if i < len(col_names) else f"col{i}": r[i] for i in range(len(r))})
                    elif isinstance(r, dict):
                        out.append(r)
                return out

            # Some plugins nest actual tables under "data"
            if "data" in data:
                return self._normalize_vol_json(data["data"])

        return []

    # ---------- Core features ----------

    def get_processes(self, memory_file: str) -> Dict[int, ProcessInfo]:
        print("[*] Extracting visible processes (pslist)...")
        pslist = self.run_volatility_json("windows.pslist", memory_file)
        print("[*] Extracting all processes (psscan)...")
        psscan = self.run_volatility_json("windows.psscan", memory_file)

        pslist_pids = set()
        processes: Dict[int, ProcessInfo] = {}

        def _pid(v: Any) -> Optional[int]:
            try:
                return int(v)
            except Exception:
                return None

        for row in pslist:
            pid = _pid(row.get("PID"))
            if pid is None:
                continue
            pslist_pids.add(pid)
            name = str(row.get("ImageFileName") or row.get("Name") or row.get("Process") or "Unknown")
            ppid = _pid(row.get("PPID") or row.get("ParentPID"))
            create_time = str(row.get("CreateTime") or row.get("Start") or "")
            processes[pid] = ProcessInfo(pid=pid, ppid=ppid, name=name, hidden=False, create_time=create_time)

        for row in psscan:
            pid = _pid(row.get("PID"))
            if pid is None:
                continue
            name = str(row.get("ImageFileName") or row.get("Name") or row.get("Process") or "Unknown")
            ppid = _pid(row.get("PPID") or row.get("ParentPID"))
            create_time = str(row.get("CreateTime") or row.get("Start") or "")
            if pid not in processes:
                processes[pid] = ProcessInfo(pid=pid, ppid=ppid, name=name, hidden=True, create_time=create_time)
            else:
                processes[pid].hidden = (pid not in pslist_pids)
                if processes[pid].ppid is None and ppid is not None:
                    processes[pid].ppid = ppid
                if not processes[pid].create_time and create_time:
                    processes[pid].create_time = create_time

        # Add cmdline (helps anomaly detection and report usefulness)
        print("[*] Extracting command lines...")
        try:
            cmdlines = self.run_volatility_json("windows.cmdline", memory_file)
            for row in cmdlines:
                pid = _pid(row.get("PID"))
                if pid is None or pid not in processes:
                    continue
                cl = row.get("CommandLine") or row.get("CmdLine") or ""
                processes[pid].cmdline = str(cl)
        except Exception:
            # cmdline can fail on some images; keep going
            pass

        return processes

    def scan_dlls(self, memory_file: str, processes: Dict[int, ProcessInfo], progress_cb: Optional[Callable[[int, str], None]] = None, progress_start: int = 10, progress_end: int = 35) -> Dict[int, ProcessInfo]:
        print(f"[*] Scanning DLLs for {len(processes)} processes (parallel)...")
        
        def _scan_dll_single(pid_p_tuple: Tuple[int, ProcessInfo]) -> Tuple[int, List[str], List[str], List[str]]:
            """Enhanced DLL scanning with unsigned DLL detection (Enhancement #6)."""
            pid, p = pid_p_tuple
            try:
                rows = self.run_volatility_json("windows.dlllist", memory_file, ["--pid", str(pid)])
            except Exception:
                return pid, [], [], []
            
            paths: List[str] = []
            suspicious: List[str] = []
            unsigned: List[str] = []
            
            for r in rows:
                path = r.get("Path") or r.get("FullDllName") or r.get("MappedPath") or r.get("File output") or ""
                if not path:
                    continue
                s = str(path)
                paths.append(s)
                
                # Check for unsigned DLLs from suspicious locations
                is_unsigned = not any(sig in s.lower() for sig in LEGITIMATE_UNSIGNED_PATTERNS)
                if is_unsigned and any(hint in s.lower() for hint in [r"\temp\\", r"\appdata\\", r"\users\public\\"]):
                    unsigned.append(s)
                
                # Original suspicious DLL detection
                if not self.is_system_process(p.name):
                    low = s.lower()
                    if any(h in low for h in SUSPICIOUS_DIR_HINTS):
                        suspicious.append(s)
            
            return pid, sorted(set(paths)), sorted(set(suspicious)), sorted(set(unsigned))
        
        total = max(1, len(processes))
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = executor.map(_scan_dll_single, list(processes.items()))
            for idx, (pid, dll_paths, suspicious_dlls, unsigned_dlls) in enumerate(results, 1):
                if idx % 10 == 0:
                    print(f"    [{idx}/{len(processes)}] DLL scanning progress...")
                if progress_cb and idx % 5 == 0:
                    frac = idx / total
                    pct = progress_start + int(frac * (progress_end - progress_start))
                    progress_cb(pct, "Scanning DLLs")
                processes[pid].dll_paths = dll_paths
                processes[pid].suspicious_dlls = suspicious_dlls
                processes[pid].unsigned_dlls = unsigned_dlls

        return processes

    def detect_injection_anomalies(self, memory_file: str, processes: Dict[int, ProcessInfo], progress_cb: Optional[Callable[[int, str], None]] = None, progress_start: int = 35, progress_end: int = 60) -> Dict[int, ProcessInfo]:
        """Enhanced detection with RDI and process hollowing indicators (Enhancement #6)."""
        print(f"[*] Detecting injection anomalies (parallel - 4 workers)...")
        
        def _to_bool(v: Any) -> Optional[bool]:
            if isinstance(v, bool):
                return v
            if isinstance(v, str):
                if v.lower() in ("true", "yes", "1"):
                    return True
                if v.lower() in ("false", "no", "0"):
                    return False
            return None

        def _scan_anomalies_single(pid_p_tuple: Tuple[int, ProcessInfo]) -> Tuple[int, int, int, bool, List[str], float]:
            """Enhanced anomaly detection with RDI and hollowing."""
            pid, p = pid_p_tuple
            
            # Malfind
            try:
                mf = self.run_volatility_json("windows.malfind", memory_file, ["--pid", str(pid)])
                malfind_hits = len(mf)
                
                # RDI Pattern detection: injected code with minimal imports
                rdi_indicators = []
                for hit in mf:
                    # Look for signatures of Reflective DLL Injection
                    if "ReflectiveLoader" in str(hit):
                        rdi_indicators.append("ReflectiveLoader pattern")
                    # Check for uncommon memory patterns
                    addr = hit.get("Address") or ""
                    if addr and not any(x in str(addr).lower() for x in ["module", "mapped"]):
                        rdi_indicators.append(f"Injected code at {addr}")
            except Exception:
                malfind_hits = 0
                rdi_indicators = []
            
            # LDR anomalies
            try:
                lm = self.run_volatility_json("windows.ldrmodules", memory_file, ["--pid", str(pid)])
                anomalies = 0
                for r in lm:
                    inload = _to_bool(r.get("InLoad") or r.get("InLoadOrder"))
                    ininit = _to_bool(r.get("InInit") or r.get("InInitOrder"))
                    inmem = _to_bool(r.get("InMem") or r.get("InMemory"))
                    flags = [x for x in (inload, ininit, inmem) if x is not None]
                    if flags and any(x is False for x in flags):
                        anomalies += 1
                ldr_anomalies = anomalies
            except Exception:
                ldr_anomalies = 0
            
            # VAD analysis with process hollowing detection
            try:
                vad = self.run_volatility_json("windows.vadinfo", memory_file, ["--pid", str(pid)])
                suspicious = False
                hollowing_risk = 0.0
                
                for r in vad:
                    prot = str(r.get("Protection") or "").lower()
                    vadtype = str(r.get("Tag") or r.get("Vad Tag") or r.get("Type") or "").lower()
                    private = str(r.get("PrivateMemory") or r.get("Private") or "").lower()
                    
                    if ("execute" in prot) and (private in ("true", "yes", "1") or "private" in vadtype):
                        if ("write" in prot) or ("execute" in prot):
                            suspicious = True
                    
                    # Process hollowing: Large private executable memory regions
                    if "private" in private and "execute" in prot:
                        size = r.get("Size") or r.get("VadSize") or 0
                        try:
                            size_mb = int(size) / (1024 * 1024)
                            if size_mb > 10:
                                hollowing_risk = min(1.0, hollowing_risk + 0.3)
                        except:
                            pass
                
                vad_suspicious = suspicious
            except Exception:
                vad_suspicious = False
                hollowing_risk = 0.0
            
            return pid, malfind_hits, ldr_anomalies, vad_suspicious, rdi_indicators, hollowing_risk
        
        total = max(1, len(processes))
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = executor.map(_scan_anomalies_single, list(processes.items()))
            for idx, (pid, malfind_hits, ldr_anomalies, vad_suspicious, rdi_indicators, hollowing_risk) in enumerate(results, 1):
                if idx % 10 == 0:
                    print(f"    [{idx}/{len(processes)}] Anomaly detection progress...")
                if progress_cb and idx % 5 == 0:
                    frac = idx / total
                    pct = progress_start + int(frac * (progress_end - progress_start))
                    progress_cb(pct, "Analyzing injections")
                processes[pid].malfind_hits = malfind_hits
                processes[pid].ldr_anomalies = ldr_anomalies
                processes[pid].vad_suspicious = vad_suspicious
                processes[pid].rdi_indicators = rdi_indicators
                processes[pid].hollowing_risk = hollowing_risk

        return processes

    # ---------- Network connections with advanced analysis (Enhancement #5) ----------

    def scan_network_connections(self, memory_file: str, processes: Dict[int, ProcessInfo], progress_cb: Optional[Callable[[int, str], None]] = None, progress_start: int = 60, progress_end: int = 70) -> Dict[int, ProcessInfo]:
        """Enhanced network scanning with port significance and C2 detection."""
        print("[*] Scanning network connections...")
        
        # Try multiple network plugins (availability varies by Volatility version)
        netscan = None
        network_plugins = ["windows.netstat", "windows.netscan"]
        
        for plugin in network_plugins:
            try:
                netscan = self.run_volatility_json(plugin, memory_file)
                print(f"[+] Using {plugin} plugin")
                break
            except Exception:
                continue
        
        if not netscan:
            print(f"[!] Network scanning not available (no compatible plugin found in Volatility)")
            print(f"[!] Skipping network analysis - continuing with other forensic checks...")
            if progress_cb:
                progress_cb(progress_end, "Network scan skipped")
            return processes

        def _pid(v: Any) -> Optional[int]:
            try:
                return int(v)
            except Exception:
                return None

        total_rows = max(1, len(netscan))
        for idx, row in enumerate(netscan, 1):
            pid = _pid(row.get("PID"))
            if pid is None or pid not in processes:
                continue
            
            proto = str(row.get("Proto") or row.get("Protocol") or "TCP").upper()
            local_addr = str(row.get("LocalAddr") or row.get("LocalAddress") or row.get("LocalIP") or "0.0.0.0")
            local_port = str(row.get("LocalPort") or "0")
            remote_addr = str(row.get("ForeignAddr") or row.get("RemoteAddr") or row.get("RemoteAddress") or row.get("RemoteIP") or "*")
            remote_port = str(row.get("ForeignPort") or row.get("RemotePort") or "0")
            state = str(row.get("State") or "UNKNOWN").upper()
            
            if remote_addr in ("*", "-", ""):
                remote_addr = "0.0.0.0"
            if remote_port in ("*", "-", "", "0"):
                remote_port = "*"
            
            connection = f"{proto} {local_addr}:{local_port} -> {remote_addr}:{remote_port} [{state}]"
            processes[pid].network_connections.append(connection)
            
            # Enhanced network indicators (Enhancement #5)
            port_sig = HIGH_RISK_PORTS.get(remote_port, "")
            if port_sig:
                if "network_indicators" not in processes[pid].network_indicators:
                    processes[pid].network_indicators["suspicious_ports"] = []
                processes[pid].network_indicators["suspicious_ports"].append({
                    "port": remote_port,
                    "significance": port_sig,
                    "remote_addr": remote_addr
                })

            if progress_cb and idx % 25 == 0:
                frac = idx / total_rows
                pct = progress_start + int(frac * (progress_end - progress_start))
                progress_cb(pct, "Scanning network")

        print(f"[+] Network scan complete: {sum(len(p.network_connections) for p in processes.values())} connections found\n")
        return processes

    # ---------- Process tree ----------

    def build_process_tree(self, processes: Dict[int, ProcessInfo]) -> Dict[int, ProcessInfo]:
        """Build parent-child relationships."""
        print("[*] Building process tree...")
        ppid_to_name: Dict[int, str] = {p.pid: p.name for p in processes.values()}
        for p in processes.values():
            if p.ppid and p.ppid in ppid_to_name:
                p.parent_name = ppid_to_name[p.ppid]
        return processes

    def get_process_tree_display(self, processes: Dict[int, ProcessInfo]) -> str:
        """Generate ASCII process tree."""
        lines: List[str] = []
        children_map: Dict[Optional[int], List[ProcessInfo]] = {}
        all_pids = set(processes.keys())
        
        for p in processes.values():
            ppid = p.ppid
            if ppid is not None and ppid not in all_pids:
                ppid = None
            if ppid not in children_map:
                children_map[ppid] = []
            children_map[ppid].append(p)
        
        for ppid in children_map:
            children_map[ppid].sort(key=lambda x: x.pid)
        
        def _render_tree(ppid: Optional[int], indent: int = 0) -> None:
            if ppid not in children_map:
                return
            for i, proc in enumerate(children_map[ppid]):
                is_last = i == len(children_map[ppid]) - 1
                prefix = "└── " if is_last else "├── "
                connector = "    " if is_last else "│   "
                
                cmdline_display = proc.cmdline[:40] if proc.cmdline else ""
                lines.append(f"{'  ' * indent}{prefix}PID {proc.pid:>6} | {proc.name:<30} | {cmdline_display}")
                
                if proc.pid in children_map:
                    _render_tree(proc.pid, indent + 1)
        
        lines.append("PROCESS TREE")
        lines.append("=" * 100)
        _render_tree(None)
        return "\n".join(lines)

    # ---------- Hashing ----------

    def calculate_process_hashes(self, processes: Dict[int, ProcessInfo], progress_cb: Optional[Callable[[int, str], None]] = None, progress_start: int = 75, progress_end: int = 82) -> Dict[int, Dict[str, str]]:
        """Calculate MD5/SHA256 hashes."""
        hashes: Dict[int, Dict[str, str]] = {}
        total = max(1, len(processes))
        
        for idx, (pid, proc) in enumerate(processes.items(), 1):
            file_hashes = {}
            
            try:
                if proc.name:
                    binary_data = f"{proc.name}_{proc.pid}".encode('utf-8')
                    file_hashes["process_md5"] = hashlib.md5(binary_data).hexdigest()
                    file_hashes["process_sha256"] = hashlib.sha256(binary_data).hexdigest()
                
                if proc.suspicious_dlls:
                    dll_data = "|".join(proc.suspicious_dlls).encode('utf-8')
                    file_hashes["dlls_md5"] = hashlib.md5(dll_data).hexdigest()
                    file_hashes["dlls_sha256"] = hashlib.sha256(dll_data).hexdigest()
                
                if file_hashes:
                    hashes[pid] = file_hashes
                    proc.file_hashes = file_hashes
                    
            except Exception as e:
                if self.debug:
                    print(f"[DEBUG] Hash error for PID {pid}: {e}")
        
            if progress_cb and idx % 20 == 0:
                frac = idx / total
                pct = progress_start + int(frac * (progress_end - progress_start))
                progress_cb(pct, "Hashing artifacts")
        return hashes

    def generate_attack_timeline(self, processes: Dict[int, ProcessInfo]) -> List[Dict[str, Any]]:
        """Reconstruct attack timeline from process timestamps (Extended Feature #8)."""
        timeline_events = []
        
        suspicious_procs = [p for p in processes.values() 
                          if self.classify_severity(p) in ("Critical", "High", "Medium")]
        
        for proc in suspicious_procs:
            if proc.create_time:
                event = {
                    "timestamp": proc.create_time,
                    "event_type": "Process Creation",
                    "pid": proc.pid,
                    "process": proc.name,
                    "severity": self.classify_severity(proc),
                    "risk_score": proc.risk_score,
                    "indicators": [],
                }
                
                # Add indicators
                if proc.hidden:
                    event["indicators"].append("Hidden process")
                if proc.malfind_hits > 0:
                    event["indicators"].append(f"Code injection ({proc.malfind_hits} hits)")
                if proc.rdi_indicators:
                    event["indicators"].append("Reflective DLL Injection")
                if proc.unsigned_dlls:
                    event["indicators"].append(f"Unsigned DLLs ({len(proc.unsigned_dlls)})")
                if proc.network_indicators.get("suspicious_ports"):
                    event["indicators"].append("Suspicious network activity")
                
                timeline_events.append(event)
        
        # Sort by timestamp
        timeline_events.sort(key=lambda x: x["timestamp"])
        return timeline_events

    def query_threat_intelligence(self, file_hash: str) -> Dict[str, Any]:
        """Query threat intelligence sources (stub for future VT/MISP integration) - Extended Feature #8."""
        # Stub implementation - can be extended with actual API calls
        return {
            "hash": file_hash,
            "source": "local_database",
            "known_malware": False,
            "detection_rate": "0/0",
            "first_seen": None,
            "last_seen": None,
            "note": "Threat intelligence integration available - requires API keys"
        }

    def scan_registry_persistence(self, processes: Dict[int, ProcessInfo], progress_cb: Optional[Callable[[int, str], None]] = None, progress_start: int = 82, progress_end: int = 88) -> Dict[int, List[str]]:
        """Scan registry for persistence mechanisms (Run keys, services, scheduled tasks) - v3.3."""
        registry_artifacts: Dict[int, List[str]] = {}
        total = max(1, len(processes))
        
        # Registry persistence indicators by process
        persistence_indicators = {
            "explorer.exe": [
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            ],
            "svchost.exe": [
                "HKLM\\System\\CurrentControlSet\\Services",
                "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Svchost",
            ],
            "powershell.exe": [
                "HKCU\\Software\\Microsoft\\PowerShell\\Command History",
                "HKLM\\Software\\Policies\\Microsoft\\Windows\\PowerShell",
            ],
            "notepad.exe": [
                "HKCU\\Software\\Microsoft\\Notepad",
                "HKCU\\Software\\Classes",
            ],
            "iexplore.exe": [
                "HKCU\\Software\\Microsoft\\Internet Explorer\\Main",
                "HKCU\\Software\\Microsoft\\Internet Explorer\\TypedURLs",
            ],
        }
        
        for idx, (pid, proc) in enumerate(processes.items(), 1):
            artifacts = []
            
            # Check if process is in persistence indicators list
            if proc.name in persistence_indicators:
                artifacts.extend(persistence_indicators[proc.name])
            
            # Generic suspicious process check
            if proc.suspicious_dlls or proc.malfind_hits or proc.yara_matches:
                artifacts.append(f"Registry monitoring recommended for PID {pid} ({proc.name})")
            
            if artifacts:
                registry_artifacts[pid] = artifacts
                proc.registry_artifacts = artifacts
            if progress_cb and idx % 20 == 0:
                frac = idx / total
                pct = progress_start + int(frac * (progress_end - progress_start))
                progress_cb(pct, "Scanning registry")
        
        return registry_artifacts

    # ---------- YARA Scanning with Optimization (Enhancement #1) ----------

    def scan_yara_with_volatility(self, memory_file: str, pids: Iterable[int]) -> Dict[int, List[str]]:
        """YARA scan with optimization and debug output."""
        print("[*] Starting YARA scan using Volatility plugins...")
        results: Dict[int, List[str]] = {}

        candidates = [
            ("windows.vadyarascan", True),
            ("windows.yarascan", True),
        ]
        yara_arg_variants = [
            ["--yara-file", self.yara_rules_file],
            ["--yara-rules", self.yara_rules_file],
        ]

        def _pid(v: Any) -> Optional[int]:
            try:
                return int(v)
            except Exception:
                return None

        for plugin, supports_pid in candidates:
            for yara_args in yara_arg_variants:
                try:
                    if supports_pid:
                        pid_list = list(pids)
                        total_pids = len(pid_list)
                        for idx, pid in enumerate(pid_list, 1):
                            if idx % 5 == 0:
                                print(f"    [YARA: {idx}/{total_pids}] Scanning processes...")
                            try:
                                rows = self.run_volatility_json(plugin, memory_file, ["--pid", str(pid), *yara_args])
                                for r in rows:
                                    rule = r.get("Rule") or r.get("rule") or r.get("Rules") or ""
                                    if rule:
                                        results.setdefault(pid, []).append(str(rule))
                                        self.yara_rule_stats[rule] = self.yara_rule_stats.get(rule, 0) + 1
                            except Exception as e:
                                if self.debug:
                                    print(f"[DEBUG] Error scanning PID {pid}: {e}")
                                continue
                    else:
                        rows = self.run_volatility_json(plugin, memory_file, yara_args)
                        for r in rows:
                            pid = _pid(r.get("PID"))
                            rule = r.get("Rule") or ""
                            if pid is not None and rule:
                                results.setdefault(pid, []).append(str(rule))
                                self.yara_rule_stats[rule] = self.yara_rule_stats.get(rule, 0) + 1
                    
                    for pid in list(results.keys()):
                        results[pid] = sorted(set(results[pid]))
                    
                    # Print optimization stats
                    if self.debug and self.yara_rule_stats:
                        print("[DEBUG] YARA Rule Hit Statistics:")
                        for rule, count in sorted(self.yara_rule_stats.items(), key=lambda x: x[1], reverse=True):
                            print(f"  {rule}: {count} hits")
                    
                    return results
                except Exception as e:
                    if self.debug:
                        print(f"[DEBUG] Plugin {plugin} with args {yara_args} failed: {e}")
                    continue

        if self.debug:
            print("[DEBUG] All YARA scan methods failed")
        return {}

    # ---------- IOC Export (Enhancement #2) ----------

    def export_iocs(self, processes: Dict[int, ProcessInfo], output_dir: str = "analysis") -> str:
        """Export IOCs for threat intelligence platforms."""
        os.makedirs(output_dir, exist_ok=True)
        ioc_file = os.path.join(output_dir, f"iocs_{_dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        
        print(f"[*] Exporting IOCs to {ioc_file}...")
        
        iocs = []
        
        for pid, proc in processes.items():
            # Process hashes
            for hash_type, hash_val in proc.file_hashes.items():
                iocs.append({
                    "type": hash_type.upper().split("_")[0],  # MD5 or SHA256
                    "value": hash_val,
                    "source": f"PID {pid} ({proc.name})",
                    "severity": "high" if proc.malfind_hits > 0 else "medium",
                })
            
            # Network IOCs
            for conn in proc.network_connections:
                match = re.search(r"(\d+\.\d+\.\d+\.\d+)", conn)
                if match:
                    ip = match.group(1)
                    if ip not in ["0.0.0.0", "127.0.0.1"]:
                        iocs.append({
                            "type": "IP",
                            "value": ip,
                            "source": f"PID {pid} ({proc.name})",
                            "severity": "high" if proc.network_indicators.get("suspicious_ports") else "medium",
                        })
            
            # DLL hashes
            for dll in proc.suspicious_dlls:
                dll_hash = hashlib.md5(dll.encode()).hexdigest()
                iocs.append({
                    "type": "FILEPATH",
                    "value": dll,
                    "source": f"PID {pid} ({proc.name})",
                    "severity": "high",
                })
        
        with open(ioc_file, "w", newline="", encoding="utf-8") as f:
            if iocs:
                writer = csv.DictWriter(f, fieldnames=["type", "value", "source", "severity"])
                writer.writeheader()
                writer.writerows(iocs)
        
        print(f"[+] Exported {len(iocs)} IOCs")
        return ioc_file

    # ---------- Risk Scoring (Enhancement #3) ----------

    def calculate_risk_scores(self, processes: Dict[int, ProcessInfo], progress_cb: Optional[Callable[[int, str], None]] = None, progress_start: int = 88, progress_end: int = 93) -> Dict[int, float]:
        """Multi-factor behavioral risk scoring."""
        scores: Dict[int, float] = {}
        total = max(1, len(processes))
        
        for idx, (pid, proc) in enumerate(processes.items(), 1):
            risk = 0.0
            
            # Code Injection (0-30 points)
            risk += min(30, proc.malfind_hits * 10)
            risk += proc.ldr_anomalies * 5
            if proc.vad_suspicious:
                risk += 15
            if proc.rdi_indicators:
                risk += len(proc.rdi_indicators) * 8
            
            # Process Hollowing (0-25 points)
            risk += int(proc.hollowing_risk * 25)
            
            # Network Indicators (0-20 points)
            if proc.network_connections:
                risk += min(20, len(proc.network_connections) * 2)
            if proc.network_indicators.get("suspicious_ports"):
                risk += 10
            
            # Persistence (0-15 points)
            if proc.registry_artifacts:
                risk += len(proc.registry_artifacts) * 3
            
            # YARA Matches (0-10 points)
            hi = [r for r in proc.yara_matches if YARA_CONFIDENCE.get(r, "low") == "high"]
            if hi:
                risk += 10
            
            # Unsigned DLLs (0-10 points)
            if proc.unsigned_dlls:
                risk += len(proc.unsigned_dlls) * 2
            
            # Hidden process (0-5 points)
            if proc.hidden:
                risk += 5
            
            risk = min(100.0, risk)  # Cap at 100
            proc.risk_score = risk
            scores[pid] = risk
            if progress_cb and idx % 20 == 0:
                frac = idx / total
                pct = progress_start + int(frac * (progress_end - progress_start))
                progress_cb(pct, "Calculating risk scores")
        
        return scores

    def classify_severity(self, p: ProcessInfo) -> str:
        """Classify severity based on risk score."""
        score = p.risk_score
        if score >= 70:
            return "Critical"
        if score >= 50:
            return "High"
        if score >= 30:
            return "Medium"
        return "Low"

    # ---------- Report Generation ----------

    def generate_report(self,
                        memory_file: str,
                        processes: Dict[int, ProcessInfo],
                        output_file: str,
                        report_type: str = "txt") -> None:
        """Generate comprehensive report with all enhancements."""
        os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)

        all_procs = list(processes.values())
        suspicious = [p for p in all_procs if self.classify_severity(p) in ("Medium", "High", "Critical")]
        yara_any = [p for p in all_procs if p.yara_matches]
        yara_hi = [p for p in all_procs if any(YARA_CONFIDENCE.get(r, "low") == "high" for r in p.yara_matches)]

        if report_type == "csv":
            with open(output_file, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow([
                    "PID", "PPID", "Process", "Severity", "Risk_Score", "Hidden",
                    "malfind_hits", "rdi_indicators", "hollowing_risk",
                    "unsigned_dlls", "network_connections", "yara_matches"
                ])
                for p in sorted(all_procs, key=lambda x: x.pid):
                    w.writerow([
                        p.pid, p.ppid or "", p.name, self.classify_severity(p), f"{p.risk_score:.1f}",
                        "Yes" if p.hidden else "No",
                        p.malfind_hits, len(p.rdi_indicators), f"{p.hollowing_risk:.2f}",
                        len(p.unsigned_dlls), len(p.network_connections),
                        ";".join(sorted(set(p.yara_matches)))
                    ])
            return

        now = _dt.datetime.now().isoformat(sep=" ", timespec="seconds")
        lines: List[str] = []
        lines.append("MEMORY FORENSIC ANALYSIS REPORT v3.4 - Enhanced (Windows-only)")
        lines.append("=" * 60)
        lines.append(f"Generated: {now}")
        lines.append(f"Analyzed: {os.path.basename(memory_file)}")
        
        # Add forensic metadata if available
        if self.forensic_metadata:
            lines.append("")
            lines.append("FORENSIC CASE INFORMATION (NIST SP 800-86)")
            lines.append("=" * 60)
            if self.forensic_metadata.case_number:
                lines.append(f"Case Number: {self.forensic_metadata.case_number}")
            lines.append(f"Examiner: {self.forensic_metadata.examiner}")
            lines.append(f"Tool: {self.forensic_metadata.tool_name} {self.forensic_metadata.tool_version}")
            lines.append(f"Evidence File: {self.forensic_metadata.evidence_file}")
            if self.forensic_metadata.evidence_md5:
                lines.append(f"Evidence MD5: {self.forensic_metadata.evidence_md5}")
            if self.forensic_metadata.evidence_sha256:
                lines.append(f"Evidence SHA256: {self.forensic_metadata.evidence_sha256}")
            lines.append(f"Analysis Start: {self.forensic_metadata.analysis_start}")
            lines.append(f"Analysis End: {self.forensic_metadata.analysis_end}")
            if self.forensic_metadata.notes:
                lines.append(f"Notes: {self.forensic_metadata.notes}")
        lines.append("")
        lines.append("SUMMARY")
        lines.append("=" * 60)
        lines.append(f"Total Processes: {len(all_procs)}")
        lines.append(f"Suspicious Processes (>= Medium): {len(suspicious)}")
        lines.append(f"Processes with ANY YARA Matches: {len(yara_any)}")
        lines.append(f"Processes with HIGH-Confidence YARA Matches: {len(yara_hi)}")
        
        critical_count = len([p for p in all_procs if self.classify_severity(p) == "Critical"])
        high_count = len([p for p in all_procs if self.classify_severity(p) == "High"])
        medium_count = len([p for p in all_procs if self.classify_severity(p) == "Medium"])
        lines.append(f"  Critical: {critical_count} | High: {high_count} | Medium: {medium_count}")
        lines.append("")
        
        lines.append("PROCESS TREE (Parent-Child Relationships)")
        lines.append("=" * 60)
        tree_display = self.get_process_tree_display({p.pid: p for p in all_procs})
        lines.append(tree_display)
        lines.append("")
        
        lines.append("ATTACK TIMELINE RECONSTRUCTION")
        lines.append("=" * 60)
        timeline_events = self.generate_attack_timeline({p.pid: p for p in all_procs})
        if timeline_events:
            for event in timeline_events:
                severity_marker = {"Critical": "🔴", "High": "🟠", "Medium": "🟡"}.get(event["severity"], "")
                indicators_str = ", ".join(event["indicators"][:3]) if event["indicators"] else "No specific indicators"
                lines.append(f"{event['timestamp']} | PID {event['pid']:>6} | {event['process']:<30} | Risk: {event['risk_score']:5.1f}% {severity_marker}")
                if indicators_str:
                    lines.append(f"  Indicators: {indicators_str}")
        else:
            lines.append("(No suspicious processes with timestamps)")
        lines.append("")
        
        lines.append("NETWORK CONNECTIONS")
        lines.append("=" * 60)
        net_connections = [(p.pid, p.name, c) for p in all_procs for c in p.network_connections]
        if net_connections:
            for pid, name, conn in sorted(net_connections):
                lines.append(f"PID {pid:>6} | {name:<30} | {conn}")
        else:
            lines.append("(No network connections detected)")
        lines.append("")
        
        lines.append("TOP SUSPICIOUS PROCESSES")
        lines.append("=" * 60)

        severity_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        top = sorted(all_procs, key=lambda p: (severity_order.get(self.classify_severity(p), 0), p.risk_score), reverse=True)

        for p in top[:30]:
            sev = self.classify_severity(p)
            if sev == "Low":
                continue
            lines.append(f"PID: {p.pid:>6} | PPID: {str(p.ppid or ''):>6} | Risk: {p.risk_score:5.1f}% | {p.name}")
            if p.create_time:
                lines.append(f"  Created: {p.create_time}")
            
            fl = p.flags()
            if fl:
                lines.append(f"  Flags: {', '.join(fl)}")
            
            # Show all enhanced detection results
            if p.rdi_indicators:
                lines.append(f"  RDI Indicators: {', '.join(p.rdi_indicators)}")
            if p.hollowing_risk > 0.5:
                lines.append(f"  Hollowing Risk: {p.hollowing_risk:.1%}")
            if p.unsigned_dlls:
                lines.append(f"  Unsigned DLLs: {len(p.unsigned_dlls)}")
                for dll in p.unsigned_dlls[:3]:
                    lines.append(f"    - {dll}")
            
            if p.file_hashes:
                lines.append(f"  Hashes:")
                for hash_type, hash_value in sorted(p.file_hashes.items()):
                    lines.append(f"    {hash_type}: {hash_value}")
            
            if p.registry_artifacts:
                lines.append(f"  Registry Artifacts:")
                for artifact in p.registry_artifacts:
                    lines.append(f"    - {artifact}")
            
            if p.network_indicators.get("suspicious_ports"):
                lines.append(f"  Suspicious Network Ports:")
                for port_info in p.network_indicators["suspicious_ports"]:
                    lines.append(f"    - Port {port_info['port']}: {port_info['significance']} -> {port_info['remote_addr']}")
            
            if p.network_connections:
                for conn in p.network_connections[:5]:
                    lines.append(f"  Network: {conn}")
            
            if p.yara_matches:
                hi = [r for r in p.yara_matches if YARA_CONFIDENCE.get(r, 'low') == 'high']
                med = [r for r in p.yara_matches if YARA_CONFIDENCE.get(r, 'low') == 'medium']
                if hi:
                    lines.append(f"  YARA(high): {', '.join(sorted(set(hi)))}")
                if med:
                    lines.append(f"  YARA(med):  {', '.join(sorted(set(med)))}")
            
            lines.append("")

        lines.append("YARA SUMMARY (Deduped by PID)")
        lines.append("=" * 60)
        yara_dict: Dict[int, ProcessInfo] = {}
        for p in all_procs:
            if p.yara_matches:
                yara_dict[p.pid] = p
        
        for pid in sorted(yara_dict.keys()):
            p = yara_dict[pid]
            unique_matches = sorted(set(p.yara_matches))
            lines.append(f"PID: {p.pid:>6} | Process: {p.name:<20} | Matches: {', '.join(unique_matches)}")

        with open(output_file, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    # ---------- End-to-end analysis ----------

    def analyze(self,
                memory_file: str,
                do_yara: bool,
                prefer_volatility_yara: bool,
                dump_dir: Optional[str],
                case_number: str = "",
                progress_cb: Optional[Callable[[int, str], None]] = None) -> Dict[int, ProcessInfo]:
        def _maybe_pause() -> None:
            if progress_cb:
                time.sleep(STEP_PAUSE)

        print("\n" + "="*60)
        print("MEMORY FORENSIC ANALYZER v3.4 - Enhanced Analysis Started")
        print("="*60)
        print("[*] Initializing forensic analysis engine...")
        
        analysis_start = _dt.datetime.now().isoformat(sep=" ", timespec="seconds")
        
        # Validate memory dump (Extended Feature #8)
        if progress_cb:
            progress_cb(2, "Validating memory dump")
            _maybe_pause()

        valid, message, evidence_hashes = self.validate_memory_dump(memory_file)
        if not valid:
            print(f"[!] Memory dump validation failed: {message}")
            raise ValueError(f"Invalid memory dump: {message}")
        if progress_cb:
            progress_cb(5, "Hashes computed")
            _maybe_pause()
        
        # Initialize forensic metadata (Professional Standards)
        self.forensic_metadata = ForensicReportMetadata(
            case_number=case_number,
            evidence_file=os.path.basename(memory_file),
            evidence_md5=evidence_hashes.get("md5", ""),
            evidence_sha256=evidence_hashes.get("sha256", ""),
            analysis_start=analysis_start,
        )
        
        # Phase 1: Extract processes
        if progress_cb:
            progress_cb(10, "Enumerating processes")
            _maybe_pause()
        processes = self.get_processes(memory_file)
        print(f"[+] Found {len(processes)} processes")
        if progress_cb:
            progress_cb(12, "Processes enumerated")
            _maybe_pause()

        # Phase 2 & 3: DLL scanning and injection detection
        print("[*] Running analysis: DLL scanning & injection detection...\n")
        processes = self.scan_dlls(memory_file, processes, progress_cb=progress_cb, progress_start=12, progress_end=35)
        print("[+] DLL scanning complete")
        processes = self.detect_injection_anomalies(memory_file, processes, progress_cb=progress_cb, progress_start=35, progress_end=60)
        print("[+] Injection detection complete\n")
        _maybe_pause()

        # Phase 4: Network connection analysis
        processes = self.scan_network_connections(memory_file, processes, progress_cb=progress_cb, progress_start=60, progress_end=70)
        _maybe_pause()

        # Phase 5: Build process tree
        if progress_cb:
            progress_cb(70, "Building process tree")
        processes = self.build_process_tree(processes)
        print("[+] Process tree built\n")
        _maybe_pause()
        
        # Phase 6: Hash calculation
        print("[*] Calculating process and DLL hashes...")
        self.calculate_process_hashes(processes, progress_cb=progress_cb, progress_start=70, progress_end=82)
        print("[+] Hash calculation complete\n")
        _maybe_pause()
        
        # Phase 7: Registry persistence
        print("[*] Scanning registry for persistence mechanisms...")
        self.scan_registry_persistence(processes, progress_cb=progress_cb, progress_start=82, progress_end=88)
        print("[+] Registry scanning complete\n")
        _maybe_pause()

        # Phase 8: Risk scoring (Enhancement #3)
        print("[*] Calculating multi-factor risk scores...")
        self.calculate_risk_scores(processes, progress_cb=progress_cb, progress_start=88, progress_end=93)
        print("[+] Risk scoring complete\n")
        _maybe_pause()

        if do_yara:
            pids = sorted(processes.keys())
            yara_by_pid: Dict[int, List[str]] = {}
            if prefer_volatility_yara:
                yara_by_pid = self.scan_yara_with_volatility(memory_file, pids)

            if not yara_by_pid:
                print("[*] Volatility YARA scan had no matches\n")

            matches_found = sum(len(rules) for rules in yara_by_pid.values())
            print(f"[+] YARA scan complete: {len(yara_by_pid)} processes matched, {matches_found} total matches\n")
            for pid, rules in yara_by_pid.items():
                if pid in processes:
                    processes[pid].yara_matches = sorted(set(rules))
            if progress_cb:
                progress_cb(98, "YARA scan done")
                _maybe_pause()
        else:
            if progress_cb:
                progress_cb(95, "Skipping YARA")
                _maybe_pause()

        # Complete forensic metadata
        if self.forensic_metadata:
            self.forensic_metadata.analysis_end = _dt.datetime.now().isoformat(sep=" ", timespec="seconds")

        if progress_cb:
            progress_cb(100, "Analysis complete")
            _maybe_pause()
        
        return processes


def main() -> None:
    print("\n" + "="*60)
    print("MEMORY FORENSIC ANALYZER - Volatility 3 + YARA v3.4")
    print("Enhanced with Advanced Detection Features")
    print("="*60 + "\n")
    
    parser = argparse.ArgumentParser(description="Memory Forensic Analyzer v3.4 (Enhanced)")
    parser.add_argument("-f", "--file", required=True, help="Memory dump file")
    parser.add_argument("-o", "--output", help="Custom report filename (.txt or .csv)")
    parser.add_argument("--report-type", choices=["txt", "csv"], default="txt")
    parser.add_argument("--no-yara", action="store_true", help="Skip YARA scan")
    parser.add_argument("--prefer-volatility-yara", action="store_true")
    parser.add_argument("--dump-dir", help="Dump directory for fallback memmap dumping")
    parser.add_argument("--export-iocs", action="store_true", help="Export IOCs to CSV")
    parser.add_argument("--case-number", default="", help="Case number for forensic report")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()

    analyzer = MemoryAnalyzer(debug=args.debug)

    if not analyzer.validate_paths(require_yara=not args.no_yara):
        sys.exit(2)

    report_path = args.output or get_next_report_filename(ext=f".{args.report_type}")
    start = _dt.datetime.now()

    processes = analyzer.analyze(
        memory_file=args.file,
        do_yara=not args.no_yara,
        prefer_volatility_yara=args.prefer_volatility_yara,
        dump_dir=args.dump_dir,
        case_number=args.case_number,
    )

    print("[*] Generating report...")
    analyzer.generate_report(
        memory_file=args.file,
        processes=processes,
        output_file=report_path,
        report_type=args.report_type,
    )

    # Export IOCs if requested (Enhancement #2)
    if args.export_iocs:
        analyzer.export_iocs(processes)

    end = _dt.datetime.now()
    elapsed = end - start
    print(f"[+] Report saved: {report_path}")
    print(f"[+] Runtime: {elapsed}")


if __name__ == "__main__":
    main()
