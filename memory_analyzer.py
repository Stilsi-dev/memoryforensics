#!/usr/bin/env python3
"""
Memory Forensic Analyzer - Volatility 3 Compatible (Windows-only)

Scans a memory dump using Volatility 3 and YARA rules to:
- Extract running processes (pslist/psscan) and mark hidden ones
- Detect injection/anomalies (malfind, ldrmodules, vadinfo summary)
- Detect suspicious DLL paths (dlllist)
- Scan memory with YARA (prefer Volatility vadyarascan/yarascan; fallback to memmap dumps)
- Generate TXT/CSV reports

Designed to reduce false positives by:
- Using JSON output from Volatility (stable parsing)
- Deduplicating YARA matches per PID
- Separating high/low-confidence rule matches
"""
from __future__ import annotations

import argparse
import csv
import datetime as _dt
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

VOLATILITY_PATH = os.path.join("volatility3", "vol.py")
YARA_RULES_FILE = "malware_rules.yar"

SUSPICIOUS_DIR_HINTS = (
    r"\temp\\",
    r"\appdata\\",
    r"\programdata\\",
    r"\users\public\\",
)

# YARA confidence tiers (used for reporting/scoring).
# Keep this small and explicit to avoid over-weighting generic rules.
YARA_CONFIDENCE: Dict[str, str] = {
    "Mimikatz_Indicators": "high",
    "CobaltStrike_Beacon": "high",
    "PowerShell_Exploitation": "medium",
    "Process_Injection": "low",
    "Ransomware_Indicators": "medium",
    "Suspicious_Process_Paths": "low",
    "Credential_Dumping_Tools": "medium",
    "Malicious_Office_Macros": "low",
    "Web_Shell_Indicators": "low",
    "RemoteAccessTool_Strings": "medium",
    "Malware_Strings_Generic": "low",
}


def get_next_report_filename(base_dir: str = "analysis",
                             prefix: str = "analysisReport_",
                             ext: str = ".txt") -> str:
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
    hidden: bool = False
    cmdline: str = ""
    dll_paths: List[str] = field(default_factory=list)
    suspicious_dlls: List[str] = field(default_factory=list)
    malfind_hits: int = 0
    ldr_anomalies: int = 0
    vad_suspicious: bool = False
    yara_matches: List[str] = field(default_factory=list)

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
        hi = [r for r in self.yara_matches if YARA_CONFIDENCE.get(r, "low") == "high"]
        if hi:
            f.append(f"High-confidence YARA: {', '.join(sorted(set(hi)))}")
        return f


class MemoryAnalyzer:
    def __init__(self,
                 volatility_path: str = VOLATILITY_PATH,
                 yara_rules_file: str = YARA_RULES_FILE) -> None:
        self.volatility_path = volatility_path
        self.yara_rules_file = yara_rules_file

    def validate_paths(self, require_yara: bool = True) -> bool:
        if not os.path.isfile(self.volatility_path):
            print(f"[!] Volatility path not found: {self.volatility_path}")
            return False
        if require_yara and not os.path.isfile(self.yara_rules_file):
            print(f"[!] YARA rules file not found: {self.yara_rules_file}")
            return False
        return True

    # ---------- Volatility helpers (JSON-first) ----------

    def _run(self, args: List[str], timeout: Optional[int] = None) -> Tuple[int, str, str]:
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr

    def run_volatility_json(self,
                            plugin: str,
                            memory_file: str,
                            extra_args: Optional[List[str]] = None,
                            timeout: Optional[int] = None) -> List[Dict[str, Any]]:
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
        rc, out, err = self._run(cmd, timeout=timeout)
        if rc != 0:
            raise RuntimeError(f"Volatility failed ({plugin}): {err.strip() or out.strip()}")

        out = out.strip()
        if not out:
            return []

        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            # Some environments may have non-JSON noise; attempt to extract the last JSON object.
            m = re.search(r"(\{.*\}|\[.*\])\s*$", out, flags=re.S)
            if not m:
                return []
            data = json.loads(m.group(1))

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
        pslist = self.run_volatility_json("windows.pslist", memory_file)
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
            processes[pid] = ProcessInfo(pid=pid, ppid=ppid, name=name, hidden=False)

        for row in psscan:
            pid = _pid(row.get("PID"))
            if pid is None:
                continue
            name = str(row.get("ImageFileName") or row.get("Name") or row.get("Process") or "Unknown")
            ppid = _pid(row.get("PPID") or row.get("ParentPID"))
            if pid not in processes:
                processes[pid] = ProcessInfo(pid=pid, ppid=ppid, name=name, hidden=True)
            else:
                processes[pid].hidden = (pid not in pslist_pids)
                if processes[pid].ppid is None and ppid is not None:
                    processes[pid].ppid = ppid

        # Add cmdline (helps anomaly detection and report usefulness)
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

    def scan_dlls(self, memory_file: str, processes: Dict[int, ProcessInfo]) -> Dict[int, ProcessInfo]:
        for pid, p in processes.items():
            try:
                rows = self.run_volatility_json("windows.dlllist", memory_file, ["--pid", str(pid)])
            except Exception:
                continue

            paths: List[str] = []
            suspicious: List[str] = []

            for r in rows:
                # Different Vol3 builds use different keys; try common ones
                path = r.get("Path") or r.get("FullDllName") or r.get("MappedPath") or r.get("File output") or ""
                if not path:
                    continue
                s = str(path)
                paths.append(s)
                low = s.lower()
                if any(h in low for h in SUSPICIOUS_DIR_HINTS):
                    suspicious.append(s)

            p.dll_paths = sorted(set(paths))
            p.suspicious_dlls = sorted(set(suspicious))

        return processes

    def detect_injection_anomalies(self, memory_file: str, processes: Dict[int, ProcessInfo]) -> Dict[int, ProcessInfo]:
        def _to_bool(v: Any) -> Optional[bool]:
            if isinstance(v, bool):
                return v
            if isinstance(v, str):
                if v.lower() in ("true", "yes", "1"):
                    return True
                if v.lower() in ("false", "no", "0"):
                    return False
            return None

        for pid, p in processes.items():
            # malfind
            try:
                mf = self.run_volatility_json("windows.malfind", memory_file, ["--pid", str(pid)])
                # Many rows == findings; count them
                p.malfind_hits = len(mf)
            except Exception:
                p.malfind_hits = 0

            # ldrmodules (unlinked modules)
            try:
                lm = self.run_volatility_json("windows.ldrmodules", memory_file, ["--pid", str(pid)])
                anomalies = 0
                for r in lm:
                    inload = _to_bool(r.get("InLoad") or r.get("InLoadOrder"))
                    ininit = _to_bool(r.get("InInit") or r.get("InInitOrder"))
                    inmem = _to_bool(r.get("InMem") or r.get("InMemory"))
                    # If any membership flag exists and is false => anomaly
                    flags = [x for x in (inload, ininit, inmem) if x is not None]
                    if flags and any(x is False for x in flags):
                        anomalies += 1
                p.ldr_anomalies = anomalies
            except Exception:
                p.ldr_anomalies = 0

            # vadinfo (light heuristic: RX/RWX + private)
            try:
                vad = self.run_volatility_json("windows.vadinfo", memory_file, ["--pid", str(pid)])
                suspicious = False
                for r in vad:
                    prot = str(r.get("Protection") or "").lower()
                    vadtype = str(r.get("Tag") or r.get("Vad Tag") or r.get("Type") or "").lower()
                    private = str(r.get("PrivateMemory") or r.get("Private") or "").lower()
                    # Heuristic: executable + private
                    if ("execute" in prot) and (private in ("true", "yes", "1") or "private" in vadtype):
                        if ("write" in prot) or ("execute" in prot):
                            suspicious = True
                            break
                p.vad_suspicious = suspicious
            except Exception:
                p.vad_suspicious = False

        return processes

    # ---------- YARA scanning ----------

    def scan_yara_with_volatility(self, memory_file: str, pids: Iterable[int]) -> Dict[int, List[str]]:
        """
        Prefer Volatility YARA plugins to avoid dump management.
        Attempts: windows.vadyarascan then windows.yarascan, with common arg names.
        Returns: {pid: [rule, ...]}
        """
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
                        # Scan per PID to keep output small and easy to attribute
                        for pid in pids:
                            rows = self.run_volatility_json(plugin, memory_file, ["--pid", str(pid), *yara_args])
                            for r in rows:
                                rule = r.get("Rule") or r.get("rule") or r.get("Rules") or ""
                                if rule:
                                    results.setdefault(pid, []).append(str(rule))
                    else:
                        rows = self.run_volatility_json(plugin, memory_file, yara_args)
                        for r in rows:
                            pid = _pid(r.get("PID"))
                            rule = r.get("Rule") or ""
                            if pid is not None and rule:
                                results.setdefault(pid, []).append(str(rule))
                    # If we got here without raising, plugin+args worked
                    for pid in list(results.keys()):
                        results[pid] = sorted(set(results[pid]))
                    return results
                except Exception:
                    continue

        return {}

    def scan_yara_fallback_memmap_dump(self, memory_file: str, pids: Iterable[int], dump_dir: str) -> Dict[int, List[str]]:
        """
        Fallback method: windows.memmap --dump per PID, then yara-python if installed.
        """
        try:
            import yara  # type: ignore
        except Exception:
            print("[!] yara-python not installed; skipping fallback YARA scanning.")
            return {}

        os.makedirs(dump_dir, exist_ok=True)
        rules = yara.compile(filepath=self.yara_rules_file)

        results: Dict[int, List[str]] = {}

        # Ensure dumps go into dump_dir by using CWD for vol execution
        for pid in pids:
            try:
                cmd = [
                    sys.executable,
                    self.volatility_path,
                    "-f",
                    memory_file,
                    "windows.memmap",
                    "--pid",
                    str(pid),
                    "--dump",
                ]
                rc, out, err = self._run(cmd, timeout=None)
                if rc != 0:
                    continue

                # Vol3 writes dumps into current working directory.
                # Move any new dumps for this PID into dump_dir.
                for fn in os.listdir("."):
                    if re.match(rf"pid\.{pid}\..*\.dmp$", fn, flags=re.IGNORECASE):
                        src = fn
                        dst = os.path.join(dump_dir, fn)
                        try:
                            shutil.move(src, dst)
                        except Exception:
                            pass

                pid_rules: List[str] = []
                for fn in os.listdir(dump_dir):
                    if not re.match(rf"pid\.{pid}\..*\.dmp$", fn, flags=re.IGNORECASE):
                        continue
                    path = os.path.join(dump_dir, fn)
                    try:
                        with open(path, "rb") as f:
                            data = f.read()
                        matches = rules.match(data=data)
                        pid_rules.extend([m.rule for m in matches])
                    except Exception:
                        continue

                if pid_rules:
                    results[pid] = sorted(set(pid_rules))
            except Exception:
                continue

        return results

    # ---------- Scoring & reporting ----------

    def classify_severity(self, p: ProcessInfo) -> str:
        score = 0
        if p.hidden:
            score += 2
        if p.malfind_hits > 0:
            score += 3
        if p.ldr_anomalies > 0:
            score += 2
        if p.vad_suspicious:
            score += 1
        if p.suspicious_dlls:
            score += 1

        hi = [r for r in p.yara_matches if YARA_CONFIDENCE.get(r, "low") == "high"]
        med = [r for r in p.yara_matches if YARA_CONFIDENCE.get(r, "low") == "medium"]
        if hi:
            score += 3
        elif med:
            score += 1

        if score >= 6:
            return "Critical"
        if score >= 4:
            return "High"
        if score >= 2:
            return "Medium"
        return "Low"

    def generate_report(self,
                        memory_file: str,
                        processes: Dict[int, ProcessInfo],
                        output_file: str,
                        report_type: str = "txt") -> None:
        os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)

        all_procs = list(processes.values())
        suspicious = [p for p in all_procs if self.classify_severity(p) in ("Medium", "High", "Critical")]
        yara_any = [p for p in all_procs if p.yara_matches]
        yara_hi = [p for p in all_procs if any(YARA_CONFIDENCE.get(r, "low") == "high" for r in p.yara_matches)]

        if report_type == "csv":
            with open(output_file, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow([
                    "PID", "PPID", "Process", "Severity", "Hidden",
                    "malfind_hits", "ldr_anomalies", "vad_suspicious",
                    "suspicious_dll_count", "cmdline", "yara_matches"
                ])
                for p in sorted(all_procs, key=lambda x: x.pid):
                    w.writerow([
                        p.pid, p.ppid or "", p.name, self.classify_severity(p), "Yes" if p.hidden else "No",
                        p.malfind_hits, p.ldr_anomalies, "Yes" if p.vad_suspicious else "No",
                        len(p.suspicious_dlls), p.cmdline, ";".join(sorted(set(p.yara_matches)))
                    ])
            return

        now = _dt.datetime.now().isoformat(sep=" ", timespec="seconds")
        lines: List[str] = []
        lines.append("MEMORY FORENSIC ANALYSIS REPORT (Windows-only)")
        lines.append("=" * 60)
        lines.append(f"Generated: {now}")
        lines.append(f"Analyzed: {os.path.basename(memory_file)}")
        lines.append("")
        lines.append("SUMMARY")
        lines.append("=" * 60)
        lines.append(f"Total Processes: {len(all_procs)}")
        lines.append(f"Suspicious Processes (>= Medium): {len(suspicious)}")
        lines.append(f"Processes with ANY YARA Matches: {len(yara_any)}")
        lines.append(f"Processes with HIGH-Confidence YARA Matches: {len(yara_hi)}")
        lines.append("")
        lines.append("TOP SUSPICIOUS PROCESSES")
        lines.append("=" * 60)

        top = sorted(all_procs, key=lambda p: ("Low", "Medium", "High", "Critical").index(self.classify_severity(p)), reverse=True)
        top = sorted(top, key=lambda p: {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}[self.classify_severity(p)], reverse=True)

        for p in top[:20]:
            sev = self.classify_severity(p)
            if sev == "Low" and not p.flags():
                continue
            lines.append(f"PID: {p.pid:>6} | PPID: {str(p.ppid or ''):>6} | Severity: {sev:<8} | {p.name}")
            if p.cmdline:
                lines.append(f"  CmdLine: {p.cmdline}")
            fl = p.flags()
            if fl:
                lines.append(f"  Flags: {', '.join(fl)}")
            if p.suspicious_dlls:
                for dll in p.suspicious_dlls[:10]:
                    lines.append(f"  SuspiciousDLL: {dll}")
                if len(p.suspicious_dlls) > 10:
                    lines.append(f"  SuspiciousDLL: ...({len(p.suspicious_dlls) - 10} more)")
            if p.yara_matches:
                hi = [r for r in p.yara_matches if YARA_CONFIDENCE.get(r, 'low') == 'high']
                med = [r for r in p.yara_matches if YARA_CONFIDENCE.get(r, 'low') == 'medium']
                low = [r for r in p.yara_matches if YARA_CONFIDENCE.get(r, 'low') == 'low']
                if hi:
                    lines.append(f"  YARA(high): {', '.join(sorted(set(hi)))}")
                if med:
                    lines.append(f"  YARA(med):  {', '.join(sorted(set(med)))}")
                if low:
                    lines.append(f"  YARA(low):  {', '.join(sorted(set(low)))}")
            lines.append("")

        lines.append("YARA SUMMARY (per PID, deduped)")
        lines.append("=" * 60)
        for p in sorted(all_procs, key=lambda x: x.pid):
            if not p.yara_matches:
                continue
            lines.append(f"PID: {p.pid:>6} | Process: {p.name:<20} | Matches: {', '.join(sorted(set(p.yara_matches)))}")

        with open(output_file, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    # ---------- End-to-end ----------

    def analyze(self,
                memory_file: str,
                do_yara: bool,
                prefer_volatility_yara: bool,
                dump_dir: Optional[str]) -> Dict[int, ProcessInfo]:
        processes = self.get_processes(memory_file)
        processes = self.scan_dlls(memory_file, processes)
        processes = self.detect_injection_anomalies(memory_file, processes)

        if do_yara:
            pids = sorted(processes.keys())
            yara_by_pid: Dict[int, List[str]] = {}
            if prefer_volatility_yara:
                yara_by_pid = self.scan_yara_with_volatility(memory_file, pids)

            if not yara_by_pid:
                # fallback
                if dump_dir is None:
                    dump_dir = os.path.join("analysis", "dumps", _dt.datetime.now().strftime("%Y%m%d_%H%M%S"))
                yara_by_pid = self.scan_yara_fallback_memmap_dump(memory_file, pids, dump_dir)

            for pid, rules in yara_by_pid.items():
                if pid in processes:
                    processes[pid].yara_matches = sorted(set(rules))

        return processes


def main() -> None:
    parser = argparse.ArgumentParser(description="Memory Forensic Analyzer (Windows-only, Volatility 3 + YARA)")
    parser.add_argument("-f", "--file", required=True, help="Memory dump file")
    parser.add_argument("-o", "--output", help="Custom report filename (.txt or .csv)")
    parser.add_argument("--report-type", choices=["txt", "csv"], default="txt")
    parser.add_argument("--no-yara", action="store_true", help="Skip YARA scan")
    parser.add_argument("--prefer-volatility-yara", action="store_true",
                        help="Prefer Volatility's (vad)yarascan plugin instead of dumping memory")
    parser.add_argument("--dump-dir", help="Dump directory for fallback memmap dumping (used if volatility-yara isn't available)")
    args = parser.parse_args()

    analyzer = MemoryAnalyzer()

    if not analyzer.validate_paths(require_yara=not args.no_yara):
        sys.exit(2)

    report_path = args.output or get_next_report_filename(ext=f".{args.report_type}")
    start = _dt.datetime.now()

    processes = analyzer.analyze(
        memory_file=args.file,
        do_yara=not args.no_yara,
        prefer_volatility_yara=args.prefer_volatility_yara,
        dump_dir=args.dump_dir,
    )

    analyzer.generate_report(
        memory_file=args.file,
        processes=processes,
        output_file=report_path,
        report_type=args.report_type,
    )

    end = _dt.datetime.now()
    elapsed = end - start
    print(f"[+] Report saved: {report_path}")
    print(f"[+] Runtime: {elapsed}")


if __name__ == "__main__":
    main()
