#!/usr/bin/env python3
"""
Memory Forensic Analyzer - Volatility 3 Compatible
Includes:
- Process extraction
- YARA rule scanning
- Suspicious DLL detection
- Report export in TXT and CSV
"""

import os
import sys
import shutil
import argparse
import yara
import subprocess
import csv
from datetime import datetime

# Configuration
VOLATILITY_PATH = "volatility3/vol.py"
YARA_RULES_FILE = "malware_rules.yar"


def get_next_report_filename(base_dir="analysis", prefix="analysisReport_", ext=".txt"):
    os.makedirs(base_dir, exist_ok=True)
    existing = [f for f in os.listdir(base_dir) if f.startswith(prefix) and f.endswith(ext)]
    numbers = [
        int(f[len(prefix):-len(ext)])
        for f in existing
        if f[len(prefix):-len(ext)].isdigit()
    ]
    next_num = max(numbers) + 1 if numbers else 1
    return os.path.join(base_dir, f"{prefix}{next_num:03}{ext}")


class MemoryAnalyzer:
    def __init__(self, volatility_path=VOLATILITY_PATH):
        self.volatility_path = volatility_path
        self.yara_rules = None

    def validate_paths(self):
        required = [
            (self.volatility_path, "Volatility"),
            (YARA_RULES_FILE, "YARA rules")
        ]
        all_valid = True
        for path, name in required:
            if not os.path.exists(path):
                print(f"[-] Error: {name} not found at {path}")
                all_valid = False
        return all_valid

    def load_yara_rules(self):
        try:
            self.yara_rules = yara.compile(filepath=YARA_RULES_FILE)
            print(f"[+] Successfully loaded YARA rules from {YARA_RULES_FILE}")
            return True
        except yara.SyntaxError as e:
            print(f"[-] YARA syntax error: {e}")
        except Exception as e:
            print(f"[-] Error loading YARA rules: {e}")
        return False

    def run_volatility(self, plugin, memory_file, extra_args=None):
        cmd = [
            "python", self.volatility_path,
            "-f", os.path.normpath(memory_file),
            f"windows.{plugin}"
        ]
        if extra_args:
            cmd += extra_args

        try:
            result = subprocess.run(
                cmd, check=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            print(f"[-] Volatility error: {e.stderr}")
            return None

    def get_processes(self, memory_file):
        print("[+] Extracting visible processes (pslist)...")
        pslist_output = self.run_volatility("pslist", memory_file)
        print("[+] Extracting all processes (psscan)...")
        psscan_output = self.run_volatility("psscan", memory_file)

        def parse(raw):
            lines = raw.strip().splitlines()
            for i, line in enumerate(lines):
                if line.startswith("PID"):
                    lines = lines[i:]
                    break
            headers = lines[0].split()
            procs = []
            for line in lines[1:]:
                parts = line.split(None, len(headers) - 1)
                if len(parts) < 3:
                    continue
                procs.append({
                    "PID": parts[0], "PPID": parts[1],
                    "ImageFileName": parts[2],
                    "Parent": "Unknown", "User": "N/A"
                })
            return procs

        pslist = parse(pslist_output) if pslist_output else []
        psscan = parse(psscan_output) if psscan_output else []

        pslist_pids = {p["PID"] for p in pslist}
        pid_map = {p["PID"]: p["ImageFileName"] for p in psscan}
        all_procs = []
        for p in psscan:
            p["Hidden"] = "Yes" if p["PID"] not in pslist_pids else "No"
            p["Parent"] = pid_map.get(p["PPID"], "Unknown")
            all_procs.append(p)

        return all_procs

    def scan_dlls(self, memory_file, processes):
        print("[+] Checking for DLLs...")
        for p in processes:
            pid = p["PID"]
            print(f"  [*] Checking PID {pid} ({p['ImageFileName']})...")
            dll_output = self.run_volatility("dlllist", memory_file, ["--pid", str(pid)])
            if not dll_output:
                continue

            dll_paths = []
            suspicious_found = False

            for line in dll_output.splitlines():
                line = line.strip()
                if not line or "\\" not in line:
                    continue

                dll_paths.append(line)

                # Check if the path is suspicious
                lowered = line.lower()
                if any(suspicious in lowered for suspicious in ["\\temp\\", "\\appdata\\", "\\programdata\\"]):
                    suspicious_found = True

            if dll_paths:
                p["DLL_Paths"] = dll_paths
            if suspicious_found:
                p["SuspiciousDLL"] = True

        return processes

    def detect_suspicious(self, processes):
        suspicious = []
        common_parents = ["explorer.exe", "svchost.exe", "services.exe", "wininit.exe"]
        for p in processes:
            flags = []
            severity = "Low"
            name = p.get("ImageFileName", "").lower()

            if p.get("Hidden") == "Yes":
                flags.append("Hidden process")
                severity = "High"
            if any(bad in name for bad in ["mimi", "cobalt", "inject", "malware"]):
                flags.append("Known bad name")
                severity = "Critical"
            if p["Parent"].lower() not in common_parents:
                flags.append(f"Unusual parent: {p['Parent']}")
            if p.get("SuspiciousDLL"):
                flags.append("Suspicious DLLs loaded")

            if flags:
                p["Flags"] = ", ".join(flags)
                p["Severity"] = severity
                suspicious.append(p)
        return suspicious

    def scan_memory(self, memory_file, processes, output_dir):
        if not self.yara_rules:
            return []

        print("[+] Scanning process memory with YARA rules...")
        matches = []
        for p in processes:
            pid = p.get("PID")
            if not pid:
                continue
            print(f"  [*] Scanning PID {pid} ({p['ImageFileName']})...")
            try:
                cmd = [
                    "python", self.volatility_path,
                    "-f", memory_file,
                    "windows.memmap",
                    "--pid", str(pid), "--dump"
                ]
                subprocess.run(cmd, check=True, capture_output=True, text=True)
                dump_files = [f for f in os.listdir(".") if f.startswith(f"pid.{pid}") and f.endswith(".dmp")]
                for dump_file in dump_files:
                    full_path = os.path.join(output_dir, dump_file)
                    shutil.move(dump_file, full_path)
                    with open(full_path, "rb") as f:
                        results = self.yara_rules.match(data=f.read())
                        if results:
                            p["YARA_Matches"] = [r.rule for r in results]
                            matches.append(p)
                    os.remove(full_path)
            except Exception as e:
                print(f"    [-] Error scanning PID {pid}: {str(e)}")
        return matches

    def generate_report(self, data, output_file, report_type="txt"):
        print(f"[+] Generating report: {output_file}")
        if report_type == "txt":
            with open(output_file, "w") as f:
                f.write("MEMORY FORENSIC ANALYSIS REPORT\n")
                f.write("="*60 + "\n\n")
                f.write(f"Generated: {datetime.now()}\n")
                f.write(f"Total Run Time: {data.get('run_time', 'N/A')}\n\n")
                f.write(f"Analyzed: {os.path.basename(data['memory_file'])}\n\n")

                f.write("SUMMARY\n" + "="*60 + "\n")
                f.write(f"Total Processes: {len(data['processes'])}\n")
                f.write(f"Suspicious Processes: {len(data['suspicious'])}\n")
                f.write(f"Processes with YARA Matches: {len(data['yara_matches'])}\n\n")

                f.write("SUSPICIOUS PROCESSES\n" + "="*60 + "\n")
                for p in data["suspicious"]:
                    f.write(f"PID: {p['PID']:>6} | Severity: {p.get('Severity','')} | {p['ImageFileName']:<25} | Flags: {p['Flags']}\n")
                    if p.get("DLL_Paths"):
                        for dll in p["DLL_Paths"]:
                            f.write(f"    DLL: {dll}\n")

                f.write("\nYARA RULE MATCHES\n" + "="*60 + "\n")
                for p in data["yara_matches"]:
                    f.write(f"PID: {p['PID']:>6} | Process: {p['ImageFileName']:<25} | Matches: {', '.join(p['YARA_Matches'])}\n")

        elif report_type == "csv":
            fieldnames = ["PID", "PPID", "ImageFileName", "Parent", "Hidden", "User", "Flags", "Severity", "YARA_Matches", "DLL_Paths"]
            with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for p in data["suspicious"]:
                    dll_list = p.get("DLL_Paths", [])
                    dll_display = ""
                    if dll_list:
                        shown = dll_list[:3]
                        dll_display = " | ".join(shown)
                        if len(dll_list) > 3:
                            dll_display += f" (+{len(dll_list) - 3} more)"
                    writer.writerow({
                        "PID": p.get("PID"),
                        "PPID": p.get("PPID"),
                        "ImageFileName": p.get("ImageFileName"),
                        "Parent": p.get("Parent"),
                        "Hidden": p.get("Hidden", ""),
                        "User": p.get("User", "N/A"),
                        "Flags": p.get("Flags", ""),
                        "Severity": p.get("Severity", ""),
                        "YARA_Matches": ", ".join(p.get("YARA_Matches", [])) if p.get("YARA_Matches") else "",
                        "DLL_Paths": dll_display
                    })


def main():
    print("\n" + "="*60)
    print("MEMORY FORENSIC ANALYZER - VOLATILITY 3 VERSION")
    print("="*60 + "\n")

    start_time = datetime.now()

    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=True, help="Memory dump file")
    parser.add_argument("-o", "--output", help="Custom report filename")
    parser.add_argument("--no-yara", action="store_true", help="Skip YARA scan")
    parser.add_argument("--report-type", choices=["txt", "csv"], default="txt")
    args = parser.parse_args()

    analyzer = MemoryAnalyzer()
    if not analyzer.validate_paths():
        sys.exit(1)
    if not args.no_yara:
        analyzer.load_yara_rules()

    report_path = args.output or get_next_report_filename()
    processes = analyzer.get_processes(args.file)
    processes = analyzer.scan_dlls(args.file, processes)
    suspicious = analyzer.detect_suspicious(processes)
    yara_matches = analyzer.scan_memory(args.file, processes, os.path.dirname(report_path)) if not args.no_yara else []

    end_time = datetime.now()
    elapsed = end_time - start_time

    analyzer.generate_report({
        "memory_file": args.file,
        "processes": processes,
        "suspicious": suspicious,
        "yara_matches": yara_matches,
        "run_time": str(elapsed)
    }, report_path, report_type=args.report_type)

    print(f"\n[+] Analysis complete! Report saved to: {report_path}")
    print(f"[+] Total Running Time: {elapsed}")


if __name__ == "__main__":
    main()
