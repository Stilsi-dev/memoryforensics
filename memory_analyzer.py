#!/usr/bin/env python3
"""
Memory Forensic Analyzer - Volatility 3 Compatible
Now saves reports directly as analysisReport_xxx.txt in analysis folder.
Includes progress printing for DLL scan per process.
"""

import os
import sys
import shutil
import argparse
import yara
import subprocess
from datetime import datetime

# Configuration
VOLATILITY_PATH = "volatility3/vol.py"
YARA_RULES_FILE = "malware_rules.yar"

SUSPICIOUS_PATHS = ["\\temp\\", "\\appdata\\", "\\programdata\\"]


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
            "python",
            self.volatility_path,
            "-f", os.path.normpath(memory_file),
            f"windows.{plugin}"
        ]
        if extra_args:
            cmd += extra_args

        try:
            result = subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            print(f"[-] Volatility command failed: {' '.join(cmd)}")
            print(f"Error: {e.stderr}")
            return None

    def get_processes(self, memory_file):
        print("[+] Extracting visible processes (pslist)...")
        pslist_output = self.run_volatility("pslist", memory_file)
        print("[+] Extracting all processes (psscan)...")
        psscan_output = self.run_volatility("psscan", memory_file)

        def parse_processes(raw_output):
            lines = raw_output.strip().splitlines()
            for idx, line in enumerate(lines):
                if line.strip().startswith("PID"):
                    lines = lines[idx:]
                    break
            headers = lines[0].split()
            procs = []
            for line in lines[1:]:
                parts = line.split(None, len(headers) - 1)
                if len(parts) < 3:
                    continue
                procs.append({
                    "PID": parts[0],
                    "PPID": parts[1],
                    "ImageFileName": parts[2],
                    "Parent": "Unknown"
                })
            return procs

        pslist_procs = parse_processes(pslist_output) if pslist_output else []
        psscan_procs = parse_processes(psscan_output) if psscan_output else []

        pslist_pids = {p["PID"] for p in pslist_procs}
        psscan_map = {p["PID"]: p for p in psscan_procs}

        all_procs = []
        for pid, proc in psscan_map.items():
            proc["Hidden"] = "Yes" if pid not in pslist_pids else "No"
            all_procs.append(proc)

        pid_map = {p["PID"]: p["ImageFileName"] for p in all_procs}
        for p in all_procs:
            p["Parent"] = pid_map.get(p["PPID"], "Unknown")

        return all_procs

    def detect_suspicious(self, processes):
        suspicious = []
        common_parents = ["explorer.exe", "svchost.exe", "services.exe", "wininit.exe"]
        for p in processes:
            flags = []
            name = p.get("ImageFileName", "").lower()

            if p.get("Hidden") == "Yes":
                flags.append("Hidden process (from psscan)")
            if any(bad in name for bad in ["mimi", "cobalt", "inject", "malware"]):
                flags.append("Known bad process name")
            if p["Parent"].lower() not in common_parents:
                flags.append(f"Unusual parent: {p['Parent']}")
            if p.get("SuspiciousDLL"):
                flags.append("Suspicious DLLs loaded")

            if flags:
                p["Flags"] = ", ".join(flags)
                suspicious.append(p)
        return suspicious

    def scan_dlls(self, memory_file, processes):
        print("[+] Checking for suspicious DLLs...")
        for p in processes:
            pid = p["PID"]
            print(f"  [*] Checking DLLs for PID {pid} ({p['ImageFileName']})...")
            dll_output = self.run_volatility("dlllist", memory_file, ["--pid", str(pid)])
            if not dll_output:
                continue
            for line in dll_output.splitlines():
                for bad_path in SUSPICIOUS_PATHS:
                    if bad_path in line.lower():
                        p["SuspiciousDLL"] = True
                        break
        return processes

    def scan_memory(self, memory_file, processes, output_dir, limit=10):
        if not self.yara_rules:
            return []

        print(f"[+] Scanning process memory with YARA rules (limit: {limit})...")
        matches = []

        for p in processes[:limit]:
            pid = p.get("PID")
            if not pid:
                continue
            print(f"  [*] Scanning PID {pid} ({p['ImageFileName']})...")

            try:
                cmd = [
                    "python",
                    self.volatility_path,
                    "-f", memory_file,
                    "windows.memmap",
                    "--pid", str(pid),
                    "--dump"
                ]
                subprocess.run(cmd, check=True, capture_output=True, text=True)

                dump_files = [f for f in os.listdir(".") if f.startswith(f"pid.{pid}") and f.endswith(".dmp")]
                for dump_file in dump_files:
                    src_path = os.path.abspath(dump_file)
                    dest_path = os.path.join(output_dir, dump_file)
                    shutil.move(src_path, dest_path)

                    with open(dest_path, "rb") as f:
                        file_matches = self.yara_rules.match(data=f.read())
                        if file_matches:
                            p["YARA_Matches"] = [str(m) for m in file_matches]
                            matches.append(p)
                            print(f"    [!] Found {len(file_matches)} YARA matches")

                    os.remove(dest_path)

            except Exception as e:
                print(f"    [-] Error scanning PID {pid}: {str(e)[:100]}")
                continue

        return matches

    def generate_report(self, data, output_file):
        print(f"[+] Generating report: {output_file}")
        with open(output_file, "w") as f:
            f.write("MEMORY FORENSIC ANALYSIS REPORT\n")
            f.write("="*60 + "\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Analyzed: {os.path.basename(data.get('memory_file', 'Unknown'))}\n\n")

            f.write("SUMMARY\n")
            f.write("="*60 + "\n")
            f.write(f"Total Processes: {len(data.get('processes', []))}\n")
            f.write(f"Suspicious Processes: {len(data.get('suspicious', []))}\n")
            f.write(f"Processes with YARA Matches: {len(data.get('yara_matches', []))}\n\n")

            f.write("SUSPICIOUS PROCESSES\n")
            f.write("="*60 + "\n")
            if data.get("suspicious"):
                for p in data["suspicious"]:
                    f.write(f"PID: {p['PID']:>6} | Process: {p['ImageFileName']:<30} | Flags: {p['Flags']}\n")
            else:
                f.write("No suspicious processes detected\n")

            f.write("\nYARA RULE MATCHES\n")
            f.write("="*60 + "\n")
            if data.get("yara_matches"):
                for p in data["yara_matches"]:
                    f.write(f"PID: {p['PID']:>6} | Process: {p['ImageFileName']:<30} | Matches: {', '.join(p['YARA_Matches'])}\n")
            else:
                f.write("No YARA rule matches found\n")

            f.write("\nPROCESS LIST\n")
            f.write("="*60 + "\n")
            for p in data.get("processes", []):
                hidden_str = " (Hidden)" if p.get("Hidden") == "Yes" else ""
                f.write(f"PID: {p['PID']:>6} | Process: {p['ImageFileName']:<30} | Parent: {p['Parent']}{hidden_str}\n")


def main():
    print("\n" + "="*60)
    print("MEMORY FORENSIC ANALYZER - VOLATILITY 3 VERSION")
    print("="*60 + "\n")

    parser = argparse.ArgumentParser(description="Analyze memory dumps for malicious activity")
    parser.add_argument("-f", "--file", required=True, help="Path to the memory dump file")
    parser.add_argument("-o", "--output", help="Custom report filename (optional)")
    parser.add_argument("--no-yara", action="store_true", help="Skip YARA scanning")
    parser.add_argument("--pid-limit", type=int, default=10, help="Limit number of PIDs to scan with YARA")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"[-] Memory dump not found: {args.file}")
        sys.exit(1)

    analyzer = MemoryAnalyzer()

    if not analyzer.validate_paths():
        sys.exit(1)

    if not args.no_yara and not analyzer.load_yara_rules():
        print("[!] Continuing without YARA scanning capability")

    report_path = args.output or get_next_report_filename()

    processes = analyzer.get_processes(args.file)
    if not processes:
        print("[-] Failed to extract process information")
        sys.exit(1)

    processes = analyzer.scan_dlls(args.file, processes)
    suspicious = analyzer.detect_suspicious(processes)

    yara_matches = []
    if not args.no_yara:
        yara_matches = analyzer.scan_memory(args.file, processes, os.path.dirname(report_path), limit=args.pid_limit)
    else:
        print("[!] Skipping YARA scan as per user request.")

    analyzer.generate_report({
        "memory_file": args.file,
        "processes": processes,
        "suspicious": suspicious,
        "yara_matches": yara_matches
    }, report_path)

    print(f"\n[+] Analysis complete! Report saved to: {report_path}")


if __name__ == "__main__":
    main()
