#!/usr/bin/env python3
"""
Memory Forensic Analyzer - Volatility 3 Compatible
Each analysis run creates a new folder (analysis_001, analysis_002, ...)
Dumped process memory and report are stored in the same folder.
"""

import os
import sys
import shutil
import argparse
import yara
import tempfile
import subprocess
from datetime import datetime

# Configuration
VOLATILITY_PATH = "volatility3/vol.py"
YARA_RULES_FILE = "malware_rules.yar"

def get_next_analysis_folder(base_dir="analysis"):
    os.makedirs(base_dir, exist_ok=True)
    existing = [d for d in os.listdir(base_dir)
                if os.path.isdir(os.path.join(base_dir, d)) and d.startswith("analysis_")]
    numbers = [int(d.split("_")[1]) for d in existing if d.split("_")[1].isdigit()]
    next_num = max(numbers) + 1 if numbers else 1
    folder_name = f"analysis_{next_num:03}"
    full_path = os.path.join(base_dir, folder_name)
    os.makedirs(full_path, exist_ok=True)
    return full_path

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
        print("[+] Extracting process information...")
        output = self.run_volatility("pslist", memory_file)
        if not output:
            return None

        lines = output.strip().splitlines()
        if len(lines) < 2:
            print("[-] Unexpected output format from pslist.")
            return None

        # Skip to header
        for idx, line in enumerate(lines):
            if line.strip().startswith("PID"):
                lines = lines[idx:]
                break

        headers = lines[0].split()
        processes = []

        for line in lines[1:]:
            parts = line.split(None, len(headers) - 1)
            if len(parts) < 3:
                continue
            proc = {
                "PID": parts[0],
                "PPID": parts[1],
                "ImageFileName": parts[2],
                "Parent": "Unknown"
            }
            processes.append(proc)

        pid_map = {p["PID"]: p["ImageFileName"] for p in processes}
        for p in processes:
            p["Parent"] = pid_map.get(p["PPID"], "Unknown")

        return processes

    def detect_suspicious(self, processes):
        suspicious = []
        common_parents = ["explorer.exe", "svchost.exe", "services.exe", "wininit.exe"]
        for p in processes:
            flags = []
            name = p.get("ImageFileName", "").lower()

            if any(bad in name for bad in ["mimi", "cobalt", "inject", "malware"]):
                flags.append("Known bad process name")
            if p["Parent"].lower() not in common_parents:
                flags.append(f"Unusual parent: {p['Parent']}")
            if flags:
                p["Flags"] = ", ".join(flags)
                suspicious.append(p)
        return suspicious

    def scan_memory(self, memory_file, processes, output_dir):
        if not self.yara_rules:
            return []

        print("[+] Scanning process memory with YARA rules...")
        matches = []

        for p in processes[:10]:
            pid = p.get("PID")
            if not pid:
                continue
            print(f"  [*] Scanning PID {pid} ({p['ImageFileName']})...")

            try:
                # Run Volatility to dump memory
                cmd = [
                    "python",
                    self.volatility_path,
                    "-f", memory_file,
                    "windows.memmap",
                    "--pid", str(pid),
                    "--dump"
                ]
                subprocess.run(cmd, check=True, capture_output=True, text=True)

                # Look for dump files in current working directory
                dump_files = [f for f in os.listdir(".") if f.startswith(f"pid.{pid}") and f.endswith(".dmp")]
                for dump_file in dump_files:
                    src_path = os.path.abspath(dump_file)
                    dest_path = os.path.join(output_dir, dump_file)

                    # Move to analysis folder
                    shutil.move(src_path, dest_path)

                    # YARA scan
                    with open(dest_path, "rb") as f:
                        file_matches = self.yara_rules.match(data=f.read())
                        if file_matches:
                            p["YARA_Matches"] = [str(m) for m in file_matches]
                            matches.append(p)
                            print(f"    [!] Found {len(file_matches)} YARA matches")

                    # Delete after scanning
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

            f.write("\nPROCESS LIST (First 20)\n")
            f.write("="*60 + "\n")
            for p in data.get("processes", [])[:20]:
                f.write(f"PID: {p['PID']:>6} | Process: {p['ImageFileName']:<30} | Parent: {p['Parent']}\n")

def main():
    print("\n" + "="*60)
    print("MEMORY FORENSIC ANALYZER - VOLATILITY 3 VERSION")
    print("="*60 + "\n")

    parser = argparse.ArgumentParser(description="Analyze memory dumps for malicious activity")
    parser.add_argument("-f", "--file", required=True, help="Path to the memory dump file")
    parser.add_argument("-o", "--output", default="report.txt", help="Report file name (inside analysis folder)")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"[-] Memory dump not found: {args.file}")
        sys.exit(1)

    analyzer = MemoryAnalyzer()

    if not analyzer.validate_paths():
        sys.exit(1)

    if not analyzer.load_yara_rules():
        print("[!] Continuing without YARA scanning capability")

    analysis_dir = get_next_analysis_folder()
    report_path = os.path.join(analysis_dir, args.output)

    processes = analyzer.get_processes(args.file)
    if not processes:
        print("[-] Failed to extract process information")
        sys.exit(1)

    suspicious = analyzer.detect_suspicious(processes)
    yara_matches = analyzer.scan_memory(args.file, processes, analysis_dir)

    analyzer.generate_report({
        "memory_file": args.file,
        "processes": processes,
        "suspicious": suspicious,
        "yara_matches": yara_matches
    }, report_path)

    print(f"\n[+] Analysis complete! Report and dumps saved to: {analysis_dir}")

if __name__ == "__main__":
    main()
