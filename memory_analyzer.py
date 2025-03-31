#!/usr/bin/env python3
"""
Memory Forensic Analysis Tool for Malware Detection
Group 2 - Memory Forensics Project

This tool analyzes memory dumps to detect malicious processes, anomalies,
and malware signatures using YARA rules. It provides both technical analysis
and visualizations of findings.
"""

import os
import yara
import pandas as pd
import matplotlib.pyplot as plt
import subprocess
from datetime import datetime

class MemoryAnalyzer:
    def __init__(self, memory_dump_path):
        self.memory_dump = memory_dump_path
        self.processes = []
        self.suspicious_items = []
        self.yara_rules = None
        self.report_data = {
            'analysis_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'filename': os.path.basename(memory_dump_path),
            'findings': []
        }

    def load_yara_rules(self, rules_path):
        try:
            self.yara_rules = yara.compile(rules_path)
            self.report_data['yara_rules_loaded'] = True
            return True
        except Exception as e:
            print(f"[!] Error loading YARA rules: {e}")
            self.report_data['yara_rules_loaded'] = False
            return False

    def extract_processes(self):
        print("[*] Running Volatility3 to extract process list...")
        try:
            output = subprocess.run(
                ["vol", "-f", self.memory_dump, "windows.pslist"],
                capture_output=True, text=True, check=True
            )
            lines = output.stdout.splitlines()
            self.processes = []

            for line in lines:
                if line.strip().startswith("Offset") or line.strip() == "":
                    continue
                parts = line.strip().split()
                if len(parts) >= 6:
                    pid = int(parts[2])
                    ppid = int(parts[3])
                    name = parts[-1]
                    self.processes.append({
                        'pid': pid,
                        'parent_pid': ppid,
                        'name': name,
                        'path': f"Unknown (PID: {pid})",
                        'start_time': "Unknown",
                        'user': "N/A",
                        'dlls': []
                    })

            self.report_data['process_count'] = len(self.processes)
            return self.processes

        except subprocess.CalledProcessError as e:
            print(f"[!] Error running Volatility3: {e}")
            return []

    def dump_process_memory(self, pid, output_dir="process_dumps"):
        os.makedirs(output_dir, exist_ok=True)
        print(f"[*] Dumping memory for PID {pid}...")

        try:
            subprocess.run([
                "vol", "-f", self.memory_dump, "windows.memdump",
                f"--pid={pid}", f"--dump-dir={output_dir}"
            ], check=True)

            for fname in os.listdir(output_dir):
                if fname.startswith(f"pid.{pid}.") and fname.endswith(".dmp"):
                    return os.path.join(output_dir, fname)
        except Exception as e:
            print(f"[!] Failed to dump memory for PID {pid}: {e}")
        return None

    def detect_suspicious_processes(self):
        suspicious = []
        for process in self.processes:
            flags = []
            temp_paths = ['temp', 'tmp', 'appdata', 'local\\temp']
            if any(path in process['path'].lower() for path in temp_paths):
                flags.append('Runs from temporary location')
            if process['name'].lower() != os.path.basename(process['path']).lower():
                flags.append('Name/path mismatch')
            suspicious_names = ['mimikatz', 'cobaltstrike', 'metasploit', 'netwire', 'empire', 'powersploit']
            if any(name in process['name'].lower() for name in suspicious_names):
                flags.append('Known malicious process name')
            if (process['parent_pid'] == 200 and process['pid'] == 444):
                flags.append('Unusual parent process')
            suspicious_dlls = ['unknown.dll', 'inject.dll', 'hook.dll']
            if any(dll.lower() in [d.lower() for d in process['dlls']] for dll in suspicious_dlls):
                flags.append('Suspicious DLL loaded')

            if flags:
                suspicious.append({
                    'process': process,
                    'flags': flags,
                    'type': 'suspicious_process'
                })
        self.suspicious_items.extend(suspicious)
        return suspicious

    def scan_for_malware(self):
        if not self.yara_rules:
            print("[!] YARA rules not loaded - skipping scan.")
            return []

        results = []
        for process in self.processes:
            dump_path = self.dump_process_memory(process['pid'])
            if not dump_path or not os.path.exists(dump_path):
                continue

            try:
                matches = self.yara_rules.match(filepath=dump_path)
                if matches:
                    results.append({
                        'process': process,
                        'matches': [m.rule for m in matches],
                        'type': 'malware_signature'
                    })
            except Exception as e:
                print(f"[!] YARA error scanning PID {process['pid']}: {e}")

        self.suspicious_items.extend(results)
        return results

    def generate_report(self):
        if not self.suspicious_items:
            self.report_data['conclusion'] = "No suspicious activity detected"
        else:
            self.report_data['conclusion'] = f"{len(self.suspicious_items)} suspicious items found"
            self.report_data['findings'] = self.suspicious_items
        return self.report_data

    def visualize_process_tree(self):
        try:
            df = pd.DataFrame(self.processes)
            plt.figure(figsize=(12, 8))
            for _, process in df.iterrows():
                plt.scatter(process['parent_pid'], process['pid'], label=process['name'], s=100)
                plt.text(process['parent_pid'], process['pid'],
                         f"{process['name']}\nPID: {process['pid']}",
                         fontsize=8, ha='center', va='bottom')
            if self.suspicious_items:
                for item in self.suspicious_items:
                    if 'process' in item:
                        plt.scatter(item['process']['parent_pid'],
                                    item['process']['pid'],
                                    color='red', s=150, marker='x')
            plt.title("Process Tree Visualization\n(Red X marks suspicious processes)")
            plt.xlabel("Parent PID")
            plt.ylabel("PID")
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            image_path = "process_tree.png"
            plt.savefig(image_path)
            plt.close()
            return image_path
        except Exception as e:
            print(f"[!] Error generating visualization: {e}")
            return None

if __name__ == "__main__":
    print("""
    Memory Forensic Tool - Group 2
    -----------------------------
    """)

    analyzer = MemoryAnalyzer("memory.raw")
    if not analyzer.load_yara_rules("malware_rules.yar"):
        print("[!] Continuing without YARA rules")

    print("[*] Extracting processes...")
    analyzer.extract_processes()

    print("[*] Detecting suspicious processes...")
    analyzer.detect_suspicious_processes()

    print("[*] Scanning for malware signatures...")
    analyzer.scan_for_malware()

    print("[*] Generating report...")
    report = analyzer.generate_report()

    print("[*] Creating visualization...")
    image_path = analyzer.visualize_process_tree()

    print("\n=== Analysis Report ===")
    print(f"Analyzed file: {report['filename']}")
    print(f"Analysis time: {report['analysis_time']}")
    print(f"Processes found: {report.get('process_count', 'N/A')}")
    print(f"Conclusion: {report['conclusion']}")

    if report['findings']:
        print("\n=== Findings ===")
        for i, finding in enumerate(report['findings'], 1):
            print(f"\nFinding #{i}:")
            print(f"Type: {finding['type'].upper()}")
            print(f"Process: {finding['process']['name']} (PID: {finding['process']['pid']})")
            if 'flags' in finding:
                print("Detection Flags:")
                for flag in finding['flags']:
                    print(f" - {flag}")
            if 'matches' in finding:
                print("YARA Rule Matches:")
                for match in finding['matches']:
                    print(f" - {match}")
    if image_path:
        print(f"\nProcess tree visualization saved to {image_path}")
    print("\nAnalysis complete.")
