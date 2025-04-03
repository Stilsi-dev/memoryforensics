import os
import tkinter as tk
from tkinter import filedialog, messagebox
from datetime import datetime
import subprocess
import yara
import shutil
import csv
import threading

# Configuration
VOLATILITY_PATH = "volatility3/vol.py"
YARA_RULES_FILE = "malware_rules.yar"
SUSPICIOUS_PATHS = ["\\temp\\", "\\appdata\\", "\\programdata\\"]

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
                return False, f"Error: {name} not found at {path}"
        return True, ""

    def load_yara_rules(self):
        try:
            self.yara_rules = yara.compile(filepath=YARA_RULES_FILE)
            return True, "Successfully loaded YARA rules."
        except yara.SyntaxError as e:
            return False, f"YARA syntax error: {e}"
        except Exception as e:
            return False, f"Error loading YARA rules: {e}"

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
            return f"Volatility command failed: {' '.join(cmd)}\nError: {e.stderr}"

    def get_processes(self, memory_file, update_progress):
        update_progress("Extracting visible processes (pslist)...")
        pslist_output = self.run_volatility("pslist", memory_file)
        update_progress("Extracting all processes (psscan)...")
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
                    "PID": parts[0], "PPID": parts[1],
                    "ImageFileName": parts[2],
                    "Parent": "Unknown", "User": "N/A"
                })
            return procs

        pslist = parse_processes(pslist_output) if pslist_output else []
        psscan = parse_processes(psscan_output) if psscan_output else []

        pslist_pids = {p["PID"] for p in pslist}
        pid_map = {p["PID"]: p["ImageFileName"] for p in psscan}
        all_procs = []
        for p in psscan:
            p["Hidden"] = "Yes" if p["PID"] not in pslist_pids else "No"
            p["Parent"] = pid_map.get(p["PPID"], "Unknown")
            all_procs.append(p)

        return all_procs

    def scan_dlls(self, memory_file, processes, update_progress):
        update_progress("Checking for DLLs...")
        for p in processes:
            pid = p["PID"]
            update_progress(f"  Checking PID {pid} ({p['ImageFileName']})...")
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

                lowered = line.lower()
                if any(suspicious in lowered for suspicious in ["\\temp\\", "\\appdata\\", "\\programdata\\"]):
                    suspicious_found = True

            if dll_paths:
                p["DLL_Paths"] = dll_paths
            if suspicious_found:
                p["SuspiciousDLL"] = True

        return processes

    def detect_suspicious(self, processes, update_progress):
        update_progress("Detecting suspicious processes...")
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

    def scan_memory(self, memory_file, processes, output_dir, update_progress):
        if not self.yara_rules:
            return []

        update_progress("Scanning process memory with YARA rules...")
        matches = []
        for p in processes:
            pid = p.get("PID")
            if not pid:
                continue
            update_progress(f"  Scanning PID {pid} ({p['ImageFileName']})...")
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
                continue
        return matches

    def generate_report(self, data, output_file, update_progress, report_type="txt"):
        update_progress(f"Generating report: {output_file}")
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


class MemoryAnalyzerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Memory Forensic Analyzer")
        self.geometry("800x600")

        self.memory_analyzer = MemoryAnalyzer()

        self.create_widgets()
        self.result_text = None

    def create_widgets(self):
        self.file_label = tk.Label(self, text="Select Memory Dump File:")
        self.file_label.pack(pady=10)

        self.file_entry = tk.Entry(self, width=50)
        self.file_entry.pack(pady=5)

        self.browse_button = tk.Button(self, text="Browse", command=self.browse_file)
        self.browse_button.pack(pady=5)

        self.run_button = tk.Button(self, text="Run Analysis", command=self.run_analysis)
        self.run_button.pack(pady=10)

        self.progress_label = tk.Label(self, text="", font=("Helvetica", 16))
        self.progress_label.pack(pady=20)

    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Memory Dump Files", "*.raw *.dmp *.mem"), ("All Files", "*.*")])
        if file_path:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, file_path)

    def run_analysis(self):
        memory_file = self.file_entry.get()
        if not memory_file:
            messagebox.showerror("Error", "Please select a memory dump file.")
            return

        valid_paths, message = self.memory_analyzer.validate_paths()
        if not valid_paths:
            messagebox.showerror("Error", message)
            return

        self.progress_label.config(text="Loading...")

        threading.Thread(target=self.analyze_memory, args=(memory_file,)).start()

    def analyze_memory(self, memory_file):
        self.start_time = datetime.now()

        def update_progress(message):
            self.progress_label.config(text=message)
            self.update_idletasks()

        yara_loaded, message = self.memory_analyzer.load_yara_rules()
        if not yara_loaded:
            self.show_error(message)
            return

        processes = self.memory_analyzer.get_processes(memory_file, update_progress)
        processes = self.memory_analyzer.scan_dlls(memory_file, processes, update_progress)
        suspicious = self.memory_analyzer.detect_suspicious(processes, update_progress)
        yara_matches = self.memory_analyzer.scan_memory(memory_file, processes, os.path.dirname(memory_file), update_progress)

        report_path = self.get_next_report_filename()
        self.memory_analyzer.generate_report({
            "memory_file": memory_file,
            "processes": processes,
            "suspicious": suspicious,
            "yara_matches": yara_matches,
            "run_time": str(datetime.now() - self.start_time)
        }, report_path, update_progress, report_type="txt")

        self.show_result(f"Analysis complete! Report saved to {report_path}", report_path)

    def show_error(self, message):
        self.progress_label.config(text="")
        messagebox.showerror("Error", message)

    def show_result(self, message, report_path):
        self.progress_label.config(text="")
        if self.result_text is None:
            self.result_text = tk.Text(self, height=20, width=90)
            self.result_text.pack(pady=20)
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, message + "\n\n")

        with open(report_path, "r") as report_file:
            report_content = report_file.read()
            self.result_text.insert(tk.END, report_content)

    def get_next_report_filename(self, base_dir="analysis", prefix="analysisReport_", ext=".txt"):
        os.makedirs(base_dir, exist_ok=True)
        existing = [f for f in os.listdir(base_dir) if f.startswith(prefix) and f.endswith(ext)]
        numbers = [
            int(f[len(prefix):-len(ext)])
            for f in existing
            if f[len(prefix):-len(ext)].isdigit()
        ]
        next_num = max(numbers) + 1 if numbers else 1
        return os.path.join(base_dir, f"{prefix}{next_num:03}{ext}")

if __name__ == "__main__":
    app = MemoryAnalyzerGUI()
    app.mainloop()