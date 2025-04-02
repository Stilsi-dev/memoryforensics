import os
import tkinter as tk
from tkinter import filedialog, messagebox
from datetime import datetime
import subprocess
import yara
import shutil
import csv

# Configuration
VOLATILITY_PATH = "volatility3/vol.exe"
YARA_RULES_FILE = "malware_rules.yar"
SUSPICIOUS_PATHS = ["\\temp\\", "\\appdata\\", "\\programdata\\"]

class MemoryAnalyzer:
    def __init__(self, volatility_path=VOLATILITY_PATH):
        self.volatility_path = volatility_path
        self.yara_rules = None

    def validate_paths(self):
        required = [(self.volatility_path, "Volatility"), (YARA_RULES_FILE, "YARA rules")]
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
        cmd = ["python", self.volatility_path, "-f", os.path.normpath(memory_file), f"windows.{plugin}"]
        if extra_args:
            cmd += extra_args
        try:
            result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            return f"Volatility command failed: {' '.join(cmd)}\nError: {e.stderr}"

    def get_processes(self, memory_file):
        pslist_output = self.run_volatility("pslist", memory_file)
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
                procs.append({"PID": parts[0], "PPID": parts[1], "ImageFileName": parts[2], "Parent": "Unknown"})
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
        for p in processes:
            pid = p["PID"]
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
        matches = []
        for p in processes[:limit]:
            pid = p.get("PID")
            if not pid:
                continue
            try:
                cmd = ["python", self.volatility_path, "-f", memory_file, "windows.memmap", "--pid", str(pid), "--dump"]
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
                    os.remove(dest_path)
            except Exception as e:
                continue
        return matches

    def generate_report(self, data):
        report = "MEMORY FORENSIC ANALYSIS REPORT\n" + "="*60 + "\n\n"
        report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"Analyzed: {os.path.basename(data.get('memory_file', 'Unknown'))}\n\n"
        report += "SUMMARY\n" + "="*60 + "\n"
        report += f"Total Processes: {len(data.get('processes', []))}\n"
        report += f"Suspicious Processes: {len(data.get('suspicious', []))}\n"
        report += f"Processes with YARA Matches: {len(data.get('yara_matches', []))}\n\n"
        report += "SUSPICIOUS PROCESSES\n" + "="*60 + "\n"
        if data.get("suspicious"):
            for p in data["suspicious"]:
                report += f"PID: {p['PID']:>6} | Process: {p['ImageFileName']:<30} | Flags: {p['Flags']}\n"
        else:
            report += "No suspicious processes detected\n"
        report += "\nYARA RULE MATCHES\n" + "="*60 + "\n"
        if data.get("yara_matches"):
            for p in data["yara_matches"]:
                report += f"PID: {p['PID']:>6} | Process: {p['ImageFileName']:<30} | Matches: {', '.join(p['YARA_Matches'])}\n"
        else:
            report += "No YARA rule matches found\n"
        report += "\nPROCESS LIST\n" + "="*60 + "\n"
        for p in data.get("processes", []):
            hidden_str = " (Hidden)" if p.get("Hidden") == "Yes" else ""
            report += f"PID: {p['PID']:>6} | Process: {p['ImageFileName']:<30} | Parent: {p['Parent']}{hidden_str}\n"
        return report

class MemoryAnalyzerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Memory Forensic Analyzer")
        self.geometry("800x600")

        self.memory_analyzer = MemoryAnalyzer()

        self.create_widgets()

    def create_widgets(self):
        self.file_label = tk.Label(self, text="Select Memory Dump File:")
        self.file_label.pack(pady=10)

        self.file_entry = tk.Entry(self, width=50)
        self.file_entry.pack(pady=5)

        self.browse_button = tk.Button(self, text="Browse", command=self.browse_file)
        self.browse_button.pack(pady=5)

        self.run_button = tk.Button(self, text="Run Analysis", command=self.run_analysis)
        self.run_button.pack(pady=10)

        self.result_text = tk.Text(self, height=20, width=90)
        self.result_text.pack(pady=20)

    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Memory Dump Files", "*.raw *.dmp"), ("All Files", "*.*")])
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

        yara_loaded, message = self.memory_analyzer.load_yara_rules()
        if not yara_loaded:
            messagebox.showerror("Error", message)
            return

        processes = self.memory_analyzer.get_processes(memory_file)
        if not processes:
            messagebox.showerror("Error", "Failed to extract process information.")
            return

        processes = self.memory_analyzer.scan_dlls(memory_file, processes)
        suspicious = self.memory_analyzer.detect_suspicious(processes)
        yara_matches = self.memory_analyzer.scan_memory(memory_file, processes, os.path.dirname(memory_file), limit=10)

        report = self.memory_analyzer.generate_report({
            "memory_file": memory_file,
            "processes": processes,
            "suspicious": suspicious,
            "yara_matches": yara_matches
        })

        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, report)

if __name__ == "__main__":
    app = MemoryAnalyzerGUI()
    app.mainloop()