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
from datetime import datetime
import pefile
import hashlib

class MemoryAnalyzer:
    """
    Main analyzer class that handles memory forensic analysis.
    
    Attributes:
        memory_dump (str): Path to the memory dump file
        processes (list): Extracted process information
        suspicious_items (list): Detected suspicious items
        yara_rules (yara.Rules): Compiled YARA rules for scanning
        report_data (dict): Analysis results and metadata
    """
    
    def __init__(self, memory_dump_path):
        """
        Initialize the memory analyzer with a memory dump file.
        
        Args:
            memory_dump_path (str): Path to the memory dump file
        """
        self.memory_dump = memory_dump_path
        self.processes = []          # Stores extracted process information
        self.suspicious_items = []   # Stores detected anomalies
        self.yara_rules = None       # Will hold compiled YARA rules
        self.report_data = {         # Report structure
            'analysis_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'filename': os.path.basename(memory_dump_path),
            'findings': []
        }

    def load_yara_rules(self, rules_path):
        """
        Load and compile YARA rules from specified file.
        
        Args:
            rules_path (str): Path to YARA rules file
            
        Returns:
            bool: True if rules loaded successfully, False otherwise
        """
        try:
            self.yara_rules = yara.compile(rules_path)
            self.report_data['yara_rules_loaded'] = True
            return True
        except Exception as e:
            print(f"[!] Error loading YARA rules: {e}")
            self.report_data['yara_rules_loaded'] = False
            return False

    def extract_processes(self):
        """
        Extract process information from memory dump.
        
        Note: This implementation uses mock data. In a real tool, this would:
              - Parse memory structures directly OR
              - Use Volatility framework's API
              
        Returns:
            list: Process information dictionaries
        """
        # Mock data - replace with actual memory parsing in production
        mock_processes = [
            {'pid': 100, 'name': 'explorer.exe', 'path': 'C:\\Windows\\explorer.exe', 
             'parent_pid': 80, 'start_time': '2023-01-01 08:00:00', 'user': 'SYSTEM',
             'dlls': ['kernel32.dll', 'user32.dll']},
             
            {'pid': 200, 'name': 'chrome.exe', 'path': 'C:\\Program Files\\Google\\Chrome\\chrome.exe', 
             'parent_pid': 100, 'start_time': '2023-01-01 08:05:00', 'user': 'Alice',
             'dlls': ['kernel32.dll', 'chrome_elf.dll']},
             
            {'pid': 300, 'name': 'svchost.exe', 'path': 'C:\\Windows\\System32\\svchost.exe', 
             'parent_pid': 80, 'start_time': '2023-01-01 07:59:00', 'user': 'SYSTEM',
             'dlls': ['kernel32.dll', 'advapi32.dll']},
             
            {'pid': 444, 'name': 'mimikatz.exe', 'path': 'C:\\Temp\\mimikatz.exe', 
             'parent_pid': 200, 'start_time': '2023-01-01 08:30:00', 'user': 'Alice',
             'dlls': ['kernel32.dll', 'winscard.dll']},
             
            {'pid': 500, 'name': 'lsass.exe', 'path': 'C:\\Windows\\System32\\lsass.exe', 
             'parent_pid': 80, 'start_time': '2023-01-01 07:58:00', 'user': 'SYSTEM',
             'dlls': ['kernel32.dll', 'samsrv.dll']},
        ]
        
        self.processes = mock_processes
        self.report_data['process_count'] = len(self.processes)
        return self.processes

    def detect_suspicious_processes(self):
        """
        Detect potentially malicious processes using heuristics.
        
        Checks for:
        - Processes in temporary directories
        - Name/path mismatches
        - Known suspicious names
        - Unusual parent-child relationships
        
        Returns:
            list: Detected suspicious processes with flags
        """
        suspicious = []
        
        for process in self.processes:
            flags = []
            
            # Heuristic 1: Check for temporary execution locations
            temp_paths = ['temp', 'tmp', 'appdata', 'local\\temp']
            if any(path in process['path'].lower() for path in temp_paths):
                flags.append('Runs from temporary location')
                
            # Heuristic 2: Check for name/path mismatches
            if process['name'].lower() != os.path.basename(process['path']).lower():
                flags.append('Name/path mismatch')
                
            # Heuristic 3: Known suspicious process names
            suspicious_names = ['mimikatz', 'cobaltstrike', 'metasploit', 
                              'netwire', 'empire', 'powersploit']
            if any(name in process['name'].lower() for name in suspicious_names):
                flags.append('Known malicious process name')
                
            # Heuristic 4: Unusual parent-child relationships
            if (process['parent_pid'] == 200 and process['pid'] == 444):  # Chrome spawning mimikatz
                flags.append('Unusual parent process')
                
            # Heuristic 5: Checking loaded DLLs
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
        """
        Scan processes using loaded YARA rules.
        
        Note: This is a simulation for classroom use. In production:
              - Would scan actual process memory regions
              - Would handle large memory scans efficiently
              
        Returns:
            list: Processes with YARA rule matches
        """
        if not self.yara_rules:
            print("[!] YARA rules not loaded - skipping malware scan")
            return []
            
        malicious = []
        
        # Simulate scanning without actual file access
        for process in self.processes:
            # Simulation: Flag mimikatz.exe as malicious
            if "mimikatz" in process['name'].lower():
                malicious.append({
                    'process': process,
                    'matches': ["malware_signature:mimikatz"],
                    'type': 'malware_signature'
                })
                
            # Simulation: Flag processes with "inject" in name
            elif "inject" in process['name'].lower():
                malicious.append({
                    'process': process,
                    'matches': ["suspicious_name:inject"],
                    'type': 'malware_signature'
                })
                
        self.suspicious_items.extend(malicious)
        return malicious

    def analyze_process_memory(self):
        """
        Analyze process memory for potential injections.
        
        Checks for:
        - Unusual memory allocations
        - Credential dumping patterns
        - Code injection artifacts
        
        Returns:
            list: Processes with memory anomalies
        """
        injections = []
        
        # Simulation: Flag lsass.exe as potentially compromised
        for process in self.processes:
            if process['pid'] == 500:  # lsass.exe
                injections.append({
                    'process': process,
                    'findings': 'Potential credential dumping activity detected',
                    'type': 'memory_injection'
                })
                
            # Simulation: Flag processes with unusual DLLs
            if 'unknown.dll' in [d.lower() for d in process['dlls']]:
                injections.append({
                    'process': process,
                    'findings': 'Unknown DLL loaded into process',
                    'type': 'dll_injection'
                })
                
        self.suspicious_items.extend(injections)
        return injections

    def generate_report(self):
        """
        Generate comprehensive analysis report.
        
        Returns:
            dict: Structured report containing:
                  - Metadata (time, filename)
                  - Process statistics
                  - Findings (suspicious items)
                  - Conclusion
        """
        if not self.suspicious_items:
            self.report_data['conclusion'] = "No suspicious activity detected"
        else:
            self.report_data['conclusion'] = f"{len(self.suspicious_items)} suspicious items found"
            self.report_data['findings'] = self.suspicious_items
            
        return self.report_data

    def visualize_process_tree(self):
        """
        Create visualization of process relationships.
        
        Returns:
            str: Path to the generated image file
        """
        try:
            df = pd.DataFrame(self.processes)
            
            plt.figure(figsize=(12, 8))
            
            # Create scatter plot of parent vs child PIDs
            for _, process in df.iterrows():
                plt.scatter(process['parent_pid'], process['pid'], 
                          label=process['name'], s=100)
                plt.text(process['parent_pid'], process['pid'], 
                        f"{process['name']}\nPID: {process['pid']}", 
                        fontsize=8, ha='center', va='bottom')
                
            # Highlight suspicious processes in red
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
    """
    Main execution block for command-line operation.
    """
    print("""
    Memory Forensic Tool - Group 2
    -----------------------------
    """)
    
    # Initialize analyzer with memory dump
    analyzer = MemoryAnalyzer("memory.dmp")
    
    # Load YARA rules
    if not analyzer.load_yara_rules("malware_rules.yar"):
        print("[!] Continuing without YARA rules")
    
    # Perform analysis steps
    print("[*] Extracting processes...")
    analyzer.extract_processes()
    
    print("[*] Detecting suspicious processes...")
    analyzer.detect_suspicious_processes()
    
    print("[*] Scanning for malware signatures...")
    analyzer.scan_for_malware()
    
    print("[*] Analyzing process memory...")
    analyzer.analyze_process_memory()
    
    # Generate results
    print("[*] Generating report...")
    report = analyzer.generate_report()
    
    print("[*] Creating visualization...")
    image_path = analyzer.visualize_process_tree()
    
    # Print summary report
    print("\n=== Analysis Report ===")
    print(f"Analyzed file: {report['filename']}")
    print(f"Analysis time: {report['analysis_time']}")
    print(f"Processes found: {report['process_count']}")
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
                    
            if 'findings' in finding:
                print(f"Technical Details: {finding['findings']}")
    
    if image_path:
        print(f"\nProcess tree visualization saved to {image_path}")
    
    print("\nAnalysis complete.")