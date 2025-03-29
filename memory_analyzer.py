import os
import yara
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
import pefile
import hashlib

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
        """Load YARA rules for malware detection"""
        try:
            self.yara_rules = yara.compile(rules_path)
            self.report_data['yara_rules_loaded'] = True
        except Exception as e:
            print(f"Error loading YARA rules: {e}")
            self.report_data['yara_rules_loaded'] = False

    def extract_processes(self):
        """
        Simulate process extraction from memory dump
        In a real implementation, this would use Volatility or parse memory structures directly
        """
        # This is mock data - replace with actual memory parsing code
        mock_processes = [
            {'pid': 100, 'name': 'explorer.exe', 'path': 'C:\\Windows\\explorer.exe', 
             'parent_pid': 80, 'start_time': '2023-01-01 08:00:00', 'user': 'SYSTEM'},
            {'pid': 200, 'name': 'chrome.exe', 'path': 'C:\\Program Files\\Google\\Chrome\\chrome.exe', 
             'parent_pid': 100, 'start_time': '2023-01-01 08:05:00', 'user': 'Alice'},
            {'pid': 300, 'name': 'svchost.exe', 'path': 'C:\\Windows\\System32\\svchost.exe', 
             'parent_pid': 80, 'start_time': '2023-01-01 07:59:00', 'user': 'SYSTEM'},
            {'pid': 444, 'name': 'mimikatz.exe', 'path': 'C:\\Temp\\mimikatz.exe', 
             'parent_pid': 200, 'start_time': '2023-01-01 08:30:00', 'user': 'Alice'},
            {'pid': 500, 'name': 'lsass.exe', 'path': 'C:\\Windows\\System32\\lsass.exe', 
             'parent_pid': 80, 'start_time': '2023-01-01 07:58:00', 'user': 'SYSTEM'},
        ]
        
        self.processes = mock_processes
        self.report_data['process_count'] = len(self.processes)
        return self.processes

    def detect_suspicious_processes(self):
        """Identify potentially malicious processes based on heuristics"""
        suspicious = []
        
        for process in self.processes:
            flags = []
            
            # Check for processes in temporary directories
            if 'temp' in process['path'].lower():
                flags.append('Runs from temp directory')
                
            # Check for processes with mismatched names/paths
            if process['name'].lower() != os.path.basename(process['path']).lower():
                flags.append('Name/path mismatch')
                
            # Check for known suspicious process names
            suspicious_names = ['mimikatz', 'cobaltstrike', 'metasploit', 'netwire']
            if any(name in process['name'].lower() for name in suspicious_names):
                flags.append('Known malicious process name')
                
            # Check for unusual parent-child relationships
            if process['parent_pid'] == 200 and process['pid'] == 444:  # Chrome spawning mimikatz
                flags.append('Unusual parent process')
                
            if flags:
                suspicious.append({
                    'process': process,
                    'flags': flags,
                    'type': 'suspicious_process'
                })
                
        self.suspicious_items.extend(suspicious)
        return suspicious

    def scan_for_malware(self):
        """Scan processes using YARA rules"""
        if not self.yara_rules:
            print("YARA rules not loaded")
            return []
            
        malicious = []
        
        # In a real implementation, we would scan process memory regions
        # Here we'll simulate scanning the process executable files
        
        for process in self.processes:
            try:
                # Simulate scanning the process executable
                matches = self.yara_rules.match(process['path'])
                if matches:
                    malicious.append({
                        'process': process,
                        'matches': [str(m) for m in matches],
                        'type': 'malware_signature'
                    })
            except Exception as e:
                print(f"Error scanning {process['name']}: {e}")
                
        self.suspicious_items.extend(malicious)
        return malicious

    def analyze_process_memory(self):
        """Analyze process memory for injections (simplified example)"""
        injections = []
        
        # In a real tool, we would examine memory regions for each process
        # Here's a simplified check for demonstration
        
        for process in self.processes:
            if process['pid'] == 500:  # lsass.exe
                injections.append({
                    'process': process,
                    'findings': 'Potential credential dumping activity detected',
                    'type': 'memory_injection'
                })
                
        self.suspicious_items.extend(injections)
        return injections

    def generate_report(self):
        """Generate a comprehensive report of findings"""
        if not self.suspicious_items:
            self.report_data['conclusion'] = "No suspicious activity detected"
        else:
            self.report_data['conclusion'] = f"{len(self.suspicious_items)} suspicious items found"
            self.report_data['findings'] = self.suspicious_items
            
        return self.report_data

    def visualize_process_tree(self):
        """Create a visualization of the process tree"""
        df = pd.DataFrame(self.processes)
        
        # Create a parent-child relationship graph
        plt.figure(figsize=(10, 6))
        for _, process in df.iterrows():
            plt.scatter(process['parent_pid'], process['pid'], label=process['name'])
            plt.text(process['parent_pid'], process['pid'], process['name'], fontsize=8)
            
        plt.title("Process Tree Visualization")
        plt.xlabel("Parent PID")
        plt.ylabel("PID")
        plt.grid(True)
        plt.tight_layout()
        
        # Save the visualization
        image_path = "process_tree.png"
        plt.savefig(image_path)
        plt.close()
        
        return image_path

if __name__ == "__main__":
    # Example usage
    analyzer = MemoryAnalyzer("memory.dmp")
    
    # Load YARA rules (provide path to your rules file)
    analyzer.load_yara_rules("malware_rules.yar")
    
    # Perform analysis
    analyzer.extract_processes()
    analyzer.detect_suspicious_processes()
    analyzer.scan_for_malware()
    analyzer.analyze_process_memory()
    
    # Generate results
    report = analyzer.generate_report()
    image_path = analyzer.visualize_process_tree()
    
    # Print summary
    print("\n=== Analysis Report ===")
    print(f"Analyzed file: {report['filename']}")
    print(f"Analysis time: {report['analysis_time']}")
    print(f"Processes found: {report['process_count']}")
    print(f"Conclusion: {report['conclusion']}")
    
    if report['findings']:
        print("\n=== Findings ===")
        for finding in report['findings']:
            print(f"\nType: {finding['type']}")
            print(f"Process: {finding['process']['name']} (PID: {finding['process']['pid']})")
            
            if 'flags' in finding:
                print("Flags:")
                for flag in finding['flags']:
                    print(f" - {flag}")
                    
            if 'matches' in finding:
                print("YARA Matches:")
                for match in finding['matches']:
                    print(f" - {match}")
                    
            if 'findings' in finding:
                print(f"Details: {finding['findings']}")
    
    print(f"\nProcess tree visualization saved to {image_path}")