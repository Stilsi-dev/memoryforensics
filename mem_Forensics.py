#!/usr/bin/env python3
import volatility3.framework
from volatility3.framework import automagic, interfaces, plugins
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.windows import pslist, dlllist, malfind
import yara
import os
import json
from typing import List, Dict, Tuple, Any

class RAMAnalyzer:
    def __init__(self, memory_dump: str):
        """Initialize the memory analyzer with a memory dump file"""
        self.memory_dump = memory_dump
        self.context = volatility3.framework.interfaces.context.Context()
        self.config = self._setup_volatility()
        self.yara_rules = self._load_yara_rules()
        
    def _setup_volatility(self) -> interfaces.configuration.HierarchicalDict:
        """Configure Volatility framework"""
        config = volatility3.framework.configuration.requirements.HierarchicalDict()
        
        # Automagically determine the OS and load appropriate symbols
        automagics = automagic.choose_automagic(automagic.available(self.context))
        for amagic in automagics:
            if isinstance(amagic, automagic.RequirementInterface):
                amagic(self.context)
        
        # Set the location of the memory dump
        config['location'] = f"file://{os.path.abspath(self.memory_dump)}"
        
        return config
    
    def _load_yara_rules(self, rules_dir: str = "yara_rules") -> yara.Rules:
        """Load YARA rules from directory"""
        rule_files = [f for f in os.listdir(rules_dir) if f.endswith('.yar') or f.endswith('.yara')]
        combined_rules = ""
        
        for rule_file in rule_files:
            with open(os.path.join(rules_dir, rule_file), 'r') as f:
                combined_rules += f.read() + "\n"
        
        return yara.compile(source=combined_rules)
    
    def get_process_list(self) -> List[Dict]:
        """Extract running processes with metadata"""
        plugin = pslist.PsList(self.context, self.config)
        processes = []
        
        for process in plugin._generator():
            process_name = utility.array_to_string(process.ImageFileName)
            processes.append({
                "pid": int(process.UniqueProcessId),
                "ppid": int(process.InheritedFromUniqueProcessId),
                "name": process_name,
                "create_time": str(process.get_create_time()),
                "exit_time": str(process.get_exit_time()) if process.get_exit_time() else "N/A",
                "session_id": int(process.SessionId),
                "threads": int(process.ActiveThreads),
                "handles": int(process.ObjectTable.HandleCount if process.ObjectTable else 0)
            })
        
        return processes
    
    def get_loaded_dlls(self, pid: int = None) -> Dict[int, List[Dict]]:
        """Get DLLs loaded by processes"""
        plugin = dlllist.DllList(self.context, self.config)
        result = {}
        
        for process in plugin._generator():
            current_pid = int(process.UniqueProcessId)
            if pid and current_pid != pid:
                continue
                
            process_name = utility.array_to_string(process.ImageFileName)
            dlls = []
            
            for entry in process.load_order_modules():
                dlls.append({
                    "name": utility.array_to_string(entry.BaseDllName),
                    "path": utility.array_to_string(entry.FullDllName),
                    "base_address": hex(entry.DllBase),
                    "size": hex(entry.SizeOfImage),
                    "load_count": int(entry.LoadCount)
                })
            
            result[current_pid] = {
                "process_name": process_name,
                "dlls": dlls
            }
        
        return result
    
    def detect_injections(self) -> List[Dict]:
        """Detect potential code injections"""
        plugin = malfind.Malfind(self.context, self.config)
        injections = []
        
        for process in plugin._generator():
            process_name = utility.array_to_string(process.ImageFileName)
            pid = int(process.UniqueProcessId)
            
            for vad, address_space in plugin._get_vads(process):
                if plugin._is_vad_empty(vad, address_space):
                    continue
                
                if plugin._is_executable(vad) and plugin._is_protected(vad):
                    injections.append({
                        "pid": pid,
                        "process_name": process_name,
                        "vad_start": hex(vad.get_start()),
                        "vad_end": hex(vad.get_end()),
                        "protection": vad.get_protection(
                            vad.get_available_protections(process)),
                        "flags": vad.get_flags()
                    })
        
        return injections
    
    def scan_for_malware(self) -> Dict[int, List[Dict]]:
        """Scan process memory with YARA rules"""
        results = {}
        
        # Get process memory ranges
        plugin = malfind.Malfind(self.context, self.config)
        
        for process in plugin._generator():
            pid = int(process.UniqueProcessId)
            process_name = utility.array_to_string(process.ImageFileName)
            results[pid] = {
                "process_name": process_name,
                "matches": []
            }
            
            # Get all memory regions
            for vad, address_space in plugin._get_vads(process):
                if plugin._is_vad_empty(vad, address_space):
                    continue
                
                # Read memory
                data = address_space.read(vad.get_start(), vad.get_end() - vad.get_start())
                if not data:
                    continue
                
                # Scan with YARA
                try:
                    matches = self.yara_rules.match(data=data)
                    if matches:
                        results[pid]["matches"].append({
                            "vad_start": hex(vad.get_start()),
                            "vad_end": hex(vad.get_end()),
                            "matches": [str(m) for m in matches]
                        })
                except Exception as e:
                    continue
        
        return results
    
    def analyze(self) -> Dict[str, Any]:
        """Run complete analysis"""
        return {
            "processes": self.get_process_list(),
            "loaded_dlls": self.get_loaded_dlls(),
            "injections": self.detect_injections(),
            "malware_scan": self.scan_for_malware()
        }

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Memory Forensic Analysis Tool")
    parser.add_argument("memory_dump", help="Path to memory dump file")
    parser.add_argument("-o", "--output", help="Output file (JSON format)")
    args = parser.parse_args()
    
    analyzer = RAMAnalyzer(args.memory_dump)
    results = analyzer.analyze()
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results saved to {args.output}")
    else:
        print(json.dumps(results, indent=2))