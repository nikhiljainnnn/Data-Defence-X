"""
DataDefenceX - YARA Signature Scanner
Scans memory regions and processes using YARA rules
"""

import yara
import os
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime


@dataclass
class YARAMatch:
    """Represents a YARA rule match"""
    rule_name: str
    rule_namespace: str
    strings: List[Dict]  # Matched strings with offsets
    tags: List[str]
    metadata: Dict
    severity: str  # "critical", "high", "medium", "low"
    description: str


class YARAScanner:
    """
    YARA signature scanner for memory and process analysis
    """
    
    def __init__(self, rules_dir: str = "rules/yara"):
        """
        Initialize YARA scanner
        
        Args:
            rules_dir: Directory containing YARA rule files (.yar)
        """
        self.rules_dir = rules_dir
        self.rules = None
        self.compiled_rules = None
        self.rule_count = 0
        
        # Load and compile rules
        self._load_rules()
    
    def _load_rules(self):
        """Load and compile YARA rules from directory"""
        try:
            if not os.path.exists(self.rules_dir):
                print(f"[!] YARA rules directory not found: {self.rules_dir}")
                print(f"[*] Creating directory and sample rules...")
                os.makedirs(self.rules_dir, exist_ok=True)
                self._create_sample_rules()
            
            # Find all .yar and .yara files
            rule_files = []
            for file in os.listdir(self.rules_dir):
                if file.endswith(('.yar', '.yara')):
                    rule_files.append(os.path.join(self.rules_dir, file))
            
            if not rule_files:
                print(f"[!] No YARA rule files found in {self.rules_dir}")
                print(f"[*] Creating sample rules...")
                self._create_sample_rules()
                rule_files = [
                    os.path.join(self.rules_dir, f) 
                    for f in os.listdir(self.rules_dir) 
                    if f.endswith(('.yar', '.yara'))
                ]
            
            # Compile rules
            try:
                self.compiled_rules = yara.compile(filepaths={
                    f'rule_{i}': path for i, path in enumerate(rule_files)
                })
                self.rule_count = len(rule_files)
                print(f"[*] Loaded {self.rule_count} YARA rule file(s)")
            except yara.SyntaxError as e:
                print(f"[!] YARA syntax error: {e}")
                self.compiled_rules = None
            except Exception as e:
                print(f"[!] Error compiling YARA rules: {e}")
                self.compiled_rules = None
        
        except Exception as e:
            print(f"[!] Error loading YARA rules: {e}")
            self.compiled_rules = None
    
    def _create_sample_rules(self):
        """Create sample YARA rules for fileless malware detection"""
        sample_rules = {
            'fileless_powershell.yar': '''
rule Fileless_PowerShell_EncodedCommand
{
    meta:
        description = "Detects PowerShell with encoded commands (common in fileless attacks)"
        severity = "high"
        author = "DataDefenceX"
        date = "2025-01-01"
    
    strings:
        $ps1 = "powershell" nocase
        $encoded = "-encodedcommand" nocase
        $base64 = /[A-Za-z0-9+\/]{100,}={0,2}/
        $bypass = "-executionpolicy" nocase
        $hidden = "-windowstyle hidden" nocase
    
    condition:
        $ps1 and ($encoded or ($bypass and $hidden)) or ($ps1 and $base64)
}
''',
            'fileless_wmi.yar': '''
rule Fileless_WMI_Execution
{
    meta:
        description = "Detects WMI-based fileless malware execution"
        severity = "high"
        author = "DataDefenceX"
    
    strings:
        $wmi1 = "wmic" nocase
        $wmi2 = "winmgmts" nocase
        $process = "process call create" nocase
        $cmd = "cmd.exe /c" nocase
    
    condition:
        ($wmi1 or $wmi2) and $process and $cmd
}
''',
            'fileless_rundll32.yar': '''
rule Fileless_Rundll32_Suspicious
{
    meta:
        description = "Detects suspicious Rundll32 usage (common LOLBin for fileless)"
        severity = "medium"
        author = "DataDefenceX"
    
    strings:
        $rundll = "rundll32" nocase
        $suspicious1 = "javascript:" nocase
        $suspicious2 = "vbscript:" nocase
        $suspicious3 = "data:text/html" nocase
        $temp = /[Tt]emp/
    
    condition:
        $rundll and ($suspicious1 or $suspicious2 or $suspicious3 or $temp)
}
''',
            'fileless_memory_injection.yar': '''
rule Memory_Injection_Indicators
{
    meta:
        description = "Detects memory injection techniques"
        severity = "critical"
        author = "DataDefenceX"
    
    strings:
        $virtualalloc = "VirtualAlloc" nocase
        $virtualprotect = "VirtualProtect" nocase
        $writeprocessmemory = "WriteProcessMemory" nocase
        $createremotethread = "CreateRemoteThread" nocase
        $ntunmapviewofsection = "NtUnmapViewOfSection" nocase
        $shellcode1 = /\\x90{10,}/  // NOP sled
        $shellcode2 = /\\xEB\\xFE/  // Infinite loop
    
    condition:
        (2 of ($virtualalloc, $virtualprotect, $writeprocessmemory, $createremotethread)) or
        ($ntunmapviewofsection and $virtualalloc) or
        ($shellcode1 or $shellcode2)
}
''',
            'fileless_cobaltstrike.yar': '''
rule CobaltStrike_Beacon
{
    meta:
        description = "Detects Cobalt Strike beacon indicators"
        severity = "critical"
        author = "DataDefenceX"
    
    strings:
        $beacon1 = "beacon.dll" nocase
        $beacon2 = "ReflectiveLoader" nocase
        $beacon3 = "beacon.x64.dll" nocase
        $malleable = "Malleable C2" nocase
        $sleep_mask = "sleep_mask" nocase
    
    condition:
        2 of them
}
''',
            'fileless_metasploit.yar': '''
rule Metasploit_Payload
{
    meta:
        description = "Detects Metasploit payload indicators"
        severity = "high"
        author = "DataDefenceX"
    
    strings:
        $msf1 = "meterpreter" nocase
        $msf2 = "metsrv" nocase
        $msf3 = "stdapi" nocase
        $msf4 = "priv" nocase
    
    condition:
        2 of them
}
''',
            'fileless_obfuscation.yar': '''
rule Obfuscated_Code_Indicators
{
    meta:
        description = "Detects code obfuscation techniques"
        severity = "medium"
        author = "DataDefenceX"
    
    strings:
        $base64_large = /[A-Za-z0-9+\/]{200,}={0,2}/
        $hex_encoded = /\\x[0-9A-Fa-f]{2,}/
        $xor_pattern = /XOR|xor/
        $rot13 = /ROT13|rot13/
        $eval = "eval(" nocase
        $exec = "exec(" nocase
    
    condition:
        ($base64_large and ($eval or $exec)) or
        (3 of ($hex_encoded, $xor_pattern, $rot13, $eval, $exec))
}
'''
        }
        
        for filename, content in sample_rules.items():
            filepath = os.path.join(self.rules_dir, filename)
            with open(filepath, 'w') as f:
                f.write(content)
            print(f"    [*] Created sample rule: {filename}")
    
    def scan_memory_region(self, data: bytes, region_info: Optional[Dict] = None) -> List[YARAMatch]:
        """
        Scan a memory region with YARA rules
        
        Args:
            data: Memory data to scan
            region_info: Optional metadata about the memory region
        
        Returns:
            List of YARAMatch objects
        """
        matches = []
        
        if not self.compiled_rules:
            return matches
        
        if not data or len(data) < 10:  # Skip very small regions
            return matches
        
        try:
            # Scan with YARA
            yara_matches = self.compiled_rules.match(data=data, timeout=5)
            
            for match in yara_matches:
                # Extract severity from metadata
                severity = match.meta.get('severity', 'medium')
                description = match.meta.get('description', 'YARA rule match')
                
                yara_match = YARAMatch(
                    rule_name=match.rule,
                    rule_namespace=match.namespace,
                    strings=[{
                        'identifier': s.identifier,
                        'offset': s.instances[0].offset if s.instances else 0,
                        'matched_data': s.instances[0].matched_data[:100] if s.instances else ''
                    } for s in match.strings],
                    tags=list(match.tags),
                    metadata=match.meta,
                    severity=severity,
                    description=description
                )
                
                matches.append(yara_match)
        
        except yara.TimeoutError:
            print(f"[!] YARA scan timeout for region")
        except Exception as e:
            print(f"[!] YARA scan error: {e}")
        
        return matches
    
    def scan_process_memory(self, memory_regions: List[Dict]) -> List[YARAMatch]:
        """
        Scan multiple memory regions from a process
        
        Args:
            memory_regions: List of dicts with 'data' (bytes) and optional 'info'
        
        Returns:
            List of YARAMatch objects
        """
        all_matches = []
        
        for region in memory_regions:
            data = region.get('data')
            if data:
                matches = self.scan_memory_region(data, region.get('info'))
                all_matches.extend(matches)
        
        return all_matches
    
    def scan_command_line(self, cmdline: str) -> List[YARAMatch]:
        """
        Scan command line string with YARA rules
        
        Args:
            cmdline: Command line string to scan
        
        Returns:
            List of YARAMatch objects
        """
        if not cmdline:
            return []
        
        return self.scan_memory_region(cmdline.encode('utf-8', errors='ignore'))
    
    def get_rule_statistics(self) -> Dict:
        """Get statistics about loaded rules"""
        return {
            'rule_count': self.rule_count,
            'rules_dir': self.rules_dir,
            'loaded': self.compiled_rules is not None
        }
    
    def reload_rules(self):
        """Reload YARA rules (useful for updating rules without restart)"""
        print("[*] Reloading YARA rules...")
        self._load_rules()


def test_yara_scanner():
    """Test the YARA scanner"""
    print("\n=== DataDefenceX YARA Scanner Test ===\n")
    
    scanner = YARAScanner()
    
    # Test 1: Scan suspicious PowerShell command
    print("[*] Test 1: Scanning suspicious PowerShell command")
    suspicious_cmd = "powershell -encodedcommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA=="
    matches = scanner.scan_command_line(suspicious_cmd)
    
    if matches:
        print(f"    [!] Found {len(matches)} YARA match(es):")
        for match in matches:
            print(f"        - {match.rule_name} ({match.severity}): {match.description}")
    else:
        print("    [*] No matches")
    
    # Test 2: Scan memory region with shellcode
    print("\n[*] Test 2: Scanning memory region with shellcode indicators")
    shellcode_data = b"VirtualAlloc\x00WriteProcessMemory\x00CreateRemoteThread\x00" + b"\x90" * 20
    matches = scanner.scan_memory_region(shellcode_data)
    
    if matches:
        print(f"    [!] Found {len(matches)} YARA match(es):")
        for match in matches:
            print(f"        - {match.rule_name} ({match.severity}): {match.description}")
    else:
        print("    [*] No matches")
    
    # Test 3: Statistics
    print("\n[*] Test 3: Rule statistics")
    stats = scanner.get_rule_statistics()
    print(f"    Rules loaded: {stats['rule_count']}")
    print(f"    Rules directory: {stats['rules_dir']}")
    print(f"    Status: {'Loaded' if stats['loaded'] else 'Not loaded'}")


if __name__ == "__main__":
    test_yara_scanner()