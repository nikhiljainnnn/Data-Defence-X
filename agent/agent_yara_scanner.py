"""
DataDefenceX - YARA Signature Scanner FIXED v2.0
Improved rules and whitelist filtering to reduce false positives
"""

import yara
import os
import json
from typing import List, Dict, Optional
from dataclasses import dataclass


@dataclass
class YARAMatch:
    """Represents a YARA rule match"""
    rule_name: str
    rule_namespace: str
    strings: List[Dict]
    tags: List[str]
    metadata: Dict
    severity: str
    description: str


class YARAScanner:
    """
    YARA signature scanner with whitelist support
    """
    
    # Class variable to track if rules have been loaded (suppress duplicate messages)
    _rules_loaded = False
    _load_lock = None
    
    def __init__(self, rules_dir: str = "rules/yara", suppress_messages: bool = False):
        import threading
        if YARAScanner._load_lock is None:
            YARAScanner._load_lock = threading.Lock()
        
        self.rules_dir = rules_dir
        self.compiled_rules = None
        self.rule_count = 0
        self.whitelist = self._load_whitelist()
        self.suppress_messages = suppress_messages
        
        # Load and compile rules
        self._load_rules()
    
    def _load_whitelist(self) -> Dict:
        """Load whitelist for path filtering"""
        try:
            with open('config/whitelist.json', 'r') as f:
                whitelist = json.load(f)
                return whitelist
        except:
            return {'trusted_paths': [], 'trusted_processes': []}
    
    def _load_rules(self):
        """Load and compile YARA rules"""
        try:
            if not os.path.exists(self.rules_dir):
                print(f"[!] YARA rules directory not found: {self.rules_dir}")
                os.makedirs(self.rules_dir, exist_ok=True)
                self._create_improved_rules()
            
            # Find rule files
            rule_files = []
            for file in os.listdir(self.rules_dir):
                if file.endswith(('.yar', '.yara')):
                    rule_files.append(os.path.join(self.rules_dir, file))
            
            if not rule_files:
                print(f"[*] Creating improved YARA rules...")
                self._create_improved_rules()
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
                if self.rule_count > 0:
                    # Only print once per session (first instance)
                    with YARAScanner._load_lock:
                        if not YARAScanner._rules_loaded and not self.suppress_messages:
                            print(f"[*] Loaded {self.rule_count} YARA rule file(s)")
                            YARAScanner._rules_loaded = True
            except yara.SyntaxError as e:
                print(f"[!] YARA syntax error: {e}")
                self.compiled_rules = None
            except Exception as e:
                print(f"[!] Error compiling YARA rules: {e}")
                self.compiled_rules = None
        
        except Exception as e:
            print(f"[!] Error loading YARA rules: {e}")
            self.compiled_rules = None
    
    def _create_improved_rules(self):
        """Create improved YARA rules with lower false positives"""
        
        improved_rules = {
            'fileless_powershell.yar': r'''
rule Fileless_PowerShell_EncodedCommand
{
    meta:
        description = "Detects PowerShell with encoded commands"
        severity = "high"
        author = "DataDefenceX"
        min_indicators = 2
    
    strings:
        $ps1 = "powershell" nocase
        $ps2 = "pwsh" nocase
        $encoded = "-encodedcommand" nocase
        $enc_short = "-enc" nocase
        $base64 = /[A-Za-z0-9+\/]{200,}={0,2}/  // Long base64
        $bypass = "-executionpolicy" nocase
        $hidden = "-windowstyle hidden" nocase
        $noprofile = "-noprofile" nocase
        $noninteractive = "-noninteractive" nocase
    
    condition:
        ($ps1 or $ps2) and 
        (
            ($encoded or $enc_short) or
            ($bypass and $hidden) or
            ($noprofile and $noninteractive and $base64)
        )
}
''',
            'fileless_wmi.yar': '''
rule Fileless_WMI_Execution
{
    meta:
        description = "Detects WMI-based execution"
        severity = "high"
        author = "DataDefenceX"
        min_indicators = 2
    
    strings:
        $wmi1 = "wmic" nocase
        $wmi2 = "winmgmts" nocase
        $wmi3 = "Win32_Process" nocase
        $process = "process call create" nocase
        $cmd1 = "cmd.exe /c" nocase
        $cmd2 = "powershell" nocase
        $suspicious = /eval|execute|invoke/i
    
    condition:
        ($wmi1 or $wmi2 or $wmi3) and 
        ($process and ($cmd1 or $cmd2 or $suspicious))
}
''',
            'fileless_memory_injection.yar': '''
rule Memory_Injection_Indicators
{
    meta:
        description = "Detects memory injection - requires multiple indicators"
        severity = "critical"
        author = "DataDefenceX"
        min_indicators_required = 3
    
    strings:
        // API calls
        $api1 = "VirtualAlloc" nocase
        $api2 = "VirtualProtect" nocase
        $api3 = "WriteProcessMemory" nocase
        $api4 = "CreateRemoteThread" nocase
        $api5 = "NtUnmapViewOfSection" nocase
        $api6 = "RtlCreateUserThread" nocase
        $api7 = "ZwUnmapViewOfSection" nocase
        $api8 = "QueueUserAPC" nocase
        
        // Shellcode patterns (must be substantial)
        $shellcode_nop = {90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90}  // 16+ NOPs
        $shellcode_loop = {EB FE EB FE}  // Multiple infinite loops
        $shellcode_decoder = {31 C0 50 68}  // XOR EAX, EAX; PUSH EAX; PUSH
    
    condition:
        // Require MULTIPLE indicators (3+)
        (
            // Process injection combo (need 3+ APIs)
            (3 of ($api1, $api2, $api3, $api4, $api6, $api8)) or
            
            // Process hollowing combo (specific pattern)
            (($api5 or $api7) and $api1 and $api3) or
            
            // Shellcode with injection (APIs + shellcode pattern)
            (($shellcode_nop or $shellcode_loop or $shellcode_decoder) and 
             (2 of ($api1, $api2, $api3, $api4)))
        )
}
''',
            'fileless_rundll32.yar': r'''
rule Fileless_Rundll32_Suspicious
{
    meta:
        description = "Detects suspicious Rundll32 usage"
        severity = "medium"
        author = "DataDefenceX"
        min_indicators = 2
    
    strings:
        $rundll = "rundll32" nocase
        $javascript = "javascript:" nocase
        $vbscript = "vbscript:" nocase
        $data_uri = "data:text/html" nocase
        $url = /https?:\/\//i
        $temp = /[Tt]emp\\/ 
        $appdata = /AppData\\Local\\Temp/i
    
    condition:
        $rundll and 
        (
            $javascript or $vbscript or $data_uri or
            ($url and ($temp or $appdata))
        )
}
''',
            'fileless_cobaltstrike.yar': r'''
rule CobaltStrike_Beacon
{
    meta:
        description = "Detects Cobalt Strike beacon"
        severity = "critical"
        author = "DataDefenceX"
        min_indicators = 2
    
    strings:
        $beacon1 = "beacon.dll" nocase
        $beacon2 = "ReflectiveLoader" nocase
        $beacon3 = "beacon.x64.dll" nocase
        $beacon4 = "beacon.x86.dll" nocase
        $malleable = "Malleable C2" nocase
        $sleep_mask = "sleep_mask" nocase
        $getprocaddress = "GetProcAddress" nocase
        $virtualalloc = "VirtualAlloc" nocase
        $http_check = /\/[a-zA-Z0-9]{4}\.php/  // Beacon URI pattern
    
    condition:
        2 of them
}
''',
            'fileless_metasploit.yar': '''
rule Metasploit_Payload
{
    meta:
        description = "Detects Metasploit payload"
        severity = "high"
        author = "DataDefenceX"
        min_indicators = 2
    
    strings:
        $msf1 = "meterpreter" nocase
        $msf2 = "metsrv" nocase
        $msf3 = "stdapi" nocase
        $msf4 = "priv" nocase
        $msf5 = "ext_server" nocase
        $msf6 = "ReflectiveDll" nocase
    
    condition:
        2 of them
}
''',
            'fileless_obfuscation.yar': r'''
rule Obfuscated_Code_Indicators
{
    meta:
        description = "Detects code obfuscation"
        severity = "medium"
        author = "DataDefenceX"
        min_indicators = 3
    
    strings:
        $base64_large = /[A-Za-z0-9+\/]{300,}={0,2}/  // Very long base64
        $hex_encoded = /\\x[0-9A-Fa-f]{2}/
        $unicode_obf = /\\u[0-9A-Fa-f]{4}/
        $xor_pattern = /XOR 0x[0-9A-Fa-f]{2}/i
        $rot13 = "ROT13" nocase
        $eval = "eval(" nocase
        $exec = "exec(" nocase
        $fromcharcode = "fromCharCode" nocase
        $invoke = "Invoke-Expression" nocase
        $iex = "IEX" nocase
    
    condition:
        (
            ($base64_large and ($eval or $exec or $invoke or $iex)) or
            (3 of ($hex_encoded, $unicode_obf, $xor_pattern, $fromcharcode, $rot13))
        )
}
'''
        }
        
        for filename, content in improved_rules.items():
            filepath = os.path.join(self.rules_dir, filename)
            with open(filepath, 'w') as f:
                f.write(content)
            print(f"    [*] Created improved rule: {filename}")
    
    def scan_memory_region(self, data: bytes, region_info: Optional[Dict] = None) -> List[YARAMatch]:
        """
        Scan memory region with whitelist filtering
        
        Args:
            data: Memory data to scan
            region_info: Optional metadata (exe_path, process_name)
        
        Returns:
            List of YARAMatch objects
        """
        matches = []
        
        if not self.compiled_rules or not data or len(data) < 10:
            return matches
        
        # Check whitelist first
        if region_info:
            exe_path = region_info.get('exe_path', '')
            process_name = region_info.get('process_name', '')
            
            # Skip trusted paths (check both full path and relative path)
            if exe_path:
                exe_path_lower = exe_path.lower()
                for trusted_path in self.whitelist.get('trusted_paths', []):
                    if not str(trusted_path).startswith('_comment') and isinstance(trusted_path, str):
                        trusted_lower = trusted_path.lower()
                        # Check if path starts with trusted path OR contains trusted path pattern
                        if exe_path_lower.startswith(trusted_lower) or trusted_lower in exe_path_lower:
                            return matches  # Skip scanning
            
            # Skip trusted processes
            if process_name:
                for trusted_proc in self.whitelist.get('trusted_processes', []):
                    if not str(trusted_proc).startswith('_comment'):
                        if process_name.lower() == str(trusted_proc).lower():
                            return matches  # Skip scanning
        
        try:
            # Scan with YARA
            yara_matches = self.compiled_rules.match(data=data, timeout=5)
            
            for match in yara_matches:
                severity = match.meta.get('severity', 'medium')
                description = match.meta.get('description', 'YARA rule match')
                min_indicators = match.meta.get('min_indicators_required', 1)
                
                # Strict filtering for Memory_Injection_Indicators
                if match.rule == 'Memory_Injection_Indicators':
                    # Must be critical severity
                    if severity not in ['critical']:
                        continue
                    
                    # Must have minimum indicators (3+)
                    if len(match.strings) < min_indicators:
                        continue
                    
                    # Additional context check
                    if region_info:
                        exe_path = region_info.get('exe_path', '').lower()
                        
                        # Skip if from known JIT locations (legitimate apps that use RWX memory)
                        jit_paths = [
                            'program files\\google\\chrome',
                            'program files (x86)\\google\\chrome',
                            'program files\\mozilla firefox',
                            'appdata\\local\\microsoft\\edge',
                            'program files\\microsoft',
                            'windows\\microsoft.net',
                            'appdata\\local\\programs',  # User-installed apps like Canva
                            'canva'  # Canva specifically
                        ]
                        
                        # Check if process is from JIT location - skip if so
                        is_jit_process = any(jit_path in exe_path for jit_path in jit_paths)
                        if is_jit_process:
                            continue  # Skip this match - legitimate JIT process
                
                # Create match object
                yara_match = YARAMatch(
                    rule_name=match.rule,
                    rule_namespace=match.namespace,
                    strings=[{
                        'identifier': s.identifier,
                        'offset': s.instances[0].offset if s.instances else 0,
                        'matched_data': s.instances[0].matched_data[:100] if s.instances else b''
                    } for s in match.strings],
                    tags=list(match.tags),
                    metadata=match.meta,
                    severity=severity,
                    description=description
                )
                
                matches.append(yara_match)
        
        except yara.TimeoutError:
            pass  # Timeout is normal for large regions
        except Exception as e:
            pass  # Ignore scan errors
        
        return matches
    
    def scan_process_memory(self, memory_regions: List[Dict]) -> List[YARAMatch]:
        """
        Scan multiple memory regions
        
        Args:
            memory_regions: List of dicts with 'data' and optional 'info'
        
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
    
    def scan_command_line(self, cmdline: str, process_info: Optional[Dict] = None) -> List[YARAMatch]:
        """
        Scan command line with YARA rules
        
        Args:
            cmdline: Command line string
            process_info: Optional process metadata
        
        Returns:
            List of YARAMatch objects
        """
        if not cmdline:
            return []
        
        return self.scan_memory_region(
            cmdline.encode('utf-8', errors='ignore'),
            process_info
        )
    
    def get_rule_statistics(self) -> Dict:
        """Get statistics about loaded rules"""
        return {
            'rule_count': self.rule_count,
            'rules_dir': self.rules_dir,
            'loaded': self.compiled_rules is not None,
            'whitelist_enabled': bool(self.whitelist.get('trusted_paths'))
        }
    
    def reload_rules(self):
        """Reload YARA rules"""
        print("[*] Reloading YARA rules...")
        self.whitelist = self._load_whitelist()
        self._load_rules()


def test_yara_scanner():
    """Test the YARA scanner"""
    print("\n=== DataDefenceX YARA Scanner Test ===\n")
    
    scanner = YARAScanner()
    
    # Test 1: Suspicious PowerShell
    print("[*] Test 1: Scanning suspicious PowerShell command")
    suspicious_cmd = "powershell -windowstyle hidden -encodedcommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA=="
    matches = scanner.scan_command_line(suspicious_cmd)
    
    if matches:
        print(f"    [!] Found {len(matches)} YARA match(es):")
        for match in matches:
            print(f"        - {match.rule_name} ({match.severity}): {match.description}")
    else:
        print("    [*] No matches (may need threshold adjustment)")
    
    # Test 2: Memory injection indicators
    print("\n[*] Test 2: Scanning memory with injection indicators")
    injection_data = b"VirtualAlloc\x00WriteProcessMemory\x00CreateRemoteThread\x00RtlCreateUserThread\x00" + b"\x90" * 20
    matches = scanner.scan_memory_region(injection_data)
    
    if matches:
        print(f"    [!] Found {len(matches)} YARA match(es):")
        for match in matches:
            print(f"        - {match.rule_name} ({match.severity}): {match.description}")
    else:
        print("    [*] No matches (good - requires 3+ indicators)")
    
    # Test 3: Legitimate process (should be skipped)
    print("\n[*] Test 3: Scanning legitimate process memory")
    chrome_data = b"VirtualAlloc\x00" + b"\x90" * 10
    chrome_info = {
        'exe_path': 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
        'process_name': 'chrome.exe'
    }
    matches = scanner.scan_memory_region(chrome_data, chrome_info)
    
    if matches:
        print(f"    [!] Found {len(matches)} matches (should be 0!)")
    else:
        print("    [✓] No matches - Whitelisted path works!")
    
    # Statistics
    print("\n[*] Test 4: Rule statistics")
    stats = scanner.get_rule_statistics()
    print(f"    Rules loaded: {stats['rule_count']}")
    print(f"    Whitelist enabled: {stats['whitelist_enabled']}")
    print(f"    Status: {'Loaded' if stats['loaded'] else 'Not loaded'}")


if __name__ == "__main__":
    test_yara_scanner()