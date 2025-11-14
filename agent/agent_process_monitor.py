"""
Process Monitor Agent for DataDefenceX - FINAL FIXED
PowerShell/cmd REMOVED from whitelist to enable detection
"""
import psutil
import os
import re
import base64
import string
import math
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from collections import deque
from agent.agent_yara_scanner import YARAScanner


@dataclass
class ProcessEvent:
    """Represents a process event"""
    timestamp: datetime
    event_type: str  # 'created', 'terminated', 'suspicious'
    pid: int
    name: str
    cmdline: str
    parent_pid: Optional[int]
    exe_path: str
    suspicious_indicators: List[str]
    suspicion_score: int


# Whitelist of legitimate system and common processes
# CRITICAL FIX: PowerShell and cmd REMOVED to enable suspicious command detection
WHITELIST_PROCESSES = {
    'chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe',
    'code.exe', 'python.exe',  # REMOVED: 'powershell.exe', 'cmd.exe'
    'conhost.exe', 'csrss.exe', 'explorer.exe', 'dwm.exe',
    'svchost.exe', 'lsass.exe', 'wininit.exe', 'services.exe',
    'spoolsv.exe', 'rundll32.exe', 'dllhost.exe', 'taskhostw.exe',
    'searchindexer.exe', 'audiodg.exe', 'backgroundtaskhost.exe',
    'runtimebroker.exe', 'nvda.exe', 'onedrivesetup.exe',
    'onedrive.exe', 'googlecrashhandler.exe', 'googlecrashhandler64.exe',
    'slack.exe', 'discord.exe', 'whatsapp.exe', 'telegram.exe',
    'zoom.exe', 'teams.exe', 'skype.exe', 'anydesk.exe',
    'vmware-tray.exe', 'virtualbox.exe', 'qemu.exe',
    'git.exe', 'tortoisegit.exe', 'javaw.exe', 'java.exe',
    'node.exe', 'npm.exe', 'yarn.exe', 'dotnet.exe',
    'systemsettings.exe', 'settings.exe', 'controlpanel.exe',
    'notepad.exe', 'notepad++.exe', 'gedit.exe', 'vim.exe',
    'canva.exe', 'figma.exe', 'adobe.exe', 'photoshop.exe',
    'vlc.exe', 'mediaplayerclassic.exe', 'foobar.exe',
    '7z.exe', 'winrar.exe', 'peazip.exe', '7zfm.exe',
    'nvidia.exe', 'amd.exe', 'intel.exe',
    'copilot.exe', 'claude.exe', 'chatgpt.exe',
    'pet.exe', 'ccleaner.exe', 'malwarebytes.exe',
    'avast.exe', 'bitdefender.exe', 'mcafee.exe',
    'lenovovantage.exe', 'nahimicsvc64.exe', 'rtkaudio.exe'
}

# Trusted system paths (processes here are less suspicious)
TRUSTED_PATHS = {
    'c:\\windows\\system32',
    'c:\\windows\\syswow64',
    'c:\\program files',
    'c:\\program files (x86)',
    'c:\\windows\\servicing',
    'c:\\windows\\temp',
}

# Suspicious patterns in command lines (case-insensitive matching)
SUSPICIOUS_PATTERNS = [
    r'powershell.*-encodedcommand',
    r'powershell.*-enc\s',
    r'powershell.*-e\s',  # Short form
    r'powershell.*-windowstyle\s+hidden',
    r'powershell.*-executionpolicy\s+bypass',
    r'powershell.*-noprofile',
    r'powershell.*-noninteractive',
    r'cmd.*\/c.*powershell',
    r'cmd.*\/c.*base64',
    r'rundll32.*\.dll',
    r'regsvcs.*\.exe',
    r'regasm.*\.exe',
    r'mshta.*\.hta',
    r'wscript.*\.vbs',
    r'cscript.*\.vbs',
    r'java.*\.jar.*http',
    r'certutil.*-decode',
    r'bitsadmin.*transfer',
    r'curl.*http',
    r'wget.*http',
    r'python.*-c.*import',
    r'script.*-executionpolicy.*bypass',
    r'iex\s*\(',
    r'downloadstring',
    r'invoke-expression',
    r'invoke-webrequest',
    r'webclient',
    r'bitstransfer',
]


class ProcessMonitorAgent:
    """
    Monitors process creation and behavior
    Detects suspicious process activities
    """
    
    def __init__(self, yara_scanner: Optional[YARAScanner] = None):
        """
        Initialize the process monitor
        
        Args:
            yara_scanner: Optional shared YARA scanner instance
        """
        # YARA scanner for command line analysis
        self.yara_scanner = yara_scanner if yara_scanner else YARAScanner()
        
        # Track recent processes for behavior analysis
        self.process_history = deque(maxlen=1000)
        self.parent_child_map = {}
        
        print("[*] Process Monitor initialized")
        print(f"[*] PowerShell/cmd NOT in whitelist - will analyze all commands")
    
    def get_process_info(self, pid: int) -> Optional[Dict]:
        """
        Get detailed information about a process
        
        Args:
            pid: Process ID
            
        Returns:
            Dictionary with process information or None if not found
        """
        try:
            proc = psutil.Process(pid)
            
            # Get process name
            try:
                name = proc.name()
            except Exception:
                name = ''
            
            # Get command line (try multiple methods)
            cmdline = ''
            try:
                cmdline_list = proc.cmdline()
                if cmdline_list:
                    cmdline = ' '.join(cmdline_list)
            except Exception:
                # Fallback to WMIC if psutil fails
                try:
                    import subprocess
                    result = subprocess.run(
                        ['wmic', 'process', 'where', f'ProcessId={pid}', 'get', 'CommandLine', '/format:list'],
                        capture_output=True,
                        text=True,
                        timeout=2
                    )
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            if line.startswith('CommandLine='):
                                cmdline = line.split('=', 1)[1].strip()
                                break
                except Exception:
                    pass
            
            try:
                exe_path = proc.exe() if proc.exe() else ''
            except Exception:
                exe_path = ''
            
            try:
                parent_pid = proc.ppid() if proc.ppid() else None
            except Exception:
                parent_pid = None
            
            return {
                'pid': pid,
                'name': name,
                'cmdline': cmdline,
                'exe_path': exe_path,
                'parent_pid': parent_pid,
                'create_time': proc.create_time(),
                'status': proc.status()
            }
        
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
        except Exception:
            return None
    
    def is_whitelisted(self, process_info: Dict) -> bool:
        """
        Check if process is whitelisted
        CRITICAL: PowerShell/cmd are NOT in whitelist
        """
        try:
            name = str(process_info['name']).lower()
            exe_path = str(process_info['exe_path']).lower()
            
            # Check process name whitelist
            if name in WHITELIST_PROCESSES:
                return True
            
            # Check if running from trusted path
            # BUT: Never whitelist PowerShell/cmd even from trusted paths
            if 'powershell' in name or 'cmd' in name or 'wmic' in name:
                return False  # Always analyze shell commands
            
            for trusted_path in TRUSTED_PATHS:
                if exe_path.startswith(trusted_path.lower()):
                    # Still check for suspicious cmdline
                    if not self.check_suspicious_patterns(process_info['cmdline']):
                        return True
            
            return False
        
        except Exception:
            return False
    
    def check_suspicious_patterns(self, cmdline: str) -> List[str]:
        """
        Check for suspicious patterns in command line
        
        Args:
            cmdline: Command line string
            
        Returns:
            List of matched patterns
        """
        matches = []
        
        if not cmdline:
            return matches
        
        cmdline_lower = cmdline.lower()
        
        for pattern in SUSPICIOUS_PATTERNS:
            try:
                if re.search(pattern, cmdline_lower, re.IGNORECASE):
                    matches.append(pattern)
            except re.error:
                continue
        
        return matches
    
    def is_base64_encoded(self, text: str) -> bool:
        """Check if text contains base64-encoded content"""
        if not text or len(text) < 50:
            return False
        
        # Look for long base64 strings (50+ chars)
        base64_pattern = r'[A-Za-z0-9+/]{50,}={0,2}'
        matches = re.findall(base64_pattern, text)
        
        if matches:
            # Verify it's valid base64
            for match in matches:
                try:
                    base64.b64decode(match)
                    return True
                except Exception:
                    continue
        
        return False
    
    def calculate_suspicion_score(self, process_info: Dict) -> Tuple[int, List[str]]:
        """Calculate suspicion score for a process (0-100)"""
        score = 0
        indicators = []
        
        try:
            name = str(process_info['name']).lower()
            cmdline_str = str(process_info.get('cmdline', '')).lower()
            exe_path = str(process_info.get('exe_path', '')).lower()
            
            # CRITICAL: Never skip analysis for PowerShell/cmd
            # Check for suspicious command line patterns FIRST
            pattern_matches = self.check_suspicious_patterns(cmdline_str)
            if pattern_matches:
                # Higher score for encoded commands (very suspicious)
                if any('encodedcommand' in p.lower() or '-enc' in p.lower() or '-e ' in p.lower() 
                       for p in pattern_matches):
                    score += 70  # INCREASED: Very high score for encoded commands
                    indicators.append("Encoded PowerShell command detected")
                else:
                    score += 50
                indicators.extend([f"Suspicious pattern: {p}" for p in pattern_matches[:3]])
            
            # Check for base64 patterns in command line
            if self.is_base64_encoded(cmdline_str):
                score += 30
                indicators.append("Base64-encoded content in command line")
            
            # Check if PowerShell/cmd
            if 'powershell' in name or 'cmd' in name:
                score += 15  # Base score for shell processes
                indicators.append(f"Shell process: {name}")
                
                # Additional checks for PowerShell/cmd
                if '-windowstyle' in cmdline_str and 'hidden' in cmdline_str:
                    score += 25
                    indicators.append("Hidden window mode")
                
                if 'bypass' in cmdline_str:
                    score += 25
                    indicators.append("Execution policy bypass")
                
                if '-noprofile' in cmdline_str or '-noninteractive' in cmdline_str:
                    score += 15
                    indicators.append("Non-interactive mode")
            
            # Check for suspicious parent processes
            parent_pid = process_info.get('parent_pid')
            if parent_pid:
                try:
                    parent_proc = psutil.Process(parent_pid)
                    parent_name = parent_proc.name().lower()
                    
                    # Suspicious parent combinations
                    if name in ['powershell.exe', 'cmd.exe']:
                        if parent_name in ['explorer.exe', 'winword.exe', 'excel.exe']:
                            score += 20
                            indicators.append(f"Suspicious parent: {parent_name}")
                except:
                    pass
            
            # Check for suspicious paths
            suspicious_path_keywords = ['temp', 'appdata', 'downloads', 'public']
            if any(keyword in exe_path for keyword in suspicious_path_keywords):
                score += 15
                indicators.append("Running from suspicious location")
            
            # Use YARA to scan command line
            if self.yara_scanner and cmdline_str:
                try:
                    yara_matches = self.yara_scanner.scan_command_line(
                        process_info.get('cmdline', ''),
                        process_info
                    )
                    
                    if yara_matches:
                        yara_score = len(yara_matches) * 15
                        score += yara_score
                        indicators.extend([f"YARA: {m.rule_name}" for m in yara_matches[:2]])
                except Exception:
                    pass
            
            # Cap score at 100
            score = min(score, 100)
            
            # Debug output for PowerShell
            if 'powershell' in name:
                print(f"[DEBUG] PowerShell score calculation: PID={process_info['pid']}, Score={score}, Indicators={len(indicators)}")
            
            return score, indicators
        
        except Exception as e:
            print(f"[!] Error calculating suspicion score: {e}")
            return 0, []
    
    def analyze_process(self, process_info: Dict) -> Optional[ProcessEvent]:
        """
        Analyze a process and return a ProcessEvent if suspicious
        
        Args:
            process_info: Dictionary with process information
            
        Returns:
            ProcessEvent if suspicious, None otherwise
        """
        try:
            # Skip if whitelisted (PowerShell/cmd are NOT whitelisted)
            if self.is_whitelisted(process_info):
                return None
            
            # Calculate suspicion score
            suspicion_score, indicators = self.calculate_suspicion_score(process_info)
            
            # Create event if suspicious
            if suspicion_score > 0:
                event = ProcessEvent(
                    timestamp=datetime.now(),
                    event_type='suspicious',
                    pid=process_info['pid'],
                    name=process_info['name'],
                    cmdline=process_info['cmdline'],
                    parent_pid=process_info.get('parent_pid'),
                    exe_path=process_info['exe_path'],
                    suspicious_indicators=indicators,
                    suspicion_score=suspicion_score
                )
                
                return event
            
            return None
        
        except Exception as e:
            print(f"[!] Error analyzing process: {e}")
            return None


def test_process_monitor():
    """Test the process monitor"""
    print("\n=== DataDefenceX Process Monitor Test ===\n")
    
    monitor = ProcessMonitorAgent()
    
    # Test 1: Check if PowerShell is NOT whitelisted
    print("[*] Test 1: PowerShell Whitelist Status")
    test_process = {
        'pid': 1234,
        'name': 'powershell.exe',
        'cmdline': 'powershell.exe -Command "Get-Process"',
        'exe_path': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        'parent_pid': 5678
    }
    
    is_whitelisted = monitor.is_whitelisted(test_process)
    print(f"    PowerShell whitelisted: {is_whitelisted}")
    if not is_whitelisted:
        print("    [✓] CORRECT - PowerShell will be analyzed")
    else:
        print("    [✗] WRONG - PowerShell should NOT be whitelisted")
    
    # Test 2: Encoded PowerShell command
    print("\n[*] Test 2: Encoded PowerShell Detection")
    encoded_process = {
        'pid': 1234,
        'name': 'powershell.exe',
        'cmdline': 'powershell.exe -WindowStyle Hidden -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIAVABlAHMAdAAi',
        'exe_path': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        'parent_pid': 5678
    }
    
    score, indicators = monitor.calculate_suspicion_score(encoded_process)
    print(f"    Suspicion Score: {score}/100")
    print(f"    Indicators: {len(indicators)}")
    for indicator in indicators[:3]:
        print(f"      - {indicator}")
    
    if score >= 70:
        print("    [✓] HIGH SCORE - Would be detected")
    else:
        print(f"    [✗] LOW SCORE - May not be detected (threshold: 70)")
    
    # Test 3: Normal PowerShell command
    print("\n[*] Test 3: Normal PowerShell Command")
    normal_process = {
        'pid': 1234,
        'name': 'powershell.exe',
        'cmdline': 'powershell.exe -Command "Get-Process | Select-Object -First 5"',
        'exe_path': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        'parent_pid': 5678
    }
    
    score, indicators = monitor.calculate_suspicion_score(normal_process)
    print(f"    Suspicion Score: {score}/100")
    print(f"    Indicators: {len(indicators)}")
    
    if score < 30:
        print("    [✓] LOW SCORE - Would not trigger alert")
    else:
        print(f"    [!] SCORE TOO HIGH for normal command")


if __name__ == "__main__":
    test_process_monitor()