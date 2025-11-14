"""
Process Monitor Agent for DataDefenceX
Monitors process creation and behavior
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
WHITELIST_PROCESSES = {
    'chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe',
    'code.exe', 'python.exe', 'powershell.exe', 'cmd.exe',
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

# Suspicious patterns in command lines
SUSPICIOUS_PATTERNS = [
    r'powershell.*-encodedcommand',
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
]


class ProcessMonitorAgent:
    """
    Monitors process creation and behavior
    Detects suspicious process activities
    """
    
    def __init__(self, history_size: int = 1000):
        self.running = False
        self.process_history = deque(maxlen=history_size)
        self.monitored_pids = set()
        self.previous_pids = set()
        self.yara_scanner = YARAScanner()  # Initialize YARA scanner
    
    def calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not data or len(data) == 0:
            return 0.0
        
        try:
            # Count frequency of each character
            char_freq = {}
            for char in data:
                char_freq[char] = char_freq.get(char, 0) + 1
            
            # Calculate entropy
            entropy = 0.0
            data_len = float(len(data))
            
            for count in char_freq.values():
                if count > 0:
                    p = float(count) / data_len
                    entropy -= p * math.log2(p)
            
            return entropy
        
        except Exception as e:
            print(f"[DEBUG] Error calculating entropy: {e}")
            return 0.0
    
    def is_base64_encoded(self, data: str) -> bool:
        """Check if string contains base64-encoded data"""
        try:
            if not data or len(data) < 20:
                return False
            
            # Remove common separators
            cleaned = data.replace(' ', '').replace('\n', '').replace('\r', '')
            
            # Base64 regex pattern
            base64_pattern = r'^[A-Za-z0-9+/]{20,}={0,2}$'
            
            # Check for large base64 chunks
            for chunk in re.findall(r'[A-Za-z0-9+/]{30,}={0,2}', cleaned):
                if re.match(base64_pattern, chunk):
                    return True
            
            return False
        
        except Exception as e:
            return False
    
    def check_suspicious_patterns(self, cmdline: str) -> List[str]:
        """Check for known suspicious command line patterns"""
        indicators = []
        
        if not cmdline or len(cmdline) == 0:
            return indicators
        
        try:
            cmdline_lower = str(cmdline).lower()
            
            for pattern in SUSPICIOUS_PATTERNS:
                try:
                    if re.search(pattern, cmdline_lower, re.IGNORECASE):
                        indicators.append(f"Matches pattern: {pattern}")
                except Exception:
                    pass
        
        except Exception as e:
            pass
        
        return indicators
    
    def get_process_info(self, pid: int) -> Optional[Dict]:
        """Get detailed information about a process"""
        try:
            proc = psutil.Process(pid)
            
            # Get basic info
            name = proc.name()
            
            try:
                cmdline = ' '.join(proc.cmdline()) if proc.cmdline() else ''
            except Exception:
                cmdline = ''
            
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
        """Check if process is whitelisted"""
        try:
            name = str(process_info['name']).lower()
            exe_path = str(process_info['exe_path']).lower()
            
            # Check process name whitelist
            if name in WHITELIST_PROCESSES:
                return True
            
            # Check if running from trusted path
            for trusted_path in TRUSTED_PATHS:
                if exe_path.startswith(trusted_path.lower()):
                    # Still check for suspicious cmdline
                    if not self.check_suspicious_patterns(process_info['cmdline']):
                        return True
            
            return False
        
        except Exception:
            return False
    
    def calculate_suspicion_score(self, process_info: Dict) -> Tuple[int, List[str]]:
        """Calculate suspicion score for a process (0-100)"""
        score = 0
        indicators = []
        
        try:
            name = str(process_info['name']).lower()
            cmdline = str(process_info['cmdline']).lower()
            exe_path = str(process_info['exe_path']).lower()
            
            # Check if whitelisted
            if self.is_whitelisted(process_info):
                return 0, []
            
            # Check for suspicious command line patterns
            pattern_matches = self.check_suspicious_patterns(process_info['cmdline'])
            if pattern_matches:
                score += 40
                indicators.extend(pattern_matches)
            
            # High entropy analysis (adjusted threshold)
            try:
                entropy = self.calculate_entropy(cmdline)
                if entropy > 5.5:  # Raised threshold from 5.0
                    score += 25
                    indicators.append(f"High cmdline entropy: {entropy:.2f}")
            except Exception:
                pass
            
            # Base64 encoding detection (only if other indicators present)
            if score > 0 and self.is_base64_encoded(cmdline):
                score += 20
                indicators.append("Contains Base64-encoded data")
            
            # YARA signature scanning on command line
            try:
                yara_matches = self.yara_scanner.scan_command_line(cmdline)
                if yara_matches:
                    # Count by severity
                    critical_count = sum(1 for m in yara_matches if m.severity == 'critical')
                    high_count = sum(1 for m in yara_matches if m.severity == 'high')
                    
                    if critical_count > 0:
                        score += 50
                        indicators.append(f"YARA: {critical_count} critical signature(s) matched")
                    elif high_count > 0:
                        score += 35
                        indicators.append(f"YARA: {high_count} high-severity signature(s) matched")
                    else:
                        score += 20
                        indicators.append(f"YARA: {len(yara_matches)} signature(s) matched")
                    
                    # Add rule names to indicators (show top 3)
                    for match in yara_matches[:3]:
                        indicators.append(f"  - {match.rule_name}: {match.description}")
            except Exception as e:
                pass  # YARA scanning failed, continue without it
            
            # Suspicious parent process
            try:
                parent_pid = process_info.get('parent_pid')
                if parent_pid:
                    try:
                        parent = psutil.Process(parent_pid)
                        parent_name = str(parent.name()).lower()
                        
                        suspicious_parents = {'explorer.exe', 'cmd.exe', 'powershell.exe', 
                                             'svchost.exe', 'rundll32.exe', 'mshta.exe'}
                        if parent_name in suspicious_parents and score > 20:
                            score += 15
                            indicators.append(f"Suspicious parent: {parent_name}")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            except Exception:
                pass
            
            # Temp/suspicious directory execution
            try:
                if 'temp' in exe_path or 'appdata' in exe_path:
                    if 'windows\\temp' not in exe_path:  # Exclude system temp
                        score += 30
                        indicators.append("Suspicious location: Running from Temp/AppData folder")
            except Exception:
                pass
            
            # ProgramData execution (sometimes suspicious)
            try:
                if 'programdata' in exe_path:
                    score += 15
                    indicators.append("Suspicious location: Running from ProgramData")
            except Exception:
                pass
            
            # Obfuscated/random names
            try:
                if len(name) > 15 or name.count('_') > 3 or name.count('-') > 3:
                    if not any(legit in name for legit in ['codeset', 'installer', 'update']):
                        score += 10
                        indicators.append("Suspicious process name pattern")
            except Exception:
                pass
            
            return min(score, 100), indicators
        
        except Exception as e:
            print(f"[DEBUG] Error in calculate_suspicion_score: {e}")
            return 0, []
    
    def scan_running_processes(self) -> List[ProcessEvent]:
        """Scan all currently running processes"""
        events = []
        current_pids = set()
        
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    pid = proc.info['pid']
                    current_pids.add(pid)
                    
                    process_info = self.get_process_info(pid)
                    if not process_info:
                        continue
                    
                    # Calculate suspicion
                    score, indicators = self.calculate_suspicion_score(process_info)
                    
                    # Only report suspicious processes
                    if score >= 70:  # Raised threshold to reduce false positives
                        event = ProcessEvent(
                            timestamp=datetime.now(),
                            event_type='suspicious',
                            pid=pid,
                            name=process_info['name'],
                            cmdline=process_info['cmdline'],
                            parent_pid=process_info['parent_pid'],
                            exe_path=process_info['exe_path'],
                            suspicious_indicators=indicators,
                            suspicion_score=score
                        )
                        events.append(event)
                        self.process_history.append(event)
                
                except Exception:
                    pass
        
        except Exception as e:
            print(f"[!] Error scanning processes: {e}")
        
        return events
    
    def detect_new_processes(self) -> List[ProcessEvent]:
        """Detect newly created processes"""
        events = []
        current_pids = set()
        
        try:
            for proc in psutil.process_iter(['pid']):
                try:
                    pid = proc.info['pid']
                    current_pids.add(pid)
                    
                    # Check if this is a new process
                    if pid not in self.previous_pids:
                        process_info = self.get_process_info(pid)
                        if not process_info:
                            continue
                        
                        score, indicators = self.calculate_suspicion_score(process_info)
                        
                        # Report suspicious new processes
                        if score >= 70:
                            event = ProcessEvent(
                                timestamp=datetime.now(),
                                event_type='created',
                                pid=pid,
                                name=process_info['name'],
                                cmdline=process_info['cmdline'],
                                parent_pid=process_info['parent_pid'],
                                exe_path=process_info['exe_path'],
                                suspicious_indicators=indicators,
                                suspicion_score=score
                            )
                            events.append(event)
                            self.process_history.append(event)
                
                except Exception:
                    pass
            
            self.previous_pids = current_pids
        
        except Exception as e:
            print(f"[!] Error detecting new processes: {e}")
        
        return events
    
    def get_process_tree(self, pid: int) -> Optional[Dict]:
        """Get process tree for a given PID"""
        try:
            proc = psutil.Process(pid)
            
            try:
                cmdline = ' '.join(proc.cmdline()) if proc.cmdline() else ''
            except Exception:
                cmdline = ''
            
            tree = {
                'pid': pid,
                'name': proc.name(),
                'cmdline': cmdline,
                'children': []
            }
            
            try:
                for child in proc.children(recursive=True):
                    try:
                        child_cmdline = ' '.join(child.cmdline()) if child.cmdline() else ''
                    except Exception:
                        child_cmdline = ''
                    
                    tree['children'].append({
                        'pid': child.pid,
                        'name': child.name(),
                        'cmdline': child_cmdline
                    })
            except Exception:
                pass
            
            return tree
        
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
        except Exception:
            return None


def test_process_monitor():
    """Test the process monitor"""
    print("\n=== DataDefenceX Process Monitor Test ===\n")
    
    agent = ProcessMonitorAgent()
    
    print("[*] Analyzing currently running processes...\n")
    
    events = agent.scan_running_processes()
    
    if events:
        print(f"[!] Found {len(events)} suspicious processes:\n")
        for event in sorted(events, key=lambda x: x.suspicion_score, reverse=True):
            print(f"[!] Suspicious: {event.name} (Score: {event.suspicion_score})")
            for indicator in event.suspicious_indicators:
                print(f"    - {indicator}")
    else:
        print("[+] No highly suspicious processes detected!")
    
    print("\n[*] Starting real-time monitoring (Ctrl+C to stop)...")
    print("[*] Waiting for new process creations...\n")
    
    try:
        import time
        while True:
            new_events = agent.detect_new_processes()
            if new_events:
                for event in new_events:
                    print(f"\n[!] NEW PROCESS DETECTED: {event.name} (PID: {event.pid})")
                    print(f"    Score: {event.suspicion_score}")
                    print(f"    Command: {event.cmdline[:100]}")
                    for indicator in event.suspicious_indicators:
                        print(f"    - {indicator}")
            
            time.sleep(2)
    
    except KeyboardInterrupt:
        print("\n\n[*] Monitoring stopped.")


if __name__ == "__main__":
    test_process_monitor()