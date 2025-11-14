"""
DataDefenceX - Real-Time Detection System FINAL FIXED v2.1
Properly detects suspicious PowerShell commands even from System32
"""

import time
import threading
from queue import Queue
from datetime import datetime
from typing import Dict, List, Optional
import json
import os
import sys

# Import our real-time components
from agent.agent_memory_monitor import MemoryMonitorAgent
from agent.agent_process_monitor import ProcessMonitorAgent, ProcessEvent
from engine.engine_realtime_ml import RealtimeMLEngine, RealtimeFeatures
from engine.engine_action import ActionEngine, ThreatLevel


def load_whitelist(whitelist_path: str = "config/whitelist.json") -> Dict:
    """
    Load whitelist configuration
    
    Returns:
        Dict with trusted processes, paths, thresholds
    """
    default_whitelist = {
        'trusted_processes': [],
        'trusted_paths': [],
        'thresholds': {
            'ml_threshold': 0.70,
            'confidence_threshold': 0.75,
            'yara_critical_threshold': 3
        },
        'scan_exclusions': [0, 4],
        'rate_limiting': {
            'scan_cooldown_seconds': 300,
            'max_scans_per_process': 10
        }
    }
    
    if not os.path.exists(whitelist_path):
        print(f"[!] Whitelist not found: {whitelist_path}")
        print(f"[*] Using default whitelist (empty - will scan everything)")
        return default_whitelist
    
    try:
        with open(whitelist_path, 'r') as f:
            whitelist = json.load(f)
        
        # Remove comment entries and invalid strings
        if 'trusted_processes' in whitelist:
            whitelist['trusted_processes'] = [
                p for p in whitelist['trusted_processes'] 
                if isinstance(p, str) and not p.startswith('//') and not p.startswith('_comment')
            ]
        
        if 'trusted_paths' in whitelist:
            whitelist['trusted_paths'] = [
                p for p in whitelist['trusted_paths'] 
                if isinstance(p, str) and not p.startswith('//') and not p.startswith('_comment')
            ]
        
        # Remove comment entries from other sections
        for key in ['thresholds', 'rate_limiting', 'advanced_settings']:
            if key in whitelist and isinstance(whitelist[key], dict):
                whitelist[key] = {
                    k: v for k, v in whitelist[key].items() 
                    if not k.startswith('_comment')
                }
        
        # Merge with defaults for missing keys
        for key in default_whitelist:
            if key not in whitelist:
                whitelist[key] = default_whitelist[key]
        
        print(f"[*] Loaded whitelist: {len(whitelist['trusted_processes'])} trusted processes")
        return whitelist
    
    except Exception as e:
        print(f"[!] Error loading whitelist: {e}")
        print(f"[*] Using default whitelist")
        return default_whitelist


class EventQueue:
    """Thread-safe event queue for passing data between components"""
    
    def __init__(self, maxsize: int = 1000):
        self.queue = Queue(maxsize=maxsize)
    
    def put(self, event: Dict):
        """Add event to queue"""
        try:
            self.queue.put(event, block=False)
        except:
            pass  # Queue full, skip event
    
    def get(self, block: bool = True, timeout: float = None):
        """Get event from queue"""
        return self.queue.get(block=block, timeout=timeout)
    
    def empty(self) -> bool:
        """Check if queue is empty"""
        return self.queue.empty()


class RealtimeDetectionSystem:
    """
    Main real-time detection system with whitelist support
    Integrates all components for continuous monitoring and response
    """
    
    def __init__(self, whitelist_path: str = "config/whitelist.json"):
        print("\n[*] Initializing DataDefenceX...")
        
        # Load whitelist first
        self.whitelist = load_whitelist(whitelist_path)
        
        # Initialize components with shared YARA scanner
        from agent.agent_yara_scanner import YARAScanner
        
        print("[*] Loading components...")
        
        # Shared YARA scanner to avoid duplicate loading
        try:
            shared_yara_scanner = YARAScanner()
            print("    [✔] YARA scanner loaded")
        except Exception as e:
            print(f"    [✘] YARA scanner failed: {e}")
            shared_yara_scanner = None
        
        # Memory monitor (pass shared YARA scanner)
        try:
            self.memory_agent = MemoryMonitorAgent(yara_scanner=shared_yara_scanner)
            print("    [✔] Memory monitor loaded")
        except Exception as e:
            print(f"    [✘] Memory monitor failed: {e}")
            self.memory_agent = None
        
        # Process monitor (pass shared YARA scanner)
        try:
            self.process_agent = ProcessMonitorAgent(yara_scanner=shared_yara_scanner)
            print("    [✔] Process monitor loaded")
        except Exception as e:
            print(f"    [✘] Process monitor failed: {e}")
            self.process_agent = None
        
        # ML engine
        try:
            self.ml_engine = RealtimeMLEngine()
            print("    [✔] ML engine loaded")
        except Exception as e:
            print(f"    [✘] ML engine failed: {e}")
            self.ml_engine = None
        
        # Action engine
        try:
            self.action_engine = ActionEngine()
            print("    [✔] Action engine loaded")
        except Exception as e:
            print(f"    [✘] Action engine failed: {e}")
            self.action_engine = None
        
        # Event queues
        self.process_events = EventQueue()
        self.memory_events = EventQueue()
        self.detection_results = EventQueue()
        
        # State
        self.running = False
        
        # Statistics
        self.stats = {
            'processes_scanned': 0,
            'memory_scans': 0,
            'threats_detected': 0,
            'actions_taken': 0,
            'false_positives_avoided': 0,
            'start_time': None
        }
        
        # Tracking for rate limiting
        self.scan_history = {}  # PID -> {'last_scan': datetime, 'scan_count': int}
    
    def _is_suspicious_command(self, cmdline: str, process_name: str) -> bool:
        """
        Check if command line contains suspicious patterns
        Returns True if suspicious, False if benign
        """
        if not cmdline:
            return False
        
        cmdline_lower = cmdline.lower()
        
        # Suspicious keywords for PowerShell/cmd
        suspicious_keywords = [
            '-encodedcommand', '-enc', '-e ',
            'bypass', 'hidden', '-windowstyle',
            '-noprofile', '-noninteractive', '-noni',
            'invoke-expression', 'iex', 'invoke-webrequest', 'iwr',
            'downloadstring', 'downloadfile',
            'webclient', 'net.webclient', 'webrequest',
            'bitstransfer', 'start-bitstransfer',
            'invoke-mimikatz', 'invoke-shellcode',
            'empire', 'metasploit', 'meterpreter',
            'amsi', 'reflection.assembly',
            'system.reflection', 'frombase64string'
        ]
        
        # Check for suspicious patterns
        for keyword in suspicious_keywords:
            if keyword in cmdline_lower:
                return True
        
        # Check for base64 patterns (long encoded strings)
        import re
        base64_pattern = r'[A-Za-z0-9+/]{50,}={0,2}'
        if re.search(base64_pattern, cmdline):
            return True
        
        return False
    
    def _is_whitelisted_process(self, name: str, path: str = None, cmdline: str = None) -> bool:
        """
        Check if process is whitelisted
        IMPORTANT: PowerShell/cmd with suspicious commands are NEVER whitelisted
        """
        if not name:
            return False
        
        name_lower = name.lower()
        
        # CRITICAL: Never whitelist suspicious PowerShell/cmd commands
        if ('powershell' in name_lower or 'cmd' in name_lower or 'wmic' in name_lower):
            if self._is_suspicious_command(cmdline or '', name):
                return False  # Force analysis of suspicious shell commands
        
        # Check trusted processes
        for trusted in self.whitelist.get('trusted_processes', []):
            if name_lower == trusted.lower():
                return True
        
        # Check trusted paths
        if path:
            path_lower = path.lower()
            for trusted_path in self.whitelist.get('trusted_paths', []):
                if path_lower.startswith(trusted_path.lower()):
                    # Even from trusted paths, don't whitelist suspicious commands
                    if ('powershell' in name_lower or 'cmd' in name_lower):
                        if self._is_suspicious_command(cmdline or '', name):
                            return False
                    return True
        
        return False
    
    def _should_scan_process(self, pid: int) -> bool:
        """Check if process should be scanned based on rate limiting"""
        # Check exclusions
        if pid in self.whitelist.get('scan_exclusions', [0, 4]):
            return False
        
        # Check rate limiting
        rate_config = self.whitelist.get('rate_limiting', {})
        cooldown = rate_config.get('scan_cooldown_seconds', 300)
        max_scans = rate_config.get('max_scans_per_process', 10)
        
        if pid in self.scan_history:
            history = self.scan_history[pid]
            
            # Check max scans
            if history['scan_count'] >= max_scans:
                return False
            
            # Check cooldown
            elapsed = (datetime.now() - history['last_scan']).total_seconds()
            if elapsed < cooldown:
                return False
        
        return True
    
    def _record_scan(self, pid: int):
        """Record that a process was scanned"""
        if pid not in self.scan_history:
            self.scan_history[pid] = {
                'last_scan': datetime.now(),
                'scan_count': 1
            }
        else:
            self.scan_history[pid]['last_scan'] = datetime.now()
            self.scan_history[pid]['scan_count'] += 1
    
    def start(self):
        """Start the real-time detection system"""
        print("\n" + "="*70)
        print("DataDefenceX - Real-Time Fileless Malware Detection")
        print("="*70 + "\n")
        
        self.running = True
        self.stats['start_time'] = datetime.now()
        
        print("[*] Starting monitoring agents...")
        
        # Start monitoring threads
        threads = []
        
        if self.process_agent:
            t = threading.Thread(
                target=self._process_monitor_thread, 
                daemon=True, 
                name="ProcessMonitor"
            )
            t.start()
            threads.append(t)
            print("    [✔] ProcessMonitor started")
        
        if self.memory_agent:
            t = threading.Thread(
                target=self._memory_monitor_thread, 
                daemon=True, 
                name="MemoryMonitor"
            )
            t.start()
            threads.append(t)
            print("    [✔] MemoryMonitor started")
        
        if self.ml_engine:
            t = threading.Thread(
                target=self._detection_engine_thread, 
                daemon=True, 
                name="DetectionEngine"
            )
            t.start()
            threads.append(t)
            print("    [✔] DetectionEngine started")
        
        if self.action_engine:
            t = threading.Thread(
                target=self._action_thread, 
                daemon=True, 
                name="ActionEngine"
            )
            t.start()
            threads.append(t)
            print("    [✔] ActionEngine started")
        
        # Stats reporter
        t = threading.Thread(
            target=self._stats_reporter_thread, 
            daemon=True, 
            name="StatsReporter"
        )
        t.start()
        threads.append(t)
        print("    [✔] StatsReporter started")
        
        print("\n[*] All systems operational!")
        print("[*] Monitoring for suspicious PowerShell/cmd commands...")
        print("[*] Press Ctrl+C to stop\n")
        
        # Main loop
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        """Stop the detection system"""
        print("\n[*] Stopping DataDefenceX...")
        self.running = False
        time.sleep(2)
        
        # Print final stats
        self._print_final_stats()
    
    def _process_monitor_thread(self):
        """Monitor for new suspicious processes"""
        import psutil
        
        print("[ProcessMonitor] Watching for new processes...")
        existing_pids = set()
        
        # Get existing PIDs
        try:
            existing_pids = set(p.info['pid'] for p in psutil.process_iter(['pid']))
        except:
            pass
        
        while self.running:
            try:
                current_pids = set()
                
                for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'cmdline']):
                    if not self.running:
                        break
                    
                    pid = proc.info['pid']
                    current_pids.add(pid)
                    
                    # Only analyze new processes
                    if pid not in existing_pids:
                        name = proc.info.get('name', '')
                        exe_path = proc.info.get('exe', '')
                        cmdline_raw = proc.info.get('cmdline', [])
                        
                        # Get command line as string
                        cmdline = ' '.join(cmdline_raw) if cmdline_raw else ''
                        
                        # Check if whitelisted (this now includes suspicious command check)
                        if self._is_whitelisted_process(name, exe_path, cmdline):
                            self.stats['false_positives_avoided'] += 1
                            continue
                        
                        # Skip system PIDs
                        if not self._should_scan_process(pid):
                            continue
                        
                        # Analyze process
                        try:
                            # Ensure cmdline is in process_info
                            proc_info = proc.info.copy()
                            proc_info['cmdline'] = cmdline  # Use the string version
                            
                            event = self.process_agent.analyze_process(proc_info)
                            
                            # Lower threshold for shell processes with suspicious commands
                            threshold = 20 if self._is_suspicious_command(cmdline, name) else 30
                            
                            if event and event.suspicion_score >= threshold:
                                # Log suspicious shells
                                if 'powershell' in name.lower() or 'cmd' in name.lower():
                                    print(f"[!] Suspicious shell detected: PID={pid}, Score={event.suspicion_score}, Cmd={cmdline[:100]}")
                                
                                self.process_events.put({
                                    'type': 'process',
                                    'event': event,
                                    'timestamp': datetime.now(),
                                    'has_suspicious_command': self._is_suspicious_command(cmdline, name)
                                })
                                self.stats['processes_scanned'] += 1
                        except Exception as e:
                            pass
                
                existing_pids = current_pids
                time.sleep(2)  # Check every 2 seconds
                
            except Exception as e:
                time.sleep(1)
    
    def _memory_monitor_thread(self):
        """Scan process memory with whitelist filtering"""
        import psutil
        
        print("[MemoryMonitor] Scanning process memory...")
        
        while self.running:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'exe']):
                    if not self.running:
                        break
                    
                    pid = proc.info['pid']
                    name = proc.info.get('name', '')
                    exe_path = proc.info.get('exe', '')
                    
                    # Skip whitelisted
                    if self._is_whitelisted_process(name, exe_path, None):
                        self.stats['false_positives_avoided'] += 1
                        continue
                    
                    # Check if should scan (rate limiting)
                    if not self._should_scan_process(pid):
                        continue
                    
                    # Scan memory
                    try:
                        indicators = self.memory_agent.scan_process(pid)
                        if indicators:
                            self.memory_events.put({
                                'type': 'memory',
                                'pid': pid,
                                'name': name,
                                'path': exe_path,
                                'indicators': indicators,
                                'timestamp': datetime.now()
                            })
                            self.stats['memory_scans'] += 1
                        
                        # Record scan
                        self._record_scan(pid)
                    except:
                        pass
                
                time.sleep(10)  # Memory scan every 10 seconds
                
            except Exception as e:
                time.sleep(5)
    
    def _detection_engine_thread(self):
        """Analyze events with ML engine"""
        print("[DetectionEngine] ML engine ready...")
        
        while self.running:
            try:
                # Check for process events
                if not self.process_events.empty():
                    event_data = self.process_events.get(timeout=0.1)
                    self._analyze_event(event_data)
                
                # Check for memory events
                if not self.memory_events.empty():
                    event_data = self.memory_events.get(timeout=0.1)
                    self._analyze_event(event_data)
                
                time.sleep(0.1)
                
            except Exception as e:
                time.sleep(1)
    
    def _analyze_event(self, event_data: Dict):
        """Analyze event with ML engine and context-aware scoring"""
        try:
            features = None
            process_name = ''
            process_path = ''
            has_suspicious_command = event_data.get('has_suspicious_command', False)
            
            # Extract features based on event type
            if event_data['type'] == 'process':
                process_event = event_data['event']
                process_name = process_event.name
                process_path = process_event.exe_path
                
                features = self.ml_engine.extract_features(
                    process_event={
                        'pid': process_event.pid,
                        'ppid': process_event.parent_pid,
                        'name': process_name,
                        'cmdline': process_event.cmdline,
                        'path': process_path,
                        'suspicious_score': process_event.suspicion_score
                    }
                )
            
            elif event_data['type'] == 'memory':
                process_name = event_data.get('name', '')
                process_path = event_data.get('path', '')
                
                features = self.ml_engine.extract_features(
                    memory_indicators=event_data['indicators']
                )
            
            if features:
                # Make prediction
                result = self.ml_engine.predict(features)
                
                # Context-aware scoring adjustment
                adjusted_score = result.threat_score
                
                # CRITICAL FIX: Do NOT reduce score for suspicious PowerShell/cmd commands
                # Only reduce score for benign processes from trusted paths
                if process_path and not has_suspicious_command:
                    for trusted_path in self.whitelist.get('trusted_paths', []):
                        if process_path.lower().startswith(trusted_path.lower()):
                            # Only reduce if NOT a suspicious shell command
                            is_shell = 'powershell' in process_name.lower() or 'cmd' in process_name.lower()
                            if not is_shell:
                                adjusted_score = adjusted_score * 0.7  # 30% reduction
                            break
                
                # Apply thresholds from whitelist
                thresholds = self.whitelist.get('thresholds', {})
                ml_threshold = thresholds.get('ml_threshold', 0.70) * 100
                confidence_threshold = thresholds.get('confidence_threshold', 0.75)
                
                # Lower thresholds for known suspicious commands
                if has_suspicious_command:
                    ml_threshold = ml_threshold * 0.7  # 30% lower threshold (70% -> 49%)
                    confidence_threshold = confidence_threshold * 0.8  # 20% lower (75% -> 60%)
                
                # Only alert if BOTH thresholds met
                if adjusted_score >= ml_threshold and result.confidence >= confidence_threshold:
                    self.detection_results.put({
                        'event': event_data,
                        'result': result,
                        'adjusted_score': adjusted_score
                    })
                    
                    self.stats['threats_detected'] += 1
                    self._print_detection(event_data, result, adjusted_score)
        
        except Exception as e:
            pass
    
    def _action_thread(self):
        """Take action on detected threats"""
        print("[ActionEngine] Response system armed...")
        
        while self.running:
            try:
                if not self.detection_results.empty():
                    detection = self.detection_results.get(timeout=0.1)
                    self._handle_detection(detection)
                
                time.sleep(0.1)
                
            except Exception as e:
                time.sleep(1)
    
    def _handle_detection(self, detection: Dict):
        """Take action on a detected threat"""
        try:
            event_data = detection['event']
            result = detection['result']
            adjusted_score = detection.get('adjusted_score', result.threat_score)
            
            # Determine threat level based on adjusted score
            if adjusted_score >= 90:
                threat_level = ThreatLevel.CRITICAL
            elif adjusted_score >= 75:
                threat_level = ThreatLevel.HIGH
            elif adjusted_score >= 60:
                threat_level = ThreatLevel.MEDIUM
            else:
                threat_level = ThreatLevel.LOW
            
            # Get process info
            process_info = {}
            
            if event_data['type'] == 'process':
                proc = event_data['event']
                process_info = {
                    'pid': proc.pid,
                    'name': proc.name,
                    'path': proc.exe_path,
                    'cmdline': proc.cmdline
                }
            else:
                # Memory event
                process_info = {
                    'pid': event_data.get('pid', 0),
                    'name': event_data.get('name', 'Unknown'),
                    'path': event_data.get('path', ''),
                    'cmdline': ''
                }
            
            # Detection details
            detection_details = {
                'threat_score': adjusted_score,
                'confidence': result.confidence,
                'indicators': result.contributing_features[:5]  # Top 5
            }
            
            # Take action
            print(f"\n[*] Taking action for PID {process_info['pid']} ({process_info['name']})")
            print(f"    Threat Level: {threat_level.name}")
            
            actions = self.action_engine.take_action(
                threat_level,
                process_info,
                detection_details
            )
            
            self.stats['actions_taken'] += len(actions)
            
            for action in actions:
                print(f"    [*] {action}")
        
        except Exception as e:
            print(f"[!] Error handling detection: {e}")
    
    def _stats_reporter_thread(self):
        """Periodically report statistics"""
        report_interval = 300  # 5 minutes
        
        while self.running:
            try:
                time.sleep(report_interval)
                if self.running:
                    self._print_stats()
            except:
                pass
    
    def _print_detection(self, event_data: Dict, result, adjusted_score: float):
        """Print detection alert"""
        print("\n" + "="*70)
        print("[!] THREAT DETECTED!")
        print("="*70)
        
        if event_data['type'] == 'process':
            proc = event_data['event']
            print(f"Type: Suspicious Process")
            print(f"PID: {proc.pid}")
            print(f"Name: {proc.name}")
            print(f"Path: {proc.exe_path}")
            if proc.cmdline:
                print(f"Command: {proc.cmdline[:200]}")
        else:
            print(f"Type: Memory Injection")
            print(f"PID: {event_data.get('pid', 'Unknown')}")
            print(f"Indicators: {len(event_data.get('indicators', []))}")
            
            # Show YARA matches if present
            indicators = event_data.get('indicators', [])
            if indicators and hasattr(indicators[0], 'yara_matches'):
                print(f"\nYARA Signature Matches:")
                for indicator in indicators[:3]:  # Show first 3
                    if indicator.yara_matches:
                        for match in indicator.yara_matches[:2]:
                            print(f"  - {match.rule_name} ({match.severity})")
        
        print(f"\nThreat Score: {int(adjusted_score)}/100")
        print(f"Confidence: {result.confidence*100:.1f}%")
        
        # Recommendation
        if adjusted_score >= 90:
            print(f"Recommendation: KILL - Terminate immediately")
        elif adjusted_score >= 75:
            print(f"Recommendation: SUSPEND - Stop and investigate")
        elif adjusted_score >= 60:
            print(f"Recommendation: BLOCK_NETWORK - Isolate from network")
        else:
            print(f"Recommendation: LOG_EVENT - Record for review")
        
        if result.contributing_features:
            print(f"\nKey Indicators:")
            for feature in result.contributing_features[:3]:
                print(f"  - {feature}")
        
        print(f"\nTimestamp: {datetime.now()}")
        print("="*70 + "\n")
    
    def _print_stats(self):
        """Print current statistics"""
        runtime = (datetime.now() - self.stats['start_time']).total_seconds()
        
        print("\n" + "-"*70)
        print("System Statistics")
        print("-"*70)
        print(f"Runtime: {runtime/60:.1f} minutes")
        print(f"Processes scanned: {self.stats['processes_scanned']}")
        print(f"Memory scans: {self.stats['memory_scans']}")
        print(f"Threats detected: {self.stats['threats_detected']}")
        print(f"Actions taken: {self.stats['actions_taken']}")
        print(f"False positives avoided: {self.stats['false_positives_avoided']}")
        print("-"*70 + "\n")
    
    def _print_final_stats(self):
        """Print final statistics on shutdown"""
        runtime = (datetime.now() - self.stats['start_time']).total_seconds()
        
        print("\n" + "="*70)
        print("Final Session Statistics")
        print("="*70)
        print(f"Total Runtime: {runtime/60:.1f} minutes ({runtime:.0f} seconds)")
        print(f"Processes Scanned: {self.stats['processes_scanned']}")
        print(f"Memory Scans: {self.stats['memory_scans']}")
        print(f"Threats Detected: {self.stats['threats_detected']}")
        print(f"Actions Taken: {self.stats['actions_taken']}")
        print(f"False Positives Avoided: {self.stats['false_positives_avoided']}")
        
        if runtime > 0:
            print(f"\nDetection Rate: {self.stats['threats_detected']/(runtime/3600):.2f} threats/hour")
        
        print("="*70 + "\n")


def check_prerequisites():
    """Check if all required packages are installed"""
    print("[*] Checking prerequisites...")
    
    required = ['psutil', 'yara', 'sklearn']
    missing = []
    
    for package in required:
        try:
            if package == 'sklearn':
                import sklearn
            elif package == 'yara':
                import yara
            else:
                __import__(package)
            print(f"    [✔] {package}-python installed")
        except ImportError:
            missing.append(package)
            print(f"    [✘] {package}-python NOT installed")
    
    if missing:
        print(f"\n[!] Missing packages: {', '.join(missing)}")
        print(f"[!] Install with: pip install {' '.join(missing)}")
        return False
    
    return True


def main():
    """Main entry point"""
    print("""
╔═══════════════════════════════════════════════════════╗
║                                                       ║
║        DataDefenceX Real-Time Detection              ║
║        Fileless Malware Prevention System             ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝
    """)
    
    # Check prerequisites
    if not check_prerequisites():
        sys.exit(1)
    
    # Create and start system
    try:
        system = RealtimeDetectionSystem()
        system.start()
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user")
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()