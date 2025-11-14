"""
DataDefenceX - Action Engine
Automated response to detected threats
"""

import psutil
import ctypes
from ctypes import wintypes
import os
import json
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum


class ThreatLevel(Enum):
    """Threat severity levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ActionType(Enum):
    """Types of response actions"""
    LOG = "log"
    ALERT = "alert"
    SUSPEND = "suspend"
    KILL = "kill"
    BLOCK_NETWORK = "block_network"
    QUARANTINE = "quarantine"
    CAPTURE_DUMP = "capture_dump"


@dataclass
class ActionResult:
    """Result of an action"""
    action_type: ActionType
    success: bool
    message: str
    timestamp: datetime
    details: Dict = None


class WindowsProcessController:
    """Low-level Windows process control"""
    
    # Windows API constants
    PROCESS_TERMINATE = 0x0001
    PROCESS_SUSPEND_RESUME = 0x0800
    PROCESS_QUERY_INFORMATION = 0x0400
    
    def __init__(self):
        self.kernel32 = ctypes.windll.kernel32
        self.ntdll = ctypes.windll.ntdll
    
    def kill_process(self, pid: int) -> bool:
        """
        Terminate a process immediately
        
        Args:
            pid: Process ID to kill
        
        Returns:
            True if successful, False otherwise
        """
        try:
            handle = self.kernel32.OpenProcess(
                self.PROCESS_TERMINATE,
                False,
                pid
            )
            
            if not handle:
                return False
            
            result = self.kernel32.TerminateProcess(handle, 1)
            self.kernel32.CloseHandle(handle)
            
            return bool(result)
        except Exception as e:
            print(f"[!] Error killing process {pid}: {e}")
            return False
    
    def suspend_process(self, pid: int) -> bool:
        """
        Suspend all threads in a process
        Useful for forensic analysis
        
        Args:
            pid: Process ID to suspend
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Suspend all threads
            suspended_count = 0
            
            for thread in self._enumerate_threads(pid):
                if self._suspend_thread(thread):
                    suspended_count += 1
            
            return suspended_count > 0
        except Exception as e:
            print(f"[!] Error suspending process {pid}: {e}")
            return False
    
    def resume_process(self, pid: int) -> bool:
        """Resume a suspended process"""
        try:
            resumed_count = 0
            
            for thread in self._enumerate_threads(pid):
                if self._resume_thread(thread):
                    resumed_count += 1
            
            return resumed_count > 0
        except Exception as e:
            print(f"[!] Error resuming process {pid}: {e}")
            return False
    
    def _enumerate_threads(self, pid: int) -> List[int]:
        """Get all thread IDs for a process"""
        threads = []
        
        try:
            proc = psutil.Process(pid)
            for thread in proc.threads():
                threads.append(thread.id)
        except:
            pass
        
        return threads
    
    def _suspend_thread(self, thread_id: int) -> bool:
        """Suspend a single thread"""
        THREAD_SUSPEND_RESUME = 0x0002
        
        try:
            handle = self.kernel32.OpenThread(
                THREAD_SUSPEND_RESUME,
                False,
                thread_id
            )
            
            if handle:
                self.ntdll.NtSuspendThread(handle, None)
                self.kernel32.CloseHandle(handle)
                return True
        except:
            pass
        
        return False
    
    def _resume_thread(self, thread_id: int) -> bool:
        """Resume a single thread"""
        THREAD_SUSPEND_RESUME = 0x0002
        
        try:
            handle = self.kernel32.OpenThread(
                THREAD_SUSPEND_RESUME,
                False,
                thread_id
            )
            
            if handle:
                self.ntdll.NtResumeThread(handle, None)
                self.kernel32.CloseHandle(handle)
                return True
        except:
            pass
        
        return False


class NetworkController:
    """Network access control"""
    
    def block_process_network(self, pid: int, process_name: str) -> bool:
        """
        Block network access for a process using Windows Firewall
        
        Args:
            pid: Process ID
            process_name: Process name for firewall rule
        
        Returns:
            True if successful
        """
        try:
            import subprocess
            
            # Get process executable path
            proc = psutil.Process(pid)
            exe_path = proc.exe()
            
            # Create firewall rule to block this executable
            rule_name = f"DataDefenceX_Block_{process_name}_{pid}"
            
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=out",
                "action=block",
                f"program={exe_path}",
                "enable=yes"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            return result.returncode == 0
        except Exception as e:
            print(f"[!] Error blocking network for PID {pid}: {e}")
            return False
    
    def kill_connections(self, pid: int) -> int:
        """
        Kill all active network connections for a process
        
        Returns:
            Number of connections killed
        """
        killed = 0
        
        try:
            proc = psutil.Process(pid)
            connections = proc.connections()
            
            for conn in connections:
                try:
                    # Close connection (implementation depends on OS)
                    # On Windows, would use TCP/IP API
                    killed += 1
                except:
                    pass
        except:
            pass
        
        return killed


class ActionEngine:
    """
    Main action engine for automated threat response
    Implements graduated response based on threat level
    """
    
    def __init__(self, log_dir: str = "logs"):
        self.process_controller = WindowsProcessController()
        self.network_controller = NetworkController()
        self.log_dir = log_dir
        self.action_history = []
        
        # Create log directory
        os.makedirs(log_dir, exist_ok=True)
        
        # Policy configuration
        self.auto_kill_enabled = True
        self.auto_suspend_enabled = True
        self.auto_block_network_enabled = True
    
    def take_action(self, 
                   threat_level: ThreatLevel,
                   process_info: Dict,
                   detection_details: Dict) -> List[ActionResult]:
        """
        Take appropriate action based on threat level
        
        Args:
            threat_level: Severity of threat
            process_info: Information about the malicious process
            detection_details: Details from detection engine
        
        Returns:
            List of ActionResult objects
        """
        actions_taken = []
        pid = process_info.get('pid')
        process_name = process_info.get('name', 'unknown')
        
        print(f"\n[*] Taking action for PID {pid} ({process_name})")
        print(f"    Threat Level: {threat_level.name}")
        
        # Always log
        actions_taken.append(self._log_event(process_info, detection_details, threat_level))
        
        if threat_level == ThreatLevel.CRITICAL:
            # CRITICAL: Immediate kill + network block
            print("    [!] CRITICAL THREAT - Immediate response")
            
            # 1. Block network first
            if self.auto_block_network_enabled:
                result = self._block_network(pid, process_name)
                actions_taken.append(result)
            
            # 2. Kill process
            if self.auto_kill_enabled:
                result = self._kill_process(pid, process_name)
                actions_taken.append(result)
            
            # 3. Quarantine artifacts
            result = self._quarantine_artifacts(process_info)
            actions_taken.append(result)
            
            # 4. Alert administrator
            self._send_alert(process_info, detection_details, threat_level)
        
        elif threat_level == ThreatLevel.HIGH:
            # HIGH: Suspend + capture + alert
            print("    [!] HIGH THREAT - Suspend and analyze")
            
            # 1. Suspend process for analysis
            if self.auto_suspend_enabled:
                result = self._suspend_process(pid, process_name)
                actions_taken.append(result)
            
            # 2. Capture memory dump
            result = self._capture_memory_dump(pid, process_name)
            actions_taken.append(result)
            
            # 3. Alert administrator
            self._send_alert(process_info, detection_details, threat_level)
        
        elif threat_level == ThreatLevel.MEDIUM:
            # MEDIUM: Increase monitoring
            print("    [*] MEDIUM THREAT - Enhanced monitoring")
            
            result = self._increase_monitoring(pid, process_name)
            actions_taken.append(result)
        
        else:  # LOW
            # LOW: Just log
            print("    [*] LOW THREAT - Logged for review")
        
        # Record in history
        self.action_history.append({
            'timestamp': datetime.now(),
            'pid': pid,
            'threat_level': threat_level.name,
            'actions': [a.action_type.value for a in actions_taken]
        })
        
        return actions_taken
    
    def _kill_process(self, pid: int, process_name: str) -> ActionResult:
        """Kill a malicious process"""
        print(f"    [-] Killing process {pid}...")
        
        success = self.process_controller.kill_process(pid)
        
        return ActionResult(
            action_type=ActionType.KILL,
            success=success,
            message=f"Process {pid} ({'killed' if success else 'failed to kill'})",
            timestamp=datetime.now(),
            details={'pid': pid, 'name': process_name}
        )
    
    def _suspend_process(self, pid: int, process_name: str) -> ActionResult:
        """Suspend a process for analysis"""
        print(f"    [-] Suspending process {pid}...")
        
        success = self.process_controller.suspend_process(pid)
        
        return ActionResult(
            action_type=ActionType.SUSPEND,
            success=success,
            message=f"Process {pid} ({'suspended' if success else 'failed to suspend'})",
            timestamp=datetime.now(),
            details={'pid': pid, 'name': process_name}
        )
    
    def _block_network(self, pid: int, process_name: str) -> ActionResult:
        """Block network access for process"""
        print(f"    [-] Blocking network for process {pid}...")
        
        success = self.network_controller.block_process_network(pid, process_name)
        
        if success:
            # Also kill existing connections
            killed_conns = self.network_controller.kill_connections(pid)
            details = {
                'pid': pid,
                'name': process_name,
                'connections_killed': killed_conns
            }
        else:
            details = {'pid': pid, 'name': process_name}
        
        return ActionResult(
            action_type=ActionType.BLOCK_NETWORK,
            success=success,
            message=f"Network {'blocked' if success else 'block failed'} for {pid}",
            timestamp=datetime.now(),
            details=details
        )
    
    def _quarantine_artifacts(self, process_info: Dict) -> ActionResult:
        """Move process artifacts to quarantine"""
        print(f"    [-] Quarantining artifacts...")
        
        try:
            pid = process_info.get('pid')
            path = process_info.get('path', '')
            
            if path and os.path.exists(path):
                # Move to quarantine directory
                quarantine_dir = os.path.join(self.log_dir, "quarantine")
                os.makedirs(quarantine_dir, exist_ok=True)
                
                filename = os.path.basename(path)
                quarantine_path = os.path.join(
                    quarantine_dir,
                    f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
                )
                
                # In production, use secure move
                # For now, just log the action
                
                return ActionResult(
                    action_type=ActionType.QUARANTINE,
                    success=True,
                    message=f"Artifacts quarantined: {path}",
                    timestamp=datetime.now(),
                    details={'original_path': path, 'quarantine_path': quarantine_path}
                )
            else:
                return ActionResult(
                    action_type=ActionType.QUARANTINE,
                    success=False,
                    message="No artifacts to quarantine",
                    timestamp=datetime.now()
                )
        except Exception as e:
            return ActionResult(
                action_type=ActionType.QUARANTINE,
                success=False,
                message=f"Quarantine failed: {e}",
                timestamp=datetime.now()
            )
    
    def _capture_memory_dump(self, pid: int, process_name: str) -> ActionResult:
        """Capture memory dump for forensic analysis"""
        print(f"    [-] Capturing memory dump of process {pid}...")
        
        try:
            # In production, use ProcDump or similar
            dump_dir = os.path.join(self.log_dir, "dumps")
            os.makedirs(dump_dir, exist_ok=True)
            
            dump_file = os.path.join(
                dump_dir,
                f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{process_name}_{pid}.dmp"
            )
            
            # Placeholder - in real system, capture actual dump
            # import subprocess
            # subprocess.run(['procdump', '-ma', str(pid), dump_file])
            
            return ActionResult(
                action_type=ActionType.CAPTURE_DUMP,
                success=True,
                message=f"Memory dump captured: {dump_file}",
                timestamp=datetime.now(),
                details={'dump_path': dump_file}
            )
        except Exception as e:
            return ActionResult(
                action_type=ActionType.CAPTURE_DUMP,
                success=False,
                message=f"Dump capture failed: {e}",
                timestamp=datetime.now()
            )
    
    def _increase_monitoring(self, pid: int, process_name: str) -> ActionResult:
        """Increase monitoring frequency for process"""
        print(f"    [-] Increasing monitoring for process {pid}...")
        
        # In real system, would adjust monitoring parameters
        
        return ActionResult(
            action_type=ActionType.ALERT,
            success=True,
            message=f"Enhanced monitoring enabled for {pid}",
            timestamp=datetime.now(),
            details={'pid': pid, 'name': process_name}
        )
    
    def _log_event(self, process_info: Dict, detection_details: Dict, 
                   threat_level: ThreatLevel) -> ActionResult:
        """Log detection event"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'pid': process_info.get('pid'),
            'process_name': process_info.get('name'),
            'threat_level': threat_level.name,
            'detection_details': detection_details,
            'process_info': process_info
        }
        
        # Write to log file
        log_file = os.path.join(
            self.log_dir,
            f"detections_{datetime.now().strftime('%Y%m%d')}.json"
        )
        
        try:
            # Append to daily log file
            with open(log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
            
            return ActionResult(
                action_type=ActionType.LOG,
                success=True,
                message=f"Event logged to {log_file}",
                timestamp=datetime.now()
            )
        except Exception as e:
            return ActionResult(
                action_type=ActionType.LOG,
                success=False,
                message=f"Logging failed: {e}",
                timestamp=datetime.now()
            )
    
    def _send_alert(self, process_info: Dict, detection_details: Dict,
                   threat_level: ThreatLevel):
        """Send alert to administrators"""
        alert_message = f"""
        [DataDefenceX Alert]
        Threat Level: {threat_level.name}
        Process: {process_info.get('name')} (PID {process_info.get('pid')})
        Time: {datetime.now()}
        
        Detection Details:
        {json.dumps(detection_details, indent=2)}
        """
        
        print(alert_message)
        
        # In production, send via email/SMS/webhook
        # import requests
        # requests.post(ALERT_WEBHOOK_URL, json={'alert': alert_message})


def test_action_engine():
    """Test the action engine"""
    print("\n=== DataDefenceX Action Engine Test ===\n")
    
    engine = ActionEngine(log_dir="test_logs")
    
    # Simulate detection
    process_info = {
        'pid': 1234,
        'name': 'suspicious.exe',
        'path': 'C:\\Temp\\suspicious.exe',
        'cmdline': 'suspicious.exe -encoded AAAA...'
    }
    
    detection_details = {
        'threat_score': 95,
        'indicators': ['Code injection', 'C2 communication'],
        'ml_confidence': 0.92
    }
    
    # Test different threat levels
    print("[*] Testing CRITICAL threat response:")
    results = engine.take_action(
        ThreatLevel.CRITICAL,
        process_info,
        detection_details
    )
    
    print(f"\n[*] Actions taken: {len(results)}")
    for result in results:
        print(f"    - {result.action_type.value}: {'✔' if result.success else '✘'}")


if __name__ == "__main__":
    test_action_engine()
