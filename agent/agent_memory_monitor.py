"""
DataDefenceX - Real-Time Memory Monitor Agent
Replaces Volatility with Windows API for live memory scanning
"""

import ctypes
from ctypes import wintypes
import struct
import hashlib
from dataclasses import dataclass
from typing import List, Optional
from datetime import datetime
from agent.agent_yara_scanner import YARAScanner, YARAMatch
# Windows API constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

# Load Windows DLLs
kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll


@dataclass
class MemoryRegion:
    """Represents a memory region in a process"""
    base_address: int
    region_size: int
    protection: int
    type: int
    state: int
    is_suspicious: bool = False
    hash: Optional[str] = None


@dataclass
class InjectionIndicator:
    """Indicators of memory injection"""
    pid: int
    process_name: str
    indicator_type: str  # "rwx_region", "hollowed", "remote_thread", "ape_queue"
    severity: str  # "critical", "high", "medium", "low"
    details: dict
    timestamp: datetime


class MemoryMonitorAgent:
    """
    Real-time memory monitoring agent
    Replaces Volatility for live system scanning
    """
    
    def __init__(self, yara_scanner=None):
        self.whitelist = self._load_whitelist()
        self.scan_cache = {}
        self.last_scan = {}
        # Use provided YARA scanner or create new one
        self.yara_scanner = yara_scanner if yara_scanner else YARAScanner()
    
    def _load_whitelist(self) -> set:
        """Load list of trusted system and common legitimate processes"""
        # Load from JSON whitelist file
        try:
            import json
            with open('config/whitelist.json', 'r') as f:
                whitelist_data = json.load(f)
                processes = whitelist_data.get('trusted_processes', [])
                # Convert to lowercase set
                return {p.lower() for p in processes if isinstance(p, str) and not p.startswith('//')}
        except:
            pass
        
        # Fallback to hardcoded list
        return {
            'system', 'smss.exe', 'csrss.exe', 'wininit.exe',
            'services.exe', 'lsass.exe', 'svchost.exe', 'dwm.exe',
            # Common legitimate applications that use RWX memory
            'chrome.exe', 'msedge.exe', 'firefox.exe', 'code.exe',
            'cursor.exe', 'devenv.exe', 'notepad++.exe', 'claude.exe',
            'onedrive.exe', 'widgets.exe', 'widgetservice.exe',
            'phoneexperiencehost.exe', 'searchexec.exe', 'searchhost.exe',
            'uihost.exe', 'securityhealthsystray.exe', 'nahimic3.exe',
            'nahimicnotifsys.exe', 'msedgewebview2.exe', 'crossdeviceresume.exe',
            'canva.exe', 'canvadesktop.exe'
        }
    
    def scan_process(self, pid: int) -> List[InjectionIndicator]:
        """
        Scan a process for injection indicators
        
        Returns:
            List of injection indicators found
        """
        indicators = []
        
        try:
            # Open process handle
            handle = kernel32.OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                False,
                pid
            )
            
            if not handle:
                return indicators
            
            # Get process name and path
            process_name = self._get_process_name(pid)
            process_path = self._get_process_path(pid)
            
            # Skip whitelisted processes (check both name and path)
            if process_name.lower() in self.whitelist:
                kernel32.CloseHandle(handle)
                return indicators
            
            # Check if process is in trusted path
            if process_path:
                try:
                    import json
                    with open('config/whitelist.json', 'r') as f:
                        whitelist_data = json.load(f)
                        trusted_paths = whitelist_data.get('trusted_paths', [])
                        for trusted_path in trusted_paths:
                            if isinstance(trusted_path, str) and process_path.lower().startswith(trusted_path.lower()):
                                kernel32.CloseHandle(handle)
                                return indicators
                except:
                    pass
            
            # 1. Check for RWX memory regions (highly suspicious)
            # Only flag if there are multiple large regions or very large single region
            rwx_regions = self._find_rwx_regions(handle, pid)
            if rwx_regions:
                total_size = sum(r.region_size for r in rwx_regions)
                region_count = len(rwx_regions)
                
                # Filter: Only flag if suspicious pattern
                # - Multiple regions (>2) OR
                # - Very large single region (>10MB) OR
                # - Multiple medium regions (>3) with total >5MB
                is_suspicious = (
                    region_count > 2 or
                    (region_count == 1 and total_size > 10 * 1024 * 1024) or
                    (region_count > 3 and total_size > 5 * 1024 * 1024)
                )
                
                if is_suspicious:
                    indicators.append(InjectionIndicator(
                        pid=pid,
                        process_name=process_name,
                        indicator_type="rwx_region",
                        severity="high" if region_count > 3 or total_size > 10 * 1024 * 1024 else "medium",
                        details={
                            'region_count': region_count,
                            'total_size': total_size,
                            'regions': [
                                {'base': hex(r.base_address), 'size': r.region_size}
                                for r in rwx_regions[:5]  # Limit to first 5
                            ]
                        },
                        timestamp=datetime.now()
                    ))
            
            # 2. Check for process hollowing
            if self._is_process_hollowed(handle, pid):
                indicators.append(InjectionIndicator(
                    pid=pid,
                    process_name=process_name,
                    indicator_type="hollowed",
                    severity="critical",
                    details={
                        'description': 'Process image mismatch between PEB and disk'
                    },
                    timestamp=datetime.now()
                ))
            
            # 3. Check for remote threads
            remote_threads = self._find_remote_threads(pid)
            if remote_threads:
                indicators.append(InjectionIndicator(
                    pid=pid,
                    process_name=process_name,
                    indicator_type="remote_thread",
                    severity="critical",
                    details={
                        'thread_count': len(remote_threads),
                        'threads': remote_threads
                    },
                    timestamp=datetime.now()
                ))
            
            # 4. Check for APC queue injection
            if self._detect_apc_injection(handle, pid):
                indicators.append(InjectionIndicator(
                    pid=pid,
                    process_name=process_name,
                    indicator_type="apc_queue",
                    severity="high",
                    details={
                        'description': 'Suspicious APC queue activity detected'
                    },
                    timestamp=datetime.now()
                ))
            
            # 5. YARA signature scanning on suspicious regions
            if rwx_regions:
                yara_matches = []
                for region in rwx_regions:
                    # Read memory region (limit to 1MB per region for performance)
                    memory_data = self.read_memory_region(
                        handle, 
                        region.base_address, 
                        min(region.region_size, 1024*1024)
                    )
                    if memory_data:
                        # Pass process info to YARA scanner for whitelist checking
                        matches = self.yara_scanner.scan_memory_region(memory_data, {
                            'base_address': region.base_address,
                            'size': region.region_size,
                            'protection': region.protection,
                            'process_name': process_name,
                            'exe_path': process_path
                        })
                        yara_matches.extend(matches)
                
                if yara_matches:
                    # Group matches by severity
                    critical_matches = [m for m in yara_matches if m.severity == 'critical']
                    high_matches = [m for m in yara_matches if m.severity == 'high']
                    
                    if critical_matches or high_matches:
                        indicators.append(InjectionIndicator(
                            pid=pid,
                            process_name=process_name,
                            indicator_type="yara_signature",
                            severity="critical" if critical_matches else "high",
                            details={
                                'match_count': len(yara_matches),
                                'critical_matches': len(critical_matches),
                                'high_matches': len(high_matches),
                                'rules_matched': [m.rule_name for m in yara_matches],
                                'matches': [
                                    {
                                        'rule': m.rule_name,
                                        'severity': m.severity,
                                        'description': m.description
                                    }
                                    for m in yara_matches
                                ]
                            },
                            timestamp=datetime.now()
                        ))
            
            kernel32.CloseHandle(handle)
            
        except Exception as e:
            print(f"[!] Error scanning PID {pid}: {e}")
        
        return indicators
    
    def _find_rwx_regions(self, handle, pid: int) -> List[MemoryRegion]:
        """
        Find memory regions with RWX (Read-Write-Execute) permissions
        These are highly suspicious as legitimate code shouldn't be writable
        """
        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD)
            ]
        
        rwx_regions = []
        address = 0
        max_address = 0x7FFFFFFF0000  # Max user-mode address on x64
        
        while address < max_address:
            mbi = MEMORY_BASIC_INFORMATION()
            
            # Query memory region
            result = kernel32.VirtualQueryEx(
                handle,
                ctypes.c_void_p(address),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi)
            )
            
            if result == 0:
                break
            
            # Check for RWX permissions on committed private memory
            if (mbi.State == MEM_COMMIT and 
                mbi.Type == MEM_PRIVATE and
                (mbi.Protect == PAGE_EXECUTE_READWRITE or 
                 mbi.Protect == PAGE_EXECUTE_WRITECOPY)):
                
                region = MemoryRegion(
                    base_address=mbi.BaseAddress,
                    region_size=mbi.RegionSize,
                    protection=mbi.Protect,
                    type=mbi.Type,
                    state=mbi.State,
                    is_suspicious=True
                )
                
                rwx_regions.append(region)
            
            # Move to next region
            address += mbi.RegionSize
        
        return rwx_regions
    
    def _is_process_hollowed(self, handle, pid: int) -> bool:
        """
        Detect process hollowing by comparing PEB image path with actual disk file
        
        Process hollowing: Attacker creates legitimate process in suspended state,
        unmaps its memory, and writes malicious code into it
        """
        try:
            # Get PEB (Process Environment Block) address
            class PROCESS_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("Reserved1", ctypes.c_void_p),
                    ("PebBaseAddress", ctypes.c_void_p),
                    ("Reserved2", ctypes.c_void_p * 2),
                    ("UniqueProcessId", ctypes.c_void_p),
                    ("Reserved3", ctypes.c_void_p)
                ]
            
            pbi = PROCESS_BASIC_INFORMATION()
            ntdll.NtQueryInformationProcess(
                handle,
                0,  # ProcessBasicInformation
                ctypes.byref(pbi),
                ctypes.sizeof(pbi),
                None
            )
            
            # Read PEB to get image base address
            # In real implementation, would compare PE header in memory
            # with PE header on disk to detect mismatches
            
            # Simplified check: Look for mismatched image paths
            # (Full implementation requires reading PEB structure)
            
            return False  # Placeholder - implement full PE comparison
            
        except Exception as e:
            return False
    
    def _find_remote_threads(self, pid: int) -> List[dict]:
        """
        Detect threads created by other processes (CreateRemoteThread injection)
        """
        remote_threads = []
        
        try:
            # Use NtQuerySystemInformation to enumerate threads
            # and check if thread start address is outside process modules
            
            # This is a simplified version
            # Full implementation requires SYSTEM_PROCESS_INFORMATION parsing
            
            pass
        except Exception as e:
            pass
        
        return remote_threads
    
    def _detect_apc_injection(self, handle, pid: int) -> bool:
        """
        Detect APC (Asynchronous Procedure Call) queue injection
        Used by sophisticated malware to inject code
        """
        # Check for unusual APC queue activity
        # Requires reading thread context and inspecting APC queue
        
        return False  # Placeholder
    
    def _get_process_path(self, pid: int) -> str:
        """Get process executable path"""
        try:
            import psutil
            proc = psutil.Process(pid)
            return proc.exe() if proc.exe() else ''
        except:
            return ''
    
    def _get_process_name(self, pid: int) -> str:
        """Get process name from PID"""
        try:
            import psutil
            process = psutil.Process(pid)
            return process.name()
        except:
            return "unknown"
    
    def read_memory_region(self, handle, base_address: int, size: int) -> Optional[bytes]:
        """
        Read memory from a process
        Used for YARA scanning of suspicious regions
        """
        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t()
        
        result = kernel32.ReadProcessMemory(
            handle,
            ctypes.c_void_p(base_address),
            buffer,
            size,
            ctypes.byref(bytes_read)
        )
        
        if result:
            return buffer.raw[:bytes_read.value]
        return None
    
    def calculate_region_hash(self, data: bytes) -> str:
        """Calculate SHA256 hash of memory region for change detection"""
        return hashlib.sha256(data).hexdigest()


class ContinuousMonitor:
    """
    Continuous monitoring service that scans all processes periodically
    """
    
    def __init__(self, scan_interval: int = 60):
        self.agent = MemoryMonitorAgent()
        self.scan_interval = scan_interval
        self.running = False
    
    def start(self):
        """Start continuous monitoring"""
        import psutil
        import time
        
        self.running = True
        print("[*] Starting continuous memory monitoring...")
        
        while self.running:
            try:
                # Get all running processes
                for proc in psutil.process_iter(['pid', 'name']):
                    pid = proc.info['pid']
                    
                    # Skip system processes
                    if pid in [0, 4]:
                        continue
                    
                    # Scan process
                    indicators = self.agent.scan_process(pid)
                    
                    # Report findings
                    if indicators:
                        self._handle_indicators(indicators)
                
                # Sleep before next scan
                time.sleep(self.scan_interval)
                
            except KeyboardInterrupt:
                self.running = False
                print("\n[*] Monitoring stopped")
                break
            except Exception as e:
                print(f"[!] Monitoring error: {e}")
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
    
    def _handle_indicators(self, indicators: List[InjectionIndicator]):
        """
        Handle detected indicators
        In real-time system, this would send to detection engine
        """
        for indicator in indicators:
            severity_color = {
                'critical': '\033[91m',  # Red
                'high': '\033[93m',      # Yellow
                'medium': '\033[94m',    # Blue
                'low': '\033[92m'        # Green
            }
            
            color = severity_color.get(indicator.severity, '')
            reset = '\033[0m'
            
            print(f"\n{color}[!] INJECTION DETECTED!{reset}")
            print(f"    PID: {indicator.pid}")
            print(f"    Process: {indicator.process_name}")
            print(f"    Type: {indicator.indicator_type}")
            print(f"    Severity: {indicator.severity.upper()}")
            print(f"    Details: {indicator.details}")
            print(f"    Timestamp: {indicator.timestamp}")


def test_memory_monitor():
    """Test the memory monitor with current processes"""
    import psutil
    
    print("\n=== DataDefenceX Memory Monitor Test ===\n")
    
    agent = MemoryMonitorAgent()
    
    # Scan first 10 non-system processes
    scanned = 0
    for proc in psutil.process_iter(['pid', 'name']):
        if scanned >= 10:
            break
        
        pid = proc.info['pid']
        name = proc.info['name']
        
        if pid in [0, 4]:  # Skip System and Idle
            continue
        
        print(f"[*] Scanning PID {pid} ({name})...")
        
        indicators = agent.scan_process(pid)
        
        if indicators:
            print(f"    âœ— Found {len(indicators)} indicator(s)!")
            for ind in indicators:
                print(f"      - {ind.indicator_type} ({ind.severity})")
        else:
            print("    ✔ Clean")
        
        scanned += 1


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--continuous":
        # Run continuous monitoring
        monitor = ContinuousMonitor(scan_interval=30)  # Scan every 30 seconds
        monitor.start()
    else:
        # Run test scan
        test_memory_monitor()
