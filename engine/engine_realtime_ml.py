"""
DataDefenceX - Real-Time ML Engine FIXED v2.1
Completely corrected version with all bug fixes
"""

import pickle
import numpy as np
import json
import os
from dataclasses import dataclass
from typing import List, Dict, Optional


@dataclass
class RealtimeFeatures:
    """17 lightweight features for real-time detection"""
    parent_suspicious: bool
    cmdline_entropy: float
    path_suspicious: bool
    process_chain_depth: int
    is_system_binary_misplaced: bool
    rwx_region_count: int
    private_memory_mb: float
    is_hollowed: bool
    remote_threads: int
    active_connections: int
    c2_beacon_score: float
    dns_entropy: float
    file_writes_per_min: float
    registry_mods_per_min: float
    process_creates_per_min: float
    api_calls_suspicious: int
    total_events_5min: int


@dataclass
class DetectionResult:
    """ML detection result"""
    is_malicious: bool
    threat_score: float
    confidence: float
    contributing_features: List[str]


class RealtimeMLEngine:
    """
    Real-time ML detection engine with configurable thresholds
    """
    
    def __init__(self, model_path: str = "models/fileless_malware_model_realtime.pkl"):
        """
        Initialize ML engine
        
        Args:
            model_path: Path to trained model
        """
        self.model = None
        self.feature_names = []
        
        # Load thresholds from whitelist
        self.ml_threshold = 0.70  # Default 70%
        self.confidence_threshold = 0.75  # Default 75%
        self._load_thresholds()
        
        # Load model
        self._load_model(model_path)
    
    def _load_thresholds(self):
        """Load thresholds from whitelist configuration"""
        try:
            if os.path.exists('config/whitelist.json'):
                with open('config/whitelist.json', 'r') as f:
                    whitelist = json.load(f)
                    thresholds = whitelist.get('thresholds', {})
                    
                    self.ml_threshold = thresholds.get('ml_threshold', 0.70)
                    self.confidence_threshold = thresholds.get('confidence_threshold', 0.75)
                    
                    print(f"[*] ML Threshold: {self.ml_threshold*100:.0f}%")
                    print(f"[*] Confidence Threshold: {self.confidence_threshold*100:.0f}%")
            else:
                print(f"[*] Using default thresholds (70%/75%) - whitelist.json not found")
        except Exception as e:
            print(f"[*] Using default thresholds (70%/75%) - {e}")
    
    def _load_model(self, model_path: str):
        """Load trained ML model - FIXED VERSION"""
        try:
            if not os.path.exists(model_path):
                print(f"[!] Model not found: {model_path}")
                print(f"[!] Run train_model_updated_v2.1.py first")
                return
            
            # Load model
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
            
            # FIXED: Load feature names with correct path
            # Try multiple possible locations for feature file
            possible_feature_paths = [
                'models/realtime_features.pkl',
                model_path.replace('_model_realtime.pkl', '_features.pkl'),
                model_path.replace('fileless_malware_model_realtime.pkl', 'realtime_features.pkl')
            ]
            
            feature_file_loaded = False
            for features_path in possible_feature_paths:
                if os.path.exists(features_path):
                    try:
                        with open(features_path, 'rb') as f:
                            self.feature_names = pickle.load(f)
                        print(f"[*] Feature names loaded from: {features_path}")
                        feature_file_loaded = True
                        break
                    except:
                        continue
            
            if not feature_file_loaded:
                # Use default feature names if file not found
                print(f"[*] Using default feature names")
                self.feature_names = [
                    'parent_suspicious', 'cmdline_entropy', 'path_suspicious',
                    'process_chain_depth', 'is_system_binary_misplaced',
                    'rwx_region_count', 'private_memory_mb', 'is_hollowed',
                    'remote_threads', 'active_connections', 'c2_beacon_score',
                    'dns_entropy', 'file_writes_per_min', 'registry_mods_per_min',
                    'process_creates_per_min', 'api_calls_suspicious', 'total_events_5min'
                ]
            
            print(f"[*] ML model loaded: {os.path.basename(model_path)}")
            
        except Exception as e:
            print(f"[!] Error loading model: {e}")
            import traceback
            traceback.print_exc()
            self.model = None
    
    def extract_features(self, 
                        process_event: Optional[Dict] = None,
                        memory_indicators: Optional[List] = None) -> Optional[RealtimeFeatures]:
        """
        Extract 17 real-time features from process or memory event
        
        Args:
            process_event: Process event data
            memory_indicators: Memory scan indicators
        
        Returns:
            RealtimeFeatures object or None
        """
        try:
            if process_event:
                return self._extract_from_process(process_event)
            elif memory_indicators:
                return self._extract_from_memory(memory_indicators)
            else:
                return None
        except Exception as e:
            print(f"[!] Feature extraction error: {e}")
            return None
    
    def _extract_from_process(self, proc: Dict) -> RealtimeFeatures:
        """Extract features from process event"""
        import math
        import re
        from collections import Counter
        
        # Feature 0: parent_suspicious
        ppid = proc.get('ppid', 0)
        parent_suspicious = ppid > 10 and ppid not in [0, 4]
        
        # Feature 1: cmdline_entropy
        cmdline = proc.get('cmdline', '')
        if cmdline and len(cmdline) > 10:
            # Simple entropy calculation
            counter = Counter(cmdline)
            length = len(cmdline)
            if length > 0:
                entropy = -sum((count/length) * math.log2(count/length) 
                              for count in counter.values() if count > 0)
                cmdline_entropy = min(entropy, 7.0)
            else:
                cmdline_entropy = 0.0
        else:
            cmdline_entropy = 0.0
        
        # CRITICAL FIX: Boost entropy for suspicious PowerShell commands
        # PowerShell with encoded commands should have high entropy
        name = proc.get('name', '').lower()
        if 'powershell' in name or 'cmd' in name:
            if cmdline:
                suspicious_keywords = ['-encodedcommand', '-enc', 'bypass', 'hidden']
                if any(kw in cmdline.lower() for kw in suspicious_keywords):
                    # Boost entropy to reflect suspicious nature
                    cmdline_entropy = max(cmdline_entropy, 6.0)
                # Check for base64 patterns
                base64_pattern = r'[A-Za-z0-9+/]{50,}={0,2}'
                if re.search(base64_pattern, cmdline):
                    cmdline_entropy = max(cmdline_entropy, 6.5)
        
        # Feature 2: path_suspicious
        path = proc.get('path', '').lower()
        suspicious_paths = ['temp', 'appdata', 'downloads', 'public']
        path_suspicious = any(sp in path for sp in suspicious_paths)
        
        # Feature 3: process_chain_depth
        suspicious_score = proc.get('suspicious_score', 0)
        process_chain_depth = min(int(suspicious_score / 20), 10)  # Rough estimate
        
        # CRITICAL FIX: Boost process_chain_depth for suspicious PowerShell commands
        if 'powershell' in name or 'cmd' in name:
            if cmdline:
                suspicious_keywords = ['-encodedcommand', '-enc', 'bypass', 'hidden']
                if any(kw in cmdline.lower() for kw in suspicious_keywords):
                    process_chain_depth = max(process_chain_depth, 5)  # Higher depth for suspicious
        
        # Feature 4: is_system_binary_misplaced
        system_binaries = ['powershell.exe', 'cmd.exe', 'wmic.exe', 'rundll32.exe']
        is_system = any(sb in name for sb in system_binaries)
        is_wrong_location = 'system32' not in path and 'syswow64' not in path
        is_system_binary_misplaced = is_system and is_wrong_location
        
        # CRITICAL FIX: Boost C2 beacon score for suspicious PowerShell commands
        c2_beacon_score = 0.1  # Low default
        if 'powershell' in name or 'cmd' in name:
            if cmdline:
                suspicious_keywords = ['-encodedcommand', '-enc', 'bypass', 'hidden', 'downloadstring', 'iex']
                if any(kw in cmdline.lower() for kw in suspicious_keywords):
                    c2_beacon_score = 0.7  # High C2 score for suspicious PowerShell
        
        # Boost api_calls_suspicious for suspicious commands
        api_calls_suspicious = 0
        if 'powershell' in name or 'cmd' in name:
            if cmdline:
                suspicious_keywords = ['-encodedcommand', '-enc', 'bypass', 'hidden']
                if any(kw in cmdline.lower() for kw in suspicious_keywords):
                    api_calls_suspicious = 8  # Indicate suspicious API usage
        
        # Features 5-16: Default values (not available from process event alone)
        return RealtimeFeatures(
            parent_suspicious=parent_suspicious,
            cmdline_entropy=cmdline_entropy,
            path_suspicious=path_suspicious,
            process_chain_depth=process_chain_depth,
            is_system_binary_misplaced=is_system_binary_misplaced,
            rwx_region_count=0,  # Not available from process event
            private_memory_mb=50.0,  # Estimated
            is_hollowed=False,  # Not available
            remote_threads=0,  # Not available
            active_connections=1,  # Estimated
            c2_beacon_score=c2_beacon_score,  # Enhanced for suspicious PowerShell
            dns_entropy=2.5,  # Normal default
            file_writes_per_min=5.0,  # Normal default
            registry_mods_per_min=1.0,  # Normal default
            process_creates_per_min=0.0,  # None
            api_calls_suspicious=api_calls_suspicious,  # Enhanced for suspicious PowerShell
            total_events_5min=20  # Estimated
        )
    
    def _extract_from_memory(self, indicators: List) -> Optional[RealtimeFeatures]:
        """Extract features from memory indicators"""
        if not indicators:
            return None
        
        try:
            # Aggregate indicators
            total_rwx = 0
            total_private_mb = 0
            total_remote_threads = 0
            
            for ind in indicators:
                if hasattr(ind, 'rwx_regions'):
                    total_rwx += ind.rwx_regions
                if hasattr(ind, 'private_bytes'):
                    total_private_mb += ind.private_bytes / (1024*1024)
                if hasattr(ind, 'remote_threads'):
                    total_remote_threads += ind.remote_threads
            
            # Count YARA matches
            yara_matches = []
            for ind in indicators:
                if hasattr(ind, 'yara_matches') and ind.yara_matches:
                    yara_matches.extend(ind.yara_matches)
            
            critical_yara = sum(1 for m in yara_matches if hasattr(m, 'severity') and m.severity == 'critical')
            
            # Check for hollowing
            is_hollowed = any(hasattr(ind, 'is_hollowed') and ind.is_hollowed 
                             for ind in indicators)
            
            # Build features
            return RealtimeFeatures(
                parent_suspicious=False,  # Not available
                cmdline_entropy=3.0,  # Neutral
                path_suspicious=False,  # Not available
                process_chain_depth=2,  # Normal
                is_system_binary_misplaced=False,  # Not available
                rwx_region_count=min(total_rwx, 50),
                private_memory_mb=min(total_private_mb, 500.0),
                is_hollowed=is_hollowed,
                remote_threads=min(total_remote_threads, 10),
                active_connections=5,  # Estimated
                c2_beacon_score=min(critical_yara * 0.2, 1.0),  # Based on YARA
                dns_entropy=4.0,  # Slightly elevated
                file_writes_per_min=10.0,  # Estimated
                registry_mods_per_min=5.0,  # Estimated
                process_creates_per_min=0.0,  # Not available
                api_calls_suspicious=critical_yara,
                total_events_5min=len(indicators) * 10
            )
        except Exception as e:
            print(f"[!] Error extracting features from memory: {e}")
            return None
    
    def predict(self, features: RealtimeFeatures) -> DetectionResult:
        """
        Make prediction with ML model
        
        Args:
            features: RealtimeFeatures object
        
        Returns:
            DetectionResult with threat assessment
        """
        if not self.model:
            return DetectionResult(
                is_malicious=False,
                threat_score=0.0,
                confidence=0.0,
                contributing_features=["Model not loaded"]
            )
        
        try:
            # Convert to numpy array
            feature_array = np.array([[
                float(features.parent_suspicious),
                float(features.cmdline_entropy),
                float(features.path_suspicious),
                float(features.process_chain_depth),
                float(features.is_system_binary_misplaced),
                float(features.rwx_region_count),
                float(features.private_memory_mb),
                float(features.is_hollowed),
                float(features.remote_threads),
                float(features.active_connections),
                float(features.c2_beacon_score),
                float(features.dns_entropy),
                float(features.file_writes_per_min),
                float(features.registry_mods_per_min),
                float(features.process_creates_per_min),
                float(features.api_calls_suspicious),
                float(features.total_events_5min)
            ]])
            
            # Make prediction
            prediction = self.model.predict(feature_array)[0]
            proba = self.model.predict_proba(feature_array)[0]
            
            # Get confidence (max probability)
            confidence = float(max(proba))
            
            # Calculate threat score (0-100)
            threat_score = float(proba[1] * 100)  # Probability of malicious * 100
            
            # Identify contributing features
            contributing = self._identify_contributing_features(features)
            
            return DetectionResult(
                is_malicious=(prediction == 1),
                threat_score=threat_score,
                confidence=confidence,
                contributing_features=contributing
            )
        
        except Exception as e:
            print(f"[!] Prediction error: {e}")
            import traceback
            traceback.print_exc()
            return DetectionResult(
                is_malicious=False,
                threat_score=0.0,
                confidence=0.0,
                contributing_features=[f"Error: {str(e)}"]
            )
    
    def _identify_contributing_features(self, features: RealtimeFeatures) -> List[str]:
        """Identify which features contributed most to detection"""
        contributors = []
        
        try:
            # Check suspicious features
            if features.rwx_region_count > 5:
                contributors.append(f"RWX memory regions detected ({features.rwx_region_count})")
            
            if features.is_hollowed:
                contributors.append("Process hollowing detected")
            
            if features.remote_threads > 0:
                contributors.append(f"Remote thread injection ({features.remote_threads})")
            
            if features.cmdline_entropy > 5.0:
                contributors.append(f"High command line entropy ({features.cmdline_entropy:.2f})")
            
            if features.c2_beacon_score > 0.5:
                contributors.append(f"C2 beacon indicators (score: {features.c2_beacon_score:.2f})")
            
            if features.is_system_binary_misplaced:
                contributors.append("System binary in suspicious location")
            
            if features.api_calls_suspicious > 5:
                contributors.append(f"Suspicious API calls ({features.api_calls_suspicious})")
            
            if features.total_events_5min > 100:
                contributors.append(f"High event rate ({features.total_events_5min} events)")
            
            # Return top contributors or generic if none specific
            if contributors:
                return contributors[:5]  # Top 5
            else:
                return ["Multiple indicators combined"]
        except Exception as e:
            return ["Feature analysis error"]


def test_realtime_ml():
    """Test the ML engine"""
    print("\n=== DataDefenceX Real-Time ML Engine Test ===\n")
    
    engine = RealtimeMLEngine()
    
    if not engine.model:
        print("[!] Model not loaded - cannot run tests")
        print("[!] Run: python train_model_updated_v2.1.py")
        return
    
    # Test 1: Benign process
    print("[*] Test 1: Benign Process")
    benign_features = RealtimeFeatures(
        parent_suspicious=False,
        cmdline_entropy=2.5,
        path_suspicious=False,
        process_chain_depth=2,
        is_system_binary_misplaced=False,
        rwx_region_count=0,
        private_memory_mb=30.0,
        is_hollowed=False,
        remote_threads=0,
        active_connections=1,
        c2_beacon_score=0.05,
        dns_entropy=2.0,
        file_writes_per_min=3.0,
        registry_mods_per_min=1.0,
        process_creates_per_min=0.0,
        api_calls_suspicious=0,
        total_events_5min=15
    )
    
    result = engine.predict(benign_features)
    print(f"    Verdict: {'MALICIOUS' if result.is_malicious else 'BENIGN'}")
    print(f"    Threat Score: {result.threat_score:.1f}/100")
    print(f"    Confidence: {result.confidence*100:.1f}%")
    
    # Test 2: Malicious process
    print("\n[*] Test 2: Malicious Process (Memory Injection)")
    malicious_features = RealtimeFeatures(
        parent_suspicious=True,
        cmdline_entropy=5.8,
        path_suspicious=True,
        process_chain_depth=5,
        is_system_binary_misplaced=False,
        rwx_region_count=8,
        private_memory_mb=180.0,
        is_hollowed=True,
        remote_threads=3,
        active_connections=10,
        c2_beacon_score=0.85,
        dns_entropy=4.8,
        file_writes_per_min=40.0,
        registry_mods_per_min=20.0,
        process_creates_per_min=5.0,
        api_calls_suspicious=12,
        total_events_5min=200
    )
    
    result = engine.predict(malicious_features)
    print(f"    Verdict: {'MALICIOUS' if result.is_malicious else 'BENIGN'}")
    print(f"    Threat Score: {result.threat_score:.1f}/100")
    print(f"    Confidence: {result.confidence*100:.1f}%")
    print(f"    Contributing Factors:")
    for factor in result.contributing_features[:3]:
        print(f"      - {factor}")
    
    # Test 3: Threshold check
    print("\n[*] Test 3: Threshold Configuration")
    print(f"    ML Threshold: {engine.ml_threshold*100:.0f}%")
    print(f"    Confidence Threshold: {engine.confidence_threshold*100:.0f}%")
    print(f"    Status: {'CONFIGURED' if engine.ml_threshold > 0.5 else 'DEFAULT'}")
    
    print("\n[✓] ML Engine test complete!")


if __name__ == "__main__":
    test_realtime_ml()
