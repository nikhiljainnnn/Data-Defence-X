"""
DataDefenceX - Real-Time ML Engine FIXED v2.0
Updated with configurable thresholds from whitelist
"""

import pickle
import numpy as np
import json
import os
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple


@dataclass
class RealtimeFeatures:
    """20 features for real-time detection (17 original + 3 YARA)"""
    # Process features (5)
    parent_suspicious: bool
    cmdline_entropy: float
    path_suspicious: bool
    process_chain_depth: int
    is_system_binary_misplaced: bool
    
    # Memory features (4)
    rwx_region_count: int
    private_memory_mb: float
    is_hollowed: bool
    remote_threads: int
    
    # Network features (3)
    active_connections: int
    c2_beacon_score: float
    dns_entropy: float
    
    # Behavioral features (5)
    file_writes_per_min: float
    registry_mods_per_min: float
    process_creates_per_min: float
    api_calls_suspicious: int
    total_events_5min: int
    
    # YARA features (3)
    yara_critical_matches: int = 0
    yara_high_matches: int = 0
    yara_total_matches: int = 0


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
            with open('config/whitelist.json', 'r') as f:
                whitelist = json.load(f)
                thresholds = whitelist.get('thresholds', {})
                
                self.ml_threshold = thresholds.get('ml_threshold', 0.70)
                self.confidence_threshold = thresholds.get('confidence_threshold', 0.75)
                
                print(f"[*] ML Threshold: {self.ml_threshold*100:.0f}%")
                print(f"[*] Confidence Threshold: {self.confidence_threshold*100:.0f}%")
        except Exception as e:
            print(f"[*] Using default thresholds (70%/75%)")
    
    def _load_model(self, model_path: str):
        """Load trained ML model"""
        try:
            if not os.path.exists(model_path):
                print(f"[!] Model not found: {model_path}")
                print(f"[!] Run train_model_updated_v2.1.py first")
                return
            
            # Load model
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
            
            # Load feature names
            features_path = model_path.replace('_realtime.pkl', '_features.pkl')
            if os.path.exists(features_path.replace('_model', '')):
                with open(features_path.replace('_model', ''), 'rb') as f:
                    self.feature_names = pickle.load(f)
            else:
                # Default feature names
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
            RealtimeFeatures object
        """
        try:
            if process_event:
                return self._extract_from_process(process_event)
            elif memory_indicators:
                return self._extract_from_memory(memory_indicators)
            else:
                return None
        except Exception as e:
            return None
    
    def _extract_from_process(self, proc: Dict) -> RealtimeFeatures:
        """Extract features from process event"""
        import math
        
        # Feature 0: parent_suspicious
        ppid = proc.get('ppid', 0)
        parent_suspicious = ppid > 10 and ppid not in [0, 4]
        
        # Feature 1: cmdline_entropy
        cmdline = proc.get('cmdline', '')
        if cmdline and len(cmdline) > 10:
            # Simple entropy calculation
            from collections import Counter
            counter = Counter(cmdline)
            length = len(cmdline)
            entropy = -sum((count/length) * math.log2(count/length) 
                          for count in counter.values())
            cmdline_entropy = min(entropy, 7.0)
        else:
            cmdline_entropy = 0.0
        
        # Feature 2: path_suspicious
        path = proc.get('path', '').lower()
        suspicious_paths = ['temp', 'appdata', 'downloads', 'public']
        path_suspicious = any(sp in path for sp in suspicious_paths)
        
        # Feature 3: process_chain_depth
        process_chain_depth = proc.get('suspicious_score', 0) / 20  # Rough estimate
        
        # Feature 4: is_system_binary_misplaced
        system_binaries = ['powershell.exe', 'cmd.exe', 'wmic.exe', 'rundll32.exe']
        name = proc.get('name', '').lower()
        is_system = any(sb in name for sb in system_binaries)
        is_wrong_location = 'system32' not in path and 'syswow64' not in path
        is_system_binary_misplaced = is_system and is_wrong_location
        
        # Features 5-16: Default values (not available from process event alone)
        # YARA features will be extracted from process event if available
        yara_critical = proc.get('yara_critical_matches', 0)
        yara_high = proc.get('yara_high_matches', 0)
        yara_total = proc.get('yara_total_matches', 0)
        
        return RealtimeFeatures(
            parent_suspicious=parent_suspicious,
            cmdline_entropy=cmdline_entropy,
            path_suspicious=path_suspicious,
            process_chain_depth=min(int(process_chain_depth), 10),
            is_system_binary_misplaced=is_system_binary_misplaced,
            rwx_region_count=0,  # Not available
            private_memory_mb=50.0,  # Estimated
            is_hollowed=False,  # Not available
            remote_threads=0,  # Not available
            active_connections=1,  # Estimated
            c2_beacon_score=0.1,  # Low default
            dns_entropy=2.5,  # Normal default
            file_writes_per_min=5.0,  # Normal default
            registry_mods_per_min=1.0,  # Normal default
            process_creates_per_min=0.0,  # None
            api_calls_suspicious=0,  # Not available
            total_events_5min=20,  # Estimated
            yara_critical_matches=yara_critical,
            yara_high_matches=yara_high,
            yara_total_matches=yara_total
        )
    
    def _extract_from_memory(self, indicators: List) -> RealtimeFeatures:
        """Extract features from memory indicators"""
        if not indicators:
            return None
        
        # Extract YARA matches from indicators
        yara_critical = 0
        yara_high = 0
        yara_total = 0
        
        # Aggregate indicators
        total_rwx = 0
        total_private_mb = 0.0
        total_remote_threads = 0
        
        for ind in indicators:
            # Extract YARA matches
            if hasattr(ind, 'indicator_type') and ind.indicator_type == 'yara_signature':
                if hasattr(ind, 'details'):
                    details = ind.details
                    yara_critical += details.get('critical_matches', 0)
                    yara_high += details.get('high_matches', 0)
                    yara_total += details.get('match_count', 0)
            
            # Extract RWX regions
            if hasattr(ind, 'rwx_regions'):
                total_rwx += ind.rwx_regions
            elif hasattr(ind, 'indicator_type') and ind.indicator_type == 'rwx_region':
                if hasattr(ind, 'details'):
                    total_rwx += ind.details.get('region_count', 0)
            
            # Extract private memory
            if hasattr(ind, 'private_bytes'):
                total_private_mb += ind.private_bytes / (1024*1024)
            
            # Extract remote threads
            if hasattr(ind, 'remote_threads'):
                total_remote_threads += ind.remote_threads
            elif hasattr(ind, 'indicator_type') and ind.indicator_type == 'remote_thread':
                if hasattr(ind, 'details'):
                    total_remote_threads += ind.details.get('thread_count', 0)
        
        # Check for hollowing
        is_hollowed = any(
            (hasattr(ind, 'indicator_type') and ind.indicator_type == 'hollowed') or
            (hasattr(ind, 'is_hollowed') and ind.is_hollowed)
            for ind in indicators
        )
        
        # Build features
        return RealtimeFeatures(
            parent_suspicious=False,  # Not available
            cmdline_entropy=3.0,  # Neutral
            path_suspicious=False,  # Not available
            process_chain_depth=2,  # Normal
            is_system_binary_misplaced=False,  # Not available
            rwx_region_count=min(total_rwx, 50),
            private_memory_mb=min(total_private_mb, 500.0) if total_private_mb > 0 else 50.0,
            is_hollowed=is_hollowed,
            remote_threads=min(total_remote_threads, 10),
            active_connections=5,  # Estimated
            c2_beacon_score=min(yara_critical * 0.2, 1.0),  # Based on YARA
            dns_entropy=4.0,  # Slightly elevated
            file_writes_per_min=10.0,  # Estimated
            registry_mods_per_min=5.0,  # Estimated
            process_creates_per_min=0.0,  # Not available
            api_calls_suspicious=yara_critical,
            total_events_5min=len(indicators) * 10,
            yara_critical_matches=yara_critical,
            yara_high_matches=yara_high,
            yara_total_matches=yara_total
        )
    
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
            import warnings
            # Suppress sklearn feature name warnings
            with warnings.catch_warnings():
                warnings.filterwarnings('ignore', category=UserWarning, module='sklearn')
                
                # Convert to numpy array (17 features - model was trained with 17 features)
                # Note: YARA features are extracted but not used in prediction (model compatibility)
                # YARA data is still used in contributing_features and threat scoring
                feature_array = np.array([[
                    float(features.parent_suspicious),
                    features.cmdline_entropy,
                    float(features.path_suspicious),
                    features.process_chain_depth,
                    float(features.is_system_binary_misplaced),
                    features.rwx_region_count,
                    features.private_memory_mb,
                    float(features.is_hollowed),
                    features.remote_threads,
                    features.active_connections,
                    features.c2_beacon_score,
                    features.dns_entropy,
                    features.file_writes_per_min,
                    features.registry_mods_per_min,
                    features.process_creates_per_min,
                    features.api_calls_suspicious,
                    features.total_events_5min
                    # Note: YARA features (yara_critical_matches, yara_high_matches, yara_total_matches)
                    # are NOT included here because the model was trained with only 17 features
                ]])
                
                # Make prediction
                prediction = self.model.predict(feature_array)[0]
                proba = self.model.predict_proba(feature_array)[0]
            
            # Get confidence (max probability)
            confidence = max(proba)
            
            # Calculate base threat score (0-100) from ML prediction
            base_threat_score = proba[1] * 100  # Probability of malicious * 100
            
            # Enhance threat score with YARA data (if available)
            # YARA matches are strong indicators, so boost score accordingly
            yara_critical = getattr(features, 'yara_critical_matches', 0)
            yara_high = getattr(features, 'yara_high_matches', 0)
            
            # Boost threat score based on YARA matches
            yara_boost = 0
            if yara_critical > 0:
                yara_boost = min(yara_critical * 10, 30)  # Up to +30 points for critical
            elif yara_high > 0:
                yara_boost = min(yara_high * 5, 15)  # Up to +15 points for high
            
            # Final threat score (capped at 100)
            threat_score = min(base_threat_score + yara_boost, 100.0)
            
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
            return DetectionResult(
                is_malicious=False,
                threat_score=0.0,
                confidence=0.0,
                contributing_features=[f"Error: {str(e)}"]
            )
    
    def _identify_contributing_features(self, features: RealtimeFeatures) -> List[str]:
        """Identify which features contributed most to detection"""
        contributors = []
        
        # Check YARA matches first (high priority indicators)
        yara_critical = getattr(features, 'yara_critical_matches', 0)
        yara_high = getattr(features, 'yara_high_matches', 0)
        yara_total = getattr(features, 'yara_total_matches', 0)
        
        if yara_critical > 0:
            contributors.append(f"YARA critical matches ({yara_critical})")
        if yara_high > 0:
            contributors.append(f"YARA high severity matches ({yara_high})")
        if yara_total > 0 and yara_critical == 0 and yara_high == 0:
            contributors.append(f"YARA signature matches ({yara_total})")
        
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


if __name__ == "__main__":
    test_realtime_ml()