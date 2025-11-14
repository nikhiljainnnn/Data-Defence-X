"""
DataDefenceX - Real-Time ML Engine
Lightweight feature extraction and fast prediction
"""

import numpy as np
import pickle
from sklearn.ensemble import RandomForestClassifier
from dataclasses import dataclass
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from collections import defaultdict, deque


@dataclass
class RealtimeFeatures:
    """Lightweight features for real-time detection"""
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
    file_writes_per_min: int
    registry_mods_per_min: int
    process_creates_per_min: int
    api_calls_suspicious: int
    total_events_5min: int
    
    # YARA features (3)
    yara_critical_matches: int
    yara_high_matches: int
    yara_total_matches: int
    
    def to_array(self) -> np.ndarray:
        """Convert to numpy array for ML prediction"""
        return np.array([
            int(self.parent_suspicious),
            self.cmdline_entropy,
            int(self.path_suspicious),
            self.process_chain_depth,
            int(self.is_system_binary_misplaced),
            self.rwx_region_count,
            self.private_memory_mb,
            int(self.is_hollowed),
            self.remote_threads,
            self.active_connections,
            self.c2_beacon_score,
            self.dns_entropy,
            self.file_writes_per_min,
            self.registry_mods_per_min,
            self.process_creates_per_min,
            self.api_calls_suspicious,
            self.total_events_5min,
            self.yara_critical_matches,
            self.yara_high_matches,
            self.yara_total_matches
        ]).reshape(1, -1)


@dataclass
class DetectionResult:
    """Result from ML detection"""
    is_malicious: bool
    confidence: float
    threat_score: int  # 0-100
    contributing_features: List[str]
    timestamp: datetime
    recommendation: str


class RealtimeMLEngine:
    """
    Lightweight ML engine for real-time detection
    Uses simplified features instead of heavy Volatility extraction
    """
    
    def __init__(self, model_path: Optional[str] = None):
        self.model = None
        self.feature_importance = None
        self.event_cache = defaultdict(lambda: deque(maxlen=300))  # 5 min history
        
        if model_path:
            self.load_model(model_path)
        else:
            # Create simple model for demonstration
            self.model = self._create_simple_model()
    
    def _create_simple_model(self) -> RandomForestClassifier:
        """
        Create a simple Random Forest for testing
        In production, use the trained model from train_model.py
        """
        model = RandomForestClassifier(
            n_estimators=50,  # Fewer trees for faster inference
            max_depth=15,
            min_samples_split=5,
            random_state=42,
            n_jobs=1  # Single thread for predictable latency
        )
        
        # Mock training data - in real system, use actual training
        # Updated to 20 features (17 original + 3 YARA features)
        X_train = np.random.rand(1000, 20)
        y_train = np.random.randint(0, 2, 1000)
        model.fit(X_train, y_train)
        
        return model
    
    def load_model(self, model_path: str):
        """Load pre-trained model"""
        with open(model_path, 'rb') as f:
            self.model = pickle.load(f)
        
        # Get feature importance
        if hasattr(self.model, 'feature_importances_'):
            self.feature_importance = self.model.feature_importances_
    
    def extract_features(self, 
                        process_event: Optional[Dict] = None,
                        memory_indicators: Optional[List] = None,
                        network_data: Optional[Dict] = None) -> RealtimeFeatures:
        """
        Extract lightweight features from live events
        No Volatility required!
        
        Args:
            process_event: Data from ProcessMonitorAgent
            memory_indicators: Data from MemoryMonitorAgent
            network_data: Data from NetworkMonitorAgent
        
        Returns:
            RealtimeFeatures object
        """
        # Initialize with defaults
        features = {
            'parent_suspicious': False,
            'cmdline_entropy': 0.0,
            'path_suspicious': False,
            'process_chain_depth': 1,
            'is_system_binary_misplaced': False,
            'rwx_region_count': 0,
            'private_memory_mb': 0.0,
            'is_hollowed': False,
            'remote_threads': 0,
            'active_connections': 0,
            'c2_beacon_score': 0.0,
            'dns_entropy': 0.0,
            'file_writes_per_min': 0,
            'registry_mods_per_min': 0,
            'process_creates_per_min': 0,
            'api_calls_suspicious': 0,
            'total_events_5min': 0,
            'yara_critical_matches': 0,
            'yara_high_matches': 0,
            'yara_total_matches': 0
        }
        
        # Extract from process event
        if process_event:
            features['parent_suspicious'] = process_event.get('suspicious_score', 0) > 50
            features['cmdline_entropy'] = self._calculate_entropy(
                process_event.get('cmdline', '')
            )
            features['path_suspicious'] = self._is_path_suspicious(
                process_event.get('path', '')
            )
            features['process_chain_depth'] = self._get_chain_depth(
                process_event.get('pid', 0)
            )
        
        # Extract from memory indicators
        if memory_indicators:
            for indicator in memory_indicators:
                if indicator.indicator_type == 'rwx_region':
                    features['rwx_region_count'] = indicator.details.get('region_count', 0)
                elif indicator.indicator_type == 'hollowed':
                    features['is_hollowed'] = True
                elif indicator.indicator_type == 'remote_thread':
                    features['remote_threads'] = indicator.details.get('thread_count', 0)
                elif indicator.indicator_type == 'yara_signature':
                    # Extract YARA signature matches
                    details = indicator.details
                    features['yara_critical_matches'] = details.get('critical_matches', 0)
                    features['yara_high_matches'] = details.get('high_matches', 0)
                    features['yara_total_matches'] = details.get('match_count', 0)
        
        # Extract from network data
        if network_data:
            features['active_connections'] = network_data.get('connection_count', 0)
            features['c2_beacon_score'] = network_data.get('beacon_score', 0.0)
            features['dns_entropy'] = network_data.get('dns_entropy', 0.0)
        
        # Calculate behavioral features from event cache
        if process_event and 'pid' in process_event:
            pid = process_event['pid']
            features.update(self._calculate_behavioral_features(pid))
        
        return RealtimeFeatures(**features)
    
    def predict(self, features: RealtimeFeatures) -> DetectionResult:
        """
        Make real-time prediction
        Target latency: <100ms
        
        Args:
            features: RealtimeFeatures object
        
        Returns:
            DetectionResult with verdict and confidence
        """
        start_time = datetime.now()
        
        # Convert features to array
        X = features.to_array()
        
        # Make prediction
        prediction = self.model.predict(X)[0]
        prediction_proba = self.model.predict_proba(X)[0]
        
        is_malicious = bool(prediction == 1)
        confidence = float(prediction_proba[prediction])
        threat_score = int(prediction_proba[1] * 100)
        
        # Identify contributing features
        contributing = self._get_contributing_features(features, X)
        
        # Generate recommendation
        recommendation = self._generate_recommendation(threat_score)
        
        # Calculate latency
        latency = (datetime.now() - start_time).total_seconds() * 1000
        
        if latency > 100:
            print(f"[!] Warning: Prediction latency {latency:.1f}ms exceeds target")
        
        return DetectionResult(
            is_malicious=is_malicious,
            confidence=confidence,
            threat_score=threat_score,
            contributing_features=contributing,
            timestamp=datetime.now(),
            recommendation=recommendation
        )
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy"""
        import math
        from collections import Counter
        
        if not text:
            return 0.0
        
        counts = Counter(text)
        length = len(text)
        entropy = 0.0
        
        for count in counts.values():
            prob = count / length
            entropy -= prob * math.log2(prob)
        
        return entropy
    
    def _is_path_suspicious(self, path: str) -> bool:
        """Check if path is suspicious"""
        if not path:
            return False
        
        path_lower = path.lower()
        suspicious = [
            'temp', 'appdata\\local\\temp', 'users\\public',
            'programdata', 'downloads'
        ]
        
        return any(s in path_lower for s in suspicious)
    
    def _get_chain_depth(self, pid: int) -> int:
        """Get process ancestry depth"""
        import psutil
        
        depth = 0
        current_pid = pid
        
        try:
            while current_pid > 0 and depth < 10:
                proc = psutil.Process(current_pid)
                current_pid = proc.ppid()
                depth += 1
        except:
            pass
        
        return depth
    
    def _calculate_behavioral_features(self, pid: int) -> Dict:
        """Calculate behavioral features from event history"""
        events = self.event_cache[pid]
        
        if not events:
            return {
                'file_writes_per_min': 0,
                'registry_mods_per_min': 0,
                'process_creates_per_min': 0,
                'api_calls_suspicious': 0,
                'total_events_5min': 0
            }
        
        # Count events in last 5 minutes
        now = datetime.now()
        recent_events = [e for e in events if (now - e['timestamp']).seconds < 300]
        
        # Calculate rates
        time_window = 5.0  # minutes
        
        return {
            'file_writes_per_min': sum(1 for e in recent_events if e['type'] == 'file_write') / time_window,
            'registry_mods_per_min': sum(1 for e in recent_events if e['type'] == 'registry') / time_window,
            'process_creates_per_min': sum(1 for e in recent_events if e['type'] == 'process') / time_window,
            'api_calls_suspicious': sum(1 for e in recent_events if e.get('suspicious', False)),
            'total_events_5min': len(recent_events)
        }
    
    def _get_contributing_features(self, features: RealtimeFeatures, X: np.ndarray) -> List[str]:
        """Identify which features contributed most to the prediction"""
        contributing = []
        
        feature_names = [
            'parent_suspicious', 'cmdline_entropy', 'path_suspicious',
            'process_chain_depth', 'is_system_binary_misplaced',
            'rwx_region_count', 'private_memory_mb', 'is_hollowed',
            'remote_threads', 'active_connections', 'c2_beacon_score',
            'dns_entropy', 'file_writes_per_min', 'registry_mods_per_min',
            'process_creates_per_min', 'api_calls_suspicious', 'total_events_5min',
            'yara_critical_matches', 'yara_high_matches', 'yara_total_matches'
        ]
        
        # Get feature values
        values = X[0]
        
        # Identify suspicious features
        if values[0] == 1:  # parent_suspicious
            contributing.append("Suspicious parent process")
        
        if values[1] > 4.5:  # high cmdline entropy
            contributing.append(f"High command-line entropy ({values[1]:.2f})")
        
        if values[5] > 0:  # rwx regions
            contributing.append(f"RWX memory regions detected ({int(values[5])})")
        
        if values[7] == 1:  # is_hollowed
            contributing.append("Process hollowing detected")
        
        if values[8] > 0:  # remote threads
            contributing.append(f"Remote thread injection ({int(values[8])} threads)")
        
        if values[10] > 0.7:  # high C2 beacon score
            contributing.append(f"C2 beacon behavior (score: {values[10]:.2f})")
        
        # YARA signature matches
        if values[17] > 0:  # yara_critical_matches
            contributing.append(f"YARA: {int(values[17])} critical signature(s) matched")
        
        if values[18] > 0:  # yara_high_matches
            contributing.append(f"YARA: {int(values[18])} high-severity signature(s) matched")
        
        return contributing[:5]  # Return top 5
    
    def _generate_recommendation(self, threat_score: int) -> str:
        """Generate action recommendation based on threat score"""
        if threat_score >= 90:
            return "KILL_PROCESS - Immediate termination required"
        elif threat_score >= 75:
            return "SUSPEND_PROCESS - Suspend for forensic analysis"
        elif threat_score >= 60:
            return "INCREASE_MONITORING - Watch closely"
        elif threat_score >= 40:
            return "LOG_EVENT - Record for review"
        else:
            return "ALLOW - No action needed"
    
    def record_event(self, pid: int, event: Dict):
        """Record event in cache for behavioral analysis"""
        event['timestamp'] = datetime.now()
        self.event_cache[pid].append(event)


class OnlineLearner:
    """
    Optional: Online learning capability
    Updates model based on analyst feedback
    """
    
    def __init__(self, base_model):
        self.base_model = base_model
        self.feedback_buffer = []
        self.retrain_threshold = 100  # Retrain after 100 feedbacks
    
    def record_feedback(self, features: np.ndarray, true_label: int):
        """Record analyst feedback for model improvement"""
        self.feedback_buffer.append((features, true_label))
        
        if len(self.feedback_buffer) >= self.retrain_threshold:
            self.retrain()
    
    def retrain(self):
        """Incrementally update model with new feedback"""
        print("[*] Retraining model with new feedback...")
        
        X_new = np.vstack([f[0] for f in self.feedback_buffer])
        y_new = np.array([f[1] for f in self.feedback_buffer])
        
        # In production, use incremental learning (e.g., SGD)
        # For Random Forest, would need to retrain entirely
        
        self.feedback_buffer = []


def test_realtime_ml():
    """Test real-time ML engine"""
    print("\n=== DataDefenceX Real-Time ML Engine Test ===\n")
    
    engine = RealtimeMLEngine()
    
    # Test Case 1: Benign process
    print("[*] Test 1: Benign Process")
    benign_features = RealtimeFeatures(
        parent_suspicious=False,
        cmdline_entropy=3.5,
        path_suspicious=False,
        process_chain_depth=3,
        is_system_binary_misplaced=False,
        rwx_region_count=0,
        private_memory_mb=50.0,
        is_hollowed=False,
        remote_threads=0,
        active_connections=2,
        c2_beacon_score=0.1,
        dns_entropy=3.0,
        file_writes_per_min=5,
        registry_mods_per_min=1,
        process_creates_per_min=0,
        api_calls_suspicious=0,
        total_events_5min=25,
        yara_critical_matches=0,
        yara_high_matches=0,
        yara_total_matches=0
    )
    
    result = engine.predict(benign_features)
    print(f"    Verdict: {'MALICIOUS' if result.is_malicious else 'BENIGN'}")
    print(f"    Confidence: {result.confidence*100:.1f}%")
    print(f"    Threat Score: {result.threat_score}/100")
    print(f"    Recommendation: {result.recommendation}\n")
    
    # Test Case 2: Malicious process
    print("[*] Test 2: Malicious Process (Code Injection)")
    malicious_features = RealtimeFeatures(
        parent_suspicious=True,
        cmdline_entropy=5.2,  # High entropy
        path_suspicious=True,
        process_chain_depth=2,
        is_system_binary_misplaced=False,
        rwx_region_count=3,  # Multiple RWX regions
        private_memory_mb=120.0,
        is_hollowed=False,
        remote_threads=2,  # Remote thread injection
        active_connections=5,
        c2_beacon_score=0.85,  # High C2 score
        dns_entropy=4.8,
        file_writes_per_min=50,
        registry_mods_per_min=10,
        process_creates_per_min=5,
        api_calls_suspicious=15,
        total_events_5min=200,
        yara_critical_matches=2,  # YARA critical matches
        yara_high_matches=1,  # YARA high matches
        yara_total_matches=3  # Total YARA matches
    )
    
    result = engine.predict(malicious_features)
    print(f"    Verdict: {'MALICIOUS' if result.is_malicious else 'BENIGN'}")
    print(f"    Confidence: {result.confidence*100:.1f}%")
    print(f"    Threat Score: {result.threat_score}/100")
    print(f"    Recommendation: {result.recommendation}")
    print(f"    Contributing Factors:")
    for factor in result.contributing_features:
        print(f"      - {factor}")


if __name__ == "__main__":
    test_realtime_ml()
