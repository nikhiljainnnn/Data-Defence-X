import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, roc_auc_score
import pickle
import warnings
import sys
import os
from datetime import datetime
import json

warnings.filterwarnings('ignore')

# Color codes for terminal output
class Colors:
    SUCCESS = '\033[92m'
    ERROR = '\033[91m'
    INFO = '\033[94m'
    WARNING = '\033[93m'
    RESET = '\033[0m'

def print_section(text):
    """Print section header"""
    print(f"\n{'='*70}\n{text}\n{'='*70}\n")

def print_status(text, status="info"):
    """Print status message with color"""
    colors = {
        'success': Colors.SUCCESS,
        'error': Colors.ERROR,
        'info': Colors.INFO,
        'warning': Colors.WARNING
    }
    color = colors.get(status, Colors.INFO)
    print(f"{color}[*] {text}{Colors.RESET}")


class FeatureMapper:
    
    # Real-time feature definitions (17 features)
    REALTIME_FEATURES = [
        'parent_suspicious',           # 0: Process parent-child relationship
        'cmdline_entropy',             # 1: Command line entropy
        'path_suspicious',             # 2: Suspicious path location
        'process_chain_depth',         # 3: Process ancestry depth
        'is_system_binary_misplaced',  # 4: System binary in wrong location
        'rwx_region_count',            # 5: RWX memory regions (CRITICAL)
        'private_memory_mb',           # 6: Private memory usage
        'is_hollowed',                 # 7: Process hollowing detected
        'remote_threads',              # 8: Remote thread injection
        'active_connections',          # 9: Active network connections
        'c2_beacon_score',             # 10: C2 beacon probability
        'dns_entropy',                 # 11: DNS query entropy
        'file_writes_per_min',         # 12: File write rate
        'registry_mods_per_min',       # 13: Registry modification rate
        'process_creates_per_min',     # 14: Process creation rate
        'api_calls_suspicious',        # 15: Suspicious API calls
        'total_events_5min'            # 16: Total events in 5 min window
    ]
    
    @staticmethod
    def map_volatility_to_realtime(X_volatility):
        n_samples = len(X_volatility)
        X_realtime = np.zeros((n_samples, 17))
        
        print_status("  → Mapping process features...", "info")
        
        # Feature 0: parent_suspicious (from process relationships)
        if 'pslist.nppid' in X_volatility.columns:
            X_realtime[:, 0] = (X_volatility['pslist.nppid'] > 15).astype(int)
        
        # Feature 1: cmdline_entropy (approximate from process diversity)
        if 'pslist.nproc' in X_volatility.columns:
            X_realtime[:, 1] = np.clip(X_volatility['pslist.nproc'] / 10.0, 0, 7)
        
        # Feature 2: path_suspicious (from module loading patterns)
        if 'ldrmodules.not_in_load' in X_volatility.columns:
            X_realtime[:, 2] = (X_volatility['ldrmodules.not_in_load'] > 0).astype(int)
        
        # Feature 3: process_chain_depth (from parent process count)
        if 'pslist.nppid' in X_volatility.columns:
            X_realtime[:, 3] = np.clip(X_volatility['pslist.nppid'] / 5.0, 1, 10)
        
        # Feature 4: is_system_binary_misplaced (from module inconsistencies)
        if 'ldrmodules.not_in_mem' in X_volatility.columns:
            X_realtime[:, 4] = (X_volatility['ldrmodules.not_in_mem'] > 0).astype(int)
        
        print_status("  → Mapping memory features...", "info")
        
        # Feature 5: rwx_region_count (CRITICAL - from malfind)
        if 'malfind.ninjections' in X_volatility.columns:
            X_realtime[:, 5] = X_volatility['malfind.ninjections']
        
        # Feature 6: private_memory_mb (from malfind commitCharge)
        if 'malfind.commitCharge' in X_volatility.columns:
            X_realtime[:, 6] = X_volatility['malfind.commitCharge'] / 1024.0
        
        # Feature 7: is_hollowed (from psxview hidden processes)
        if 'psxview.not_in_pslist' in X_volatility.columns:
            X_realtime[:, 7] = (X_volatility['psxview.not_in_pslist'] > 0).astype(int)
        
        # Feature 8: remote_threads (from malfind protection)
        if 'malfind.protection' in X_volatility.columns:
            X_realtime[:, 8] = X_volatility['malfind.protection']
        
        print_status("  → Mapping network features...", "info")
        
        # Feature 9: active_connections (from handles.nport)
        if 'handles.nport' in X_volatility.columns:
            X_realtime[:, 9] = X_volatility['handles.nport']
        
        # Feature 10: c2_beacon_score (derived from network + file activity)
        if 'handles.nport' in X_volatility.columns and 'handles.nfile' in X_volatility.columns:
            port_norm = np.clip(X_volatility['handles.nport'] / 100.0, 0, 1)
            file_norm = np.clip(X_volatility['handles.nfile'] / 1000.0, 0, 1)
            X_realtime[:, 10] = port_norm * file_norm
        
        # Feature 11: dns_entropy (approximate from handle diversity)
        if 'handles.nhandles' in X_volatility.columns:
            X_realtime[:, 11] = np.clip(X_volatility['handles.nhandles'] / 1000.0, 0, 7)
        
        print_status("  → Mapping behavioral features...", "info")
        
        # Feature 12: file_writes_per_min (from handles.nfile)
        if 'handles.nfile' in X_volatility.columns:
            X_realtime[:, 12] = np.clip(X_volatility['handles.nfile'] / 10.0, 0, 100)
        
        # Feature 13: registry_mods_per_min (from handles.nkey)
        if 'handles.nkey' in X_volatility.columns:
            X_realtime[:, 13] = np.clip(X_volatility['handles.nkey'] / 5.0, 0, 50)
        
        # Feature 14: process_creates_per_min (from pslist.nproc)
        if 'pslist.nproc' in X_volatility.columns:
            X_realtime[:, 14] = np.clip(X_volatility['pslist.nproc'] / 20.0, 0, 10)
        
        # Feature 15: api_calls_suspicious (from callbacks.nanonymous)
        if 'callbacks.nanonymous' in X_volatility.columns:
            X_realtime[:, 15] = X_volatility['callbacks.nanonymous']
        
        # Feature 16: total_events_5min (from handle activity)
        if 'handles.avg_handles_per_proc' in X_volatility.columns:
            X_realtime[:, 16] = np.clip(X_volatility['handles.avg_handles_per_proc'], 0, 500)
        
        print_status("  → Feature mapping complete", "success")
        
        return X_realtime


def validate_dataset(data):
    print_status("Validating dataset...", "info")
    
    # Check minimum size
    if len(data) < 100:
        return False, "Dataset too small (minimum 100 samples required)"
    
    # Check for required column types
    if 'Class' not in data.columns and 'Category' not in data.columns:
        return False, "No 'Class' or 'Category' column found"
    
    # Check for sufficient features
    feature_cols = [col for col in data.columns if col not in ['Class', 'Category']]
    if len(feature_cols) < 10:
        return False, f"Insufficient features ({len(feature_cols)} found, minimum 10 required)"
    
    # Check for extreme imbalance
    if 'Class' in data.columns:
        class_dist = data['Class'].value_counts()
    elif 'Category' in data.columns:
        class_dist = data['Category'].value_counts()
    
    if len(class_dist) < 2:
        return False, "Dataset must have at least 2 classes"
    
    imbalance_ratio = class_dist.max() / class_dist.min()
    if imbalance_ratio > 100:
        return False, f"Extreme class imbalance (ratio: {imbalance_ratio:.1f}:1)"
    
    print_status(f"  ✓ Dataset structure valid", "success")
    print_status(f"  ✓ {len(data):,} samples", "success")
    print_status(f"  ✓ {len(feature_cols)} features", "success")
    print_status(f"  ✓ Class balance ratio: {imbalance_ratio:.2f}:1", "success")
    
    return True, None


def preprocess_data(data):
    print_status("Preprocessing data...", "info")
    
    # Handle Class column
    if 'Class' not in data.columns:
        if 'Category' in data.columns:
            print_status("Converting Category to binary Class", "info")
            # Robust conversion handling various formats
            data['Class'] = data['Category'].apply(
                lambda x: 0 if str(x).strip().lower() in ['benign', '0', 'clean'] else 1
            )
        else:
            raise ValueError("No Class or Category column found")
    
    # Ensure Class is numeric
    if data['Class'].dtype == 'object':
        print_status("Converting Class to numeric format", "info")
        data['Class'] = data['Class'].apply(
            lambda x: 0 if str(x).strip().lower() in ['benign', '0', 'clean'] else 1
        )
    
    # Handle missing values
    missing_count = data.isnull().sum().sum()
    if missing_count > 0:
        print_status(f"Filling {missing_count:,} missing values with 0", "warning")
        data = data.fillna(0)
    
    # Handle infinite values
    data = data.replace([np.inf, -np.inf], 0)
    
    # Separate features and labels
    exclude_cols = ['Class', 'Category']
    feature_cols = [col for col in data.columns if col not in exclude_cols]
    
    X_full = data[feature_cols]
    y = data['Class']
    
    # Verify no issues with labels
    unique_labels = y.unique()
    if len(unique_labels) != 2:
        raise ValueError(f"Expected 2 classes, found {len(unique_labels)}: {unique_labels}")
    
    if not set(unique_labels).issubset({0, 1}):
        raise ValueError(f"Labels must be 0 and 1, found: {unique_labels}")
    
    # Print statistics
    print_status(f"Features: {len(feature_cols)}", "success")
    print_status(f"Benign samples: {(y==0).sum():,} ({(y==0).sum()/len(y)*100:.1f}%)", "info")
    print_status(f"Malicious samples: {(y==1).sum():,} ({(y==1).sum()/len(y)*100:.1f}%)", "info")
    
    return X_full, y, feature_cols


def train_dual_models(dataset_file):
    
    print_section("DUAL MODEL TRAINING SYSTEM v2.1")
    print_status("Training BOTH forensic and real-time models", "info")
    
    # --- 1. Load Dataset ---
    print_status("Loading CIC-MalMem-2022 dataset...", "info")
    
    if not os.path.exists(dataset_file):
        print_status("ERROR: Dataset file not found!", "error")
        print(f"Looking for: {os.path.abspath(dataset_file)}")
        print("\nPlease ensure the file is in the current directory")
        sys.exit(1)
    
    try:
        data = pd.read_csv(dataset_file)
        print_status(f"Dataset loaded: {len(data):,} samples", "success")
        print(f"   Shape: {data.shape}")
        print(f"   Columns: {data.shape[1]}")
    except Exception as e:
        print_status(f"Error loading dataset: {e}", "error")
        sys.exit(1)
    
    # --- 2. Validate Dataset ---
    is_valid, error_msg = validate_dataset(data)
    if not is_valid:
        print_status(f"Dataset validation failed: {error_msg}", "error")
        sys.exit(1)
    
    # --- 3. Preprocess Data ---
    try:
        X_full, y, feature_cols = preprocess_data(data)
    except Exception as e:
        print_status(f"Preprocessing failed: {e}", "error")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    # --- 4. Create Real-Time Features ---
    print_status("Creating real-time feature mapping...", "info")
    
    mapper = FeatureMapper()
    X_realtime = mapper.map_volatility_to_realtime(X_full)
    X_realtime_df = pd.DataFrame(X_realtime, columns=mapper.REALTIME_FEATURES)
    
    print_status(f"Real-time features: {len(mapper.REALTIME_FEATURES)}", "success")
    
    # --- 5. Split Data ---
    print_status("Splitting data (80/20 train/test)...", "info")
    
    try:
        # Full features split
        X_full_train, X_full_test, y_train, y_test = train_test_split(
            X_full, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Real-time features split (same indices for consistency)
        X_rt_train, X_rt_test = train_test_split(
            X_realtime_df, test_size=0.2, random_state=42, stratify=y
        )
        
        print_status(f"Training samples: {len(X_full_train):,}", "info")
        print_status(f"Testing samples: {len(X_full_test):,}", "info")
        
    except Exception as e:
        print_status(f"Data splitting failed: {e}", "error")
        sys.exit(1)
    
    # --- 6. Train Forensic Model ---
    print_section("TRAINING FORENSIC MODEL (57 features)")
    
    clf_forensic = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        verbose=0
    )
    
    print_status("Training forensic model (may take 1-2 minutes)...", "info")
    start_time = datetime.now()
    clf_forensic.fit(X_full_train, y_train)
    forensic_time = (datetime.now() - start_time).total_seconds()
    
    # Evaluate forensic model
    y_forensic_train_pred = clf_forensic.predict(X_full_train)
    y_forensic_test_pred = clf_forensic.predict(X_full_test)
    
    forensic_train_acc = accuracy_score(y_train, y_forensic_train_pred)
    forensic_test_acc = accuracy_score(y_test, y_forensic_test_pred)
    
    # Cross-validation
    print_status("Running cross-validation...", "info")
    cv_scores = cross_val_score(clf_forensic, X_full_train, y_train, cv=5, n_jobs=-1)
    forensic_cv_mean = cv_scores.mean()
    forensic_cv_std = cv_scores.std()
    
    print_status(f"Training completed in {forensic_time:.1f}s", "success")
    print_status(f"Training accuracy: {forensic_train_acc*100:.2f}%", "info")
    print_status(f"Testing accuracy: {forensic_test_acc*100:.2f}%", "success")
    print_status(f"CV accuracy: {forensic_cv_mean*100:.2f}% (±{forensic_cv_std*100:.2f}%)", "info")
    
    # Check for overfitting
    if forensic_train_acc - forensic_test_acc > 0.05:
        print_status("Warning: Possible overfitting detected (train-test gap > 5%)", "warning")
    
    # --- 7. Train Real-Time Model ---
    print_section("TRAINING REAL-TIME MODEL (17 features)")
    
    clf_realtime = RandomForestClassifier(
        n_estimators=50,       # Fewer trees for speed
        max_depth=15,          # Shallower for speed
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=1,              # Single thread for predictable latency
        verbose=0
    )
    
    print_status("Training real-time model...", "info")
    start_time = datetime.now()
    clf_realtime.fit(X_rt_train, y_train)
    realtime_time = (datetime.now() - start_time).total_seconds()
    
    # Evaluate real-time model
    y_realtime_train_pred = clf_realtime.predict(X_rt_train)
    y_realtime_test_pred = clf_realtime.predict(X_rt_test)
    
    realtime_train_acc = accuracy_score(y_train, y_realtime_train_pred)
    realtime_test_acc = accuracy_score(y_test, y_realtime_test_pred)
    
    # Cross-validation
    print_status("Running cross-validation...", "info")
    cv_scores_rt = cross_val_score(clf_realtime, X_rt_train, y_train, cv=5, n_jobs=-1)
    realtime_cv_mean = cv_scores_rt.mean()
    realtime_cv_std = cv_scores_rt.std()
    
    print_status(f"Training completed in {realtime_time:.1f}s", "success")
    print_status(f"Training accuracy: {realtime_train_acc*100:.2f}%", "info")
    print_status(f"Testing accuracy: {realtime_test_acc*100:.2f}%", "success")
    print_status(f"CV accuracy: {realtime_cv_mean*100:.2f}% (±{realtime_cv_std*100:.2f}%)", "info")
    
    # Check for overfitting
    if realtime_train_acc - realtime_test_acc > 0.05:
        print_status("Warning: Possible overfitting detected (train-test gap > 5%)", "warning")
    
    # --- 8. Compare Models ---
    print_section("MODEL COMPARISON")
    
    print(f"\n{'Model':<20} {'Features':<12} {'Test Acc':<12} {'CV Acc':<12} {'Time':<10}")
    print("-" * 70)
    print(f"{'Forensic':<20} {len(feature_cols):<12} {forensic_test_acc*100:<11.2f}% {forensic_cv_mean*100:<11.2f}% {forensic_time:<9.1f}s")
    print(f"{'Real-Time':<20} {len(mapper.REALTIME_FEATURES):<12} {realtime_test_acc*100:<11.2f}% {realtime_cv_mean*100:<11.2f}% {realtime_time:<9.1f}s")
    
    accuracy_drop = (forensic_test_acc - realtime_test_acc) * 100
    feature_reduction = (1 - len(mapper.REALTIME_FEATURES)/len(feature_cols)) * 100
    speed_improvement = forensic_time / realtime_time
    
    print(f"\nAccuracy drop: {accuracy_drop:.2f}%")
    print(f"Feature reduction: {feature_reduction:.1f}%")
    print(f"Training speed improvement: {speed_improvement:.1f}x faster")
    
    # --- 9. Detailed Evaluation ---
    print_section("REAL-TIME MODEL EVALUATION")
    
    # Classification report
    print("\nClassification Report:")
    print(classification_report(y_test, y_realtime_test_pred, 
                                target_names=['Benign', 'Malicious'],
                                digits=4))
    
    # Confusion matrix
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_realtime_test_pred)
    print(f"\n{'':>15}Predicted Benign  Predicted Malicious")
    print(f"{'Actual Benign':>15}{cm[0][0]:>15}{cm[0][1]:>20}")
    print(f"{'Actual Malicious':>15}{cm[1][0]:>15}{cm[1][1]:>20}")
    
    # Calculate additional metrics
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
    
    print(f"\nFalse Positive Rate: {fpr*100:.2f}%")
    print(f"False Negative Rate: {fnr*100:.2f}%")
    
    # ROC AUC Score
    try:
        y_realtime_proba = clf_realtime.predict_proba(X_rt_test)[:, 1]
        roc_auc = roc_auc_score(y_test, y_realtime_proba)
        print(f"ROC AUC Score: {roc_auc:.4f}")
    except:
        pass
    
    # Feature importance
    print("\nTop 10 Most Important Features (Real-Time Model):")
    feature_importance = pd.DataFrame({
        'feature': mapper.REALTIME_FEATURES,
        'importance': clf_realtime.feature_importances_
    }).sort_values('importance', ascending=False)
    
    for idx, row in feature_importance.head(10).iterrows():
        print(f"  {row['feature']:<30} {row['importance']:.4f}")
    
    # --- 10. Save Models ---
    print_section("SAVING MODELS")
    
    os.makedirs('models', exist_ok=True)
    
    try:
        # Save forensic model
        forensic_model_file = 'models/fileless_malware_model_forensic.pkl'
        with open(forensic_model_file, 'wb') as f:
            pickle.dump(clf_forensic, f)
        print_status(f"Forensic model saved: {forensic_model_file}", "success")
        
        with open('models/forensic_features.pkl', 'wb') as f:
            pickle.dump(feature_cols, f)
        print_status(f"Forensic features saved", "success")
        
        # Save real-time model
        realtime_model_file = 'models/fileless_malware_model_realtime.pkl'
        with open(realtime_model_file, 'wb') as f:
            pickle.dump(clf_realtime, f)
        print_status(f"Real-time model saved: {realtime_model_file}", "success")
        
        with open('models/realtime_features.pkl', 'wb') as f:
            pickle.dump(mapper.REALTIME_FEATURES, f)
        print_status(f"Real-time features saved", "success")
        
        # Save feature mapper
        with open('models/feature_mapper.pkl', 'wb') as f:
            pickle.dump(mapper, f)
        print_status(f"Feature mapper saved", "success")
        
        # Save comprehensive metadata
        metadata = {
            'training_date': datetime.now().isoformat(),
            'dataset_file': dataset_file,
            'dataset_samples': len(data),
            'training_samples': len(X_full_train),
            'testing_samples': len(X_full_test),
            'class_distribution': {
                'benign': int((y==0).sum()),
                'malicious': int((y==1).sum())
            },
            'forensic_model': {
                'features': len(feature_cols),
                'feature_names': feature_cols,
                'train_accuracy': float(forensic_train_acc),
                'test_accuracy': float(forensic_test_acc),
                'cv_accuracy_mean': float(forensic_cv_mean),
                'cv_accuracy_std': float(forensic_cv_std),
                'training_time_seconds': forensic_time,
                'n_estimators': 100,
                'max_depth': 20
            },
            'realtime_model': {
                'features': len(mapper.REALTIME_FEATURES),
                'feature_names': mapper.REALTIME_FEATURES,
                'train_accuracy': float(realtime_train_acc),
                'test_accuracy': float(realtime_test_acc),
                'cv_accuracy_mean': float(realtime_cv_mean),
                'cv_accuracy_std': float(realtime_cv_std),
                'training_time_seconds': realtime_time,
                'n_estimators': 50,
                'max_depth': 15,
                'false_positive_rate': float(fpr),
                'false_negative_rate': float(fnr),
                'feature_importance': {
                    fname: float(fimp) 
                    for fname, fimp in zip(mapper.REALTIME_FEATURES, clf_realtime.feature_importances_)
                }
            },
            'performance_metrics': {
                'accuracy_drop_percent': float(accuracy_drop),
                'feature_reduction_percent': float(feature_reduction),
                'training_speed_improvement': float(speed_improvement)
            }
        }
        
        with open('models/model_metadata.json', 'w') as f:
            json.dump(metadata, f, indent=2)
        print_status(f"Metadata saved", "success")
        
    except Exception as e:
        print_status(f"Error saving models: {e}", "error")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    # --- 11. Summary ---
    print_section("TRAINING COMPLETE")
    
    print(f"""
{Colors.SUCCESS}✅ Successfully trained DUAL detection models!{Colors.RESET}

{Colors.INFO}FORENSIC MODEL (Post-Incident Analysis):{Colors.RESET}
  - Features: {len(feature_cols)} (full Volatility dataset)
  - Test Accuracy: {forensic_test_acc*100:.2f}%
  - CV Accuracy: {forensic_cv_mean*100:.2f}% (±{forensic_cv_std*100:.2f}%)
  - Use case: Deep analysis of memory dumps
  - File: {forensic_model_file}

{Colors.INFO}REAL-TIME MODEL (Live Detection):{Colors.RESET}
  - Features: {len(mapper.REALTIME_FEATURES)} (lightweight)
  - Test Accuracy: {realtime_test_acc*100:.2f}%
  - CV Accuracy: {realtime_cv_mean*100:.2f}% (±{realtime_cv_std*100:.2f}%)
  - False Positive Rate: {fpr*100:.2f}%
  - Use case: Continuous monitoring
  - File: {realtime_model_file}

{Colors.WARNING}Trade-offs:{Colors.RESET}
  - Accuracy drop: {accuracy_drop:.2f}%
  - Feature reduction: {feature_reduction:.1f}%
  - Training speed: {speed_improvement:.1f}x faster
  - Inference speed: ~10x faster (estimated)

{Colors.SUCCESS}Next Steps:{Colors.RESET}
  1. For forensic analysis: python main.py <dump.mem>
  2. For real-time detection: python realtime_main.py
  3. Models are in: ./models/
  4. View metadata: cat models/model_metadata.json

{Colors.SUCCESS}Both systems are now ready to deploy! 🚀{Colors.RESET}
""")


def quick_model_test():
    """Quick test to verify models work"""
    print_section("QUICK MODEL VALIDATION")
    
    try:
        # Load real-time model
        with open('models/fileless_malware_model_realtime.pkl', 'rb') as f:
            model = pickle.load(f)
        
        print_status("Model loaded successfully", "success")
        
        # Test benign prediction
        benign_features = np.array([[0, 3.0, 0, 2, 0, 0, 50.0, 0, 0, 1, 0.1, 2.5, 5, 1, 0, 0, 20]])
        benign_pred = model.predict(benign_features)[0]
        
        # Test malicious prediction
        malicious_features = np.array([[1, 6.0, 1, 5, 0, 5, 200.0, 1, 3, 10, 0.9, 5.0, 50, 20, 5, 10, 200]])
        malicious_pred = model.predict(malicious_features)[0]
        
        print_status(f"Benign test: {'PASS ✓' if benign_pred == 0 else 'FAIL ✗'}", 
                    "success" if benign_pred == 0 else "error")
        print_status(f"Malicious test: {'PASS ✓' if malicious_pred == 1 else 'FAIL ✗'}", 
                    "success" if malicious_pred == 1 else "error")
        
        if benign_pred == 0 and malicious_pred == 1:
            print_status("Model validation successful!", "success")
            return True
        else:
            print_status("Model validation failed!", "error")
            return False
            
    except Exception as e:
        print_status(f"Validation error: {e}", "error")
        return False


def main():
    print(f"""
{Colors.INFO}╔═══════════════════════════════════════════════════════╗
║                                                       ║
║     DataDefenceX ML Training System v2.1             ║
║     Enhanced Dual Model Training                     ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝{Colors.RESET}
    """)
    
    # Get dataset file
    dataset_file = "Obfuscated-MalMem2022.csv"
    
    if len(sys.argv) > 1:
        dataset_file = sys.argv[1]
    
    print(f"Dataset file: {dataset_file}\n")
    
    try:
        # Train models
        train_dual_models(dataset_file)
        
        # Quick validation
        if os.path.exists('models/fileless_malware_model_realtime.pkl'):
            quick_model_test()
        
    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}Training interrupted by user.{Colors.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n{Colors.ERROR}Unexpected error: {e}{Colors.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()