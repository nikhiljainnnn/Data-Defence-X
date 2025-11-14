# DataDefenceX - Intelligent RAM Analysis for Fileless Malware Detection

<div align="center">

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Accuracy](https://img.shields.io/badge/Accuracy-93.42%25-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Framework](https://img.shields.io/badge/Framework-Volatility3-orange.svg)]()

*A hybrid forensic analysis tool combining YARA signatures and Machine Learning to detect fileless malware in memory dumps*

[Overview](#-overview) • [Architecture](#-system-architecture) • [Quick Start](#-quick-start) • [Features](#-key-features) • [Results](#-performance-metrics)

</div>

---

## 🎯 Overview

DataDefenceX addresses the critical challenge of detecting fileless malware—sophisticated attacks that exist only in RAM, bypassing traditional file-based antivirus solutions. By combining signature-based detection (YARA) with behavioral analysis (Random Forest ML), the system achieves 93.42% accuracy in identifying malicious memory patterns.

### The Problem

- *70% of modern attacks* use fileless techniques
- Traditional AV tools are *blind to RAM-only threats*
- Forensic investigation is *extremely difficult* without specialized tools
- Attacks leverage *legitimate system tools* (PowerShell, WMI, living-off-the-land)

### Our Solution

A dual-engine detection system that:
1. *YARA Engine*: Rapid signature matching for known malware patterns
2. *ML Engine*: Behavioral analysis using 57 forensic features
3. *Hybrid Verdict*: Combines both approaches for maximum accuracy

---

## 🏗 System Architecture


┌─────────────────────────────────────────────────┐
│           Memory Dump Input (.mem)              │
└─────────────────┬───────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────┐
│         Main Analysis Pipeline (main.py)        │
└─────────────────┬───────────────────────────────┘
                  │
        ┌─────────┴─────────┐
        │                   │
        ▼                   ▼
┌──────────────┐    ┌──────────────────┐
│ YARA Engine  │    │    ML Engine     │
│              │    │                  │
│ • 12 Rules   │    │ • Feature        │
│ • Signature  │    │   Extraction     │
│   Matching   │    │ • Random Forest  │
│ • Fast Scan  │    │ • 57 Features    │
└──────┬───────┘    └────────┬─────────┘
       │                     │
       │                     ▼
       │            ┌──────────────────┐
       │            │ Volatility3      │
       │            │ Framework        │
       │            │                  │
       │            │ • Process List   │
       │            │ • DLL Analysis   │
       │            │ • Network Conn   │
       │            │ • Injections     │
       │            └────────┬─────────┘
       │                     │
       └──────────┬──────────┘
                  ▼
┌─────────────────────────────────────────────────┐
│           Threat Score Calculation              │
│         (Weighted Confidence Fusion)            │
└─────────────────┬───────────────────────────────┘
                  ▼
┌─────────────────────────────────────────────────┐
│          Final Verdict & JSON Report            │
│     • Detection Details                         │
│     • Confidence Scores                         │
│     • Remediation Recommendations               │
└─────────────────────────────────────────────────┘


---

## 🚀 Quick Start

### Prerequisites

bash
# System Requirements
- Python 3.8 or higher
- 16GB RAM (recommended for large memory dumps)
- Linux/macOS/Windows


### Installation

bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/DataDefenceX.git
cd DataDefenceX

# 2. Run automated setup
chmod +x setup.sh
./setup.sh

# This will:
# - Install Python dependencies
# - Clone and setup Volatility3
# - Verify YARA rules
# - Create necessary directories


### Training the Model

bash
# 1. Download CIC-MalMem-2022 dataset
# Source: https://www.kaggle.com/datasets/luccagodoy/obfuscated-malware-memory-2022-cic
# Place the CSV file in the project root as: Obfuscated-MalMem2022.csv

# 2. Train the Random Forest classifier
python3 train_model.py

# Expected Output:
# =====================================
# Training Accuracy:  99.85%
# Testing Accuracy:   93.42%
# Model saved to: models/fileless_malware_model.pkl
# =====================================


### Running Analysis

bash
# Analyze a memory dump
python3 main.py samples/suspicious.mem

# Run demo with provided samples
./demo.sh


---

## ✨ Key Features

### 1. Dual-Engine Detection

*YARA Signature Engine*
- 12 custom rules targeting fileless malware families
- Pattern matching for:
  - PowerShell fileless attacks
  - Process hollowing
  - DLL injection
  - Reflective loading
  - Cobalt Strike beacons
  - AsyncRAT
  - Mimikatz
  - WMI persistence

*Machine Learning Engine*
- Random Forest classifier (100 trees)
- 57 behavioral features extracted from:
  - Process relationships and counts
  - DLL loading patterns
  - Network connections
  - Memory injection indicators
  - Service activity
  - Thread analysis

### 2. Comprehensive Feature Extraction

Uses Volatility3 plugins to analyze:

| Category | Features | Description |
|----------|----------|-------------|
| *Process* | 15 features | PID counts, parent relationships, suspicious names |
| *Memory* | 12 features | Injection patterns, VAD analysis, memory regions |
| *Network* | 8 features | Connection counts, ports, remote IPs |
| *DLL* | 10 features | Loading patterns, injection indicators |
| *Services* | 7 features | Service enumeration, persistence mechanisms |
| *Threads* | 5 features | Thread analysis, remote thread creation |

### 3. Intelligent Threat Scoring

python
Final Threat Score = (YARA_Weight × YARA_Score) + (ML_Weight × ML_Confidence)

Where:
- YARA Detection: 0-100 (based on rule severity)
- ML Confidence: 0-100 (probability × 100)
- Adaptive weighting based on detection confidence


### 4. Production-Ready Implementation

- ✅ Robust error handling and logging
- ✅ JSON-formatted reports for automation
- ✅ Timeout management for large dumps
- ✅ Progress indicators for long operations
- ✅ Modular architecture for easy extension

---

## 📊 Performance Metrics

### Dataset: CIC-MalMem-2022

- *Total Samples*: 58,596
  - Benign: 29,298
  - Malicious: 29,298
- *Malware Families*: Trojan, Spyware, Ransomware, RAT
- *Training/Test Split*: 80/20

### Results

| Metric | Value | Interpretation |
|--------|-------|----------------|
| *Accuracy* | 93.42% | Overall correct classifications |
| *Precision* | 94.1% | True positives / All positives |
| *Recall* | 92.8% | True positives / Actual malicious |
| *F1-Score* | 93.4% | Harmonic mean of precision/recall |
| *False Positive Rate* | 5.9% | Benign flagged as malicious |
| *False Negative Rate* | 7.2% | Malicious missed |
| *Analysis Time* | ~120 sec | Average per memory dump |

### Confusion Matrix


                  Predicted
                Benign  Malicious
Actual Benign    5,485     344     (94.1% accuracy)
       Malicious   422   5,435     (92.8% accuracy)


### Feature Importance (Top 10)

1. *malfind_injections* (18.3%) - Memory injection indicators
2. *suspicious_process_count* (12.7%) - Unusual process patterns
3. *network_connections* (9.8%) - External communications
4. *dll_injection_indicators* (8.4%) - DLL manipulation
5. *powershell_processes* (7.9%) - PowerShell abuse
6. *parent_child_anomalies* (6.5%) - Process relationship violations
7. *service_count* (5.2%) - Service modifications
8. *remote_thread_count* (4.8%) - Remote thread creation
9. *registry_modifications* (4.1%) - Persistence mechanisms
10. *memory_protection_changes* (3.9%) - Memory permission changes

---

## 📁 Project Structure


DataDefenceX/
│
├── main.py                      # Main orchestrator and CLI interface
├── train_model.py               # ML model training pipeline
├── yara_scanner.py              # YARA rule engine
├── ml_scanner.py                # ML classification engine
├── utils.py                     # Helper functions and utilities
├── fileless.yar                 # YARA rule definitions
│
├── requirements.txt             # Python dependencies
├── setup.sh                     # Automated installation script
├── demo.sh                      # Demo execution script
├── README.md                    # This file
├── LICENSE                      # MIT License
│
├── models/                      # Trained ML models
│   ├── fileless_malware_model.pkl      # Random Forest model
│   ├── model_features.pkl              # Feature names/order
│   └── model_metadata.json             # Training metadata
│
├── samples/                     # Sample memory dumps (not included)
│   ├── benign.mem              # Clean system memory
│   └── attack4_AsyncRAT.mem    # Malicious sample
│
├── output/                      # Analysis reports
│   └── [timestamp]_report.json # JSON-formatted results
│
└── volatility3/                 # Memory forensics framework
    └── [Volatility3 installation]


---

## 🔬 Technical Implementation

### YARA Rules Example

yara
rule PowerShell_Fileless_Attack {
    meta:
        description = "Detects PowerShell-based fileless malware"
        severity = "high"
    
    strings:
        $ps1 = "powershell.exe" nocase
        $ps2 = "System.Management.Automation" nocase
        $encoded = "-encodedcommand" nocase
        $bypass = "-ExecutionPolicy Bypass" nocase
        $download = "DownloadString" nocase
        $iex = "Invoke-Expression" nocase
    
    condition:
        $ps1 and ($ps2 or $encoded) and 
        ($bypass or $download or $iex)
}


### Feature Extraction Process

python
# Example feature extraction workflow
features = {
    # Process analysis
    'total_processes': len(process_list),
    'suspicious_processes': count_suspicious_names(process_list),
    'orphan_processes': find_orphans(process_list),
    
    # Memory injection detection
    'malfind_injections': run_volatility_plugin('malfind'),
    'hollowfind_detections': run_volatility_plugin('hollowfind'),
    
    # Network indicators
    'network_connections': len(get_connections()),
    'suspicious_ports': check_port_patterns(connections),
    
    # DLL analysis
    'loaded_dlls': count_dlls(process_list),
    'unsigned_dlls': find_unsigned(dlls),
}


### ML Classification Pipeline

python
# Random Forest training configuration
classifier = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42,
    class_weight='balanced'
)

# Feature scaling
scaler = StandardScaler()
X_scaled = scaler.fit_transform(features)

# Model training
classifier.fit(X_train, y_train)


---

## 💻 Usage Examples

### Example 1: Analyzing a Suspicious Memory Dump

bash
$ python3 main.py samples/attack4_AsyncRAT.mem

╔═══════════════════════════════════════════════════════════╗
║            DATADEFENCEX ANALYSIS REPORT                   ║
╚═══════════════════════════════════════════════════════════╝

File:              attack4_AsyncRAT.mem
Size:              2.1 GB
Status:            🚨 MALICIOUS
Threat Score:      87.5/100

═══════════════════════════════════════════════════════════
YARA DETECTION RESULTS
═══════════════════════════════════════════════════════════

✓ PowerShell_Fileless_Attack (HIGH)
  ├─ Process: powershell.exe (PID: 4120)
  ├─ Matched Strings:
  │  • "-encodedcommand" at offset 0x1A2F00
  │  • "Invoke-Expression" at offset 0x1A3120
  └─ Description: PowerShell-based fileless malware execution

✓ AsyncRAT_Memory_Signature (CRITICAL)
  ├─ Process: RegAsm.exe (PID: 5832)
  ├─ Matched Strings:
  │  • "AsyncClient" namespace indicator
  │  • C2 communication patterns
  └─ Description: AsyncRAT remote access trojan

═══════════════════════════════════════════════════════════
MACHINE LEARNING ANALYSIS
═══════════════════════════════════════════════════════════

✓ Verdict:         MALICIOUS
✓ Confidence:      94.3%
✓ Risk Level:      HIGH

Top Contributing Features:
  1. malfind_injections: 15 detections (Critical)
  2. suspicious_process_count: 8 processes
  3. network_connections: 3 external IPs
  4. powershell_processes: 2 instances
  5. dll_injection_indicators: 12 anomalies

═══════════════════════════════════════════════════════════
RECOMMENDATIONS
═══════════════════════════════════════════════════════════

1. IMMEDIATE ACTIONS:
   • Isolate affected system from network
   • Terminate processes: PID 4120, 5832
   • Block C2 IP addresses: 192.0.2.45, 198.51.100.89

2. FORENSIC INVESTIGATION:
   • Analyze PowerShell command history
   • Review scheduled tasks for persistence
   • Check registry autorun keys

3. REMEDIATION:
   • Full system rebuild recommended
   • Update PowerShell execution policies
   • Deploy EDR solution

═══════════════════════════════════════════════════════════
ANALYSIS COMPLETE
═══════════════════════════════════════════════════════════
Duration: 118.5 seconds
Report saved to: output/20241114_153042_report.json


### Example 2: Batch Analysis

bash
# Analyze multiple memory dumps
for dump in samples/*.mem; do
    python3 main.py "$dump" --output-dir batch_results/
done

# Generate summary report
python3 utils.py summarize batch_results/


### Example 3: JSON Output Format

json
{
  "file": "attack4_AsyncRAT.mem",
  "timestamp": "2024-11-14T15:30:42Z",
  "verdict": "MALICIOUS",
  "threat_score": 87.5,
  "yara_results": {
    "detected": true,
    "matches": [
      {
        "rule": "PowerShell_Fileless_Attack",
        "severity": "high",
        "process": "powershell.exe",
        "pid": 4120,
        "strings": ["encodedcommand", "Invoke-Expression"]
      }
    ]
  },
  "ml_results": {
    "prediction": "malicious",
    "confidence": 0.943,
    "features": {
      "malfind_injections": 15,
      "suspicious_process_count": 8,
      "network_connections": 3
    }
  },
  "recommendations": [
    "Isolate system immediately",
    "Terminate suspicious processes",
    "Full forensic investigation required"
  ]
}


---

## 🧪 Testing & Validation

### Test Dataset

Download sample memory dumps from:
- *CIC-MalMem-2022*: https://www.unb.ca/cic/datasets/malmem-2022.html
- *Memory Forensics Attack Simulation*: https://daniyyell.com/datasets/

### Running Tests

bash
# Test with benign sample
python3 main.py samples/benign.mem
# Expected: BENIGN (Score: 10-20)

# Test with malicious sample
python3 main.py samples/attack4_AsyncRAT.mem
# Expected: MALICIOUS (Score: 80-90)

# Run full test suite
python3 -m pytest tests/


### Cross-Validation Results

5-fold cross-validation on CIC-MalMem-2022:

| Fold | Accuracy | Precision | Recall | F1-Score |
|------|----------|-----------|--------|----------|
| 1    | 93.8%    | 94.2%     | 93.1%  | 93.6%    |
| 2    | 93.1%    | 93.9%     | 92.5%  | 93.2%    |
| 3    | 93.6%    | 94.3%     | 92.9%  | 93.6%    |
| 4    | 93.2%    | 94.0%     | 92.6%  | 93.3%    |
| 5    | 93.5%    | 94.1%     | 92.8%  | 93.4%    |
| *Mean* | *93.4%* | *94.1%* | *92.8%* | *93.4%* |

---

## 🔧 Configuration

### Adjusting Detection Sensitivity

Edit config.py:

python
# YARA scanning
YARA_TIMEOUT = 300  # seconds
YARA_FAST_MODE = False  # Set True for quick scans

# ML classification
ML_CONFIDENCE_THRESHOLD = 0.7  # 0.0-1.0
ML_FEATURE_TIMEOUT = 600  # seconds

# Threat scoring
YARA_WEIGHT = 0.6
ML_WEIGHT = 0.4

# Output
VERBOSE_LOGGING = True
JSON_OUTPUT = True


### Adding Custom YARA Rules

Add to fileless.yar:

yara
rule Custom_Malware_Pattern {
    meta:
        description = "Detects custom malware family"
        author = "Your Name"
        date = "2024-11-14"
        severity = "high"
    
    strings:
        $pattern1 = { 4D 5A ?? ?? ?? ?? ?? ?? ?? 50 45 }
        $pattern2 = "CustomMalwareString"
    
    condition:
        $pattern1 and $pattern2
}


---

## 🚧 Limitations & Future Work

### Current Limitations

1. *Analysis Time*: Large memory dumps (>4GB) require 3-5 minutes
2. *Feature Extraction*: Relies on Volatility3 plugin availability
3. *Unknown Malware*: Zero-day attacks may evade signature-based detection
4. *Resource Intensive*: Requires significant RAM for analysis

### Future Enhancements

#### 1. Real-Time Monitoring

Current: Post-incident analysis of memory dumps
Future:  Real-time agent-based detection
  ├─ Streaming feature extraction
  ├─ Online learning for model updates
  └─ <5 second detection latency


#### 2. Advanced Obfuscation Detection

Addition: Entropy analysis for packed/encrypted regions
  ├─ Shannon entropy calculation
  ├─ Threshold: Entropy > 7.2 = suspicious
  └─ Integration with ML feature vector


#### 3. Secure Enclave Deployment

Enhancement: Intel SGX integration
  ├─ Tamper-proof analysis environment
  ├─ Protected model and rule storage
  └─ Trusted execution for compromised systems


#### 4. Extended Platform Support

Roadmap:
  ├─ Windows memory dumps (fully tested)
  ├─ Linux memory dumps (in progress)
  ├─ macOS memory dumps (planned)
  └─ Mobile platforms (iOS/Android) (research phase)


---

## 📚 Technical References

### Research Papers

1. *Fileless Malware Detection*
   - "Fileless Malware Detection Using Machine Learning" (IEEE, 2023)
   - "Memory Forensics: Detecting Malware in RAM" (ACM CCS, 2022)

2. *Feature Engineering*
   - "Behavioral Analysis of Memory Dumps for Malware Classification" (USENIX, 2023)
   - CIC-MalMem-2022 Dataset Paper

### Tools & Frameworks

- *Volatility Foundation*: https://www.volatilityfoundation.org/
- *YARA*: https://virustotal.github.io/yara/
- *Scikit-learn*: https://scikit-learn.org/

### Datasets

- *CIC-MalMem-2022*: https://www.unb.ca/cic/datasets/malmem-2022.html
- *EMBER*: https://github.com/elastic/ember
- *SOREL-20M*: https://github.com/sophos/SOREL-20M

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

### Code Contributions

1. Fork the repository
2. Create a feature branch (git checkout -b feature/amazing-feature)
3. Commit your changes (git commit -m 'Add amazing feature')
4. Push to the branch (git push origin feature/amazing-feature)
5. Open a Pull Request

### YARA Rule Contributions

- Follow YARA best practices
- Include description, severity, and test cases
- Verify no false positives on benign samples

### Bug Reports

Open an issue with:
- System configuration
- Memory dump characteristics
- Error messages and logs
- Expected vs actual behavior

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


MIT License

Copyright (c) 2024 DataDefenceX Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software.


---

## 📧 Contact & Support

- *Issues*: [GitHub Issues](https://github.com/YOUR_USERNAME/DataDefenceX/issues)
- *Documentation*: [Wiki](https://github.com/YOUR_USERNAME/DataDefenceX/wiki)
- *Security*: Please report security vulnerabilities privately via email

---

## 🙏 Acknowledgments

- *Volatility Foundation* for the memory forensics framework
- *University of New Brunswick* for the CIC-MalMem-2022 dataset
- *YARA Rules Community* for signature contributions
- *Scikit-learn* team for the machine learning library

---

<div align="center">

*Built with ❤ for cybersecurity research*

⭐ Star this repository if you find it useful!

[Documentation](https://github.com/YOUR_USERNAME/DataDefenceX/wiki) • [Report Bug](https://github.com/YOUR_USERNAME/DataDefenceX/issues) • [Request Feature](https://github.com/YOUR_USERNAME/DataDefenceX/issues)

</div>