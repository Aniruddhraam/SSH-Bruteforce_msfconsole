# SSH Brute Force Traffic Analysis and Threat Detection

This repository contains a dataset extracted from malicious SSH brute force traffic (`mal_ssh.csv`) and a fully featured Python parsing engine (`parser_info.py`) that performs in-depth feature extraction, SSH protocol interpretation, TCP flag analysis, and automated threat classification suitable for cybersecurity research and machine learning pipelines.

---

## Table of Contents
- [Project Overview](#project-overview)
- [Repository Structure](#repository-structure)
- [Dataset Description](#dataset-description)
- [Parser Overview](#parser-overview)
- [How to Use](#how-to-use)
  - [1. Install Dependencies](#1-install-dependencies)
  - [2. Run the Parser](#2-run-the-parser)
  - [3. Output Files](#3-output-files)
- [Feature Engineering Summary](#feature-engineering-summary)
- [Threat Labeling Approaches](#threat-labeling-approaches)
- [Example Workflow](#example-workflow)
- [Notes](#notes)

---

## Project Overview
This project analyzes SSH brute force attack traffic captured from a controlled environment. The original packet capture was converted into CSV form for safe distribution. The CSV file is then parsed using a custom-built Python engine capable of:

- TCP attribute extraction
- SSH protocol feature extraction
- Threat indicator generation
- Multi-method automated labeling
- Feature generation for machine learning

This enables researchers to build supervised models for SSH intrusion detection.

---

## Repository Structure
```
root/
├── mal_ssh.csv               # Extracted malicious SSH traffic (CSV)
├── parser_info.py            # Feature extraction + labeling engine
├── README.md                 # Project documentation
└── requirements.txt          # Python dependencies
```

---

## Dataset Description
The file `mal_ssh.csv` contains traffic exported from Wireshark using the "Packet List as CSV" format.

Typical columns include:
- Packet number
- Timestamp
- Source IP
- Destination IP
- Protocol
- Length
- Info

The parser normalizes these and extracts dozens of derived features for threat analysis.

---

## Parser Overview
The parser (`parser_info.py`) implements a class **SSHThreatParser** which performs:

### 1. TCP Feature Extraction
- Ports
- SYN/ACK/FIN/RST/PSH/URG flags
- Flag counts
- Connection state inference
- Sequence/ack numbers
- Window size, MSS, timestamps

### 2. SSH Protocol Feature Extraction
- SSH version
- Implementation (e.g., OpenSSH)
- Role (client/server)
- Key exchange states
- Diffie-Hellman stages
- Encrypted packet lengths

### 3. Threat Indicator Engine
- Failed connection counter
- Rapid connection attempts
- SSH brute force patterns
- High volume SSH activity
- Connection rate / failure rate analysis

### 4. Threat Classification
Includes four labeling methods:
- Improved (default)
- Simple
- Aggregate
- Original legacy

---

## How to Use

### 1. Install Dependencies
```
pip install -r requirements.txt
```
Dependencies include:
- pandas
- numpy

### 2. Run the Parser
```
python parser_info.py
```
This will:
- Load `mal_ssh.csv`
- Parse and extract features
- Compute threat indicators
- Label traffic with `MALICIOUS` / `BENIGN`
- Save output to:

```
ssh_threat_detection_dataset.csv
```

### 3. Output Files
After execution, you will have:

- **ssh_threat_detection_dataset.csv**  
  (fully processed ML‑ready dataset)

Contains all derived TCP/SSH/threat features + final labels.

---

## Feature Engineering Summary
The final dataset contains:

- TCP-level features
- SSH protocol features
- Derived timing features
- Threat indicator heuristics
- Multi-stage brute force detection flags
- Connection classification states
- Inter-packet timing
- Connection frequency per source IP

The parser is designed to generate a complete ML‑ready dataset without additional preprocessing.

---

## Threat Labeling Approaches

### **Improved Mode (default)**
Uses connection rate, failure rate, SSH volume, and burst patterns.

### **Simple Mode**
Labels based on direct SSH traffic or packet-level failure conditions.

### **Aggregate Mode**
Uses source IP–level behavior aggregates.

### **Original Mode**
Legacy compatibility, provided for completeness.

---

## Example Workflow
1. Capture SSH brute force traffic in a controlled environment.
2. Export packet list as CSV from Wireshark.
3. Place the CSV file into the repository.
4. Run the parser to generate:
   - Full feature set
   - Threat-labeled dataset
5. Use the output CSV for machine learning experiments.

---

## Notes
- All data comes from a controlled lab environment.
- No sensitive or real-world user data is included.
- The dataset is safe to publish and intended for cybersecurity research.
- The parser is extensible and can be adapted for additional protocols.
