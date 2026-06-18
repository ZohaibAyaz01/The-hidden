# The Hidden - Advanced Malware Forensics & Payload Extraction Toolkit

![Bash](https://img.shields.io/badge/Bash-Linux-green.svg)
![DFIR](https://img.shields.io/badge/DFIR-Digital%20Forensics-blue.svg)
![Security](https://img.shields.io/badge/Cybersecurity-Malware%20Analysis-red.svg)
![Status](https://img.shields.io/badge/Status-Active-brightgreen.svg)

## Overview

The Hidden is an advanced Digital Forensics and Incident Response (DFIR) toolkit developed for malware analysis, steganography detection, payload extraction, and forensic investigation.

Designed for Linux environments, the tool automates multiple forensic techniques including entropy analysis, header validation, string intelligence gathering, embedded file carving, EOF payload extraction, and forensic risk scoring.

The objective is to assist security researchers, malware analysts, DFIR professionals, and students in identifying hidden content, suspicious indicators, and potentially malicious artifacts within files.

---

## Contributors

* **Abdullah Zia**
* **Zohaib Ayaz**

---

## Key Features

### File Integrity Analysis

* SHA-256 hash generation
* Logical vs Physical size comparison
* Slack space analysis
* File structure validation

### Malware Detection

* Detection of suspicious code patterns
* Credential and secret discovery
* Shell execution artifact identification
* Network indicator extraction

### Payload Extraction

* EOF payload detection
* Hidden data recovery
* Binary payload extraction
* Embedded content identification

### Steganography & Obfuscation Detection

* Entropy analysis
* High-entropy artifact detection
* Encrypted payload identification
* Packed malware detection indicators

### File Carving

* Embedded ZIP extraction
* PDF recovery
* ELF binary extraction
* Signature-based carving

### Forensic Reporting

* Risk scoring engine
* Automated findings report
* Confidence-based malware assessment
* Investigation artifact generation

---

## Architecture

```text
Target File
     │
     ▼
Forensic Analysis Engine
     │
 ┌───┼───────────────────┐
 │   │                   │
 ▼   ▼                   ▼
Header Validation    String Analysis
Entropy Analysis     Payload Detection
File Carving         Risk Assessment
 │
 ▼
Forensic Confidence Report
```

---

## Core Modules

### Header & Signature Validation

Verifies whether file extensions match actual file signatures and identifies common malware camouflage techniques.

### Intelligent String Analysis

Extracts printable strings and searches for:

* URLs
* IP Addresses
* Credentials
* API Keys
* Shell Commands
* PowerShell Artifacts
* Crypto Markers

### EOF Payload Extraction

Detects and extracts hidden data appended after legitimate file endings.

Supported Formats:

* JPEG
* PNG

### Entropy Analysis

Calculates Shannon Entropy to identify:

* Encrypted payloads
* Packed executables
* Obfuscated malware

### Smart File Carving

Searches for embedded file signatures and automatically extracts discovered artifacts.

Supported Types:

* ZIP
* PDF
* ELF
* Additional embedded binary structures

### Forensic Confidence Engine

Combines multiple indicators into a weighted risk score ranging from 0–100.

---

## Installation

### Requirements

Linux Environment

Required Utilities:

```bash
bash
grep
awk
dd
strings
file
hexdump
sha256sum
xxd
```

### Clone Repository

```bash
git clone https://github.com/yourusername/TheHidden.git
cd TheHidden
```

### Make Executable

```bash
chmod +x TheHidden.sh
```

---

## Usage

Run the toolkit:

```bash
./TheHidden.sh
```

Enter the path to the file you want to analyze:

```bash
Target File > suspicious.jpg
```

---

## Analysis Modules

| Module               | Function                       |
| -------------------- | ------------------------------ |
| Size Analysis        | Logical vs Physical file size  |
| Slack Space Analysis | Detect hidden storage regions  |
| Hash Verification    | SHA-256 integrity verification |
| Header Validation    | File signature checks          |
| String Intelligence  | Suspicious string discovery    |
| EOF Extraction       | Hidden payload extraction      |
| Entropy Analysis     | Encryption/packing detection   |
| File Carving         | Embedded artifact recovery     |
| Report Generator     | Risk assessment report         |

---

## Example Use Cases

### Malware Investigation

Analyze suspicious files for hidden payloads and embedded malware.

### Steganography Detection

Identify hidden data appended to image files.

### Incident Response

Quickly evaluate suspicious artifacts during investigations.

### Digital Forensics Education

Demonstrate forensic concepts and malware analysis techniques in laboratory environments.

---

## Generated Artifacts

The tool can automatically create:

* Extracted String Logs
* Payload Files
* Carved Embedded Files
* Forensic Investigation Reports

---

## Research Applications

This project demonstrates practical applications of:

* Digital Forensics
* Malware Analysis
* Threat Hunting
* Incident Response
* File System Forensics
* Steganography Detection
* Security Automation

---

## Future Enhancements

* PE File Analysis
* YARA Rule Integration
* Memory Dump Analysis
* Multi-threaded Scanning
* Threat Intelligence Integration
* Automated IOC Generation
* PDF Malware Detection
* ELF Behavioral Analysis

---

## Disclaimer

This project is intended for educational, research, and authorized security testing purposes only. Users are responsible for ensuring compliance with applicable laws and organizational policies before analyzing any files or systems.

## License

MIT License
