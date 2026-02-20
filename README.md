# 🛡️ CyberShield - Multi-Tool Security Analysis Platform

A comprehensive cybersecurity toolkit with a web-based interface for analyzing files, networks, memory, registry, URLs, and system vulnerabilities on Windows systems.

> ⚠️ **Note:** This project is designed for **Windows only** and does not support Linux. Support for other operating systems may be added in the future.

## 💻 Windows Setup Guide

### 1. Create a Virtual Environment

Open Command Prompt or PowerShell and run:

```
cmd
python -m venv .venv
```

### 2. Activate the Virtual Environment

```
cmd
.venv\Scripts\activate
```

### 3. Install Dependencies

```
cmd
pip install -r requirements.txt
```

### 4. Run the Application

```
cmd
python app.py
```

The application will start at `http://127.0.0.1:5000`

### 5. Access the Web Interface

Open your browser and navigate to:
```
http://127.0.0.1:5000
```

## 📋 Project Overview

CyberShield is a Flask-based web application that provides multiple security scanning and analysis tools. It combines various security utilities into a unified web interface for easy access and comprehensive system analysis.

---

## 🛠️ Tools & Modules

### 1. File Analysis Module (`file_analysis/`)

**Purpose:** Analyzes suspicious files for malware, packed executables, and embedded threats.

**Key Features:**
- **File Identification**: Detect file type, format, and calculate MD5/SHA256 hashes
- **Entropy Analysis**: Calculate Shannon entropy to detect packed/encrypted files (>7.2 = suspicious)
- **Extension Spoofing Detection**: Identify files that are actually executables disguised with other extensions
- **PE (Portable Executable) Analysis**:
  - Digital signature verification
  - Packer detection (UPX, etc.)
  - Compilation timestamp analysis
  - Timestomping detection (future dates)
  - Dangerous API detection (VirtualAlloc, WriteProcessMemory, CreateRemoteThread, ShellExecute)
- **Embedded File Detection**: Find hidden files within the main file (ZIP, EXE, PDF, ELF)
- **String Extraction**: Extract and analyze strings (IP addresses, emails, URLs, registry keys, suspicious commands)
- **YARA Rules Scanning**: Scan files against custom YARA rule sets

**Files:**
- `file_analysis.py` - Command-line analyzer
- `web_analyzer.py` - Web interface version

---

### 2. Network Analysis Module (`network/`)

**Purpose:** Discovers devices on the network and analyzes network configuration.

**Key Features:**
- **Interface Detection**: Identify active network interface (Wi-Fi)
- **Public IP Info**: Fetch ISP and ASN information from ipinfo.io
- **DHCP/DNS Parsing**: Extract DHCP and DNS server information
- **Host Discovery**: Scan network for active devices using nmap
- **Port Scanning**: Scan common ports (21, 22, 23, 80, 443, 445, 3389, 161)
- **OS Fingerprinting**: Guess operating system from nmap data
- **SNMP Queries**: Query SNMP community 'public' for device information
- **NetBIOS Enumeration**: Get NetBIOS names via nbtstat

**Files:**
- `network.py` - Command-line network analyzer
- `web_network.py` - Web interface version

---

### 3. Registry Scanner Module (`registry_scanner/`)

**Purpose:** Scans Windows registry for malicious persistence mechanisms and security issues.

**Key Features:**
- **Startup Program Detection**: Scan all Run/RunOnce registry keys
- **Winlogon Hijacking Detection**: Check for shell/userinit modifications
- **AppInit DLLs Scanning**: Detect DLL injection points
- **Image File Execution Options (IFEO)**: Find debugger hijacking
- **LSA Package Analysis**: Detect credential theft packages
- **Session Manager Analysis**: Check BootExecute for rootkit persistence
- **Service Scanning**: Analyze Windows services for suspicious ImagePath
- **Print Monitor Detection**: Find persistence via print monitors

**Suspicious Indicators Detected:**
- Base64-encoded PowerShell commands
- Direct IP URLs (C2 indicators)
- Hidden window execution
- Suspicious paths (temp, appdata, recycler)
- Dangerous extensions (.vbs, .bat, .ps1, .scr, .hta)

**Files:**
- `registry_scanner.py` - Registry scanner engine
- `web_registry_scanner.py` - Web interface version

---

### 4. System Monitor Module (`system_monitor/`)

**Purpose:** Continuously monitors system activity and logs events to a file.

**Key Features:**
- **Process Monitoring**: Track new and terminated processes
- **Network Connection Monitoring**: Monitor ESTABLISHED connections
- **File System Monitoring**: Watch Downloads, Desktop, Documents folders for changes
- **Resource Monitoring**: Alert on high CPU (>80%), RAM (>85%), Disk (>90%) usage
- **Real-time Logging**: All events logged to `system_activity.log`

**Monitored Events:**
- PROCESS_START/PROCESS_STOP
- NETWORK_CONNECT/NETWORK_DISCONNECT
- FILE_CREATE/FILE_MODIFY/FILE_DELETE
- SYSTEM_ALERT (high resource usage)

**Files:**
- `system_logger.py` - Background monitoring service
- `log_analyzer.py` - Log analysis utilities
- `web_system_monitor.py` - Web interface version

---

### 5. URL/Website Scanner Module (`url_scan/`)

**Purpose:** Analyzes URLs and websites for security issues.

**Key Features:**
- **SSL/TLS Analysis**: Certificate information and validity
- **Security Headers Check**: Check for HSTS, CSP, X-Frame-Options
- **DNS Enumeration**: Query A, AAAA, MX, NS, TXT records
- **Subdomain Discovery**: Certificate Transparency logs via crt.sh
- **HTTP Methods Detection**: Check allowed HTTP methods
- **Directory Brute-forcing**: Scan for common directories (admin, login, backup, .git, test)
- **Technology Detection**: Identify CMS (WordPress, Drupal, Joomla) and web servers
- **WAF Detection**: Detect Cloudflare, Akamai, Imperva
- **Favicon Hashing**: Generate MD5 hash of favicon
- **IP Reputation**: Check AbuseIPDB for malicious IPs

**Files:**
- `url_scan.py` - Command-line URL scanner
- `web_url_scan.py` - Web interface version

---

### 6. Software Version Scanner Module (`vulnerability_scanner/`)

**Purpose:** Scans installed software for outdated versions.

**Key Features:**
- **Software Enumeration**: Scan Windows registry for installed programs
- **Version Parsing**: Extract and normalize version numbers
- **Vulnerability Database**: Compare against known vulnerable versions
- **winget Integration**: Check for available updates via Windows Package Manager
- **Risk Scoring**: Calculate 0-100 risk score based on:
  - Known CVEs in database
  - Version age compared to thresholds
  - Available updates

**Risk Levels:**
- Critical (≥90): Known critical vulnerabilities
- High (≥70): Known high-severity vulnerabilities
- Medium (≥50): Known medium-severity vulnerabilities
- Low (≥30): Update available

**Registry Paths Scanned:**
- HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
- HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\...\Uninstall
- HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall

**Files:**
- `web_vulnerability_scanner.py` - Main scanner
- `vulnerability_db.json` - Local vulnerability database

---

### 7. Memory Analyzer Module (`memory/`)

**Purpose:** Analyzes RAM usage and processes for suspicious activity.

**Key Features:**
- **RAM Statistics**: Total, available, used, free memory
- **Swap/Pagefile Analysis**: Swap memory usage details
- **Memory Health Analysis**: Determine system pressure level (Healthy/Moderate/High)
- **Memory Sampling**: Monitor memory usage over time
- **Top Memory Consumers**: List processes using most memory
- **Process Investigation**: Detailed analysis by PID or name
- **Process Tree**: Show parent/child process relationships
- **Suspicion Scoring**: Calculate 0-100 risk score based on:
  - High CPU (>50%): +20 points
  - High Memory (>10%): +20 points
  - Suspicious location (temp/appdata/downloads): +30 points
  - Random executable names: +10 points
  - Unsigned executables: +10 points

**Risk Levels:**
- HIGH: Score ≥ 60
- MEDIUM: Score ≥ 30
- LOW: Score < 30

**Files:**
- `memory.py` - Command-line memory analyzer
- `web_memory.py` - Web interface version

---

## 🌐 Web Interface

### Available Routes

| Route | Description |
|-------|-------------|
| `/` | Home/Dashboard |
| `/file-analysis` | File upload and analysis |
| `/firewall-status` | Basic firewall check |
| `/password-analysis` | Password strength checker |
| `/ram` | RAM and memory analysis |
| `/url-scan` | URL/Website scanner |
| `/network` | Network discovery |
| `/system-monitor` | System activity logs |
| `/vulnerability-scanner` | Software vulnerability scan |
| `/registry-scanner` | Windows registry security scan |

### API Endpoints

**RAM:**
- `/api/ram/basic` - System summary, RAM details, health analysis
- `/api/ram/top-processes` - Top 10 memory consumers
- `/api/ram/all-processes` - All processes (paginated)
- `/api/ram/sampling` - Real-time memory sampling (Server-Sent Events)
- `/api/ram/process-tree/<pid>` - Process tree for specific PID

**Network:**
- `/api/network/info` - Network interface and public IP info
- `/api/network/devices` - Device discovery (streaming)

**System Monitor:**
- `/api/system-monitor/stats` - Dashboard statistics
- `/api/system-monitor/logs` - Filtered logs
- `/api/system-monitor/event-types` - Available event types

**URL Scan:**
- `/api/url-scan` - POST endpoint for URL analysis

**Vulnerability:**
- `/api/vulnerability-scanner/scan` - Software vulnerability scan

**Registry:**
- `/api/registry-scanner/scan` - Registry security scan

---

## 🚀 Running the Application

### Prerequisites

Install required Python packages:
```
bash
pip install flask psutil requests python-whois dnspython pysnmpcolorama pefile puremagic oletools yara-python werkzeug
```

### Start the Server

```
bash
python app.py
```

The application will start at `http://127.0.0.1:5000`

### Access the Web Interface

Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 📁 Project Structure

```
final_project/
├── app.py                      # Flask main application
├── requirements.txt            # Python dependencies
├── system_activity.log        # System monitoring logs
│
├── file_analysis/             # File analysis module
│   ├── file_analysis.py       # CLI analyzer
│   ├── web_analyzer.py        # Web analyzer
│   └── yara_rules/           # YARA rule sets
│
├── network/                  # Network analysis module
│   ├── network.py            # CLI network scanner
│   └── web_network.py        # Web network scanner
│
├── registry_scanner/         # Registry scanner module
│   ├── registry_scanner.py   # Registry scanner engine
│   └── web_registry_scanner.py
│
├── system_monitor/          # System monitoring module
│   ├── system_logger.py      # Background logger
│   ├── log_analyzer.py       # Log analysis
│   └── web_system_monitor.py
│
├── url_scan/                # URL scanner module
│   ├── url_scan.py          # CLI URL scanner
│   └── web_url_scan.py      # Web URL scanner
│
├── vulnerability_scanner/   # Vulnerability scanner
│   ├── web_vulnerability_scanner.py
│   └── vulnerability_db.json
│
├── memory/                  # Memory analyzer module
│   ├── memory.py            # CLI memory analyzer
│   └── web_memory.py        # Web memory analyzer
│
├── templates/               # HTML templates
│   ├── index.html
│   ├── file_analysis.html
│   ├── network.html
│   ├── ram.html
│   ├── url_scan.html
│   ├── system_monitor.html
│   ├── vulnerability_scanner.html
│   └── registry_scanner.html
│
├── static/                 # CSS/JS files
│   ├── css/
│   └── js/
│
└── uploads/                # Uploaded files directory
```

---

## ⚠️ Important Notes

1. **Windows Only**: Some modules (Registry Scanner, System Monitor) require Windows
2. **Administrator Privileges**: Registry scanning and some network features may require elevated permissions
3. **nmap Required**: Network scanning requires nmap to be installed
4. **API Keys**: Some features (AbuseIPDB) require API keys to be configured

---

## 🔧 Configuration

### File Upload Settings
- Max file size: 50MB
- Allowed extensions: exe, dll, pdf, doc, docx, zip, txt, bin, sys

### Network Scanning
- Common ports: 21, 22, 23, 80, 443, 445, 3389, 161

### System Monitoring
- CPU Alert Threshold: >80%
- RAM Alert Threshold: >85%
- Disk Alert Threshold: >90%

---

## 📄 Additional Documentation

- `MODULES_PARAMETER_DOCUMENTATION.md` - Detailed parameter documentation
- `IMPLEMENTATION_SUMMARY.md` - Implementation details
- `USAGE.md` - Usage guide

---

*CyberShield - Comprehensive Security Analysis Platform*
