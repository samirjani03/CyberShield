# Detailed Parameter Analysis for Each Security Module

This document provides a comprehensive explanation of all parameters used in each scanning module of this cybersecurity project.

---

## 1. FILE ANALYSIS MODULE (`file_analysis/file_analysis.py`)

### Class: `UniversalAnalyzer`

| Parameter | Type | Description |
|-----------|------|-------------|
| `file_path` | str | Path to the file to be analyzed |

### Key Methods & Their Parameters:

#### `__init__(file_path)`
- `file_path`: Path to the target file for analysis

#### `calculate_entropy()`
- Calculates Shannon entropy (0-8 scale) to detect packed/encrypted files
- Entropy > 7.2 indicates potential packing or encryption

#### `extract_strings()`
- Uses regex patterns from `PATTERNS` dictionary:
  - **IPv4 Address**: `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`
  - **Email**: `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`
  - **URL**: `http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+`
  - **Registry Keys**: `HKEY_\w+`
  - **Suspicious Commands**: `(cmd\.exe|powershell|/bin/sh|/bin/bash|wget|curl)`

#### `scan_embedded()`
- Detects hidden files within the main file using signatures:
  - `PK\x03\x04`: ZIP Archive / Office Doc
  - `MZ`: Windows Executable (EXE)
  - `%PDF`: PDF Document
  - `\x7fELF`: Linux Executable

#### `analyze_pe_advanced(pe)`
- `pe`: Pre-loaded pefile object
- Checks:
  - Digital Signature (SECURITY directory)
  - Packer Detection (UPX section names)
  - Compilation Timestamp
  - Dangerous API Imports (VirtualAlloc, WriteProcessMemory, CreateRemoteThread, ShellExecute)

#### `yara_scan(rule_root, sample_path)`
- `rule_root`: Path to YARA rules directory
- `sample_path`: Path to file being scanned

### Configuration Constants:
```
python
KNOWN_MALWARE_DB = {
    'b48f58334c6799d5543c72b2260f8983': {'family': 'WannaCry', 'type': 'Ransomware'},
    '87bed5a7cba00c7e1f4015f1bbede187': {'family': 'Ryuk', 'type': 'Ransomware'},
}

EMBEDDED_SIGNATURES = {
    b'PK\x03\x04': "ZIP Archive / Office Doc",
    b'MZ': "Windows Executable (EXE)",
    b'%PDF': "PDF Document",
    b'\x7fELF': "Linux Executable"
}
```

---

## 2. NETWORK MODULE (`network/network.py`)

### Key Functions & Parameters:

| Function | Parameters | Description |
|----------|------------|-------------|
| `get_interface_network()` | None | Returns (ip, network) tuple for Wi-Fi interface |
| `get_public_info()` | None | Fetches public IP info from ipinfo.io |
| `parse_dhcp_dns()` | None | Parses DHCP and DNS servers from `ipconfig /all` |
| `discover_hosts_with_nmap(network)` | `network`: IPv4Network object | Uses nmap for host discovery (-sn flag) |
| `nmap_scan(ip)` | `ip`: Target IP address | Port scan with arguments: `-sS -sV -O -Pn -p {COMMON_PORTS}` |
| `snmp_sysdesc(ip)` | `ip`: Target IP | Queries SNMP community 'public' on port 161 |
| `netbios_name(ip)` | `ip`: Target IP | Uses `nbtstat -A` to get NetBIOS name |

### Configuration Constants:
```
python
COMMON_PORTS = "21,22,23,80,443,445,3389,161"
```

### nmap_scan Parameters Breakdown:
- `-sS`: TCP SYN scan (stealth)
- `-sV`: Service version detection
- `-O`: OS detection
- `-Pn`: No ping (skip host discovery)
- `-p {COMMON_PORTS}`: Scan specified ports

### SNMP Parameters:
- **Community String**: 'public' (default read-only)
- **Timeout**: 1 second
- **Retries**: 0
- **OID**: 1.3.6.1.2.1.1.1.0 (sysDescr)

---

## 3. REGISTRY SCANNER MODULE (`registry_scanner/registry_scanner.py`)

### Class: `RegistryScanner`

#### Configuration Parameters:

##### Startup Locations Scanned:
```
python
STARTUP_LOCATIONS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunServices"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"),
]
```

##### Security-Critical Locations:
- Winlogon (shell, userinit)
- AppInit_DLLs
- Image File Execution Options (IFEO)
- Safe Boot configuration
- LSA Packages
- Session Manager (BootExecute)
- AppCertDlls
- Print Monitors
- Services

#### Key Methods:

| Method | Parameters | Description |
|--------|------------|-------------|
| `scan_registry_key(hive, path, wow64_64)` | `hive`: Registry hive, `path`: Key path, `wow64_64`: 64-bit view | Scans specific registry key |
| `is_suspicious(value)` | `value`: Registry value | Checks for obfuscation patterns, suspicious paths/extensions |
| `scan_startup_programs()` | None | Scans all startup locations |
| `scan_winlogon()` | None | Checks shell/userinit for hijacking |
| `scan_ifeo_debuggers()` | None | Detects debugger hijacking |
| `scan_lsa_packages()` | None | Checks for credential theft packages |
| `scan_services(limit)` | `limit`: Max services to scan (default 80) | Scans Windows services |

#### Suspicious Indicators:

##### Obfuscation Patterns:
```
python
OBFUSCATION_PATTERNS = [
    (r"-enc\s+[A-Za-z0-9+/=]{20,}", "Base64-encoded PowerShell command"),
    (r"-e\s+[A-Za-z0-9+/=]{20,}", "Base64-encoded command"),
    (r"FromBase64String|\[Convert\]::", "Base64 decoding in command"),
    (r"iex\s*\(|Invoke-Expression", "Dynamic code execution"),
    (r"hidden|bypass|encoded", "Stealth execution flag"),
    (r"http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/", "Direct IP URL (C2 indicator)"),
    (r"powershell.*-w\s*1\s+", "Hidden window execution"),
    (r"cmd\s+/c\s+echo\s+[A-Za-z0-9+/=]+", "Encoded cmd payload"),
]
```

##### Suspicious Paths:
```
python
SUSPICIOUS_PATHS = [
    "temp", "tmp", "appdata\\local\\temp", "programdata",
    "public\\", "roaming\\", "\\users\\public", "\\temp\\",
    "appdata\\roaming\\", "program files (x86)\\", "\\recycler",
]
```

##### Suspicious Extensions:
```
python
SUSPICIOUS_EXTENSIONS = [
    ".vbs", ".bat", ".cmd", ".ps1", ".scr", ".hta", ".js", ".jse", ".wsf"
]
```

---

## 4. SYSTEM MONITOR MODULE (`system_monitor/system_logger.py`)

### Class: `SystemActivityLogger`

| Parameter | Type | Description |
|-----------|------|-------------|
| `log_file` | str | Output file for logs (default: "system_activity.log") |

#### Key Methods:

| Method | Parameters | Description |
|--------|------------|-------------|
| `monitor_processes()` | None | Tracks new/terminated processes |
| `monitor_network()` | None | Monitors ESTABLISHED connections |
| `monitor_files(watch_dirs)` | `watch_dirs`: List of directories | Monitors file creation/modification/deletion |
| `monitor_system_resources()` | None | Alerts on CPU>80%, RAM>85%, Disk>90% |

#### Monitored Directories (Default):
```
python
watch_dirs = [
    home / "Downloads",
    home / "Desktop",
    home / "Documents"
]
```

#### System Resource Thresholds:
- **CPU Alert**: > 80%
- **RAM Alert**: > 85%
- **Disk Alert**: > 90%

#### Monitoring Intervals:
- Process/Network: Every 5 seconds
- Files: Every 15 seconds (every 3rd cycle)
- System Resources: Every 30 seconds (every 6th cycle)

---

## 5. URL SCAN MODULE (`url_scan/url_scan.py`)

### Key Functions & Parameters:

| Function | Parameters | Description |
|----------|------------|-------------|
| `ssl_analysis(domain)` | `domain`: Target domain | SSL/TLS certificate analysis |
| `get_headers(domain)` | `domain`: Target domain | Security header analysis |
| `get_dns(domain)` | `domain`: Target domain | DNS record enumeration (A, AAAA, MX, NS, TXT) |
| `get_subdomains(domain)` | `domain`: Target domain | Certificate Transparency logs via crt.sh |
| `check_http_methods(domain)` | `domain`: Target domain | OPTIONS request for allowed methods |
| `directory_scan(domain)` | `domain`: Target domain | Brute-force common directories |
| `detect_tech(domain)` | `domain`: Target domain | CMS and technology detection |
| `detect_waf(headers)` | `headers`: HTTP response headers | WAF detection |
| `abuseip_lookup(ip)` | `ip`: IP address | AbuseIPDB reputation check |

#### Configuration:
```
python
ABUSEIPDB_API_KEY = ""   # API key for IP reputation lookup

COMMON_DIRS = ["admin", "login", "dashboard", "backup", ".git", "test"]
```

#### SSL Analysis Parameters:
- **Timeout**: 5 seconds
- **Port**: 443
- **SSL Context**: Default (Python ssl.create_default_context())

#### DNS Record Types:
- A (IPv4)
- AAAA (IPv6)
- MX (Mail Exchange)
- NS (Name Servers)
- TXT (Text Records)

#### Security Headers Checked:
- Strict-Transport-Security
- Content-Security-Policy
- X-Frame-Options

---

## 6. VULNERABILITY SCANNER MODULE (`vulnerability_scanner/web_vulnerability_scanner.py`)

### Key Functions & Parameters:

| Function | Parameters | Description |
|----------|------------|-------------|
| `parse_version(version_str)` | `version_str`: Version string | Extracts normalized version tuple |
| `compare_versions(v_installed, v_reference)` | Two version tuples | Compares version numbers |
| `get_installed_software()` | None | Enumerates installed software from registry |
| `load_vulnerability_db()` | None | Loads JSON vulnerability database |
| `compute_risk_score(software, vuln_db, winget_upgrades)` | Software dict, DB, winget data | Calculates 0-100 risk score |
| `get_winget_upgrades()` | None | Runs `winget upgrade` for available updates |

#### Registry Paths Scanned:
```
python
UNINSTALL_PATHS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
]
```

#### Version Patterns Regex:
```
python
VERSION_PATTERNS = [
    r'(\d{1,5}\.\d{1,5}\.\d{1,5}\.\d{1,5})',   # 1.2.3.4
    r'(\d{1,5}\.\d{1,5}\.\d{1,5})',             # 1.2.3
    r'(\d{1,5}\.\d{1,5})',                       # 1.2
    r'(\d{1,5})',                                # 1
    r'(\d{4}\.\d{1,2}\.\d{1,2})',               # 2024.1.15
    r'(\d{4}\.\d{1,2})',                         # 2024.1
    r'v?(\d+\.\d+\.\d+[.\d]*)',                  # v1.2.3 or 1.2.3.4
]
```

#### Risk Score Thresholds:
- **Critical** (score ≥90): Version older than critical threshold
- **High** (score ≥70): Version older than high threshold
- **Medium** (score ≥50): Version older than medium threshold
- **Low** (score ≥30): Update available via winget

#### winget Parameters:
- `--accept-source-agreements`: Accept source agreements
- `--include-unknown`: Include packages without version
- **Timeout**: 90 seconds

---

## 7. MEMORY ANALYZER MODULE (`memory/memory.py`)

### Key Functions & Parameters:

| Function | Parameters | Description |
|----------|------------|-------------|
| `get_ram_details()` | None | Returns comprehensive RAM statistics |
| `show_advanced_ram()` | None | Shows detailed memory breakdown |
| `memory_health_analysis()` | None | Analyzes memory pressure status |
| `memory_sampling(duration)` | `duration`: Seconds to sample (default 5) | Samples memory usage over time |
| `show_top_memory_processes(limit)` | `limit`: Number of processes (default 5) | Lists top memory consumers |
| `show_process_memory_details(pid)` | `pid`: Process ID | Detailed memory info for specific process |
| `calculate_suspicion(process)` | `process`: psutil.Process object | Calculates 0-100 suspicion score |
| `scan_processes()` | None | Scans all processes for suspicious activity |
| `show_process_tree(pid, name)` | Either `pid` or `name` | Shows process parent/child relationships |

#### Memory Health Thresholds:
```
python
def memory_pressure_status():
    percent = psutil.virtual_memory().percent
    if percent < 60:
        return "HEALTHY"
    elif percent < 80:
        return "MODERATE"
    else:
        return "HIGH PRESSURE"
```

#### Suspicion Score Calculation:
| Factor | Condition | Points |
|--------|-----------|--------|
| High CPU | > 50% | +20 |
| High Memory | > 10% | +20 |
| Suspicious Location | temp/appdata/downloads | +30 |
| Random-looking name | 10+ alphanumeric chars | +10 |
| Unsigned executable | Not in Program Files | +10 |

#### Risk Levels:
- **HIGH**: Score ≥ 60
- **MEDIUM**: Score ≥ 30
- **LOW**: Score < 30

---

## Summary Table

| Module | Primary Scan Target | Key Parameters |
|--------|---------------------|-----------------|
| File Analysis | Files/PE executables | file_path, entropy threshold (7.2), YARA rules |
| Network | Network infrastructure | IP, network range, ports (21,22,23,80,443,445,3389,161) |
| Registry | Windows Registry | HKLM/HKCU paths, WOW64 flags, suspicious patterns |
| System Monitor | Running system | Process, network, file, CPU/RAM/Disk thresholds |
| URL Scan | Websites/URLs | Domain, SSL cert, DNS records, HTTP headers |
| Vulnerability | Software | Installed software versions, vulnerability DB |
| Memory | RAM/Processes | PID, memory percentage, process tree |

---

*This documentation was generated as part of the cybersecurity project analysis.*
