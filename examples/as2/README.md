# AS2 -- ICS/SCADA Railway and Power Grid Attack (NCL Singapore)

## Scenario

The AS2 (Attack Scenario 2) dataset is from the [National Cybersecurity R&D Laboratory (NCL)](https://ncl.sg/) at the National University of Singapore. It simulates an APT44 (Sandworm)-inspired multi-stage cyberattack against interconnected railway and power grid ICS/SCADA infrastructure, based on the 2015 BlackEnergy attack on the Ukrainian power grid.

The attack chain spans IT-to-OT lateral movement: exploiting a web application vulnerability to deploy a web shell, planting a disguised trojan for C2, pivoting through SSH to HMI stations, and ultimately injecting false data into PLCs to trigger a power grid circuit breaker shutdown that causes a railway power outage.

**Source:** [NCL Singapore Data Resources](https://ncl.sg/data_resources) (free download)
**Paper:** [Signals and Symptoms: ICS Attack Dataset From Railway Cyber Range](https://arxiv.org/html/2507.01768v1) (Yusof et al., 2025)

## Evidence Analyzed

| Evidence Type | Items | Description |
|---------------|-------|-------------|
| Memory dumps | 2 | staff01 (3.1GB) and staff03 (1.3GB) -- Windows workstations on corporation network |
| Network capture | 1 | tcpdump from main router, ~9.5 hours (04:40--14:06 UTC), 922MB |
| Application logs | 1 | Railway web application logs (345KB) |
| Misc | 3 | SSL keylog file, attack demo videos (Railway, Power Grid, HMI) |

## Results

| Metric | Value |
|--------|-------|
| Findings | 12 (6 critical, 6 high) |
| Confirmed | 11 |
| Inference | 1 |
| Hypotheses ruled out | 1 |
| Tool calls | 152 |
| Wall-clock time | ~21 minutes |
| Evidence sources indexed | 17 |

### Findings

1. **[CRITICAL] ICS Attack Malware: attackScript_FDI_Exy.exe in Startup Folder** -- FDI (False Data Injection) + exfiltration tool in Windows Startup folder on staff01, with active S7comm connection to PLC 10.27.34.41:102.
2. **[CRITICAL] C2 Data Exfiltration via /dataPost/spyTrojan01** -- HTTP POST beaconing every ~5s to 100.101.1.145:5001 over TLS 1.3, with self-signed "ncl" certificate. Full C2 API decoded: `/dataPost/`, `/filedownload`, `/fileupload`, `/getLastRst`.
3. **[CRITICAL] Trojanized ZoomMeetingInstaller.exe via File Sync** -- Supply chain compromise through internal file sync server at 10.27.34.12:8081. PyInstaller-packed Python app with PyQt5 GUI disguised as Zoom installer.
4. **[CRITICAL] ICS Protocol Activity: S7comm and Modbus TCP** -- 2,471 S7comm frames and 1,320 Modbus TCP frames across 4 PCAPs. All observed operations are reads; FDI attack likely operates at HMI display level.
5. **[CRITICAL] Hardcoded Credentials: admin/ncl1234** -- Credential tuple found in malware memory (`10.27.34.102;admin;ncl1234`). "ncl" matches C2 TLS certificate organization, linking credential to attacker infrastructure.
6. **[CRITICAL] Lateral Movement via SSH to 3 ICS HMI Stations** -- ZoomMeetingInstaller.exe established SSH to 10.27.34.103, .104, .105 (controlling 7 PLCs via Modbus/S7comm). Sequential timing (~2 min apart) suggests automation.
7. **[HIGH] Secondary C2 Endpoint at 192.168.50.42:5000** -- Second C2 on internal management network (`/dataPost/IT_Sup`), same `/dataPost/` pattern as primary C2.
8. **[HIGH] Steganographic File Upload: Alice.jpg (PNG)** -- File type mismatch (.jpg extension, PNG content) uploaded to Railway web application.
9. **[HIGH] Attack Videos from MacBook Pro in Singapore** -- Three videos documenting physical ICS impact, EXIF timestamps correlate with attackScript_FDI_Exy.exe PLC connection.
10. **[HIGH] PyInstaller-Packed Attack Tools** -- Both executables are 352,256-byte PyInstaller-packed Python apps. ZoomMeetingInstaller.exe includes PyQt5 GUI; attackScript_FDI_Exy.exe loads select.pyd for socket operations.
11. **[HIGH] ICS Network Topology: 4 HMI Stations, 7 PLCs/RTUs** -- Complete SCADA network mapped with Modbus and S7comm communication paths.
12. **[HIGH] RDP Session and File Sync Server** -- RDP from 10.27.34.11 to staff03 before malware execution; file sync client connection to 10.27.34.12:8081 confirmed as delivery mechanism.

### ATT&CK Coverage

22 techniques across 12 tactics (Enterprise + ICS):

| Tactic | Techniques |
|--------|-----------|
| Initial Access | T0886 Remote Services, T1078.001 Default Accounts |
| Execution | T1059.006 Python, T1204.002 Malicious File |
| Persistence | T1547.001 Startup Folder |
| Defense Evasion | T1027 Obfuscation, T1027.002 Software Packing, T1036.005 Masquerading |
| Credential Access | T1552.001 Credentials In Files |
| Lateral Movement | T0843 Program Download, T0886 Remote Services, T1021.001 RDP, T1021.004 SSH, T1570 Lateral Tool Transfer |
| Command and Control | T1001.002 Steganography, T1071.001 Web Protocols, T1105 Ingress Tool Transfer, T1573.002 Asymmetric Crypto |
| Exfiltration | T1041 Exfiltration Over C2 Channel |
| Impact (ICS) | T0831 Manipulation of Control |
| Impair Process Control (ICS) | T0855 Unauthorized Command Message |
| Collection (ICS) | T0801 Monitor Process State |

## Ground Truth Comparison

The ground truth is documented in [Table 2 of the paper](https://arxiv.org/html/2507.01768v1) which describes 12 attack steps.

**Correctly identified (steps 2-7, 12):**
- Trojan deployment via file sync server disguised as `ZoomMeetingInstaller.exe` (step 2) -- identified supply chain vector
- Staff execution of disguised trojan via scheduled batch file (step 3) -- full process tree reconstructed
- C2 communication with `/dataPost/spyTrojan01` endpoint characterized (step 4) -- C2 API fully decoded from memory
- Network recon, credential theft (admin/ncl1234), lateral movement to HMI stations via SSH (step 5)
- FDI attack script (`attackScript_FDI_Exy.exe`) correctly identified with S7comm connection to PLC (step 6)
- SSH connections to SCADA workstations documented with timestamps (step 7)
- Physical impact on railway and power grid documented via video EXIF correlation (step 12)

**Additionally found (not in ground truth table):**
- Secondary C2 endpoint at 192.168.50.42:5000 on internal management network
- Hardcoded credentials linking malware to C2 infrastructure via "ncl" identifier
- PyInstaller packing analysis of both attack tools
- Complete ICS network topology with all HMI-to-PLC communication paths
- Startup folder persistence mechanism

**Partially identified (step 1):**
- File upload to Railway web application found (Alice.jpg), but the pickle deserialization exploit (`image.txt` with `builtins.exec()`) was not decoded in this run (was found in a prior run)

**Not directly observed (steps 8-11):**
- False data injection into RTU memory (step 8) -- no Modbus/S7 write operations visible in PCAP; correctly hypothesized HMI-level FDI instead
- HMI anomaly detection and automated protection trigger (steps 9-10) -- occurred on systems not captured in memory dumps
- PLC circuit breaker command (step 11) -- physical-layer effect documented via video but protocol-level command not captured

## Output Files

- [`as2.report.md`](as2.report.md) -- Full markdown report with executive summary, investigation narrative, findings, IOCs, MITRE ATT&CK coverage, and audit trail
- [`as2.report.html`](as2.report.html) -- Self-contained HTML report with dark/light theme, sidebar navigation, interactive timeline, and evidence browser
- [`claude.log`](claude.log) -- Raw Claude Code session log showing the agent's reasoning, tool calls, and analysis steps
