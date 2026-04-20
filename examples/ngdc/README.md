# NGDC -- 2012 National Gallery DC Scenario

## Scenario

The [2012 National Gallery DC scenario](https://digitalcorpora.org/corpora/scenarios/national-gallery-dc-2012-attack/) is a multi-device forensic investigation spanning approximately 10 days. It involves two intertwined criminal conspiracies centered around the National Gallery of Art in Washington, DC: an insider theft plot targeting a rare stamp collection, and unauthorized surveillance via a kernel-level keylogger. Evidence is distributed across disk images, mobile devices, network captures, and email logs from multiple suspects.

**Source:** [Digital Corpora](https://digitalcorpora.org/corpora/scenarios/national-gallery-dc-2012-attack/) (free download, ~112 GB)

## Evidence Analyzed

| Evidence Type | Items | Description |
|---------------|-------|-------------|
| Disk images (E01) | 9 daily snapshots each | Tracy's MacBook Air, external drive |
| Mobile images | 6 phone ZIPs, 12 tablet E01s | Carry's Samsung Nexus S, ASUS Transformer TF101 |
| Network captures | 4 exterior PCAPs, 4 interior PCAPs | NGDC interior/exterior network traffic |
| Email logs | 12 keylogger EML files | LogKext output emailed to joe.sum.twelve@gmail.com |

**Total evidence items classified:** 89

## Results

| Metric | Value |
|--------|-------|
| Findings | 12 (7 critical, 3 high, 2 medium) |
| Confirmed | 9 |
| Inference | 3 |
| Hypotheses ruled out | 1 |
| Tool calls | 159 |
| Wall-clock time | ~28 minutes |
| Evidence sources indexed | 18 |

### Findings

1. **[CRITICAL] LogKext Keylogger Installed on Tracy's MacBook Air** -- Kernel-level keylogger capturing all keystrokes from Tracy and Terry, emailing logs to joe.sum.twelve@gmail.com via Postfix at ~3-hour intervals.
2. **[CRITICAL] Tracy Exfiltrated Confidential NGDC Stamp Exhibit Documents** -- Terminal commands captured by keylogger show Tracy creating encrypted ZIP of stamp insurance documents (password: "Hercules"), emailing to coralbluetwo@hotmail.com.
3. **[CRITICAL] Stolen NGDC Documents Found on Tracy's External Drive** -- "NGDC things" directory containing stamp insurance PDFs, security guard rotation schedule, and blank NGDC letterhead. Deleted copies at root level show reorganization.
4. **[CRITICAL] Tracy Emailed Stolen Documents to Coral** -- Email from tracysumtwelve@gmail.com to coralbluetwo@hotmail.com with subject "things" and attachment "public.zip". Drafts found. documents.zip in Trash.
5. **[CRITICAL] Joe Installed LogKext Keylogger** -- Deleted user account "joesumtwelve" with Safari cache showing logkext research. Full installation: kernel extension, LaunchDaemon, support files, installation receipts.
6. **[CRITICAL] Coral Forwarded Stolen Documents to Perry Patsum** -- Within 20 minutes of receiving Tracy's email, Coral forwarded to perrypatsum@yahoo.com with subject "Some things for you" (Message-ID: 4FFB1349.70506@hotmail.com).
7. **[CRITICAL] Joe's Search History: Intentional Keylogger Research** -- "what does minmeg do logkext" (66x), "logkext minmeg" (36x), "is it ok to keylog children" (7x), "mac mail and crontab daughter".
8. **[HIGH] Tracy Facilitated Unauthorized Physical Access for Coral/Carry** -- Keylogger captured: "I can definitely help get your tablet in. Our security guards can be pretty ridiculous sometimes!"
9. **[HIGH] Wider Conspiracy Network: Pat, King, Coral Connected** -- Pat (patsumtwelve@gmail.com) emailed King (throne1966@hotmail.com) CC'ing Coral with subject "can't pass up" on July 6, three days before exfiltration.
10. **[HIGH] Financial Motive: Tracy's Tuition Crisis** -- Searches for private school tuition help, email to Joe about Prufrock Preparatory tuition, "our ticket" reference to stamp exhibit. Even Terry searched "how to help your parents with private school."
11. **[MEDIUM] VM.vmdk Virtual Machine on External Drive** -- Virtual machine disk coexisting with stolen NGDC documents on the portable exFAT drive.
12. **[MEDIUM] NGDC Interior Network Traffic: Webmail Access** -- Gmail and Outlook access from 192.168.1.101 during work hours, plus Louvre museum browsing on July 6.

### Key Actors Identified

| Actor | Role | Key Evidence |
|-------|------|-------------|
| Tracy (tracysumtwelve@gmail.com) | Gallery insider, document theft | Keylogger captures, encrypted ZIP creation, security bypass offer |
| Carry/Coral (cat2welve@gmail.com, coralbluetwo@hotmail.com) | Co-conspirator, intermediary | Forwarded documents to Perry within 20 minutes |
| Joe (joe.sum.twelve@gmail.com) | Keylogger operator | LogKext installation, "is it ok to keylog children" searches |
| Pat (patsumtwelve@gmail.com) | Conspirator | "can't pass up" email to King and Coral |
| Perry Patsum (perrypatsum@yahoo.com) | End recipient of stolen documents | Received forwarded documents from Coral |
| King (throne1966@hotmail.com) | Additional conspirator | Received "can't pass up" email from Pat |
| Terry (terrysumtwelve@gmail.com) | Tracy's daughter (not involved) | Innocent activity captured by keylogger |

## Ground Truth Comparison

The scenario narrative is [published on Digital Corpora](https://digitalcorpora.org/corpora/scenarios/national-gallery-dc-2012-attack/).

**Correctly identified:**
- Stamp theft conspiracy (Tracy + Coral) with full evidence chain and ZIP password "Hercules"
- LogKext keylogger installation, attribution to Joe, and dual-purpose nature
- Document exfiltration via encrypted ZIP with email chain (Tracy -> Coral -> Perry, 20-min turnaround)
- Physical security bypass (Tracy helping Carry bring tablet into gallery)
- Complete 5-person conspiracy network mapped with email addresses
- Financial motive (tuition crisis, divorce, "our ticket")
- Joe's keylogger research including "is it ok to keylog children" and crontab configuration
- Two distinct narratives correctly identified (insider theft + unauthorized surveillance)
- Security guard rotation schedule identified as critical intelligence for physical theft planning

**Not fully articulated:**
- Carry's tablet activity (steganography app "Sly", stamp valuation searches, "places with art and poor security" CNN search) was found in a prior run but not in this one
- The art defacement plot (Alex / Krasnovia) is not identified as a separate conspiracy

## Output Files

- [`ngdc.report.md`](ngdc.report.md) -- Full markdown report with executive summary, investigation narrative, findings, IOCs, MITRE ATT&CK coverage, and audit trail
- [`ngdc.report.html`](ngdc.report.html) -- Self-contained HTML report with dark/light theme, sidebar navigation, interactive timeline, and evidence browser
