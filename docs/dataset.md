# Mulder -- Dataset Documentation

## Dataset Used

**Name:** *(Fill in after dataset selection)*

**Source:** *(Link to the dataset download page)*

**Recommended options:**
- [DFRWS 2023 Challenge Data](https://dfrws.org/) -- memory dump + disk image with documented intrusion
- [SANS DFIR Challenge Images](https://www.sans.org/) -- curated forensic images with ground truth
- [Volatility Foundation Sample Images](https://github.com/volatilityfoundation/volatility3/wiki/Memory-Samples) -- memory dumps for testing Volatility plugins

**Selection criteria:**
- Must include a Windows memory dump (for Volatility extraction)
- Should include event logs or a disk image (for cross-source correlation)
- Must have documented ground truth findings (for accuracy measurement)
- Should be publicly available (for reproducibility)

---

## Contents

| Artifact | Path | Size | Description |
|----------|------|------|-------------|
| Memory dump | | | Windows memory image |
| Disk image | | | Filesystem image (E01/dd) |
| Event logs | | | Windows EVTX files |
| Text logs | | | Application/system logs |

---

## Expected Findings (Ground Truth)

These are the known-bad indicators documented in the dataset's answer key. Mulder's findings will be compared against this list for the accuracy report.

| # | Finding | Severity | Expected Sources |
|---|---------|----------|-----------------|
| 1 | | | |
| 2 | | | |
| 3 | | | |
| 4 | | | |
| 5 | | | |

---

## Ingestion Notes

```bash
mulder ingest /path/to/dataset/ --case-id dataset-name
```

**Expected extraction results:**
- Volatility plugins: pslist, pstree, cmdline, netscan, malfind, dlllist, svcscan, handles
- Event log channels: Security, System, Application, PowerShell, Sysmon (if available)
- Timeline: Plaso super timeline (if disk image present)
- Log files: any text logs in the dataset

**Expected window count:** *(Fill in after ingestion)*

**Expected ingestion time:** *(Fill in after ingestion)*
