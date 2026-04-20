# Example Investigations

This directory contains sample outputs from Mulder investigations run against well-known forensic datasets with published ground truth. Each subdirectory includes the generated reports and a README documenting the results and accuracy assessment.

| Scenario | Source | Evidence Types | Findings | Coverage |
|----------|--------|---------------|----------|----------|
| [ngdc](ngdc/) | [Digital Corpora -- National Gallery DC 2012](https://digitalcorpora.org/corpora/scenarios/national-gallery-dc-2012-attack/) | Disk images, mobile devices, PCAPs, email logs | 12 (7 critical, 3 high) | Stamp-theft chain + keylogger fully reconstructed; artwork defacement plot not surfaced |
| [nist-data-leakage](nist-data-leakage/) | [NIST CFReDS Data Leakage Case](https://cfreds.nist.gov/all/NIST/DataLeakageCase) | PC disk image, 2 USB images, CD-R image | 10 (5 critical, 5 high) | Full exfiltration chain, premeditation, and cleanup session reconstructed |
