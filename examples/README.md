# Example Investigations

This directory contains sample outputs from Mulder investigations run against well-known forensic datasets with published ground truth. Each subdirectory includes the generated reports and a README documenting the results and accuracy assessment.

| Scenario | Source | Evidence Types | Findings | Accuracy |
|----------|--------|---------------|----------|----------|
| [ngdc](ngdc/) | [Digital Corpora -- National Gallery DC 2012](https://digitalcorpora.org/corpora/scenarios/national-gallery-dc-2012-attack/) | Disk images, mobile devices, PCAPs, email logs | 12 (7 critical, 3 high) | ~85-90% of ground truth |
| [nist-data-leakage](nist-data-leakage/) | [NIST CFReDS Data Leakage Case](https://cfreds.nist.gov/all/NIST/DataLeakageCase) | PC disk image, 2 USB images, CD-R image | 10 (5 critical, 5 high) | All major elements |
| [as2](as2/) | [NCL Singapore Railway/Power Grid ICS Attack](https://ncl.sg/data_resources) | 2 memory dumps, PCAP, web logs, SSL keylog | 12 (6 critical, 6 high) | 7/12 attack steps + extras |
