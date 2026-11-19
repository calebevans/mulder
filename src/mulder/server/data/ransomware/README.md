# Ransomware lookup tables

`ransomware_extensions_lookup.csv` and `ransomware_notes_lookup.csv` are copied
unmodified from Splunk's security_content repository:

- Source: https://github.com/splunk/security_content/tree/develop/lookups/csv
- Commit: `a9ef36bfc90fc79eb54828f0310e681eba6a3eca`
- Author: Splunk Threat Research Team
- License: Apache-2.0 (https://github.com/splunk/security_content/blob/develop/LICENSE)

Both are wildcard lists (`*` only, case-insensitive). The extension table maps
a file extension to a family name; the note table lists file names known to be
ransom notes and carries no family. They are read by
`mulder.server.tools.composite.ransomware_family`.
