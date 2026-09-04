# Mulder MCP Tool Manifest

Every tool is exposed as `mcp__mulder__{name}`. All tools return a dict containing at minimum `tool_call_id` and `status`. Extraction tools additionally return `source_name`, `windows_indexed`, and `line_count`. Write tools (those with a `source_name`) return only metadata plus a 500-character content preview; full output is accessible via `search()` or `get_raw_output()`.

**Role Key:** `CATALOG` `EXTRACT_PLANNER` `EXTRACT_EXECUTOR` `EXTRACT_ANALYST` `CROSS_PLANNER` `CROSS_EXECUTOR` `CROSS_ANALYST` `NARRATIVE_PLANNER` `NARRATIVE_EXECUTOR` `NARRATIVE_ANALYST` `REPORT`

---

## 1. Case Management

### scan_evidence

Scan an evidence directory and create a new case for investigation.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| evidence_path | str | yes | Directory or file containing forensic evidence |
| case_id | str \| None | no | Unique case identifier; auto-derived from directory name if omitted |
| replace | bool | no | Delete and recreate an existing case (default False) |

**Returns:** `case_id`, `evidence_path`, `evidence_tree`, `type_summary`, `total_items`

**Roles:** `CATALOG`

### open_case

Switch the active case to an already-existing case.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| case_id | str | yes | Case identifier to load |

**Returns:** `case_id`, `source_count`

**Roles:** `ALL_ROLES`

### list_cases

List all cases in the database directory.

*No parameters.*

**Returns:** `results[]` (case_id, evidence_root, source_count, ingested_at), `active_case`

**Roles:** `CATALOG` `EXTRACT_PLANNER` `REPORT`

### extract_archive

Extract a compressed evidence archive to make its contents accessible.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| archive_path | str | yes | Path to the compressed archive |
| extract_to | str \| None | no | Optional destination directory |

**Returns:** `extracted_to`, `total_files_extracted`, `type_summary`, `total_evidence_items`

**Roles:** `CATALOG` `EXTRACT_EXECUTOR`

### collect_linux_live_state_bundle

Explicitly collect bounded, typed state from the current Linux host into a
sealed bundle below the case directory. This tool has no command, SSH, remote,
network, arbitrary input-path, or arbitrary output-path parameter.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| host_id | str | yes | Exact current hostname to authorize and record |
| checks | list[str] | yes | Built-in Linux check IDs to run |
| bundle_name | str | yes | Safe output filename stem |
| max_files_per_check | int | no | Per-check file bound (default 2,000) |
| max_bytes_per_file | int | no | Per-file capture bound (default 2 MiB) |
| max_total_bytes | int | no | Aggregate capture bound (default 64 MiB) |

**Returns:** bundle path/digest/seal and per-check
`success`/`empty`/`partial`/`failed` coverage. Detailed coverage is also stored
in the case coverage register.

**Roles:** `CATALOG` `EXTRACT_EXECUTOR`

### verify_evidence_integrity

Verify the integrity of all indexed source data by recomputing BLAKE2b hashes.

*No parameters.*

**Returns:** `total_sources`, `verified_count`, `modified_count`, `no_hash_count`, `sources[]`, `elapsed_ms`

**Roles:** `CATALOG`

---

## 2. Extraction: Memory

### run_volatility

Run a single Volatility 3 plugin against a memory dump and index the output.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| plugin | str | yes | Plugin name (e.g. "pslist" or "windows.pslist.PsList") |
| memory_path | str | yes | Path to the memory dump file |

**Returns:** `source_name`, `windows_indexed`, `line_count`, `plugin`

**Roles:** `EXTRACT_EXECUTOR`

### run_volatility_batch

Run multiple Volatility 3 plugins in one call with shared context setup.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| plugins | list[str] | yes | Plugin names (short or full form) |
| memory_path | str | yes | Path to the memory dump file |
| force | bool | no | Skip the already-indexed check (default False) |

**Returns:** `plugins_requested`, `plugins_succeeded`, `plugins_failed`, `total_windows_indexed`, `per_plugin{}`

**Roles:** `EXTRACT_EXECUTOR`

---

## 3. Extraction: Disk

### run_mmls

List partitions in a disk image using TSK mmls.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| image_path | str | yes | Path to the disk image (E01, dd, img) |

**Returns:** `source_name` (tsk.partitions), `windows_indexed`, `line_count`

**Roles:** `EXTRACT_EXECUTOR`

### run_fls

List all files and directories (including deleted) from a disk image. Automatically analyzes all NTFS partitions above 100 MB when multiple partitions are present, indexing each as a separate source. The largest NTFS partition is selected as primary when `partition_offset` is omitted.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| image_path | str | yes | Path to the disk image |
| partition_offset | int \| None | no | Sector offset; auto-detected (largest NTFS) if omitted |
| force | bool | no | Re-run extraction even if sources already exist |

**Returns:** `source_name` (tsk.filelist), `windows_indexed`, `line_count`, `partitions_analyzed`

**Roles:** `EXTRACT_EXECUTOR`

### run_fsstat

Retrieve filesystem metadata (type, block size, volume label) from a disk image.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| image_path | str | yes | Path to the disk image |

**Returns:** `source_name` (tsk.fsstat), `windows_indexed`, `line_count`

**Roles:** `EXTRACT_EXECUTOR`

### run_mactime

Generate a filesystem MAC timeline from a disk image using TSK fls + mactime.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| image_path | str | yes | Path to the disk image |
| time_range | str \| None | no | Date range filter (e.g. "2015-08-01..2015-08-05") |

**Returns:** `source_name` (tsk.timeline), `windows_indexed`, `line_count`

**Roles:** `EXTRACT_EXECUTOR`

### run_bulk_extractor

Carve IOCs (URLs, emails, domains, IPs) from a disk image using bulk_extractor.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| image_path | str | yes | Path to the disk image |
| features | list[str] \| None | no | Feature types to index (default all) |
| scanners | list[str] \| None | no | Scanner names to enable (default all) |
| max_depth | int \| None | no | Maximum recursion depth (default 12) |
| force | bool | no | Re-run extraction even if sources already exist |

**Returns:** `features_indexed`, `total_windows_indexed`, `per_feature[]`

**Roles:** `EXTRACT_EXECUTOR`

### run_strings

Extract printable strings from a file or disk image.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| target_path | str | yes | Path to the file to scan |
| min_length | int | no | Minimum string length (default 8) |

**Returns:** `source_name` (strings.output), `windows_indexed`, `line_count`

**Roles:** `EXTRACT_EXECUTOR`

### run_plaso

Run log2timeline (Plaso) against an evidence file to build a super-timeline.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| evidence_path | str | yes | Path to a disk image or directory |
| parsers | str \| None | no | Comma-separated Plaso parsers (e.g. "winevtx,prefetch,pe") |
| time_range | str \| None | no | Date filter passed to psort |

**Returns:** `source_name` (plaso.timeline), `windows_indexed`

**Roles:** `EXTRACT_EXECUTOR`

### run_foremost

Carve files from a disk image using foremost.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| image_path | str | yes | Path to the disk image |

**Returns:** `source_name` (foremost.audit), `windows_indexed`

**Roles:** `EXTRACT_EXECUTOR`

### run_scalpel

Carve files from a disk image using Scalpel.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| image_path | str | yes | Path to the disk image or raw partition |

**Returns:** `source_name` (scalpel.audit), `windows_indexed`

**Roles:** `EXTRACT_EXECUTOR`

### run_binwalk

Scan a file for embedded files, firmware headers, and compressed archives.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| target_path | str | yes | Path to the file to scan |
| extract | bool | no | If True, extract embedded files (default False) |

**Returns:** `source_name` (binwalk.scan), `windows_indexed`

**Roles:** `EXTRACT_EXECUTOR`

### run_photorec

Recover deleted files from a disk image using PhotoRec.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| image_path | str | yes | Path to the disk image or partition |

**Returns:** `source_name` (photorec.report), `windows_indexed`

**Roles:** `EXTRACT_EXECUTOR`

### run_hashdeep

Compute recursive cryptographic hashes using hashdeep.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| target_path | str | yes | Path to the file or directory to hash |

**Returns:** `source_name` (hashdeep.hashes), `windows_indexed`

**Roles:** `EXTRACT_EXECUTOR`

### run_ssdeep

Compute fuzzy hashes of files using ssdeep.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| target_path | str | yes | Path to a file or directory |
| recursive | bool | no | Hash all files recursively (default False) |

**Returns:** `source_name` (ssdeep.hashes), `windows_indexed`

**Roles:** `EXTRACT_EXECUTOR`

### run_exiftool

Extract file metadata (EXIF, document properties) using exiftool.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| target_path | str | no | Path to the file or directory |
| file_path | str | no | Alias for target_path |

**Returns:** `source_name` (exiftool.metadata), `windows_indexed`

**Roles:** `EXTRACT_EXECUTOR` `EXTRACT_ANALYST`

### run_chkrootkit

Scan for known Linux rootkits and suspicious kernel modifications.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| target_path | str \| None | no | Alternate root path to check (e.g. a mounted disk image) |

**Returns:** `source_name` (chkrootkit.scan), `windows_indexed`

**Roles:** `EXTRACT_EXECUTOR`

### run_vshadow_info

List Volume Shadow Copy (VSS) snapshots in a disk image.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| image_path | str | yes | Path to the disk image or raw partition |
| offset | int | no | Volume offset in bytes (default 0) |

**Returns:** `source_name` (vshadow.info), `windows_indexed`

**Roles:** `EXTRACT_EXECUTOR`

### run_dislocker

Inspect or decrypt a BitLocker-encrypted volume.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| image_path | str | yes | Path to the BitLocker-encrypted partition/image |
| recovery_key | str | no | BitLocker 48-digit recovery key |
| password | str | no | BitLocker password |

**Returns:** `source_name` (dislocker.metadata or dislocker.decrypted), `mount_point`

**Roles:** `EXTRACT_EXECUTOR`

### run_bdeinfo

Extract metadata from a BitLocker-encrypted volume using libbde.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| image_path | str | yes | Path to the BitLocker-encrypted partition/image |

**Returns:** `source_name` (bde.info), `windows_indexed`

**Roles:** `EXTRACT_EXECUTOR`

### run_fvdeinfo

Extract metadata from a FileVault-encrypted macOS volume.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| image_path | str | yes | Path to the FileVault-encrypted volume image |

**Returns:** `source_name` (fvde.info), `windows_indexed`

**Roles:** `EXTRACT_EXECUTOR`

---

## 4. Extraction: Windows Artifacts

### run_evtx_parser

Extract .evtx files from a disk image and return a prioritized manifest.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| evtx_path | str | yes | Path to an EVTX file, directory, or disk image |
| force | bool | no | Re-run extraction even if sources already exist |

**Returns:** `extract_dir`, `total_files`, `high_priority_count`, `manifest[]`

**Roles:** `EXTRACT_EXECUTOR`

### index_evtx_file

Parse and index a specific EVTX file from a prior run_evtx_parser extraction.

When indexing a Security log, automatically indexes System.evtx and PowerShell operational logs from the same extraction directory (if present and not already indexed) for persistence and execution coverage.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| filename | str | yes | Name of the .evtx file to parse |
| event_ids | list[int] \| None | no | Event IDs to extract (all if omitted) |
| image_path | str | no | Disk image path for multi-image sessions |

**Returns:** `source_name` (evtx.\<channel\>), `windows_indexed`, `line_count`

**Auto-companion behavior:** Indexing `Security.evtx` triggers automatic indexing of `System.evtx` and `Microsoft-Windows-PowerShell%4Operational.evtx` from the same directory.

**Roles:** `EXTRACT_EXECUTOR`

### run_hayabusa

Detect threats in EVTX files using 3,700+ Sigma rules via Hayabusa.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| evtx_dir | str | no | Directory containing .evtx files |
| min_severity | str | no | Minimum alert severity (default "medium") |
| image_path | str | no | Disk image path for extraction directory lookup |
| force | bool | no | Re-run extraction even if sources already exist |

**Returns:** `total_alerts`, `by_severity{}`, `top_rules[]`, `mitre_techniques[]`

**Roles:** `EXTRACT_EXECUTOR`

### run_chainsaw

Analyze Windows artifacts using Chainsaw with Sigma rules.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| evidence_path | str | yes | Path to EVTX directory or SRUM database |
| mode | Literal['hunt', 'search', 'srum', 'timeline'] | no | Analysis mode (default "hunt") |
| sigma_rules_path | str | no | Path to Sigma rules directory |
| search_term | str \| None | no | Required when mode="search" |
| time_range_start | str \| None | no | ISO 8601 start time filter |
| time_range_end | str \| None | no | ISO 8601 end time filter |
| force | bool | no | Re-run extraction even if sources already exist |

**Returns:** `total_findings`, `severity_counts{}`, `mitre_techniques[]`, `detections[]`

**Roles:** `EXTRACT_EXECUTOR`

### run_registry_parser

Parse Windows registry hives from a disk image using RECmd or RegRipper.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| image_path | str | yes | Path to the disk image |
| hive | str \| None | no | Specific hive to parse (e.g. "SYSTEM") |
| force | bool | no | Re-run extraction even if sources already exist |
| include_user_hives | bool | no | Discover and parse per-user NTUSER.DAT and UsrClass.dat hives (default True) |

**Returns:** `hives_parsed`, `total_windows_indexed`, `per_hive[]`

**Indexing:** System hives as `registry.<hive>` (e.g. `registry.system`). Per-user hives as `registry.ntuser.<username>` and `registry.usrclass.<username>`.

**User hive artifacts:** TypedURLs, RecentDocs, UserAssist execution counts, MRU lists, shell folders, environment variables, per-user Run keys, mapped drives (MountPoints2), WordWheelQuery, Shellbags (UsrClass.dat).

**Roles:** `EXTRACT_EXECUTOR`

### run_regripper

Analyze a Windows registry hive using RegRipper.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| hive_path | str | yes | Path to the registry hive file |
| profile | str \| None | no | RegRipper plugin profile name |

**Returns:** `source_name` (regripper.\<hive\>), `windows_indexed`

**Roles:** `EXTRACT_EXECUTOR`

### query_registry_value

Query a specific registry key or value from a Windows hive file. Extracts the target hive from a disk image using TSK and reads the requested key or value using python-registry. Returns decoded, typed values including automatic conversion of FILETIME timestamps, Unix epochs, REG_BINARY, and REG_MULTI_SZ data.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| case_id | str | yes | Active case identifier |
| image_path | str | yes | Path to the disk image containing the registry hive |
| hive | Literal['system', 'software', 'sam', 'security', 'ntuser', 'usrclass'] | yes | Target hive name |
| key_path | str | yes | Registry key path relative to the hive root |
| value_name | str \| None | no | Specific value to retrieve; returns all values and subkeys if omitted |
| username | str \| None | no | Required when hive is "ntuser" or "usrclass" |

**Returns:** `value`, `value_type`, `key_metadata`, `last_written_timestamp`

**Roles:** `EXTRACT_ANALYST`

### run_prefetch_parser

Parse Windows Prefetch files from a disk image using PECmd (EZ Tools).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| image_path | str | yes | Path to the disk image |
| force | bool | no | Re-run extraction even if sources already exist |

**Returns:** `source_name` (ez.prefetch), `windows_indexed`

**Roles:** `EXTRACT_EXECUTOR`

### run_amcache_parser

Parse Amcache from a disk image using AmcacheParser (EZ Tools).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| image_path | str | yes | Path to the disk image |
| force | bool | no | Re-run extraction even if sources already exist |

**Returns:** `source_name` (ez.amcache), `windows_indexed`

**Roles:** `EXTRACT_EXECUTOR`

### run_shimcache_parser

Parse ShimCache (AppCompatCache) from a disk image using AppCompatCacheParser.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| image_path | str | yes | Path to the disk image |
| force | bool | no | Re-run extraction even if sources already exist |

**Returns:** `source_name` (ez.shimcache), `windows_indexed`

**Roles:** `EXTRACT_EXECUTOR`

### run_mft_parser

Parse the $MFT from a disk image using MFTECmd (EZ Tools).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| image_path | str | yes | Path to the disk image |
| force | bool | no | Re-run extraction even if sources already exist |

**Returns:** `source_name` (ez.mft), `windows_indexed`

**Roles:** `EXTRACT_EXECUTOR`

### run_pasco

Parse an Internet Explorer index.dat file for browser history.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| indexdat_path | str | yes | Path to the index.dat file |

**Returns:** `source_name` (pasco.history), `windows_indexed`

**Roles:** `EXTRACT_EXECUTOR`

### run_zircolite

Apply Sigma detection rules to Linux logs using Zircolite.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| events_path | str | yes | Path to the log file or directory |
| log_format | Literal['auditd', 'sysmon_linux', 'json', 'evtx'] | no | Log format (default "auditd") |
| ruleset_path | str \| None | no | Path to custom ruleset directory |
| sigma_level_filter | Literal['informational', 'low', 'medium', 'high', 'critical'] \| None | no | Minimum Sigma level (default "medium") |
| force | bool | no | Re-run extraction even if sources already exist |

**Returns:** `total_detections`, `level_counts{}`, `mitre_coverage{}`, `timeline[]`

**Roles:** `EXTRACT_EXECUTOR`

---

## 5. Extraction: Network

### run_pcap_analysis

Analyze a PCAP or PCAPng network capture file using tshark.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| pcap_path | str | yes | Path to the .pcap or .pcapng file |
| mode | str | no | "summary", "conversations", "dns", "http", "smtp", "tls", "beaconing", "tunneling", "custom", or "all" (default "summary") |
| display_filter | str \| None | no | Wireshark display filter (required for mode="custom") |
| max_packets | int | no | Maximum packets to process (default 10000) |
| ssl_keylog_path | str \| None | no | Path to NSS key log file for TLS decryption |

**Returns:** per-mode results with `source_name`, `windows_indexed`

**Roles:** `EXTRACT_EXECUTOR`

### run_zeek_analysis

Analyze a PCAP using Zeek for protocol-aware log generation.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| pcap_path | str | yes | Absolute path to the PCAP file |
| protocols | list[str] \| None | no | Protocol filter list (default all) |
| generate_files | bool | no | Extract transferred files (default True) |

**Returns:** `log_summaries[]`, `total_connections`, `protocols_detected[]`, `dns_queries[]`, `http_requests[]`

**Roles:** `EXTRACT_EXECUTOR`

### run_suricata

Replay PCAP against Suricata IDS rules to detect known threats.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| pcap_path | str | yes | Absolute path to the PCAP file |
| alert_severity_threshold | int | no | Max severity level to include (default 3) |

**Returns:** `alerts[]`, `statistics{}`, `mitre_techniques{}`, `timeline[]`

**Roles:** `EXTRACT_EXECUTOR`

### analyze_disk_pcaps

Discover and analyze packet captures stored on a disk image.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| case_id | str | yes | Active case identifier |
| image_path | str | yes | Path to the disk image containing PCAP files |
| max_pcap_size_mb | int | no | Skip PCAPs larger than this (default 100 MB) |
| run_ids | bool | no | Run Suricata IDS analysis (default True) |
| extract_credentials | bool | no | Extract cleartext credentials (default True) |

**Returns:** `pcaps_discovered`, `pcaps_analyzed`, `analyses[]`, `credentials[]`, `pcaps_skipped_oversize[]`

**Roles:** `EXTRACT_EXECUTOR`

### run_tcpflow

Reconstruct TCP streams from a PCAP file using tcpflow.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| pcap_path | str | yes | Path to the PCAP/PCAPNG file |

**Returns:** `source_name` (tcpflow.streams), `stream_count`, `windows_indexed`

**Roles:** `EXTRACT_EXECUTOR`

### run_tcpxtract

Extract files from TCP streams in a PCAP using tcpxtract.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| pcap_path | str | yes | Path to the PCAP file |

**Returns:** `source_name` (tcpxtract.carved), `files_carved`, `windows_indexed`

**Roles:** `EXTRACT_EXECUTOR`

---

## 6. Extraction: Mobile

### run_mvt_android

Scan Android device backup for spyware indicators using MVT.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| evidence_path | str | yes | Path to Android backup directory or bugreport |
| iocs | str | no | Path to STIX2 IOC file |

**Returns:** `modules_run[]`, `module_counts{}`, `total_indicators`, `detections`

**Roles:** `EXTRACT_EXECUTOR`

### run_mvt_ios

Scan iOS backup or filesystem dump for spyware indicators using MVT.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| evidence_path | str | yes | Path to iOS backup directory or filesystem dump |
| iocs | str | no | Path to STIX2 IOC file |
| mode | str | no | "backup" (default) or "fs" |

**Returns:** `modules_run[]`, `module_counts{}`, `total_indicators`, `detections`

**Roles:** `EXTRACT_EXECUTOR`

### parse_android_artifacts

Parse Android artifacts from a logical extraction or carved databases.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| evidence_path | str | yes | Directory with extracted Android data, or raw .bin dump |
| artifact_types | list[str] \| None | no | Types to parse (e.g. ["sms", "contacts", "whatsapp"]) |

**Returns:** `source_name` (phone.android), `parsed_types[]`, `windows_indexed`

**Roles:** `EXTRACT_EXECUTOR`

### parse_ios_artifacts

Parse iOS artifacts from an iTunes/Finder backup or extracted files.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| evidence_path | str | yes | Path to the iOS backup directory |
| artifact_types | list[str] \| None | no | Types to parse (e.g. ["sms", "calls", "safari"]) |

**Returns:** `source_name` (phone.ios), `parsed_types[]`, `manifest_found`

**Roles:** `EXTRACT_EXECUTOR`

### carve_sqlite_from_raw

Carve SQLite databases from a raw binary image (phone dump).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| image_path | str | yes | Path to the raw binary image |
| max_databases | int | no | Maximum databases to carve (default 50) |

**Returns:** `source_name` (phone.carved_sqlite), `databases[]`

**Roles:** `EXTRACT_EXECUTOR`

### decrypt_app_data

Attempt to decrypt and parse application data from a mobile device.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| app_data_path | str | yes | Path to the app's data directory |
| known_passwords | list[str] \| None | no | Passwords to try for SQLCipher decryption |

**Returns:** `source_name` (phone.app_data), `plaintext_dbs_found`, `encrypted_dbs_decrypted`

**Roles:** `EXTRACT_EXECUTOR`

### run_aleapp

Parse Android forensic artifacts using ALEAPP (300+ artifact types).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| extraction_path | str | yes | Path to the Android extraction |
| input_type | str | no | "fs", "tar", "zip", or "gz" (default "fs") |
| artifact_filter | list[str] \| None | no | Artifact module names to process |

**Returns:** `source_name` (phone.aleapp), `total_artifacts_parsed`, `total_records`, `categories{}`

**Roles:** `EXTRACT_EXECUTOR`

### run_ileapp

Parse iOS forensic artifacts using iLEAPP (200+ artifact types).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| extraction_path | str | yes | Path to the iOS extraction |
| input_type | str | no | "fs", "tar", "zip", "gz", or "itunes" (default "fs") |
| artifact_filter | list[str] \| None | no | Artifact module names to process |

**Returns:** `source_name` (phone.ileapp), `total_artifacts_parsed`, `total_records`, `categories{}`

**Roles:** `EXTRACT_EXECUTOR`

---

## 7. Extraction: Binary

### triage_binary

Triage a binary using rabin2 for forensic analysis.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| case_id | str | yes | Active case identifier |
| file_path | str | yes | Absolute path to the binary |
| depth | str | no | "quick", "standard" (default), or "deep" |

**Returns:** `file_info{}`, `timestamps{}`, `packing_indicators[]`, `suspicious_imports{}`, `triage_verdict{}`

**Roles:** `EXTRACT_EXECUTOR` `EXTRACT_ANALYST`

### run_capa

Identify capabilities in a binary using Mandiant CAPA.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| case_id | str | yes | Active case identifier |
| file_path | str | yes | Absolute path to the binary |
| output_format | str | no | "default" or "mitre" (default "default") |
| rules_path | str \| None | no | Custom rules directory |

**Returns:** `capabilities[]`, `mitre_summary{}`, `total_rules_matched`

**Roles:** `EXTRACT_EXECUTOR` `EXTRACT_ANALYST`

### run_floss

Extract obfuscated strings from a binary using FLOSS.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| case_id | str | yes | Active case identifier |
| file_path | str | yes | Absolute path to the binary |
| minimum_length | int | no | Minimum string length (default 6) |
| include_static | bool | no | Include standard static strings (default True) |

**Returns:** `decoded_strings[]`, `stack_strings[]`, `tight_strings[]`, `total_decoded`

**Roles:** `EXTRACT_EXECUTOR`

### run_detect_it_easy

Identify packers, compilers, and protectors using Detect-It-Easy.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| case_id | str | yes | Active case identifier |
| file_path | str | yes | Absolute path to the binary |
| deep_scan | bool | no | Enable deep scan mode (default True) |

**Returns:** `detections[]`, `compilers[]`, `packers[]`, `protectors[]`, `is_packed`

**Roles:** `EXTRACT_EXECUTOR`

### run_radare2

Analyze a binary executable using radare2 for malware triage.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| target_path | str | yes | Path to the binary |
| commands | str | no | Semicolon-separated r2 commands (default "iI;iS;iz;afl") |

**Returns:** `source_name` (radare2.analysis), `windows_indexed`

**Roles:** `EXTRACT_EXECUTOR`

---

## 8. Extraction: Documents

### analyze_office_document

Analyze a Microsoft Office document for malicious content.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| case_id | str | yes | Active case identifier |
| file_path | str | yes | Absolute path to the Office document |
| extract_macros | bool | no | Extract full VBA source (default True) |
| analyze_dde | bool | no | Check for DDE/DDEAUTO fields (default True) |

**Returns:** `macros[]`, `indicators[]`, `dde_links[]`, `risk_assessment{}`, `has_vba`

**Roles:** `EXTRACT_EXECUTOR`

### analyze_pdf

Analyze a PDF file for malicious indicators.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| case_id | str | yes | Active case identifier |
| file_path | str | yes | Absolute path to the PDF |
| extract_javascript | bool | no | Extract embedded JavaScript (default True) |
| extract_urls | bool | no | Extract URLs (default True) |
| extract_embedded | bool | no | List embedded files (default True) |

**Returns:** `indicators[]`, `risk_assessment{}`, `javascript[]`

**Roles:** `EXTRACT_EXECUTOR`

### parse_pst

Parse Outlook PST/OST files for forensic email analysis.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| case_id | str | yes | Active case identifier |
| file_path | str | yes | Absolute path to the PST/OST file |
| extract_attachments | bool | no | Extract file attachments (default True) |
| date_range_start | str \| None | no | Start date filter (YYYY-MM-DD) |
| date_range_end | str \| None | no | End date filter (YYYY-MM-DD) |
| search_term | str \| None | no | Keyword filter across all fields |

**Returns:** `total_emails`, `total_attachments`, `folder_structure{}`, `emails[]`, `suspicious_findings[]`

**Roles:** `EXTRACT_EXECUTOR`

---

## 9. Extraction: Malware / YARA

### yara_scan_files

Scan a mounted filesystem or extracted directory for malware using YARA rules.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| target_path | str | yes | Path to scan (file or directory) |
| rules | str \| None | no | Custom YARA rule source (file, directory, or inline) |
| ruleset | str | no | "builtin" (default), "standard", or "full" |

**Returns:** `source` (yara.files), `result_count`, `hit_metadata{}`

**Roles:** `EXTRACT_EXECUTOR`

### yara_scan_memory

Scan the memory dump with YARA rules for malware signatures.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| rules | str \| None | no | Custom YARA rule source |
| ruleset | str | no | "builtin" (default), "standard", or "full" |

**Returns:** `source` (yara.memory), `result_count`, `hit_metadata{}`

**Roles:** `EXTRACT_EXECUTOR`

### yara_scan_with_volatility

Scan process virtual address descriptors with YARA via Volatility 3 vadyarascan.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| pid | int \| None | no | Target a single PID |
| rules | str \| None | no | Custom YARA rule source |

**Returns:** `source` (yara.volatility), `result_count`, `hit_metadata{}`

**Roles:** `EXTRACT_EXECUTOR`

### run_clamav

Scan files for malware signatures using ClamAV.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| target_path | str | yes | Path to the file or directory to scan |

**Returns:** `source_name` (clamav.scan), `detections`, `windows_indexed`

**Roles:** `EXTRACT_EXECUTOR`

---

## 10. Query Tools

### search

Search all ingested evidence for keywords or regex patterns.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| query | str | no | Search term or regex pattern |
| source | str \| None | no | Source name or prefix to scope the search |
| max_results | int | no | Maximum matching windows (default 50) |
| regex | bool | no | Treat query as regex (default False) |
| t_start | str \| None | no | ISO 8601 start time filter |
| t_end | str \| None | no | ISO 8601 end time filter |
| queries | list[str] \| None | no | Multiple search terms (OR logic) |
| exclude_sources | list[str] \| None | no | Source prefixes to exclude |

**Returns:** `results[]`, `total_matches`, `has_more`, `sources_matched[]`

**Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR` `CROSS_ANALYST` `NARRATIVE_EXECUTOR` `NARRATIVE_ANALYST` `REPORT`

### get_raw_output

Retrieve full raw text from a specific evidence source with cursor pagination.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| source_name | str | yes | Exact source name or prefix |
| after_id | int | no | Cursor for keyset pagination (default 0) |
| limit | int | no | Maximum windows to return (default 50) |

**Returns:** `raw_text`, `total_windows`, `next_after_id`, `has_more`

**Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR` `CROSS_ANALYST` `NARRATIVE_EXECUTOR` `NARRATIVE_ANALYST` `REPORT`

### get_timeline

Merge events from all indexed sources into a single chronological view.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| t_start | str | yes | ISO 8601 start time |
| t_end | str | yes | ISO 8601 end time |
| limit | int | no | Maximum events to return (default 50) |

**Returns:** `results[]` (event_time, source_name, raw_text), `total_events`, `sources_represented[]`

**Roles:** `EXTRACT_ANALYST` `CROSS_PLANNER` `CROSS_EXECUTOR` `CROSS_ANALYST` `NARRATIVE_PLANNER` `NARRATIVE_EXECUTOR` `NARRATIVE_ANALYST` `REPORT`

### list_sources

List all evidence sources currently indexed in the active case.

*No parameters.*

**Returns:** `results[]` (source_name, source_path, extractor, line_count, hash)

**Roles:** `CATALOG` `EXTRACT_PLANNER` `CROSS_PLANNER` `NARRATIVE_PLANNER` `EXTRACT_ANALYST` `CROSS_ANALYST` `NARRATIVE_EXECUTOR` `REPORT`

### get_source_stats

Return per-source statistics including citation coverage.

*No parameters.*

**Returns:** `total_sources`, `cited_sources`, `uncited_sources`, `sources[]`

**Roles:** `CATALOG` `EXTRACT_ANALYST` `CROSS_PLANNER` `CROSS_ANALYST` `NARRATIVE_EXECUTOR` `REPORT`

### bookmark_window

Bookmark a specific window for later review.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| window_id | int | yes | The window_id to bookmark |
| note | str | yes | Why this window is interesting |
| source_name | str | no | Source name for context |

**Returns:** `bookmark_id`, `window_id`, `note`

**Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR` `CROSS_ANALYST` `NARRATIVE_ANALYST`

### get_bookmarks

Retrieve all bookmarked windows with their notes.

*No parameters.*

**Returns:** `results[]` (bookmark_id, window_id, note, raw_text, event_time)

**Roles:** `CROSS_PLANNER` `CROSS_ANALYST` `REPORT`

### remove_bookmark

Remove a bookmark by ID.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| bookmark_id | int | yes | The bookmark ID to remove |

**Returns:** `bookmark_id`, `removed`

**Roles:** `EXTRACT_ANALYST` `CROSS_ANALYST` `NARRATIVE_ANALYST`

### decode_payload

Safely decode an encoded payload found in evidence.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| data | str | no | The encoded string to decode |
| encoding | str | no | "auto", "base64", "hex", "utf16le", or "pickle" (default "auto") |
| source | str \| None | no | Indexed source to extract encoded strings from |
| pattern | str \| None | no | Search pattern within the source |

**Returns:** `results{}` (detected_encoding, layers[], decoded, decoded_length)

**Roles:** `CROSS_EXECUTOR`

### get_carved_iocs

Retrieve IOC data carved by bulk_extractor from the case database.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| feature | str \| None | no | Feature type (e.g. "email", "url"); omit for summary |

**Returns:** summary mode: `results[]` (source_name, feature, window_count); detail mode: windowed response

**Roles:** `CROSS_EXECUTOR`

---

## 11. Filesystem Tools

### list_directory

List files and directories at a given path.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| path | str | yes | Directory path to list |
| recursive | bool | no | List all files recursively (default False) |

**Returns:** `results[]` (name, type, size_bytes, size_human)

**Roles:** `CATALOG` `EXTRACT_PLANNER` `EXTRACT_EXECUTOR`

### read_evidence_file

Read a text file from the evidence directory.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| file_path | str | no | Absolute path to the file |
| max_bytes | int | no | Maximum bytes to read (default 1 MB) |
| path | str | no | Alias for file_path |

**Returns:** `content`, `file_size`, `truncated`, `is_binary`

**Roles:** `EXTRACT_EXECUTOR` `EXTRACT_ANALYST` `CROSS_EXECUTOR`

### extract_file_by_inode

Extract a file from the disk image by inode number using TSK icat.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| inode | int | yes | Inode number of the file to extract |
| filesystem_type | str \| None | no | TSK filesystem type (auto-detected if omitted) |
| image_path | str \| None | no | Path to the specific disk image (required for multi-image cases) |

**Returns:** text files: `source_name`, `windows_indexed`; binary files: `sha256`, `size_bytes`

**Roles:** `EXTRACT_EXECUTOR`

### get_file_metadata

Return file metadata (MAC times, size, blocks) for an inode using TSK istat.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| inode | int | yes | Inode number of the file |
| filesystem_type | str \| None | no | TSK filesystem type (auto-detected if omitted) |
| image_path | str \| None | no | Path to the specific disk image (required for multi-image cases) |

**Returns:** `source_name`, `windows_indexed`

**Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR`

### list_partitions

Return the partition table extracted from the disk image (TSK mmls).

*No parameters.*

**Returns:** windowed response with partition layout

**Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR`

### list_files

List files from the disk image filesystem (TSK fls).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| path_filter | str \| None | no | Substring filter on file paths |
| include_deleted | bool | no | Only show deleted files (default False) |

**Returns:** `total_windows`, `approx_file_count`, `top_directories[]`

**Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR`

### get_deleted_files

Return a summary of deleted files detected in the disk image.

*No parameters.*

**Returns:** `approx_deleted_count`, `top_directories[]`

**Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR` `CROSS_ANALYST`

### get_fs_timeline

Return the filesystem timeline (mactime) within a time range.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| t_start | str | yes | ISO 8601 start time |
| t_end | str | yes | ISO 8601 end time |

**Returns:** windowed response with timeline events

**Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR` `CROSS_ANALYST`

### index_app_files

Index text and config files from application directories on a disk image.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| case_id | str | yes | Active case identifier |
| image_path | str | yes | Path to the disk image |
| directory_pattern | str | yes | Path pattern to match directories (supports wildcards) |
| extensions | list[str] \| None | no | File extensions to include (defaults to .ini, .cfg, .conf, .txt, .log, .xml, .json, .yaml, .yml, .properties, .csv, .bat, .cmd, .ps1, .reg, .inf, .manifest) |
| max_file_size_kb | int | no | Skip files larger than this (default 512 KB) |
| max_files | int | no | Maximum files to extract per call (default 200) |

**Returns:** `files_discovered`, `files_extracted`, `files_indexed`, `source_prefix`, `sample_files[]`

**Roles:** `EXTRACT_EXECUTOR`

**Example patterns:**
- `Program Files/mIRC` - index all text/config files in a specific app directory
- `Documents and Settings/*/Application Data/Thunderbird` - index across all user profiles
- `Program Files/*` - broad sweep of all program directories

---

## 12. Composite Analysis

### find_persistence_mechanisms

Detect persistence mechanisms across registry, services, event logs, and timeline.

*No parameters.*

**Returns:** `results[]` (type, key_pattern/executable, source, evidence_text), `missing_sources[]`

**Roles:** `CROSS_EXECUTOR`

### find_lateral_movement_indicators

Detect lateral movement by correlating logon events, network connections, and RDP artifacts.

*No parameters.*

**Returns:** `results[]` (type, source, event_time, evidence_text), `missing_sources[]`

**Roles:** `CROSS_EXECUTOR`

### find_data_exfiltration_indicators

Detect potential data exfiltration by correlating network, URL, and file access artifacts.

*No parameters.*

**Returns:** `results[]` (type, service/domain, source, evidence_text), `missing_sources[]`

**Roles:** `CROSS_EXECUTOR`

### find_file_staging

Detect signs of data staging and exfiltration preparation in filesystem data.

Searches indexed filesystem sources (tsk.filelist, ez.mft) for recently created archive files, archives in suspicious locations (temp dirs, Downloads, Recycle Bin), large files indicating bulk data collection, and archives that were created then deleted (exfiltrated then cleaned up). Complements `find_data_exfiltration_indicators` by focusing on host filesystem artifacts rather than network traffic.

*No parameters.*

**Returns:** `results[]` (type, source, event_time, evidence_text), `missing_sources[]`

**Roles:** `CROSS_EXECUTOR` `EXTRACT_ANALYST` `NARRATIVE_EXECUTOR`

### find_defense_evasion

Detect defense evasion techniques across memory, filesystem, and event logs.

*No parameters.*

**Returns:** `results[]` (type, source, event_time, evidence_text), `missing_sources[]`

**Roles:** `CROSS_EXECUTOR`

### find_suspicious_processes

Identify suspicious processes by cross-referencing memory forensics artifacts.

*No parameters.*

**Returns:** `results[]` (pid, name, cmdline, suspicion_reasons[], anomaly_score), `missing_sources[]`

**Roles:** `CROSS_EXECUTOR`

### correlate_across_sources

Cross-reference all evidence sources within a time window.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| t_start | str | yes | ISO 8601 start time |
| t_end | str | yes | ISO 8601 end time |
| sources | list[str] \| None | no | Source names to include (default all) |

**Returns:** `results{}` (windows_by_source), `sources_with_data[]`, `sources_without_data[]`

**Roles:** `CROSS_EXECUTOR` `NARRATIVE_EXECUTOR`

### reconstruct_execution_chains

Reconstruct parent-child process execution chains from memory forensics.

*No parameters.*

**Returns:** `results[][]` (chains of process nodes with pid, name, cmdline, connections, malfind_hit)

**Roles:** `CROSS_EXECUTOR`

### find_execution_evidence

Build a unified execution evidence view from multiple artifact sources.

*No parameters.*

**Returns:** `results[]` (executable, sources[], event_times[], window_count)

**Roles:** `CROSS_EXECUTOR`

### analyze_execution_timeline

Build a unified execution timeline from prefetch, amcache, and shimcache.

*No parameters.*

**Returns:** `results[]` (executable, first_seen, last_seen, run_count, sha1, anomaly_flags[])

**Roles:** `CROSS_EXECUTOR`

### assess_recovery

Assess evidence recoverability by cross-referencing deleted files, carving results, and anti-forensics indicators.

*No parameters.*

**Returns:** `results{}` (total_deleted_files, anti_forensics_detected[], evidence_gaps[])

**Roles:** `CROSS_EXECUTOR`

### correlate_pcap_with_host

Cross-reference PCAP network events with host artifacts.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| t_start | str \| None | no | ISO 8601 start time for correlation window |
| t_end | str \| None | no | ISO 8601 end time for correlation window |

**Returns:** `results[]` (type, matched_ips[], pid, process)

**Roles:** `CROSS_EXECUTOR`

---

## 13. Memory Query Tools

### list_processes_from_memory

List all processes captured in the memory dump (Volatility pslist).

*No parameters.*

**Returns:** windowed response from `volatility.pslist`

**Roles:** `CROSS_EXECUTOR`

### get_process_tree

Return the process parent-child tree from memory (Volatility pstree).

*No parameters.*

**Returns:** windowed response from `volatility.pstree`

**Roles:** `CROSS_EXECUTOR`

### scan_hidden_processes

Detect processes hidden from the linked list by comparing psscan against pslist.

*No parameters.*

**Returns:** `results[]` (pid, evidence_windows[])

**Roles:** `CROSS_EXECUTOR`

### get_process_environment

Return environment variables for a specific process from memory.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| pid | int | yes | Process ID to query |

**Returns:** windowed response filtered to the given PID

**Roles:** `CROSS_EXECUTOR` `CROSS_ANALYST`

### get_process_privileges

Return token privileges for a specific process from memory.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| pid | int | yes | Process ID to query |

**Returns:** windowed response filtered to the given PID

**Roles:** `CROSS_EXECUTOR` `CROSS_ANALYST`

### scan_kernel_modules

Detect hidden kernel modules by comparing modscan against modules.

*No parameters.*

**Returns:** `results[]` (module_name, evidence_windows[])

**Roles:** `CROSS_EXECUTOR`

### get_userassist

Return UserAssist registry entries extracted from memory.

*No parameters.*

**Returns:** windowed response from `volatility.userassist`

**Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR` `CROSS_ANALYST`

### scan_files_in_memory

Return a summary of file objects cached in the memory dump (Volatility filescan).

*No parameters.*

**Returns:** `approx_file_count`, `sample_paths[]`

**Roles:** `CROSS_EXECUTOR` `CROSS_ANALYST`

### get_eventlog_anomalies

Find anomalous entries in a Windows Event Log channel.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| channel | str | yes | Event log channel (e.g. "security", "system") |
| t_start | str | yes | ISO 8601 start time |
| t_end | str | yes | ISO 8601 end time |
| top_percent | float | no | Top outlier percentage (default 0.1) |

**Returns:** windowed response with anomalous events

**Roles:** `CROSS_EXECUTOR`

### extract_mft_timeline

Extract the Plaso super-timeline for a time range.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| t_start | str | yes | ISO 8601 start time |
| t_end | str | yes | ISO 8601 end time |

**Returns:** windowed response from `plaso.timeline`

**Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR` `CROSS_ANALYST`

### parse_prefetch

Return all parsed Windows Prefetch data.

*No parameters.*

**Returns:** windowed response from `prefetch.all`

**Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR` `CROSS_ANALYST`

### get_amcache

Return parsed AmCache / registry system hive data.

*No parameters.*

**Returns:** windowed response from `registry.system`

**Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR` `CROSS_ANALYST`

---

## 14. EZ Tools Query Tools

### parse_prefetch_detailed

Return detailed Prefetch data parsed by PECmd (EZ Tools).

*No parameters.* **Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR`

### parse_amcache

Return Amcache data parsed by AmcacheParser (EZ Tools).

*No parameters.* **Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR`

### parse_shimcache

Return ShimCache data parsed by AppCompatCacheParser (EZ Tools).

*No parameters.* **Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR`

### parse_jump_lists

Return Jump List data parsed by JLECmd (EZ Tools).

*No parameters.* **Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR`

### parse_lnk_files

Return LNK file data parsed by LECmd (EZ Tools).

*No parameters.* **Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR`

### parse_shellbags

Return Shellbags data parsed by SBECmd (EZ Tools).

*No parameters.* **Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR`

### parse_srum

Return SRUM data parsed by SrumECmd (EZ Tools).

*No parameters.* **Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR`

### parse_mft

Return MFT entries within a time range, parsed by MFTECmd (EZ Tools).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| t_start | str | yes | ISO 8601 start time |
| t_end | str | yes | ISO 8601 end time |

**Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR`

### parse_usn_journal

Return USN Journal entries within a time range, parsed by MFTECmd (EZ Tools).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| t_start | str | yes | ISO 8601 start time |
| t_end | str | yes | ISO 8601 end time |

**Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR`

### detect_timestomping

Analyze MFT data for files with manipulated timestamps (timestomping).

Reads the indexed `ez.mft` source (MFTECmd output) and compares $STANDARD_INFORMATION timestamps against $FILE_NAME timestamps for each file entry. Flags files where $SI Created is significantly earlier than $FN Created (SI was backdated), or $SI Created is later than $SI Modified (impossible without manipulation). Filters out known false positives from Windows Update, servicing, and installer paths.

*No parameters.*

**Returns:** `results[]` (file_path, si_created, fn_created, delta_hours, reason), `total_suspicious`, `false_positive_filtered`

**Roles:** `EXTRACT_EXECUTOR` `EXTRACT_ANALYST` `CROSS_EXECUTOR` `NARRATIVE_EXECUTOR`

### analyze_anti_forensics_clock

Normalize indexed timestamp evidence and apply the built-in, versioned
anti-forensics clock rules. Reads supported `ez.mft*`, `ez.usnjrnl*`,
`evtx.*`, and `vshadow.info*` sources locally. Missing and unsupported evidence
families remain explicit coverage outcomes; instruction-shaped evidence text
is retained as inert provenance metadata.

*No parameters.*

**Returns:** `outcome`, `coverage[]`, `clock_models[]`, `observations[]`,
`findings[]`

**Roles:** `EXTRACT_EXECUTOR` `CROSS_EXECUTOR` `NARRATIVE_EXECUTOR`

### analyze_evtx_pack

Apply fixed, versioned local rules to supported indexed EVTX line/CSV sources.
Returns channel coverage, normalized events, exact record/field proof
selectors, rule hashes, and structural findings.

*No parameters.*

**Returns:** `outcome`, `coverage[]`, `ruleset_hash`, `rule_hashes`,
`observations[]`, `relationships[]`, `findings[]`

**Roles:** `EXTRACT_EXECUTOR` `CROSS_EXECUTOR` `NARRATIVE_EXECUTOR`

### analyze_kubernetes_pack

Analyze local Kubernetes audit/events/manifests/RBAC/images/NetworkPolicy
egress under the active evidence root. Does not contact a Kubernetes cluster.

*No parameters.*

**Returns:** `outcome`, `coverage[]`, `ruleset_hash`, `rule_hashes`,
`observations[]`, `relationships[]`, `findings[]`

**Roles:** `EXTRACT_EXECUTOR` `CROSS_EXECUTOR` `NARRATIVE_EXECUTOR`

### analyze_cloudtrail_pack

Analyze documented CloudTrail `Records` JSON or JSON-gzip exports under the
active evidence root. Performs no AWS API, credential, or network operation.

*No parameters.*

**Returns:** `outcome`, `coverage[]`, `ruleset_hash`, `rule_hashes`,
`observations[]`, `relationships[]`, `findings[]`

**Roles:** `EXTRACT_EXECUTOR` `CROSS_EXECUTOR` `NARRATIVE_EXECUTOR`

---

## 15. Plaso Query Tools

### get_plaso_stats

Return Plaso parser hit statistics collected during ingest.

*No parameters.*

**Returns:** windowed response from `plaso.stats`

**Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR`

### filter_timeline

Query the Plaso timeline with time range and optional filters.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| t_start | str | yes | ISO 8601 start time |
| t_end | str | yes | ISO 8601 end time |
| keyword | str \| None | no | Keyword filter on output |
| parser | str \| None | no | Plaso parser name filter |

**Returns:** `source_name` (plaso.filtered), `result_count`, `windows_indexed`

**Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR` `CROSS_ANALYST`

### export_timeline_slice

Export a 5-minute timeline slice centred on a timestamp.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| timestamp | str | yes | ISO 8601 centre timestamp |

**Returns:** `source_name` (plaso.slice), `result_count`, `windows_indexed`

**Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR`

---

## 16. Browser & Artifact Tools

### parse_browser_history

Extract browser history from Chrome, Firefox, and Safari databases in a disk image.

*No parameters.*

**Returns:** `source` (browser.history), `result_count`

**Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR` `CROSS_ANALYST`

### parse_plist

Extract and parse macOS plist files from a disk image.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| plist_filter | str \| None | no | Filename filter (e.g. "loginitems", "wifi") |

**Returns:** `source` (plist.parsed), `result_count`

**Roles:** `EXTRACT_EXECUTOR` `EXTRACT_ANALYST` `CROSS_EXECUTOR`

### query_sqlite_from_image

Extract a SQLite database from a disk image and run a SQL query.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| inode | int | yes | Inode number of the SQLite database |
| query | str | yes | SQL SELECT query to execute |
| description | str | no | Label for the indexed source name |

**Returns:** `source` (sqlite.\<description\>), `result_count`

**Roles:** `EXTRACT_EXECUTOR` `EXTRACT_ANALYST`

### run_hindsight

Analyze Chrome/Chromium browser artifacts using Hindsight.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| profile_path | str | yes | Path to the browser profile directory |
| browser | str | no | "chrome" (default), "brave", "edge", or "opera" |

**Returns:** `artifact_counts{}`, `total_artifacts`, `source_name` (hindsight.browser)

**Roles:** `EXTRACT_EXECUTOR` `EXTRACT_ANALYST`

### detect_steganography

Scan image files for hidden steganographic content.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| target_path | str | yes | Path to a file or directory of image files |

**Returns:** `source` (steg.detection), `result_count`, `files_scanned`

**Roles:** `EXTRACT_EXECUTOR` `EXTRACT_ANALYST`

### extract_steganography

Extract hidden data from a steganographic JPEG image.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| image_path | str | yes | Path to a JPEG file |
| passwords | list[str] \| None | no | Passwords to try |

**Returns:** `source` (steg.extracted), `password_used`, `extracted_size`

**Roles:** `EXTRACT_EXECUTOR`

### parse_autoruns

Parse Sysinternals Autoruns CSV output to identify persistence mechanisms. Indexes all autostart entries (services, registry, scheduled tasks, drivers) for searching.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| csv_path | str | no | Path to the Autoruns CSV file (auto-discovers from evidence if empty) |
| force | bool | no | Re-run even if already indexed (default False) |

**Returns:** `sources` (autoruns.\*), `result_count`, `files_parsed`

**Roles:** `EXTRACT_EXECUTOR` `EXTRACT_ANALYST` `CROSS_EXECUTOR`

---

## 17. Findings Management

### submit_finding

Record a forensic finding with validated evidence references.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| title | str | yes | Finding title |
| description | str | yes | Full finding description |
| severity | str | yes | critical, high, medium, low, or info |
| confidence | str | yes | "confirmed" or "inference" |
| evidence_refs | list[str] | yes | tool_call_ids from prior tool invocations |
| sources | list[str] | yes | Source names cited by this finding |
| mitre_attack_ids | list[str] \| None | no | MITRE ATT&CK technique IDs |
| event_time_start | str \| None | no | ISO 8601 start time (must be precise) |
| event_time_end | str \| None | no | ISO 8601 end time |

**Returns:** `finding_id`, `status`, `confidence`

**Roles:** `EXTRACT_ANALYST` `CROSS_ANALYST` `NARRATIVE_ANALYST`

### update_finding

Update or correct an existing finding.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| finding_id | str | yes | The finding ID to update |
| title | str \| None | no | New title |
| description | str \| None | no | New description |
| severity | str \| None | no | New severity |
| confidence | str \| None | no | New confidence |
| evidence_refs | list[str] \| None | no | New evidence refs |
| sources | list[str] \| None | no | New sources |
| mitre_attack_ids | list[str] \| None | no | New ATT&CK IDs |
| event_time_start | str \| None | no | New start time |
| event_time_end | str \| None | no | New end time |

**Returns:** `finding_id`, `updated_fields[]`

**Roles:** `EXTRACT_ANALYST` `CROSS_ANALYST` `NARRATIVE_ANALYST` `NARRATIVE_EXECUTOR` `REPORT`

### delete_finding

Delete a finding that was submitted in error.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| finding_id | str | yes | The finding ID to delete |

**Returns:** `finding_id`, `status`

**Roles:** `CROSS_ANALYST` `NARRATIVE_ANALYST`

### get_findings

Retrieve paginated findings submitted in this case.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| limit | int | no | Maximum findings to return (default 20) |
| offset | int | no | Number of findings to skip (default 0) |

**Returns:** `results[]` (finding objects), `total_findings`

**Roles:** `EXTRACT_ANALYST` `CROSS_ANALYST` `NARRATIVE_ANALYST` `CROSS_PLANNER` `NARRATIVE_PLANNER` `NARRATIVE_EXECUTOR` `REPORT`

### deduplicate_findings

Identify and consolidate duplicate findings across systems.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| case_id | str | yes | Active case identifier |
| similarity_threshold | float | no | Minimum similarity score (default 0.4) |
| dry_run | bool | no | Preview without modifying (default False) |

**Returns:** `groups[]`, `merged_count`, `kept_count`

**Roles:** `NARRATIVE_EXECUTOR` `NARRATIVE_ANALYST` `REPORT`

### submit_narrative

Submit the long-form investigation narrative report.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| narrative | str | yes | Markdown narrative text |

**Returns:** `status`, `length`

**Roles:** `REPORT`

### finalize_report

Generate the final investigation report from all submitted findings.

*No parameters.*

**Returns:** `report_path`, `html_report_path`, `finding_count`, `confirmed_count`, `inference_count`

**Roles:** `REPORT`

---

## 18. Review & Audit

### get_investigation_summary

Return a compact progress dashboard for the current investigation.

*No parameters.*

**Returns:** `sources_indexed`, `findings_submitted`, `findings_by_severity{}`, `remaining_work[]`, `ready_to_finalize`

**Roles:** `EXTRACT_ANALYST` `CROSS_PLANNER` `CROSS_ANALYST` `NARRATIVE_PLANNER` `NARRATIVE_ANALYST` `REPORT`

### check_finalize_readiness

Check whether the investigation meets all finalize_report requirements.

*No parameters.*

**Returns:** `ready_to_finalize`, `gates[]` (name, passed, detail)

**Roles:** `NARRATIVE_PLANNER` `NARRATIVE_ANALYST` `REPORT`

### audit_evidence_coverage

Identify indexed evidence sources not cited by any submitted finding.

*No parameters.*

**Returns:** `total_sources`, `cited_count`, `uncited_count`, `coverage_pct`, `uncited_sources{}`

**Roles:** `NARRATIVE_PLANNER` `NARRATIVE_ANALYST`

### audit_tool_coverage

Report applicable forensic tools that were never invoked during the investigation.

*No parameters.*

**Returns:** `evidence_items`, `total_gaps`, `coverage[]` (path, artifact_type, tools_run[], tools_not_run[])

**Roles:** `NARRATIVE_PLANNER` `NARRATIVE_ANALYST`

### track_progress

Record investigation progress for a specific system.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| system_name | str | yes | Name of the system or evidence source analyzed |
| tools_completed | list[str] | yes | List of tool names that were run |
| questions_addressed | list[str] | yes | Investigation questions covered |
| notes | str | no | Free-text notes |

**Returns:** `system_name`, `progress_summary{}`

**Roles:** `EXTRACT_ANALYST` `CROSS_ANALYST` `NARRATIVE_ANALYST`

### get_ioc_summary

Extract and deduplicate IOCs from findings and bulk_extractor data.

*No parameters.*

**Returns:** `ip_addresses{}`, `domains[]`, `email_addresses[]`, `file_paths[]`, `user_accounts[]`, `total_unique_iocs`

**Roles:** `CROSS_ANALYST` `NARRATIVE_ANALYST` `REPORT`

---

## 19. Job Control

### start_extraction_batch

Submit long-running extraction tools for background execution.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| tasks | list[dict[str, Any]] | yes | List of {tool, args} dicts |

**Returns:** `batch_id`, `tasks_submitted[]`, `tasks_skipped[]`

**Roles:** `CATALOG` `EXTRACT_EXECUTOR`

### check_extraction_status

Poll the progress of a background extraction batch.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| batch_id | str | yes | Batch ID from start_extraction_batch |

**Returns:** `completed`, `running`, `pending`, `failed`, `all_done`

**Roles:** `CATALOG` `EXTRACT_EXECUTOR`

### get_completed_results

Retrieve extraction summaries from completed background jobs.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| batch_id | str | yes | Batch ID from start_extraction_batch |
| tool_names | list[str] \| None | no | Filter to specific tools |

**Returns:** `results[]` (tool, status, source_name, windows_indexed, tool_call_id)

**Roles:** `CATALOG` `EXTRACT_EXECUTOR`

### wait

Wait for extraction batches or individual jobs to complete.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| seconds | int | no | Max seconds to wait (default 300, max 1800) |
| batch_id | str \| None | no | Batch to wait for |
| job_id | str \| None | no | Individual job to wait for |

**Returns:** `status`, `waited_seconds`, `batch_status{}` or `job_status`

**Roles:** `CATALOG` `EXTRACT_EXECUTOR`

### wait_all

Wait for multiple extraction batches to complete simultaneously.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| batch_ids | list[str] | yes | List of batch IDs |
| poll_interval | int | no | Seconds between checks (default 5) |

**Returns:** `all_done`, `waited_seconds`, `batch_results{}`

**Roles:** `CATALOG` `EXTRACT_EXECUTOR`

### run_parallel

Run multiple tool calls in parallel and return all results.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| tasks | list[dict[str, Any]] | yes | List of {tool, args} dicts |

**Returns:** `batch_id`, `parallel_results[]` (tool, result), `total_tasks`

**Roles:** `EXTRACT_EXECUTOR` `CROSS_EXECUTOR` `NARRATIVE_EXECUTOR`

---

## 20. Enrichment & Intel

### enrich_iocs

Enrich IOCs against public threat intelligence APIs (VirusTotal, AbuseIPDB, OTX, ip-api).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| case_id | str | yes | Active case identifier |
| iocs | list[str] | yes | IOC strings (IPs, domains, hashes) |
| skip_sources | list[str] \| None | no | Source names to skip |

**Returns:** list of enrichment dicts with `ioc`, `ioc_type`, `sources[]`, `aggregate_score`

**Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR` `CROSS_ANALYST`

### lookup_attack_technique

Search the MITRE ATT&CK knowledge base for techniques.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| query | str | yes | Technique ID (e.g. "T1059.001") or keyword |
| max_results | int | no | Maximum results (default 5) |

**Returns:** `match_count`, `techniques[]` (id, name, description, tactics, detection, url)

**Roles:** `CROSS_ANALYST`

### get_tool_guide

Return a reference guide of available forensic tools and their relationships.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| category | str | no | Filter by category (default "all") |

**Returns:** `categories[]`, `guide{}` or `tools[]`

**Roles:** `CROSS_PLANNER`

---

## 21. Verified Entity Graph

All graph tools refresh the deterministic verified-claim projection, enforce
server-owned bounds, and return versioned machine-readable results plus static
Markdown/SVG review views. Every node and edge retains claim, anchor, and source
selectors. No tool accepts SQL, Cypher, table names, or query fragments.

### neighbors

Return relations around an exact entity ID.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| entity_id | str | yes | Exact graph entity ID |
| depth | int | no | Traversal depth (default 1, maximum 4) |
| direction | str | no | `incoming`, `outgoing`, or `both` |
| limit | int | no | Relation limit (default 50, maximum 100) |
| include_superseded | bool | no | Include non-refuted historical edges |
| include_refuted | bool | no | Include later-contradicted historical edges |

**Roles:** `CROSS_ANALYST` `NARRATIVE_ANALYST` `REPORT`

### path_between

Return one deterministic shortest path between exact entity IDs.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| source_entity_id | str | yes | Exact starting entity ID |
| target_entity_id | str | yes | Exact destination entity ID |
| max_depth | int | no | Path depth (default 6, maximum 8) |
| directed | bool | no | Follow only source-to-target edges |
| include_superseded | bool | no | Include non-refuted historical edges |
| include_refuted | bool | no | Include later-contradicted historical edges |

**Roles:** `CROSS_ANALYST` `NARRATIVE_ANALYST` `REPORT`

### events_for_entity

Return chronological graph events touching an exact entity ID.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| entity_id | str | yes | Exact graph entity ID |
| limit | int | no | Event limit (default 50, maximum 100) |
| include_superseded | bool | no | Include non-refuted historical edges |
| include_refuted | bool | no | Include later-contradicted historical edges |

**Roles:** `CROSS_ANALYST` `NARRATIVE_ANALYST` `REPORT`

### host_timeline

Return chronological events for normalized host-scoped endpoints.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| host | str | yes | Hostname selector (case/trailing-dot normalized) |
| limit | int | no | Event limit (default 50, maximum 100) |
| include_superseded | bool | no | Include non-refuted historical edges |
| include_refuted | bool | no | Include later-contradicted historical edges |

**Roles:** `CROSS_ANALYST` `NARRATIVE_ANALYST` `REPORT`
