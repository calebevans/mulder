# Mulder MCP Tool Manifest

Every tool is exposed as `mcp__mulder__{name}`. All tools return a dict containing at minimum `tool_call_id` and `status`. Extraction tools additionally return `source_name`, `windows_indexed`, and `line_count`. Write tools (those with a `source_name`) return only metadata plus a 500-character content preview; full output is accessible via `search()` or `get_raw_output()`.

**Role Key:** `CATALOG` `EXTRACT_PLANNER` `EXTRACT_EXECUTOR` `EXTRACT_ANALYST` `CROSS_PLANNER` `CROSS_EXECUTOR` `CROSS_ANALYST` `NARRATIVE_PLANNER` `NARRATIVE_EXECUTOR` `NARRATIVE_ANALYST` `REPORT`

---

## 1. Case Management

### scan_evidence

Scan an evidence directory and create a new case for investigation. Fails while other tool calls or batch jobs are still running on the open case.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| evidence_path | str | yes | Directory or file containing forensic evidence |
| case_id | str \| None | no | Unique case identifier (one path segment, no separators or control characters); auto-derived from directory name if omitted |
| replace | bool | no | Delete and recreate an existing case (default False) |

**Returns:** `case_id`, `evidence_path`, `evidence_tree`, `type_summary`, `total_items`

**Roles:** `CATALOG`

### open_case

Switch the active case to an already-existing case. Refused with `case_in_use` while other tool calls or batch jobs are still running.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| case_id | str | yes | Case identifier to load (one path segment, no separators or control characters) |

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
| extract_to | str \| None | no | Destination under `<db-dir>/extracted/<case_id>` for the open case (`<db-dir>/extracted` when no case is open); defaults to a per-archive directory there |

**Returns:** `extracted_to`, `total_files_extracted`, `type_summary`, `total_evidence_items`

Plain `.gz` and `.bz2` evidence files are decompressed as single files; compressed
tar archives are unpacked. Only completed extractions are reused. A failed or
partial extraction returns an error and is retried on the next call. Reused
extractions return `status="already_extracted"`, `extracted_to`, and `files[]`.

The expanded size is checked against the free space on the destination
filesystem (less a 1 GiB reserve) before anything is written, for every format:
zip and tar use the declared member sizes, `.7z` (and `.rar`, and a zip that
falls back to `7z`) uses the `7z l -slt` totals, and a bare `.gz`/`.bz2` is
copied in counted chunks. An archive `7z` cannot list has no known size and is
refused rather than extracted unbounded. The member count is checked against
the free inodes where the filesystem reports them. An archive that does not fit
returns `error_type="disk_space"`; whatever that attempt had already written
(a bare stream's partial output, zip members written before a damaged one sent
it to `7z`) is removed, files already in the destination are kept, and the
message says so, or says partial output may remain if an existing file was
overwritten. Extractions onto the same filesystem take a file lock from the
size check to the last write, so concurrent calls, from tool threads or from
separate session processes, never spend the same free space twice. The check
re-reads free space on every call, so nested archives, extracted one level per
call, each see what the previous ones used.

**Roles:** `CATALOG` `EXTRACT_EXECUTOR`

### verify_evidence_integrity

Verify the integrity of all indexed source data by recomputing BLAKE2b hashes.

*No parameters.*

**Returns:** `total_sources`, `verified_count`, `modified_count`, `no_hash_count`, `incomplete_count`, `sources[]`, `elapsed_ms`. A source is `incomplete` when its indexing was interrupted or is still running.

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

List all files and directories (including deleted) from a disk image. Automatically analyzes all NTFS partitions above 100 MB when multiple partitions are present, indexing each as a separate source. The largest NTFS partition is selected as primary when `partition_offset` is omitted. Given a [triage collection](#index_triage_collection) directory instead, lists the collected files: no deleted entries, and the inode column is the row number.

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

Generate a filesystem MAC timeline from a disk image using TSK fls + mactime. Given a UAC collection directory, the timeline is built from the body file the collector wrote; other triage collections have none and get an error saying so.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| image_path | str | yes | Path to the disk image |
| time_range | str \| None | no | Date range filter (e.g. "2015-08-01..2015-08-05") |

**Returns:** `source_name` (tsk.timeline), `windows_indexed`, `line_count`; for a UAC body file also `body_rows` and `timeline_rows`, and an error (`no_rows`) when mactime wrote none

**Roles:** `EXTRACT_EXECUTOR`

### run_optical_listing

List every file on an optical disc image (CD/DVD: UDF or ISO 9660), deleted ones included. Sleuth Kit cannot read optical filesystems (`run_fls`/`run_fsstat` exit with "High entropy", `run_mmls` finds no partition table), so those tools redirect here when the image carries a UDF/ISO 9660 signature. On write-once UDF media (Windows "Live File System" CD-R) every earlier burn session is walked, so files deleted or renamed later are listed as `* ... deleted` and remain extractable. Pure Python; reads E01 (via `xmount`) and raw images.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| image_path | str | yes | Path to the disc image (E01, dd, iso, bin) |
| force | bool | no | Re-run even if `optical.listing` already exists |

**Returns:** `source_name` (optical.listing), `windows_indexed`, `line_count`, `filesystem`, `volume_label`, `sessions`, `files_present`, `files_deleted`

**Roles:** `EXTRACT_EXECUTOR`

### extract_optical_file

Extract one file from an optical disc image into the case's `extracted/` directory so `read_evidence_file`, `analyze_office_document`, `run_hashdeep` or `run_exiftool` can read it. Deleted files on write-once media are recoverable.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| image_path | str | yes | Path to the disc image |
| file_path | str | yes | Path on the disc as shown by `run_optical_listing` (e.g. `/design/winter_storm.amr`) |

**Returns:** `extracted_to`, `disc_path`, `size_bytes`, `sha256`, `deleted_on_disc`, `modified`, `created`

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

### index_triage_collection

Index a triage collection's file list and the collector's own records.

A triage collection is a directory of files copied from a live system: KAPE
target output, an unpacked Velociraptor offline collection, UAC output, or a
plain Windows volume directory (see the
[usage guide](usage-guide.md#triage-collections)). The collected files are read
by the ordinary tools, which take the collection's directory where they take a
disk image: `run_fls`, `run_registry_parser`, `query_registry_value`,
`run_prefetch_parser`, `run_amcache_parser`, `run_shimcache_parser`,
`run_mft_parser`, `run_evtx_parser`, `index_app_files`, `analyze_disk_pcaps`,
`parse_browser_history`, `parse_plist`, `query_sqlite_from_image`, and
`run_mactime` for a UAC body file. This tool indexes the rest.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| evidence_path | str | yes | The collection's directory |
| force | bool | no | Re-index even if this collection was already indexed |

**Returns:** `layout`, `host`, `volumes[]`, `files_collected`, `listing_truncated`, `collected[]`, `not_collected[]` (`not_seen_in_cut_listing[]` instead when the listing was cut), `sources[]`, `not_indexed[]`, `note`

| Source | Content |
|--------|---------|
| `tsk.filelist` | every collected file at its original path, as `fls` rows; the inode column is the row number (`$MFT`, when collected, is 0) |
| `triage.summary` | layout, host name the collection states, volumes, and which kinds of artifact were and were not collected |
| `triage.kape.copylog`, `triage.kape.skiplog` | KAPE's record of each file on the source system: original path, SHA-1, size and created/modified/accessed times; files it found and did not copy |
| `triage.velociraptor.<artifact>` | each `results/<Artifact>.json`, one JSON row per line |
| `triage.uac.<category>` | the `live_response/<category>` command output, each file under a `=== path ===` header |

A collection is not a disk: it has no unallocated space and no deleted files,
and the timestamps on the copies are those of the copy. `not_collected` lists
artifact kinds that are missing from the collection, which does not show they
were missing from the system.

Bounds: 200,000 files and directories per collection, 8 MiB per indexed source,
256 KiB per UAC output file, 40 UAC categories, 200 Velociraptor result files,
and 4 GiB for a file an artifact tool reads (a larger one is refused, not cut);
whatever was cut or left out is named in `not_indexed` and
`listing_truncated`. The walk is breadth-first across the volumes, so a cut
listing keeps the top of each one, and the kinds of artifact not found in it
are then reported as `not_seen_in_cut_listing`, not as `not_collected`. The
listing is in the order `fls` gives (by directory, names compared without
case, the system volume first), so `Windows/...` comes before
`Windows.old/...` and before a shadow copy. Memory and crash dumps inside a
collection (`MEMORY.DMP`, `*.dmp`) stay `memory_dump` evidence items. Symlinks inside a
collection are never followed, a symlink is not accepted as the collection, and Velociraptor's percent-encoded names are
decoded only for display. Layout details: KAPE's `$Extend/$J`, `$Extend/$Max`
and `$Secure_$SDS` are listed as the streams they hold (`$Extend/$UsnJrnl:$J`,
...); a Velociraptor drive collected through two accessors
(`uploads/ntfs/%5C%5C.%5CC%3A`, `uploads/auto/C%3A`) is one volume; files of a
second volume are listed under its label (`D/...`).

**Roles:** `EXTRACT_EXECUTOR`

---

## 4. Extraction: Windows Artifacts

### run_evtx_parser

Extract .evtx files from a disk image and return a prioritized manifest. A triage collection directory is handled the same way; any other directory or a single .evtx file is parsed at once.

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

### run_evtx_recovery

Recover Windows event log records left behind after a log was cleared, using evtx_dump.

What it does depends on what `evidence_path` is:

- **A `.evtx` file, or a directory of them** (searched at any depth; symlinks
  are not followed; at most 2,000 files): reads the stale records still inside
  each log, in chunks whose header was reset and in the slack after a chunk's
  last record (`evtx_dump --recover-records`).
- **Any other file** (a raw or E01 disk image, a memory dump, a file of
  unallocated space, a log whose file header is gone): carves event log chunks
  out of the raw bytes and reads every record in them, slack included. The file
  is read once and never copied; an E01 is read through xmount's flat view,
  which needs FUSE. Exact copies of a chunk are skipped, and the scan stops
  after one million chunks (64 GiB of event log). A file that starts like an
  EnCase segment that is not the first, a VMDK, qcow2 or VHDX image, or a zip
  or gzip file is still scanned as it is, and the response carries a `warning`
  that what it stores compressed was not read.

A recovered record is dropped when a live record has the same channel, record
ID and time. On a disk image the live records are those of the image's own
allocated event logs, which the tool extracts with `icat`, one at a time for
the length of the call, through the file listing `run_fls` indexed for that
image, so run `run_fls` first. Another image's listing in the same case is not
read. A deleted log is not live: where its chunks are still in the image its
records come out as `[carved]`, also when a new log was created under its
name. It does not need `run_evtx_parser` or the directory that tool extracted
to. `compared_with_live_logs` is true only when every allocated log the image
lists was read. When one could not be extracted or read, `warning` gives the
count and `not_parsed.files` names it. When there is none to extract (a memory
dump, a file of unallocated space, an image `run_fls` did not list) nothing is
compared. Either way `[carved]` records include any that are still in a live
log that was not read.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| evidence_path | str | yes | A .evtx file, a directory of .evtx files, or a raw file to carve |
| channels | list[str] \| None | no | Channel name patterns, case-insensitive, `*` allowed. Default: `Security`, `System`, `Microsoft-Windows-PowerShell/Operational`, `Microsoft-Windows-TaskScheduler/Operational`, `Microsoft-Windows-TerminalServices-*`. `["*"]` keeps every channel, and the records recovered without a channel name |
| t_start | str \| None | no | Keep records at or after this UTC time (`2024-03-01` or `2024-03-01T14:30:00`) |
| t_end | str \| None | no | Keep records at or before this UTC time; a date covers its whole day |
| max_records | int | no | Most records kept per channel (default 10000, limit 100000) |
| force | bool | no | Re-run even if this path was already recovered, for example with other channels or another time window. The earlier run's sources stay in the index |

**Returns:** `evidence_path`, `mode`, `scope{}` (the channel patterns, time window and `max_records` applied), `recovered_records`, `earliest_recovered`, `latest_recovered`, `channels{}` (per channel: `source`, `recovered`, `earliest`, `latest`, `event_ids{}` (ten most frequent), `live_records`, `live_earliest`, `live_latest`, `not_indexed_over_max_records`; the twenty with most records), `channels_not_listed`, `live_log_cleared`, `log_clearing_events[]` (the first twenty), `duplicates_of_live_dropped`, `truncated{}`, `not_parsed{}`, `summary_source`, `interpretation`; `records_without_channel{}` when the channel patterns left such records out; when carving also `compared_with_live_logs`, `duplicate_chunks_skipped`; `warning` when carved records were not compared with every live log or the file looks like a container. A call that is skipped because the path was already recovered returns `scope_of_prior_run{}`, so the caller can see whether that run covered what it now asks for.

`truncated{}` counts what was left out: `records_over_max_records`,
`records_in_channels_over_limit` (more than 40 channels), `evtx_files_not_read`,
`log_clearing_events_not_listed`, `carving_stopped_at_chunk_limit`.
`not_parsed{}` counts what could not be read: `records` (lines of evtx_dump's
output that are not JSON, records it reported it could not dump, and records
without a usable time, event ID or record ID), `files` (logs evtx_dump failed
on, and logs of a disk image `icat` could not extract) and
`files_ending_in_a_partial_chunk` (evtx_dump reads whole 64 KiB chunks only, so
the tail of such a log was not read).

Records are indexed per channel as `evtx_recovered.<channel>` (`evtx_recovered.security`,
`evtx_recovered.powershell-operational`), in time order, one per line:

```
2024-03-01T14:30:00.1234567Z | 4624 | security | [recovered record 51234] {"System":{...},"EventData":{...}}
```

These are the fields a live log's lines carry when it is indexed without EZ
Tools (`time | EventID | channel | event`), with the event as JSON. `[recovered]`
means stale space inside a log; `[carved]` means a chunk found in raw data. The
channel is the record's own, not the file's name: stale space in one log can
hold another log's records. `evtx_recovered.summary` is written on every run,
including one that recovered nothing, and lists per channel what was recovered
beside what is live, the scope applied, the clearing events, and what was cut
or not parsed.

evtx_dump recovers some records with their time, event ID, record ID and
computer but without provider, channel or event data. `["*"]` indexes them as
`evtx_recovered.no-channel` (less those whose record ID and time match a live
record). With any other patterns they are not indexed, and
`records_without_channel{}` gives their count, time range and most frequent
event IDs; that count is not compared with live records. An event ID without
its provider does not say which log or program wrote the record.

`log_clearing_events` lists Security 1102 and System 104 records written by
Microsoft-Windows-Eventlog, with the log that was cleared and the account;
`live_log_cleared` is true when one of them is in a live log (and `null` when
no live log was read).

**What a result does and does not mean.** Recovered records are what happened
to survive in cleared or reused space. A recovered record shows that event was
logged. No recovered record for an event or a period does not show it did not
happen, and recovering nothing does not show the log was never cleared. Carving
takes any 64 KiB that starts with a chunk signature and has a record where the
first record belongs; nothing ties such a chunk to the system under
investigation, so corroborate what a carved record says.

Past its time limit (ten minutes, plus two for each GiB of evidence over 4)
the tool returns a timeout and indexes nothing. A search scoped to
`evtx.<channel>` does not read `evtx_recovered.*`, and neither does a composite
tool while the live source it queries exists: search the recovered sources by
name (`source="evtx_recovered"` covers them all).

The binary is the one `mulder setup` and the image install under the asset
directory (`evtx-dump/evtx_dump`). It is never looked up on `PATH`: python-evtx,
a mulder dependency, installs a console script of the same name there, and it
is a different program.

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

### run_hayabusa_logon_summary

Summarise successful and failed Windows logons from EVTX files using Hayabusa's `logon-summary` command.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| evtx_dir | str | no | Directory containing .evtx files |
| image_path | str | no | Disk image path for extraction directory lookup |
| force | bool | no | Re-run even if the summary is already indexed |

**Returns:** `source` (logon.summary), and for `successful` and `failed`: `logons`, `combinations`, `by_logon_type{}`, `with_source_address[]` (at most 15 rows that name a source address, external addresses first: count, target account, domain and computer, logon type, source computer, source IP, and `external`: true, false, or null when the source is not an address that can be classified; IPv6 and IPv4-mapped addresses are classified), `with_source_address_not_listed`; plus `log_period` (first and last timestamp and the number of event records read) and `note`. The full tables are indexed; when there is no logon row nothing is indexed, so a later call reads the logs again.

Hayabusa 3.8.1 counts each combination of account, logon type and source over the whole log and gives no first or last time per row; `log_period` is the span the counts cover. With `image_path`, only that image's event logs are used (extracted if they are not yet), never another image's. A logon is not a compromise, and no rows is not no logons: the Security log may be cleared, rolled over or absent. The command needs Hayabusa's `rules/config` directory; without it the tool returns `error_type: asset_missing` instead of zero logons.

**Roles:** `EXTRACT_EXECUTOR`

### run_chainsaw

Analyze Windows artifacts using Chainsaw with Sigma rules.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| evidence_path | str | yes | Path to EVTX directory or SRUM database |
| mode | Literal['hunt', 'search', 'srum', 'timeline'] | no | Analysis mode (default "hunt") |
| sigma_rules_path | str | no | Path to Sigma rules directory; empty uses the rules installed by `mulder setup` |
| software_hive_path | str | no | SOFTWARE registry hive path; required when mode="srum" |
| mapping_path | str | no | Chainsaw Sigma mapping file for hunt mode; empty uses the mapping installed by `mulder setup` |
| search_term | str \| None | no | Required when mode="search" |
| time_range_start | str \| None | no | ISO 8601 start time filter |
| time_range_end | str \| None | no | ISO 8601 end time filter |
| force | bool | no | Re-run extraction even if sources already exist |

**Returns:** `total_findings`, `severity_counts{}`, `mitre_techniques[]`, `detections[]`

Hunt mode requires a mapping file. SRUM mode requires both the SRUM database and
its SOFTWARE hive. Nonzero Chainsaw exits return errors, not clean scan results.
Detection records are indexed for `search()` and `get_raw_output()` even when
the tool response contains only a bounded preview.

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

### run_usn_parser

Parse the NTFS change journal (`$Extend\$UsnJrnl:$J`) from a disk image using MFTECmd (EZ Tools).

The journal records each recent create, rename, overwrite and delete with its time; `find_encryption_activity`, `find_defense_evasion` and `assess_recovery` read it. The stream is located by listing `$Extend` (MFT entry 11) and read with `icat` by its full stream inode. Its leading sparse region is not copied, and at most the newest 256 MiB of records are parsed; `truncated` says when older records were left out.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| image_path | str | yes | Path to the disk image |
| force | bool | no | Re-run extraction even if sources already exist |

**Returns:** `source_name` (ez.usnjrnl), `windows_indexed`, `journal_bytes_parsed`, `truncated`. A volume without a journal returns `error_type: no_journal`: journaling may be off, or the journal was deleted, which is not evidence that nothing changed.

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

**Returns:** `total_detections`, `level_counts{}`, `mitre_coverage{tactics[], techniques[]}`, `timeline[]`

Matched detection records, including rule names and matched fields, are indexed
in `zircolite.detections`; the response preview may be shorter than the index.

**Roles:** `EXTRACT_EXECUTOR`

### run_cloud_audit_logs

Index exported cloud audit logs and apply Sigma detection rules to them.

Reads JSON arrays, JSON lines and CloudTrail `{"Records": [...]}` files, and
recognises GitHub audit logs, GCP Cloud Audit Logs and AWS CloudTrail per
event. Any other JSON is indexed as `cloudlog.generic` and scanned only when
`ruleset_path` is given. Nothing is fetched: export the logs first (see the
[usage guide](usage-guide.md#cloud-audit-logs)).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| evidence_path | str | yes | JSON log file, or a directory searched for .json/.jsonl/.ndjson |
| ruleset_path | str \| None | no | Sigma rules to use instead of the defaults |
| sigma_level_filter | Literal['informational', 'low', 'medium', 'high', 'critical'] \| None | no | Minimum Sigma level (default "low") |
| force | bool | no | Re-run even if these logs were already indexed |

**Returns:** `files_read`, `files_with_problems{}`, `log_types{<type>: events, source, sigma, detections, level_counts{}, rules_matched{}, mitre_coverage{}}`

Events are indexed one per line in `cloudlog.<type>` (time, actor, action,
source IP, target, raw event) and Sigma matches in `cloudlog.<type>.detections`.
`sigma` is `ok`, or says why the scan was skipped or failed; events are indexed
either way. Default rules are the SigmaHQ `rules/cloud` set for the log type,
plus mulder's own GCP rules for service account key creation, federated token
exchange, service account impersonation, IAM policy changes and Secret Manager
reads.

A file that was damaged or truncated, or that held no events, is named in
`files_with_problems`; complete events before the damage are kept. Events are
indexed in time order, and the index keeps one time per window of lines (a few
events), so a time-range query finds a window by its earliest event. Sigma
matches on full field paths (`userIdentity.type`), so a nested key cannot
stand in for a top-level field. If the events hold more than about 2,000
distinct field paths, the least-used deep ones are left out of the scan and
`sigma` says how many. Symlinks under a directory are not followed.

**Roles:** `EXTRACT_EXECUTOR`

### collect_cloud_audit_logs

Fetch and index cloud audit logs for a time window, using read-only credentials the investigator configured.

Disabled unless the investigator sets `MULDER_AGENT_COLLECTION=1` and
configures a provider (see the [usage guide](usage-guide.md#collecting-with-read-only-credentials));
otherwise it returns `not_enabled` and the missing log belongs in a `[COLLECT]`
finding. The organizations and projects read are fixed by that configuration
and cannot be chosen by the caller.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| provider | str | yes | `github` or `gcp` |
| start | str \| None | no | Start of the window, ISO 8601 (default: `days` before `end`) |
| end | str \| None | no | End of the window, ISO 8601 (default: now) |
| days | int | no | Window length when `start` is not given (default 30) |

**Returns:** `scopes{<org or project>: status, events, window, sha256, warnings[], path, indexed{}}`

Exports are written under the case directory, never the evidence directory,
each with a manifest. Events are indexed exactly as `run_cloud_audit_logs`
does. A window already collected is not fetched again.

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

### NetFlow (nfdump)

The six NetFlow tools read nfdump `nfcapd.*` files. `evidence_path` is an nfcapd directory (or
one file) inside the case evidence root. Times are UTC `YYYY-MM-DDTHH:MM:SS`, and a flow matches a
`t_start`/`t_end` window when it was active in it. Every result row is indexed under a
deterministic `netflow.<kind>.<id>` source whose line 1 is a header carrying the originating
`tool_call_id`; an identical repeat call returns `status: "skipped"` with `existing_sources`
unless `force=True`. They need nfdump >= 1.7; without it they return
`error_type: "binary_missing"`. See [netflow.md](netflow.md).

### run_netflow_analysis

Run the standard NetFlow sections over one exporter directory in one call: inventory, lateral-movement sweep, top egress destinations, direct-to-web hosts, top ingress sources and profiles of the busiest internal hosts. Plan it once per exporter directory, through `start_extraction_batch`.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| evidence_path | str | yes | nfcapd directory (or file) inside the case evidence root |
| internal_nets | list[str] \| None | no | Up to 8 CIDRs considered internal (default RFC 1918) |
| n | int | no | Rows per ranked table (default 50, clamped 5..100) |
| profile_hosts | int | no | Busiest internal hosts to profile (default 10, 0..25) |
| force | bool | no | Re-run every section even if already indexed (default False) |

**Returns:** `source_name` (netflow.analysis.&lt;id&gt;, or netflow.analysis-partial.&lt;id&gt; when a section failed), `sections[]`, `caveats`, `summary`, `files_scanned`, `files_excluded[]`, `file_range`, `warnings[]`

**Roles:** `EXTRACT_EXECUTOR`

### run_netflow_query

Bounded nfdump query: raw flow records, or rows aggregated by up to five keys.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| evidence_path | str | yes | nfcapd directory (or file) inside the case evidence root |
| filter | str | no | nfdump filter expression, whitelisted tokens (default "any") |
| aggregate | list[str] \| None | no | None for raw records, or 1..5 of proto, srcip, dstip, srcport, dstport, flags, srcip4/N, dstip4/N |
| order | str | no | Raw: tstart, tend, duration, bytes, packets, bps, bpp, pps. Aggregated: flows, bytes, packets, bps, bpp, pps (default "tstart") |
| limit | int | no | Rows to return and index (default 100, 1..500) |
| direction | str | no | "any", "egress", "ingress" or "internal", relative to internal_nets (default "any") |
| internal_nets | list[str] \| None | no | Up to 8 CIDRs (default RFC 1918) |
| t_start | str \| None | no | UTC window start |
| t_end | str \| None | no | UTC window end |
| max_inline_rows | int | no | Rows returned inline (default 20, 0..100) |
| force | bool | no | Re-run even if this exact query is indexed (default False) |

**Returns:** `source_name`, `row_count`, `rows[]` (at most `max_inline_rows`), `rows_dropped`, `truncated`, `files_scanned`, `files_excluded[]`, `file_range`, `window`, `filter_applied`, `nfdump_argv`, `warnings[]` (source netflow.query.&lt;id&gt;)

**Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR`

### run_netflow_host_profile

Profile one host: outbound and inbound peers and services, exact totals per direction, first and last seen.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| evidence_path | str | yes | nfcapd directory (or file) inside the case evidence root |
| host | str | yes | IP address to profile |
| n | int | no | Rows per ranked table (default 20, clamped 5..100) |
| internal_nets | list[str] \| None | no | Up to 8 CIDRs (default RFC 1918) |
| t_start | str \| None | no | UTC window start |
| t_end | str \| None | no | UTC window end |
| max_inline_rows | int | no | Rows returned inline (default 20, 0..100) |
| force | bool | no | Re-run even if this exact profile is indexed (default False) |

**Returns:** `source_name`, `row_count`, `rows[]` (at most `max_inline_rows`), `rows_dropped`, `truncated`, `files_scanned`, `files_excluded[]`, `file_range`, `window`, `filter_applied`, `nfdump_argv`, `warnings[]` (source netflow.profile.&lt;id&gt;)

**Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR`

### run_netflow_pair_timeline

Characterise every record between two hosts: sessions, flag mix, SYN-only retries, inter-arrival and flow-size statistics, beaconing hints.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| evidence_path | str | yes | nfcapd directory (or file) inside the case evidence root |
| src | str | yes | Source IP address |
| dst | str | yes | Destination IP address |
| dport | int \| None | no | Destination port (1..65535), or None for all ports |
| proto | str | no | "any", "tcp", "udp" or "icmp" (default "any") |
| both_directions | bool | no | Also match dst->src records (default False) |
| max_records | int | no | Records read before truncation (default 20000, 100..50000) |
| index_records | int | no | Flow rows indexed after the summary row (default 200, 0..500) |
| t_start | str \| None | no | UTC window start |
| t_end | str \| None | no | UTC window end |
| max_inline_rows | int | no | Rows returned inline (default 20, 0..100) |
| force | bool | no | Re-run even if this exact pair query is indexed (default False) |

**Returns:** `source_name`, `row_count`, `rows[]` (at most `max_inline_rows`), `rows_dropped`, `truncated`, `files_scanned`, `files_excluded[]`, `file_range`, `window`, `filter_applied`, `nfdump_argv`, `warnings[]`, `records`, `records_raw`, `hints[]`, `hints_partial` (source netflow.pair.&lt;id&gt;)

**Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR`

### run_netflow_top

Rank the top-N values of one field by flows, packets, bytes or rate.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| evidence_path | str | yes | nfcapd directory (or file) inside the case evidence root |
| stat | str | no | srcip, dstip, ip, srcport, dstport or port (default "dstip"); ip and port count a flow once per endpoint |
| order | str | no | flows, packets, bytes, pps, bps or bpp (default "flows") |
| n | int | no | Rows to keep (default 25, clamped 1..200) |
| filter | str | no | nfdump filter expression, whitelisted tokens (default "any") |
| direction | str | no | "any", "egress", "ingress" or "internal" (default "any") |
| internal_nets | list[str] \| None | no | Up to 8 CIDRs (default RFC 1918) |
| protocol_split | bool | no | Split each value by transport protocol (default False) |
| t_start | str \| None | no | UTC window start |
| t_end | str \| None | no | UTC window end |
| max_inline_rows | int | no | Rows returned inline (default 20, 0..100) |
| force | bool | no | Re-run even if this exact query is indexed (default False) |

**Returns:** `source_name`, `row_count`, `rows[]` (at most `max_inline_rows`), `rows_dropped`, `truncated`, `files_scanned`, `files_excluded[]`, `file_range`, `window`, `filter_applied`, `nfdump_argv`, `warnings[]` (source netflow.top.&lt;id&gt;)

**Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR`

### run_netflow_sweep

Detect internal fan-out (lateral movement, scans): distinct internal targets, flows, SYN-only flows and the largest burst of new targets per source and destination port.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| evidence_path | str | yes | nfcapd directory (or file) inside the case evidence root |
| ports | list[int] \| None | no | Up to 16 destination ports (default 22, 135, 139, 445, 3389, 5985, 5986) |
| min_targets | int | no | Minimum distinct targets to report a (source, port) (default 3, 2..1000) |
| n | int | no | Rows to keep (default 25, clamped 1..100) |
| syn_only | bool | no | Keep only flows with SYN set and ACK clear (default False) |
| burst_window_s | int | no | Sliding window for the burst statistic (default 60, 1..3600 s) |
| internal_nets | list[str] \| None | no | Up to 8 CIDRs (default RFC 1918) |
| t_start | str \| None | no | UTC window start |
| t_end | str \| None | no | UTC window end |
| max_inline_rows | int | no | Rows returned inline (default 20, 0..100) |
| force | bool | no | Re-run even if this exact sweep is indexed (default False) |

**Returns:** `source_name`, `row_count`, `rows[]` (at most `max_inline_rows`), `rows_dropped`, `truncated`, `files_scanned`, `files_excluded[]`, `file_range`, `window`, `filter_applied`, `nfdump_argv`, `warnings[]` (source netflow.sweep.&lt;id&gt;)

**Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR`

---

## 6. Extraction: Mobile

MVT indexes the collected module output, including detection records. ALEAPP and
iLEAPP index parsed artifact rows, including timestamps and field values. Use
`search()` or `get_raw_output()` for records beyond the bounded response previews.

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

**Returns:** `source_name` (phone.android), `parsed_types[]`, `windows_indexed`, `unreadable_count`, `unreadable_databases[]`

**Roles:** `EXTRACT_EXECUTOR`

### parse_ios_artifacts

Parse iOS artifacts from an iTunes/Finder backup or extracted files.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| evidence_path | str | yes | Path to the iOS backup directory |
| artifact_types | list[str] \| None | no | Types to parse (e.g. ["sms", "calls", "safari"]) |

**Returns:** `source_name` (phone.ios), `parsed_types[]`, `manifest_found`, `unreadable_count`, `unreadable_databases[]`

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

**Returns:** `source_name` (phone.app_data), `plaintext_dbs_found`, `encrypted_dbs_decrypted`, `unreadable_count`, `unreadable_databases[]`

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

Failed or incomplete rabin2 analysis cannot produce a `benign_indicators` verdict;
without other suspicious indicators, the verdict is `inconclusive`. Derived
triage findings are indexed alongside the raw analysis for subsequent searches.

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

Each capability's `attack[]` entries use `technique_id` for the full ATT&CK ID
(including a subtechnique suffix such as `T1059.006`) and `subtechnique` for its
name. The previous always-null `subtechnique_id` field has been removed.

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
| commands | str | no | Semicolon-separated r2 commands (default "iI;iS;iz;afl"); run under radare2's sandbox, blocking shell execution, writes, and opening other files |

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

**Returns:** `indicators[]`, `risk_assessment{}`, `javascript[]`, `urls[]`, `embedded_files[]`

URL entries include `url`, `source`, and `object_id`. Embedded-file entries include
`filename`, `object_id`, and `suspicious`; the option lists file metadata rather
than writing embedded payloads to disk. Both are indexed in `pdf.analysis`.

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
| search_term | str \| None | no | Keyword filter across subject, sender, To/Cc recipients, body, and attachment filenames |

**Returns:** `total_emails`, `total_attachments`, `folder_structure{}`, `emails[]`, `suspicious_findings[]`

RFC 2047 encoded headers are decoded, quoted recipient names are preserved,
HTML-only messages get a searchable text body, and named inline MIME parts count
as attachments.

**Roles:** `EXTRACT_EXECUTOR`

---

## 9. Extraction: Malware / YARA

### yara_scan_files

Scan a mounted filesystem or extracted directory for malware using YARA rules.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| target_path | str | yes | Path to scan (file or directory) |
| rules | str \| None | no | Custom YARA rule source (file, directory, or inline) |
| ruleset | str | no | "builtin" (default): signature-base plus the investigator's own rules. "custom": the investigator's rules alone. "standard" and "full" are aliases of "builtin". |

The investigator's own rules come from `MULDER_YARA_RULES` (see the [usage guide](usage-guide.md#using-your-own-yara-rules)).

**Returns:** `source` (yara.files), `result_count`, `hit_metadata{}`

**Roles:** `EXTRACT_EXECUTOR`

### yara_scan_memory

Scan the memory dump with YARA rules for malware signatures.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| rules | str \| None | no | Custom YARA rule source |
| ruleset | str | no | "builtin" (default): signature-base plus the investigator's own rules. "custom": the investigator's rules alone. |

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

### run_secret_scan

Find leaked credentials in CI run logs, build artifacts, repository checkouts or any other files, using gitleaks.

Scans files as they are on disk (no git history) and looks inside archives up
to two levels deep. Secrets are redacted before they are indexed or returned:
at most the first 12 characters remain, enough to identify the key without
disclosing it.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| evidence_path | str | yes | File or directory to scan |
| force | bool | no | Re-run even if this path was already scanned |

**Returns:** `total_findings`, `by_rule{}`, `files_with_findings`, `by_file{}` (50 files with the most findings), `source` (secrets.findings), `not_scanned{reason: count}`, `not_scanned_source` (secrets.not_scanned)

Each finding is one line in `secrets.findings`: time, rule, file:line, redacted
secret, description. The time is the timestamp on the line the secret sits on,
which in a CI run log is when it was printed; `-` when the line has none or the
file is inside an archive. Dated findings come first in time order. The index
keeps one time per window of lines, so a finding is placed on the timeline at
the time of the earliest finding in its window, not exactly at its own.

**What a clean result does and does not mean.** Suppression planted in the
scanned tree is not honoured: inline `gitleaks:allow` comments, a
`.gitleaks.toml` and a `.gitleaksignore` all have no effect. But gitleaks
leaves some content unscanned by its own rules, and file names and content are
attacker-influenced:

- files whose path matches its built-in allowlist (images, PDFs, lock files,
  `node_modules/`, `vendor/`, `.git/` and similar);
- files whose first bytes look like a binary format (PDF, ELF, zip, gzip);
- archives it does not recognise by extension (`.jar`, `.whl`, `.nupkg`), and
  text files named like an archive (`run.log.gz`);
- archives nested more than two levels deep, and unreadable files.

Every one of these that gitleaks reports is listed in `secrets.not_scanned`
with the reason, and counted in `not_scanned`. A secret in a listed file is
not ruled out. Two gaps are not reported: a secret that straddles gitleaks'
125,000-byte read boundary in a file with no blank lines, and the
`generic-api-key` rule's own line-level exceptions.

**Roles:** `EXTRACT_EXECUTOR`

-----------|------|----------|-------------|
| target_path | str | yes | File or directory to scan |
| force | bool | no | Re-run even if this path was already scanned |

**Returns:** `total_findings`, `by_rule{}`, `files_with_findings`, `by_file{}` (50 files with the most findings), `source` (secrets.findings)

Each finding is one line in `secrets.findings`: time, rule, file:line, redacted
secret, description. The time is the timestamp on the line the secret sits on,
which in a CI run log is when it was printed; `-` when the line has none.

**Roles:** `EXTRACT_EXECUTOR`

### run_workflow_audit

Audit GitHub Actions workflows for exploitable weaknesses using zizmor, and list the secrets each workflow refers to.

Runs offline. Finds template injection of attacker-controlled input,
dangerous triggers (`pull_request_target`, `workflow_run`), unpinned actions,
excessive permissions and credential persistence.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| evidence_path | str | yes | A repository checkout (or a directory of several), a directory of workflow YAML files, or one workflow file |
| force | bool | no | Re-run even if this path was already audited |

**Returns:** `workflows_audited`, `total_findings`, `by_severity{}`, `by_audit{}`, `suppressed_in_source`, `secrets_by_workflow{}`, `not_audited_count`, `not_audited{}`, `sources[]`

mulder picks the files itself and audits each in its own zizmor run: every
workflow in a `.github/workflows` folder at any depth, and every composite
action under or beside a `.github` folder. A directory with no such folder is
treated as a folder of exported workflows and its own YAML files are audited.
Nothing in the audited tree can narrow that: a `.git` or `.gitignore`, a
`zizmor.yml`, and inline `zizmor: ignore[...]` comments have no effect, and a
finding an ignore comment tried to hide is marked `suppressed-in-source`.

A file that could not be audited (not valid YAML, not UTF-8, a byte-order
mark, a symlink, slower than 60 seconds) is listed in `workflow.not_audited`
with the reason; a weakness in it is not ruled out. If no file could be
audited the call is an error.

Findings are indexed in `workflow.findings`, highest severity first: severity,
confidence, audit, file:line, annotation, description, suppression marker, the
offending YAML. `workflow.secrets` holds one line per file with the secrets
its text refers to (`secrets.NAME`, `secrets['NAME']`, `secrets: inherit`,
and `toJSON(secrets)` or a computed name, which reach all of them). It is per
file, not per job, counts a reference inside a comment, and does not follow a
secret passed through an environment variable or a reusable workflow.

**Roles:** `EXTRACT_EXECUTOR`

-----------|------|----------|-------------|
| repo_path | str | yes | A repository checkout (or a directory of several), a directory of workflow YAML files, or one workflow file |
| force | bool | no | Re-run even if this path was already audited |

**Returns:** `workflows_audited`, `total_findings`, `by_severity{}`, `by_audit{}`, `suppressed_in_source`, `secrets_by_workflow{}`, `sources[]`

Findings are indexed in `workflow.findings`, highest severity first: severity,
confidence, audit, file:line, annotation, description, suppression marker, the
offending YAML. `workflow.secrets` holds one line per workflow with the
`secrets.NAME` references found in its text; it is per file, not per job.

**Roles:** `EXTRACT_EXECUTOR`


---

## 10. Query Tools

### search

Search all ingested evidence for keywords or regex patterns.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| query | str | no | Search term or regex pattern |
| source | str \| list[str] \| None | no | Source name/prefix, or a list matching any listed source; an empty list applies no source-name filter |
| max_results | int | no | Maximum matching windows (default 50) |
| regex | bool | no | Treat query as regex (default False) |
| t_start | str \| None | no | ISO 8601 start time filter |
| t_end | str \| None | no | ISO 8601 end time filter |
| queries | list[str] \| None | no | Multiple search terms (OR logic) |
| exclude_sources | list[str] \| None | no | Source prefixes to exclude |
| evidence_path | str \| None | no | Evidence file path or basename; restrict to sources extracted from that image |

**Returns:** `results[]` (each hit carries `source_path`), `total_matches`, `has_more`, `sources_matched[]`

**Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR` `CROSS_ANALYST` `NARRATIVE_EXECUTOR` `NARRATIVE_ANALYST` `REPORT`

### get_raw_output

Retrieve full raw text from a specific evidence source with cursor pagination.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| source_name | str | yes | Exact source name or prefix |
| after_id | int | no | Cursor for keyset pagination (default 0) |
| limit | int | no | Maximum windows to return (default 50) |
| evidence_path | str \| None | no | Evidence file path or basename; required when the name exists for more than one image (otherwise an error lists the candidate `source_paths`) |

**Returns:** `raw_text`, `source_paths[]`, `total_windows`, `next_after_id`, `has_more`

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
| image_path | str \| None | no | Path to the specific disk image (required for multi-image cases), or the triage collection directory whose listing the inode is a row of |

**Returns:** text files: `source_name`, `windows_indexed`; binary files: `sha256`, `size_bytes`

The inode column of a triage collection's listing is a row number. When the case holds a collection beside another file listing and `image_path` is omitted, the call is refused (`image_path_required`) rather than reading that number from a disk image.

**Roles:** `EXTRACT_EXECUTOR`

### get_file_metadata

Return file metadata (MAC times, size, blocks) for an inode using TSK istat.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| inode | int | yes | Inode number of the file |
| filesystem_type | str \| None | no | TSK filesystem type (auto-detected if omitted) |
| image_path | str \| None | no | Path to the specific disk image (required for multi-image cases) |

**Returns:** `source_name`, `windows_indexed`

A triage collection has no inode metadata: for one, the call returns `not_applicable` and says where the original timestamps are.

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

### find_encryption_activity

Find bursts of file renames to one extension that may be ransomware encryption.

Reads the indexed change journal (`ez.usnjrnl`, from `run_usn_parser`), and the MFT (`ez.mft`) when no journal is indexed or the journal holds no candidate: the journal is a ring, and encryption older than its first record is still in the MFT. A burst is a run of minutes in which at least 50 files (not rename records) were renamed to the same extension, plus the slower minutes up to two minutes either side, which hold a run's first and last seconds. Every burst of an extension on a volume is reported as one candidate (`active_periods` lists them), so a run that pauses on large files is one run and starts where it started. A burst becomes a candidate when it carries a signal: the extension follows three or more kinds of data file on at least half the burst's files (`extension_appended`), a known ransom note name was created in two or more directories (`known_note_name`), or, from the journal only, the MFT shows no file with the extension before the burst and the same file was created in five or more directories (`extension_new_to_volume` with `repeated_file_across_directories`). Thresholds are named constants in `composite/ransomware.py`, set against the journal of a real WannaCry infection in which Windows servicing renamed seven times more files a minute than the ransomware.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| image_path | str | no | Analyse only this image (path or file name, as passed to `run_usn_parser`); empty analyses every indexed volume |

Each indexed volume is analysed on its own rows. With more than three volumes, the three where a candidate begins earliest are returned in full and the rest as one line each (`volumes_in_brief`); every volume is indexed in full.

**Returns:** `results.volumes[]`, each with `evidence`, `basis` (`usn_journal` or `mft`), `records_examined`, `journal_window`, `journal_note` (when a journal is indexed but the candidates come from the MFT), `candidates[]` (at most 3; more are counted in `candidates_not_listed` and named in `candidates_not_listed_first[]`), `busiest_periods[]` (the 3 largest bursts of any kind), counts of bursts found and not examined, and `rows_unparsed`; plus `results.caveats[]` and `missing_sources[]`. A candidate carries `extension`, `first_time`, `last_time`, `duration_seconds`, `files_affected`, `peak_files_per_minute`, `active_periods[]`, `signals[]`, `appended_to_extensions`, `appended_share`, `original_extensions[]`, `related_extensions[]`, `directories_affected`, `top_directories[]`, `first_directories[]`, `note_candidates[]`, `note_excerpt` (at most 1,200 characters, read with a bounded `icat` from up to three copies in the burst's own directories, keeping the one most like a known note) or `note_not_read`, `family_hints[]`, `mft_cross_check`, `starts_at_journal_start`, `older_than_journal` and `inspect_with` (a `search` call that returns rows of the burst). Indexed as `composite.encryption_activity`.

**What it does not establish:** a candidate is a lead. Compression, backup and bulk renames give many files one new extension too, and neither source names the process or the account. No candidate is not no encryption: in-place encryption, a different extension per file and a rate under the threshold are not flagged. The journal pass counts renames, so ransomware that creates each file under its new name and deletes the original (Dharma, Phobos), like activity older than the journal, is found only from the MFT; without an indexed MFT it is not flagged, and it shows only under `busiest_periods`. A slow start or tail more than two minutes from a burst is outside `first_time` and `last_time`.

**Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR` `NARRATIVE_EXECUTOR`

### ransomware_family_hints

Suggest ransomware families for a file extension, a ransom note name or note text, offline.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| extension | str | no | Extension added to encrypted files, e.g. `.lockbit` |
| note_name | str | no | File name of the ransom note |
| note_text | str | no | Text of the ransom note |

At least one is required. The extension is looked up in Splunk's `ransomware_extensions_lookup.csv` (vendored under `server/data/ransomware`, Apache-2.0). The note name is checked against Splunk's `ransomware_notes_lookup.csv`, which has no family column and so only says the name is a known ransom note name, and against the file names in the ThreatLabz ransom note corpus (the `ransomware-notes` asset, MIT). The note text is compared to that corpus by word-sequence similarity, best note per family.

**Returns:** `hints[]` (family, basis, score, detail; at most 5), `hints_found`, `known_note_name`, `caveat`, and `corpus` when the corpus is not installed. A score only ranks the hints. Families share extensions, note names and note templates, so a hint is a family to check, never an identification.

**Roles:** `EXTRACT_ANALYST` `CROSS_ANALYST` `NARRATIVE_ANALYST` `CROSS_EXECUTOR`

### find_remote_access_tools

Find remote access and management tools (AnyDesk, TeamViewer, ScreenConnect and several hundred others).

Matches the executable names and domains in the LOLRMM catalog (the `lolrmm` asset, Apache-2.0, pinned to a commit) against the indexed file listing, Prefetch, Amcache, ShimCache, registry, autoruns and DNS/HTTP/TLS sources. Names that are not a tool's own are left out: stems under four characters, names four or more catalog tools share, and a short list of Windows and common-software names; `mstsc.exe` and `quickassist.exe` count only where they ran, not where they sit on disk. A program counts as run from Prefetch only by the `ExecutableName` of its own Prefetch file, not by appearing among the files another program loaded. Logs of AnyDesk (`ad.trace`, `ad_svc.trace`, `connection_trace.txt`), TeamViewer, Splashtop, ScreenConnect and RustDesk found on the image are read (the newest 8 MiB of each) and indexed as `rmm.<tool>.<file>.<inode>`, one source per file, so each user profile's log is searchable. At most 20 log files are listed, the tools taking turns; deleted ones are listed and not read.

*No parameters.*

**Returns:** `results.tools_found`, `results.tools[]` (at most 12: tool, matched names, and per source the evidence path, line count and one sample line), `tools_not_listed[]`, `tool_logs[]` (tool, path, source, bytes indexed, `truncated`, `external_addresses[]` with one sample line each, or `not_read`), `tool_logs_not_read` (log files found beyond those listed), `sources_searched[]`, `what_a_source_establishes{}`, `caveats[]`, `missing_sources[]`. Indexed as `composite.remote_access_tools`.

**What it does not establish:** presence is not abuse; these are common IT tools. Abuse is established by installation or first run inside the incident window, by a compromised account, or by a session in the tool's own log from an address the organisation does not use. A match is a file name or a domain: unrelated software can share a name.

**Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR` `NARRATIVE_EXECUTOR`

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

**Roles:** `EXTRACT_ANALYST` `CROSS_EXECUTOR` `NARRATIVE_EXECUTOR`

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
| image_path | str \| None | no | The disk image or triage collection directory whose listing the inode came from; needed only when the case holds a collection beside another file listing |

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

Identify and consolidate duplicate findings across systems. Merges are lossless: the survivor gets the union of evidence_refs, sources and MITRE ids, the widest time range, the highest severity and confidence, and each absorbed finding's title and description under a "Merged findings" section. A live call is refused below the default threshold or when it would absorb more than 25% of findings; use `dry_run=true` first.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| case_id | str | yes | Active case identifier |
| similarity_threshold | float | no | Minimum similarity score (default 0.4; lower only with dry_run) |
| dry_run | bool | no | Preview without modifying (default False) |

**Returns:** `groups[]` (with `merged_ids`, `merged_titles`), `absorbed`, `merged_count`, `would_merge_count`, `kept_count`, `summary`

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

### resolve_question

Record how an investigation question was resolved and what the answer rests on. The orchestrator stores each plan's questions in the case database; question ids (`q_1a2b3c4d`) prefix the questions the analyst is given, and `get_investigation_summary` lists the open ones. `answered` must name at least one finding that is not `[NEGATIVE]` or `[COLLECT]`; `ruled_out` must name at least one `[NEGATIVE]` finding. To count, a named finding must exist, be that kind, and cite only logged, successful calls to tools other than the findings tools; at least one of those calls must be to a tool that extracts, searches or reads evidence, so a finding that cites only bookkeeping (`open_case`, `list_sources`, `get_investigation_summary`, `get_ioc_summary`, `get_bookmarks`, the audits, job polling) answers nothing and rules nothing out. Other ids named alongside one that counts are ignored and listed in the response. `undetermined` needs a reason. The id is accepted with or without the square brackets it is displayed in. A resolution holds only while a finding it names still exists and is still that kind; otherwise the question is open again. Calling again replaces the earlier resolution. `ruled_out` records that the sources examined did not show something, not that it did not happen.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| question_id | str | yes | The question to resolve |
| resolution | str | yes | "answered", "ruled_out" or "undetermined" |
| finding_ids | list[str] \| None | no | Findings the answer rests on; required for "answered" and "ruled_out", ignored for "undetermined" |
| reason | str | no | Required for "undetermined": what evidence is missing (kept to 1,000 characters) |

**Returns:** `question_id`, `resolution`, `finding_ids[]` (the findings the resolution was recorded against), `open_questions` (count still open), and `ignored_finding_ids` (the first 10 named ids that did not count, each with the reason) when there are any

**Roles:** `EXTRACT_ANALYST` `CROSS_ANALYST` `NARRATIVE_ANALYST` `REPORT`

---

## 18. Review & Audit

### get_investigation_summary

Return a compact progress dashboard for the current investigation.

*No parameters.*

**Returns:** `sources_indexed`, `findings_submitted`, `findings_by_severity{}`, `remaining_work[]`, `ready_to_finalize`. When investigation questions were recorded, also `questions{}` (recorded, open, answered, ruled_out, undetermined), `open_questions[]` (question_id, phase, system, question; the 15 oldest across every phase and system, each cut to 200 characters, with `open_questions_note` when there are more), `significant_findings` (findings of activity at medium severity or above) and `no_incident: true` when every question is resolved and at least one is answered or ruled out, both audits have run, there are fewer than three findings of activity and none is medium or above.

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

Run multiple tool calls in parallel and return all results. `open_case` and `scan_evidence` cannot run inside it.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| tasks | list[dict[str, Any]] | yes | List of {tool, args} dicts |

**Returns:** `batch_id`, `parallel_results[]` (tool, result), `total_tasks`

**Roles:** `EXTRACT_EXECUTOR` `CROSS_EXECUTOR` `NARRATIVE_EXECUTOR`

---

## 20. Enrichment & Intel

### enrich_iocs

Enrich IOCs against public threat intelligence APIs (VirusTotal, AbuseIPDB, OTX, GreyNoise, urlscan.io, ip-api). Each source runs only when its key is set (`VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `OTX_API_KEY`, `GREYNOISE_API_KEY`, `URLSCAN_API_KEY`). GreyNoise says whether an IP is a known internet-wide scanner; urlscan is searched for existing scans of pages on that host and never asked to scan; it contributes a scan count for the window the plan can search (30 days on the free plan) and the latest scan time, and a score only on plans that return verdicts. GreyNoise's classification is a tag; only `malicious` scores. Domains are also checked offline against a built-in list of exfiltration-capable services (request catchers, tunnels, paste sites, file drops, messaging webhooks), reported as source `exfil-list` with tags and no score. Every indicator is reduced to a host, IP or hash before any lookup: defanging (`hxxps://evil[.]example`) is undone and a URL's scheme, credentials, port, path and query are dropped, so they are never sent to a third party. The indicator as given is still stored in the case index. ip-api uses HTTPS with `IP_API_KEY`; without a key it is skipped unless `MULDER_IP_API_ALLOW_HTTP=1` allows the plaintext free endpoint.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| case_id | str | yes | Active case identifier |
| iocs | list[str] | yes | IOC strings (IPs, domains, hashes, URLs) |
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
