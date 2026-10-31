# NetFlow (nfdump) evidence

mulder reads NetFlow/IPFIX evidence stored by an nfdump collector (`nfcapd.*` files) through six
typed MCP tools: one extraction-phase one-shot, `run_netflow_analysis`, planned once per exporter
directory the way `run_zeek_analysis` is planned once per pcap, and five follow-up pivots for the
extraction analyst and the cross-system executor, once the indexed sections name the hosts, pairs
and windows to ask about. Like every other
forensic tool in mulder, they take typed parameters, build an argv list (never a shell string),
bound their output, and index every result row in the case database so findings can cite it.

## Evidence layout

An nfdump collector writes one binary file per rotation interval, usually below one directory per
exporter:

```
evidence/
  netflow/
    edge-router/                  one directory per exporter (router, firewall, probe)
      2001/02/
        nfcapd.200102030000       rotation name nfcapd.YYYYMMDDhhmm[ss]
        nfcapd.200102040000
        nfcapd.current.4242       a collector's live temp file (read like any other)
```

- Pass the **directory** (any level: exporter, year, month) as `evidence_path`; the tools walk it
  recursively. A single file also works.
- Files are admitted by their 4-byte nfdump magic (`0c a5 01 00` or `0c a5 02 00`), never by
  name: a text file named like a rotation file is excluded, a renamed capture beside rotation-named
  siblings is kept. Empty files, symlinks and files without the magic are reported in
  `files_excluded` with a reason. A call that would read more than 10 000 files (about a month of
  nfcapd's default 5-minute rotation) is refused, not truncated: the extractor and an unwindowed
  pivot need a subdirectory (a per-day layout such as `nfcapd -S 1`); a windowed pivot counts only
  the files its window selects and can narrow the window, except that files without a rotation
  date (renamed captures) are kept by every window, so when more of those than the cap sit in the
  directory only a subdirectory helps (the refusal says which).
- The case classifier types such files as `netflow_capture`, the evidence context lists each
  nfcapd directory for the planner, and the coverage audit reports one item per directory.

## Requirements

- **nfdump >= 1.7** at `/opt/nfdump/bin/nfdump` or on the server's `PATH`. The container image
  builds nfdump 1.7.10 from its checksum-pinned release archive into `/opt/nfdump`. nfdump 1.7
  writes file layout 2 by default; nfdump 1.6 (the version Ubuntu 22.04 packages) cannot read
  layout-2 files at all, so native installs must provide 1.7 or later.
- `prlimit` (util-linux): every nfdump child runs under a 4 GiB address-space limit.

Without nfdump the tools return `error_type: binary_missing`; nothing else in mulder changes. The
tools read `nfdump -V` once per binary and refuse a version below 1.7 the same way. The csv
layouts the parsers read were captured from nfdump 1.7.10 and are checked against the bundled
binary by the container smoke test; a run that exits 0 without a recognised table header or the
"No matching flows" sentinel fails with `tool_failed` instead of indexing nothing, so a format
change in a later nfdump is reported, not read as an empty result.

## The tools

All six take `evidence_path` first; the pivots accept `t_start`/`t_end` (UTC,
`YYYY-MM-DDTHH:MM:SS`; a flow counts when it was *active* in the window) and return at most
`max_inline_rows` rows inline (default 20, max 100) while every row is indexed; the extractor
returns its summary rows and no section rows inline.
Integer parameters (`n`, `limit`, `dport`, `ports`, ...) also accept digit-only strings such as
`"445"`, so batch calls behave like direct ones.

### The extractor

`run_netflow_analysis(evidence_path, internal_nets=None, n=50, profile_hosts=10)` is the tool the
extraction planner plans, once per exporter directory (always through `start_extraction_batch`).
It runs the standard sections in one call, in this order, and indexes each as its own source:

| Section | What it indexes | Source |
|---|---|---|
| `inventory` | exporter identity, data window, per-file manifest, top talkers, top services, top byte sources and destinations, /24 segment matrix (`n` rows per table, 5..100) | `netflow.inventory.<id>` (+ `.manifest`) |
| `sweep` | internal fan-out on the lateral-movement ports 22, 135, 139, 445, 3389, 5985, 5986 (`min_targets=3`, 25 rows) | `netflow.sweep.<id>` |
| `top_egress_bytes` | external destinations by bytes (`stat=dstip`, `order=bytes`, `direction=egress`) | `netflow.top.<id>` |
| `top_web_direct` | internal hosts connecting directly to external web ports (`stat=srcip`, `order=flows`, `direction=egress`, filter `dst port 80 or dst port 443`) | `netflow.top.<id>` |
| `top_ingress_sources` | external sources reaching inside (`stat=srcip`, `order=flows`, `direction=ingress`) | `netflow.top.<id>` |
| `profile` × `profile_hosts` | one `run_netflow_host_profile` (n=20) per busiest internal host, ranked by bytes sent plus received in the inventory's byte tables, internal per `internal_nets` (0..25 hosts) | `netflow.profile.<id>` each |

plus a summary source `netflow.analysis.<id>`: one row per section (name, status, source, row
count) and key-fact rows (exporter and window, top talker, top sweep source, top egress
destination, top direct-web-egress host, top ingress source), every row stamped with the data
window's start (not an event time). The envelope's `sections[]` lists each section's status,
source, row count and summary (no rows inline: `get_raw_output(<source>)` reads them) and
`caveats{}` explains how to read each kind of row. A section that fails after the inventory is
reported there and the rest still runs (`status: partial`); an exception inside a section is an
`internal_error` entry; an inventory failure ends the call (`status: error`). A section that
times out, or one the call-level deadline (2 h) left unstarted (`not_run`), also makes the call
report `error_type: timeout` at the top level, so a batch defers and retries it (when nothing
else is running and the host is idle the job store marks the job failed instead, and the
executor's one retry goes through `start_extraction_batch` again). A run that did not end
`success` registers its summary as `netflow.analysis-partial.<id>`, outside the batch-skip
prefix, so that retry reaches the tool; the next call without `force` **resumes** it: sections
that already have a complete source skip themselves, the missing ones run, and the completed
run's summary takes the `netflow.analysis.<id>` name (superseding the partial one).
Each section is indexed exactly as the matching pivot would index it, so a pivot called later
with the same parameters (for example `run_netflow_sweep(evidence_path)` with the defaults)
returns `status: skipped` with the section's source instead of running again. `force=True`
re-runs every section as `-r<k>`. Before any section runs the call registers a
`netflow.progress.<id>` record (`status=running`, the summary name, the files and sections
planned; `summary_id` = the hash that pairs it with its summary) and appends a footer when it
ends, on every path (`status=` the outcome, `summary=` the source actually registered, or
`none`; the footer write itself may fail quietly): a progress record whose last row is still its
`status=running` header is a run in flight, or a dead one once its `started=` is older than the
2 h deadline, unless a `netflow.analysis.<id>` or `netflow.complete.<id>` for that id exists (a
completed run whose footer write failed); a footer `status=partial` or `status=error` is a run
that ended incomplete (the partial summary's section rows say which sections failed; after an
inventory error there is no summary at all) unless a newer `netflow.analysis.<id>` (or `-r<k>`)
with `status=success` exists, which closes every older partial summary and progress record of
that id (its header's `supersedes=` names the record it closed, on a resume, a forced re-run or
a fresh run after an error alike). A completed run registers the rowless `netflow.complete.<id>` marker last, after its
summary rows: that marker is the batch-skip prefix, so a batch skips a second extractor task only
once a run really completed (a summary whose rows never got written carries no marker and a batch
retry resumes it). The call is
slow (the inventory's three passes plus one pass per ranked list, one per sweep and two per
profile, each over every file); every nfdump timeout is capped by the deadline (2 h). The
executor's `wait_all` gives up after 30 minutes while the job keeps running, so the extraction
analyst may see the progress record before the summary exists: the analyst prompt tells it to
read the section sources present and report the gap rather than conclude there is no NetFlow.
The reading notes for each row kind are indexed as `caveat` rows of the summary source
(`search(query="once per endpoint", source="netflow.analysis")` finds them).

### The pivots (targeted follow-up tools)

The five pivots are not planned at extraction: the extraction analyst and the cross-system
executor call them after reading the indexed `netflow.*` sources, for the hosts, pairs and
windows the analysis turned up (the pair of roles upstream gives its own follow-up tools such
as `list_files` and `get_file_metadata`).

| Tool | Answers | Bounded output |
|---|---|---|
| `run_netflow_top` | top-N of one field (`srcip`, `dstip`, `ip`, `srcport`, `dstport`, `port`) by flows, packets, bytes, pps, bps or bpp, with percent of total; optional filter, window, direction (`egress`/`ingress`/`internal` relative to `internal_nets`) and protocol split | `n` rows (1..200) |
| `run_netflow_host_profile` | one host's outbound and inbound services and peers by flows and bytes, exact per-direction flow and byte totals and first/last seen, which of the listed top peers are external (`external_peers_scope` says the count covers the ranked peer rows only) | `n` rows per table (5..100) plus a summary row |
| `run_netflow_sweep` | internal fan-out per (source, destination port): distinct targets, flows, SYN-only flows, largest burst of new targets within `burst_window_s` | `n` rows (1..100), ranked by targets; up to 20 targets listed per row |
| `run_netflow_pair_timeline` | every record between two hosts (optionally one port, optionally both directions): sessions over 1 h, longest session and its rate, source ports, flag mix, SYN-only retries, inter-arrival statistics and flow-size uniformity, with hints (`long_lived_low_rate`, `periodic`, `syn_only_retries`, `fixed_size`, `nightly`); record counts with exporter copies collapsed (`records_distinct`, `bytes_distinct`), the days records started on and were active on | reads up to `max_records` (100..50 000) records; indexes one summary row plus up to `index_records` (0..500) flow rows |
| `run_netflow_query` | a bounded nfdump query: raw records (ordered by start, end, duration or a volume field) or rows aggregated by up to five keys (`proto`, `srcip`, `dstip`, `srcport`, `dstport`, `flags`, `srcip4/N`, `dstip4/N`; one key per address side, e.g. `srcip` or one `srcip4/N`, because nfdump prints one address column per side) | `limit` rows (1..500) |

Further bounds that apply to every call:

- **Filters** are nfdump filter expressions checked against a token whitelist (primitives,
  address literals, numbers, brackets; ASCII only; at most 1000 characters). Quotes, shell
  metacharacters, hostnames, unknown words and non-ASCII characters (including non-ASCII digits)
  are rejected before any process starts. A filter that contains an `or` is parenthesised before
  the window and direction clauses are added. Examples:
  `src ip 192.0.2.10 and dst port 445`, `src net 192.0.2.0/24 and dst net 198.51.100.0/24 and
  proto tcp`, `host 203.0.113.5 and duration > 3600000`.
- **Timestamps** are UTC with ASCII digits: `YYYY-MM-DDTHH:MM:SS`, optionally with a space instead
  of `T`, fractional seconds, `Z` or `+00:00`; any other offset is rejected. All spellings of one
  instant are the same window (and the same source, see below).
- **Time windows** select files as well as records: a flow is written to the file of the interval
  in which it *expired*, so a window reads the files from one day before `t_start` to eight days
  after `t_end` (-1 day lookbehind, +8 days lookahead: a record is written when it expires, and
  the 8 days cover exporters whose active timeout is up to 7 days, plus one rotation day) and then
  filters on `first seen`/`last seen`.
- **Memory**: over more than three files, `run_netflow_query` refuses a volume ordering without
  aggregation, or an aggregation with `srcport` or with both `srcip` and `dstip` (`srcip4/N` and
  `dstip4/N` with N >= 25 count as `srcip`/`dstip`), unless a filter narrows it; a filter made only
  of `any`, `ipv4` and `ipv6` does not (nfdump keeps every distinct key in memory). Every nfdump
  process runs under a 4 GiB address-space limit; a run that hits it (exit 255, SIGABRT or an
  allocation error) returns `error_type: tool_failed` with a suggestion to narrow the window or
  filter. All nfdump processes share two slots per server; a call that waits too long for a slot
  returns `error_type: timeout` and can be retried.
- **Damaged files**: nfdump 1.7 reports a truncated or block-corrupt file on stderr but still exits
  0 after stopping or skipping part of its walk. Any message on stderr therefore fails the call
  (`error_type: tool_failed`, the message quoted, nothing indexed) instead of returning an
  undercount; point `evidence_path` at the intact files or a single file and retry. The
  inventory section excludes a file whose `nfdump -I` reports an error and reads the rest.
- **Time**: each call's timeout scales with the number of files read (120 s + 30 s per file,
  capped at 30 min).

## Source names and citation

Each call indexes its rows under a deterministic source name:

| Source | Written by |
|---|---|
| `netflow.analysis.<id>` | `run_netflow_analysis` (the summary of one call) |
| `netflow.inventory.<id>` (+ `netflow.inventory.<id>.manifest`) | `run_netflow_analysis` (inventory section) |
| `netflow.top.<id>` | `run_netflow_top`, or a ranked section of `run_netflow_analysis` |
| `netflow.profile.<id>` | `run_netflow_host_profile`, or a profile section of `run_netflow_analysis` |
| `netflow.sweep.<id>` | `run_netflow_sweep`, or the sweep section of `run_netflow_analysis` |
| `netflow.pair.<id>` | `run_netflow_pair_timeline` |
| `netflow.query.<id>` | `run_netflow_query` |

`<id>` is a 16-hex-digit digest of the tool, the resolved `evidence_path` and the effective
parameters after normalisation: the window as parsed (to the second, `T` form) and the filter
with keywords lower-cased and whitespace collapsed (addresses, numbers and flag letters are kept
as written, and nfdump receives the filter as given). `params_effective` echoes the normalised
values. Repeating an identical call returns `status: skipped` with the existing source, also when
identical calls run concurrently (one runs, the others wait and answer `skipped`); with
`force=True` the call runs again and registers `<name>-r1`, `<name>-r2`, ... (the header row says
which name it supersedes). A call that matches nothing registers an empty source
(`status: indexed_empty`) so it is on record.

- Line 1 of every non-empty source is a header row (no event time) that names the tool, the
  originating `tool_call_id`, the files read and every effective parameter:
  `get_raw_output('<name>', limit=1)` recovers the provenance of any `netflow.*` source.
- Every other row is one line, `<event_time> netflow <kind> key=value ...`, with its own UTC
  `event_time` (to the second), so `search` with `t_start`/`t_end` and `get_timeline` work on
  NetFlow rows, and phrase searches such as `search(query='"dport=445"', source='netflow')` hit
  exactly the rows that carry the value. Flow and pair rows use the record's first-seen time,
  sweep rows the start of the burst, and ranked rows (top, profile, inventory) the earliest
  first-seen among the flows that overlap the scanned window, which can lie before the window.
  To list everything one call produced, search by its source name without a time range.
- `search(source='netflow')` spans every NetFlow source of the case; `source='netflow.sweep'`
  spans every sweep call and its re-runs.
- Each response carries a `hint` naming the source, the `tool_call_id` and ready-made
  `search`/`get_timeline` calls for its rows.

## Limitations

- `flows=`, `packets=` and `bytes=` sum every exporter record, aggregated rows included: an
  exporter can emit one flow more than once (for example once per interface, sometimes with
  different counters), and aggregation does not remove the copies. Treat them as record counts
  and upper bounds, not connection counts. `run_netflow_pair_timeline` removes exact duplicates
  (`records=`) and also collapses re-exports of one flow (`records_distinct=`,
  `bytes_distinct=`, `near_copies_collapsed=`).
- `stat=ip` / `stat=port` (and the inventory section's talker rows) count each flow once per endpoint, so
  their shares add up to more than 100 %; use `srcip`/`dstip` for shares that add up.
- Raw queries ordered by start/end/duration read the first `limit` matches in *file* order and sort
  those; `truncated=true` means the window or filter should be narrowed (or the query aggregated).
- IPv6 records are parsed (nfdump runs with `-6` so addresses are never abbreviated), but IPv6
  has not been exercised end to end.
- Every distinct parameter set is its own source, so exploratory calls add sources to the case.
- Flow timestamps are evidence data: a record whose first or last seen lies outside
  1970-01-01 .. 2100-01-01 UTC is dropped, counted in `rows_dropped` and named in `warnings`, as
  is a statistics row whose time is not a valid UTC time in that range.
