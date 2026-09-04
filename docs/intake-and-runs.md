# Immutable intake and restart-safe runs

Mulder can bind a case to a KAPE or Velociraptor export before analysis and
resume successful orchestration phases without trusting mutable process state.
The intake manifest, run ledger, and audit log are separate boundaries:

- `<case>.intake.json` commits every logical member, size, SHA-256 digest,
  artifact class, collector metadata source, and examiner assertion source.
- `<case>.runs.db` stores stable run handles, append-only operational events,
  abandoned attempts, cancellation requests, and successful checkpoints.
- `<case>.audit.jsonl` remains the authoritative tamper-evident activity chain.
  Each reusable checkpoint has an exact phase/input/result envelope in that
  chain; changing the SQLite result or its identity invalidates resume.
- `<case>.<run-id>.run.json` is the reportable per-run projection.
  `<case>.report-run.json` binds generated report bytes to one such run;
  `<case>.run.json` is only the latest-run status convenience view.

## Intake

```bash
mulder intake-collection /exports/host01 case-42 --format auto
mulder intake-collection /exports/F.CAFE.zip case-43 --format velociraptor
```

Directories are opened descriptor-relative without following symbolic links.
ZIP validation and provenance use one stable container snapshot and reject
absolute/traversing/backslash paths, links, encryption, duplicates,
case-folding collisions, oversized members, and unsafe compression ratios.
The reviewed materializer has fixed 512 MiB/member and 8 GiB/collection caps,
never invokes `7z`, and writes a read-only view. Re-importing identical evidence
content is idempotent even if an examiner corrects a separate assertion.
Different content cannot replace an existing case intake; use a new case ID.

Collector-derived metadata remains distinguishable from examiner assertions.
The manifest proves the bytes and recorded statements, not the identity of the
collector or examiner; use the case-sealing signature layer for examiner
identity.

## Profiles, forecasts, and handles

```bash
mulder forecast-run /evidence --profile quick \
  --db-dir ~/.mulder/cases --cwd ~/.mulder/workspace
mulder investigate /evidence case-42 --profile quick
mulder run-status case-42 run-0123
mulder investigate /evidence case-42 --resume-run run-0123
mulder cancel-run case-42 run-0123 --requested-by examiner@example.org
mulder investigate /evidence case-42 --resume-run run-0123 --resume-after-approval
```

`quick` reduces every model-role budget to 35% and has a permanent `sampled`
coverage ceiling. Its Markdown and HTML reports carry an explicit
“SAMPLED TRIAGE — NOT FULL COVERAGE” warning. `full` runs the configured
workflow at normal budgets, but still cannot claim full coverage without
affirmative coverage-register records.

The health forecast is a conservative size heuristic for disk, memory, and a
time range. Archive estimates use expanded member sizes. Both `forecast-run`
and the investigate gate check the planned output database and workspace
volumes rather than assuming the evidence volume is writable. A missing output
directory is measured on its nearest existing directory ancestor without being
created and is disclosed as a warning. Unknown memory or unreadable evidence
fails the readiness decision. It is not a performance guarantee or completion
evidence. `--require-healthy` makes a negative forecast a start gate.

Cancellation is cooperative: it is persisted immediately and enforced before
the next phase/checkpoint boundary. Mulder does not kill a tool midway through
an evidence read. A process interruption leaves its current attempt marked
`running`; the next exact resume marks it `interrupted` and starts a new
attempt, while already successful exact-input checkpoints are reused. Every MCP
tool body, including queued background work, holds a shared generation lease.
Resuming takes an exclusive lease before incrementing the generation, so it
fails while an old process has an in-flight tool and superseded processes cannot
start another tool, phase, or checkpoint. Background batches must all return an
exact, terminal result set before analysis can create a successful checkpoint.

## Trust limits

- A raw path inventory is a change detector based on path, size, and mtime; it
  is not a content commitment. A verified intake digest is preferred whenever
  one exists.
- Checkpoint reuse proves consistency with the audit chain currently present.
  External retention or a signed case receipt is still needed to detect suffix
  truncation of an otherwise valid unsealed audit file.
- Checkpoint writes span SQLite and the append-only JSONL chain, so a crash can
  leave an audit record marked `proposed`. It is deliberately not a completion
  claim. A phase is complete only when a committed SQLite row cites that exact
  proposal hash and all typed identity/result fields validate; receipts seal
  both parts of that conjunction.
- KAPE and Velociraptor formats evolve. Unknown or ambiguous exports must be
  selected explicitly and remain bounded by the same path and byte policies.
