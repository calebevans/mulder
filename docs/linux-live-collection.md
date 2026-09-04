# Linux live-state collection

Mulder exposes one explicit `collect_linux_live_state_bundle` MCP tool for local
Linux acquisition. It is not called during normal evidence scanning and is not
an SSH or general command runner. A loaded case, the exact current hostname, a
safe bundle name, and one or more built-in check IDs are required.

The supported checks are `journal_auth`, `systemd`, `cron_at`,
`packages_repos`, `shell_history`, `process_network_modules`,
`web_roots_logs`, and `container_kubernetes`. Each maps to a reviewed fixed set
of logical paths. The tool has no input/output path, program, command, shell,
remote-host, or network parameter. It reads the local `/` scope and writes only
to `<db-dir>/live-bundles/<bundle-name>.mlive`.

Each `.mlive` file is a deterministic ZIP containing raw source members,
per-check JSON inventories, and a canonical manifest. The manifest binds:

- the local host, logical root, selected checks, and every declared path;
- the filesystem/procfs methods and explicit absence of command, network, and
  remote access;
- collector, Mulder, and parser versions;
- collection limits and each member's SHA-256 and exact captured size; and
- `success`, `empty`, `partial`, or `failed` coverage for every selected check.

Truncated files and denied or escaping paths are `partial`, not clean. A check
with no readable evidence and acquisition errors is `failed`. The MCP adapter
persists those states in the case coverage register, so downstream negative
conclusions remain limited to what was actually acquired.

Verify a bundle without MCP, a model, network access, or forensic binaries:

```bash
mulder verify-linux-live /path/to/host-snapshot.mlive
mulder verify-linux-live /path/to/host-snapshot.mlive --json
```

The content seal detects changed, missing, or uncommitted members and canonical
manifest changes. It is an integrity commitment, not an examiner signature or
identity assertion.

`linux_live_pack_descriptor()` supplies inert, deterministic pack metadata for
the domain-pack registry integration line: classifier, tool/parser binding,
capability, one hunt and coverage gate per check, and replay commitments. It
does not discover or execute plug-in code.
