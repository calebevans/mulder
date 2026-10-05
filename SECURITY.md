# Security Policy

## Supported versions

Security fixes are made on `main` and ship in the next release. Only the latest
release is supported; please reproduce on it (or on `main`) before reporting.

## Reporting a vulnerability

Please **do not** open a public issue, pull request or discussion for a
security problem.

Report it privately through GitHub instead:
**[Report a vulnerability](https://github.com/calebevans/mulder/security/advisories/new)**
(Security tab → *Report a vulnerability*).

A useful report includes:

- the Mulder version or commit, and how it was run (Docker image, `install.sh`,
  local `uv` install) and with which model provider;
- the affected component (for example a tool wrapper, the MCP server, the audit
  log, case handling or report generation);
- steps to reproduce, ideally with a minimal evidence file or directory;
- the impact you expect, and a suggested fix if you have one.

You will get a reply in the advisory thread. Please keep the details private
until a fix is released and the advisory is published.

## Scope

Mulder processes evidence that is attacker-controlled by design, so the
following are in scope:

- crafted evidence (disk images, memory dumps, PCAPs, logs, archives) that
  writes, reads or executes outside the case directory, runs commands, or
  crashes or hangs an investigation;
- content in evidence that bypasses a security boundary, for example forging
  or altering audit-log entries or evidence citations, or making a role or
  tool act outside its permissions;
- injection into generated reports (HTML, IOC exports) or into tool command
  lines;
- leaks of credentials or evidence content to places they should not go.

Out of scope:

- vulnerabilities in third-party forensic tools themselves (please report those
  upstream; issues in how Mulder invokes or isolates them are in scope);
- wrong or missed findings that do not cross a security boundary - please open
  a regular issue for those.
