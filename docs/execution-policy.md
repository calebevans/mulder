# Command execution policy

Mulder's command boundary is `CommandRunner.run(CommandRequest)`. A request is
an argv-only declaration of the executable and arguments plus its filesystem,
environment, network, time, memory, CPU, and output capabilities. Shell command
strings are not part of the interface.

`CommandPolicy` resolves the executable and requires an exact match with a
pinned path. It also resolves every declared working, input, and output path
through the shared component-aware path policy. Environment overrides are
allowlisted; loader and runtime injection variables are always rejected and
removed from inherited child environments. Network use is denied unless its
class is explicitly allowed. Decisions use stable reason codes.

The runner uses the paths returned by the decision, starts a separate process
group, enforces timeout and combined-output caps, applies requested POSIX CPU
and memory bounds, and emits a content-minimal audit event. The event commits
the complete request through a SHA-256 digest without copying arguments or
environment values into the log. Output content is likewise represented by a
full digest. Receipts also record the network enforcement result and backend,
so a caller can distinguish a policy declaration from OS enforcement.

## No-network backend

`NetworkClass.NONE` is enforced below the caller declaration. On Linux,
`BubblewrapNetworkIsolationBackend` resolves `bwrap`, proves that it can create
a network namespace distinct from the parent, and only then launches the
command with `--unshare-net`. Finding the executable is not considered proof.
If the probe fails, the host prohibits user/network namespaces, `bwrap` is
missing, or the platform is not Linux, the command is denied with
`network_isolation_unavailable`; it is never launched without isolation.

Native Linux installations that run forensic commands therefore require the
`bubblewrap` package and a host configuration that permits unprivileged
bubblewrap namespaces. The project container installs it. macOS and Windows
remain fail-closed until an equally verifiable backend is provided. This
backend deliberately preserves the existing filesystem view; it asserts only
network isolation, while path allowlists and OS file permissions remain the
filesystem controls.

The initial migration covers the shared `run_cli_tool` path used by strings,
hashdeep, exiftool, ssdeep, and pasco. Legacy direct-process modules are listed
as documented exceptions in `tests/test_execution_policy.py`; the test rejects
direct process calls in any new source module. Later migrations should remove
modules from that set. The long-lived model proxy and installation helper are
separate lifecycle categories and should not be mechanically forced through a
short-lived forensic-command API.

Policy denial is enforcement, not evidence. A denied, timed-out, or capped
command must map to an unavailable/failed/partial tool outcome and can never be
interpreted as a successful empty result. The injected backend Interface keeps
availability and launch behavior deterministic in unit tests; production uses
the verified bubblewrap adapter.
