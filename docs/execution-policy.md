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
full digest.

The initial migration covers the shared `run_cli_tool` path used by strings,
hashdeep, exiftool, ssdeep, and pasco. Legacy direct-process modules are listed
as documented exceptions in `tests/test_execution_policy.py`; the test rejects
direct process calls in any new source module. Later migrations should remove
modules from that set. The long-lived model proxy and installation helper are
separate lifecycle categories and should not be mechanically forced through a
short-lived forensic-command API.

Policy denial is enforcement, not evidence. A denied, timed-out, or capped
command must map to an unavailable/failed/partial tool outcome and can never be
interpreted as a successful empty result. Network declarations are a fail-
closed policy decision point; kernel or container isolation can enforce an
allowed network class more narrowly in deployment, but cannot widen it.
