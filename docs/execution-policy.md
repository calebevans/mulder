# Command execution policy

Mulder's command boundary is `CommandRunner.run(CommandRequest)`. A request is
an argv-only declaration of the executable and arguments plus its filesystem,
environment, network, time, memory, CPU, and output capabilities. Shell command
strings are not part of the interface.

`CommandPolicy` resolves the executable and requires an exact match with a
pinned path. It records device, inode, mode, size, mtime, and ctime identities
for the executable and approved roots. The runner opens and holds descriptors
for the executable, working directory, typed inputs, output parents, and roots;
component walks refuse symlinks. Linux payload paths are launched through
`/proc/self/fd` bindings, so a rename or symlink swap between policy evaluation
and process creation cannot redirect the child. Mutable executables are copied
to a private, unlinked snapshot before isolation preparation. New outputs are
staged through a descriptor in their held parent and atomically committed only
after a successful launch.

Environment overrides are copied into an immutable mapping at request
construction. The exact child environment is then snapshotted before policy
evaluation, stripped of loader/runtime injection variables, and committed by
SHA-256 in both the policy decision and execution receipt. Network use is
denied unless its class is explicitly allowed. Decisions use stable reason
codes.

The runner uses the paths returned by the decision, starts a separate process
group, enforces timeout and combined-output caps, applies requested POSIX CPU
and memory bounds, and emits a content-minimal audit event. The event commits
the complete request through a SHA-256 digest without copying arguments or
environment values into the log. Output content is likewise represented by a
full digest. Receipts also record the network enforcement result and backend,
so a caller can distinguish a policy declaration from OS enforcement.

## No-network backend

`NetworkClass.NONE` is enforced below the caller declaration. On Linux,
`BubblewrapNetworkIsolationBackend` pins `/usr/bin/bwrap` (or an explicitly
configured absolute path), requires a root-owned executable and root-controlled
path, and records its full SHA-256/metadata identity. The parent process then
inspects the probe process tree through `/proc` and proves that the actual
payload process occupies a network namespace distinct from its own before
launching the command with `--unshare-net`.
Neither `PATH` resolution nor wrapper-controlled stdout is considered proof;
replacement of the attested executable invalidates the cached verification.
If the probe fails, the host prohibits user/network namespaces, `bwrap` is
missing, or the platform is not Linux, the command is denied with
`network_isolation_unavailable`; it is never launched without isolation.

Native Linux installations that run forensic commands therefore require the
`bubblewrap` package and a host configuration that permits unprivileged
bubblewrap namespaces. The project container installs it. macOS and Windows
remain fail-closed until an equally verifiable backend is provided. This
backend creates read-only/read-write bind mounts from the held descriptors to
private `/run/mulder-bound/*` paths in the child namespace. Filesystem
authorization therefore follows the object approved by policy, not a later
lookup of the caller's original path.

## Privileged mount protocol

The privileged helper is launched through an attested `unshare --net` backend,
which isolates networking without creating a private mount namespace whose
mounts would vanish at helper exit. It accepts only exact
`/proc/self/fd/<number>` source and target references held by the unprivileged
broker. Each request includes a
fresh nonce and canonical request digest. The helper returns the complete
canonical request with that exact digest; the broker rejects truncated,
replayed, or mismatched responses. After mounting, the broker independently
checks `/proc/self/mountinfo` for the exact target, source/loop backing, and
`ro,nodev,nosuid,noexec` flags. Unmount success likewise requires the target
and any E01 intermediate mount to disappear. A failed or ambiguous mount result
triggers rollback; an unverified unmount preserves the mountpoint for safe
operator recovery rather than recursively deleting it.

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
