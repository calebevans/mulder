# Domain packs

Domain packs are versioned, inert declarations that add a complete forensic
workflow to Mulder. A pack connects evidence classification, existing MCP
tools, hunts, completion gates, benchmark fixtures, and replay commitments
through one registry Interface. Mulder does not search for, import, or execute
code named by a pack manifest.

The core distribution includes four explicitly registered specialist packs:
`anti-forensics.clock`, `windows.evtx`, `kubernetes.security`, and
`cloud.aws-cloudtrail`. The contract remains the stable Seam on which further
reviewed packs can be built.

## Contract

`DomainPackManifest` is strict: unknown fields, duplicate IDs, and references
to undeclared tools, parsers, capabilities, hunts, gates, or fixtures are
errors. Its `schema_version` describes the JSON shape; `support_version`
describes the runtime activation contract. Each pack also declares the Mulder
and core-contract versions it supports.

A complete manifest contains:

- classifier rules based only on file/directory paths;
- bindings to short names in Mulder's existing tool-access registry, including
  each planner/executor/analyst role that may use the tool;
- exact supported parser versions;
- required capability IDs and each hunt's subset of those capabilities;
- planner, executor, and analyst hunt instructions;
- gates that require declared tool attempts;
- content-addressed local fixtures and typed benchmark expectations; and
- receipt/replay behavior that commits the pack, fixture, parser, and tool
  identities.

The canonical manifest digest is SHA-256 over sorted, compact UTF-8 JSON.
Registration order does not affect an activation receipt.

## Trusted registration and preflight

Trusted application code constructs and registers manifests explicitly:

```python
from pathlib import Path

from mulder.packs import DomainPackRegistry, PackRuntimeInventory

registry = DomainPackRegistry()
registry.register(my_reviewed_manifest)
result = registry.enable(
    ["windows.specialist"],
    PackRuntimeInventory(
        available_capabilities=("forensic.local-read",),
        parser_versions={"evtx-parser": "1.2"},
        fixture_root=Path("tests/fixtures/packs"),
    ),
)
if not result.ready:
    raise RuntimeError(result.outcome.reason)
activation = result.activation
assert activation is not None
```

Call preflight only after the normal Mulder tool modules have registered their
decorated tools. A binding cannot expand tool permissions: every declared pack
role must already be granted by the tool-access registry.

Preflight is atomic. No workflow activates if any requested pack fails:

| Condition | Typed outcome |
|---|---|
| Unknown pack support, Mulder/core schema, missing parser version, or parser drift | `UNSUPPORTED_VERSION` |
| Missing tool, tool role, capability, fixture root, or fixture | `UNAVAILABLE` |
| Fixture is unsafe, unreadable, or differs from its declared bytes | `FAILED` |
| All declarations resolve and every fixture verifies | `SUCCESS_NONEMPTY` |

An unsupported parser can therefore never be mistaken for successful-empty or
clean evidence.

## Activation views

A successful `DomainPackActivation` exposes three coordinated views:

1. `classifier_rules` can be passed to
   `ClassifierConfig(pack_rules=activation.classifier_rules)`.
2. `workflow_steps` contains complete `PhaseConfig` values and declarative
   gates. Passing the activation to `Orchestrator(pack_activation=activation)`
   inserts every hunt after extraction without editing the central phase list.
3. `receipt` is an `ActivationManifest`. Write it as
   `<case-id>.packs.json`; case sealing treats that suffix as a standard
   artifact and commits its bytes.

Pack gates attest that declared tools were attempted. They do not claim that a
tool result is malicious, benign, or complete. The typed tool outcome and
benchmark expectation remain the source of those semantics.

## Safety and extension limits

- There is intentionally no filesystem discovery, entry-point loading,
  `importlib`, manifest-specified callable, subprocess, or network behavior.
- Classifiers use path metadata only; they do not parse evidence.
- Exact version lists are intentionally conservative. Supporting a new parser
  schema requires a reviewed manifest change and fixture benchmark.
- Capability IDs are supplied by the embedding runtime. A pack can require a
  capability but cannot grant one.
- Specialist content and signed third-party distribution belong to later work;
  neither is implemented by this contract.
- The current CLI/MCP subprocess configuration has no pack-selection option.
  Callers embedding Mulder must pass the preflighted activation to the
  classifier and orchestrator Interfaces themselves.

The public Interface is exported from `mulder.packs`; implementation details
remain local to `mulder.packs.base`.

## Built-in anti-forensics and clock pack

Built-ins are trusted static declarations, but they are not silently enabled.
Register and preflight the shipped pack through the same registry Interface:

```python
from mulder.packs import (
    DomainPackRegistry,
    PackRuntimeInventory,
    anti_forensics_fixture_root,
    register_builtin_packs,
)

registry = DomainPackRegistry()
register_builtin_packs(registry)
result = registry.enable(
    ["anti-forensics.clock"],
    PackRuntimeInventory(
        available_capabilities=("forensic.local-read",),
        parser_versions={
            "anti-forensics-clock": "1.0",
            "mftecmd-si-fn": "1.0",
        },
        fixture_root=anti_forensics_fixture_root(),
    ),
)
```

The pack retains the existing MFTECmd SI/FN detector and adds a strict
`mulder.anti-forensics-clock` normalized-evidence Interface. Its workflow
correlates:

- `$STANDARD_INFORMATION` and `$FILE_NAME` creation times;
- USN sequence/time order and file-change witnesses;
- normalized `$LogFile` sequence observations when supplied by a supported
  Adapter;
- Windows event 104/1102 log clears;
- normalized running/deleted/image-path mismatches;
- VSS snapshots and normalized per-file historical witnesses; and
- source-clock anchors, offset, drift, and uncertainty.

Every time keeps its original representation beside normalized UTC, its
normalization rule/version, declared uncertainty, and source selector/digest.
A SI/FN backdate is only `confirmed` with a witness whose provenance has a
different independence key. The sole no-witness exception is the versioned
`ntfs-si-after-modified` rule at version `1.0`; other SI/FN differences remain
`indicated`.

The indexed-evidence Adapter supports the MFTECmd MFT/USN CSV and Mulder's
python-evtx line formats. It inventories VSS creation times but cannot produce
per-file VSS witnesses. Mulder does not currently include a raw `$LogFile`
parser or a process/file-state normalizer. Those cells are reported as
`UNSUPPORTED_VERSION`; absent MFT, USN, event-log, or VSS sources are
`UNAVAILABLE`. Either state makes the aggregate result `PARTIAL`, never a
clean result. Evidence-envelope flags are preserved as handling metadata and
cannot create a finding.

## EVTX, Kubernetes, and CloudTrail pilots

The three pilot packs share a small typed result Interface while retaining
domain-specific analyzers. Every observation, relationship, and finding
contains a proof with:

- evidence-relative source identity;
- an exact record selector and the exact field selectors used;
- original-source, decoded-content, and canonical-record SHA-256 digests;
- decoded encoding plus evidence-envelope handling/sensitivity flags; and
- for findings, the version and canonical declaration hash of the matching
  rule.

Rule hashes and an aggregate ruleset hash make the deterministic rule inputs
receipt-friendly. A match proves the structured action or configuration named
by that rule; it does not by itself prove malicious intent. Missing families
produce `UNAVAILABLE`, incompatible fields or versions produce
`UNSUPPORTED_VERSION`, and mixed valid/incompatible inputs produce `PARTIAL`.

### Windows EVTX

`windows.evtx` retains the existing extraction/index tools and adds
`analyze_evtx_pack`. The local Adapter understands Mulder's python-evtx line
format and EvtxECmd-style CSV, including a UTF-8 BOM and declared header
aliases. It requires coverage for Security, System, PowerShell, and Sysmon and
uses fixed structural rules for log clear, encoded PowerShell, and service
installation records. It does not expose the existing arbitrary Chainsaw
search mode as part of the pack.

### Kubernetes

`kubernetes.security` reads JSON, JSON-lines, and YAML beneath the active
evidence root. It supports the stable `audit.k8s.io/v1` event shape plus core
events, workload pod specs, the four stable RBAC kinds, container-image
references, and `networking.k8s.io/v1` NetworkPolicy egress. It emits explicit
principal/action, binding, workload/image, and egress-destination
relationships. The interpretations follow the Kubernetes documentation for
[audit events](https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/),
[RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/),
[images](https://kubernetes.io/docs/concepts/containers/images/), and
[NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/).

The Adapter does not contact a cluster, execute `kubectl`, resolve image tags,
or infer runtime state absent from the supplied artifacts.

### AWS CloudTrail

`cloud.aws-cloudtrail` is the first cloud pilot. It parses only local JSON (or
JSON-gzip) log files with the documented top-level `Records` array and
CloudTrail event major version 1. AWS documents this as the delivered log
format and recommends matching the major version while accepting additive
minor versions: [CloudTrail record contents](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)
and [log file examples](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html).

The fixed offline rules cover trail-integrity actions, privileged IAM policy
changes, successful root console login without MFA, and globally open security
group ingress. Relationships retain principal, service/action, source address,
and resource ARN. There are no AWS SDK calls, credential loading, enrichment,
fallbacks, or generic query parameters.

All three MCP tools take no parameters. Local evidence collection is capped at
256 candidate files and 16 MiB per decoded document; exceeding a limit becomes
typed incomplete/unsupported coverage instead of silent sampling.
