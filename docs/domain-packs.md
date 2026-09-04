# Domain packs

Domain packs are versioned, inert declarations that add a complete forensic
workflow to Mulder. A pack connects evidence classification, existing MCP
tools, hunts, completion gates, benchmark fixtures, and replay commitments
through one registry Interface. Mulder does not search for, import, or execute
code named by a pack manifest.

There are no specialist packs in the core distribution yet. The contract is
the stable Seam on which those packs can be built.

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
