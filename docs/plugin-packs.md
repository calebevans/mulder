# Declarative plugin packs and release provenance

Mulder does not search the filesystem for plugins. With no approved location,
`mulder plugins discover --json` returns an empty versioned catalog and changes
nothing. An examiner opts in by naming an exact `--manifest` or a `--root` whose
direct children contain `mulder-plugin.json`.

## Version 1 trust boundary

A version 1 pack is data, not code. Its strict JSON manifest declares:

- a stable plugin ID, display name, version, and license;
- symbolic tool, path, write, and network capabilities;
- exact supported versions and SHA-256 digests for every required Mulder tool,
  parser, and external binary;
- every static resource, including its media type and SHA-256.

Discovery validates the entire pack tree before activation. It rejects paths
that escape the pack, symlinks, undeclared files, executable permission bits,
Python/native/WebAssembly/shell resources, package metadata and dynamic entry
points. Capabilities are compared with a separate examiner-provided ceiling;
manifest text can never turn symbolic scopes into raw paths or widen that
ceiling. This release intentionally has no plugin import hook.

Compatibility is also declarative and offline. The examiner supplies an
inventory such as:

```json
{
  "components": [
    {
      "kind": "parser",
      "name": "evtx",
      "version": "0.8.1",
      "digest": "sha256:..."
    }
  ]
}
```

A missing component, unlisted version, or digest drift makes the catalog entry
`UNSUPPORTED_VERSION`; activation then fails loudly. Discovery never invokes a
tool, imports a pack, downloads a component, or queries a registry.

```bash
mulder plugins discover \
  --root /examiner/approved-packs \
  --approval capability-approval.json \
  --inventory component-inventory.json \
  --json

mulder plugins activate CASE-001 \
  --db-dir ./cases \
  --plugin example.evtx-hunt \
  --manifest /examiner/approved-packs/evtx/mulder-plugin.json \
  --approval capability-approval.json \
  --inventory component-inventory.json
```

Activation stores immutable, case-local identity, license, capability,
component, manifest-digest and pack-digest records. `seal-case` binds them into
both the logical database commitment and visible receipt methodology. Replay
contracts separately bind tool/parser/binary versions, component digests, and
plugin digests. Replay comparison remains offline and reports drift; it does
not reinstall anything.

## Release SBOM and build provenance

`release-metadata generate` reads the committed `uv.lock` plus explicitly named
wheel/sdist artifacts. An explicit source-date epoch makes its SBOM and SLSA
provenance-shaped document byte deterministic. It performs no network calls.

```bash
mulder release-metadata generate \
  --project-root . \
  --artifact-dir dist \
  --source-revision "$(git rev-parse HEAD)" \
  --source-date-epoch "$(git log -1 --format=%ct)" \
  --builder-id https://github.com/example/mulder/actions/release

mulder release-metadata verify dist/release-supply-chain.json \
  --release-root .
```

Verification checks the canonical document digest, embedded SBOM digest,
dependency-lock commitment, and each local distribution digest without a
registry or transparency service. The document is provenance metadata, not an
examiner signature or a remote attestation; release signing remains a separate
deployment concern.
