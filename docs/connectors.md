# Reviewed import and export connectors

Mulder's connector layer has two small public operations:

- `ImmutableImporter.import_snapshot(request)` reads a policy-scoped source and
  writes a separate, content-addressed intake bundle.
- `ApprovedExporter.export(request)` projects and delivers a policy-scoped
  artifact from an exact, signed, approved case manifest.

Both policies default to disabled. Import and export credentials are distinct
types and bind one connector, source or destination ID, and exact HTTPS origin.
Tokens are passed only in transport headers and never appear in manifests or
receipts. HTTP redirects are disabled.

## Import boundary

Filesystem imports accept only absolute paths within configured roots, reject
symlinks and special files, detect changes during reads, and retain the caller's
original locator plus its resolved locator. Directory snapshots use a sorted ZIP
with fixed metadata. Remote requests accept a dataset, time window, limit, and
field/operator/value terms; callers cannot provide an arbitrary URL or vendor
query string.

Every acquisition writes only:

```text
<intake-root>/<manifest-sha256>/
  manifest.json
  payload.bin
```

The exact source bytes and their SHA-256 digest are retained. The manifest also
binds source/query provenance, response metadata, credential ID (not the
secret), and per-file digests for directory snapshots. Files and bundle
directories have write bits removed. `verify_import_bundle()` rechecks both the
content commitments and those immutable permissions. Connector intake does not
modify a case database or evidence registry; reviewed ingestion remains a
separate workflow.

## Export boundary

Remote export additionally requires all of the following:

1. A `mulder.case-manifest` whose exact raw-file SHA-256 matches the request.
2. Successful offline case verification and a valid Ed25519 signature.
3. A signer fingerprint explicitly trusted by the destination policy.
4. The canonical PR 5.3 `review_approval` block in the manifest, with an approve
   decision binding one claim-set digest and the sealed audit head.
5. A destination scope allowing the connector, case (when restricted), artifact
   type, origin, and record limit.

Authorization is repeated after building the read-only case-review projection
and immediately before delivery. Evidence, claims, or audit mutation therefore
invalidates the sealed case instead of being exported under stale approval.
TheHive exposes only alert/case creation endpoints; the generic SIEM adapter
exposes only IOC/case ingestion endpoints. There is no arbitrary request path,
live containment operation, shell command, or evidence mutation interface.

The production transport mappings are intentionally narrow pilot contracts.
Specific TheHive, SIEM, Wazuh, syslog-gateway, and cloud deployments may require
a reviewed adapter for their exact API version and authentication scheme. The
transport protocols support deterministic test doubles without network access.

PR 5.3 is integrated in the roadmap build, so ordinary approved sealing emits
the canonical `review_approval` block consumed here. Cases without that exact
state-bound approval still fail closed; connectors recognize the shared review
record and never create a second approval store.
