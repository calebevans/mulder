# Verified-claim graph projection

Mulder’s entity graph is a deterministic SQLite projection, not a second truth
store. Its source is the current set of atomic claims whose latest persisted
verification result and current epistemic state are both `verified`. A rebuild
also reopens every stored anchor against its source/window identity and exact
character span. A claim with missing, changed, or support-free anchors produces
no active edge.

The public interface is deliberately small:

```python
build = case_db.rebuild_entity_graph()
snapshot = case_db.get_entity_graph()
proof = case_db.get_graph_edge_provenance(snapshot.relations[0].edge_id)
```

Callers cannot submit SQL, Cypher, table names, predicates, or query fragments.
Bounded pivot operations belong in a later module; PR 6.1 exposes only a typed
snapshot and one exact provenance traversal.

## Projection convention

Every verified atomic claim projects one directed relation from its `subject`
to its `object_value`. A subject written as `type:value` produces that entity
type; otherwise its type is `value`. Target types are inferred for the existing
typed predicates (`image_name`, `ip_equals`, `domain_equals`, `hash_equals`,
`path_equals`, and `timestamp_equals`), then from a `type:value` string, with
`value` as the conservative fallback.

The following optional scalar claim qualifiers refine graph presentation. They
do not alter claim verification:

- `subject_host` and `object_host` scope identities that can recur on hosts;
- `object_type` explicitly types a target when the predicate cannot;
- `subject_alias` and `object_alias` add one display alias per endpoint;
- `event_time` supplies an event timestamp for the relation.

Primary display values are aliases too. Aliases are normalized for lookup but
are never globally unique: a collision is reported in `alias_collisions` and
does not merge entities. Entity IDs include case, type, scalar kind, normalized
value, and host scope, preventing PID/user/path reuse on different hosts from
collapsing silently.

If `event_time` is absent, timestamps on supporting anchor windows become
events. Offset-aware ISO-8601 values retain their original string and normalize
to UTC with the observed offset. Naive and unparseable strings remain explicit
and receive no invented UTC value.

## Identity, history, and evidence

Projection, entity, alias, relation, and event IDs are SHA-256-derived from
canonical semantic inputs. Rebuilding unchanged inputs repairs rows without
creating a new projection. A changed verified claim set creates a new active
projection and marks removed rows and the prior projection as `superseded`;
historical rows remain available only via `include_superseded=True`.

Each relation stores the derivation rule/version, claim ID, exact verification
ID, and supporting anchor IDs. `get_graph_edge_provenance` resolves those IDs to
the verified claim, verifier result/reason/version, immutable exact text,
window text and coordinates, and source path/hash/extractor. The projection
does not infer actor identity, semantic equivalence, clock correctness, or an
alias merge beyond these deterministic conventions.
