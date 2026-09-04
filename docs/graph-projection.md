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

from mulder.graph_query import NeighborsQuery

view = case_db.query_entity_graph(
    NeighborsQuery(entity_id=snapshot.entities[0].entity_id, depth=2, limit=50)
)
```

Callers cannot submit SQL, Cypher, table names, predicates, or query fragments.
The query implementation refreshes the deterministic projection before reading,
so withdrawn or newly contradicted claims cannot remain active in a review view.

## Bounded queries and review views

`query_entity_graph` accepts exactly four discriminated request models:

- `NeighborsQuery` walks incoming, outgoing, or both edge directions up to depth
  4 and returns at most 100 relations;
- `PathBetweenQuery` finds one deterministic shortest directed or undirected path
  up to depth 8;
- `EventsForEntityQuery` returns at most 100 chronologically ordered events for
  an exact entity ID;
- `HostTimelineQuery` returns at most 100 chronologically ordered events whose
  relation endpoint is scoped to, or itself identifies, the normalized host.

All traversals also have a non-configurable 1,000-edge expansion ceiling. The
result records its requested output/depth bounds, actual expansions, and whether
a bound truncated the answer. These limits are validated at the database seam,
not left to an MCP client or model.

Every returned edge and event carries a selector with the claim ID, the exact
verification used by the projection, the claim's current epistemic state, and
supporting anchor/window/source path/hash coordinates. Every returned node
carries the selectors from its incident returned edges. Entity IDs include the
case ID and every SQL statement is case-filtered, preventing a selector copied
from another case from producing results.

Active verified edges are the default. `include_superseded=True` opts into
historical edges whose claim was withdrawn or otherwise ceased to project;
`include_refuted=True` separately opts into historical edges whose claim is now
`contradicted`. Query results label these `verified`, `superseded`, or `refuted`.
The static dependency-free SVG and Markdown renderer uses the same typed query
result and renders superseded/refuted edges with distinct labels and line styles.
MCP tools return both the machine-readable result and this static review view.
The report renderer can accept the same results through its optional
`graph_results` argument.

The four MCP tools—`neighbors`, `path_between`, `events_for_entity`, and
`host_timeline`—are available only to cross-analysis, narrative-analysis, and
report roles. They accept scalar typed parameters rather than query-language
text.

The read-only case-review projection and loopback console reuse the same
`GraphQueryResult` type for a deterministic depth-one neighborhood (or an
examiner-selected entity through the bounded GET route). Unlike the authorized
`CaseDB.query_entity_graph` seam, review never rebuilds or writes the graph. It
first derives the current verified-claim input digest inside the immutable case
snapshot and compares it with the active persisted projection. Missing and stale
projections are reported as `not_built` or `stale`, and their rows are withheld.
Available edges retain their proof selectors and link to the console's exact
case-scoped evidence drill-down.

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
