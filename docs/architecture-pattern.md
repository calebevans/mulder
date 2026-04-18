# Agentic Tool Memory Architecture

## The Pattern

An AI agent calls external tools to gather information. Instead of
holding tool output in the agent's conversation context (which is
ephemeral and size-limited), every tool output is automatically:

1. **Windowed** -- broken into semantically coherent chunks
2. **Embedded** -- each chunk gets a vector embedding
3. **Stored** -- chunks + embeddings go into a vector database with metadata (source, timestamp, tool name)
4. **Queryable** -- the agent accesses its own past tool outputs through structured API calls (semantic search, time-range correlation, anomaly scoring)

The agent's working memory is the database, not the conversation
history. Findings and conclusions are also persisted to the database
as they're produced, so nothing is lost if the conversation context
is compacted or the session is interrupted.

## Architecture

```
┌─────────────────────────────────────────────┐
│  AI Agent (any LLM-based agent framework)   │
│  - Decides which tools to call              │
│  - Reasons about results                    │
│  - Submits conclusions incrementally        │
└──────────────────┬──────────────────────────┘
                   │ API (MCP, REST, function calls, etc.)
┌──────────────────▼──────────────────────────┐
│  Tool Orchestration Layer                    │
│                                              │
│  ┌────────────┐  ┌───────────┐  ┌─────────┐ │
│  │ Tool calls │→ │ Windowing │→ │ Embed   │ │
│  │ (any CLI   │  │ (chunk    │  │ (local  │ │
│  │  or API)   │  │  output)  │  │  or API)│ │
│  └────────────┘  └───────────┘  └────┬────┘ │
│                                      │      │
│  ┌───────────────────────────────────▼────┐ │
│  │  Vector Database (SQLite-vec, pgvector, │ │
│  │  Pinecone, Qdrant, etc.)               │ │
│  │  - raw_text + embedding per chunk      │ │
│  │  - source metadata (tool, timestamp)   │ │
│  │  - findings / conclusions              │ │
│  └───────────────────────────────────────┘  │
│                                              │
│  Query Tools (exposed back to the agent):    │
│  - semantic_search(query) → relevant chunks  │
│  - get_raw_output(source) → paginated text   │
│  - correlate(time_range) → cross-source view │
│  - get_anomalies(source, range) → outliers   │
│  - get_findings() → persisted conclusions    │
│  - submit_finding() → persist a conclusion   │
└──────────────────────────────────────────────┘
```

## Why This Works

### Problem: Context Window is Ephemeral

Traditional agent systems put tool output directly into the
conversation. This creates three issues:

1. **Size limit** -- Large outputs (scan results, log files, database
   queries) overwhelm the context window
2. **Loss on compaction** -- When context is trimmed/summarized, raw
   evidence is lost and the agent can't quote it
3. **No cross-referencing** -- The agent can't efficiently search across
   outputs from different tools called at different times

### Solution: Database as External Memory

By embedding and storing tool output, the agent gets:

1. **Unlimited working memory** -- The database holds everything; the
   agent only pulls what it needs via search
2. **Persistence** -- Survives context compaction, session interruption,
   even agent crashes. The database IS the state.
3. **Semantic retrieval** -- The agent can find relevant information
   across ALL past tool outputs with a natural language query
4. **Cross-source correlation** -- "Show me everything that happened
   at timestamp X" works across all tools automatically
5. **Incremental conclusions** -- Findings are persisted as they're
   made, not batched at the end

## Components

### 1. Windowing + Embedding: Cordon

[**Cordon**](https://github.com/calebevans/cordon) is the library
that handles windowing, embedding, and anomaly scoring in this
architecture. It takes raw text output, intelligently chunks it into
semantically coherent windows, computes embeddings (local via
sentence-transformers or remote via API), and provides anomaly
scoring via k-NN density analysis on the embedding space.

Cordon handles the core pipeline:
- **Windowing** -- splits raw tool output into chunks that are small
  enough to embed meaningfully (~100-500 tokens) but large enough to
  preserve context. Annotates with timestamps when present.
- **Embedding** -- computes vector embeddings per chunk. Supports
  local models (sentence-transformers, all-MiniLM-L6-v2, ~384 dims)
  and remote APIs (Gemini, OpenAI, etc.).
- **Anomaly scoring** -- k-NN density scoring surfaces statistically
  unusual chunks. Chunks whose embeddings are far from their neighbors
  are ranked highest, letting the agent focus on outliers.
- **Reduction** -- for very large outputs, Cordon can intelligently
  reduce text while preserving the most anomalous/relevant sections.

For technical/structured data (tool outputs, logs, scan results),
local embeddings work well because the vocabulary is constrained
and similarity is mostly about matching identifiers, patterns, and
values rather than nuanced meaning.

### 3. Vector Database

Stores chunks with:
- `raw_text` -- the original chunk text (always preserved)
- `embedding` -- the vector for similarity search
- `source_name` -- which tool produced this (e.g., "nmap.scan",
  "sql.query.users", "api.response.orders")
- `source_path` -- the input that was analyzed
- `event_time` -- timestamp extracted from the data (if any)
- `metadata` -- tool parameters, duration, etc.

### 4. Query Tools

These are exposed to the agent as callable functions:

- **`search(query, k=20)`** -- semantic similarity search across
  ALL stored chunks. Returns the most relevant chunks regardless
  of which tool produced them.

- **`get_raw_output(source, offset, limit)`** -- paginated access
  to the raw text from a specific tool's output. For when the
  agent needs to re-read exact output.

- **`correlate(time_start, time_end)`** -- returns chunks from ALL
  sources that have timestamps within the given window. Reveals
  connections between different data sources.

- **`get_anomalies(source, time_range, top_percent)`** -- uses
  k-NN density scoring on embeddings to surface statistically
  unusual chunks. Chunks whose embeddings are far from their
  neighbors are ranked highest.

- **`submit_finding(title, description, evidence_refs)`** --
  persists a conclusion to the database with references to the
  specific chunks that support it. This is the agent's way of
  "writing notes" that survive context compaction.

- **`get_findings()`** -- retrieves all persisted conclusions.
  The agent checks this at decision points to remember what
  it has already determined.

### 5. Audit Trail

Every tool call is logged with:
- Unique ID (for traceability)
- Tool name and parameters
- Output hash (proves the output wasn't modified)
- Duration
- Timestamp

Conclusions reference specific tool call IDs, creating a
complete provenance chain from raw data to final output.

## When to Use This Pattern

This architecture is valuable when:

- **Tool outputs are large** -- scan results, log files, database
  queries, API responses that don't fit in context
- **Investigations are long-running** -- multi-step analysis where
  the agent needs to reference earlier findings
- **Cross-referencing matters** -- findings from one tool inform
  queries to another
- **Reproducibility is required** -- you need to trace conclusions
  back to specific evidence
- **The agent might lose context** -- long sessions, context
  compaction, or multi-session workflows

## Where This Pattern Applies

Any domain where an agent orchestrates tools with substantial output:

- **Security** -- forensic analysis, threat hunting, vulnerability
  assessment, incident response
- **Data engineering** -- database exploration, ETL validation,
  data quality analysis
- **Research** -- literature review, experiment analysis, multi-source
  synthesis
- **DevOps** -- infrastructure auditing, log analysis, performance
  investigation
- **Legal/compliance** -- document review, regulatory analysis,
  evidence gathering
- **Code analysis** -- large codebase exploration, dependency auditing,
  security review

## Implementation Notes

- **Windowing + embedding**: [Cordon](https://github.com/calebevans/cordon)
  (`pip install cordon`) handles the windowing, embedding, anomaly
  scoring, and reduction pipeline. It supports both local
  (sentence-transformers) and remote (API-based) embedding backends.
- **Embedding model choice**: For structured/technical text, local
  models (all-MiniLM-L6-v2, 80MB) are fast and sufficient. Save
  API-based embeddings for natural language heavy domains.
- **Chunk size tradeoff**: Smaller chunks = more precise retrieval
  but more embeddings to compute. 200-500 tokens is a good default.
- **Database choice**: SQLite-vec for single-machine deployments
  (zero infrastructure). pgvector/Qdrant for distributed systems.
- **The agent must be told** to use the database as memory. Without
  prompting, agents default to holding everything in context.
  Explicit instructions like "use search() to recall evidence"
  and "submit findings as you go" are necessary.
