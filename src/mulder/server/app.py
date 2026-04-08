"""FastMCP server definition and initialization for Mulder."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.index.correlator import Correlator
from mulder.index.embedder import Embedder
from mulder.index.query import QueryEngine
from mulder.index.reducer import OutputReducer

logger = logging.getLogger(__name__)

mcp = FastMCP("Mulder")


@dataclass
class ServerContext:
    """Shared state available to every MCP tool at runtime."""

    db: CaseDB
    query_engine: QueryEngine
    correlator: Correlator
    reducer: OutputReducer
    audit: AuditLog


_ctx: ServerContext | None = None


def get_ctx() -> ServerContext:
    """Return the current server context or raise if not initialised."""
    if _ctx is None:
        raise RuntimeError("Server context not initialised. Call init_server() before mcp.run().")
    return _ctx


def init_server(case_id: str, db_dir: Path, audit_path: Path) -> None:
    """Initialise all components and store them in the module-level context.

    Called by ``cli.py`` before ``mcp.run()``.
    """
    global _ctx  # noqa: PLW0603

    logger.info("Opening case database for '%s' ...", case_id)
    db = CaseDB.open(case_id, db_dir)

    logger.info("Loading embedding model ...")
    embedder = Embedder()

    query_engine = QueryEngine(db, embedder)
    correlator = Correlator(query_engine, db)
    reducer = OutputReducer()
    audit = AuditLog(audit_path)

    _ctx = ServerContext(
        db=db,
        query_engine=query_engine,
        correlator=correlator,
        reducer=reducer,
        audit=audit,
    )
    logger.info("Server context ready for case '%s'", case_id)


import mulder.server.tools_composite as _tools_composite  # noqa: E402, F401
import mulder.server.tools_core as _tools_core  # noqa: E402, F401
import mulder.server.tools_findings as _tools_findings  # noqa: E402, F401
