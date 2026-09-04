"""Optional loopback-first web adapter for the transport-neutral review model."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hmac
import ipaddress
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from jinja2 import Environment, PackageLoader, StrictUndefined
from pydantic import ValidationError
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from mulder.graph_query import GraphQueryRequest, NeighborsQuery
from mulder.review.events import MAX_RUN_EVENT_PAGE, RunEventError, RunEventJournal, encode_sse
from mulder.review.model import (
    MAX_EVIDENCE_LIMIT,
    MAX_FINDING_LIMIT,
    MAX_REVISION_LIMIT,
    CaseReviewError,
    EvidenceDetail,
    EvidenceReviewQuery,
    ReviewQuery,
    query_case_review,
    query_evidence_detail,
)

_TEMPLATES = Environment(
    loader=PackageLoader("mulder.review", "templates"),
    autoescape=True,
    undefined=StrictUndefined,
)
_FALSE_VALUES = frozenset({"0", "false", "no"})


class ReviewConsoleError(ValueError):
    """Raised when the console cannot be configured safely."""


def _is_loopback_host(host: str) -> bool:
    candidate = host.strip().lower()
    if candidate == "localhost":
        return True
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True)
class ReviewConsoleConfig:
    """Validated local-console configuration shared by the CLI and web adapter."""

    case_id: str
    db_dir: Path
    host: str = "127.0.0.1"
    port: int = 8765
    auth_token: str | None = None

    def __post_init__(self) -> None:
        if (
            not self.case_id
            or self.case_id in {".", ".."}
            or Path(self.case_id).name != self.case_id
        ):
            raise ReviewConsoleError("case_id must be one non-empty path segment")
        if not self.host.strip():
            raise ReviewConsoleError("host must not be empty")
        if not 1 <= self.port <= 65535:
            raise ReviewConsoleError("port must be between 1 and 65535")
        if self.auth_token is not None and not self.auth_token:
            raise ReviewConsoleError("auth_token must not be empty")
        if not self.loopback_only and self.auth_token is None:
            raise ReviewConsoleError(
                "non-loopback binding requires an explicit examiner-supplied auth token"
            )

    @property
    def loopback_only(self) -> bool:
        return _is_loopback_host(self.host)


class _ConsoleMiddleware:
    """Authenticate configured deployments and attach defensive response headers."""

    def __init__(self, app: ASGIApp, config: ReviewConsoleConfig) -> None:
        self.app = app
        self.config = config

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        if self.config.auth_token is not None and not self._authorized(scope):
            response = JSONResponse(
                {"detail": "authorization required"},
                status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="Mulder case review", charset="UTF-8"'},
            )
            await response(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message.get("type") == "http.response.start":
                raw_headers = message.setdefault("headers", [])
                if not isinstance(raw_headers, list):
                    raise TypeError("ASGI response headers must be a list")
                raw_headers.extend(
                    [
                        (b"cache-control", b"no-store"),
                        (b"content-security-policy", b"default-src 'self'; object-src 'none'"),
                        (b"referrer-policy", b"no-referrer"),
                        (b"x-content-type-options", b"nosniff"),
                        (b"x-frame-options", b"DENY"),
                    ]
                )
            await send(message)

        await self.app(scope, receive, send_with_headers)

    def _authorized(self, scope: Scope) -> bool:
        expected = self.config.auth_token
        if expected is None:
            return True
        headers = scope.get("headers", [])
        authorization = next(
            (
                value.decode("latin-1")
                for name, value in headers
                if name.lower() == b"authorization"
            ),
            "",
        )
        if authorization.startswith("Bearer "):
            return hmac.compare_digest(authorization[7:], expected)
        if not authorization.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(authorization[6:], validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            return False
        username, separator, password = decoded.partition(":")
        return bool(separator) and username == "mulder" and hmac.compare_digest(password, expected)


def _case_matches(request: Request, config: ReviewConsoleConfig) -> bool:
    return request.path_params.get("case_id") == config.case_id


def _review_query(
    config: ReviewConsoleConfig,
    *,
    graph_query: GraphQueryRequest | None = None,
) -> ReviewQuery:
    return ReviewQuery(
        case_id=config.case_id,
        db_dir=config.db_dir,
        finding_limit=MAX_FINDING_LIMIT,
        evidence_limit=MAX_EVIDENCE_LIMIT,
        revision_limit=MAX_REVISION_LIMIT,
        graph_query=graph_query,
    )


def _error_response(exc: CaseReviewError | RunEventError, *, html: bool) -> Response:
    status = 404 if "not found" in str(exc).lower() else 409
    if html:
        body = _TEMPLATES.get_template("error.html.j2").render(
            title="Case review unavailable",
            message=str(exc),
        )
        return HTMLResponse(body, status_code=status)
    return JSONResponse({"detail": str(exc)}, status_code=status)


def create_review_app(config: ReviewConsoleConfig) -> Starlette:
    """Create a read-only ASGI adapter for one explicitly selected case."""

    async def root(_request: Request) -> Response:
        return RedirectResponse(f"/cases/{quote(config.case_id, safe='')}", status_code=302)

    async def case_page(request: Request) -> Response:
        if not _case_matches(request, config):
            return Response(status_code=404)
        try:
            review = query_case_review(_review_query(config))
        except CaseReviewError as exc:
            return _error_response(exc, html=True)
        anchor_urls = {
            anchor.anchor_id: (
                f"/cases/{quote(config.case_id, safe='')}/evidence/"
                f"{quote(anchor.anchor_id, safe='')}"
            )
            for finding in (*review.findings.active, *review.findings.withdrawn)
            for claim in finding.claims
            for anchor in claim.anchors
        }
        graph_node_labels = {
            node.entity.entity_id: node.entity.display_value
            for result in review.graph.items
            for node in result.nodes
        }
        for result in review.graph.items:
            for edge in result.edges:
                for anchor in edge.evidence_selector.anchors:
                    anchor_urls[anchor.anchor_id] = (
                        f"/cases/{quote(config.case_id, safe='')}/evidence/"
                        f"{quote(anchor.anchor_id, safe='')}"
                    )
        body = _TEMPLATES.get_template("console.html.j2").render(
            review=review,
            proof_cards=review.proof_cards(),
            anchor_urls=anchor_urls,
            graph_node_labels=graph_node_labels,
            event_url=f"/api/cases/{quote(config.case_id, safe='')}/events",
            graph_url=f"/api/cases/{quote(config.case_id, safe='')}/graph",
            reasoning_url=f"/api/cases/{quote(config.case_id, safe='')}/reasoning",
        )
        return HTMLResponse(body)

    async def review_json(request: Request) -> Response:
        if not _case_matches(request, config):
            return Response(status_code=404)
        try:
            review = query_case_review(_review_query(config))
        except CaseReviewError as exc:
            return _error_response(exc, html=False)
        return JSONResponse(review.model_dump(mode="json", by_alias=True))

    async def proof_cards_json(request: Request) -> Response:
        if not _case_matches(request, config):
            return Response(status_code=404)
        try:
            review = query_case_review(_review_query(config))
        except CaseReviewError as exc:
            return _error_response(exc, html=False)
        return JSONResponse(
            {
                "schema": "mulder.finding-proof-card-collection",
                "version": 1,
                "case_id": config.case_id,
                "cards": review.proof_cards(),
            }
        )

    async def graph_json(request: Request) -> Response:
        if not _case_matches(request, config):
            return Response(status_code=404)
        graph_query: GraphQueryRequest | None = None
        entity_id = request.query_params.get("entity_id")
        if entity_id is not None:
            try:
                graph_query = NeighborsQuery.model_validate(
                    {
                        "entity_id": entity_id,
                        "depth": int(request.query_params.get("depth", "1")),
                        "direction": request.query_params.get("direction", "both"),
                        "limit": int(request.query_params.get("limit", "50")),
                    }
                )
            except (TypeError, ValueError, ValidationError):
                return JSONResponse(
                    {"detail": "invalid bounded graph query parameters"},
                    status_code=400,
                )
        try:
            review = query_case_review(_review_query(config, graph_query=graph_query))
        except CaseReviewError as exc:
            return _error_response(exc, html=False)
        return JSONResponse(review.graph.model_dump(mode="json"))

    async def reasoning_json(request: Request) -> Response:
        if not _case_matches(request, config):
            return Response(status_code=404)
        try:
            review = query_case_review(_review_query(config))
        except CaseReviewError as exc:
            return _error_response(exc, html=False)
        return JSONResponse(review.reasoning.model_dump(mode="json"))

    def evidence(request: Request) -> EvidenceDetail:
        return query_evidence_detail(
            EvidenceReviewQuery(
                case_id=config.case_id,
                anchor_id=str(request.path_params["anchor_id"]),
                db_dir=config.db_dir,
            )
        )

    async def evidence_page(request: Request) -> Response:
        if not _case_matches(request, config):
            return Response(status_code=404)
        try:
            detail = evidence(request)
        except CaseReviewError as exc:
            return _error_response(exc, html=True)
        body = _TEMPLATES.get_template("evidence.html.j2").render(detail=detail)
        return HTMLResponse(body)

    async def evidence_json(request: Request) -> Response:
        if not _case_matches(request, config):
            return Response(status_code=404)
        try:
            detail = evidence(request)
        except CaseReviewError as exc:
            return _error_response(exc, html=False)
        return JSONResponse(detail.model_dump(mode="json", by_alias=True))

    async def events(request: Request) -> Response:
        if not _case_matches(request, config):
            return Response(status_code=404)
        cursor_text = request.headers.get("last-event-id", "0").strip() or "0"
        try:
            cursor = int(cursor_text)
        except ValueError:
            return JSONResponse({"detail": "Last-Event-ID must be an integer"}, status_code=400)
        if cursor < 0:
            return JSONResponse({"detail": "Last-Event-ID must be non-negative"}, status_code=400)
        try:
            limit = int(request.query_params.get("limit", str(MAX_RUN_EVENT_PAGE)))
        except ValueError:
            return JSONResponse({"detail": "limit must be an integer"}, status_code=400)
        if not 1 <= limit <= MAX_RUN_EVENT_PAGE:
            return JSONResponse(
                {"detail": f"limit must be between 1 and {MAX_RUN_EVENT_PAGE}"},
                status_code=400,
            )
        follow = request.query_params.get("follow", "1").lower() not in _FALSE_VALUES
        journal = RunEventJournal(
            config.db_dir / f"{config.case_id}.audit.jsonl", config.case_id
        )
        try:
            first_page = journal.read(after_sequence=cursor, limit=limit)
        except RunEventError as exc:
            return _error_response(exc, html=False)

        async def stream() -> AsyncIterator[bytes]:
            current = cursor
            page = first_page
            while True:
                for event in page.events:
                    current = event.sequence
                    yield encode_sse(event)
                if page.has_more:
                    page = journal.read(after_sequence=current, limit=limit)
                    continue
                if not follow or await request.is_disconnected():
                    break
                yield b": keep-alive\n\n"
                await asyncio.sleep(0.5)
                page = journal.read(after_sequence=current, limit=limit)

        from starlette.responses import StreamingResponse

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={"X-Accel-Buffering": "no", "Connection": "keep-alive"},
        )

    async def stylesheet(_request: Request) -> Response:
        css = (Path(__file__).parent / "static" / "review.css").read_text(encoding="utf-8")
        return Response(css, media_type="text/css")

    async def script(_request: Request) -> Response:
        js = (Path(__file__).parent / "static" / "review.js").read_text(encoding="utf-8")
        return Response(js, media_type="text/javascript")

    routes = [
        Route("/", root, methods=["GET"]),
        Route("/cases/{case_id}", case_page, methods=["GET"]),
        Route(
            "/cases/{case_id}/evidence/{anchor_id}",
            evidence_page,
            methods=["GET"],
            name="evidence_page",
        ),
        Route("/api/cases/{case_id}", review_json, methods=["GET"]),
        Route("/api/cases/{case_id}/proof-cards", proof_cards_json, methods=["GET"]),
        Route("/api/cases/{case_id}/graph", graph_json, methods=["GET"]),
        Route("/api/cases/{case_id}/reasoning", reasoning_json, methods=["GET"]),
        Route(
            "/api/cases/{case_id}/evidence/{anchor_id}",
            evidence_json,
            methods=["GET"],
        ),
        Route("/api/cases/{case_id}/events", events, methods=["GET"]),
        Route("/static/review.css", stylesheet, methods=["GET"]),
        Route("/static/review.js", script, methods=["GET"]),
    ]
    app = Starlette(debug=False, routes=routes)
    app.add_middleware(_ConsoleMiddleware, config=config)
    return app


def run_review_console(config: ReviewConsoleConfig) -> None:
    """Run the local console with the optional Uvicorn adapter."""
    import uvicorn

    uvicorn.run(
        create_review_app(config),
        host=config.host,
        port=config.port,
        access_log=False,
    )
