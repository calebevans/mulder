"""Narrow transport ports and bounded HTTP implementations for connectors."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

import httpx

from mulder.connectors.models import ConnectorTransportError


@dataclass(frozen=True)
class SnapshotTransportRequest:
    origin: str
    path: str
    method: Literal["GET", "POST"]
    headers: tuple[tuple[str, str], ...]
    body: bytes | None
    max_response_bytes: int


@dataclass(frozen=True)
class SnapshotTransportResponse:
    body: bytes
    content_type: str
    request_id: str | None = None


class SnapshotTransport(Protocol):
    def fetch(self, request: SnapshotTransportRequest) -> SnapshotTransportResponse:
        """Perform one already-authorized read-only snapshot request."""


@dataclass(frozen=True)
class ExportTransportRequest:
    origin: str
    path: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    max_response_bytes: int = 1_000_000


@dataclass(frozen=True)
class ExportTransportResponse:
    remote_reference: str
    body: bytes = b""


class ExportTransport(Protocol):
    def deliver(self, request: ExportTransportRequest) -> ExportTransportResponse:
        """Deliver one already-authorized case artifact (never a containment action)."""


class HttpSnapshotTransport:
    """Synchronous HTTP port with redirects disabled and a bounded response."""

    def __init__(self, *, timeout_seconds: float = 30.0) -> None:
        self._timeout = timeout_seconds

    def fetch(self, request: SnapshotTransportRequest) -> SnapshotTransportResponse:
        url = request.origin + request.path
        try:
            with (
                httpx.Client(timeout=self._timeout, follow_redirects=False) as client,
                client.stream(
                    request.method,
                    url,
                    headers=dict(request.headers),
                    content=request.body,
                ) as response,
            ):
                if response.status_code < 200 or response.status_code >= 300:
                    raise ConnectorTransportError(
                        f"snapshot transport returned HTTP {response.status_code}"
                    )
                chunks: list[bytes] = []
                size = 0
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > request.max_response_bytes:
                        raise ConnectorTransportError(
                            "snapshot response exceeds policy byte limit"
                        )
                    chunks.append(chunk)
                body = b"".join(chunks)
                content_type = response.headers.get("content-type", "application/octet-stream")
                request_id = response.headers.get("x-request-id")
        except httpx.HTTPError as exc:
            raise ConnectorTransportError(f"snapshot transport failed: {exc}") from exc
        return SnapshotTransportResponse(
            body=body,
            content_type=content_type,
            request_id=request_id,
        )


class HttpExportTransport:
    """Synchronous HTTP delivery port with redirects disabled."""

    def __init__(self, *, timeout_seconds: float = 30.0) -> None:
        self._timeout = timeout_seconds

    def deliver(self, request: ExportTransportRequest) -> ExportTransportResponse:
        url = request.origin + request.path
        try:
            with (
                httpx.Client(timeout=self._timeout, follow_redirects=False) as client,
                client.stream(
                    "POST",
                    url,
                    headers=dict(request.headers),
                    content=request.body,
                ) as response,
            ):
                if response.status_code < 200 or response.status_code >= 300:
                    raise ConnectorTransportError(
                        f"export transport returned HTTP {response.status_code}"
                    )
                chunks: list[bytes] = []
                size = 0
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > request.max_response_bytes:
                        raise ConnectorTransportError(
                            "export response exceeds bounded receipt limit"
                        )
                    chunks.append(chunk)
                body = b"".join(chunks)
                reference = response.headers.get("location") or response.headers.get(
                    "x-request-id"
                )
        except httpx.HTTPError as exc:
            raise ConnectorTransportError(f"export transport failed: {exc}") from exc
        if not reference:
            raise ConnectorTransportError("export response did not provide a remote reference")
        return ExportTransportResponse(remote_reference=reference, body=body)
