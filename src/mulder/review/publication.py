"""State-bound publication artifacts and rendered-output quality gates.

Publication is deliberately downstream of :mod:`mulder.review.model`.  Every
audience view is rendered from the same immutable review projection, and an
APPROVED sidecar commits both that projection and the exact bytes delivered to
readers.  Renderers are presentation adapters: they copy epistemic labels from
the fact model and never derive stronger ones.
"""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Literal, cast
from urllib.parse import unquote

from mulder.review.decisions import ReviewWorkflow, ReviewWorkflowError
from mulder.review.model import (
    MAX_EVIDENCE_LIMIT,
    MAX_FINDING_LIMIT,
    MAX_REVISION_LIMIT,
    CaseReviewModel,
    FindingState,
    ReviewQuery,
    query_case_review,
)

PUBLICATION_SCHEMA = "mulder.publication-manifest"
PUBLICATION_VERSION = 1
AUDIENCES = ("executive", "technical", "examiner")

PublicationState = Literal["DRAFT", "APPROVED"]
Audience = Literal["executive", "technical", "examiner"]
QAStatus = Literal["pass", "fail", "skipped"]


class PublicationError(ValueError):
    """Raised when publication state or rendered artifacts are unsafe."""


@dataclass(frozen=True)
class QACheck:
    """One machine-readable render or fact-model quality check."""

    name: str
    status: QAStatus
    blocking: bool
    detail: str


@dataclass(frozen=True)
class RenderedArtifact:
    """Commitment to one audience/format output."""

    name: str
    audience: Audience
    format: Literal["markdown", "html", "pdf"]
    sha256: str
    size_bytes: int


@dataclass(frozen=True)
class _RenderedAudience:
    markdown: str
    html: str
    pdf: bytes | None
    pdf_page_geometry_ok: bool | None
    pdf_page_count: int


class _PublicationHTMLParser(HTMLParser):
    """Collect structural proof links and verbatim epistemic bindings."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ids: set[str] = set()
        self.fragments: list[str] = []
        self.claim_states: dict[str, list[str]] = {}
        self.visible_characters = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del tag
        values = dict(attrs)
        element_id = values.get("id")
        if element_id:
            self.ids.add(element_id)
        href = values.get("href")
        if href and href.startswith("#"):
            self.fragments.append(unquote(href[1:]))
        claim_id = values.get("data-claim-id")
        state = values.get("data-epistemic-state")
        if claim_id is not None and state is not None:
            self.claim_states.setdefault(claim_id, []).append(state)

    def handle_data(self, data: str) -> None:
        self.visible_characters += len("".join(data.split()))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _domain_digest(domain: bytes, value: object) -> str:
    return "sha256:" + hashlib.sha256(domain + b"\0" + _canonical_json(value)).hexdigest()


def _bytes_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _manifest_hash(manifest: dict[str, object]) -> str:
    value = dict(manifest)
    integrity = dict(cast(dict[str, object], value.get("integrity", {})))
    integrity.pop("manifest_hash", None)
    value["integrity"] = integrity
    return _domain_digest(b"mulder.publication-manifest:v1", value)


def _atomic_write(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as f:
            temporary = Path(f.name)
            f.write(value)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
    except BaseException:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise


def _safe_id(kind: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:20]
    return f"{kind}-{digest}"


def _md(value: object) -> str:
    """Escape untrusted facts for plain Markdown cells and paragraphs."""
    text = " ".join(str(value).splitlines())
    return re.sub(r"([\\`*_[\]<>|])", r"\\\1", text)


def _all_findings(review: CaseReviewModel) -> tuple[FindingState, ...]:
    return (*review.findings.active, *review.findings.withdrawn)


def _expected_claim_states(review: CaseReviewModel) -> dict[str, str]:
    return {
        claim.claim_id: claim.epistemic_state
        for finding in _all_findings(review)
        for claim in finding.claims
    }


def _render_markdown(review: CaseReviewModel, audience: Audience, fact_digest: str) -> str:
    lines = [
        f"# Mulder {_md(audience.title())} publication — `{_md(review.case.case_id)}`",
        "",
        f"Publication audience: `{audience}`  ",
        f"Fact-model commitment: `{fact_digest}`  ",
        "Epistemic labels below are copied verbatim from the case-review fact model.",
        "",
    ]
    if audience == "executive":
        lines.extend(
            (
                "## Decision summary",
                "",
                f"Active findings: {review.findings.active_total}; "
                f"withdrawn findings: {review.findings.withdrawn_total}.",
                "",
            )
        )
        for item in review.findings.active:
            lines.append(
                f"- **{_md(item.finding.title)}** — severity `{item.finding.severity}`, "
                f"confidence `{item.finding.confidence}`"
            )
        lines.append("")
    elif audience == "technical":
        lines.extend(("## Investigation state", ""))
        for phase in review.phases:
            lines.append(
                f"- `{_md(phase.name)}`: `{phase.state}` — "
                + _md("; ".join(phase.basis) or "no durable basis")
            )
        lines.extend(
            (
                "",
                f"Audit: `{review.audit.integrity_status}`; receipt: `{review.receipt.status}`; "
                f"review approval: `{review.approval.state}`.",
                "",
                "## Findings and claims",
                "",
            )
        )
        for item in _all_findings(review):
            lines.append(
                f"- `{_md(item.finding.finding_id)}` ({_md(item.lifecycle_state)}): "
                f"{_md(item.finding.title)}"
            )
            for claim in item.claims:
                lines.append(
                    f"  - `{claim.epistemic_state}` — {_md(claim.statement)} "
                    f"([proof](#{_safe_id('claim', claim.claim_id)}))"
                )
        lines.append("")
    else:
        lines.extend(("## Examiner review", ""))
        for item in _all_findings(review):
            lines.append(f"### {_md(item.finding.finding_id)} — {_md(item.finding.title)}")
            lines.extend(
                (
                    "",
                    f"Lifecycle: `{_md(item.lifecycle_state)}`; severity: "
                    f"`{item.finding.severity}`; confidence: `{item.finding.confidence}`.",
                    "",
                )
            )
            for claim in item.claims:
                links = ", ".join(
                    f"[anchor {index + 1}](#{_safe_id('anchor', anchor.anchor_id)})"
                    for index, anchor in enumerate(claim.anchors)
                )
                lines.append(
                    f"- `{claim.epistemic_state}` — {_md(claim.statement)}"
                    + (f" ({links})" if links else "")
                )
        lines.append("")

    lines.extend(("## Proof appendix", ""))
    for item in _all_findings(review):
        for claim in item.claims:
            lines.extend(
                (
                    f'<a id="{_safe_id("claim", claim.claim_id)}"></a>',
                    f"### Claim `{_md(claim.claim_id)}` — `{claim.epistemic_state}`",
                    "",
                    _md(claim.statement),
                    "",
                )
            )
            for anchor in claim.anchors:
                lines.extend(
                    (
                        f'<a id="{_safe_id("anchor", anchor.anchor_id)}"></a>',
                        f"- Anchor `{_md(anchor.anchor_id)}` ({_md(anchor.role)}): "
                        f"`{_md(anchor.source_name)}:{anchor.line_start}-{anchor.line_end}` "
                        f"chars `{anchor.char_start}-{anchor.char_end}`, source "
                        f"`{_md(anchor.source_hash)}` — {_md(anchor.exact_text)}",
                    )
                )
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _render_html(review: CaseReviewModel, audience: Audience, fact_digest: str) -> str:
    title = f"Mulder {audience.title()} publication — {review.case.case_id}"
    body: list[str] = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        f"<title>{html.escape(title)}</title>",
        "<style>@page{size:A4;margin:18mm}body{font:14px system-ui,sans-serif;"
        "max-width:980px;margin:auto;color:#172033}code{overflow-wrap:anywhere}"
        "section{break-inside:avoid;margin:1.2rem 0}.state{font-weight:700}"
        ".anchor{border-left:3px solid #72809a;padding-left:.8rem}</style></head><body>",
        f"<h1>{html.escape(title)}</h1>",
        f'<p data-fact-model-digest="{html.escape(fact_digest, quote=True)}">'
        f"Audience: <code>{audience}</code>. Fact model: <code>{html.escape(fact_digest)}</code>."
        " Epistemic labels are copied verbatim from the case-review fact model.</p>",
    ]
    if audience == "executive":
        body.append(
            f"<h2>Decision summary</h2><p>Active findings: {review.findings.active_total}; "
            f"withdrawn findings: {review.findings.withdrawn_total}.</p><ul>"
        )
        for item in review.findings.active:
            body.append(
                f"<li><strong>{html.escape(item.finding.title)}</strong> — severity "
                f"<code>{item.finding.severity}</code>, confidence "
                f"<code>{item.finding.confidence}</code></li>"
            )
        body.append("</ul>")
    elif audience == "technical":
        body.append("<h2>Investigation state</h2><ul>")
        for phase in review.phases:
            basis = "; ".join(phase.basis) or "no durable basis"
            body.append(
                f"<li><code>{html.escape(phase.name)}</code>: <code>{phase.state}</code> — "
                f"{html.escape(basis)}</li>"
            )
        body.append(
            "</ul><h2>Findings and claims</h2>"
            f"<p>Audit: <code>{html.escape(review.audit.integrity_status)}</code>; "
            f"receipt: <code>{html.escape(review.receipt.status)}</code>; review approval: "
            f"<code>{html.escape(review.approval.state)}</code>.</p><ul>"
        )
        for item in _all_findings(review):
            body.append(
                f"<li><code>{html.escape(item.finding.finding_id)}</code> "
                f"({html.escape(item.lifecycle_state)}): {html.escape(item.finding.title)}<ul>"
            )
            for claim in item.claims:
                claim_id = html.escape(claim.claim_id, quote=True)
                proof_id = _safe_id("claim", claim.claim_id)
                state = claim.epistemic_state
                body.append(
                    f'<li><span class="state" data-claim-id="{claim_id}" '
                    f'data-epistemic-state="{state}">{state}</span> — '
                    f'{html.escape(claim.statement)} (<a href="#{proof_id}">proof</a>)</li>'
                )
            body.append("</ul></li>")
        body.append("</ul>")
    else:
        body.append("<h2>Examiner review</h2>")
        for item in _all_findings(review):
            body.append(
                f"<section><h3>{html.escape(item.finding.finding_id)} — "
                f"{html.escape(item.finding.title)}</h3><p>Lifecycle: "
                f"<code>{html.escape(item.lifecycle_state)}</code>; severity: "
                f"<code>{item.finding.severity}</code>; confidence: "
                f"<code>{item.finding.confidence}</code>.</p><ul>"
            )
            for claim in item.claims:
                claim_id = html.escape(claim.claim_id, quote=True)
                state = claim.epistemic_state
                anchor_links = ", ".join(
                    f'<a href="#{_safe_id("anchor", anchor.anchor_id)}">anchor {index + 1}</a>'
                    for index, anchor in enumerate(claim.anchors)
                )
                body.append(
                    f'<li><span class="state" data-claim-id="{claim_id}" '
                    f'data-epistemic-state="{state}">{state}</span> — '
                    f"{html.escape(claim.statement)}"
                    + (f" ({anchor_links})" if anchor_links else "")
                    + "</li>"
                )
            body.append("</ul></section>")

    body.append("<h2>Proof appendix</h2>")
    for item in _all_findings(review):
        for claim in item.claims:
            body.append(
                f'<section id="{_safe_id("claim", claim.claim_id)}"><h3>Claim '
                f"<code>{html.escape(claim.claim_id)}</code> — "
                f'<span class="state" data-claim-id="{html.escape(claim.claim_id, quote=True)}" '
                f'data-epistemic-state="{claim.epistemic_state}">{claim.epistemic_state}</span>'
                f"</h3><p>{html.escape(claim.statement)}</p>"
            )
            for anchor in claim.anchors:
                source_selector = (
                    f"{html.escape(anchor.source_name)}:{anchor.line_start}-{anchor.line_end}"
                )
                claim_target = _safe_id("claim", claim.claim_id)
                body.append(
                    f'<div class="anchor" id="{_safe_id("anchor", anchor.anchor_id)}">'
                    f"<p>Anchor <code>{html.escape(anchor.anchor_id)}</code> "
                    f"({html.escape(anchor.role)}): "
                    f"<code>{source_selector}</code> "
                    f"chars <code>{anchor.char_start}-{anchor.char_end}</code>, source "
                    f"<code>{html.escape(anchor.source_hash)}</code></p>"
                    f"<blockquote>{html.escape(anchor.exact_text)}</blockquote>"
                    f'<p><a href="#{claim_target}">back to claim</a></p></div>'
                )
            body.append("</section>")
    body.append("</body></html>\n")
    return "".join(body)


def _render_pdf(html_text: str) -> tuple[bytes | None, bool | None, int]:
    try:
        import weasyprint
    except ImportError:
        return None, None, 0
    document = weasyprint.HTML(string=html_text).render()
    pages = list(document.pages)
    geometry_ok = bool(pages) and all(page.width > 0 and page.height > 0 for page in pages)
    return cast(bytes, document.write_pdf()), geometry_ok, len(pages)


def _render_audience(
    review: CaseReviewModel,
    audience: Audience,
    fact_digest: str,
    *,
    generate_pdf: bool,
) -> _RenderedAudience:
    markdown = _render_markdown(review, audience, fact_digest)
    html_text = _render_html(review, audience, fact_digest)
    pdf, geometry, count = _render_pdf(html_text) if generate_pdf else (None, None, 0)
    return _RenderedAudience(markdown, html_text, pdf, geometry, count)


def _markdown_proof_targets(document: str) -> tuple[set[str], list[str]]:
    targets = set(re.findall(r'<a\s+id="([^"]+)"\s*></a>', document))
    links = re.findall(r"\]\(#([^)]+)\)", document)
    return targets, links


def _qa_checks(
    review: CaseReviewModel,
    markdown_documents: dict[Audience, str],
    html_documents: dict[Audience, str],
    pdf_documents: dict[Audience, tuple[bytes, bool | None, int]],
    *,
    pdf_requested: bool,
) -> tuple[QACheck, ...]:
    pages = (
        review.findings.page,
        review.findings.evidence_page,
        review.findings.revision_page,
    )
    complete = all(not page.truncated for page in pages)
    checks: list[QACheck] = [
        QACheck(
            "fact_model_complete",
            "pass" if complete else "fail",
            True,
            "all findings, anchors, and revisions are present"
            if complete
            else (
                "bounded review projection is truncated; increase product limits "
                "before publication"
            ),
        )
    ]
    anchors_complete = all(
        len(claim.anchors) == claim.anchor_count
        for finding in _all_findings(review)
        for claim in finding.claims
    )
    checks.append(
        QACheck(
            "anchor_completeness",
            "pass" if anchors_complete else "fail",
            True,
            "every claim carries all recorded exact anchors"
            if anchors_complete
            else "one or more claims omit recorded anchors",
        )
    )
    checks.append(
        QACheck(
            "audit_integrity",
            "pass" if review.audit.integrity_ok else "fail",
            True,
            review.audit.message,
        )
    )
    expected_states = _expected_claim_states(review)
    for audience in AUDIENCES:
        typed_audience = cast(Audience, audience)
        markdown_targets, markdown_links = _markdown_proof_targets(
            markdown_documents[typed_audience]
        )
        missing_markdown = sorted(set(markdown_links) - markdown_targets)
        checks.append(
            QACheck(
                f"{audience}_markdown_proof_links",
                "pass" if not missing_markdown else "fail",
                True,
                "all Markdown proof links resolve"
                if not missing_markdown
                else "missing targets: " + ", ".join(missing_markdown[:10]),
            )
        )
        parser = _PublicationHTMLParser()
        parser.feed(html_documents[typed_audience])
        missing = sorted(set(parser.fragments) - parser.ids)
        checks.append(
            QACheck(
                f"{audience}_proof_links",
                "pass" if not missing else "fail",
                True,
                "all internal proof links resolve"
                if not missing
                else "missing targets: " + ", ".join(missing[:10]),
            )
        )
        rendered_states = {
            claim_id: states[0]
            for claim_id, states in parser.claim_states.items()
            if states and len(set(states)) == 1
        }
        exact_states = rendered_states == expected_states
        checks.append(
            QACheck(
                f"{audience}_epistemic_labels",
                "pass" if exact_states else "fail",
                True,
                "rendered claim labels exactly match the fact model"
                if exact_states
                else (
                    "rendered claim labels are missing, duplicated inconsistently, or strengthened"
                ),
            )
        )
        checks.append(
            QACheck(
                f"{audience}_visible_content",
                "pass" if parser.visible_characters >= 80 else "fail",
                True,
                f"{parser.visible_characters} non-whitespace visible characters",
            )
        )

        pdf = pdf_documents.get(typed_audience)
        if pdf is None:
            checks.append(
                QACheck(
                    f"{audience}_pdf",
                    "skipped",
                    False,
                    "PDF not requested or optional WeasyPrint dependency unavailable",
                )
            )
        else:
            value, geometry_ok, count = pdf
            valid = value.startswith(b"%PDF-") and len(value) > 100 and geometry_ok is True
            checks.append(
                QACheck(
                    f"{audience}_pdf",
                    "pass" if valid else "fail",
                    pdf_requested,
                    f"{count} page(s), PDF header and non-zero page geometry checked",
                )
            )
    return tuple(checks)


def _qa_passed(checks: tuple[QACheck, ...]) -> bool:
    return all(check.status != "fail" for check in checks if check.blocking)


class PublicationManager:
    """Create, verify, and approve state-bound multi-audience publications."""

    def __init__(self, case_id: str, db_dir: Path) -> None:
        if not case_id or Path(case_id).name != case_id:
            raise PublicationError("case_id must be one non-empty path segment")
        self.case_id = case_id
        self.db_dir = Path(db_dir).expanduser().resolve(strict=False)
        self.manifest_path = self.db_dir / f"{case_id}.publication.json"

    def _query(self) -> CaseReviewModel:
        return query_case_review(
            ReviewQuery(
                case_id=self.case_id,
                db_dir=self.db_dir,
                finding_limit=MAX_FINDING_LIMIT,
                evidence_limit=MAX_EVIDENCE_LIMIT,
                revision_limit=MAX_REVISION_LIMIT,
            )
        )

    @staticmethod
    def _fact_payload(review: CaseReviewModel) -> dict[str, object]:
        return cast(dict[str, object], review.model_dump(mode="json", by_alias=True))

    def create_draft(self, *, generate_pdf: bool = True) -> Path:
        """Render all audience views from one snapshot and write a DRAFT sidecar."""
        previous_hash: str | None = None
        if self.manifest_path.is_file():
            previous = self.read()
            integrity = previous.get("integrity")
            if isinstance(integrity, dict):
                raw_hash = integrity.get("manifest_hash")
                previous_hash = raw_hash if isinstance(raw_hash, str) else None

        review = self._query()
        fact_payload = self._fact_payload(review)
        fact_digest = _domain_digest(b"mulder.case-review-publication:v1", fact_payload)
        if self.manifest_path.is_file():
            existing = self.read()
            existing_fact = existing.get("fact_model")
            if (
                existing.get("state") == "APPROVED"
                and isinstance(existing_fact, dict)
                and existing_fact.get("digest") == fact_digest
            ):
                raise PublicationError("refusing to downgrade the current APPROVED publication")

        rendered = {
            cast(Audience, audience): _render_audience(
                review, cast(Audience, audience), fact_digest, generate_pdf=generate_pdf
            )
            for audience in AUDIENCES
        }
        html_documents = {audience: value.html for audience, value in rendered.items()}
        markdown_documents = {audience: value.markdown for audience, value in rendered.items()}
        pdf_documents = {
            audience: (value.pdf, value.pdf_page_geometry_ok, value.pdf_page_count)
            for audience, value in rendered.items()
            if value.pdf is not None
        }
        checks = _qa_checks(
            review,
            markdown_documents,
            html_documents,
            pdf_documents,
            pdf_requested=generate_pdf,
        )
        artifacts: list[RenderedArtifact] = []
        for audience, value in rendered.items():
            outputs: list[tuple[Literal["markdown", "html", "pdf"], bytes]] = [
                ("markdown", value.markdown.encode("utf-8")),
                ("html", value.html.encode("utf-8")),
            ]
            if value.pdf is not None:
                outputs.append(("pdf", value.pdf))
            for format_name, content in outputs:
                extension = "md" if format_name == "markdown" else format_name
                name = f"{self.case_id}.publication.{audience}.{extension}"
                _atomic_write(self.db_dir / name, content)
                artifacts.append(
                    RenderedArtifact(
                        name=name,
                        audience=audience,
                        format=format_name,
                        sha256=_bytes_digest(content),
                        size_bytes=len(content),
                    )
                )

        workflow = ReviewWorkflow(self.case_id, self.db_dir)
        try:
            claim_digest, audit_head = workflow.snapshot_digests()
        except ReviewWorkflowError:
            claim_digest, audit_head = "unavailable", review.audit.head_hash or "unavailable"
        manifest: dict[str, object] = {
            "schema": PUBLICATION_SCHEMA,
            "version": PUBLICATION_VERSION,
            "state": "DRAFT",
            "case_id": self.case_id,
            "created_at": _now(),
            "previous_manifest_hash": previous_hash,
            "fact_model": {
                "schema": review.review_schema,
                "version": review.version,
                "digest": fact_digest,
                "claim_set_digest": claim_digest,
                "audit_head_digest": audit_head,
            },
            "audiences": list(AUDIENCES),
            "artifacts": [asdict(artifact) for artifact in artifacts],
            "qa": {"passed": _qa_passed(checks), "checks": [asdict(check) for check in checks]},
            "approval": None,
            "integrity": {"algorithm": "sha256"},
        }
        cast(dict[str, object], manifest["integrity"])["manifest_hash"] = _manifest_hash(manifest)
        _atomic_write(
            self.manifest_path,
            json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
            + b"\n",
        )
        return self.manifest_path

    def approve(self) -> Path:
        """Promote a verified DRAFT whose facts and artifacts are still current."""
        manifest = self.read()
        if manifest.get("state") != "DRAFT":
            raise PublicationError("only a DRAFT publication can be approved")
        prior_qa = manifest.get("qa")
        if not isinstance(prior_qa, dict) or prior_qa.get("passed") is not True:
            raise PublicationError("publication QA failed in the rendered draft")
        review = self._query()
        current_digest = _domain_digest(
            b"mulder.case-review-publication:v1", self._fact_payload(review)
        )
        fact_model = manifest.get("fact_model")
        if not isinstance(fact_model, dict) or fact_model.get("digest") != current_digest:
            raise PublicationError("publication fact model is stale; render a new draft")

        artifacts_raw = manifest.get("artifacts")
        if not isinstance(artifacts_raw, list):
            raise PublicationError("publication artifact commitments are missing")
        html_documents: dict[Audience, str] = {}
        markdown_documents: dict[Audience, str] = {}
        pdf_documents: dict[Audience, tuple[bytes, bool | None, int]] = {}
        seen_outputs: set[tuple[Audience, str]] = set()
        for raw in artifacts_raw:
            if not isinstance(raw, dict):
                raise PublicationError("publication artifact entry is invalid")
            name = raw.get("name")
            audience = raw.get("audience")
            format_name = raw.get("format")
            if (
                not isinstance(name, str)
                or audience not in AUDIENCES
                or format_name not in {"markdown", "html", "pdf"}
            ):
                raise PublicationError("publication artifact identity is invalid")
            typed_audience = cast(Audience, audience)
            output_key = (typed_audience, cast(str, format_name))
            if output_key in seen_outputs:
                raise PublicationError("publication artifact entry is duplicated")
            seen_outputs.add(output_key)
            extension = "md" if format_name == "markdown" else format_name
            expected_name = f"{self.case_id}.publication.{audience}.{extension}"
            if name != expected_name:
                raise PublicationError(
                    f"publication artifact name does not match its audience/format: {name}"
                )
            path = (self.db_dir / name).resolve(strict=False)
            if path.parent != self.db_dir or not path.is_file():
                raise PublicationError(
                    f"publication artifact is missing or outside db_dir: {name}"
                )
            content = path.read_bytes()
            if raw.get("sha256") != _bytes_digest(content) or raw.get("size_bytes") != len(
                content
            ):
                raise PublicationError(f"publication artifact changed after QA: {name}")
            if format_name == "html":
                try:
                    html_documents[typed_audience] = content.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise PublicationError(f"publication HTML is not UTF-8: {name}") from exc
            elif format_name == "markdown":
                try:
                    markdown_documents[typed_audience] = content.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise PublicationError(f"publication Markdown is not UTF-8: {name}") from exc
            else:
                # Page geometry was checked at render time. At approval time the
                # exact-byte commitment and PDF header remain independently checkable.
                pdf_documents[typed_audience] = (content, True, 1)
        if set(html_documents) != set(AUDIENCES):
            raise PublicationError("publication must contain one HTML view per audience")
        if set(markdown_documents) != set(AUDIENCES):
            raise PublicationError("publication must contain one Markdown view per audience")

        checks = _qa_checks(
            review,
            markdown_documents,
            html_documents,
            pdf_documents,
            pdf_requested=bool(pdf_documents),
        )
        if not _qa_passed(checks):
            failures = ", ".join(
                check.name for check in checks if check.blocking and check.status == "fail"
            )
            raise PublicationError(f"publication QA failed: {failures}")
        try:
            approval = ReviewWorkflow(self.case_id, self.db_dir).require_approved_state()
        except ReviewWorkflowError as exc:
            raise PublicationError(
                f"publication approval requires analyst approval: {exc}"
            ) from exc
        if fact_model.get("claim_set_digest") != approval.claim_set_digest:
            raise PublicationError("analyst approval does not bind the publication claim set")

        manifest["state"] = "APPROVED"
        manifest["approved_at"] = _now()
        manifest["qa"] = {"passed": True, "checks": [asdict(check) for check in checks]}
        manifest["approval"] = approval.as_mapping()
        manifest["integrity"] = {"algorithm": "sha256"}
        cast(dict[str, object], manifest["integrity"])["manifest_hash"] = _manifest_hash(manifest)
        _atomic_write(
            self.manifest_path,
            json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
            + b"\n",
        )
        return self.manifest_path

    def read(self) -> dict[str, object]:
        """Read and verify the publication sidecar's self-commitment."""
        try:
            raw = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise PublicationError(f"publication sidecar not found: {self.manifest_path}") from exc
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PublicationError(f"publication sidecar is unreadable: {exc}") from exc
        if (
            not isinstance(raw, dict)
            or raw.get("schema") != PUBLICATION_SCHEMA
            or raw.get("version") != PUBLICATION_VERSION
            or raw.get("state") not in {"DRAFT", "APPROVED"}
            or raw.get("case_id") != self.case_id
        ):
            raise PublicationError("unsupported publication sidecar")
        manifest = cast(dict[str, object], raw)
        integrity = manifest.get("integrity")
        expected = integrity.get("manifest_hash") if isinstance(integrity, dict) else None
        if not isinstance(expected, str) or expected != _manifest_hash(manifest):
            raise PublicationError("publication sidecar integrity check failed")
        return manifest


__all__ = [
    "AUDIENCES",
    "PUBLICATION_SCHEMA",
    "PUBLICATION_VERSION",
    "PublicationError",
    "PublicationManager",
    "QACheck",
    "RenderedArtifact",
]
