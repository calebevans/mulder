"""CLI smoke tests using Click's CliRunner."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from mulder.cli import cli


class TestCliHelp:
    """Tests for basic CLI help and version output."""

    def test_help_succeeds(self) -> None:
        """--help flag exits 0 with usage text."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "Usage" in result.output
        assert "forensic" in result.output.lower() or "mulder" in result.output.lower()

    def test_version_succeeds(self) -> None:
        """--version flag exits 0 with version info."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "mulder" in result.output.lower()


class TestCliInvalidOptions:
    """Tests for invalid option handling."""

    def test_invalid_option_fails(self) -> None:
        """Unknown option exits non-zero."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--nonexistent-flag"])
        assert result.exit_code != 0

    def test_serve_help(self) -> None:
        """serve --help exits 0 with transport options."""
        runner = CliRunner()
        result = runner.invoke(cli, ["serve", "--help"])
        assert result.exit_code == 0
        assert "transport" in result.output


class TestCliInvestigate:
    """Tests for the investigate command validation."""

    def test_investigate_requires_evidence(self) -> None:
        """investigate command without evidence path fails gracefully."""
        runner = CliRunner()
        result = runner.invoke(cli, ["investigate"])
        assert result.exit_code != 0

    def test_investigate_help(self) -> None:
        """investigate --help exits 0 and shows evidence_path argument."""
        runner = CliRunner()
        result = runner.invoke(cli, ["investigate", "--help"])
        assert result.exit_code == 0
        assert "EVIDENCE_PATH" in result.output
        assert "--data-policy" in result.output
        assert "--airgap" in result.output

    def test_airgap_preflight_rejects_default_cloud_models(self, tmp_path: Path) -> None:
        """CLI fails before constructing an orchestrator for cloud routes."""
        runner = CliRunner()
        with patch("mulder.orchestrator.runner.Orchestrator") as orchestrator:
            result = runner.invoke(
                cli,
                [
                    "investigate",
                    "/evidence",
                    "case-42",
                    "--airgap",
                    "--cwd",
                    str(tmp_path / "workspace"),
                    "--db-dir",
                    str(tmp_path / "cases"),
                ],
            )
        assert result.exit_code != 0
        assert "zero-egress preflight failed" in result.output
        orchestrator.assert_not_called()


class TestCliExportCommands:
    """Tests for export subcommand help texts."""

    def test_export_iocs_help(self) -> None:
        """export-iocs --help exits 0."""
        runner = CliRunner()
        result = runner.invoke(cli, ["export-iocs", "--help"])
        assert result.exit_code == 0
        assert "CASE_ID" in result.output

    def test_export_navigator_help(self) -> None:
        """export-navigator --help exits 0."""
        runner = CliRunner()
        result = runner.invoke(cli, ["export-navigator", "--help"])
        assert result.exit_code == 0
        assert "CASE_ID" in result.output
