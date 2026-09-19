"""CLI smoke tests using Click's CliRunner."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

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


class TestMaxCompactions:
    """``--max-compactions`` and ``MULDER_MAX_COMPACTIONS`` reach the orchestrator."""

    @staticmethod
    def _invoke(args: list[str], env: dict[str, str] | None = None) -> tuple[int, MagicMock]:
        runner = CliRunner()
        with (
            patch("mulder.orchestrator.runner.Orchestrator") as orchestrator_cls,
            patch("asyncio.run", return_value=MagicMock(success=True)),
        ):
            result = runner.invoke(cli, ["investigate", "/evidence", "case-1", *args], env=env)
        return result.exit_code, orchestrator_cls

    def _max_compactions(self, args: list[str], env: dict[str, str] | None = None) -> int:
        exit_code, cls = self._invoke(args, env)
        assert exit_code == 0
        value: int = cls.call_args.kwargs["max_compactions"]
        return value

    def test_default_is_three(self) -> None:
        assert self._max_compactions([]) == 3

    def test_flag(self) -> None:
        assert self._max_compactions(["--max-compactions", "7"]) == 7

    def test_env_var(self) -> None:
        assert self._max_compactions([], env={"MULDER_MAX_COMPACTIONS": "5"}) == 5

    def test_flag_beats_env_var(self) -> None:
        args = ["--max-compactions", "7"]
        assert self._max_compactions(args, env={"MULDER_MAX_COMPACTIONS": "5"}) == 7

    def test_negative_is_rejected(self) -> None:
        exit_code, _ = self._invoke(["--max-compactions", "-1"])
        assert exit_code != 0
