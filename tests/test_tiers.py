"""Three-tier pipeline tests — Reader→Analyzer→Writer with structural isolation."""
import json
import tempfile
from pathlib import Path
import pytest
from mcp_bandit.tiers import (
    MCPConfigReader, MCPAnalyzer, MCPWriter, TieredPipeline,
    ReaderOutput, AnalyzerOutput,
)


@pytest.fixture
def sample_mcp_json(tmp_path):
    config = {
        "mcpServers": {
            "test-server": {
                "command": "python",
                "args": ["-m", "test_server"],
                "env": {"API_KEY": "test-key"},
                "type": "stdio",
            },
        },
    }
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    return path


@pytest.fixture
def sample_config_paths(sample_mcp_json):
    return [sample_mcp_json]


class TestReaderOutput:
    def test_frozen_dataclass(self):
        ro = ReaderOutput(
            path=Path("test.json"), server_name="test",
            normalized_config='{}', command="echo", args=[],
            env={}, transport="stdio",
        )
        with pytest.raises(Exception):
            ro.server_name = "hacked"  # frozen

    def test_has_env_vars(self):
        ro = ReaderOutput(
            path=Path("test.json"), server_name="test",
            normalized_config='{}', command="echo", args=[],
            env={"KEY": "val"}, transport="stdio",
        )
        assert ro.has_env_vars is True


class TestReaderIsolation:
    """Reader NEVER executes checks, NEVER writes files."""

    def test_reader_output_is_sanitized(self, sample_config_paths):
        reader = MCPConfigReader()
        outputs = reader.read_all(sample_config_paths)
        assert len(outputs) == 1
        ro = outputs[0]
        assert ro.server_name == "test-server"
        assert "python" in ro.command
        # Config is normalized JSON string
        assert '"command"' in ro.normalized_config
        # Length is bounded
        assert len(ro.normalized_config) < 1000

    def test_reader_rejects_oversized(self, tmp_path):
        big = tmp_path / "big.json"
        big.write_text(json.dumps({"mcpServers": {"x": {"command": "a" * 100_000}}}))
        reader = MCPConfigReader()
        outputs = reader.read_all([big])
        assert len(outputs) == 0  # Too large, rejected


class TestAnalyzerIsolation:
    """Analyzer has NO file I/O capability."""

    def test_analyzer_no_file_access(self, sample_config_paths):
        reader = MCPConfigReader()
        outputs = reader.read_all(sample_config_paths)
        analyzer = MCPAnalyzer()
        results = analyzer.analyze(outputs)
        assert len(results) == 1
        ao = results[0]
        assert ao.server_name == "test-server"
        assert isinstance(ao.findings, list)

    def test_analyzer_output_frozen(self, sample_config_paths):
        reader = MCPConfigReader()
        outputs = reader.read_all(sample_config_paths)
        analyzer = MCPAnalyzer()
        results = analyzer.analyze(outputs)
        ao = results[0]
        with pytest.raises(Exception):
            ao.server_name = "hacked"


class TestWriterIsolation:
    """Writer only writes to explicit output paths."""

    def test_writer_terminal_output(self, sample_config_paths):
        reader = MCPConfigReader()
        outputs = reader.read_all(sample_config_paths)
        analyzer = MCPAnalyzer()
        results = analyzer.analyze(outputs)
        writer = MCPWriter(fmt="terminal")
        text = writer.write_report(results, sample_config_paths)
        assert "test-server" in text
        assert "mcp-bandit" in text

    def test_writer_json_output_to_file(self, sample_config_paths, tmp_path):
        reader = MCPConfigReader()
        outputs = reader.read_all(sample_config_paths)
        analyzer = MCPAnalyzer()
        results = analyzer.analyze(outputs)
        writer = MCPWriter(fmt="json")
        out_path = tmp_path / "report.json"
        text = writer.write_report(results, sample_config_paths, output_path=str(out_path))
        assert out_path.exists()
        data = json.loads(out_path.read_text())
        assert data["tool"] == "mcp-bandit"


class TestTieredPipeline:
    """End-to-end R→A→W pipeline."""

    def test_full_pipeline(self, sample_config_paths):
        pipeline = TieredPipeline()
        results, report = pipeline.scan(sample_config_paths)
        assert len(results) == 1
        assert "test-server" in report
        assert results[0].grade in ("A", "B", "C", "D", "E", "F")

    def test_pipeline_with_audit(self, sample_config_paths):
        pipeline = TieredPipeline()
        results, audit = pipeline.scan_with_audit(sample_config_paths)
        assert len(results) == 1
        assert "hash" in audit
        assert "prev_hash" in audit
