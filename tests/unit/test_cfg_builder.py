from __future__ import annotations

from pathlib import Path

import pytest

import malware_analyzer.core.cfg_builder as cfg_builder
from malware_analyzer.core.models import FileInfo, FileType


def _pe_info() -> FileInfo:
    return FileInfo(
        file_path="sample.exe",
        file_name="sample.exe",
        file_size=4096,
        file_type=FileType.PE32,
        platform="Windows",
    )


def test_cfg_builder_skips_large_function_ranges() -> None:
    if cfg_builder.capstone is None:
        pytest.skip("capstone unavailable")

    data = b"\x90" * 2048
    result = cfg_builder.build_cfg(
        Path("sample.exe"),
        _pe_info(),
        data,
        max_disasm_bytes=2048,
        max_function_size_bytes=64,
    )

    assert int(result.get("cfg_skipped_functions", 0)) >= 1


class _FakeGraph:
    def __init__(self, comment: str, format: str) -> None:
        self.comment = comment
        self.format = format
        self.nodes: list[str] = []
        self.edges: list[tuple[str, str]] = []

    def attr(self, **kwargs) -> None:
        _ = kwargs

    def node(self, node_id: str, label: str, shape: str, fontsize: str) -> None:
        _ = (label, shape, fontsize)
        self.nodes.append(node_id)

    def edge(self, src: str, dst: str) -> None:
        self.edges.append((src, dst))

    def pipe(self, format: str) -> bytes:
        _ = format
        return b"<svg><g id='cfg'></g></svg>"


def test_cfg_builder_render_cfg_svg(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cfg_builder, "GraphvizDigraph", _FakeGraph)

    output_path = tmp_path / "cfg.svg"
    svg = cfg_builder.render_cfg(
        {
            "nodes": 3,
            "graph_edges": [[0, 1], [1, 2]],
        },
        output_path=output_path,
    )

    assert svg.startswith("<svg")
    assert output_path.exists()
