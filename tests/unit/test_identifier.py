from __future__ import annotations

from pathlib import Path
import zipfile

from malware_analyzer.core.identifier import identify
from malware_analyzer.core.models import FileType


def test_identify_unknown_file(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"not-a-binary")

    info = identify(sample)
    assert info.file_type == FileType.UNKNOWN
    assert info.file_size > 0


def test_identify_dex_file(tmp_path: Path) -> None:
    sample = tmp_path / "classes.dex"
    sample.write_bytes(b"dex\n035\x00")

    info = identify(sample)
    assert info.file_type == FileType.DEX
    assert info.platform == "Android"


def test_identify_elf_file(tmp_path: Path) -> None:
    sample = tmp_path / "app.elf"
    sample.write_bytes(b"\x7fELF\x02\x01\x01")

    info = identify(sample)
    assert info.file_type == FileType.ELF


def test_identify_apk_archive_without_apk_extension(tmp_path: Path) -> None:
    sample = tmp_path / "sample_no_ext.bin"
    with zipfile.ZipFile(sample, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")

    info = identify(sample)
    assert info.file_type == FileType.APK
    assert info.platform == "Android"
