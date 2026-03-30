from __future__ import annotations

from malware_analyzer.config.settings import get_settings
from malware_analyzer.detection import similarity as similarity_engine
from malware_analyzer.storage.database import connect_db, init_db


def _insert_sample(
    *,
    sha256: str,
    file_name: str,
    family: str,
    imphash: str,
    ssdeep: str,
    tlsh: str,
) -> None:
    conn = connect_db()
    try:
        conn.execute(
            """
            INSERT INTO samples (
                sha256, file_name, file_path, file_size, file_type, platform,
                architecture, mime_type, packed, packer, md5, sha1,
                tlsh, ssdeep, imphash, local_score, intel_score, score,
                family, family_confidence, source, tags, raw_json
            ) VALUES (
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?
            )
            ON CONFLICT(sha256) DO UPDATE SET
                file_name=excluded.file_name,
                tlsh=excluded.tlsh,
                ssdeep=excluded.ssdeep,
                imphash=excluded.imphash,
                family=excluded.family
            """,
            (
                sha256,
                file_name,
                f"/tmp/{file_name}",
                1024,
                "PE32",
                "Windows",
                "x86",
                "application/octet-stream",
                0,
                "",
                "",
                "",
                tlsh,
                ssdeep,
                imphash,
                10.0,
                0.0,
                10.0,
                family,
                "low",
                "Local",
                "",
                "{}",
            ),
        )
        conn.commit()
    finally:
        conn.close()


def test_similarity_engine_db_lookups(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("MSA_OUTPUT_DIR", str(tmp_path / "output"))
    get_settings.cache_clear()

    init_db()

    sha_target = "a" * 64
    sha_imphash = "b" * 64
    sha_ssdeep = "c" * 64
    sha_tlsh = "d" * 64

    shared_imphash = "1" * 32

    _insert_sample(
        sha256=sha_target,
        file_name="target.exe",
        family="Win.Injector.Generic",
        imphash=shared_imphash,
        ssdeep="ssdeep-target",
        tlsh="tlsh-target",
    )
    _insert_sample(
        sha256=sha_imphash,
        file_name="imphash.exe",
        family="Win.Injector.Generic",
        imphash=shared_imphash,
        ssdeep="ssdeep-imphash",
        tlsh="tlsh-imphash",
    )
    _insert_sample(
        sha256=sha_ssdeep,
        file_name="ssdeep.exe",
        family="Win.Generic",
        imphash="2" * 32,
        ssdeep="ssdeep-near",
        tlsh="tlsh-other",
    )
    _insert_sample(
        sha256=sha_tlsh,
        file_name="tlsh.exe",
        family="Win.Generic",
        imphash="3" * 32,
        ssdeep="ssdeep-other",
        tlsh="tlsh-near",
    )

    monkeypatch.setattr(similarity_engine, "compare_ssdeep", lambda left, right: 42 if "near" in right else 0)
    monkeypatch.setattr(similarity_engine, "compare_tlsh", lambda left, right: 12 if "near" in right else 300)

    by_imphash = similarity_engine.find_similar_by_imphash(sha_target)
    by_ssdeep = similarity_engine.find_similar_by_ssdeep(sha_target)
    by_tlsh = similarity_engine.find_similar_by_tlsh(sha_target)
    combined = similarity_engine.find_similar_samples(sha_target, limit=10)

    assert any(str(item.get("sha256", "")) == sha_imphash for item in by_imphash)
    assert any(str(item.get("sha256", "")) == sha_ssdeep for item in by_ssdeep)
    assert any(str(item.get("sha256", "")) == sha_tlsh for item in by_tlsh)

    reasons = {str(item.get("sha256", "")): str(item.get("reason", "")) for item in combined}
    assert sha_imphash in reasons
    assert "imphash" in reasons[sha_imphash]
    assert sha_ssdeep in reasons
    assert "ssdeep=" in reasons[sha_ssdeep]
    assert sha_tlsh in reasons
    assert "tlsh=" in reasons[sha_tlsh]

    monkeypatch.delenv("MSA_OUTPUT_DIR", raising=False)
    get_settings.cache_clear()
