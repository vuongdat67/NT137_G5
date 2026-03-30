from __future__ import annotations

from malware_analyzer.core.extractors.string_extractor import classify_strings, extract_strings


def test_string_extractor_extracts_ascii_utf16_and_classifies() -> None:
    data = (
        b"http://evil.test/path "
        b"192.168.1.10 "
        b"admin@example.com "
        b"HKEY_LOCAL_MACHINE\\Software\\Demo "
        b"Global\\DemoMutex_01 "
        b"C:\\Windows\\System32\\cmd.exe "
        b"ZXZpbF9wYXlsb2FkX2RhdGE= "
        b"expand 32-byte k "
        + bytes.fromhex("01020408102040801b36")
        + b"T\x00E\x00S\x00T\x00"
    )

    strings = extract_strings(data)
    classified = classify_strings(strings, data=data)

    assert any("http://evil.test/path" in item for item in classified["urls"])
    assert any("192.168.1.10" in item for item in classified["ips"])
    assert any("admin@example.com" in item for item in classified["emails"])
    assert any("HKEY_LOCAL_MACHINE\\Software\\Demo" in item for item in classified["registry"])
    assert any("Global\\DemoMutex_01" in item for item in classified["mutex"])
    assert any("C:\\Windows\\System32\\cmd.exe" in item for item in classified["filepaths"])
    assert any("ZXZpbF9wYXlsb2FkX2RhdGE=" in item for item in classified["b64"])
    assert any("evil_payload_data" in item for item in classified["b64_decoded"])
    assert any(item in {"AES_RCON", "CHACHA_CONSTANT", "CRYPTO_KEYWORD"} for item in classified["crypto_constants"])
    assert any("TEST" in item for item in strings)
