from __future__ import annotations

from pathlib import Path

from malware_analyzer.core.models import FileInfo, FileType
from malware_analyzer.core.parsers.apk_parser import APKParser


class _FakeAPK:
    def __init__(self, _path: str) -> None:
        pass

    def get_package(self) -> str:
        return "com.example.demo"

    def get_permissions(self) -> list[str]:
        return [
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.INTERNET",
        ]

    def get_certificates(self) -> list[object]:
        class _Name:
            def __init__(self, value: str) -> None:
                self.human_friendly = value

        class _Cert:
            issuer = _Name("CN=Demo")
            subject = _Name("CN=Demo")

        return [_Cert()]

    def get_activities(self) -> list[str]:
        return ["com.example.demo.MainActivity"]

    def get_services(self) -> list[str]:
        return ["com.example.demo.SyncService"]

    def get_receivers(self) -> list[str]:
        return ["com.example.demo.BootReceiver"]

    def get_intent_filters(self, component_type: str, name: str) -> dict[str, list[str]]:
        if component_type == "receiver":
            return {"action": ["android.intent.action.BOOT_COMPLETED"]}
        return {"action": ["android.intent.action.VIEW"]}

    def get_files(self) -> list[str]:
        return [
            "AndroidManifest.xml",
            "classes.dex",
            "lib/arm64-v8a/libnative.so",
        ]

    def get_all_dex(self) -> list[bytes]:
        return [
            b"Landroid/content/Intent;->setAction\x00"
            b"Landroid/telephony/SmsManager;->sendTextMessage\x00"
            b"BOOT_COMPLETED\x00"
            b"H\x00E\x00L\x00L\x00O\x00",
        ]


def _apk_info(path: Path) -> FileInfo:
    return FileInfo(
        file_path=str(path),
        file_name=path.name,
        file_size=2048,
        file_type=FileType.APK,
        platform="Android",
    )


def test_apk_parser_extracts_intents_api_calls_native_libs_and_strings(monkeypatch, tmp_path: Path) -> None:
    sample = tmp_path / "sample.apk"
    sample.write_bytes(b"PK\x03\x04")

    monkeypatch.setattr("malware_analyzer.core.parsers.apk_parser.AndroguardAPK", _FakeAPK)

    parser = APKParser()
    parsed = parser.parse(sample, _apk_info(sample), sample.read_bytes())

    assert parsed.get("apk_package_name") == "com.example.demo"
    assert int(parsed.get("apk_permissions_count", 0)) >= 2
    assert "android.intent.action.BOOT_COMPLETED" in parsed.get("apk_intents", [])
    assert int(parsed.get("apk_intents_count", 0)) >= 1
    assert "lib/arm64-v8a/libnative.so" in parsed.get("apk_native_libs", [])
    assert int(parsed.get("apk_native_libs_count", 0)) == 1

    api_calls = parsed.get("apk_api_calls", [])
    assert isinstance(api_calls, list)
    assert any("SmsManager" in str(item) for item in api_calls)

    api_classes = parsed.get("apk_api_classes", [])
    assert isinstance(api_classes, list)
    assert any("Landroid/telephony/SmsManager;" in str(item) for item in api_classes)

    strings = parsed.get("apk_strings", [])
    assert isinstance(strings, list)
    assert any("BOOT_COMPLETED" in str(item) for item in strings)
    assert bool(parsed.get("apk_is_self_signed", False)) is True
