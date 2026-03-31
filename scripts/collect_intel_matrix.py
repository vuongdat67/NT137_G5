from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from malware_analyzer.intelligence.bazaar_client import BazaarClient, BazaarQuery
from malware_analyzer.storage.repository import SampleRepository


def _parse_query(query: str) -> tuple[str, str]:
    text = query.strip()
    if not text or ":" not in text:
        raise ValueError(f"Invalid query: {query}")

    key, value = text.split(":", 1)
    prefix = key.strip().lower()
    data = value.strip()
    if not data:
        raise ValueError(f"Query value is empty: {query}")

    mapping = {
        "file_type": "By File Type",
        "tag": "By Tag",
        "signature": "By Family",
        "hash": "By Hash",
        "yara": "By YARA",
        "issuer": "By Issuer",
        "serial": "By Serial",
    }
    mode = mapping.get(prefix)
    if mode is None:
        raise ValueError(f"Unsupported query prefix '{prefix}' in: {query}")
    return mode, data


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect MalwareBazaar intel by query list (file_type/tag/signature) and optionally apply to local DB."
    )
    parser.add_argument(
        "--query",
        action="append",
        default=[],
        help="Query expression, for example file_type:exe, tag:ransomware, signature:RemcosRAT.",
    )
    parser.add_argument("--limit-per-query", type=int, default=200, help="Max rows for each query.")
    parser.add_argument("--api-key", type=str, default="", help="Optional MalwareBazaar API key.")
    parser.add_argument("--apply", action="store_true", default=True, help="Apply fetched intel to local DB.")
    parser.add_argument("--no-apply", dest="apply", action="store_false", help="Skip applying intel to local DB.")
    parser.add_argument(
        "--output-json",
        type=Path,
        default=Path("output") / "intel" / "collect_intel_matrix_latest.json",
        help="Path to write JSON summary report.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    queries = list(args.query)
    if not queries:
        queries = [
            "file_type:exe",
            "file_type:dll",
            "file_type:apk",
            "file_type:elf",
            "tag:ransomware",
            "tag:stealer",
            "tag:rat",
            "signature:RemcosRAT",
            "signature:AsyncRAT",
            "signature:AgentTesla",
        ]

    client = BazaarClient()
    repository = SampleRepository() if bool(args.apply) else None

    summary = {
        "timestamp_utc": datetime.now(tz=timezone.utc).isoformat(),
        "limit_per_query": max(1, int(args.limit_per_query)),
        "apply_to_db": bool(args.apply),
        "queries": [],
        "total_fetched": 0,
        "total_applied": 0,
        "total_skipped": 0,
        "last_error": "",
    }

    for raw in queries:
        mode, value = _parse_query(raw)
        entries = client.query(
            BazaarQuery(mode=mode, value=value, limit=max(1, int(args.limit_per_query))),
            api_key=str(args.api_key or "").strip(),
        )

        fetched = len(entries)
        applied = 0
        skipped = 0
        if repository is not None and entries:
            applied, skipped = repository.apply_intel_entries(entries, source="MalwareBazaar")

        query_item = {
            "query": raw,
            "mode": mode,
            "value": value,
            "fetched": fetched,
            "applied": applied,
            "skipped": skipped,
            "error": str(client.last_error or ""),
        }
        summary["queries"].append(query_item)
        summary["total_fetched"] += fetched
        summary["total_applied"] += applied
        summary["total_skipped"] += skipped
        if client.last_error:
            summary["last_error"] = str(client.last_error)

    out_path = Path(args.output_json)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, ensure_ascii=True, indent=2), encoding="utf-8")

    print(out_path)
    print(json.dumps(summary, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
