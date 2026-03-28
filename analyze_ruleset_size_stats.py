#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import heapq
from pathlib import Path
from statistics import mean
from typing import Dict, Iterable, List, Sequence

from synthclass.core import FIELD_NAMES, discover_rulesets, load_ruleset


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze ClassBench ruleset folders by size bucket and summarize endpoint/overlap statistics."
    )
    parser.add_argument(
        "--size-folders",
        nargs="+",
        required=True,
        help="Ordered ruleset folders or files to analyze, e.g. Rulesets/1k_2k_4k_8k/1k_1 Rulesets/16k_1",
    )
    parser.add_argument(
        "--output-dir",
        default="Output/ruleset_size_stats",
        help="Directory for per-ruleset and per-size summary CSV files",
    )
    parser.add_argument(
        "--ruleset-limit",
        type=int,
        default=0,
        help="Optional limit per size folder for quick smoke tests; 0 means all rulesets",
    )
    return parser.parse_args()


def unique_endpoint_count(rules, field: int) -> int:
    endpoints = set()
    for rule in rules:
        low, high = rule.ranges[field]
        endpoints.add(low)
        endpoints.add(high)
    return len(endpoints)


def overlapping_pair_percentage(rules, field: int) -> float:
    count = len(rules)
    if count < 2:
        return 0.0
    intervals = sorted((rule.ranges[field][0], rule.ranges[field][1]) for rule in rules)
    active_ends: List[int] = []
    overlapping_pairs = 0
    for low, high in intervals:
        while active_ends and active_ends[0] < low:
            heapq.heappop(active_ends)
        overlapping_pairs += len(active_ends)
        heapq.heappush(active_ends, high)
    total_pairs = count * (count - 1) // 2
    return 100.0 * overlapping_pairs / float(total_pairs)


def analyze_ruleset(path: Path, size_label: str) -> Dict[str, object]:
    rules = load_ruleset(path)
    row: Dict[str, object] = {
        "size_label": size_label,
        "ruleset_name": path.name,
        "rule_count": len(rules),
    }
    for field, field_name in enumerate(FIELD_NAMES):
        row[f"{field_name}_unique_endpoints"] = unique_endpoint_count(rules, field)
        row[f"{field_name}_overlapping_pair_pct"] = overlapping_pair_percentage(rules, field)
    return row


def average_rows(size_label: str, rows: Sequence[Dict[str, object]]) -> Dict[str, object]:
    summary: Dict[str, object] = {
        "size_label": size_label,
        "ruleset_count": len(rows),
        "avg_rule_count": mean(float(row["rule_count"]) for row in rows),
    }
    for field_name in FIELD_NAMES:
        summary[f"{field_name}_avg_unique_endpoints"] = mean(
            float(row[f"{field_name}_unique_endpoints"]) for row in rows
        )
        summary[f"{field_name}_avg_overlapping_pair_pct"] = mean(
            float(row[f"{field_name}_overlapping_pair_pct"]) for row in rows
        )
    return summary


def write_csv(path: Path, rows: Sequence[Dict[str, object]]) -> None:
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def iter_bucket_rows(folder_paths: Sequence[Path], ruleset_limit: int) -> Iterable[Dict[str, object]]:
    for folder_path in folder_paths:
        size_label = folder_path.name
        ruleset_paths = discover_rulesets([str(folder_path)])
        if ruleset_limit > 0:
            ruleset_paths = ruleset_paths[:ruleset_limit]
        for ruleset_path in ruleset_paths:
            yield analyze_ruleset(ruleset_path, size_label)


def main() -> None:
    args = parse_args()
    folder_paths = [Path(raw).expanduser().resolve() for raw in args.size_folders]
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    per_ruleset_rows = list(iter_bucket_rows(folder_paths, args.ruleset_limit))
    if not per_ruleset_rows:
        raise SystemExit("No rulesets found for analysis.")

    grouped_rows: Dict[str, List[Dict[str, object]]] = {}
    for row in per_ruleset_rows:
        grouped_rows.setdefault(str(row["size_label"]), []).append(row)
    per_size_rows = [average_rows(size_label, grouped_rows[size_label]) for size_label in grouped_rows]

    write_csv(output_dir / "per_ruleset_statistics.csv", per_ruleset_rows)
    write_csv(output_dir / "per_size_statistics.csv", per_size_rows)

    print(f"Analyzed {len(per_ruleset_rows)} rulesets across {len(per_size_rows)} size buckets.")
    print(f"Wrote per-ruleset statistics to {output_dir / 'per_ruleset_statistics.csv'}")
    print(f"Wrote averaged per-size statistics to {output_dir / 'per_size_statistics.csv'}")


if __name__ == "__main__":
    main()
