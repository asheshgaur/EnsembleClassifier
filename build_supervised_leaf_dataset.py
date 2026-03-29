#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from synthclass import BenchmarkRunner, SynthClassSettings, default_config_catalog, discover_rulesets
from synthclass.supervised import (
    build_leaf_supervision_dataset,
    read_leaf_dataset_jsonl,
    write_leaf_dataset_csv,
    write_leaf_dataset_jsonl,
)


DEFAULT_PORTFOLIO = (
    "PartitionSort",
    "PriorityTuple",
    "HyperCuts",
    "HyperSplit",
    "ByteCuts",
    "CutSplit",
    "TabTree",
    "NPTree",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a supervised SynthClass leaf dataset by benchmarking all techniques on every leaf subset.")
    parser.add_argument("--rulesets", nargs="+", required=True, help="Ruleset files or directories")
    parser.add_argument("--trace-dirs", nargs="*", default=[], help="Optional directories containing packet traces")
    parser.add_argument("--packets-per-ruleset", type=int, default=256)
    parser.add_argument("--leaf-packet-cap", type=int, default=128)
    parser.add_argument("--portfolio", default=",".join(DEFAULT_PORTFOLIO))
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--main-binary", default="")
    parser.add_argument("--output-dir", default="Output/supervised_leaf_dataset")
    parser.add_argument("--benchmark-cache", default="", help="Optional persistent benchmark cache JSONL path")
    parser.add_argument("--append", action="store_true", help="Append new rulesets to an existing leaf dataset instead of rebuilding from scratch")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--alpha", type=float, default=1.0)
    parser.add_argument("--beta", type=float, default=1e-6)
    parser.add_argument("--gamma", type=float, default=1e-3)
    parser.add_argument("--max-depth", type=int, default=5)
    parser.add_argument("--log-every", type=int, default=1)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    ruleset_paths = discover_rulesets(args.rulesets)
    if not ruleset_paths:
        raise SystemExit("No rulesets found.")
    portfolio = tuple(item.strip() for item in args.portfolio.split(",") if item.strip())
    repo_root = Path(args.repo_root).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    cache_path = (
        Path(args.benchmark_cache).expanduser().resolve()
        if args.benchmark_cache
        else output_dir / "benchmark_cache.jsonl"
    )
    benchmark_runner = BenchmarkRunner(
        repo_root=repo_root,
        main_binary=Path(args.main_binary).expanduser().resolve() if args.main_binary else None,
        packet_cap=args.leaf_packet_cap,
        cache_path=cache_path,
    )
    settings = SynthClassSettings(
        alpha=args.alpha,
        beta=args.beta,
        gamma=args.gamma,
        max_depth=args.max_depth,
    )
    dataset_path = output_dir / "leaf_dataset.jsonl"
    csv_dataset_path = output_dir / "leaf_dataset.csv"
    metadata_path = output_dir / "leaf_dataset_metadata.json"
    existing_rows = []
    rulesets_to_process = list(ruleset_paths)
    if args.append and dataset_path.exists():
        existing_rows = read_leaf_dataset_jsonl(dataset_path)
        existing_paths = {
            str(row["source_ruleset_path"])
            for row in existing_rows
            if row.get("source_ruleset_path")
        }
        existing_names = {
            str(row.get("ruleset_name", ""))
            for row in existing_rows
            if not row.get("source_ruleset_path") and row.get("ruleset_name")
        }
        rulesets_to_process = [
            path
            for path in ruleset_paths
            if str(path.resolve()) not in existing_paths and path.name not in existing_names
        ]
        if metadata_path.exists():
            existing_metadata = json.loads(metadata_path.read_text())
            if tuple(existing_metadata.get("portfolio", [])) != portfolio:
                raise SystemExit("Existing dataset portfolio does not match the requested portfolio.")
            if (
                float(existing_metadata.get("alpha", settings.alpha)) != settings.alpha
                or float(existing_metadata.get("beta", settings.beta)) != settings.beta
                or float(existing_metadata.get("gamma", settings.gamma)) != settings.gamma
            ):
                raise SystemExit("Existing dataset objective weights do not match the requested weights.")
    print(
        f"[setup] rulesets={len(ruleset_paths)} process_now={len(rulesets_to_process)} "
        f"portfolio={','.join(portfolio)} packets_per_ruleset={args.packets_per_ruleset} "
        f"output_dir={output_dir} cache={cache_path}",
        flush=True,
    )
    examples, metadata = build_leaf_supervision_dataset(
        ruleset_paths=rulesets_to_process,
        benchmark_runner=benchmark_runner,
        portfolio=portfolio,
        packets_per_ruleset=args.packets_per_ruleset,
        seed=args.seed,
        trace_dirs=[Path(path).expanduser().resolve() for path in args.trace_dirs],
        settings=settings,
        config_catalog=default_config_catalog(),
        log_every=args.log_every,
    )
    combined_examples = existing_rows + examples
    write_leaf_dataset_jsonl(dataset_path, combined_examples)
    metadata_payload = metadata.to_dict()
    metadata_payload["benchmark_cache"] = str(cache_path)
    metadata_path.write_text(json.dumps(metadata_payload, indent=2, sort_keys=True))
    write_leaf_dataset_csv(
        csv_dataset_path,
        combined_examples,
        feature_names=metadata.feature_names,
        portfolio=portfolio,
    )
    summary = {
        "ruleset_count": len(ruleset_paths),
        "new_ruleset_count": len(rulesets_to_process),
        "skipped_ruleset_count": len(ruleset_paths) - len(rulesets_to_process),
        "new_leaf_count": len(examples),
        "leaf_count": len(combined_examples),
        "portfolio": list(portfolio),
        "feature_count": len(metadata.feature_names),
        "csv_dataset": str(csv_dataset_path),
        "benchmark_cache": str(cache_path),
        "cache_stats": benchmark_runner.cache_stats(),
        "output_dir": str(output_dir),
    }
    (output_dir / "dataset_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True))
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
