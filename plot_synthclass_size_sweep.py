#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from statistics import mean
from typing import Dict, List, Sequence


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Average SynthClass evaluation_history.jsonl in contiguous chunks and draw bar graphs."
    )
    parser.add_argument(
        "--input",
        default="Output/synthclass_size_sweep/evaluation_history.jsonl",
        help="Path to evaluation_history.jsonl",
    )
    parser.add_argument(
        "--group-size",
        type=int,
        default=10,
        help="Number of contiguous evaluation rows to average together",
    )
    parser.add_argument(
        "--output-dir",
        default="Output/synthclass_size_sweep/plots",
        help="Directory for summary CSV and output graphs",
    )
    return parser.parse_args()


def load_jsonl(path: Path) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    with path.open("r") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def chunk_rows(rows: Sequence[Dict[str, object]], group_size: int) -> List[List[Dict[str, object]]]:
    return [list(rows[index : index + group_size]) for index in range(0, len(rows), group_size)]


def chunk_label(chunk: Sequence[Dict[str, object]], index: int) -> str:
    phase_labels = [str(row.get("eval_phase_label", "")).strip() for row in chunk if row.get("eval_phase_label")]
    if phase_labels and len(set(phase_labels)) == 1:
        return phase_labels[0]
    episodes = [int(row["episode"]) for row in chunk if "episode" in row]
    if episodes:
        return f"Episodes {episodes[0]}-{episodes[-1]}"
    return f"Group {index + 1}"


def summarize_chunks(chunks: Sequence[Sequence[Dict[str, object]]]) -> List[Dict[str, object]]:
    summary: List[Dict[str, object]] = []
    for index, chunk in enumerate(chunks):
        if not chunk:
            continue
        summary.append(
            {
                "group_index": index + 1,
                "label": chunk_label(chunk, index),
                "evaluation_count": len(chunk),
                "episode_start": int(chunk[0].get("episode", 0)),
                "episode_end": int(chunk[-1].get("episode", 0)),
                "avg_eval_latency_mean_s": mean(float(row["eval_latency_mean_s"]) for row in chunk),
                "avg_eval_memory_mean_bytes": mean(float(row["eval_memory_mean_bytes"]) for row in chunk),
                "avg_eval_build_mean_ms": mean(float(row["eval_build_mean_ms"]) for row in chunk),
            }
        )
    return summary


def write_summary_csv(path: Path, rows: Sequence[Dict[str, object]]) -> None:
    header = [
        "group_index",
        "label",
        "evaluation_count",
        "episode_start",
        "episode_end",
        "avg_eval_latency_mean_s",
        "avg_eval_memory_mean_bytes",
        "avg_eval_build_mean_ms",
    ]
    with path.open("w") as handle:
        handle.write(",".join(header) + "\n")
        for row in rows:
            handle.write(",".join(str(row[column]) for column in header) + "\n")


def plot_metric(rows: Sequence[Dict[str, object]], metric_key: str, ylabel: str, title: str, output_path: Path) -> None:
    try:
        import matplotlib.pyplot as plt
    except ImportError as exc:  # pragma: no cover
        raise SystemExit("matplotlib is required to draw graphs. Install it with `python -m pip install matplotlib`.") from exc

    labels = [str(row["label"]) for row in rows]
    values = [float(row[metric_key]) for row in rows]

    figure, axis = plt.subplots(figsize=(10, 5))
    axis.bar(labels, values, color="#1f77b4")
    axis.set_title(title)
    axis.set_ylabel(ylabel)
    axis.set_xlabel("Ruleset size bucket")
    axis.grid(axis="y", linestyle="--", alpha=0.35)
    plt.setp(axis.get_xticklabels(), rotation=30, ha="right")
    figure.tight_layout()
    figure.savefig(output_path, dpi=200)
    plt.close(figure)


def main() -> None:
    args = parse_args()
    input_path = Path(args.input).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    rows = load_jsonl(input_path)
    if not rows:
        raise SystemExit(f"No evaluation rows found in {input_path}")
    if args.group_size <= 0:
        raise SystemExit("--group-size must be positive")

    chunks = chunk_rows(rows, args.group_size)
    summary_rows = summarize_chunks(chunks)
    write_summary_csv(output_dir / "grouped_evaluation_summary.csv", summary_rows)

    plot_metric(
        summary_rows,
        metric_key="avg_eval_latency_mean_s",
        ylabel="Average classification latency (s)",
        title="SynthClass Average Evaluation Latency by Ruleset Size",
        output_path=output_dir / "latency_bar.png",
    )
    plot_metric(
        summary_rows,
        metric_key="avg_eval_memory_mean_bytes",
        ylabel="Average memory usage (bytes)",
        title="SynthClass Average Evaluation Memory by Ruleset Size",
        output_path=output_dir / "memory_bar.png",
    )
    plot_metric(
        summary_rows,
        metric_key="avg_eval_build_mean_ms",
        ylabel="Average build time (ms)",
        title="SynthClass Average Evaluation Build Time by Ruleset Size",
        output_path=output_dir / "build_time_bar.png",
    )

    print(f"Read {len(rows)} evaluation rows from {input_path}")
    print(f"Wrote grouped summary to {output_dir / 'grouped_evaluation_summary.csv'}")
    print(f"Wrote plots to {output_dir}")


if __name__ == "__main__":
    main()
