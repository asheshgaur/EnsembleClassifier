#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path
from statistics import mean
from typing import Dict, List, Sequence


DEFAULT_TECHNIQUES = ("SynthClass", "PartitionSort", "PTSS", "HyperCuts", "HyperSplit")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare SynthClass grouped latency against other techniques averaged by ruleset size."
    )
    parser.add_argument(
        "--synthclass-summary",
        default="Output/synthclass_size_sweep/plots/grouped_evaluation_summary.csv",
        help="Path to grouped_evaluation_summary.csv",
    )
    parser.add_argument(
        "--technique-results",
        default="Output/ruleset_size_stats/New_Results - Sheet1.csv",
        help="Path to the external technique runtime CSV",
    )
    parser.add_argument(
        "--output-dir",
        default="Output/ruleset_size_stats/comparison_plots",
        help="Directory for the combined CSV and plot",
    )
    parser.add_argument(
        "--techniques",
        default=",".join(DEFAULT_TECHNIQUES),
        help="Comma-separated technique names to plot from the combined summary CSV",
    )
    parser.add_argument(
        "--synthclass-scale",
        type=float,
        default=1e6,
        help="Multiply SynthClass avg_eval_latency_mean_s by this factor before plotting; default converts seconds to microseconds.",
    )
    parser.add_argument(
        "--technique-divisor",
        type=float,
        default=1.0,
        help="Divide all non-SynthClass technique values by this factor before averaging; use 1000000 if the CSV stores total time for one million packets.",
    )
    parser.add_argument(
        "--log-y",
        action="store_true",
        help="Plot the y-axis on a logarithmic scale so very small SynthClass bars remain visible.",
    )
    return parser.parse_args()


def normalize_size_label(raw: str) -> str:
    text = raw.strip()
    if "_" in text:
        text = text.split("_", 1)[0]
    if "-" in text:
        text = text.split("-", 1)[0]
    return text


def size_sort_key(size_label: str) -> int:
    text = size_label.lower().rstrip()
    if text.endswith("k"):
        text = text[:-1]
    return int(text)


def load_synthclass_summary(path: Path, scale: float) -> Dict[str, float]:
    values: Dict[str, float] = {}
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            size_label = normalize_size_label(row["label"])
            values[size_label] = float(row["avg_eval_latency_mean_s"]) * scale
    return values


def load_technique_averages(path: Path, divisor: float) -> Dict[str, Dict[str, float]]:
    if divisor == 0.0:
        raise SystemExit("--technique-divisor must be non-zero")
    with path.open(newline="") as handle:
        reader = csv.reader(handle)
        header = next(reader)
        technique_names: List[str] = []
        for column in header[1:]:
            if not column:
                break
            technique_names.append(column.strip())
        grouped: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))
        for row in reader:
            if not row:
                continue
            file_name = row[0].strip()
            if not file_name or file_name == "File":
                continue
            size_label = normalize_size_label(file_name)
            for offset, technique in enumerate(technique_names, start=1):
                cell = row[offset].strip()
                if not cell:
                    continue
                grouped[size_label][technique].append(float(cell) / divisor)
    averaged: Dict[str, Dict[str, float]] = {}
    for size_label, per_technique in grouped.items():
        averaged[size_label] = {
            technique: mean(values) for technique, values in per_technique.items() if values
        }
    return averaged


def build_combined_rows(
    synthclass_values: Dict[str, float],
    technique_values: Dict[str, Dict[str, float]],
) -> List[Dict[str, object]]:
    size_labels = sorted(set(synthclass_values) | set(technique_values), key=size_sort_key)
    all_techniques = sorted(
        {
            technique
            for per_size in technique_values.values()
            for technique in per_size.keys()
        }
    )
    rows: List[Dict[str, object]] = []
    for size_label in size_labels:
        row: Dict[str, object] = {"size_label": size_label, "SynthClass": synthclass_values.get(size_label, "")}
        for technique in all_techniques:
            row[technique] = technique_values.get(size_label, {}).get(technique, "")
        rows.append(row)
    return rows


def write_csv(path: Path, rows: Sequence[Dict[str, object]]) -> None:
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def plot_grouped_bars(
    rows: Sequence[Dict[str, object]],
    techniques: Sequence[str],
    output_path: Path,
    ylabel: str,
    log_y: bool,
) -> None:
    try:
        import matplotlib.pyplot as plt
    except ImportError as exc:  # pragma: no cover
        raise SystemExit("matplotlib is required to draw the comparison graph. Install it with `python -m pip install matplotlib`.") from exc

    labels = [str(row["size_label"]) for row in rows]
    values_by_technique = [[float(row[technique]) for row in rows] for technique in techniques]
    bar_count = len(techniques)
    x_positions = list(range(len(labels)))
    width = 0.8 / max(1, bar_count)

    figure, axis = plt.subplots(figsize=(12, 6))
    for index, technique in enumerate(techniques):
        offsets = [position - 0.4 + width / 2.0 + index * width for position in x_positions]
        axis.bar(offsets, values_by_technique[index], width=width, label=technique)

    axis.set_xticks(x_positions)
    axis.set_xticklabels(labels)
    axis.set_xlabel("Ruleset size bucket")
    axis.set_ylabel(ylabel)
    axis.set_title("Average Packet Classification Time by Ruleset Size")
    axis.grid(axis="y", linestyle="--", alpha=0.35)
    if log_y:
        axis.set_yscale("log")
    axis.legend()
    figure.tight_layout()
    figure.savefig(output_path, dpi=200)
    plt.close(figure)


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    synthclass_values = load_synthclass_summary(Path(args.synthclass_summary).expanduser().resolve(), args.synthclass_scale)
    technique_values = load_technique_averages(
        Path(args.technique_results).expanduser().resolve(),
        args.technique_divisor,
    )
    combined_rows = build_combined_rows(synthclass_values, technique_values)
    write_csv(output_dir / "latency_comparison_summary.csv", combined_rows)

    selected_techniques = [name.strip() for name in args.techniques.split(",") if name.strip()]
    if not selected_techniques:
        raise SystemExit("No techniques selected for plotting.")
    missing = [name for name in selected_techniques if name not in combined_rows[0]]
    if missing:
        raise SystemExit(f"Unknown technique columns requested: {', '.join(missing)}")

    ylabel = "Average classification time"
    if abs(args.synthclass_scale - 1.0) < 1e-12 and abs(args.technique_divisor - 1000000.0) < 1e-6:
        ylabel = "Average classification time per packet (seconds)"
    elif abs(args.synthclass_scale - 1e6) < 1e-12:
        ylabel = "Average classification time (microseconds)"
    elif abs(args.synthclass_scale - 1.0) < 1e-12:
        ylabel = "Average classification time (seconds)"

    plot_grouped_bars(
        combined_rows,
        techniques=selected_techniques,
        output_path=output_dir / "latency_comparison_bar.png",
        ylabel=ylabel,
        log_y=args.log_y,
    )

    print(f"Wrote combined summary to {output_dir / 'latency_comparison_summary.csv'}")
    print(f"Wrote comparison graph to {output_dir / 'latency_comparison_bar.png'}")


if __name__ == "__main__":
    main()
