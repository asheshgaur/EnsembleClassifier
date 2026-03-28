#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from synthclass.supervised import (
    SupervisedDatasetMetadata,
    TorchDependencyError,
    read_leaf_dataset_jsonl,
    train_leaf_selector_model,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train a supervised neural network to choose the best classifier for SynthClass leaf subsets.")
    parser.add_argument("--dataset", default="Output/supervised_leaf_dataset/leaf_dataset.jsonl")
    parser.add_argument("--metadata", default="Output/supervised_leaf_dataset/leaf_dataset_metadata.json")
    parser.add_argument("--output-dir", default="Output/supervised_leaf_model")
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--learning-rate", type=float, default=3e-4)
    parser.add_argument("--weight-decay", type=float, default=1e-5)
    parser.add_argument("--validation-fraction", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--resume-model", default="", help="Optional checkpoint path to continue training from")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    dataset_path = Path(args.dataset).expanduser().resolve()
    metadata_path = Path(args.metadata).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()
    rows = read_leaf_dataset_jsonl(dataset_path)
    metadata_raw = json.loads(metadata_path.read_text())
    metadata = SupervisedDatasetMetadata(
        feature_names=tuple(metadata_raw["feature_names"]),
        portfolio=tuple(metadata_raw["portfolio"]),
        alpha=float(metadata_raw["alpha"]),
        beta=float(metadata_raw["beta"]),
        gamma=float(metadata_raw["gamma"]),
    )
    print(
        f"[setup] rows={len(rows)} portfolio={','.join(metadata.portfolio)} "
        f"features={len(metadata.feature_names)} output_dir={output_dir}",
        flush=True,
    )
    try:
        best_record, history = train_leaf_selector_model(
            dataset_rows=rows,
            metadata=metadata,
            output_dir=output_dir,
            device=args.device,
            epochs=args.epochs,
            batch_size=args.batch_size,
            learning_rate=args.learning_rate,
            weight_decay=args.weight_decay,
            validation_fraction=args.validation_fraction,
            seed=args.seed,
            resume_model_path=Path(args.resume_model).expanduser().resolve() if args.resume_model else None,
        )
    except TorchDependencyError as exc:
        raise SystemExit(str(exc)) from exc
    summary = {
        "dataset_rows": len(rows),
        "history_length": len(history),
        "resumed_from": str(Path(args.resume_model).expanduser().resolve()) if args.resume_model else "",
        "best_record": best_record,
        "output_dir": str(output_dir),
    }
    (output_dir / "training_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True))
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
