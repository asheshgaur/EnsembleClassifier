#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
from typing import List
import json

from synthclass import BenchmarkRunner, HeuristicController, SynthClassBuilder, SynthClassSettings, default_config_catalog, discover_rulesets
from synthclass.core import extract_node_observation
from synthclass.ppo import PPOHyperparameters, TorchDependencyError, TorchPPOController
from synthclass.training import EvaluationPhase, RulesetPool, evaluate_controller, run_training_loop, write_jsonl


DEFAULT_PORTFOLIO = (
    "PartitionSort",
    "PriorityTuple",
    "HyperCuts",
    "HyperSplit",
    "ByteCuts",
    "CutSplit",
    "TabTree",
    "NPTree",
    "TCAM",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train or smoke-test the SynthClass RL controller.")
    parser.add_argument("--controller", choices=("heuristic", "ppo"), default="heuristic")
    parser.add_argument("--train-rulesets", nargs="+", required=True, help="Ruleset files or directories")
    parser.add_argument("--eval-rulesets", nargs="*", default=[], help="Held-out ruleset files or directories")
    parser.add_argument(
        "--eval-phase-rulesets",
        nargs="*",
        default=[],
        help="Ordered evaluation phase directories or files. Each phase stays active for --eval-phase-length episodes.",
    )
    parser.add_argument("--eval-phase-length", type=int, default=100)
    parser.add_argument("--trace-dirs", nargs="*", default=[], help="Optional directories containing packet traces")
    parser.add_argument("--episodes", type=int, default=10)
    parser.add_argument("--batch-size", type=int, default=4)
    parser.add_argument("--eval-interval", type=int, default=5)
    parser.add_argument("--packets-per-ruleset", type=int, default=256)
    parser.add_argument("--leaf-packet-cap", type=int, default=128)
    parser.add_argument("--portfolio", default=",".join(DEFAULT_PORTFOLIO))
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--main-binary", default="")
    parser.add_argument("--output-dir", default="Output/synthclass")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--alpha", type=float, default=1.0)
    parser.add_argument("--beta", type=float, default=1e-6)
    parser.add_argument("--gamma", type=float, default=1e-3)
    parser.add_argument("--max-depth", type=int, default=5)
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--learning-rate", type=float, default=3e-4)
    parser.add_argument("--clip-ratio", type=float, default=0.2)
    parser.add_argument("--entropy-coeff", type=float, default=0.01)
    parser.add_argument("--value-coeff", type=float, default=0.5)
    parser.add_argument("--discount", type=float, default=0.99)
    parser.add_argument("--update-epochs", type=int, default=4)
    parser.add_argument("--minibatch-size", type=int, default=64)
    parser.add_argument("--max-grad-norm", type=float, default=0.5)
    parser.add_argument("--log-every", type=int, default=1)
    parser.add_argument("--log-tree-decisions", action="store_true")
    parser.add_argument("--save-checkpoint", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    repo_root = Path(args.repo_root).expanduser().resolve()
    train_rulesets = discover_rulesets(args.train_rulesets)
    eval_rulesets = discover_rulesets(args.eval_rulesets)
    eval_phase_inputs = [Path(path).expanduser().resolve() for path in args.eval_phase_rulesets]
    if not train_rulesets:
        raise SystemExit("No training rulesets found.")
    if eval_rulesets and eval_phase_inputs:
        raise SystemExit("Use either --eval-rulesets or --eval-phase-rulesets, not both.")
    portfolio = tuple(item.strip() for item in args.portfolio.split(",") if item.strip())
    config_catalog = default_config_catalog()
    train_pool = RulesetPool(
        ruleset_paths=train_rulesets,
        packets_per_ruleset=args.packets_per_ruleset,
        seed=args.seed,
        trace_dirs=[Path(path).expanduser().resolve() for path in args.trace_dirs],
    )
    eval_pool = None
    if eval_rulesets:
        eval_pool = RulesetPool(
            ruleset_paths=eval_rulesets,
            packets_per_ruleset=args.packets_per_ruleset,
            seed=args.seed + 17,
            trace_dirs=[Path(path).expanduser().resolve() for path in args.trace_dirs],
        )
    eval_phases: List[EvaluationPhase] = []
    for phase_index, phase_input in enumerate(eval_phase_inputs):
        phase_rulesets = discover_rulesets([str(phase_input)])
        if not phase_rulesets:
            raise SystemExit(f"No evaluation rulesets found for phase input: {phase_input}")
        phase_label = phase_input.name or f"phase_{phase_index + 1}"
        eval_phases.append(
            EvaluationPhase(
                label=phase_label,
                pool=RulesetPool(
                    ruleset_paths=phase_rulesets,
                    packets_per_ruleset=args.packets_per_ruleset,
                    seed=args.seed + 17 + phase_index,
                    trace_dirs=[Path(path).expanduser().resolve() for path in args.trace_dirs],
                ),
                start_episode=phase_index * args.eval_phase_length + 1,
                end_episode=(phase_index + 1) * args.eval_phase_length,
            )
        )
    if eval_phases:
        eval_pool = eval_phases[0].pool
    benchmark_runner = BenchmarkRunner(
        repo_root=repo_root,
        main_binary=Path(args.main_binary).expanduser().resolve() if args.main_binary else None,
        packet_cap=args.leaf_packet_cap,
    )
    settings = SynthClassSettings(
        alpha=args.alpha,
        beta=args.beta,
        gamma=args.gamma,
        max_depth=args.max_depth,
    )

    sample_example = train_pool.load(train_rulesets[0])
    feature_dim = len(
        extract_node_observation(
            rules=sample_example.rules,
            packets=sample_example.packets,
            remaining_dimensions=tuple(range(5)),
            depth=0,
            root_rule_count=len(sample_example.rules),
            root_packet_count=len(sample_example.packets),
        ).feature_vector
    )
    if args.controller == "heuristic":
        controller = HeuristicController(portfolio=portfolio, config_catalog=config_catalog)
    else:
        hyperparameters = PPOHyperparameters(
            learning_rate=args.learning_rate,
            clip_ratio=args.clip_ratio,
            entropy_coeff=args.entropy_coeff,
            value_coeff=args.value_coeff,
            gamma=args.discount,
            update_epochs=args.update_epochs,
            minibatch_size=args.minibatch_size,
            max_grad_norm=args.max_grad_norm,
        )
        try:
            controller = TorchPPOController(
                portfolio=portfolio,
                config_catalog=config_catalog,
                input_dim=feature_dim,
                hyperparameters=hyperparameters,
                device=args.device,
            )
        except TorchDependencyError as exc:
            raise SystemExit(str(exc)) from exc

    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    print(
        f"[setup] controller={args.controller} train_rulesets={len(train_rulesets)} "
        f"eval_rulesets={len(eval_rulesets)} eval_phases={len(eval_phases)} portfolio={','.join(portfolio)} "
        f"episodes={args.episodes} output_dir={output_dir}",
        flush=True,
    )
    training_history, evaluation_history = run_training_loop(
        controller=controller,
        benchmark_runner=benchmark_runner,
        train_pool=train_pool,
        eval_pool=eval_pool,
        eval_phases=eval_phases,
        settings=settings,
        episodes=args.episodes,
        batch_size=args.batch_size,
        eval_interval=args.eval_interval,
        log_every=args.log_every,
        log_tree_decisions=args.log_tree_decisions,
    )
    write_jsonl(output_dir / "training_history.jsonl", training_history)
    if evaluation_history:
        write_jsonl(output_dir / "evaluation_history.jsonl", evaluation_history)
    export_eval_pool = eval_phases[-1].pool if eval_phases else eval_pool
    export_eval_rulesets = export_eval_pool.ruleset_paths if export_eval_pool is not None else []
    export_example = (
        export_eval_pool.load(export_eval_rulesets[0])
        if export_eval_pool is not None and export_eval_rulesets
        else train_pool.load(train_rulesets[0])
    )
    export_builder = SynthClassBuilder(controller=controller, benchmark_runner=benchmark_runner, settings=settings)
    export_summary = export_builder.build(
        ruleset_name=export_example.ruleset_path.name,
        rules=export_example.rules,
        packets=export_example.packets,
        deterministic=True,
    )
    (output_dir / "final_tree.json").write_text(json.dumps(export_summary.to_dict(), indent=2, sort_keys=True))
    write_jsonl(output_dir / "final_tree_nodes.jsonl", export_summary.node_records())
    if args.save_checkpoint and hasattr(controller, "save"):
        controller.save(output_dir / "policy.pt")  # type: ignore[attr-defined]
    summary = {
        "controller": args.controller,
        "episodes": args.episodes,
        "portfolio": list(portfolio),
        "train_rulesets": [str(path) for path in train_rulesets],
        "eval_rulesets": [str(path) for path in eval_rulesets],
        "eval_phases": [
            {
                "label": phase.label,
                "start_episode": phase.start_episode,
                "end_episode": phase.end_episode,
                "rulesets": [str(path) for path in phase.pool.ruleset_paths],
            }
            for phase in eval_phases
        ],
        "output_dir": str(output_dir),
    }
    (output_dir / "run_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True))
    final_output = {
        "last_training": training_history[-1] if training_history else summary,
    }
    if export_eval_pool is not None and not evaluation_history:
        final_output["last_evaluation"] = evaluate_controller(
            controller,
            benchmark_runner,
            export_eval_pool,
            settings,
            deterministic=True,
        )
    elif evaluation_history:
        final_output["last_evaluation"] = evaluation_history[-1]
    print(json.dumps(final_output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
