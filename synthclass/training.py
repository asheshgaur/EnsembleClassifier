from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple
import hashlib
import json
import random

from .benchmark import BenchmarkRunner
from .controller import Controller
from .core import Packet, Rule, discover_rulesets, generate_training_packets, load_packet_trace, load_ruleset
from .tree import EpisodeSummary, SynthClassBuilder, SynthClassSettings


@dataclass
class RulesetExample:
    ruleset_path: Path
    rules: List[Rule]
    packets: List[Packet]


@dataclass
class EvaluationPhase:
    label: str
    pool: "RulesetPool"
    start_episode: int
    end_episode: int


class RulesetPool:
    def __init__(
        self,
        ruleset_paths: Sequence[Path],
        packets_per_ruleset: int,
        seed: int,
        trace_dirs: Optional[Sequence[Path]] = None,
    ) -> None:
        self.ruleset_paths = list(ruleset_paths)
        self.packets_per_ruleset = packets_per_ruleset
        self.seed = seed
        self.trace_dirs = [path.resolve() for path in (trace_dirs or [])]
        self._cache: Dict[Path, RulesetExample] = {}

    def sample(self, rng: random.Random) -> RulesetExample:
        path = self.ruleset_paths[rng.randrange(len(self.ruleset_paths))]
        return self.load(path)

    def load(self, path: Path) -> RulesetExample:
        if path not in self._cache:
            rules = load_ruleset(path)
            trace_path = self._resolve_trace(path)
            if trace_path is not None and trace_path.exists():
                packets = load_packet_trace(trace_path)
            else:
                packets = generate_training_packets(
                    rules,
                    self.packets_per_ruleset,
                    self.seed + _stable_name_hash(path.name) % 100000,
                )
            self._cache[path] = RulesetExample(ruleset_path=path, rules=rules, packets=packets)
        return self._cache[path]

    def iter_examples(self) -> Iterable[RulesetExample]:
        for path in self.ruleset_paths:
            yield self.load(path)

    def _resolve_trace(self, ruleset_path: Path) -> Optional[Path]:
        candidates = [
            ruleset_path.with_suffix(ruleset_path.suffix + ".trace"),
            ruleset_path.with_name(ruleset_path.name + ".trace"),
            ruleset_path.with_suffix(".trace"),
        ]
        for trace_dir in self.trace_dirs:
            candidates.extend(
                [
                    trace_dir / (ruleset_path.name + ".trace"),
                    trace_dir / (ruleset_path.stem + ".trace"),
                ]
            )
        for candidate in candidates:
            if candidate.exists():
                return candidate
        return None


def run_training_loop(
    controller: Controller,
    benchmark_runner: BenchmarkRunner,
    train_pool: RulesetPool,
    eval_pool: Optional[RulesetPool],
    eval_phases: Optional[Sequence[EvaluationPhase]],
    settings: SynthClassSettings,
    episodes: int,
    batch_size: int,
    eval_interval: int,
    deterministic_eval: bool = True,
    log_every: int = 1,
    log_tree_decisions: bool = False,
) -> Tuple[List[dict], List[dict]]:
    rng = random.Random(train_pool.seed)
    pending_batch: List[EpisodeSummary] = []
    training_history: List[dict] = []
    evaluation_history: List[dict] = []
    for episode_index in range(episodes):
        example = train_pool.sample(rng)
        episode_label = f"{episode_index + 1}/{episodes}"
        if log_every > 0 and (episode_index == 0 or (episode_index + 1) % log_every == 0):
            print(
                f"[train] episode {episode_index + 1}/{episodes} ruleset={example.ruleset_path.name} "
                f"rules={len(example.rules)} packets={len(example.packets)}",
                flush=True,
            )
        tree_logger = None
        if log_tree_decisions:
            tree_logger = _make_tree_logger(phase="train", episode_label=episode_label)
        builder = SynthClassBuilder(
            controller=controller,
            benchmark_runner=benchmark_runner,
            settings=settings,
            node_logger=tree_logger,
        )
        summary = builder.build(
            ruleset_name=example.ruleset_path.name,
            rules=example.rules,
            packets=example.packets,
            deterministic=False,
        )
        pending_batch.append(summary)
        record = {
            "episode": episode_index + 1,
            "ruleset": summary.ruleset_name,
            "reward": summary.reward,
            "mean_latency_s": summary.mean_latency_s,
            "memory_bytes": summary.total_memory_bytes,
            "build_time_ms": summary.total_build_time_ms,
            "decision_count": summary.decision_count,
        }
        if hasattr(controller, "update") and len(pending_batch) >= max(1, batch_size):
            update_metrics = controller.update(pending_batch)  # type: ignore[attr-defined]
            record.update(update_metrics)
            pending_batch = []
        training_history.append(record)
        if log_every > 0 and (episode_index == 0 or (episode_index + 1) % log_every == 0):
            print(
                f"[train] episode {episode_index + 1}/{episodes} reward={summary.reward:.6f} "
                f"latency={summary.mean_latency_s:.9f}s memory={summary.total_memory_bytes} "
                f"build={summary.total_build_time_ms:.3f}ms decisions={summary.decision_count}",
                flush=True,
            )
        if (eval_pool is not None or eval_phases) and eval_interval > 0 and (episode_index + 1) % eval_interval == 0:
            active_phase = _active_evaluation_phase(eval_phases, episode_index + 1)
            active_eval_pool = active_phase.pool if active_phase is not None else eval_pool
            if active_eval_pool is None:
                continue
            phase_suffix = f" phase={active_phase.label}" if active_phase is not None else ""
            print(f"[eval] starting evaluation at episode {episode_index + 1}{phase_suffix}", flush=True)
            evaluation_record = evaluate_controller(
                controller=controller,
                benchmark_runner=benchmark_runner,
                pool=active_eval_pool,
                settings=settings,
                deterministic=deterministic_eval,
                episode=episode_index + 1,
                log_tree_decisions=log_tree_decisions,
                phase=active_phase,
            )
            evaluation_history.append(evaluation_record)
            print(
                f"[eval] episode {episode_index + 1} reward={evaluation_record['eval_reward_mean']:.6f} "
                f"latency={evaluation_record['eval_latency_mean_s']:.9f}s "
                f"memory={evaluation_record['eval_memory_mean_bytes']:.1f} "
                f"build={evaluation_record['eval_build_mean_ms']:.3f}ms",
                flush=True,
            )
    if hasattr(controller, "update") and pending_batch:
        controller.update(pending_batch)  # type: ignore[attr-defined]
    return training_history, evaluation_history


def evaluate_controller(
    controller: Controller,
    benchmark_runner: BenchmarkRunner,
    pool: RulesetPool,
    settings: SynthClassSettings,
    deterministic: bool,
    episode: Optional[int] = None,
    log_tree_decisions: bool = False,
    phase: Optional[EvaluationPhase] = None,
) -> dict:
    rewards: List[float] = []
    latencies: List[float] = []
    memories: List[int] = []
    build_times: List[float] = []
    for example in pool.iter_examples():
        tree_logger = None
        if log_tree_decisions:
            episode_label = str(episode) if episode is not None else None
            tree_logger = _make_tree_logger(phase="eval", episode_label=episode_label)
        builder = SynthClassBuilder(
            controller=controller,
            benchmark_runner=benchmark_runner,
            settings=settings,
            node_logger=tree_logger,
        )
        summary = builder.build(
            ruleset_name=example.ruleset_path.name,
            rules=example.rules,
            packets=example.packets,
            deterministic=deterministic,
        )
        rewards.append(summary.reward)
        latencies.append(summary.mean_latency_s)
        memories.append(summary.total_memory_bytes)
        build_times.append(summary.total_build_time_ms)
    record = {
        "eval_reward_mean": sum(rewards) / float(max(1, len(rewards))),
        "eval_latency_mean_s": sum(latencies) / float(max(1, len(latencies))),
        "eval_memory_mean_bytes": sum(memories) / float(max(1, len(memories))),
        "eval_build_mean_ms": sum(build_times) / float(max(1, len(build_times))),
        "eval_ruleset_count": len(rewards),
    }
    if episode is not None:
        record["episode"] = episode
    if phase is not None:
        record["eval_phase_label"] = phase.label
        record["eval_phase_start_episode"] = phase.start_episode
        record["eval_phase_end_episode"] = phase.end_episode
    return record


def write_jsonl(path: Path, rows: Sequence[dict]) -> None:
    with path.open("w") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def _make_tree_logger(phase: str, episode_label: Optional[str]) -> Callable[[dict], None]:
    def _logger(event: dict) -> None:
        print(_format_tree_event(event, phase=phase, episode_label=episode_label), flush=True)

    return _logger


def _format_tree_event(event: dict, phase: str, episode_label: Optional[str]) -> str:
    parts = [f"[tree] phase={phase}"]
    if episode_label:
        parts.append(f"episode={episode_label}")
    parts.append(f"ruleset={event['ruleset_name']}")
    parts.append(f"node={event['node_id']}")
    parts.append(f"kind={event['kind']}")
    parts.append(f"depth={event['depth']}")
    parts.append(f"rules={event['rule_count']}")
    parts.append(f"packets={event['packet_count']}")
    if event.get("selected_classifier"):
        parts.append(f"classifier={event['selected_classifier']}")
    if event.get("config_name"):
        parts.append(f"config={event['config_name']}")
    split_dimension = event.get("split_dimension")
    if split_dimension is not None:
        parts.append(f"split_dim={split_dimension}")
    if event["kind"] == "bypass":
        parts.append(f"skip_dim={event['split_dimension']}")
    if event["kind"] == "routing":
        parts.append(f"children={event.get('child_count', 0)}")
    if event["kind"] == "terminal":
        if event.get("benchmark_construction_time_ms") is not None:
            parts.append(f"build={event['benchmark_construction_time_ms']:.3f}ms")
        if event.get("benchmark_classification_time_s") is not None:
            parts.append(f"latency={event['benchmark_classification_time_s']:.9f}s")
        if event.get("benchmark_memory_bytes") is not None:
            parts.append(f"memory={event['benchmark_memory_bytes']}")
        if event.get("benchmark_accuracy_percent") is not None:
            parts.append(f"accuracy={event['benchmark_accuracy_percent']:.2f}")
    return " ".join(parts)


def _active_evaluation_phase(eval_phases: Optional[Sequence[EvaluationPhase]], episode: int) -> Optional[EvaluationPhase]:
    if not eval_phases:
        return None
    for phase in eval_phases:
        if phase.start_episode <= episode <= phase.end_episode:
            return phase
    return eval_phases[-1]


def _stable_name_hash(name: str) -> int:
    return int(hashlib.sha1(name.encode("utf-8")).hexdigest()[:12], 16)
