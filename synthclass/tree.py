from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence, Tuple
import math
import time

from .benchmark import BenchmarkRunner
from .controller import Controller
from .core import (
    BenchmarkResult,
    ControllerAction,
    EpisodeStep,
    NodeObservation,
    Packet,
    Range,
    Rule,
    TreeCost,
    extract_node_observation,
    interval_overlaps,
)


@dataclass
class RoutingEdge:
    region: Range
    child: "CompositionNode"

    def to_dict(self) -> dict:
        return {"region": [self.region[0], self.region[1]], "child": self.child.to_dict()}


@dataclass
class CompositionNode:
    node_id: str
    kind: str
    depth: int
    rule_ids: Tuple[int, ...]
    packet_count: int
    remaining_dimensions: Tuple[int, ...]
    split_dimension: Optional[int] = None
    fixed_range: Optional[Range] = None
    classifier_name: Optional[str] = None
    config_name: Optional[str] = None
    benchmark: Optional[BenchmarkResult] = None
    metrics: TreeCost = field(default_factory=TreeCost)
    edges: List[RoutingEdge] = field(default_factory=list)
    child: Optional["CompositionNode"] = None

    def to_dict(self) -> dict:
        payload = {
            "node_id": self.node_id,
            "kind": self.kind,
            "depth": self.depth,
            "rule_ids": list(self.rule_ids),
            "packet_count": self.packet_count,
            "remaining_dimensions": list(self.remaining_dimensions),
            "split_dimension": self.split_dimension,
            "fixed_range": list(self.fixed_range) if self.fixed_range else None,
            "classifier_name": self.classifier_name,
            "config_name": self.config_name,
            "metrics": {
                "total_classification_time_s": self.metrics.total_classification_time_s,
                "total_build_time_ms": self.metrics.total_build_time_ms,
                "total_memory_bytes": self.metrics.total_memory_bytes,
            },
        }
        if self.benchmark is not None:
            payload["benchmark"] = {
                "classifier_name": self.benchmark.classifier_name,
                "construction_time_ms": self.benchmark.construction_time_ms,
                "classification_time_s": self.benchmark.classification_time_s,
                "memory_bytes": self.benchmark.memory_bytes,
                "accuracy_percent": self.benchmark.accuracy_percent,
                "packet_count": self.benchmark.packet_count,
            }
        if self.child is not None:
            payload["child"] = self.child.to_dict()
        if self.edges:
            payload["edges"] = [edge.to_dict() for edge in self.edges]
        return payload

    def flatten_records(self) -> List[dict]:
        record = {
            "node_id": self.node_id,
            "kind": self.kind,
            "depth": self.depth,
            "rule_count": len(self.rule_ids),
            "packet_count": self.packet_count,
            "rule_ids": list(self.rule_ids),
            "remaining_dimensions": list(self.remaining_dimensions),
            "split_dimension": self.split_dimension,
            "fixed_range": list(self.fixed_range) if self.fixed_range else None,
            "selected_classifier": self.classifier_name,
            "config_name": self.config_name,
            "total_classification_time_s": self.metrics.total_classification_time_s,
            "total_build_time_ms": self.metrics.total_build_time_ms,
            "total_memory_bytes": self.metrics.total_memory_bytes,
        }
        if self.benchmark is not None:
            record["benchmark_classifier"] = self.benchmark.classifier_name
            record["benchmark_construction_time_ms"] = self.benchmark.construction_time_ms
            record["benchmark_classification_time_s"] = self.benchmark.classification_time_s
            record["benchmark_memory_bytes"] = self.benchmark.memory_bytes
            record["benchmark_accuracy_percent"] = self.benchmark.accuracy_percent
        if self.edges:
            record["child_regions"] = [list(edge.region) for edge in self.edges]
        records = [record]
        if self.child is not None:
            records.extend(self.child.flatten_records())
        for edge in self.edges:
            records.extend(edge.child.flatten_records())
        return records


@dataclass
class SynthClassSettings:
    alpha: float = 1.0
    beta: float = 1e-6
    gamma: float = 1e-3
    max_depth: int = 5
    pairwise_overlap_samples: int = 256


@dataclass
class EpisodeSummary:
    ruleset_name: str
    reward: float
    total_classification_time_s: float
    mean_latency_s: float
    total_memory_bytes: int
    total_build_time_ms: float
    decision_count: int
    root: CompositionNode
    steps: List[EpisodeStep]

    def to_dict(self) -> dict:
        return {
            "ruleset_name": self.ruleset_name,
            "reward": self.reward,
            "total_classification_time_s": self.total_classification_time_s,
            "mean_latency_s": self.mean_latency_s,
            "total_memory_bytes": self.total_memory_bytes,
            "total_build_time_ms": self.total_build_time_ms,
            "decision_count": self.decision_count,
            "root": self.root.to_dict(),
        }

    def node_records(self) -> List[dict]:
        records = self.root.flatten_records()
        for record in records:
            record["ruleset_name"] = self.ruleset_name
        return records


class SynthClassBuilder:
    def __init__(
        self,
        controller: Controller,
        benchmark_runner: BenchmarkRunner,
        settings: Optional[SynthClassSettings] = None,
        node_logger: Optional[Callable[[dict], None]] = None,
    ) -> None:
        self.controller = controller
        self.benchmark_runner = benchmark_runner
        self.settings = settings or SynthClassSettings()
        self.node_logger = node_logger
        self._steps: List[EpisodeStep] = []
        self._node_counter = 0
        self._root_rule_count = 0
        self._root_packet_count = 0
        self._ruleset_name = ""

    def build(self, ruleset_name: str, rules: Sequence[Rule], packets: Sequence[Packet], deterministic: bool = False) -> EpisodeSummary:
        self._steps = []
        self._node_counter = 0
        self._root_rule_count = len(rules)
        self._root_packet_count = len(packets)
        self._ruleset_name = ruleset_name
        build_start = time.perf_counter()
        root = self._build_node(
            rules=list(rules),
            packets=list(packets),
            remaining_dimensions=tuple(range(5)),
            depth=0,
            deterministic=deterministic,
        )
        python_build_ms = (time.perf_counter() - build_start) * 1000.0
        root.metrics.total_build_time_ms += python_build_ms
        total_classification_time_s = root.metrics.total_classification_time_s
        mean_latency_s = 0.0
        if self._root_packet_count:
            mean_latency_s = total_classification_time_s / float(self._root_packet_count)
        reward = -(
            self.settings.alpha * mean_latency_s
            + self.settings.beta * float(root.metrics.total_memory_bytes)
            + self.settings.gamma * root.metrics.total_build_time_ms
        )
        for step in self._steps:
            step.reward = reward
        return EpisodeSummary(
            ruleset_name=ruleset_name,
            reward=reward,
            total_classification_time_s=total_classification_time_s,
            mean_latency_s=mean_latency_s,
            total_memory_bytes=root.metrics.total_memory_bytes,
            total_build_time_ms=root.metrics.total_build_time_ms,
            decision_count=len(self._steps),
            root=root,
            steps=list(self._steps),
        )

    def _build_node(
        self,
        rules: Sequence[Rule],
        packets: Sequence[Packet],
        remaining_dimensions: Tuple[int, ...],
        depth: int,
        deterministic: bool,
    ) -> CompositionNode:
        node_id = f"v{self._node_counter}"
        self._node_counter += 1
        for field in remaining_dimensions:
            if self._is_bypass_dimension(rules, field):
                next_dimensions = tuple(dimension for dimension in remaining_dimensions if dimension != field)
                self._emit_node_log(
                    {
                        "node_id": node_id,
                        "kind": "bypass",
                        "depth": depth,
                        "rule_count": len(rules),
                        "packet_count": len(packets),
                        "remaining_dimensions": list(remaining_dimensions),
                        "split_dimension": field,
                        "fixed_range": list(rules[0].ranges[field]) if rules else None,
                    }
                )
                child = self._build_node(rules, packets, next_dimensions, depth + 1, deterministic)
                metrics = TreeCost(
                    total_classification_time_s=child.metrics.total_classification_time_s
                    + len(packets) * self._bypass_cost_seconds(child),
                    total_build_time_ms=child.metrics.total_build_time_ms,
                    total_memory_bytes=child.metrics.total_memory_bytes + self._bypass_memory_bytes(child),
                )
                return CompositionNode(
                    node_id=node_id,
                    kind="bypass",
                    depth=depth,
                    rule_ids=tuple(rule.rule_id for rule in rules),
                    packet_count=len(packets),
                    remaining_dimensions=remaining_dimensions,
                    split_dimension=field,
                    fixed_range=rules[0].ranges[field] if rules else None,
                    child=child,
                    metrics=metrics,
                )

        observation = extract_node_observation(
            rules=rules,
            packets=packets,
            remaining_dimensions=remaining_dimensions,
            depth=depth,
            root_rule_count=self._root_rule_count,
            root_packet_count=self._root_packet_count,
            max_pair_samples=self.settings.pairwise_overlap_samples,
        )
        action = self.controller.select_action(observation, deterministic=deterministic)
        self._emit_node_log(
            {
                "node_id": node_id,
                "kind": "decision",
                "depth": depth,
                "rule_count": len(rules),
                "packet_count": len(packets),
                "remaining_dimensions": list(remaining_dimensions),
                "selected_classifier": action.classifier_name,
                "config_name": action.config.name,
                "split_dimension": action.split_dimension,
            }
        )
        step = EpisodeStep(
            observation=observation,
            structure_mask=self.controller.structure_mask(observation),
            dimension_mask=self.controller.dimension_mask(observation),
            config_mask=self.controller.config_mask(observation),
            action=action,
        )
        self._steps.append(step)

        force_terminal = (
            not remaining_dimensions
            or depth >= self.settings.max_depth
            or len(rules) <= action.config.leaf_rule_threshold
        )
        if force_terminal:
            benchmark = self.benchmark_runner.benchmark_terminal(rules, packets, action.classifier_name, action.config)
            metrics = TreeCost(
                total_classification_time_s=benchmark.classification_time_s,
                total_build_time_ms=benchmark.construction_time_ms,
                total_memory_bytes=benchmark.memory_bytes,
            )
            node = CompositionNode(
                node_id=node_id,
                kind="terminal",
                depth=depth,
                rule_ids=tuple(rule.rule_id for rule in rules),
                packet_count=len(packets),
                remaining_dimensions=remaining_dimensions,
                classifier_name=action.classifier_name,
                config_name=action.config.name,
                benchmark=benchmark,
                metrics=metrics,
            )
            self._emit_terminal_log(node)
            return node

        split_dimension = action.split_dimension
        if split_dimension is None or split_dimension not in remaining_dimensions:
            split_dimension = remaining_dimensions[0]
        regions = self._build_regions(rules, split_dimension, action.config.routing_fanout)
        child_partitions = self._partition_children(rules, packets, split_dimension, regions)
        next_dimensions = tuple(dimension for dimension in remaining_dimensions if dimension != split_dimension)
        useful_children = [partition for partition in child_partitions if partition[1]]
        if len(useful_children) <= 1 or all(len(child_rules) == len(rules) for _, child_rules, _ in useful_children):
            benchmark = self.benchmark_runner.benchmark_terminal(rules, packets, action.classifier_name, action.config)
            metrics = TreeCost(
                total_classification_time_s=benchmark.classification_time_s,
                total_build_time_ms=benchmark.construction_time_ms,
                total_memory_bytes=benchmark.memory_bytes,
            )
            node = CompositionNode(
                node_id=node_id,
                kind="terminal",
                depth=depth,
                rule_ids=tuple(rule.rule_id for rule in rules),
                packet_count=len(packets),
                remaining_dimensions=remaining_dimensions,
                classifier_name=action.classifier_name,
                config_name=action.config.name,
                benchmark=benchmark,
                metrics=metrics,
            )
            self._emit_terminal_log(node, fallback_split_dimension=split_dimension)
            return node

        metrics = TreeCost(
            total_classification_time_s=len(packets) * self._routing_cost_seconds(action),
            total_build_time_ms=0.0,
            total_memory_bytes=self._routing_memory_bytes(action, len(useful_children)),
        )
        edges: List[RoutingEdge] = []
        for region, child_rules, child_packets in useful_children:
            child_node = self._build_node(child_rules, child_packets, next_dimensions, depth + 1, deterministic)
            metrics += child_node.metrics
            edges.append(RoutingEdge(region=region, child=child_node))
        node = CompositionNode(
            node_id=node_id,
            kind="routing",
            depth=depth,
            rule_ids=tuple(rule.rule_id for rule in rules),
            packet_count=len(packets),
            remaining_dimensions=remaining_dimensions,
            split_dimension=split_dimension,
            classifier_name=action.classifier_name,
            config_name=action.config.name,
            metrics=metrics,
            edges=edges,
        )
        self._emit_node_log(
            {
                "node_id": node.node_id,
                "kind": node.kind,
                "depth": node.depth,
                "rule_count": len(node.rule_ids),
                "packet_count": node.packet_count,
                "selected_classifier": node.classifier_name,
                "config_name": node.config_name,
                "split_dimension": node.split_dimension,
                "child_count": len(node.edges),
                "child_regions": [list(edge.region) for edge in node.edges],
            }
        )
        return node

    def _emit_terminal_log(self, node: CompositionNode, fallback_split_dimension: Optional[int] = None) -> None:
        payload = {
            "node_id": node.node_id,
            "kind": node.kind,
            "depth": node.depth,
            "rule_count": len(node.rule_ids),
            "packet_count": node.packet_count,
            "remaining_dimensions": list(node.remaining_dimensions),
            "selected_classifier": node.classifier_name,
            "config_name": node.config_name,
            "split_dimension": node.split_dimension if node.split_dimension is not None else fallback_split_dimension,
            "benchmark_construction_time_ms": node.benchmark.construction_time_ms if node.benchmark is not None else None,
            "benchmark_classification_time_s": node.benchmark.classification_time_s if node.benchmark is not None else None,
            "benchmark_memory_bytes": node.benchmark.memory_bytes if node.benchmark is not None else None,
            "benchmark_accuracy_percent": node.benchmark.accuracy_percent if node.benchmark is not None else None,
        }
        self._emit_node_log(payload)

    def _emit_node_log(self, payload: dict) -> None:
        if self.node_logger is None:
            return
        event = {
            "ruleset_name": self._ruleset_name,
        }
        event.update(payload)
        self.node_logger(event)

    @staticmethod
    def _is_bypass_dimension(rules: Sequence[Rule], field: int) -> bool:
        if not rules:
            return False
        low, high = rules[0].ranges[field]
        for rule in rules[1:]:
            if rule.ranges[field] != (low, high):
                return False
        return True

    @staticmethod
    def _build_regions(rules: Sequence[Rule], field: int, fanout: int) -> List[Range]:
        low = min(rule.ranges[field][0] for rule in rules)
        high = max(rule.ranges[field][1] for rule in rules)
        if low >= high or fanout <= 1:
            return [(low, high)]
        width = max(1, math.ceil((high - low + 1) / float(fanout)))
        regions: List[Range] = []
        start = low
        while start <= high and len(regions) < fanout:
            end = high if len(regions) == fanout - 1 else min(high, start + width - 1)
            regions.append((start, end))
            start = end + 1
        return regions

    @staticmethod
    def _partition_children(
        rules: Sequence[Rule],
        packets: Sequence[Packet],
        field: int,
        regions: Sequence[Range],
    ) -> List[Tuple[Range, List[Rule], List[Packet]]]:
        partitions: List[Tuple[Range, List[Rule], List[Packet]]] = []
        for region in regions:
            child_rules = [rule for rule in rules if interval_overlaps(rule.ranges[field], region)]
            child_packets = [packet for packet in packets if region[0] <= packet[field] <= region[1]]
            partitions.append((region, child_rules, child_packets))
        return partitions

    @staticmethod
    def _routing_cost_seconds(action: ControllerAction) -> float:
        comparisons = max(1, math.ceil(math.log2(max(2, action.config.routing_fanout))))
        return comparisons * action.config.routing_compare_cost_ns * 1e-9

    @staticmethod
    def _routing_memory_bytes(action: ControllerAction, child_count: int) -> int:
        return action.config.routing_node_bytes + child_count * action.config.routing_edge_bytes

    @staticmethod
    def _bypass_cost_seconds(child: CompositionNode) -> float:
        if child.config_name is None and child.classifier_name is None:
            return 5e-9
        return 5e-9

    @staticmethod
    def _bypass_memory_bytes(child: CompositionNode) -> int:
        return 32
