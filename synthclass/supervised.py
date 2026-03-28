from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple
import json
import math
import random

from .benchmark import BenchmarkRunner
from .core import (
    FIELD_MAX_VALUES,
    FIELD_NAMES,
    TOTAL_FIELDS,
    BenchmarkResult,
    NodeConfigChoice,
    Packet,
    Rule,
    default_config_catalog,
    extract_node_observation,
)
from .training import RulesetPool
from .tree import SynthClassSettings

try:
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, Dataset
except ImportError:  # pragma: no cover
    torch = None
    nn = None
    DataLoader = object
    Dataset = object


@dataclass
class LeafSubset:
    ruleset_name: str
    leaf_id: str
    depth: int
    rules: List[Rule]
    packets: List[Packet]
    remaining_dimensions: Tuple[int, ...]
    used_dimensions: Tuple[int, ...]
    partition_config: NodeConfigChoice


@dataclass
class TechniqueTarget:
    classifier_name: str
    construction_time_ms: float
    classification_time_s: float
    memory_bytes: int
    accuracy_percent: float
    valid: bool = True
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "classifier_name": self.classifier_name,
            "construction_time_ms": self.construction_time_ms,
            "classification_time_s": self.classification_time_s,
            "memory_bytes": self.memory_bytes,
            "accuracy_percent": self.accuracy_percent,
            "valid": self.valid,
            "error": self.error,
        }


@dataclass
class LeafTrainingExample:
    source_ruleset_path: str
    ruleset_name: str
    leaf_id: str
    depth: int
    rule_count: int
    packet_count: int
    remaining_dimensions: Tuple[int, ...]
    used_dimensions: Tuple[int, ...]
    partition_config_name: str
    rule_ids: Tuple[int, ...]
    feature_vector: Tuple[float, ...]
    targets: Dict[str, TechniqueTarget]
    best_technique: str
    best_cost: float

    def to_dict(self) -> dict:
        return {
            "source_ruleset_path": self.source_ruleset_path,
            "ruleset_name": self.ruleset_name,
            "leaf_id": self.leaf_id,
            "depth": self.depth,
            "rule_count": self.rule_count,
            "packet_count": self.packet_count,
            "remaining_dimensions": list(self.remaining_dimensions),
            "used_dimensions": list(self.used_dimensions),
            "partition_config_name": self.partition_config_name,
            "rule_ids": list(self.rule_ids),
            "feature_vector": list(self.feature_vector),
            "targets": {name: target.to_dict() for name, target in self.targets.items()},
            "best_technique": self.best_technique,
            "best_cost": self.best_cost,
        }


@dataclass
class SupervisedDatasetMetadata:
    feature_names: Tuple[str, ...]
    portfolio: Tuple[str, ...]
    alpha: float
    beta: float
    gamma: float

    def to_dict(self) -> dict:
        return {
            "feature_names": list(self.feature_names),
            "portfolio": list(self.portfolio),
            "alpha": self.alpha,
            "beta": self.beta,
            "gamma": self.gamma,
        }


class LeafPartitionPlanner:
    def __init__(
        self,
        settings: Optional[SynthClassSettings] = None,
        config_catalog: Optional[Sequence[NodeConfigChoice]] = None,
    ) -> None:
        self.settings = settings or SynthClassSettings()
        self.config_catalog = tuple(config_catalog or default_config_catalog())
        self._node_counter = 0
        self._root_rule_count = 0
        self._root_packet_count = 0

    def collect_leaves(self, ruleset_name: str, rules: Sequence[Rule], packets: Sequence[Packet]) -> List[LeafSubset]:
        self._node_counter = 0
        self._root_rule_count = len(rules)
        self._root_packet_count = len(packets)
        leaves: List[LeafSubset] = []
        self._collect_node(
            ruleset_name=ruleset_name,
            rules=list(rules),
            packets=list(packets),
            remaining_dimensions=tuple(range(TOTAL_FIELDS)),
            used_dimensions=tuple(),
            depth=0,
            leaves=leaves,
        )
        return leaves

    def _collect_node(
        self,
        ruleset_name: str,
        rules: List[Rule],
        packets: List[Packet],
        remaining_dimensions: Tuple[int, ...],
        used_dimensions: Tuple[int, ...],
        depth: int,
        leaves: List[LeafSubset],
    ) -> None:
        leaf_id = f"v{self._node_counter}"
        self._node_counter += 1

        for field in remaining_dimensions:
            if self._is_bypass_dimension(rules, field):
                next_dimensions = tuple(dimension for dimension in remaining_dimensions if dimension != field)
                next_used = tuple(sorted(set(used_dimensions + (field,))))
                self._collect_node(
                    ruleset_name=ruleset_name,
                    rules=rules,
                    packets=packets,
                    remaining_dimensions=next_dimensions,
                    used_dimensions=next_used,
                    depth=depth + 1,
                    leaves=leaves,
                )
                return

        observation = extract_node_observation(
            rules=rules,
            packets=packets,
            remaining_dimensions=remaining_dimensions,
            depth=depth,
            root_rule_count=self._root_rule_count,
            root_packet_count=self._root_packet_count,
            max_pair_samples=self.settings.pairwise_overlap_samples,
        )
        config = self._pick_config(observation.rule_count)
        if not remaining_dimensions or depth >= self.settings.max_depth or len(rules) <= config.leaf_rule_threshold:
            leaves.append(
                LeafSubset(
                    ruleset_name=ruleset_name,
                    leaf_id=leaf_id,
                    depth=depth,
                    rules=list(rules),
                    packets=list(packets),
                    remaining_dimensions=remaining_dimensions,
                    used_dimensions=used_dimensions,
                    partition_config=config,
                )
            )
            return

        split_dimension = self._pick_dimension(observation)
        if split_dimension not in remaining_dimensions:
            split_dimension = remaining_dimensions[0]
        regions = self._build_regions(rules, split_dimension, config.routing_fanout)
        child_partitions = self._partition_children(rules, packets, split_dimension, regions)
        useful_children = [partition for partition in child_partitions if partition[1]]
        if len(useful_children) <= 1 or all(len(child_rules) == len(rules) for _, child_rules, _ in useful_children):
            leaves.append(
                LeafSubset(
                    ruleset_name=ruleset_name,
                    leaf_id=leaf_id,
                    depth=depth,
                    rules=list(rules),
                    packets=list(packets),
                    remaining_dimensions=remaining_dimensions,
                    used_dimensions=used_dimensions,
                    partition_config=config,
                )
            )
            return

        next_dimensions = tuple(dimension for dimension in remaining_dimensions if dimension != split_dimension)
        next_used = tuple(sorted(set(used_dimensions + (split_dimension,))))
        for _, child_rules, child_packets in useful_children:
            self._collect_node(
                ruleset_name=ruleset_name,
                rules=child_rules,
                packets=child_packets,
                remaining_dimensions=next_dimensions,
                used_dimensions=next_used,
                depth=depth + 1,
                leaves=leaves,
            )

    def _pick_config(self, rule_count: int) -> NodeConfigChoice:
        for config in self.config_catalog:
            if rule_count <= config.leaf_rule_threshold:
                return config
        return self.config_catalog[-1]

    def _pick_dimension(self, observation) -> int:
        if not observation.available_dimensions:
            return 0
        best_dimension = observation.available_dimensions[0]
        best_score = float("-inf")
        for dimension in observation.available_dimensions:
            unique_endpoints, overlap_ratio, entropy, prefix_fraction = observation.per_dimension_features[dimension]
            score = unique_endpoints + entropy + prefix_fraction - overlap_ratio
            if score > best_score:
                best_score = score
                best_dimension = dimension
        return best_dimension

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
    def _build_regions(rules: Sequence[Rule], field: int, fanout: int) -> List[Tuple[int, int]]:
        low = min(rule.ranges[field][0] for rule in rules)
        high = max(rule.ranges[field][1] for rule in rules)
        if low >= high or fanout <= 1:
            return [(low, high)]
        width = max(1, math.ceil((high - low + 1) / float(fanout)))
        regions: List[Tuple[int, int]] = []
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
        regions: Sequence[Tuple[int, int]],
    ) -> List[Tuple[Tuple[int, int], List[Rule], List[Packet]]]:
        partitions: List[Tuple[Tuple[int, int], List[Rule], List[Packet]]] = []
        for region in regions:
            child_rules = [rule for rule in rules if not (rule.ranges[field][1] < region[0] or region[1] < rule.ranges[field][0])]
            child_packets = [packet for packet in packets if region[0] <= packet[field] <= region[1]]
            partitions.append((region, child_rules, child_packets))
        return partitions


def extract_leaf_feature_names() -> Tuple[str, ...]:
    names: List[str] = [
        "log_rule_fraction",
        "log_packet_fraction",
        "remaining_dimension_fraction",
        "depth_fraction",
        "packet_fraction",
    ]
    for field_name in FIELD_NAMES:
        names.extend(
            [
                f"{field_name}_unique_endpoint_fraction",
                f"{field_name}_mean_overlap_ratio",
                f"{field_name}_range_entropy",
                f"{field_name}_prefix_alignable_fraction",
                f"{field_name}_exact_match_fraction",
                f"{field_name}_wildcard_fraction",
                f"{field_name}_mean_normalized_range_size",
                f"{field_name}_used_upstream",
                f"{field_name}_available_here",
            ]
        )
    return tuple(names)


def extract_leaf_feature_vector(
    leaf: LeafSubset,
    root_rule_count: int,
    root_packet_count: int,
    max_pair_samples: int = 256,
) -> Tuple[float, ...]:
    observation = extract_node_observation(
        rules=leaf.rules,
        packets=leaf.packets,
        remaining_dimensions=leaf.remaining_dimensions,
        depth=leaf.depth,
        root_rule_count=root_rule_count,
        root_packet_count=root_packet_count,
        max_pair_samples=max_pair_samples,
    )
    safe_root_packets = max(1, root_packet_count)
    values: List[float] = [
        observation.feature_vector[0],
        math.log1p(len(leaf.packets)) / math.log1p(safe_root_packets),
        len(leaf.remaining_dimensions) / float(TOTAL_FIELDS),
        leaf.depth / float(max(1, TOTAL_FIELDS)),
        len(leaf.packets) / float(safe_root_packets),
    ]
    used_dimension_set = set(leaf.used_dimensions)
    available_dimension_set = set(leaf.remaining_dimensions)
    for field in range(TOTAL_FIELDS):
        unique_endpoint_fraction, overlap_ratio, entropy, prefix_fraction = observation.per_dimension_features[field]
        values.extend(
            [
                unique_endpoint_fraction,
                overlap_ratio,
                entropy,
                prefix_fraction,
                _exact_match_fraction(leaf.rules, field),
                _wildcard_fraction(leaf.rules, field),
                _mean_normalized_range_size(leaf.rules, field),
                1.0 if field in used_dimension_set else 0.0,
                1.0 if field in available_dimension_set else 0.0,
            ]
        )
    return tuple(values)


def benchmark_leaf_portfolio(
    benchmark_runner: BenchmarkRunner,
    leaf: LeafSubset,
    portfolio: Sequence[str],
) -> Dict[str, TechniqueTarget]:
    targets: Dict[str, TechniqueTarget] = {}
    for classifier_name in portfolio:
        try:
            result = benchmark_runner.benchmark_terminal(
                rules=leaf.rules,
                packets=leaf.packets,
                classifier_name=classifier_name,
                config=leaf.partition_config,
            )
            targets[classifier_name] = TechniqueTarget(
                classifier_name=classifier_name,
                construction_time_ms=result.construction_time_ms,
                classification_time_s=result.classification_time_s,
                memory_bytes=result.memory_bytes,
                accuracy_percent=result.accuracy_percent,
            )
        except RuntimeError as exc:
            targets[classifier_name] = TechniqueTarget(
                classifier_name=classifier_name,
                construction_time_ms=0.0,
                classification_time_s=0.0,
                memory_bytes=0,
                accuracy_percent=0.0,
                valid=False,
                error=str(exc),
            )
    return targets


def best_technique_for_targets(
    targets: Dict[str, TechniqueTarget],
    alpha: float,
    beta: float,
    gamma: float,
) -> Tuple[str, float]:
    best_name = ""
    best_cost = float("inf")
    for classifier_name, target in targets.items():
        if not target.valid:
            continue
        cost = alpha * target.classification_time_s + beta * float(target.memory_bytes) + gamma * target.construction_time_ms
        if cost < best_cost:
            best_cost = cost
            best_name = classifier_name
    return best_name, best_cost


def write_leaf_dataset_jsonl(path: Path, rows: Sequence[object]) -> None:
    with path.open("w") as handle:
        for row in rows:
            payload = row.to_dict() if hasattr(row, "to_dict") else row
            handle.write(json.dumps(payload, sort_keys=True) + "\n")


def build_leaf_supervision_dataset(
    ruleset_paths: Sequence[Path],
    benchmark_runner: BenchmarkRunner,
    portfolio: Sequence[str],
    packets_per_ruleset: int,
    seed: int,
    trace_dirs: Optional[Sequence[Path]] = None,
    settings: Optional[SynthClassSettings] = None,
    config_catalog: Optional[Sequence[NodeConfigChoice]] = None,
    log_every: int = 1,
) -> Tuple[List[LeafTrainingExample], SupervisedDatasetMetadata]:
    planner = LeafPartitionPlanner(settings=settings, config_catalog=config_catalog)
    ruleset_pool = RulesetPool(
        ruleset_paths=ruleset_paths,
        packets_per_ruleset=packets_per_ruleset,
        seed=seed,
        trace_dirs=trace_dirs,
    )
    feature_names = extract_leaf_feature_names()
    examples: List[LeafTrainingExample] = []
    current_settings = settings or SynthClassSettings()
    for index, ruleset_path in enumerate(ruleset_paths):
        ruleset = ruleset_pool.load(ruleset_path)
        if log_every > 0 and (index == 0 or (index + 1) % log_every == 0):
            print(
                f"[dataset] ruleset {index + 1}/{len(ruleset_paths)} name={ruleset_path.name} "
                f"rules={len(ruleset.rules)} packets={len(ruleset.packets)}",
                flush=True,
            )
        leaves = planner.collect_leaves(ruleset_path.name, ruleset.rules, ruleset.packets)
        for leaf_index, leaf in enumerate(leaves):
            feature_vector = extract_leaf_feature_vector(
                leaf=leaf,
                root_rule_count=len(ruleset.rules),
                root_packet_count=len(ruleset.packets),
                max_pair_samples=current_settings.pairwise_overlap_samples,
            )
            targets = benchmark_leaf_portfolio(benchmark_runner=benchmark_runner, leaf=leaf, portfolio=portfolio)
            best_name, best_cost = best_technique_for_targets(
                targets=targets,
                alpha=current_settings.alpha,
                beta=current_settings.beta,
                gamma=current_settings.gamma,
            )
            examples.append(
                LeafTrainingExample(
                    source_ruleset_path=str(ruleset_path.resolve()),
                    ruleset_name=ruleset_path.name,
                    leaf_id=f"{leaf.leaf_id}_leaf{leaf_index}",
                    depth=leaf.depth,
                    rule_count=len(leaf.rules),
                    packet_count=len(leaf.packets),
                    remaining_dimensions=leaf.remaining_dimensions,
                    used_dimensions=leaf.used_dimensions,
                    partition_config_name=leaf.partition_config.name,
                    rule_ids=tuple(rule.rule_id for rule in leaf.rules),
                    feature_vector=feature_vector,
                    targets=targets,
                    best_technique=best_name,
                    best_cost=best_cost,
                )
            )
    metadata = SupervisedDatasetMetadata(
        feature_names=feature_names,
        portfolio=tuple(portfolio),
        alpha=current_settings.alpha,
        beta=current_settings.beta,
        gamma=current_settings.gamma,
    )
    return examples, metadata


class TorchDependencyError(RuntimeError):
    pass


def ensure_torch() -> None:
    if torch is None or nn is None:
        raise TorchDependencyError("PyTorch is required for supervised training. Use the `python` environment that has torch installed.")


class LeafTechniqueNet(nn.Module if nn is not None else object):  # type: ignore[misc]
    def __init__(self, input_dim: int, num_techniques: int) -> None:
        super().__init__()
        self.backbone = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.ReLU(),
            nn.Dropout(0.10),
            nn.Linear(128, 128),
            nn.ReLU(),
            nn.Dropout(0.10),
            nn.Linear(128, 64),
            nn.ReLU(),
        )
        self.latency_head = nn.Linear(64, num_techniques)
        self.memory_head = nn.Linear(64, num_techniques)
        self.build_head = nn.Linear(64, num_techniques)

    def forward(self, features):
        hidden = self.backbone(features)
        return {
            "latency": self.latency_head(hidden),
            "memory": self.memory_head(hidden),
            "build": self.build_head(hidden),
        }


class LeafRegressionDataset(Dataset if Dataset is not object else object):  # type: ignore[misc]
    def __init__(
        self,
        rows: Sequence[dict],
        portfolio: Sequence[str],
        feature_mean: Optional[Sequence[float]] = None,
        feature_std: Optional[Sequence[float]] = None,
    ) -> None:
        ensure_torch()
        self.portfolio = tuple(portfolio)
        self.rows = list(rows)
        raw_features = torch.tensor([row["feature_vector"] for row in self.rows], dtype=torch.float32)
        if feature_mean is None:
            self.feature_mean = raw_features.mean(dim=0)
        else:
            self.feature_mean = torch.tensor(feature_mean, dtype=torch.float32)
        if feature_std is None:
            self.feature_std = raw_features.std(dim=0, unbiased=False)
        else:
            self.feature_std = torch.tensor(feature_std, dtype=torch.float32)
        self.feature_std = torch.clamp(self.feature_std, min=1e-6)
        self.features = (raw_features - self.feature_mean) / self.feature_std
        self.latency = torch.zeros((len(self.rows), len(self.portfolio)), dtype=torch.float32)
        self.memory = torch.zeros((len(self.rows), len(self.portfolio)), dtype=torch.float32)
        self.build = torch.zeros((len(self.rows), len(self.portfolio)), dtype=torch.float32)
        self.mask = torch.zeros((len(self.rows), len(self.portfolio)), dtype=torch.float32)
        self.best_indices = torch.full((len(self.rows),), -1, dtype=torch.long)
        for row_index, row in enumerate(self.rows):
            targets = row["targets"]
            for technique_index, technique in enumerate(self.portfolio):
                target = targets.get(technique)
                if target is None or not target.get("valid", False):
                    continue
                self.latency[row_index, technique_index] = _transform_latency(float(target["classification_time_s"]))
                self.memory[row_index, technique_index] = _transform_memory(float(target["memory_bytes"]))
                self.build[row_index, technique_index] = _transform_build(float(target["construction_time_ms"]))
                self.mask[row_index, technique_index] = 1.0
            best_name = row.get("best_technique", "")
            if best_name in self.portfolio:
                self.best_indices[row_index] = self.portfolio.index(best_name)

    def __len__(self) -> int:
        return len(self.rows)

    def __getitem__(self, index: int):
        return {
            "features": self.features[index],
            "latency": self.latency[index],
            "memory": self.memory[index],
            "build": self.build[index],
            "mask": self.mask[index],
            "best_index": self.best_indices[index],
        }


def read_leaf_dataset_jsonl(path: Path) -> List[dict]:
    rows: List[dict] = []
    with path.open("r") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped:
                rows.append(json.loads(stripped))
    return rows


def split_rows_by_ruleset(rows: Sequence[dict], validation_fraction: float, seed: int) -> Tuple[List[dict], List[dict]]:
    if validation_fraction <= 0.0:
        return list(rows), []
    ruleset_names = sorted({str(row.get("source_ruleset_path", row["ruleset_name"])) for row in rows})
    rng = random.Random(seed)
    rng.shuffle(ruleset_names)
    validation_count = max(1, int(round(len(ruleset_names) * validation_fraction)))
    validation_rulesets = set(ruleset_names[:validation_count])
    train_rows = [row for row in rows if str(row.get("source_ruleset_path", row["ruleset_name"])) not in validation_rulesets]
    validation_rows = [row for row in rows if str(row.get("source_ruleset_path", row["ruleset_name"])) in validation_rulesets]
    if not train_rows or not validation_rows:
        return list(rows), []
    return train_rows, validation_rows


def train_leaf_selector_model(
    dataset_rows: Sequence[dict],
    metadata: SupervisedDatasetMetadata,
    output_dir: Path,
    device: str = "cpu",
    epochs: int = 50,
    batch_size: int = 256,
    learning_rate: float = 3e-4,
    weight_decay: float = 1e-5,
    validation_fraction: float = 0.2,
    seed: int = 1337,
    resume_model_path: Optional[Path] = None,
) -> Tuple[dict, List[dict]]:
    ensure_torch()
    output_dir.mkdir(parents=True, exist_ok=True)
    resume_payload = None
    resume_feature_mean = None
    resume_feature_std = None
    if resume_model_path is not None:
        resume_payload = torch.load(resume_model_path, map_location=device)
        if tuple(resume_payload.get("feature_names", [])) != metadata.feature_names:
            raise ValueError("Resume model feature names do not match the dataset metadata.")
        if tuple(resume_payload.get("portfolio", [])) != metadata.portfolio:
            raise ValueError("Resume model portfolio does not match the dataset metadata.")
        resume_feature_mean = resume_payload.get("feature_mean")
        resume_feature_std = resume_payload.get("feature_std")
    train_rows, validation_rows = split_rows_by_ruleset(dataset_rows, validation_fraction=validation_fraction, seed=seed)
    train_dataset = LeafRegressionDataset(
        train_rows,
        portfolio=metadata.portfolio,
        feature_mean=resume_feature_mean,
        feature_std=resume_feature_std,
    )
    validation_dataset = (
        LeafRegressionDataset(
            validation_rows,
            portfolio=metadata.portfolio,
            feature_mean=train_dataset.feature_mean.tolist(),
            feature_std=train_dataset.feature_std.tolist(),
        )
        if validation_rows
        else None
    )
    generator = torch.Generator().manual_seed(seed)
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True, generator=generator)
    validation_loader = DataLoader(validation_dataset, batch_size=batch_size, shuffle=False) if validation_dataset else None

    model = LeafTechniqueNet(input_dim=len(metadata.feature_names), num_techniques=len(metadata.portfolio)).to(device)
    if resume_payload is not None:
        model.load_state_dict(resume_payload["state_dict"])
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate, weight_decay=weight_decay)

    history: List[dict] = []
    existing_history: List[dict] = []
    history_path = output_dir / "training_history.jsonl"
    epoch_offset = 0
    if resume_model_path is not None and history_path.exists():
        existing_history = read_leaf_dataset_jsonl(history_path)
        if existing_history:
            epoch_offset = int(existing_history[-1].get("epoch", 0))
    best_record: dict = {}
    best_score = float("inf")
    for epoch in range(epochs):
        model.train()
        train_loss_total = 0.0
        train_batches = 0
        for batch in train_loader:
            features = batch["features"].to(device)
            targets_latency = batch["latency"].to(device)
            targets_memory = batch["memory"].to(device)
            targets_build = batch["build"].to(device)
            mask = batch["mask"].to(device)
            predictions = model(features)
            loss = (
                _masked_mse(predictions["latency"], targets_latency, mask)
                + _masked_mse(predictions["memory"], targets_memory, mask)
                + _masked_mse(predictions["build"], targets_build, mask)
            )
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            train_loss_total += float(loss.item())
            train_batches += 1

        record = {
            "epoch": epoch_offset + epoch + 1,
            "train_loss": train_loss_total / float(max(1, train_batches)),
        }
        if validation_loader is not None:
            record.update(
                evaluate_leaf_selector_model(
                    model=model,
                    loader=validation_loader,
                    device=device,
                    alpha=metadata.alpha,
                    beta=metadata.beta,
                    gamma=metadata.gamma,
                )
            )
            monitor = record["validation_loss"]
        else:
            monitor = record["train_loss"]
        history.append(record)
        if monitor < best_score:
            best_score = monitor
            best_record = dict(record)
            torch.save(
                {
                    "state_dict": model.state_dict(),
                    "feature_names": list(metadata.feature_names),
                    "portfolio": list(metadata.portfolio),
                    "feature_mean": train_dataset.feature_mean.tolist(),
                    "feature_std": train_dataset.feature_std.tolist(),
                    "metadata": metadata.to_dict(),
                },
                output_dir / "leaf_selector_model.pt",
            )

    full_history = existing_history + history
    with history_path.open("w") as handle:
        for row in full_history:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    return best_record, full_history


def evaluate_leaf_selector_model(
    model,
    loader,
    device: str,
    alpha: float,
    beta: float,
    gamma: float,
) -> dict:
    ensure_torch()
    model.eval()
    loss_total = 0.0
    batches = 0
    correct = 0
    total = 0
    with torch.no_grad():
        for batch in loader:
            features = batch["features"].to(device)
            targets_latency = batch["latency"].to(device)
            targets_memory = batch["memory"].to(device)
            targets_build = batch["build"].to(device)
            mask = batch["mask"].to(device)
            best_index = batch["best_index"].to(device)
            predictions = model(features)
            loss = (
                _masked_mse(predictions["latency"], targets_latency, mask)
                + _masked_mse(predictions["memory"], targets_memory, mask)
                + _masked_mse(predictions["build"], targets_build, mask)
            )
            loss_total += float(loss.item())
            batches += 1

            predicted_cost = (
                alpha * _inverse_latency(predictions["latency"])
                + beta * _inverse_memory(predictions["memory"])
                + gamma * _inverse_build(predictions["build"])
            )
            true_cost = (
                alpha * _inverse_latency(targets_latency)
                + beta * _inverse_memory(targets_memory)
                + gamma * _inverse_build(targets_build)
            )
            predicted_index = _masked_argmin(predicted_cost, mask)
            true_index = _masked_argmin(true_cost, mask)
            valid_rows = best_index >= 0
            correct += int((predicted_index[valid_rows] == true_index[valid_rows]).sum().item())
            total += int(valid_rows.sum().item())
    accuracy = correct / float(max(1, total))
    return {
        "validation_loss": loss_total / float(max(1, batches)),
        "validation_best_technique_accuracy": accuracy,
    }


def _masked_mse(prediction, target, mask):
    diff = (prediction - target) * mask
    denom = mask.sum().clamp_min(1.0)
    return (diff * diff).sum() / denom


def _masked_argmin(costs, mask):
    masked_costs = costs.masked_fill(mask <= 0.0, float("inf"))
    return torch.argmin(masked_costs, dim=1)


def _transform_latency(value: float) -> float:
    return math.log10(max(value, 1e-12))


def _transform_memory(value: float) -> float:
    return math.log2(max(1.0, value + 1.0))


def _transform_build(value: float) -> float:
    return math.log10(max(value, 1e-9))


def _inverse_latency(values):
    return torch.pow(10.0, values)


def _inverse_memory(values):
    return torch.pow(2.0, values) - 1.0


def _inverse_build(values):
    return torch.pow(10.0, values)


def _exact_match_fraction(rules: Sequence[Rule], field: int) -> float:
    if not rules:
        return 0.0
    exact = 0
    for rule in rules:
        low, high = rule.ranges[field]
        if low == high:
            exact += 1
    return exact / float(len(rules))


def _wildcard_fraction(rules: Sequence[Rule], field: int) -> float:
    if not rules:
        return 0.0
    wildcard = 0
    full_low = 0
    full_high = FIELD_MAX_VALUES[field]
    for rule in rules:
        if rule.ranges[field] == (full_low, full_high):
            wildcard += 1
    return wildcard / float(len(rules))


def _mean_normalized_range_size(rules: Sequence[Rule], field: int) -> float:
    if not rules:
        return 0.0
    domain_size = FIELD_MAX_VALUES[field] + 1
    return sum(rule.range_size(field) / float(domain_size) for rule in rules) / float(len(rules))
