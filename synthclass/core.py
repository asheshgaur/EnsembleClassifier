from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
import csv
import math
import random


FIELD_NAMES = ("src_ip", "dst_ip", "src_port", "dst_port", "protocol")
FIELD_BITS = (32, 32, 16, 16, 8)
FIELD_MAX_VALUES = tuple((1 << bits) - 1 for bits in FIELD_BITS)
IP_FIELDS = (0, 1)
TOTAL_FIELDS = len(FIELD_NAMES)

Packet = Tuple[int, int, int, int, int]
Range = Tuple[int, int]


@dataclass(frozen=True)
class Rule:
    rule_id: int
    priority: int
    ranges: Tuple[Range, Range, Range, Range, Range]
    prefix_lengths: Tuple[int, int, int, int, int]
    raw_text: str

    def matches(self, packet: Packet) -> bool:
        for field, value in enumerate(packet):
            low, high = self.ranges[field]
            if value < low or value > high:
                return False
        return True

    def range_size(self, field: int) -> int:
        low, high = self.ranges[field]
        return max(0, high - low + 1)


@dataclass
class NodeConfigChoice:
    name: str
    leaf_rule_threshold: int
    routing_fanout: int
    routing_compare_cost_ns: float = 30.0
    routing_node_bytes: int = 96
    routing_edge_bytes: int = 24
    bypass_compare_cost_ns: float = 5.0
    bypass_node_bytes: int = 32
    classifier_args: Dict[str, Dict[str, str]] = field(default_factory=dict)

    def cli_args_for(self, classifier_name: str) -> Dict[str, str]:
        args = dict(self.classifier_args.get(classifier_name, {}))
        if classifier_name == "NPTree":
            args.setdefault("NPTree.MaxRulesPerNode", str(self.leaf_rule_threshold))
        if classifier_name == "CutTSS":
            args.setdefault("CutTSS.Bucket", str(max(2, self.routing_fanout * 2)))
            args.setdefault("CutTSS.Threshold", str(max(8, self.leaf_rule_threshold)))
        if classifier_name == "CutSplit":
            args.setdefault("CutSplit.Bucket", str(max(2, self.routing_fanout * 2)))
            args.setdefault("CutSplit.Threshold", str(max(8, self.leaf_rule_threshold)))
        if classifier_name == "TabTree":
            args.setdefault("TabTree.Bucket", str(max(2, self.routing_fanout)))
            args.setdefault("TabTree.Threshold", str(max(16, self.leaf_rule_threshold)))
        return args


@dataclass
class BenchmarkResult:
    classifier_name: str
    construction_time_ms: float
    classification_time_s: float
    memory_bytes: int
    accuracy_percent: float
    packet_count: int
    raw_row: Dict[str, str] = field(default_factory=dict)


@dataclass
class TreeCost:
    total_classification_time_s: float = 0.0
    total_build_time_ms: float = 0.0
    total_memory_bytes: int = 0

    def __iadd__(self, other: "TreeCost") -> "TreeCost":
        self.total_classification_time_s += other.total_classification_time_s
        self.total_build_time_ms += other.total_build_time_ms
        self.total_memory_bytes += other.total_memory_bytes
        return self


@dataclass
class NodeObservation:
    feature_vector: Tuple[float, ...]
    per_dimension_features: Tuple[Tuple[float, float, float, float], ...]
    available_dimensions: Tuple[int, ...]
    rule_count: int
    packet_count: int
    depth: int
    packet_fraction: float


@dataclass
class ControllerAction:
    classifier_name: str
    split_dimension: Optional[int]
    config: NodeConfigChoice
    structure_index: int
    dimension_index: int
    config_index: int
    log_prob: Optional[float] = None
    value_estimate: Optional[float] = None


@dataclass
class EpisodeStep:
    observation: NodeObservation
    structure_mask: Tuple[bool, ...]
    dimension_mask: Tuple[bool, ...]
    config_mask: Tuple[bool, ...]
    action: ControllerAction
    reward: float = 0.0


def default_config_catalog() -> Tuple[NodeConfigChoice, ...]:
    return (
        NodeConfigChoice(name="tiny", leaf_rule_threshold=8, routing_fanout=2),
        NodeConfigChoice(name="small", leaf_rule_threshold=16, routing_fanout=2),
        NodeConfigChoice(name="medium", leaf_rule_threshold=32, routing_fanout=4),
        NodeConfigChoice(name="large", leaf_rule_threshold=64, routing_fanout=4),
        NodeConfigChoice(name="xlarge", leaf_rule_threshold=128, routing_fanout=8),
    )


def discover_rulesets(paths: Sequence[str]) -> List[Path]:
    discovered: List[Path] = []
    for raw_path in paths:
        path = Path(raw_path).expanduser().resolve()
        if path.is_dir():
            discovered.extend(sorted(path.rglob("*.rules")))
        elif path.is_file():
            discovered.append(path)
    return sorted(set(discovered))


def load_ruleset(path: Path) -> List[Rule]:
    raw_lines = [line.strip() for line in path.read_text().splitlines() if line.strip()]
    total_rules = len(raw_lines)
    rules: List[Rule] = []
    for index, line in enumerate(raw_lines):
        tokens = line.split()
        if len(tokens) < 9:
            raise ValueError(f"Unsupported ClassBench rule format in {path}: {line}")
        src_range, src_prefix = _parse_ip_prefix(tokens[0][1:])
        dst_range, dst_prefix = _parse_ip_prefix(tokens[1])
        src_port = (int(tokens[2]), int(tokens[4]))
        dst_port = (int(tokens[5]), int(tokens[7]))
        proto_range = _parse_protocol(tokens[8])
        priority = total_rules - index - 1
        rules.append(
            Rule(
                rule_id=index,
                priority=priority,
                ranges=(src_range, dst_range, src_port, dst_port, proto_range),
                prefix_lengths=(src_prefix, dst_prefix, 0, 0, 0),
                raw_text=line,
            )
        )
    return rules


def load_packet_trace(path: Path) -> List[Packet]:
    packets: List[Packet] = []
    with path.open("r", newline="") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            fields = stripped.split()
            if len(fields) < TOTAL_FIELDS:
                raise ValueError(f"Invalid packet trace line in {path}: {line!r}")
            packets.append(tuple(int(fields[index]) for index in range(TOTAL_FIELDS)))
    return packets


def write_ruleset(path: Path, rules: Sequence[Rule]) -> None:
    with path.open("w", newline="") as handle:
        for rule in rules:
            handle.write(rule.raw_text.rstrip() + "\n")


def write_packet_trace(path: Path, packets: Sequence[Packet]) -> None:
    with path.open("w", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t")
        for packet in packets:
            writer.writerow(packet)


def generate_training_packets(rules: Sequence[Rule], packet_count: int, seed: int) -> List[Packet]:
    if packet_count <= 0 or not rules:
        return []
    rng = random.Random(seed)
    packets: List[Packet] = []
    for _ in range(packet_count):
        rule = rules[rng.randrange(len(rules))]
        packets.append(tuple(_sample_value(rule.ranges[field], rng) for field in range(TOTAL_FIELDS)))
    return packets


def extract_node_observation(
    rules: Sequence[Rule],
    packets: Sequence[Packet],
    remaining_dimensions: Sequence[int],
    depth: int,
    root_rule_count: int,
    root_packet_count: int,
    max_pair_samples: int = 256,
) -> NodeObservation:
    safe_root_rule_count = max(1, root_rule_count)
    safe_root_packet_count = max(1, root_packet_count)
    per_dimension_features: List[Tuple[float, float, float, float]] = []
    feature_vector: List[float] = [
        math.log1p(len(rules)) / math.log1p(safe_root_rule_count),
        len(remaining_dimensions) / float(TOTAL_FIELDS),
    ]
    for field in range(TOTAL_FIELDS):
        unique_endpoints = _unique_endpoint_fraction(rules, field)
        overlap_ratio = _mean_pairwise_overlap_ratio(rules, field, max_pair_samples)
        entropy = _range_entropy(rules, field)
        prefix_fraction = _prefix_alignable_fraction(rules, field)
        per_dimension_features.append((unique_endpoints, overlap_ratio, entropy, prefix_fraction))
        feature_vector.extend((unique_endpoints, overlap_ratio, entropy, prefix_fraction))
    packet_fraction = len(packets) / float(safe_root_packet_count)
    feature_vector.extend(
        (
            depth / float(max(1, TOTAL_FIELDS)),
            packet_fraction,
            packet_fraction,
        )
    )
    return NodeObservation(
        feature_vector=tuple(feature_vector),
        per_dimension_features=tuple(per_dimension_features),
        available_dimensions=tuple(remaining_dimensions),
        rule_count=len(rules),
        packet_count=len(packets),
        depth=depth,
        packet_fraction=packet_fraction,
    )


def interval_overlaps(a: Range, b: Range) -> bool:
    return not (a[1] < b[0] or b[1] < a[0])


def interval_overlap_ratio(a: Range, b: Range) -> float:
    if not interval_overlaps(a, b):
        return 0.0
    overlap_low = max(a[0], b[0])
    overlap_high = min(a[1], b[1])
    union_low = min(a[0], b[0])
    union_high = max(a[1], b[1])
    overlap = max(0, overlap_high - overlap_low + 1)
    union = max(1, union_high - union_low + 1)
    return overlap / float(union)


def is_prefix_alignable(low: int, high: int) -> bool:
    size = high - low + 1
    return size > 0 and (size & (size - 1) == 0) and low % size == 0


def _parse_ip_prefix(token: str) -> Tuple[Range, int]:
    ip_text, prefix_text = token.split("/")
    prefix = int(prefix_text)
    ip_value = _ipv4_to_int(ip_text)
    host_bits = 32 - prefix
    if host_bits <= 0:
        return (ip_value, ip_value), prefix
    mask = ((1 << prefix) - 1) << host_bits
    low = ip_value & mask
    high = low | ((1 << host_bits) - 1)
    return (low, high), prefix


def _parse_protocol(token: str) -> Range:
    value_text, mask_text = token.split("/")
    if mask_text != "0xFF":
        return (0, 255)
    value = int(value_text, 16)
    return (value, value)


def _ipv4_to_int(ip_text: str) -> int:
    parts = [int(part) for part in ip_text.split(".")]
    value = 0
    for part in parts:
        value = (value << 8) | part
    return value


def _sample_value(value_range: Range, rng: random.Random) -> int:
    low, high = value_range
    if high <= low:
        return low
    return rng.randint(low, high)


def _unique_endpoint_fraction(rules: Sequence[Rule], field: int) -> float:
    if not rules:
        return 0.0
    endpoints = set()
    for rule in rules:
        endpoints.add(rule.ranges[field][0])
        endpoints.add(rule.ranges[field][1])
    return len(endpoints) / float(max(1, 2 * len(rules)))


def _mean_pairwise_overlap_ratio(rules: Sequence[Rule], field: int, max_pair_samples: int) -> float:
    count = len(rules)
    if count < 2:
        return 0.0
    all_pairs = count * (count - 1) // 2
    if all_pairs <= max_pair_samples:
        ratios = [
            interval_overlap_ratio(rules[left].ranges[field], rules[right].ranges[field])
            for left in range(count)
            for right in range(left + 1, count)
        ]
        return sum(ratios) / float(len(ratios))
    rng = random.Random((field + 1) * 1000003 + count)
    total = 0.0
    for _ in range(max_pair_samples):
        left = rng.randrange(count)
        right = rng.randrange(count - 1)
        if right >= left:
            right += 1
        total += interval_overlap_ratio(rules[left].ranges[field], rules[right].ranges[field])
    return total / float(max_pair_samples)


def _range_entropy(rules: Sequence[Rule], field: int, buckets: int = 8) -> float:
    if not rules:
        return 0.0
    domain_size = FIELD_MAX_VALUES[field] + 1
    histogram = [0] * buckets
    for rule in rules:
        normalized_log = math.log2(max(1, rule.range_size(field))) / float(FIELD_BITS[field])
        bucket = min(buckets - 1, max(0, int(normalized_log * buckets)))
        histogram[bucket] += 1
    probabilities = [count / float(len(rules)) for count in histogram if count]
    entropy = -sum(probability * math.log(probability + 1e-12, 2) for probability in probabilities)
    return entropy / math.log(max(2, buckets), 2)


def _prefix_alignable_fraction(rules: Sequence[Rule], field: int) -> float:
    if not rules:
        return 0.0
    matches = 0
    for rule in rules:
        low, high = rule.ranges[field]
        if field in IP_FIELDS and rule.prefix_lengths[field] > 0:
            matches += 1
            continue
        if is_prefix_alignable(low, high):
            matches += 1
    return matches / float(len(rules))
