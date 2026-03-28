from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Dict, List, Optional, Sequence, Tuple
import csv
import hashlib
import json
import subprocess

from .core import BenchmarkResult, NodeConfigChoice, Packet, Rule, write_packet_trace, write_ruleset


def _parse_float(value: str) -> float:
    value = value.strip()
    if not value or value == "N/A":
        return 0.0
    return float(value)


def _parse_int(value: str) -> int:
    value = value.strip()
    if not value or value == "N/A":
        return 0
    return int(float(value))


class BenchmarkRunner:
    def __init__(
        self,
        repo_root: Path,
        main_binary: Optional[Path] = None,
        packet_cap: Optional[int] = None,
        cache_path: Optional[Path] = None,
    ) -> None:
        self.repo_root = repo_root.resolve()
        self.main_binary = (main_binary or self.repo_root / "main").resolve()
        self.packet_cap = packet_cap
        self.cache_path = cache_path.resolve() if cache_path is not None else None
        self._cache: Dict[str, BenchmarkResult] = {}
        self._binary_signature = self._compute_binary_signature()
        self._cache_hits = 0
        self._cache_misses = 0
        self._loaded_persistent_entries = 0
        if self.cache_path is not None and self.cache_path.exists():
            self._load_persistent_cache()

    def benchmark_terminal(
        self,
        rules: Sequence[Rule],
        packets: Sequence[Packet],
        classifier_name: str,
        config: NodeConfigChoice,
    ) -> BenchmarkResult:
        sampled_packets, scale_factor = self._sample_packets(packets)
        cli_args = dict(sorted(config.cli_args_for(classifier_name).items()))
        cache_key = self._build_cache_key(
            rules=rules,
            sampled_packets=sampled_packets,
            original_packet_count=len(packets),
            classifier_name=classifier_name,
            config=config,
            cli_args=cli_args,
        )
        cached = self._cache.get(cache_key)
        if cached is not None:
            self._cache_hits += 1
            return replace(cached)
        self._cache_misses += 1

        with TemporaryDirectory(prefix="synthclass_terminal_") as temp_dir_raw:
            temp_dir = Path(temp_dir_raw)
            rules_path = temp_dir / "node.rules"
            packets_path = temp_dir / "node.trace"
            output_path = temp_dir / "node.csv"
            write_ruleset(rules_path, rules)
            write_packet_trace(packets_path, sampled_packets)

            command = [
                str(self.main_binary),
                f"f={rules_path}",
                f"p={packets_path}",
                f"technique={classifier_name}",
                "m=Classification",
                "Shuffle=0",
                "AccuracyPackets=-1",
                "Parallel=0",
                f"o={output_path}",
            ]
            for key, value in cli_args.items():
                command.append(f"{key}={value}")

            process = subprocess.run(
                command,
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                check=False,
            )
            if process.returncode != 0:
                raise RuntimeError(
                    f"Benchmark failed for {classifier_name}.\nSTDOUT:\n{process.stdout}\nSTDERR:\n{process.stderr}"
                )
            with output_path.open("r", newline="") as handle:
                row = next(csv.DictReader(handle))

        result = BenchmarkResult(
            classifier_name=classifier_name,
            construction_time_ms=_parse_float(row.get("ConstructionTime(ms)", "0")),
            classification_time_s=_parse_float(row.get("ClassificationTime(s)", "0")) * scale_factor,
            memory_bytes=_parse_int(row.get("Size(bytes)", "0")),
            accuracy_percent=_parse_float(row.get("Accuracy(%)", "0")),
            packet_count=len(packets),
            raw_row=dict(row),
        )
        self._cache[cache_key] = replace(result)
        self._persist_cache_entry(cache_key, result)
        return result

    def _sample_packets(self, packets: Sequence[Packet]) -> Tuple[List[Packet], float]:
        if self.packet_cap is None or len(packets) <= self.packet_cap:
            return list(packets), 1.0
        step = max(1, len(packets) // self.packet_cap)
        sampled = list(packets[::step][: self.packet_cap])
        if not sampled:
            return [], 1.0
        return sampled, len(packets) / float(len(sampled))

    def _packet_signature(self, packets: Sequence[Packet]) -> str:
        hasher = hashlib.sha1()
        for packet in packets:
            hasher.update(",".join(str(value) for value in packet).encode("ascii"))
            hasher.update(b";")
        hasher.update(str(len(packets)).encode("ascii"))
        return hasher.hexdigest()

    def cache_stats(self) -> dict:
        return {
            "cache_hits": self._cache_hits,
            "cache_misses": self._cache_misses,
            "persistent_entries_loaded": self._loaded_persistent_entries,
            "cache_path": str(self.cache_path) if self.cache_path is not None else "",
        }

    def _compute_binary_signature(self) -> str:
        try:
            stat = self.main_binary.stat()
            return f"{self.main_binary}:{stat.st_size}:{stat.st_mtime_ns}"
        except FileNotFoundError:
            return str(self.main_binary)

    def _rules_signature(self, rules: Sequence[Rule]) -> str:
        hasher = hashlib.sha1()
        for rule in rules:
            hasher.update(rule.raw_text.rstrip().encode("utf-8"))
            hasher.update(b"\n")
        return hasher.hexdigest()

    def _build_cache_key(
        self,
        rules: Sequence[Rule],
        sampled_packets: Sequence[Packet],
        original_packet_count: int,
        classifier_name: str,
        config: NodeConfigChoice,
        cli_args: Dict[str, str],
    ) -> str:
        payload = {
            "binary_signature": self._binary_signature,
            "classifier_name": classifier_name,
            "config_name": config.name,
            "leaf_rule_threshold": config.leaf_rule_threshold,
            "routing_fanout": config.routing_fanout,
            "cli_args": cli_args,
            "rules_signature": self._rules_signature(rules),
            "packet_signature": self._packet_signature(sampled_packets),
            "original_packet_count": original_packet_count,
            "sampled_packet_count": len(sampled_packets),
        }
        return hashlib.sha1(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()

    def _load_persistent_cache(self) -> None:
        if self.cache_path is None:
            return
        with self.cache_path.open("r") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    payload = json.loads(stripped)
                    key = str(payload["cache_key"])
                    result_payload = payload["result"]
                    self._cache[key] = BenchmarkResult(
                        classifier_name=result_payload["classifier_name"],
                        construction_time_ms=float(result_payload["construction_time_ms"]),
                        classification_time_s=float(result_payload["classification_time_s"]),
                        memory_bytes=int(result_payload["memory_bytes"]),
                        accuracy_percent=float(result_payload["accuracy_percent"]),
                        packet_count=int(result_payload["packet_count"]),
                        raw_row=dict(result_payload.get("raw_row", {})),
                    )
                    self._loaded_persistent_entries += 1
                except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                    continue

    def _persist_cache_entry(self, cache_key: str, result: BenchmarkResult) -> None:
        if self.cache_path is None:
            return
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "cache_key": cache_key,
            "result": {
                "classifier_name": result.classifier_name,
                "construction_time_ms": result.construction_time_ms,
                "classification_time_s": result.classification_time_s,
                "memory_bytes": result.memory_bytes,
                "accuracy_percent": result.accuracy_percent,
                "packet_count": result.packet_count,
                "raw_row": result.raw_row,
            },
        }
        with self.cache_path.open("a") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
