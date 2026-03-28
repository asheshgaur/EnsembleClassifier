from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Sequence, Tuple

from .core import ControllerAction, NodeConfigChoice, NodeObservation, TOTAL_FIELDS


class Controller(ABC):
    def __init__(self, portfolio: Sequence[str], config_catalog: Sequence[NodeConfigChoice]) -> None:
        self.portfolio = tuple(portfolio)
        self.config_catalog = tuple(config_catalog)

    def structure_mask(self, observation: NodeObservation) -> Tuple[bool, ...]:
        return tuple(True for _ in self.portfolio)

    def dimension_mask(self, observation: NodeObservation) -> Tuple[bool, ...]:
        available = set(observation.available_dimensions)
        return tuple(field in available for field in range(TOTAL_FIELDS))

    def config_mask(self, observation: NodeObservation) -> Tuple[bool, ...]:
        return tuple(True for _ in self.config_catalog)

    @abstractmethod
    def select_action(self, observation: NodeObservation, deterministic: bool = False) -> ControllerAction:
        raise NotImplementedError


class HeuristicController(Controller):
    """Simple fallback controller for smoke tests and debugging."""

    def select_action(self, observation: NodeObservation, deterministic: bool = False) -> ControllerAction:
        config_index = self._pick_config(observation)
        config = self.config_catalog[config_index]
        dimension_index = self._pick_dimension(observation)
        structure_index = self._pick_structure(observation, dimension_index)
        classifier_name = self.portfolio[structure_index]
        split_dimension = dimension_index if dimension_index in observation.available_dimensions else None
        return ControllerAction(
            classifier_name=classifier_name,
            split_dimension=split_dimension,
            config=config,
            structure_index=structure_index,
            dimension_index=dimension_index,
            config_index=config_index,
        )

    def _pick_config(self, observation: NodeObservation) -> int:
        rule_count = observation.rule_count
        for index, config in enumerate(self.config_catalog):
            if rule_count <= config.leaf_rule_threshold:
                return index
        return len(self.config_catalog) - 1

    def _pick_dimension(self, observation: NodeObservation) -> int:
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

    def _pick_structure(self, observation: NodeObservation, split_dimension: int) -> int:
        preferred = []
        if observation.rule_count <= 32:
            preferred = ["NPTree", "PartitionSort", "PriorityTuple"]
        elif split_dimension in (0, 1):
            preferred = ["HyperSplit", "HyperCuts", "PartitionSort"]
        else:
            preferred = ["ByteCuts", "PriorityTuple", "PartitionSort"]
        for classifier in preferred:
            if classifier in self.portfolio:
                return self.portfolio.index(classifier)
        return 0
