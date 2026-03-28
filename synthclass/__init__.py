"""SynthClass Python package."""

from .core import (
    BenchmarkResult,
    ControllerAction,
    EpisodeStep,
    NodeConfigChoice,
    NodeObservation,
    Rule,
    TreeCost,
    default_config_catalog,
    discover_rulesets,
    generate_training_packets,
    load_packet_trace,
    load_ruleset,
)
from .benchmark import BenchmarkRunner
from .controller import Controller, HeuristicController
from .supervised import (
    LeafTechniqueNet,
    LeafTrainingExample,
    SupervisedDatasetMetadata,
    build_leaf_supervision_dataset,
    train_leaf_selector_model,
)
from .tree import CompositionNode, SynthClassBuilder, SynthClassSettings

__all__ = [
    "BenchmarkResult",
    "BenchmarkRunner",
    "CompositionNode",
    "Controller",
    "ControllerAction",
    "EpisodeStep",
    "HeuristicController",
    "LeafTechniqueNet",
    "LeafTrainingExample",
    "NodeConfigChoice",
    "NodeObservation",
    "Rule",
    "SupervisedDatasetMetadata",
    "SynthClassBuilder",
    "SynthClassSettings",
    "TreeCost",
    "build_leaf_supervision_dataset",
    "default_config_catalog",
    "discover_rulesets",
    "generate_training_packets",
    "load_packet_trace",
    "load_ruleset",
    "train_leaf_selector_model",
]
