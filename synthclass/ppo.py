from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .controller import Controller
from .core import ControllerAction, EpisodeStep, NodeConfigChoice, NodeObservation, TOTAL_FIELDS

try:
    import torch
    from torch import nn
    from torch.distributions import Categorical
except ImportError as import_error:  # pragma: no cover - dependency gate
    torch = None
    nn = None
    Categorical = None
    _TORCH_IMPORT_ERROR = import_error
else:
    _TORCH_IMPORT_ERROR = None


class TorchDependencyError(RuntimeError):
    pass


def ensure_torch() -> None:
    if torch is None or nn is None or Categorical is None:
        raise TorchDependencyError(
            "SynthClass PPO requires torch. Install it first, for example with "
            "`python3 -m pip install -r requirements-synthclass.txt`."
        ) from _TORCH_IMPORT_ERROR


@dataclass
class PPOHyperparameters:
    learning_rate: float = 3e-4
    clip_ratio: float = 0.2
    entropy_coeff: float = 0.01
    value_coeff: float = 0.5
    gamma: float = 0.99
    update_epochs: int = 4
    minibatch_size: int = 64
    max_grad_norm: float = 0.5


class SynthClassPolicyNetwork(nn.Module if nn is not None else object):  # type: ignore[misc]
    def __init__(self, input_dim: int, num_structures: int, num_configs: int, hidden_size: int = 128) -> None:
        super().__init__()
        self.backbone = nn.Sequential(
            nn.Linear(input_dim, hidden_size),
            nn.ReLU(),
            nn.Linear(hidden_size, hidden_size),
            nn.ReLU(),
            nn.Linear(hidden_size, hidden_size),
            nn.ReLU(),
        )
        self.structure_head = nn.Linear(hidden_size, num_structures)
        self.dimension_head = nn.Linear(hidden_size, TOTAL_FIELDS)
        self.config_head = nn.Linear(hidden_size, num_configs)
        self.value_head = nn.Linear(hidden_size, 1)

    def forward(self, states):
        hidden = self.backbone(states)
        return {
            "structure_logits": self.structure_head(hidden),
            "dimension_logits": self.dimension_head(hidden),
            "config_logits": self.config_head(hidden),
            "value": self.value_head(hidden).squeeze(-1),
        }


class TorchPPOController(Controller):
    def __init__(
        self,
        portfolio: Sequence[str],
        config_catalog: Sequence[NodeConfigChoice],
        input_dim: int,
        hyperparameters: Optional[PPOHyperparameters] = None,
        device: str = "cpu",
    ) -> None:
        ensure_torch()
        super().__init__(portfolio, config_catalog)
        self.hyperparameters = hyperparameters or PPOHyperparameters()
        self.device = torch.device(device)
        self.network = SynthClassPolicyNetwork(
            input_dim=input_dim,
            num_structures=len(self.portfolio),
            num_configs=len(self.config_catalog),
        ).to(self.device)
        self.optimizer = torch.optim.Adam(self.network.parameters(), lr=self.hyperparameters.learning_rate)

    def select_action(self, observation: NodeObservation, deterministic: bool = False) -> ControllerAction:
        ensure_torch()
        state = torch.tensor(observation.feature_vector, dtype=torch.float32, device=self.device).unsqueeze(0)
        outputs = self.network(state)
        structure_mask = torch.tensor(self.structure_mask(observation), dtype=torch.bool, device=self.device).unsqueeze(0)
        dimension_mask = torch.tensor(self.dimension_mask(observation), dtype=torch.bool, device=self.device).unsqueeze(0)
        config_mask = torch.tensor(self.config_mask(observation), dtype=torch.bool, device=self.device).unsqueeze(0)
        structure_dist = self._masked_categorical(outputs["structure_logits"], structure_mask)
        dimension_dist = self._masked_categorical(outputs["dimension_logits"], dimension_mask)
        config_dist = self._masked_categorical(outputs["config_logits"], config_mask)
        if deterministic:
            structure_index = torch.argmax(self._apply_mask(outputs["structure_logits"], structure_mask), dim=-1)
            dimension_index = torch.argmax(self._apply_mask(outputs["dimension_logits"], dimension_mask), dim=-1)
            config_index = torch.argmax(self._apply_mask(outputs["config_logits"], config_mask), dim=-1)
        else:
            structure_index = structure_dist.sample()
            dimension_index = dimension_dist.sample()
            config_index = config_dist.sample()
        log_prob = (
            structure_dist.log_prob(structure_index)
            + dimension_dist.log_prob(dimension_index)
            + config_dist.log_prob(config_index)
        )
        return ControllerAction(
            classifier_name=self.portfolio[int(structure_index.item())],
            split_dimension=int(dimension_index.item()),
            config=self.config_catalog[int(config_index.item())],
            structure_index=int(structure_index.item()),
            dimension_index=int(dimension_index.item()),
            config_index=int(config_index.item()),
            log_prob=float(log_prob.item()),
            value_estimate=float(outputs["value"].item()),
        )

    def update(self, episodes: Sequence) -> Dict[str, float]:
        ensure_torch()
        steps: List[EpisodeStep] = []
        returns: List[float] = []
        for episode in episodes:
            episode_steps = list(episode.steps)
            horizon = len(episode_steps)
            for index, step in enumerate(episode_steps):
                steps.append(step)
                returns.append(episode.reward * (self.hyperparameters.gamma ** max(0, horizon - index - 1)))
        if not steps:
            return {"policy_loss": 0.0, "value_loss": 0.0, "entropy": 0.0}

        states = torch.tensor([step.observation.feature_vector for step in steps], dtype=torch.float32, device=self.device)
        structure_masks = torch.tensor([step.structure_mask for step in steps], dtype=torch.bool, device=self.device)
        dimension_masks = torch.tensor([step.dimension_mask for step in steps], dtype=torch.bool, device=self.device)
        config_masks = torch.tensor([step.config_mask for step in steps], dtype=torch.bool, device=self.device)
        structure_actions = torch.tensor([step.action.structure_index for step in steps], dtype=torch.long, device=self.device)
        dimension_actions = torch.tensor([step.action.dimension_index for step in steps], dtype=torch.long, device=self.device)
        config_actions = torch.tensor([step.action.config_index for step in steps], dtype=torch.long, device=self.device)
        old_log_probs = torch.tensor([step.action.log_prob or 0.0 for step in steps], dtype=torch.float32, device=self.device)
        old_values = torch.tensor([step.action.value_estimate or 0.0 for step in steps], dtype=torch.float32, device=self.device)
        returns_tensor = torch.tensor(returns, dtype=torch.float32, device=self.device)
        advantages = returns_tensor - old_values
        advantages = (advantages - advantages.mean()) / (advantages.std(unbiased=False) + 1e-8)

        batch_size = len(steps)
        batch_indices = torch.arange(batch_size, device=self.device)
        policy_loss_value = 0.0
        value_loss_value = 0.0
        entropy_value = 0.0
        for _ in range(self.hyperparameters.update_epochs):
            permutation = batch_indices[torch.randperm(batch_size, device=self.device)]
            for start in range(0, batch_size, self.hyperparameters.minibatch_size):
                indices = permutation[start : start + self.hyperparameters.minibatch_size]
                outputs = self.network(states[indices])
                structure_dist = self._masked_categorical(outputs["structure_logits"], structure_masks[indices])
                dimension_dist = self._masked_categorical(outputs["dimension_logits"], dimension_masks[indices])
                config_dist = self._masked_categorical(outputs["config_logits"], config_masks[indices])
                new_log_probs = (
                    structure_dist.log_prob(structure_actions[indices])
                    + dimension_dist.log_prob(dimension_actions[indices])
                    + config_dist.log_prob(config_actions[indices])
                )
                entropy = (
                    structure_dist.entropy().mean()
                    + dimension_dist.entropy().mean()
                    + config_dist.entropy().mean()
                )
                ratio = torch.exp(new_log_probs - old_log_probs[indices])
                unclipped = ratio * advantages[indices]
                clipped = torch.clamp(
                    ratio,
                    1.0 - self.hyperparameters.clip_ratio,
                    1.0 + self.hyperparameters.clip_ratio,
                ) * advantages[indices]
                policy_loss = -torch.min(unclipped, clipped).mean()
                value_loss = torch.nn.functional.mse_loss(outputs["value"], returns_tensor[indices])
                loss = (
                    policy_loss
                    + self.hyperparameters.value_coeff * value_loss
                    - self.hyperparameters.entropy_coeff * entropy
                )
                self.optimizer.zero_grad()
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.network.parameters(), self.hyperparameters.max_grad_norm)
                self.optimizer.step()
                policy_loss_value = float(policy_loss.item())
                value_loss_value = float(value_loss.item())
                entropy_value = float(entropy.item())
        return {
            "policy_loss": policy_loss_value,
            "value_loss": value_loss_value,
            "entropy": entropy_value,
        }

    def save(self, path: Path) -> None:
        ensure_torch()
        payload = {
            "state_dict": self.network.state_dict(),
            "portfolio": list(self.portfolio),
            "config_names": [config.name for config in self.config_catalog],
        }
        torch.save(payload, path)

    def load(self, path: Path) -> None:
        ensure_torch()
        payload = torch.load(path, map_location=self.device)
        self.network.load_state_dict(payload["state_dict"])

    @staticmethod
    def _apply_mask(logits, mask):
        return logits.masked_fill(~mask, -1e9)

    @classmethod
    def _masked_categorical(cls, logits, mask):
        return Categorical(logits=cls._apply_mask(logits, mask))
