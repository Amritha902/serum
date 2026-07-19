"""The containment environment: a partially-observed defence POMDP.

An outbreak unfolds in discrete time over a static host topology. At each
step the defender receives an *observation* (who is infected, plus the static
network inventory) but crucially **not** the payload's target CVE. It then
spends a per-step action budget on interventions, after which the worm
attempts to spread along vulnerability-compatible edges.

Interventions
-------------
patch(v)    : immunise host v against the *believed* CVE. Cheap, but useless if
              the belief is wrong. Preserves availability.
isolate(v)  : cut host v from the network entirely. Always stops spread through
              v, but incurs an availability penalty (the host goes dark).
segment(u,v): sever a single link. Surgical; preserves both hosts.

The environment is policy-agnostic: a policy is any callable
``policy(env, obs) -> list[Action]``. See ``ContainmentEnv.run``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Callable, Optional

import networkx as nx
import numpy as np

from serum.sim.payload import Payload


class Status(IntEnum):
    SUSCEPTIBLE = 0
    INFECTED = 1
    ISOLATED = 2   # removed by the defender (unavailable but safe)
    RECOVERED = 3  # cleaned/patched after infection (immune, back online)


@dataclass(frozen=True)
class Action:
    kind: str                     # "patch" | "isolate" | "segment"
    target: object                # node id, or (u, v) tuple for "segment"

    @staticmethod
    def patch(v):
        return Action("patch", v)

    @staticmethod
    def isolate(v):
        return Action("isolate", v)

    @staticmethod
    def segment(u, v):
        return Action("segment", (u, v))

    @staticmethod
    def probe(v):
        return Action("probe", v)


@dataclass
class Observation:
    """What the defender sees. Deliberately excludes the payload CVE."""
    t: int
    infected: frozenset          # currently infected hosts
    newly_infected: frozenset    # infected during the previous spread step
    isolated: frozenset
    patched: frozenset
    seeds: frozenset             # planted patient-zeros (known to defender)
    captured_cve: object = None  # the payload CVE if a honeypot has captured it


@dataclass
class EpisodeResult:
    infected_fraction: float     # peak fraction of the fleet ever infected
    final_infected: int
    availability: float          # fraction of hosts never isolated
    steps_to_containment: int    # step at which spread stopped
    budget_spent: int
    trace: list                  # per-step infected counts (for plots)
    payload_cve: int
    map_cve_correct: Optional[bool] = None  # did the belief's MAP match truth?


# A policy maps (env, observation) -> chosen actions (respecting the budget).
Policy = Callable[["ContainmentEnv", Observation], list]


class ContainmentEnv:
    def __init__(
        self,
        g: nx.Graph,
        payload: Payload,
        seeds: list,
        budget_per_step: int = 5,
        horizon: int = 40,
        isolation_penalty: float = 1.0,
        recovery_time: int = 0,
        decoys=None,
        rng: np.random.Generator | None = None,
    ):
        self.g0 = g
        self.payload = payload
        self.seeds = list(seeds)
        # decoys: hosts the attacker fakes as infected (via a side channel) to
        # mislead the defender's exploit inference. They are reported as infected
        # but never really infect anyone and never count toward the outbreak.
        self.decoys = list(decoys) if decoys else []
        self.budget_per_step = int(budget_per_step)
        self.horizon = int(horizon)
        self.isolation_penalty = float(isolation_penalty)
        # recovery_time == 0 -> SI (no recovery); > 0 -> SIR (a host that has been
        # infected for this many steps is cleaned and becomes immune).
        self.recovery_time = int(recovery_time)
        self.rng = rng or np.random.default_rng()
        self.reset()

    # -- lifecycle -------------------------------------------------------
    def reset(self) -> Observation:
        self.g = self.g0.copy()
        self.n = self.g.number_of_nodes()
        self.status = {v: Status.SUSCEPTIBLE for v in self.g.nodes()}
        self.patched: set = set()
        self.isolated: set = set()
        self.segmented: set = set()
        self.honeypots: set = set()
        self._captured_cve = None
        self.t = 0
        self.budget_spent = 0
        self.trace: list[int] = []
        for s in self.seeds:
            self.status[s] = Status.INFECTED
        self._infected = set(self.seeds)
        # decoys are reported to the defender as freshly infected (poisoning the
        # belief) but are NOT in the real infected set: they never spread and are
        # excluded from the outbreak count.
        self._newly = set(self.seeds) | set(self.decoys)
        self._ever = set(self.seeds)               # every host ever infected (real)
        self._age = {s: 0 for s in self.seeds}     # steps since infection (SIR)
        self.trace.append(len(self._infected))
        return self._observe()

    def _observe(self) -> Observation:
        return Observation(
            t=self.t,
            infected=frozenset(self._infected),
            newly_infected=frozenset(self._newly),
            isolated=frozenset(self.isolated),
            patched=frozenset(self.patched),
            seeds=frozenset(self.seeds),
            captured_cve=self._captured_cve,
        )

    # -- interventions ---------------------------------------------------
    def _apply(self, action: Action) -> bool:
        """Apply one intervention. Returns True if it consumed budget."""
        if action.kind == "patch":
            v = action.target
            if v in self.isolated or self.status[v] == Status.INFECTED:
                return False  # cannot immunise the already-lost
            self.patched.add(v)
            return True
        if action.kind == "isolate":
            v = action.target
            if v in self.isolated:
                return False
            self.isolated.add(v)
            if self.status[v] != Status.INFECTED:
                self.status[v] = Status.ISOLATED
            self._infected.discard(v)  # an isolated infected host cannot spread
            return True
        if action.kind == "segment":
            u, v = action.target
            key = (u, v) if u <= v else (v, u)
            if key in self.segmented or not self.g.has_edge(u, v):
                return False
            self.segmented.add(key)
            return True
        if action.kind == "probe":
            # deploy a honeypot: emulates a vulnerable service to attract the worm;
            # absorbs an attack and captures the payload (reveals the CVE).
            v = action.target
            if v in self.honeypots or v in self.isolated \
                    or self.status[v] == Status.INFECTED:
                return False
            self.honeypots.add(v)
            return True
        raise ValueError(f"unknown action kind: {action.kind!r}")

    def _edge_open(self, u, v) -> bool:
        key = (u, v) if u <= v else (v, u)
        return key not in self.segmented

    # -- dynamics --------------------------------------------------------
    def _spread_once(self) -> set:
        """One synchronous SI spread step, gated by vulnerability + defences."""
        newly = set()
        payload = self.payload
        for u in list(self._infected):
            if u in self.isolated:
                continue
            for v in self.g.neighbors(u):
                if not self._edge_open(u, v):
                    continue
                if v in self.honeypots:
                    # the honeypot advertises the vulnerable service, so the worm
                    # attacks it -> the payload is captured and the CVE revealed;
                    # the honeypot absorbs the attack (v is never infected).
                    if self._captured_cve is None:
                        self._captured_cve = payload.cve
                    continue
                if self.status[v] != Status.SUSCEPTIBLE:
                    continue
                if v in self.isolated or v in self.patched:
                    continue
                if not payload.can_infect(self.g.nodes[v]["vuln"]):
                    continue  # <-- the crux: only exploitable hosts fall
                if self.rng.random() < payload.beta:
                    newly.add(v)
        for v in newly:
            self.status[v] = Status.INFECTED
            self._infected.add(v)
            self._ever.add(v)
            self._age[v] = 0
        return newly

    def _recover(self) -> None:
        """SIR: hosts infected for >= recovery_time are cleaned and made immune."""
        if self.recovery_time <= 0:
            return
        for v in list(self._infected):
            self._age[v] = self._age.get(v, 0) + 1
            if self._age[v] >= self.recovery_time:
                self.status[v] = Status.RECOVERED
                self._infected.discard(v)

    def step(self, actions: list) -> Observation:
        budget = self.budget_per_step
        for action in actions:
            if budget <= 0:
                break
            if self._apply(action):
                budget -= 1
                self.budget_spent += 1
        self._newly = self._spread_once()
        self._recover()
        self.t += 1
        self.trace.append(len(self._infected))
        return self._observe()

    def done(self) -> bool:
        return self.t >= self.horizon or len(self._newly) == 0

    # -- full episode ----------------------------------------------------
    def run(self, policy: Policy) -> EpisodeResult:
        obs = self.reset()
        containment_step = self.horizon
        while not self.done():
            actions = policy(self, obs) or []
            obs = self.step(actions)
            if len(self._newly) == 0 and containment_step == self.horizon:
                containment_step = self.t
        # every host that was ever infected (spreading, recovered, or isolated
        # while infected) -- the true outbreak size, robust to SIR and isolation.
        ever_infected = len(self._ever)
        return EpisodeResult(
            infected_fraction=ever_infected / self.n,
            final_infected=len(self._infected),
            availability=1.0 - len(self.isolated) / self.n,
            steps_to_containment=containment_step,
            budget_spent=self.budget_spent,
            trace=list(self.trace),
            payload_cve=self.payload.cve,
        )
