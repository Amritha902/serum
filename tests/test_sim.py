"""Smoke + invariant tests for the containment simulator."""

import os
import sys

import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from serum.agents.content_aware import ContentAwareAgent, OracleContentAware
from serum.baselines.heuristics import DegreeDefense, NoDefense
from serum.inference.belief import CVEBelief
from serum.sim.environment import Action, ContainmentEnv, Status
from serum.sim.network import cve_prevalence, generate_network, vulnerable_subgraph
from serum.sim.payload import sample_payload


def make_env(seed=0, **kw):
    rng = np.random.default_rng(seed)
    g = generate_network(n=200, n_cves=12, vuln_lambda=6.0,
                         popularity_alpha=0.8, rng=rng)
    pl = sample_payload(g, beta=0.15, strategy="stealth", rng=rng)
    carriers = [v for v, d in g.nodes(data=True) if pl.cve in d["vuln"]]
    seeds = [int(s) for s in rng.choice(carriers, size=3, replace=False)]
    return ContainmentEnv(g, pl, seeds, rng=np.random.default_rng(seed + 1), **kw), pl


def test_network_has_vuln_profiles():
    g = generate_network(n=100, rng=np.random.default_rng(0))
    assert all("vuln" in d and len(d["vuln"]) >= 1 for _, d in g.nodes(data=True))
    assert abs(cve_prevalence(g).sum()) > 0


def test_spread_is_vulnerability_gated():
    """Only hosts carrying the payload CVE may ever become infected."""
    env, pl = make_env()
    env.run(NoDefense())
    for v in env.g.nodes():
        if env.status[v] == Status.INFECTED and v not in env.seeds:
            assert pl.cve in env.g.nodes[v]["vuln"], "infected a non-vulnerable host!"


def test_sir_recovery_makes_hosts_immune():
    """Under SIR, an infected host recovers after recovery_time steps, stops
    spreading, and cannot be reinfected; the outbreak size still counts it."""
    env, _ = make_env(recovery_time=2)
    env.reset()
    seed = env.seeds[0]
    env.step([]); env.step([])          # two steps -> seeds should recover
    assert env.status[seed] == Status.RECOVERED
    assert seed not in env._infected
    assert seed in env._ever            # still counted in the outbreak size
    # a recovered host is immune: it never re-enters the infected set
    for _ in range(5):
        env.step([])
        assert env.status[seed] == Status.RECOVERED


def test_honeypot_captures_payload_and_absorbs_attack():
    """A honeypot on a frontier host captures the payload (reveals the CVE) and
    is never itself infected."""
    env, pl = make_env()
    env.reset()
    # place a honeypot on a susceptible neighbour of a seed
    seed = env.seeds[0]
    target = next((w for w in env.g.neighbors(seed)
                   if env.status[w] == Status.SUSCEPTIBLE), None)
    if target is None:
        pytest.skip("seed has no susceptible neighbour in this instance")
    env.step([Action.probe(target)])
    # after a spread step the seed attacks the honeypot -> capture
    for _ in range(3):
        if env._captured_cve is not None:
            break
        env.step([])
    assert env._captured_cve == pl.cve
    assert env.status[target] != Status.INFECTED     # honeypot absorbed the attack
    assert target not in env._ever


def test_isolate_removes_from_spread():
    env, _ = make_env()
    env.reset()
    victim = env.seeds[0]
    env.step([Action.isolate(victim)])
    assert victim in env.isolated
    assert victim not in env._infected


def test_belief_never_excludes_true_cve():
    """The true CVE must remain in the consistent support at all times."""
    env, pl = make_env()
    belief = CVEBelief(env.g)
    obs = env.reset()
    for _ in range(20):
        belief.update(obs.newly_infected, obs.seeds)
        assert belief.consistent[pl.cve], "belief wrongly excluded the true CVE"
        if env.done():
            break
        obs = env.step([])


def test_belief_narrows_and_ranks_truth_high():
    """As the outbreak grows the belief must (a) never exclude the true CVE,
    (b) shrink the consistent support below the full universe, and (c) rank the
    true CVE among the most probable candidates.

    Note: exact MAP recovery is *not* guaranteed and is not claimed. Spread is
    vulnerability-gated, so two exploits are indistinguishable while every
    infected host happens to carry both -- a genuine identifiability limit.
    This is precisely why the agent plans under the full posterior rather than
    committing to a single MAP CVE."""
    env, pl = make_env()
    belief = CVEBelief(env.g)
    obs = env.reset()
    for _ in range(env.horizon):
        belief.update(obs.newly_infected, obs.seeds)
        if env.done():
            break
        obs = env.step([])
    post = belief.posterior()
    assert belief.consistent[pl.cve]                       # never excluded
    assert belief.support_size() < env.g.graph["n_cves"]   # genuinely narrowed
    rank = int((post > post[pl.cve]).sum())                # 0 == most probable
    assert rank <= 2, f"true CVE ranked #{rank + 1} (posterior too diffuse)"


def test_soft_belief_survives_detection_noise():
    """A single false-positive infection (a host NOT carrying the true CVE) must
    not destroy the belief: the hard model wrongly excludes the truth, the soft
    model keeps it ranked high."""
    env, pl = make_env()
    env.reset()
    # find a host that does NOT carry the true CVE -> a plausible false positive
    fp = next(v for v in env.g.nodes()
              if pl.cve not in env.g.nodes[v]["vuln"] and v not in env.seeds)

    hard = CVEBelief(env.g, mode="hard")
    soft = CVEBelief(env.g, mode="soft", noise=0.05)
    # feed some genuine evidence, then the false positive
    obs = env._observe()
    for _ in range(6):
        hard.update(obs.newly_infected, obs.seeds)
        soft.update(obs.newly_infected, obs.seeds)
        if env.done():
            break
        obs = env.step([])
    hard.update({fp}, frozenset())
    soft.update({fp}, frozenset())

    assert not hard.consistent[pl.cve]                 # hard model: truth excluded
    post = soft.posterior()
    rank = int((post > post[pl.cve]).sum())
    assert rank <= 3, "soft belief lost the true CVE after one false positive"


def test_content_aware_beats_no_defense():
    inf_ours, inf_none = [], []
    for s in range(6):
        env, _ = make_env(seed=s)
        inf_ours.append(env.run(ContentAwareAgent(env.g)).infected_fraction)
        env2, _ = make_env(seed=s)
        inf_none.append(env2.run(NoDefense()).infected_fraction)
    assert np.mean(inf_ours) < np.mean(inf_none)


def test_learned_policy_runs_and_beats_no_defense():
    """The learned linear policy (belief-augmented features) runs end-to-end and,
    with the content-aware-like weight vector, contains better than no defense."""
    import numpy as np
    from serum.agents.learned import LearnedPolicy, N_FEATURES
    from serum.baselines.heuristics import NoDefense
    w = np.zeros(N_FEATURES); w[0] = 1.0        # weight the exposed-vuln-degree feature
    ours, none = [], []
    for s in range(5):
        env, _ = make_env(seed=s)
        ours.append(env.run(LearnedPolicy(env.g, weights=w)).infected_fraction)
        env2, _ = make_env(seed=s)
        none.append(env2.run(NoDefense()).infected_fraction)
    assert np.mean(ours) <= np.mean(none)


def test_oracle_preserves_availability():
    env, _ = make_env()
    res = env.run(OracleContentAware(patch=True))
    assert res.availability == 1.0  # patching never takes a host offline


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))


def test_decoys_poison_hard_belief_but_soft_resists():
    """Belief-poisoning: decoy infections (not carrying the true CVE) make the
    hard belief exclude the truth, while the soft belief keeps it with mass."""
    from serum.attack.deception import choose_decoys
    env, pl = make_env()
    decoys = choose_decoys(env.g, pl, k=3, rng=np.random.default_rng(0))
    if not decoys:
        pytest.skip("no decoy candidates in this instance")
    env2 = ContainmentEnv(env.g, pl, env.seeds, decoys=decoys,
                          rng=np.random.default_rng(1))
    obs = env2.reset()
    hard = CVEBelief(env.g, mode="hard")
    soft = CVEBelief(env.g, mode="soft", noise=0.05)
    hard.update(obs.newly_infected, obs.seeds)
    soft.update(obs.newly_infected, obs.seeds)
    assert not hard.consistent[pl.cve]           # hard belief poisoned
    assert soft.posterior()[pl.cve] > 0          # soft belief retains the truth
