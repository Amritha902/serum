"""Tests for the IoT-botnet scenario (Mirai-style)."""
import os
import sys

import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from serum.agents.content_aware import ContentAwareAgent
from serum.baselines.heuristics import NoDefense
from serum.scenarios.iot import (
    DEFAULT_CVE_BETAS,
    DEFAULT_DEVICE_TYPES,
    build_iot_fleet,
    ddos_capacity,
    mirai_payload,
)
from serum.sim.environment import ContainmentEnv, Status


def _fleet(seed: int = 0, n: int = 200):
    return build_iot_fleet(n=n, rng=np.random.default_rng(seed))


def test_iot_fleet_has_required_node_attrs():
    """Every device must carry device_type, vuln, value, and cost_isolate --
    the four attributes the containment env + blast-radius metric expect."""
    fleet = _fleet()
    g = fleet.g
    assert g.number_of_nodes() > 0
    for _, d in g.nodes(data=True):
        assert d["device_type"] in {t[0] for t in DEFAULT_DEVICE_TYPES}
        assert isinstance(d["vuln"], frozenset) and len(d["vuln"]) >= 1
        assert d["value"] > 0.0
        assert d["cost_isolate"] > 0.0
    assert g.graph["n_cves"] == len(DEFAULT_CVE_BETAS)
    assert g.graph["scenario"] == "iot-mirai"


def test_iot_firmware_is_product_level_monoculture():
    """All devices of a given type share the *same* firmware CVE set. This is
    the qualitative property that separates IoT (product-level monoculture)
    from enterprise (segment-level monoculture)."""
    fleet = _fleet()
    by_type: dict = {}
    for _, d in fleet.g.nodes(data=True):
        by_type.setdefault(d["device_type"], set()).add(d["vuln"])
    for dt, sets in by_type.items():
        assert len(sets) == 1, (
            f"device type {dt!r} has {len(sets)} distinct vuln sets -- "
            f"firmware monoculture broken"
        )


def test_mirai_payload_only_hits_carriers():
    """A Mirai-style payload (default telnet creds) must not infect device
    classes whose firmware does not carry the target CVE (bulbs, thermostats,
    doorbells, printers under the default catalog)."""
    fleet = _fleet(seed=1, n=400)
    payload = mirai_payload(fleet, cve=0)
    # find carriers/non-carriers according to the catalog
    non_carrier_types = {t[0] for t in DEFAULT_DEVICE_TYPES if 0 not in t[2]}
    non_carrier_nodes = {v for v, d in fleet.g.nodes(data=True)
                         if d["device_type"] in non_carrier_types}
    carriers = [v for v, d in fleet.g.nodes(data=True) if 0 in d["vuln"]]
    if len(carriers) < 3:
        pytest.skip("degenerate fleet: too few Mirai carriers to seed")
    seed_rng = np.random.default_rng(2)
    seeds = [int(v) for v in seed_rng.choice(carriers, size=3, replace=False)]
    env = ContainmentEnv(fleet.g, payload, seeds,
                         budget_per_step=0, horizon=25,
                         rng=np.random.default_rng(3))
    res = env.run(NoDefense())
    # Non-carrier device types must be intact -- vulnerability-gating is a
    # simulator invariant, but re-checking it inside the IoT binding guards
    # against a wiring mistake in the catalog.
    for v in non_carrier_nodes:
        assert env.status[v] != Status.INFECTED, (
            f"non-carrier device {v} ({fleet.g.nodes[v]['device_type']}) was "
            f"infected by a Mirai-style payload"
        )
    # And the outbreak actually happened (at least the seeds and some spread).
    assert res.infected_fraction > 0.0


def test_blast_radius_reflects_ddos_capacity_share():
    """SERUM's blast_radius on an IoT fleet must equal the DDoS capacity share
    of the infected devices -- because value = device bandwidth here."""
    fleet = _fleet(seed=4)
    payload = mirai_payload(fleet, cve=0)
    carriers = [v for v, d in fleet.g.nodes(data=True) if 0 in d["vuln"]]
    if len(carriers) < 3:
        pytest.skip("degenerate fleet")
    seeds = [int(v) for v in
             np.random.default_rng(5).choice(carriers, size=3, replace=False)]
    env = ContainmentEnv(fleet.g, payload, seeds,
                         budget_per_step=0, horizon=25,
                         rng=np.random.default_rng(6))
    res = env.run(NoDefense())
    # reconstruct capacity share independently from env's own bookkeeping.
    total_cap = ddos_capacity(fleet.g, fleet.g.nodes())
    inf_cap = ddos_capacity(fleet.g, env._ever)
    ratio = inf_cap / total_cap
    assert abs(res.blast_radius - ratio) < 1e-9


def test_content_aware_beats_no_defense_on_ddos_blast_radius():
    """Sanity: on an IoT outbreak, content-aware must not do worse than no
    defense on either metric (a paired mean check across a few trials)."""
    inf_ca, inf_none = [], []
    blast_ca, blast_none = [], []
    for s in range(4):
        fleet = _fleet(seed=s, n=300)
        payload = mirai_payload(fleet, cve=0)
        carriers = [v for v, d in fleet.g.nodes(data=True) if 0 in d["vuln"]]
        if len(carriers) < 3:
            continue
        seeds = [int(v) for v in
                 np.random.default_rng(s + 11).choice(carriers, size=3,
                                                      replace=False)]
        env_a = ContainmentEnv(fleet.g, payload, seeds,
                               budget_per_step=3, horizon=25,
                               rng=np.random.default_rng(s + 100))
        env_b = ContainmentEnv(fleet.g, payload, seeds,
                               budget_per_step=3, horizon=25,
                               rng=np.random.default_rng(s + 100))
        r_a = env_a.run(ContentAwareAgent(env_a.g, value_weighted=True))
        r_b = env_b.run(NoDefense())
        inf_ca.append(r_a.infected_fraction)
        inf_none.append(r_b.infected_fraction)
        blast_ca.append(r_a.blast_radius)
        blast_none.append(r_b.blast_radius)
    assert len(inf_ca) >= 3
    assert np.mean(inf_ca) <= np.mean(inf_none) + 1e-9
    assert np.mean(blast_ca) <= np.mean(blast_none) + 1e-9


def test_mirai_payload_rejects_out_of_range_cve():
    fleet = _fleet()
    with pytest.raises(ValueError):
        mirai_payload(fleet, cve=len(DEFAULT_CVE_BETAS))
    with pytest.raises(ValueError):
        mirai_payload(fleet, cve=-1)


def test_build_iot_fleet_catches_bad_catalog():
    """A device catalog that references a CVE beyond the beta universe must
    raise -- silent misalignment would leave a device with a 'vulnerability'
    the payload has no beta for."""
    bad_catalog = (
        ("phantom", 1.0, (99,), 10.0),
    )
    with pytest.raises(ValueError):
        build_iot_fleet(n=10, device_types=bad_catalog,
                        cve_betas=(0.1, 0.2), rng=np.random.default_rng(0))
