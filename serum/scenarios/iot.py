"""Mirai-style IoT botnet scenario for SERUM.

Turns SERUM's generic containment machinery into an IoT DDoS setting:

- The fleet is a mesh of IoT devices; each has a *device type* (IP camera,
  DVR, SOHO router, thermostat, doorbell, ...). Each device type is a natural
  monoculture at the *product* level -- every unit of a given model ships the
  same firmware image, hence the same set of CVEs. This is qualitatively
  different from the enterprise scenario (where monoculture is *segment*-level
  because network zones share an OS image); here it is *type*-level.
- A Mirai-style payload targets one widely-shared firmware CVE (by default,
  ``cve=0`` = default telnet credentials -- Mirai's flagship hook), which
  spans several device types. The vulnerable subgraph is broad but not
  universal, so both the outbreak size and its DDoS blast radius depend on
  the device-type mix.
- DDoS blast radius: each device carries a bandwidth ``value`` (Mbps). A
  compromised router conscripts far more uplink than a compromised smart bulb,
  so the botnet's DDoS capacity is proportional to the *value-weighted*
  outbreak, which is exactly SERUM's ``blast_radius`` metric.

Nothing in the generic simulator changes: this module only wires device types,
firmware profiles, criticality, and payload into the standard SERUM interfaces
(a ``networkx.Graph`` with per-node ``vuln``, ``value``, ``cost_isolate``, and
a ``Payload``). The framework stays general; IoT is one application binding.

Archetypes are drawn from the Mirai-era public retrospectives
(Antonakakis et al., USENIX Security 2017; Kolias et al., IEEE Computer 2017).
The numbers are illustrative device classes, not a live inventory.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

import networkx as nx
import numpy as np

from serum.sim.network import _base_topology
from serum.sim.payload import Payload


# Device catalog: (type_name, deployment_weight, firmware_cve_indices, ddos_mbps).
# Indices are keyed into ``DEFAULT_CVE_BETAS`` below. Deployment weights are
# unnormalised (they get normalised at build time). The order of entries is
# stable so tests can index into the catalog reliably.
DEFAULT_DEVICE_TYPES: tuple = (
    ("camera",     0.30, (0, 1),    30.0),   # IP cameras: telnet + web-UI RCE
    ("dvr",        0.25, (0, 2),    40.0),   # DVRs: telnet + RTSP auth bypass
    ("router",     0.12, (0, 3, 4), 250.0),  # SOHO routers: telnet + UPnP + WPS
    ("thermostat", 0.10, (1,),      10.0),   # smart thermostats: web-UI RCE
    ("doorbell",   0.08, (5,),      15.0),   # smart doorbells: MQTT bypass
    ("light",      0.08, (6,),      5.0),    # smart bulbs: token replay
    ("hub",        0.05, (0, 6),    60.0),   # smart-home hubs: telnet + token
    ("printer",    0.02, (7,),      20.0),   # network printers: legacy LPD
)


# Per-CVE transmissibility in the IoT universe. Higher = easier to exploit.
# Rough intuition:
#   0: default telnet credentials -- Mirai's wide-net hook, very easy
#   1: web-UI RCE -- moderate
#   2: RTSP auth bypass on DVRs -- moderate
#   3: UPnP misconfig on routers -- easy
#   4: WPS pin brute-force -- moderate
#   5: MQTT auth bypass on doorbells -- moderate
#   6: bulb/hub token replay -- easy but small footprint
#   7: legacy LPD printer bug -- moderate
DEFAULT_CVE_BETAS: tuple = (0.45, 0.20, 0.22, 0.30, 0.18, 0.20, 0.15, 0.20)


@dataclass
class IoTFleet:
    """A ready-to-run IoT fleet: graph + the device-type catalog it was built
    from. The graph is the object plugged into ``ContainmentEnv``; the extra
    fields exist for inspection and reproducibility (e.g. reporting the DDoS
    capacity share held by each device type)."""

    g: nx.Graph
    device_types: list          # per-node device type name (indexed like g.nodes())
    type_catalog: tuple         # the (name, weight, cves, mbps) rows used
    cve_betas: tuple            # per-CVE betas


def build_iot_fleet(
    n: int = 600,
    topology: str = "rgg",
    m: int = 3,
    device_types: Sequence = DEFAULT_DEVICE_TYPES,
    cve_betas: Sequence = DEFAULT_CVE_BETAS,
    cost_scales_with_value: bool = True,
    rng: np.random.Generator | None = None,
) -> IoTFleet:
    """Assemble an IoT fleet ready to plug into ``ContainmentEnv``.

    Each node is stamped with:
      - ``device_type`` (str)    : device class
      - ``vuln`` (frozenset[int]): firmware CVE indices for that class
      - ``value`` (float)        : DDoS bandwidth in Mbps -- the criticality
        weight for the ``blast_radius`` metric (= botnet uplink capacity)
      - ``cost_isolate`` (float) : defaults to ``value`` (isolating a router
        hurts more than isolating a bulb); pass ``cost_scales_with_value=False``
        to fall back to unit isolation cost.

    The topology default is ``rgg`` (random geometric graph), the closest
    off-the-shelf model of an IoT mesh / physical-proximity network. The other
    ``_base_topology`` families (``ba``, ``ws``, ``er``) also work.
    """
    rng = rng or np.random.default_rng()
    g = _base_topology(n, topology, m, rng)

    names = [t[0] for t in device_types]
    weights = np.array([t[1] for t in device_types], dtype=float)
    if weights.sum() <= 0:
        raise ValueError("device-type weights must sum to > 0")
    weights = weights / weights.sum()
    vuln_by_type = {t[0]: frozenset(int(c) for c in t[2]) for t in device_types}
    value_by_type = {t[0]: float(t[3]) for t in device_types}
    n_cves = len(cve_betas)

    # Sanity: every CVE referenced by any device type must be inside the beta
    # universe. Silent misalignment here would give a device a "vulnerability"
    # for which the payload has no beta -- a subtle simulation bug.
    for name, cves in vuln_by_type.items():
        for c in cves:
            if c < 0 or c >= n_cves:
                raise ValueError(
                    f"device type {name!r} references cve index {c}, but the "
                    f"beta universe has size {n_cves}"
                )

    types_out: list = []
    total_value = 0.0
    total_cost = 0.0
    for v in g.nodes():
        dt = names[int(rng.choice(len(names), p=weights))]
        types_out.append(dt)
        val = value_by_type[dt]
        cost = val if cost_scales_with_value else 1.0
        g.nodes[v]["device_type"] = dt
        g.nodes[v]["vuln"] = vuln_by_type[dt]
        g.nodes[v]["value"] = float(val)
        g.nodes[v]["cost_isolate"] = float(cost)
        total_value += val
        total_cost += cost

    g.graph["n_cves"] = int(n_cves)
    g.graph["topology"] = topology
    g.graph["scenario"] = "iot-mirai"
    g.graph["cve_betas"] = tuple(float(b) for b in cve_betas)
    g.graph["device_catalog"] = tuple(names)
    g.graph["total_value"] = float(total_value)
    g.graph["total_cost"] = float(total_cost)
    return IoTFleet(
        g=g,
        device_types=types_out,
        type_catalog=tuple(device_types),
        cve_betas=tuple(cve_betas),
    )


def mirai_payload(fleet: IoTFleet, cve: int = 0) -> Payload:
    """A Mirai-style payload targeting one shared firmware CVE.

    Default ``cve=0`` = default-telnet-credentials, which spans camera / DVR /
    router / hub in ``DEFAULT_DEVICE_TYPES`` -- the wide-net hook that gave the
    original Mirai its footprint. Pass a different index to weaponise a
    narrower vulnerability (e.g. router-only UPnP)."""
    if cve < 0 or cve >= len(fleet.cve_betas):
        raise ValueError(f"cve {cve} out of range for the IoT universe")
    return Payload(cve=int(cve), beta=float(fleet.cve_betas[cve]))


def ddos_capacity(g: nx.Graph, infected) -> float:
    """Total DDoS capacity (Mbps) held by the given set of infected devices.

    This is the same quantity that ``EpisodeResult.blast_radius`` reports as a
    fraction of the fleet total; exposed here for scripts that want the
    absolute number instead of the ratio."""
    inf = set(infected)
    return float(sum(g.nodes[v].get("value", 0.0) for v in inf))
