# SERUM Application: Mirai-style IoT botnet containment

This is SERUM's flagship application binding. The framework is deliberately
general -- vulnerability-gated spread + payload-blind Bayesian containment --
and this document specialises it to the IoT-botnet setting that motivated the
project in the first place. Nothing in the generic simulator is changed; the
binding is a scenario module (`serum/scenarios/iot.py`), a config
(`configs/iot.yaml`), and a headline experiment (`scripts/iot_botnet.py`).

## Why IoT

Mirai (2016) and its many descendants (Satori, Reaper, Mozi, Mirai_ptea, ...)
share three properties that make them a natural home for SERUM's assumptions:

1. **Vulnerability-gated spread.** Mirai's canonical hook was default telnet
   credentials shipped in the firmware of a specific family of cameras / DVRs /
   routers. A payload landed only on devices whose firmware carried the
   weakness; every other device on the LAN was untouched by that exploit path.
   This is *exactly* SERUM's model: the true contagion graph is a subgraph of
   the physical topology induced by which hosts carry the target CVE.
2. **Product-level monoculture.** Firmware is a natural monoculture at the
   *product* level -- every unit of a given camera model runs the same image,
   hence carries the same CVEs. Where the enterprise scenario had monoculture
   at the *segment* level (a department's desktops share an OS image), the
   IoT scenario has it at the *type* level (all Foscam FI9821W units share
   firmware). SERUM's segment-correlated software model absorbs this directly:
   we just make the "segment" a device type.
3. **DDoS blast radius, not device count.** The operational quantity for an
   IoT botnet is the *bandwidth* it can conscript, not the raw count of
   compromised devices. Ten compromised SOHO routers with 250 Mbps uplinks
   outshoot a thousand compromised smart bulbs at 5 Mbps. SERUM's
   `blast_radius` metric already reports the fraction of total host `value`
   ever infected -- we simply set `value` to device uplink bandwidth and the
   metric becomes DDoS capacity conscripted (as a fraction of the fleet
   ceiling).

## Model

A synthetic IoT fleet is built from a compact device catalog (see
`serum/scenarios/iot.py::DEFAULT_DEVICE_TYPES`). Each entry is
`(type_name, deployment_weight, firmware_cve_indices, ddos_mbps)`; devices are
placed on an `rgg` (random geometric) mesh -- the physical-proximity model
closest to a real IoT deployment. Every device is stamped with:

- `device_type`: its class (`camera`, `dvr`, `router`, ...);
- `vuln`: the firmware CVE set for that class;
- `value`: DDoS uplink bandwidth (Mbps) -- the criticality weight for
  `blast_radius`;
- `cost_isolate` = `value` by default (isolating a router hurts more than
  isolating a smart bulb).

The default CVE universe has 8 entries reflecting Mirai-era classes: default
telnet credentials, web-UI RCE, DVR RTSP auth bypass, router UPnP misconfig,
WPS pin brute-force, doorbell MQTT bypass, bulb/hub token replay, legacy LPD
printer bug. Per-CVE `beta`s (transmissibility) roughly track ease of
exploitation.

A Mirai-style payload (`mirai_payload`) targets one shared firmware CVE
(default: index 0 = default telnet credentials), which spans camera / DVR /
router / hub. The vulnerable subgraph is therefore broad but not universal.

## Headline experiment

`scripts/iot_botnet.py` runs a paired comparison of four policies on the same
fleet, payload, and spread randomness:

- `no-defense`         -- lower bound (let the botnet burn).
- `degree`             -- classic structure-only heuristic.
- `content-aware`      -- SERUM's belief-weighted defender, value-blind.
- `content-aware+value`-- SERUM steered by device bandwidth (DDoS-aware).

Two metrics per policy:

- `infected_fraction`  -- fraction of *devices* recruited.
- `blast_radius`       -- fraction of *DDoS capacity* conscripted.

See `results/iot_botnet.json` and the corresponding entry in `docs/DEVLOG.md`
for the current numbers. The honest expectation (mirroring the enterprise
blast-radius study) is that content-aware reduces both metrics vs structural
baselines, and the value-weighted variant further reduces `blast_radius` at
possibly a small cost on `infected_fraction` -- a real steering trade, not a
free win. Whatever the run produces, it is reported truthfully.

## What this application does *not* claim

- The device catalog is illustrative, not a live inventory. It captures the
  Mirai-era mix qualitatively (order-of-magnitude device populations,
  bandwidth, and firmware CVE overlap) but is not calibrated against a
  present-day scan.
- The topology (`rgg`) is a proximity mesh, not a routed graph. Real IoT
  deployments blend LAN mesh with WAN reachability; both are within reach of
  SERUM's `_base_topology` families, but the headline uses `rgg` as the
  natural default.
- The blast-radius metric is bandwidth-conscripted, not observed DDoS
  throughput at a victim -- the two differ because of upstream shaping,
  scrubbing, and target capacity; those are downstream of the botnet-formation
  problem SERUM addresses.
