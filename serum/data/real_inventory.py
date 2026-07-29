"""Import a MEASURED host-level inventory into a SERUM network (mitigates L1).

Limitation L1: SERUM's favorable-regime result is validated on real *topology*
and real *CVE catalog*, but the host->CVE mapping is *modeled* (product-popularity
+ software-monoculture zones), not *measured*. Closing L1 requires a real
segmented network with measured per-host vulnerabilities -- proprietary scan data
(e.g. an enterprise Tenable/Nessus export) restricted by privacy, which we cannot
publish or fabricate.

This module makes the project *ready to close L1 the moment such data is
available*: it builds a SERUM graph directly from two files a defender already
has, with the host->CVE mapping taken **verbatim from the scan** (measured, not
modeled). Everything downstream (belief, baselines, content-aware agent, env)
then runs unchanged, because the only contract a SERUM network must satisfy is:
each node carries a ``vuln`` frozenset of integer CVE ids, and
``g.graph["n_cves"]`` records the universe size.

Expected inputs (both are formats a real scan+asset inventory export to):

* **scan** -- a "long" table of findings, one (host, cve) pair per row. Accepts
  a CSV path or an iterable of (host_id, cve_id) pairs. Column names are
  auto-detected (host: one of host/host_id/asset/ip/fqdn; cve: one of
  cve/cve_id/plugin_cve/vuln). Hosts with zero findings are still included if
  they appear in the topology.
* **edges** -- the reachability/topology graph, one ``host_a,host_b`` pair per
  line (CSV or whitespace). This is the network the worm can traverse (subnet
  adjacency, VLAN reachability, or a router/switch map).

CVE ids are interned to a contiguous integer universe; the string<->index map is
stored on ``g.graph["cve_ids"]`` so results can be reported against real CVE ids.
"""

from __future__ import annotations

import csv
from pathlib import Path

import networkx as nx

_HOST_KEYS = ("host", "host_id", "hostid", "asset", "asset_id", "ip", "fqdn", "name")
_CVE_KEYS = ("cve", "cve_id", "cveid", "plugin_cve", "vuln", "vulnerability")


def _pick(fieldnames, keys):
    lower = {f.lower().strip(): f for f in fieldnames}
    for k in keys:
        if k in lower:
            return lower[k]
    return None


def _read_scan_csv(path):
    """Yield (host, cve) string pairs from a long-format scan CSV."""
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return
        hcol = _pick(reader.fieldnames, _HOST_KEYS)
        ccol = _pick(reader.fieldnames, _CVE_KEYS)
        if hcol is None or ccol is None:
            raise ValueError(
                f"scan CSV must have a host column ({_HOST_KEYS}) and a CVE column "
                f"({_CVE_KEYS}); got {reader.fieldnames}")
        for row in reader:
            host = (row.get(hcol) or "").strip()
            cve = (row.get(ccol) or "").strip()
            if host and cve:
                yield host, cve


def _read_edges(path):
    """Yield (host_a, host_b) string pairs from an edge list (CSV or whitespace)."""
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in (line.split(",") if "," in line else line.split())]
        if len(parts) >= 2 and parts[0] and parts[1]:
            yield parts[0], parts[1]


def build_inventory_network(scan_pairs, edges) -> nx.Graph:
    """Build a SERUM graph from measured (host, cve) findings and a topology.

    Parameters
    ----------
    scan_pairs : iterable of (host_id, cve_id) -- measured findings (strings).
    edges      : iterable of (host_a, host_b) -- topology edges (strings).

    The vulnerability set of each host is taken *verbatim* from ``scan_pairs``
    (measured), which is the sole difference from the modeled generators.
    """
    edges = [(str(a), str(b)) for a, b in edges]
    findings: dict[str, set] = {}
    cve_ids: dict[str, int] = {}          # cve string -> contiguous index

    def intern(cve: str) -> int:
        if cve not in cve_ids:
            cve_ids[cve] = len(cve_ids)
        return cve_ids[cve]

    for host, cve in scan_pairs:
        findings.setdefault(str(host), set()).add(intern(str(cve)))

    g = nx.Graph()
    hosts = set(findings)
    for a, b in edges:
        hosts.add(a); hosts.add(b)
    g.add_nodes_from(hosts)
    g.add_edges_from((a, b) for a, b in edges if a != b)

    for h in g.nodes():
        g.nodes[h]["vuln"] = frozenset(findings.get(h, set()))   # measured, verbatim

    g.graph["n_cves"] = max(len(cve_ids), 1)
    g.graph["cve_ids"] = {v: k for k, v in cve_ids.items()}      # index -> real CVE id
    g.graph["topology"] = "real-inventory"
    g.graph["data_source"] = "measured-scan"
    return g


def load_scan_network(scan, edges) -> nx.Graph:
    """Load a measured-inventory network from files or in-memory iterables.

    ``scan`` : a CSV path (str/Path) or an iterable of (host, cve) pairs.
    ``edges``: a file path (str/Path) or an iterable of (host_a, host_b) pairs.
    """
    scan_pairs = _read_scan_csv(scan) if isinstance(scan, (str, Path)) else scan
    edge_pairs = _read_edges(edges) if isinstance(edges, (str, Path)) else edges
    # materialise the scan generator before building (it is consumed once)
    return build_inventory_network(list(scan_pairs), list(edge_pairs))
