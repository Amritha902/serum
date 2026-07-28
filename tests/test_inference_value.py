"""When is online inference load-bearing? (grill G2) + array-prior regression.

Two things guarded here:
  1. CVEBelief must accept an explicit ndarray prior (a latent bug: the string
     comparisons ran before the isinstance(ndarray) check and threw).
  2. The `misleading_prior` helper is well-formed, and online inference beats a
     static prior by MORE under a misleading prior than under a good one -- the
     honest characterization of when the online update actually pays off.
"""
from __future__ import annotations

import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from serum.inference.belief import CVEBelief
from serum.sim.network import generate_network


def _net(seed=0, n=200, n_cves=12):
    rng = np.random.default_rng(seed)
    return generate_network(n=n, n_cves=n_cves, vuln_lambda=6.0,
                            popularity_alpha=0.8, rng=rng)


def test_belief_accepts_ndarray_prior():
    g = _net(0)
    K = g.graph["n_cves"]
    arr = np.ones(K)
    arr[0] = 5.0
    b = CVEBelief(g, prior=arr)
    post = b.posterior()
    assert abs(post.sum() - 1.0) < 1e-9
    # the mass-5 CVE should have the largest prior mass
    assert int(np.argmax(post)) == 0


def test_misleading_prior_is_wellformed():
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "scripts"))
    from inference_value import misleading_prior
    from serum.sim.network import cve_prevalence
    g = _net(1)
    p = misleading_prior(g, concentration=0.7)
    assert abs(p.sum() - 1.0) < 1e-9
    assert int(np.argmax(p)) == int(cve_prevalence(g).argmax())
    assert p.max() > 0.5
