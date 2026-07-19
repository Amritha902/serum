"""NVD 2.0 API client: robust, cached, rate-limited ingestion of raw CVE records.

The National Vulnerability Database exposes ~370k CVEs via a paged REST API. We
fetch pages of raw JSON, cache each page to disk (so re-runs are free and the
pipeline is reproducible offline), and respect NVD's rate limits with polite
backoff. An API key (env ``NVD_API_KEY``) raises the limit but is optional.

This module only *fetches and caches*; parsing/validation lives in ``clean.py``.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_PAGE = 2000                     # NVD hard cap on resultsPerPage
DEFAULT_CACHE = "data/raw/nvd"

# NVD asks for <=5 req/30s without a key, <=50 with one. Be polite.
_DELAY_NO_KEY = 6.5
_DELAY_KEY = 0.8


class NVDClient:
    def __init__(self, cache_dir: str = DEFAULT_CACHE, api_key: str | None = None,
                 sleep=time.sleep):
        self.cache_dir = cache_dir
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self._delay = _DELAY_KEY if self.api_key else _DELAY_NO_KEY
        self._sleep = sleep
        os.makedirs(cache_dir, exist_ok=True)

    # -- low level -------------------------------------------------------
    def _cache_path(self, start: int, per_page: int, params: dict) -> str:
        extra = "_".join(f"{k}-{v}" for k, v in sorted(params.items()))
        extra = "".join(c if c.isalnum() or c in "-_" else "" for c in extra)
        suffix = f"_{extra}" if extra else ""
        return os.path.join(self.cache_dir, f"page_{start:07d}_{per_page}{suffix}.json")

    def _fetch_page(self, start: int, per_page: int, params: dict | None = None,
                    retries: int = 4) -> dict:
        """Fetch one page, using the on-disk cache when present."""
        params = params or {}
        path = self._cache_path(start, per_page, params)
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)

        query = {"resultsPerPage": per_page, "startIndex": start, **params}
        url = f"{API}?{urllib.parse.urlencode(query)}"
        headers = {"User-Agent": "serum-research/0.1"}
        if self.api_key:
            headers["apiKey"] = self.api_key

        last_err = None
        for attempt in range(retries):
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=60) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                with open(path, "w") as f:
                    json.dump(data, f)
                self._sleep(self._delay)   # be polite between live requests
                return data
            except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as e:
                last_err = e
                backoff = self._delay * (2 ** attempt)
                self._sleep(backoff)       # exponential backoff on 403/429/5xx
        raise RuntimeError(f"NVD fetch failed at start={start}: {last_err}")

    # -- high level ------------------------------------------------------
    def iter_raw_cves(self, limit: int = 4000, per_page: int = MAX_PAGE,
                      params: dict | None = None):
        """Yield raw ``cve`` dicts up to ``limit``, paging as needed.

        ``params`` are extra NVD query params, e.g. a published-date window
        {"pubStartDate": ..., "pubEndDate": ...} to fetch recent CVEs."""
        per_page = min(per_page, MAX_PAGE)
        fetched = 0
        start = 0
        total = None
        while fetched < limit:
            page = self._fetch_page(start, min(per_page, limit - fetched), params)
            if total is None:
                total = page.get("totalResults", 0)
            vulns = page.get("vulnerabilities", [])
            if not vulns:
                break
            for item in vulns:
                yield item["cve"]
                fetched += 1
                if fetched >= limit:
                    break
            start += len(vulns)
            if total is not None and start >= total:
                break

    def fetch_raw(self, limit: int = 4000, params: dict | None = None) -> list:
        return list(self.iter_raw_cves(limit=limit, params=params))

    @staticmethod
    def recent_window(days: int = 120, today: str | None = None) -> dict:
        """Build a published-date window param dict for the last ``days`` days.

        ``today`` is an ISO date (YYYY-MM-DD); required because callers in
        deterministic contexts should pass an explicit date. NVD caps the window
        at 120 days."""
        from datetime import date, timedelta
        if today is None:
            end = date.today()
        else:
            end = date.fromisoformat(today)
        start = end - timedelta(days=min(days, 120))
        fmt = "T00:00:00.000"
        return {"pubStartDate": start.isoformat() + fmt,
                "pubEndDate": end.isoformat() + fmt}
