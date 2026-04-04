#!/usr/bin/env python3
"""
Fetch solar-related CVEs from NIST NVD.
NO API KEY REQUIRED — but rate-limited to 5 req/30s without one.
Free API key at https://nvd.nist.gov/developers/request-an-api-key lifts limit to 50 req/30s.

Usage:
    python 01_fetch_nvd_cves.py
    python 01_fetch_nvd_cves.py --api-key YOUR_NVD_KEY
"""

import argparse
import json
import time
from pathlib import Path

import requests

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# All CVE IDs from the plan + a keyword search for solar
TARGET_CVES = [
    "CVE-2024-50685",
    "CVE-2024-50692",
    "CVE-2024-50693",
    "CVE-2024-50686",
    "CVE-2025-0731",
    "CVE-2022-29303",
    "CVE-2023-23333",
    "CVE-2025-36753",
]

KEYWORD_SEARCHES = [
    "solar inverter",
    "photovoltaic",
    "Growatt",
    "Sungrow",
    "SolarView",
]

OUTPUT_DIR = Path(__file__).parent.parent / "output"
OUTPUT_DIR.mkdir(exist_ok=True)


def get_headers(api_key: str | None) -> dict:
    if api_key:
        return {"apiKey": api_key}
    return {}


def fetch_cve_by_id(cve_id: str, headers: dict) -> dict | None:
    url = f"{NVD_BASE}?cveId={cve_id}"
    resp = requests.get(url, headers=headers, timeout=15)
    if resp.status_code == 200:
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        return vulns[0] if vulns else None
    print(f"  [WARN] {cve_id} → HTTP {resp.status_code}")
    return None


def fetch_cves_by_keyword(keyword: str, headers: dict, max_results: int = 20) -> list:
    url = f"{NVD_BASE}?keywordSearch={requests.utils.quote(keyword)}&resultsPerPage={max_results}"
    resp = requests.get(url, headers=headers, timeout=15)
    if resp.status_code == 200:
        return resp.json().get("vulnerabilities", [])
    print(f"  [WARN] keyword '{keyword}' → HTTP {resp.status_code}")
    return []


def parse_cve(vuln: dict) -> dict:
    cve = vuln.get("cve", {})
    cve_id = cve.get("id", "UNKNOWN")

    # Timestamps — NVD returns full ISO 8601 datetimes, e.g. "2024-11-01T17:15:14.547"
    published_raw = cve.get("published", "")       # when CVE was first added to NVD
    modified_raw = cve.get("lastModified", "")     # last time any field was updated
    vuln_status = cve.get("vulnStatus", "")        # "Analyzed" | "Modified" | "Awaiting Analysis" | "Rejected"

    # CVSS score — prefer v3.1, fall back to v3.0, then v2
    metrics = cve.get("metrics", {})
    cvss_score = None
    cvss_severity = None
    cvss_version = None
    cvss_vector = None
    cvss_source = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            cvss_data = m.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_severity = m.get("baseSeverity") or cvss_data.get("baseSeverity")
            cvss_version = cvss_data.get("version")
            cvss_vector = cvss_data.get("vectorString")
            cvss_source = m.get("source")  # e.g. "nvd@nist.gov" or reporter org
            break

    descriptions = cve.get("descriptions", [])
    desc_en = next((d["value"] for d in descriptions if d["lang"] == "en"), "")

    references = [r["url"] for r in cve.get("references", [])]

    # Days since published / last modified (useful for "how stale is this?")
    from datetime import datetime, timezone

    def parse_iso(ts: str) -> datetime | None:
        if not ts:
            return None
        try:
            # NVD timestamps may or may not have a timezone offset
            ts_clean = ts.rstrip("Z")
            return datetime.fromisoformat(ts_clean).replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    now = datetime.now(timezone.utc)
    published_dt = parse_iso(published_raw)
    modified_dt = parse_iso(modified_raw)

    days_since_published = (now - published_dt).days if published_dt else None
    days_since_modified = (now - modified_dt).days if modified_dt else None

    return {
        "cve_id": cve_id,
        # Full timestamps
        "published": published_raw,
        "published_date": published_raw[:10] if published_raw else "",
        "last_modified": modified_raw,
        "last_modified_date": modified_raw[:10] if modified_raw else "",
        # Age in days (useful for dashboard "how old is this unpatched vuln?")
        "days_since_published": days_since_published,
        "days_since_modified": days_since_modified,
        # Analysis status from NVD
        "vuln_status": vuln_status,
        # CVSS
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cvss_version": cvss_version,
        "cvss_vector": cvss_vector,
        "cvss_source": cvss_source,
        "description": desc_en[:400],
        "references": references[:5],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-key", default=None, help="NVD API key (optional, lifts rate limit)")
    args = parser.parse_args()

    headers = get_headers(args.api_key)
    delay = 0.6 if args.api_key else 6.5  # respect rate limits

    results = {}

    # 1. Fetch specific CVEs by ID
    print("=== Fetching specific CVEs by ID ===")
    for cve_id in TARGET_CVES:
        print(f"  → {cve_id}")
        vuln = fetch_cve_by_id(cve_id, headers)
        if vuln:
            results[cve_id] = parse_cve(vuln)
        else:
            results[cve_id] = {"cve_id": cve_id, "error": "not found in NVD"}
        time.sleep(delay)

    # 2. Keyword searches
    print("\n=== Keyword searches ===")
    keyword_hits = {}
    for keyword in KEYWORD_SEARCHES:
        print(f"  → '{keyword}'")
        vulns = fetch_cves_by_keyword(keyword, headers)
        for v in vulns:
            parsed = parse_cve(v)
            if parsed["cve_id"] not in results:  # don't overwrite direct lookups
                keyword_hits[parsed["cve_id"]] = parsed
        print(f"     found {len(vulns)} results")
        time.sleep(delay)

    out = {
        "direct_lookups": results,
        "keyword_discoveries": keyword_hits,
        "total": len(results) + len(keyword_hits),
    }

    out_path = OUTPUT_DIR / "nvd_cves.json"
    out_path.write_text(json.dumps(out, indent=2))
    print(f"\n✓ Saved {out['total']} CVE records → {out_path}")

    # Print a quick summary table
    print("\n--- Summary ---")
    print(f"{'CVE ID':<20} {'CVSS':>5}  {'Severity':<10}  {'Published':<12}  {'Days Old':>8}  {'Status':<20}  Description")
    print("-" * 115)
    for cve_id, rec in sorted(results.items(), key=lambda x: -(x[1].get("cvss_score") or 0)):
        score = rec.get("cvss_score", "?")
        sev = rec.get("cvss_severity", "?")
        pub = rec.get("published_date", "?")
        age = rec.get("days_since_published")
        age_str = str(age) if age is not None else "?"
        status = rec.get("vuln_status", "?")[:20]
        desc = rec.get("description", "")[:40]
        print(f"{cve_id:<20} {str(score):>5}  {str(sev):<10}  {pub:<12}  {age_str:>8}  {status:<20}  {desc}")


if __name__ == "__main__":
    main()
