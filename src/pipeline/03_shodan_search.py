#!/usr/bin/env python3
"""
Shodan search for exposed solar inverter management interfaces.
REQUIRES SHODAN API KEY — set env var SHODAN_API_KEY or pass --api-key.

Free tier:    100 results/month, no export
Academic:     Full results, export available
Paid ($49/mo): 10,000 query credits, download

Get a key at https://account.shodan.io/

Usage:
    export SHODAN_API_KEY=your_key_here
    python 03_shodan_search.py
    python 03_shodan_search.py --query 'http.title:"SolarView Compact"' --limit 50
    python 03_shodan_search.py --all-queries --limit 100
"""

import argparse
import json
import os
import time
from pathlib import Path

# pip install shodan
try:
    import shodan
except ImportError:
    print("Run: pip install shodan")
    raise

OUTPUT_DIR = Path(__file__).parent.parent.parent / "output"
OUTPUT_DIR.mkdir(exist_ok=True)

# All queries from shodan_web_queries.txt, grouped by vendor
QUERIES = {
    "Growatt": [
        '"Growatt" port:80,443,8080',
        'http.title:"Growatt"',
        '"server.growatt.com"',
    ],
    "Sungrow": [
        '"Sungrow" port:80,443',
        'http.title:"iSolarCloud"',
        '"WiNet" port:80',
    ],
    "SMA": [
        'http.title:"Sunny Webbox"',
        'http.title:"SunnyPortal"',
        '"SMA" "Solar" port:80,443',
    ],
    "SolarView": [
        'http.title:"SolarView Compact"',
    ],
    "Generic_Industrial": [
        'port:502 "solar"',
        'port:1883 "solar"',
        'port:8899 "inverter"',
    ],
    "Generic_Solar": [
        'http.title:"PV Monitor"',
        'http.title:"PV System"',
    ],
}

# CVE-vendor keyword mapping for cross-referencing
VENDOR_KEYWORDS = {
    "Growatt":  ["growatt", "shinewifi", "shinelan"],
    "Sungrow":  ["sungrow", "isolarcloud", "winet"],
    "SMA":      ["sma", "sunnyportal", "sunny webbox"],
    "SolarView": ["solarview", "solar view"],
}


def identify_vendor(result: dict) -> str:
    """Guess vendor from banner, HTML, and product fields."""
    text = " ".join([
        result.get("data", ""),
        result.get("product", ""),
        str(result.get("http", {}).get("title", "")),
        str(result.get("http", {}).get("html", ""))[:500],
    ]).lower()

    for vendor, keywords in VENDOR_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            return vendor
    return "Unknown"


def check_default_creds_indicator(result: dict) -> bool:
    """Heuristic: look for default credential hints in response."""
    text = str(result.get("data", "")).lower()
    indicators = ["123456", "default password", "admin/admin", "password: admin"]
    return any(ind in text for ind in indicators)


def extract_firmware(result: dict) -> str | None:
    """Try to pull firmware version from banner/headers."""
    data = result.get("data", "")
    http = result.get("http", {})
    headers = str(http.get("headers", ""))
    html = str(http.get("html", ""))[:1000]

    import re
    patterns = [
        r"firmware[:\s/]+v?([\d.]+)",
        r"version[:\s/]+v?([\d.]+)",
        r"fw[:\s/]+v?([\d.]+)",
    ]
    for src in [data, headers, html]:
        for pat in patterns:
            m = re.search(pat, src, re.IGNORECASE)
            if m:
                return m.group(1)
    return None


def flatten_result(result: dict, query_vendor: str) -> dict:
    """Convert a Shodan result object to a flat dict."""
    http = result.get("http", {})
    ssl = result.get("ssl", {})
    location = result.get("location", {})

    return {
        "ip": result.get("ip_str"),
        "port": result.get("port"),
        "transport": result.get("transport", "tcp"),
        "vendor": identify_vendor(result) or query_vendor,
        "query_vendor": query_vendor,
        "product": result.get("product", ""),
        "os": result.get("os", ""),
        "country": location.get("country_code", ""),
        "country_name": location.get("country_name", ""),
        "region": location.get("region_code", ""),
        "city": location.get("city", ""),
        "lat": location.get("latitude"),
        "lon": location.get("longitude"),
        "org": result.get("org", ""),
        "isp": result.get("isp", ""),
        "asn": result.get("asn", ""),
        "hostnames": result.get("hostnames", []),
        "http_title": http.get("title", ""),
        "http_status": http.get("status"),
        "has_tls": bool(ssl),
        "tls_cert_subject": ssl.get("cert", {}).get("subject", {}).get("CN", "") if ssl else "",
        "open_ports": result.get("ports", [result.get("port")]),
        "has_modbus": 502 in result.get("ports", [result.get("port", 0)]),
        "has_mqtt": 1883 in result.get("ports", [result.get("port", 0)]),
        "default_creds_indicator": check_default_creds_indicator(result),
        "firmware_version": extract_firmware(result),
        "last_seen": result.get("timestamp", "")[:10] if result.get("timestamp") else "",
        "shodan_id": result.get("_shodan", {}).get("id", ""),
    }


def run_query(api: shodan.Shodan, query: str, vendor: str, limit: int) -> list[dict]:
    results = []
    try:
        print(f"  Querying: {query[:60]}")
        search = api.search(query, limit=limit)
        total = search.get("total", 0)
        print(f"  Total matches on Shodan: {total:,}")
        for result in search.get("matches", []):
            results.append(flatten_result(result, vendor))
        print(f"  Retrieved: {len(results)} (limited to {limit})")
    except shodan.APIError as e:
        print(f"  [ERROR] {e}")
    return results


def deduplicate(devices: list[dict]) -> list[dict]:
    seen = set()
    unique = []
    for d in devices:
        key = (d["ip"], d["port"])
        if key not in seen:
            seen.add(key)
            unique.append(d)
    return unique


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-key", default=os.environ.get("SHODAN_API_KEY"))
    parser.add_argument("--query", help="Run a single custom query")
    parser.add_argument("--all-queries", action="store_true", help="Run all predefined queries")
    parser.add_argument("--vendor", default="all", help="Vendor to query (default: all)")
    parser.add_argument("--limit", type=int, default=100, help="Results per query (default: 100)")
    args = parser.parse_args()

    if not args.api_key:
        print("ERROR: SHODAN_API_KEY not set.")
        print("Set it with: export SHODAN_API_KEY=your_key")
        print("Or pass: --api-key YOUR_KEY")
        return

    api = shodan.Shodan(args.api_key)

    # Show account info
    try:
        info = api.info()
        print(f"Shodan account: {info.get('query_credits', '?')} query credits remaining\n")
    except Exception as e:
        print(f"[WARN] Could not fetch account info: {e}\n")

    all_devices = []

    if args.query:
        # Single custom query
        devices = run_query(api, args.query, "Custom", args.limit)
        all_devices.extend(devices)
    else:
        # Run predefined queries
        vendors_to_run = (
            list(QUERIES.keys())
            if (args.all_queries or args.vendor == "all")
            else [args.vendor]
        )

        for vendor in vendors_to_run:
            if vendor not in QUERIES:
                print(f"[WARN] Unknown vendor: {vendor}. Options: {list(QUERIES.keys())}")
                continue

            print(f"\n=== {vendor} ===")
            for query in QUERIES[vendor]:
                devices = run_query(api, query, vendor, args.limit)
                all_devices.extend(devices)
                time.sleep(1.5)  # respect rate limits

    # Deduplicate (same IP+port from multiple queries)
    unique = deduplicate(all_devices)
    print(f"\n=== Results ===")
    print(f"Total raw: {len(all_devices)} | After dedup: {len(unique)}")

    # Save
    out_path = OUTPUT_DIR / "shodan_raw.json"
    out_path.write_text(json.dumps(unique, indent=2))
    print(f"✓ Raw results → {out_path}")

    # Quick summary
    from collections import Counter
    vendors = Counter(d["vendor"] for d in unique)
    countries = Counter(d["country"] for d in unique)
    print(f"\nVendors: {dict(vendors.most_common(10))}")
    print(f"Countries: {dict(countries.most_common(10))}")
    print(f"\nDefault creds indicators: {sum(1 for d in unique if d['default_creds_indicator'])}")
    print(f"No TLS: {sum(1 for d in unique if not d['has_tls'])}")
    print(f"Modbus exposed: {sum(1 for d in unique if d['has_modbus'])}")
    print(f"MQTT exposed: {sum(1 for d in unique if d['has_mqtt'])}")


if __name__ == "__main__":
    main()
