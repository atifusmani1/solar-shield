#!/usr/bin/env python3
"""
Risk scoring engine for discovered solar inverter devices.
NO API KEY REQUIRED — reads local output files from previous steps.

Implements the scoring model from the plan:
  30% CVE match severity
  25% Default credentials detected
  15% No TLS/encryption
  15% Exposed industrial protocol (Modbus/MQTT)
  10% Firmware age / known-vulnerable version
   5% Geographic risk (grid criticality)

Usage:
    python 04_risk_score.py
    python 04_risk_score.py --input output/shodan_raw.json
"""

import argparse
import json
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "data"
OUTPUT_DIR = Path(__file__).parent.parent / "output"
OUTPUT_DIR.mkdir(exist_ok=True)

# Load reference data
CVE_DB = json.loads((DATA_DIR / "cve_database.json").read_text())
GRID_DATA = json.loads((DATA_DIR / "grid_capacity.json").read_text())

# Countries with high grid criticality (high solar penetration)
CRITICAL_GRID_COUNTRIES = {
    c for c, info in GRID_DATA["europe"]["countries"].items()
    if info.get("grid_critical")
} | {"CA", "TX"}  # US critical states


def cve_severity_score(vendor: str, firmware: str | None) -> float:
    """Return 0.0-1.0 based on worst known CVE for this vendor/firmware."""
    vendor_key = None
    vendor_lower = vendor.lower()
    for kw, mapped in CVE_DB["keyword_to_vendor_map"].items():
        if kw in vendor_lower:
            vendor_key = mapped
            break

    if not vendor_key or vendor_key not in CVE_DB["vendors"]:
        return 0.3  # unknown vendor — moderate baseline

    vendor_data = CVE_DB["vendors"][vendor_key]

    # Check if known-vulnerable firmware version
    firmware_intel = vendor_data.get("firmware_intel", {})
    if firmware:
        for fw_ver, status in firmware_intel.items():
            if fw_ver.lower() in (firmware or "").lower() or firmware.lower() in fw_ver.lower():
                if "CRITICAL" in status:
                    return 1.0
                if "VULNERABLE" in status:
                    return 0.8
                if "PATCHED" in status:
                    return 0.2

    # Fall back to worst CVE for the vendor
    cves = vendor_data.get("cves", {})
    if not cves:
        # Growatt has no CVE IDs but is CRITICAL
        return 1.0 if vendor_data.get("risk_level") == "CRITICAL" else 0.7

    worst = 0.0
    for cve_id, cve_info in cves.items():
        score = cve_info.get("cvss", 0)
        try:
            score = float(score)
        except (TypeError, ValueError):
            score = 7.0  # default HIGH if score is a label
        if score >= 9.0:
            worst = max(worst, 1.0)
        elif score >= 7.0:
            worst = max(worst, 0.7)
        elif score >= 4.0:
            worst = max(worst, 0.4)

    return worst


def firmware_age_score(firmware_version: str | None) -> float:
    """
    Heuristic firmware age score.
    Without a proper version database, use simple rules:
      - No firmware detected: assume moderately old (0.5)
      - Very low version numbers: older = riskier
    """
    if not firmware_version:
        return 0.5

    # Known vulnerable version strings
    known_vulnerable = [
        "1.0", "1.1", "1.2", "2.0", "2.1", "3.0", "3.1", "3.2",
        "v6.0",  # SolarView Compact actively exploited
    ]
    for vv in known_vulnerable:
        if vv in firmware_version:
            return 0.9

    # Try to parse major.minor
    import re
    m = re.search(r"(\d+)\.(\d+)", firmware_version)
    if m:
        major, minor = int(m.group(1)), int(m.group(2))
        if major <= 1:
            return 0.8
        if major <= 2:
            return 0.5
        return 0.2
    return 0.5


def calculate_risk_score(device: dict) -> dict:
    """
    Score a single device 0-100. Returns enriched device dict.
    """
    cve_component = cve_severity_score(
        device.get("vendor", ""),
        device.get("firmware_version"),
    )
    creds_component = 1.0 if device.get("default_creds_indicator") else 0.0
    no_tls_component = 0.0 if device.get("has_tls") else 1.0
    industrial_component = 1.0 if (device.get("has_modbus") or device.get("has_mqtt")) else 0.0
    firmware_component = firmware_age_score(device.get("firmware_version"))
    geo_component = 1.0 if device.get("country") in CRITICAL_GRID_COUNTRIES else 0.3

    raw = (
        0.30 * cve_component
        + 0.25 * creds_component
        + 0.15 * no_tls_component
        + 0.15 * industrial_component
        + 0.10 * firmware_component
        + 0.05 * geo_component
    )
    score = min(round(raw * 100), 100)

    severity = (
        "CRITICAL" if score >= 80
        else "HIGH" if score >= 60
        else "MEDIUM" if score >= 40
        else "LOW"
    )

    return {
        **device,
        "risk_score": score,
        "risk_severity": severity,
        "risk_components": {
            "cve": round(cve_component * 30, 1),
            "default_creds": round(creds_component * 25, 1),
            "no_tls": round(no_tls_component * 15, 1),
            "industrial_protocol": round(industrial_component * 15, 1),
            "firmware_age": round(firmware_component * 10, 1),
            "geo": round(geo_component * 5, 1),
        },
        "matched_cves": get_matched_cves(device.get("vendor", "")),
    }


def get_matched_cves(vendor: str) -> list[str]:
    vendor_lower = vendor.lower()
    for kw, mapped in CVE_DB["keyword_to_vendor_map"].items():
        if kw in vendor_lower:
            vendor_data = CVE_DB["vendors"].get(mapped, {})
            return list(vendor_data.get("cves", {}).keys())
    return []


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default=str(OUTPUT_DIR / "shodan_raw.json"))
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[ERROR] Input file not found: {input_path}")
        print("Run 03_shodan_search.py first, or provide --input path.")

        # Demo mode: score a few synthetic devices
        print("\n--- Demo mode: scoring synthetic devices ---")
        demo_devices = [
            {"ip": "1.2.3.4", "vendor": "Growatt", "has_tls": False, "has_modbus": False,
             "has_mqtt": False, "default_creds_indicator": True, "firmware_version": "3.2.1",
             "country": "DE", "port": 80},
            {"ip": "5.6.7.8", "vendor": "SolarView", "has_tls": False, "has_modbus": False,
             "has_mqtt": False, "default_creds_indicator": False, "firmware_version": "v6.0",
             "country": "JP", "port": 80},
            {"ip": "9.10.11.12", "vendor": "Sungrow", "has_tls": False, "has_modbus": False,
             "has_mqtt": True, "default_creds_indicator": False, "firmware_version": "WiNet v1.1.0",
             "country": "IT", "port": 1883},
            {"ip": "13.14.15.16", "vendor": "SMA", "has_tls": True, "has_modbus": False,
             "has_mqtt": False, "default_creds_indicator": False, "firmware_version": "4.1.0",
             "country": "US", "port": 443},
        ]
        scored = [calculate_risk_score(d) for d in demo_devices]
        devices = scored
    else:
        raw = json.loads(input_path.read_text())
        print(f"Loaded {len(raw)} devices from {input_path}")
        devices = [calculate_risk_score(d) for d in raw]

    # Sort by risk score descending
    devices.sort(key=lambda d: d["risk_score"], reverse=True)

    # Save
    out_path = OUTPUT_DIR / "devices_scored.json"
    out_path.write_text(json.dumps(devices, indent=2))
    print(f"\n✓ Scored {len(devices)} devices → {out_path}")

    # Print summary
    from collections import Counter
    severity_counts = Counter(d["risk_severity"] for d in devices)
    print(f"\n=== Severity Distribution ===")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = severity_counts.get(sev, 0)
        bar = "█" * min(count, 40)
        print(f"  {sev:<10} {count:>5}  {bar}")

    print(f"\n=== Top 10 Highest-Risk Devices ===")
    print(f"{'IP':<16} {'Score':>5}  {'Severity':<10}  {'Vendor':<12}  {'Country':<6}  CVEs")
    print("-" * 75)
    for d in devices[:10]:
        cves = ",".join(d.get("matched_cves", []))[:30] or "none"
        print(
            f"{d['ip']:<16} {d['risk_score']:>5}  "
            f"{d['risk_severity']:<10}  {d.get('vendor','?'):<12}  "
            f"{d.get('country','?'):<6}  {cves}"
        )


if __name__ == "__main__":
    main()
