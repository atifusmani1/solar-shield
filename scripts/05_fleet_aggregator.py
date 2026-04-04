#!/usr/bin/env python3
"""
Fleet aggregation and "botnet potential" calculator.
NO API KEY REQUIRED — reads local scored devices + grid capacity data.

Groups devices by vendor and region, then calculates:
  - Total exposed capacity (MW)
  - % of regional grid solar capacity
  - Grid destabilization risk (threshold: 2% of regional solar)

Usage:
    python 05_fleet_aggregator.py
    python 05_fleet_aggregator.py --input output/devices_scored.json
"""

import argparse
import json
from collections import defaultdict
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "data"
OUTPUT_DIR = Path(__file__).parent.parent / "output"
OUTPUT_DIR.mkdir(exist_ok=True)

GRID_DATA = json.loads((DATA_DIR / "grid_capacity.json").read_text())
AVG_INVERTER_KW = GRID_DATA["avg_mixed_inverter_kw"]  # 10.0 kW
DESTABILIZATION_THRESHOLD_PCT = 2.0


def get_region_solar_gw(country_code: str) -> float:
    """Look up solar capacity for a country/state."""
    eu = GRID_DATA["europe"]["countries"]
    us = GRID_DATA["us_states"]
    if country_code in eu:
        return eu[country_code]["solar_gw"]
    if country_code in us:
        return us[country_code]["solar_gw"]
    return 10.0  # conservative fallback for unknown regions


def aggregate_fleet(devices: list[dict]) -> dict:
    """
    Build fleet summary grouped by country and vendor.
    Returns the full aggregation with botnet potential calculations.
    """
    by_country = defaultdict(lambda: defaultdict(list))
    by_vendor = defaultdict(list)

    for d in devices:
        country = d.get("country") or "XX"
        vendor = d.get("vendor") or "Unknown"
        by_country[country][vendor].append(d)
        by_vendor[vendor].append(d)

    # Country-level aggregation
    country_summary = {}
    for country, vendor_map in by_country.items():
        all_country_devices = [d for devs in vendor_map.values() for d in devs]
        total_devices = len(all_country_devices)
        solar_gw = get_region_solar_gw(country)

        exposed_mw = (total_devices * AVG_INVERTER_KW) / 1000
        exposed_gw = exposed_mw / 1000
        pct = (exposed_gw / solar_gw * 100) if solar_gw > 0 else 0

        critical_count = sum(1 for d in all_country_devices if d.get("risk_severity") == "CRITICAL")
        default_creds_count = sum(1 for d in all_country_devices if d.get("default_creds_indicator"))
        no_tls_count = sum(1 for d in all_country_devices if not d.get("has_tls"))

        country_summary[country] = {
            "country": country,
            "total_devices": total_devices,
            "vendors": {v: len(devs) for v, devs in vendor_map.items()},
            "solar_gw": solar_gw,
            "exposed_capacity_mw": round(exposed_mw, 2),
            "exposed_capacity_gw": round(exposed_gw, 3),
            "pct_of_grid": round(pct, 3),
            "destabilization_risk": pct > DESTABILIZATION_THRESHOLD_PCT,
            "risk_label": (
                "CRITICAL" if pct > DESTABILIZATION_THRESHOLD_PCT
                else "HIGH" if pct > 0.5
                else "MEDIUM"
            ),
            "critical_devices": critical_count,
            "default_creds_devices": default_creds_count,
            "no_tls_devices": no_tls_count,
            "avg_risk_score": round(
                sum(d.get("risk_score", 0) for d in all_country_devices) / total_devices, 1
            ) if total_devices else 0,
        }

    # Vendor-level aggregation
    vendor_summary = {}
    for vendor, devs in by_vendor.items():
        total = len(devs)
        countries = list({d.get("country", "XX") for d in devs})
        critical = sum(1 for d in devs if d.get("risk_severity") == "CRITICAL")
        exposed_mw = (total * AVG_INVERTER_KW) / 1000

        vendor_summary[vendor] = {
            "vendor": vendor,
            "total_devices": total,
            "countries": countries,
            "exposed_capacity_mw": round(exposed_mw, 2),
            "critical_devices": critical,
            "critical_pct": round(critical / total * 100, 1) if total else 0,
            "avg_risk_score": round(
                sum(d.get("risk_score", 0) for d in devs) / total, 1
            ) if total else 0,
        }

    # Global summary
    total_all = len(devices)
    total_exposed_mw = (total_all * AVG_INVERTER_KW) / 1000
    eu_solar_gw = GRID_DATA["europe"]["total_solar_gw"]
    eu_pct = (total_exposed_mw / 1000 / eu_solar_gw * 100) if eu_solar_gw > 0 else 0

    global_summary = {
        "total_devices_found": total_all,
        "total_exposed_capacity_mw": round(total_exposed_mw, 2),
        "eu_solar_gw": eu_solar_gw,
        "eu_destabilization_threshold_gw": eu_solar_gw * DESTABILIZATION_THRESHOLD_PCT / 100,
        "eu_pct_of_grid": round(eu_pct, 3),
        "eu_destabilization_risk": eu_pct > DESTABILIZATION_THRESHOLD_PCT,
        "countries_at_risk": [
            c for c, s in country_summary.items() if s["destabilization_risk"]
        ],
        "total_critical_devices": sum(1 for d in devices if d.get("risk_severity") == "CRITICAL"),
        "total_default_creds": sum(1 for d in devices if d.get("default_creds_indicator")),
        "total_no_tls": sum(1 for d in devices if not d.get("has_tls")),
        "avg_inverter_kw_assumed": AVG_INVERTER_KW,
    }

    return {
        "global": global_summary,
        "by_country": country_summary,
        "by_vendor": vendor_summary,
    }


def print_report(agg: dict):
    g = agg["global"]
    print("\n" + "=" * 60)
    print("  SOLAR INVERTER FLEET EXPOSURE REPORT")
    print("=" * 60)
    print(f"  Total devices found:       {g['total_devices_found']:,}")
    print(f"  Estimated exposed capacity: {g['total_exposed_capacity_mw']:,.1f} MW")
    print(f"  EU solar grid capacity:    {g['eu_solar_gw']:,.0f} GW")
    print(f"  % of EU solar grid:        {g['eu_pct_of_grid']:.3f}%")
    dest_risk = "⚠ CRITICAL" if g["eu_destabilization_risk"] else "OK"
    print(f"  EU grid destabilization:   {dest_risk}")
    print(f"  Critical-severity devices: {g['total_critical_devices']:,}")
    print(f"  Devices w/ default creds:  {g['total_default_creds']:,}")
    print(f"  Devices without TLS:       {g['total_no_tls']:,}")

    print(f"\n--- Countries at Destabilization Risk (>2% threshold) ---")
    at_risk = [s for s in agg["by_country"].values() if s["destabilization_risk"]]
    if at_risk:
        for s in sorted(at_risk, key=lambda x: -x["pct_of_grid"]):
            print(f"  {s['country']}: {s['total_devices']} devices = "
                  f"{s['exposed_capacity_mw']:.1f} MW = {s['pct_of_grid']:.2f}% of grid  ⚠")
    else:
        print("  None — based on current device count")

    print(f"\n--- Top Countries by Exposure ---")
    print(f"  {'Country':<8} {'Devices':>8}  {'MW':>8}  {'% Grid':>8}  {'Avg Score':>10}")
    print(f"  {'-'*50}")
    for s in sorted(agg["by_country"].values(), key=lambda x: -x["total_devices"])[:15]:
        print(
            f"  {s['country']:<8} {s['total_devices']:>8}  "
            f"{s['exposed_capacity_mw']:>8.1f}  "
            f"{s['pct_of_grid']:>7.3f}%  "
            f"{s['avg_risk_score']:>10.1f}"
        )

    print(f"\n--- Vendor Breakdown ---")
    print(f"  {'Vendor':<15} {'Devices':>8}  {'MW':>8}  {'Critical%':>10}  {'Avg Score':>10}")
    print(f"  {'-'*55}")
    for s in sorted(agg["by_vendor"].values(), key=lambda x: -x["total_devices"]):
        print(
            f"  {s['vendor']:<15} {s['total_devices']:>8}  "
            f"{s['exposed_capacity_mw']:>8.1f}  "
            f"{s['critical_pct']:>9.1f}%  "
            f"{s['avg_risk_score']:>10.1f}"
        )

    print("\n" + "=" * 60)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default=str(OUTPUT_DIR / "devices_scored.json"))
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[INFO] {input_path} not found — running with demo data.")
        print("Run 03_shodan_search.py + 04_risk_score.py first for real results.\n")
        # Use synthetic demo data
        devices = [
            {"ip": f"1.2.3.{i}", "vendor": "Growatt", "country": "DE",
             "has_tls": False, "default_creds_indicator": True,
             "risk_score": 85, "risk_severity": "CRITICAL"}
            for i in range(500)
        ] + [
            {"ip": f"5.6.7.{i}", "vendor": "SolarView", "country": "JP",
             "has_tls": False, "default_creds_indicator": False,
             "risk_score": 90, "risk_severity": "CRITICAL"}
            for i in range(800)
        ] + [
            {"ip": f"9.10.11.{i}", "vendor": "Sungrow", "country": "IT",
             "has_tls": False, "default_creds_indicator": False,
             "risk_score": 70, "risk_severity": "HIGH"}
            for i in range(300)
        ]
    else:
        devices = json.loads(input_path.read_text())
        print(f"Loaded {len(devices)} scored devices from {input_path}")

    agg = aggregate_fleet(devices)
    print_report(agg)

    out_path = OUTPUT_DIR / "fleet_aggregation.json"
    out_path.write_text(json.dumps(agg, indent=2))
    print(f"\n✓ Full aggregation saved → {out_path}")


if __name__ == "__main__":
    main()
