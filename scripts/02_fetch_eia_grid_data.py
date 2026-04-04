#!/usr/bin/env python3
"""
Fetch US state-level solar capacity from the EIA Open Data API.
NO API KEY REQUIRED for basic queries (EIA v2 API is public).

Usage:
    python 02_fetch_eia_grid_data.py

Outputs:
    output/eia_solar_capacity.json   — raw capacity data by state
    output/grid_impact_summary.json  — botnet potential per state
"""

import json
import time
from pathlib import Path

import requests

# EIA v2 API — no key required
EIA_BASE = "https://api.eia.gov/v2"

OUTPUT_DIR = Path(__file__).parent.parent / "output"
OUTPUT_DIR.mkdir(exist_ok=True)

# Pre-loaded from data/grid_capacity.json as fallback
FALLBACK_US_SOLAR_GW = {
    "CA": 50.0, "TX": 25.0, "FL": 14.0, "AZ": 10.0, "NC": 9.0,
    "NY": 7.0,  "NV": 6.5,  "NJ": 5.5,  "MA": 4.5,  "VA": 4.0,
}


def fetch_eia_solar_capacity() -> dict:
    """
    Pull installed solar PV capacity (MW) by US state from EIA.
    Endpoint: electricity/electric-power-operational-data
    """
    url = (
        f"{EIA_BASE}/electricity/electric-power-operational-data/data/"
        "?frequency=annual"
        "&data[0]=capacity"
        "&facets[fueltypeDescription][]=Solar%20Photovoltaic"
        "&sort[0][column]=period&sort[0][direction]=desc"
        "&length=60"
        "&offset=0"
    )
    try:
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"[WARN] EIA API call failed: {e}")
        print("       Using fallback data from grid_capacity.json")
        return {}


def fetch_eia_state_generation() -> dict:
    """
    Pull most recent annual solar generation (MWh) by state.
    Useful for understanding how solar-dependent each state is.
    """
    url = (
        f"{EIA_BASE}/electricity/electric-power-operational-data/data/"
        "?frequency=annual"
        "&data[0]=generation"
        "&facets[fueltypeDescription][]=Solar%20Photovoltaic"
        "&sort[0][column]=period&sort[0][direction]=desc"
        "&length=60"
        "&offset=0"
    )
    try:
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"[WARN] EIA generation API call failed: {e}")
        return {}


def calculate_botnet_potential(exposed_count: int, state_solar_gw: float,
                                avg_inverter_kw: float = 10.0) -> dict:
    """
    Given N exposed inverters in a state:
    - Estimate total exposed capacity
    - Calculate as % of state grid solar
    - Flag if > 2% threshold (grid destabilization risk)
    """
    exposed_mw = (exposed_count * avg_inverter_kw) / 1000
    exposed_gw = exposed_mw / 1000
    pct_of_grid = (exposed_gw / state_solar_gw * 100) if state_solar_gw > 0 else 0
    return {
        "exposed_devices": exposed_count,
        "avg_inverter_kw": avg_inverter_kw,
        "exposed_capacity_mw": round(exposed_mw, 2),
        "exposed_capacity_gw": round(exposed_gw, 3),
        "state_solar_gw": state_solar_gw,
        "pct_of_grid": round(pct_of_grid, 3),
        "grid_destabilization_risk": pct_of_grid > 2.0,
        "risk_label": "CRITICAL" if pct_of_grid > 2.0 else ("HIGH" if pct_of_grid > 0.5 else "MEDIUM"),
    }


def main():
    print("=== Fetching EIA Solar Capacity Data ===")
    print("(No API key required)\n")

    capacity_data = fetch_eia_solar_capacity()
    generation_data = fetch_eia_state_generation()
    time.sleep(1)

    # Parse EIA response into state → GW dict
    state_solar_gw = dict(FALLBACK_US_SOLAR_GW)  # start with fallback

    if capacity_data and "response" in capacity_data:
        records = capacity_data["response"].get("data", [])
        for rec in records:
            state = rec.get("location", "")
            mw = rec.get("capacity")
            if state and mw and len(state) == 2:
                gw = float(mw) / 1000
                if gw > state_solar_gw.get(state, 0):
                    state_solar_gw[state] = round(gw, 2)
        print(f"✓ Loaded {len(records)} EIA capacity records")
    else:
        print("  Using fallback data (10 states)")

    # Demo: calculate botnet potential assuming 1000 exposed devices per state
    print("\n=== Botnet Potential by State (assuming 1,000 exposed devices) ===")
    print(f"{'State':<6} {'Solar (GW)':>10}  {'Exposed MW':>10}  {'% Grid':>7}  Risk")
    print("-" * 55)

    impact_by_state = {}
    for state, solar_gw in sorted(state_solar_gw.items(), key=lambda x: -x[1]):
        impact = calculate_botnet_potential(
            exposed_count=1000,
            state_solar_gw=solar_gw,
        )
        impact_by_state[state] = impact
        risk = impact["risk_label"]
        print(
            f"{state:<6} {solar_gw:>10.1f}  "
            f"{impact['exposed_capacity_mw']:>10.1f}  "
            f"{impact['pct_of_grid']:>6.3f}%  {risk}"
        )

    # Save outputs
    out_capacity = OUTPUT_DIR / "eia_solar_capacity.json"
    out_capacity.write_text(json.dumps({"state_solar_gw": state_solar_gw}, indent=2))
    print(f"\n✓ Capacity data → {out_capacity}")

    out_impact = OUTPUT_DIR / "grid_impact_summary.json"
    out_impact.write_text(json.dumps(impact_by_state, indent=2))
    print(f"✓ Impact summary → {out_impact}")

    print("\nNote: Re-run with actual device counts from Shodan scan for real numbers.")


if __name__ == "__main__":
    main()
