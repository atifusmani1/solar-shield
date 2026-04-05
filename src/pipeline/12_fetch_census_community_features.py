#!/usr/bin/env python3
"""
Fetch community-level property and demographic features from the U.S. Census
American Community Survey (ACS) 5-year estimates for high-solar states.

No API key required (rate limit: 500 calls/day unauthenticated).
Optional free key at https://api.census.gov/data/key_signup.html lifts limit.

Outputs (same schema as script 10's community_features_by_zip.csv):
  - data/processed/census_community_features_by_zip.csv   (ZCTA level)
  - data/processed/census_community_features_by_state.csv (state summary)

Usage:
    python scripts/12_fetch_census_community_features.py
    python scripts/12_fetch_census_community_features.py --states CA TX FL
    python scripts/12_fetch_census_community_features.py --all-states
    python scripts/12_fetch_census_community_features.py --api-key YOUR_KEY
"""

from __future__ import annotations

import argparse
import os
import time
from pathlib import Path

import pandas as pd
import requests

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
PROCESSED_DIR = REPO_ROOT / "data" / "processed"
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

CENSUS_BASE = "https://api.census.gov/data/2022/acs/acs5"

# High-solar states by installed capacity (EIA 2023) — default target
HIGH_SOLAR_STATES = [
    "CA", "TX", "FL", "AZ", "NC", "NV", "NJ", "GA", "VA", "NY",
    "MA", "SC", "CO", "MD", "PA", "OH", "IL", "MN", "WA", "OR",
]

ALL_STATES = [
    "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA",
    "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD",
    "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ",
    "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC",
    "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY",
]

# FIPS codes for state-level filtering
STATE_FIPS = {
    "AL": "01", "AK": "02", "AZ": "04", "AR": "05", "CA": "06", "CO": "08",
    "CT": "09", "DE": "10", "FL": "12", "GA": "13", "HI": "15", "ID": "16",
    "IL": "17", "IN": "18", "IA": "19", "KS": "20", "KY": "21", "LA": "22",
    "ME": "23", "MD": "24", "MA": "25", "MI": "26", "MN": "27", "MS": "28",
    "MO": "29", "MT": "30", "NE": "31", "NV": "32", "NH": "33", "NJ": "34",
    "NM": "35", "NY": "36", "NC": "37", "ND": "38", "OH": "39", "OK": "40",
    "OR": "41", "PA": "42", "RI": "44", "SC": "45", "SD": "46", "TN": "47",
    "TX": "48", "UT": "49", "VT": "50", "VA": "51", "WA": "53", "WV": "54",
    "WI": "55", "WY": "56",
}

# ACS variables — all confirmed working against the 2022 ACS 5-year API
ACS_VARIABLES = {
    "B01003_001E": "total_population",
    "B25001_001E": "total_housing_units",
    "B25002_002E": "occupied_units",
    "B25003_001E": "tenure_total",
    "B25003_002E": "owner_occupied_units",
    "B25003_003E": "renter_occupied_units",
    "B25024_002E": "single_family_detached_units",
    "B25024_003E": "single_family_attached_units",
    "B25035_001E": "median_year_built",
    "B25077_001E": "median_home_value",
    "B19013_001E": "median_household_income",
}


def fetch_all_zctas(
    variables: list[str],
    api_key: str | None,
    retries: int = 3,
) -> list[list[str]] | None:
    """Fetch ZCTA-level ACS data for the entire country in one request.

    The Census ACS API does not support filtering ZCTAs by state — ZCTAs
    cross state boundaries and are not a sub-geography of states in the
    Census hierarchy.  The national request returns ~33,000 rows and
    includes a 'state' FIPS column for post-hoc filtering.
    """
    var_str = ",".join(["NAME"] + variables)
    params: dict[str, str] = {
        "get": var_str,
        "for": "zip code tabulation area:*",
    }
    if api_key:
        params["key"] = api_key

    for attempt in range(retries):
        try:
            print("Fetching all ZCTAs (national request)...")
            resp = requests.get(CENSUS_BASE, params=params, timeout=120)
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code == 429:
                wait = 10 * (attempt + 1)
                print(f"  [rate limit] waiting {wait}s...")
                time.sleep(wait)
            else:
                print(f"  [ERROR] HTTP {resp.status_code}: {resp.text[:200]}")
                return None
        except requests.RequestException as e:
            print(f"  [ERROR] request error: {e}")
            if attempt < retries - 1:
                time.sleep(5)
    return None


def parse_response(rows: list[list[str]], variables: list[str]) -> pd.DataFrame:
    """Convert raw Census API response into a DataFrame."""
    if not rows or len(rows) < 2:
        return pd.DataFrame()

    header = rows[0]
    data = rows[1:]
    df = pd.DataFrame(data, columns=header)
    return df


def build_community_features(df: pd.DataFrame) -> pd.DataFrame:
    """Compute derived features matching the script-10 community schema."""
    # Rename raw ACS column names to friendly names
    for raw, friendly in ACS_VARIABLES.items():
        if raw in df.columns:
            df = df.rename(columns={raw: friendly})

    if "zip code tabulation area" in df.columns:
        df = df.rename(columns={"zip code tabulation area": "geo_id"})
    if "state" in df.columns:
        df = df.rename(columns={"state": "state_fips"})

    # Coerce numerics (Census returns strings, uses -666666666 for missing)
    numeric_cols = list(ACS_VARIABLES.values())
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
            df[col] = df[col].where(df[col] > -600000, other=None)

    # Derived features matching script-10 community schema
    df["parcel_count"] = df["total_housing_units"]
    df["residential_parcel_count"] = df["occupied_units"]

    sf_units = df.get("single_family_detached_units", 0).fillna(0)
    sf_attached = df.get("single_family_attached_units", 0).fillna(0)
    total_units = df["total_housing_units"].fillna(1).clip(lower=1)
    occupied = df["occupied_units"].fillna(0)
    owner = df["owner_occupied_units"].fillna(0)

    df["single_family_count"] = sf_units
    df["single_family_share"] = (sf_units / total_units).clip(0, 1)
    df["residential_share"] = (occupied / total_units).clip(0, 1)
    df["owner_occupancy_rate"] = (owner / occupied.clip(lower=1)).clip(0, 1)

    # Solar candidate: owner-occupied single-family homes
    df["solar_candidate_share"] = (df["single_family_share"] * df["owner_occupancy_rate"]).clip(0, 1)
    df["solar_candidate_count"] = (df["solar_candidate_share"] * total_units).round().astype("Int64")

    df["median_final_value"] = df["median_home_value"]
    df["median_year_built"] = df["median_year_built"]
    df["median_property_age"] = (2026 - df["median_year_built"]).clip(lower=0)
    df["high_value_share"] = (df["median_home_value"].fillna(0) >= 1_000_000).astype(float)

    # Population density proxy (units per reported area — we don't have area so use raw count)
    df["housing_density_proxy"] = df["total_housing_units"]

    keep = [
        "geo_id",
        "state_fips",
        "NAME",
        "parcel_count",
        "residential_parcel_count",
        "single_family_count",
        "solar_candidate_count",
        "single_family_share",
        "residential_share",
        "owner_occupancy_rate",
        "solar_candidate_share",
        "high_value_share",
        "median_final_value",
        "median_home_value",
        "median_household_income",
        "median_year_built",
        "median_property_age",
        "total_population",
        "total_housing_units",
        "occupied_units",
        "owner_occupied_units",
        "renter_occupied_units",
        "single_family_detached_units",
        "single_family_attached_units",
        "housing_density_proxy",
    ]
    keep = [c for c in keep if c in df.columns]
    return df[keep].copy()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--states",
        nargs="+",
        default=None,
        help="State abbreviations to fetch (e.g. CA TX FL). Default: top 20 solar states.",
    )
    parser.add_argument(
        "--all-states",
        action="store_true",
        help="Include all 50 states (default: top 20 solar states).",
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("CENSUS_API_KEY"),
        help="Optional Census API key (lifts rate limit). Set CENSUS_API_KEY env var or pass here.",
    )
    args = parser.parse_args()

    if args.all_states:
        states = ALL_STATES
    elif args.states:
        states = [s.upper() for s in args.states]
    else:
        states = HIGH_SOLAR_STATES

    variables = list(ACS_VARIABLES.keys())

    # Resolve target state FIPS codes for filtering
    target_fips: set[str] | None = None
    if not args.all_states:
        target_fips = {STATE_FIPS[s] for s in states if s in STATE_FIPS}

    print("=== Census ACS community feature fetch ===")
    print(f"States: {'all' if args.all_states else states}")
    print(f"Variables: {len(variables)}")
    print(f"API key: {'yes' if args.api_key else 'no (500 req/day limit)'}")
    print()

    # Single national request — Census API does not support per-state ZCTA queries
    rows = fetch_all_zctas(variables, args.api_key)
    if rows is None:
        print("\n[ERROR] No data fetched. Check network connection.")
        return

    raw_df = parse_response(rows, variables)
    if raw_df.empty:
        print("\n[ERROR] Empty response from Census API.")
        return

    print(f"  {len(raw_df) - 1} ZCTAs returned nationally")

    # Filter to target states using the 'state' FIPS column Census includes
    if target_fips and "state" in raw_df.columns:
        raw_df = raw_df[raw_df["state"].isin(target_fips)].copy()
        print(f"  {len(raw_df)} ZCTAs after filtering to {len(target_fips)} states")

    # Add state abbreviation lookup
    fips_to_abbr = {v: k for k, v in STATE_FIPS.items()}
    if "state" in raw_df.columns:
        raw_df["state_abbr"] = raw_df["state"].map(fips_to_abbr)

    features = build_community_features(raw_df)
    combined = features

    # Drop ZCTAs with no housing units (uninhabited / water areas)
    combined = combined[combined["total_housing_units"].fillna(0) > 0].copy()

    # Sort by solar candidate share descending
    combined = combined.sort_values("solar_candidate_share", ascending=False).reset_index(drop=True)

    zip_out = PROCESSED_DIR / "census_community_features_by_zip.csv"
    combined.to_csv(zip_out, index=False)
    print(f"\nSaved {len(combined)} ZCTAs -> {zip_out}")

    # State summary (only if state_fips column is present)
    state_out = PROCESSED_DIR / "census_community_features_by_state.csv"
    if "state_fips" in combined.columns:
        state_summary = (
            combined.groupby("state_fips")
            .agg(
                zcta_count=("geo_id", "count"),
                total_housing_units=("total_housing_units", "sum"),
                total_population=("total_population", "sum"),
                median_home_value=("median_home_value", "median"),
                median_household_income=("median_household_income", "median"),
                avg_single_family_share=("single_family_share", "mean"),
                avg_owner_occupancy_rate=("owner_occupancy_rate", "mean"),
                avg_solar_candidate_share=("solar_candidate_share", "mean"),
            )
            .reset_index()
            .sort_values("avg_solar_candidate_share", ascending=False)
        )
        state_summary.to_csv(state_out, index=False)
        print(f"Saved {len(state_summary)} states -> {state_out}")
    else:
        print("[INFO] No state_fips column — state summary skipped")

    print("\n=== Top 10 ZCTAs by solar candidate share ===")
    print(
        combined[["geo_id", "NAME", "single_family_share", "owner_occupancy_rate",
                   "solar_candidate_share", "median_home_value", "median_household_income"]]
        .head(10)
        .to_string(index=False)
    )


if __name__ == "__main__":
    main()
