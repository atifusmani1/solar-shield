#!/usr/bin/env python3
"""
Enhance risk model with:
  1. EIA state-weighted cyber pressure (replaces global constant)
  2. Income × solar candidate interaction feature
  3. Property age sweet-spot scoring
  4. K-means clustering for ML-derived risk tiers

Reads:
  - data/processed/census_community_features_by_zip.csv
  - data/processed/zcta_centroids.csv
  - data/grid_capacity.json
  - output/vulnerability_cves.csv
  - output/vulnerability_affected_products.csv

Outputs:
  - data/processed/community_model_inputs_census_nationwide.csv  (OVERWRITE with enhanced version)
  - data/processed/cluster_profiles.csv
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
PROCESSED = REPO_ROOT / "data" / "processed"
OUTPUT = REPO_ROOT / "output"

# ── ZIP prefix → state mapping ───────────────────────────────────────────────
# First 3 digits of a ZIP code reliably map to a state/territory.
# Source: USPS Publication 65 (National Five-Digit ZIP Code & Post Office Directory)
ZIP3_TO_STATE: dict[str, str] = {}
_ranges: list[tuple[int, int, str]] = [
    (  6,   9, "PR"), ( 10,  14, "MA"), ( 15,  16, "VT"), ( 17,  19, "MA"),
    ( 20,  20, "DC"), ( 21,  21, "MD"), ( 22,  24, "VA"), ( 25,  26, "WV"),
    ( 27,  28, "NC"), ( 29,  29, "SC"), ( 30,  31, "GA"), ( 32,  34, "FL"),
    ( 35,  36, "AL"), ( 37,  38, "TN"), ( 39,  39, "MS"), ( 40,  42, "KY"),
    ( 43,  45, "OH"), ( 46,  47, "IN"), ( 48,  49, "MI"), ( 50,  52, "IA"),
    ( 53,  54, "WI"), ( 55,  56, "MN"), ( 57,  57, "SD"), ( 58,  58, "ND"),
    ( 59,  59, "MT"), ( 60,  62, "IL"), ( 63,  65, "MO"), ( 66,  67, "KS"),
    ( 68,  69, "NE"), ( 70,  71, "LA"), ( 72,  72, "AR"), ( 73,  74, "OK"),
    ( 75,  79, "TX"), ( 80,  81, "CO"), ( 82,  83, "WY"), ( 84,  84, "UT"),
    ( 85,  86, "AZ"), ( 87,  88, "NM"), ( 89,  89, "NV"), ( 90,  96, "CA"),
    ( 97,  97, "OR"), ( 98,  99, "WA"), (  1,   5, "NY"), (100, 149, "NY"),
    (150, 196, "PA"), (197, 199, "DE"), (  0,   0, "NY"),
    (967, 968, "HI"), (995, 999, "AK"), (969, 969, "GU"),
    (  3,   3, "NH"), (  4,   4, "ME"),
]

# Handle overlapping 3-digit ranges for the Northeast (ZIP prefixes 0xx–1xx)
# Build a more precise lookup
def _build_zip3_map() -> dict[str, str]:
    """Build ZIP3 → state mapping from range table + overrides."""
    m: dict[str, str] = {}

    # Three-digit ranges (most of the country)
    three_digit = [
        (100, 104, "NY"), (105, 109, "NY"), (110, 119, "NY"), (120, 129, "NY"),
        (130, 139, "NY"), (140, 149, "NY"),
        (150, 168, "PA"), (169, 169, "PA"), (170, 179, "PA"), (180, 196, "PA"),
        (197, 199, "DE"),
        (200, 205, "DC"), (206, 212, "MD"), (213, 213, "VA"), (214, 219, "MD"),
        (220, 246, "VA"),
        (247, 268, "WV"),
        (270, 289, "NC"),
        (290, 299, "SC"),
        (300, 319, "GA"), (320, 349, "FL"),
        (350, 369, "AL"),
        (370, 385, "TN"),
        (386, 397, "MS"),
        (400, 427, "KY"),
        (430, 459, "OH"),
        (460, 479, "IN"),
        (480, 499, "MI"),
        (500, 528, "IA"),
        (530, 549, "WI"),
        (550, 567, "MN"),
        (570, 577, "SD"),
        (580, 588, "ND"),
        (590, 599, "MT"),
        (600, 629, "IL"),
        (630, 658, "MO"),
        (660, 679, "KS"),
        (680, 693, "NE"),
        (700, 714, "LA"),
        (716, 729, "AR"),
        (730, 749, "OK"),
        (750, 799, "TX"),
        (800, 816, "CO"),
        (820, 831, "WY"),
        (832, 838, "ID"),
        (840, 847, "UT"),
        (850, 865, "AZ"),
        (870, 884, "NM"),
        (889, 898, "NV"),
        (900, 961, "CA"),
        (967, 968, "HI"),
        (970, 979, "OR"),
        (980, 994, "WA"),
        (995, 999, "AK"),
    ]

    for lo, hi, st in three_digit:
        for z3 in range(lo, hi + 1):
            m[f"{z3:03d}"] = st

    # Two-digit / New England overrides (ZIP 0xxxx)
    ne = [
        ( 10,  27, "MA"), ( 28,  29, "RI"),
        ( 30,  38, "NH"), ( 39,  49, "ME"),
        ( 50,  54, "VT"), ( 55,  55, "MA"),
        ( 60,  69, "CT"),
    ]
    for lo, hi, st in ne:
        for z2 in range(lo, hi + 1):
            key = f"0{z2:02d}" if z2 >= 10 else f"00{z2}"
            m[key] = st

    return m


ZIP3_TO_STATE = _build_zip3_map()


def zip_to_state(geo_id: str) -> str | None:
    """Map a 5-digit ZIP/ZCTA to a state abbreviation."""
    z3 = geo_id[:3]
    return ZIP3_TO_STATE.get(z3)


# ── EIA Solar Capacity ──────────────────────────────────────────────────────
def load_eia_capacity() -> dict[str, float]:
    """Load state-level installed solar GW from grid_capacity.json + expanded estimates."""
    with open(REPO_ROOT / "data" / "grid_capacity.json") as f:
        data = json.load(f)

    # Start with the states in the JSON
    cap: dict[str, float] = {}
    for st, info in data.get("us_states", {}).items():
        if isinstance(info, dict) and "solar_gw" in info:
            cap[st] = info["solar_gw"]

    # Add estimates for remaining states (EIA 2023 approximations)
    # These are approximate but directionally correct
    additional = {
        "GA": 7.5, "SC": 3.0, "CO": 4.5, "MD": 3.5, "PA": 2.0,
        "OH": 2.0, "IL": 2.5, "MN": 2.5, "OR": 2.0, "WA": 1.5,
        "IN": 2.0, "UT": 3.0, "CT": 1.5, "HI": 2.0, "NM": 2.5,
        "MS": 1.0, "AL": 1.0, "TN": 1.0, "MO": 1.0, "LA": 1.0,
        "AR": 1.0, "WI": 0.8, "MI": 1.0, "KY": 0.5, "IA": 1.0,
        "KS": 0.5, "NE": 0.3, "OK": 1.0, "WV": 0.1, "SD": 0.2,
        "ND": 0.1, "MT": 0.2, "WY": 0.1, "ID": 0.8, "ME": 0.5,
        "NH": 0.3, "VT": 0.4, "RI": 0.5, "DE": 0.3, "DC": 0.2,
        "AK": 0.05,
    }
    for st, gw in additional.items():
        if st not in cap:
            cap[st] = gw

    return cap


def compute_state_solar_weight(capacity: dict[str, float]) -> dict[str, float]:
    """
    Convert state solar GW into a 0–1 weight for cyber pressure scaling.

    Logic: more installed capacity → more inverters → more attack surface.
    Normalised so California (highest) = 1.0, near-zero states ≈ 0.1.
    """
    if not capacity:
        return {}

    max_gw = max(capacity.values())
    weights: dict[str, float] = {}
    for st, gw in capacity.items():
        # Log-scale to avoid CA completely dominating (50 GW vs 0.1 GW)
        # floor at 0.1 so even low-solar states have some pressure
        raw = np.log1p(gw) / np.log1p(max_gw)
        weights[st] = max(0.1, round(raw, 4))

    return weights


# ── Cyber pressure from CVE data ────────────────────────────────────────────
def compute_base_cyber_pressure() -> tuple[float, dict]:
    """Compute the base (global) cyber pressure score and related stats from CVE data."""
    from scripts_helper import curate_and_score  # avoid circular — inline it

    cves = pd.read_csv(OUTPUT / "vulnerability_cves.csv", low_memory=False)
    products = pd.read_csv(OUTPUT / "vulnerability_affected_products.csv", low_memory=False)

    cves["cvss_score"] = pd.to_numeric(cves["cvss_score"], errors="coerce")
    cves["cisa_kev"] = pd.to_numeric(cves["cisa_kev"], errors="coerce").fillna(0).astype(int)
    products["vendor"] = products["vendor"].fillna("").astype(str).str.strip().str.lower()
    products["is_vulnerable"] = pd.to_numeric(products["is_vulnerable"], errors="coerce").fillna(1).astype(int)

    # Inline the solar filtering from script 11
    solar_vendors = {
        "growatt", "sungrowpower", "sungrow", "sma", "sma_solar_technology_ag",
        "solarview", "goodwe", "enphase", "ginlong", "solis", "deye", "bosswerk",
        "fronius", "solaredge", "tesla", "huawei", "fusionsolar",
    }
    exclude = {"canonical", "linux", "oracle", "sun", "solarwinds", "envoyproxy",
               "austin_group", "redhat", "cncf", "cilium", "pomerium", "istio"}

    merged = products.merge(cves, on="cve_id", how="left")
    solar = merged[
        (merged["is_vulnerable"] == 1)
        & (merged["vendor"].isin(solar_vendors))
        & (~merged["vendor"].isin(exclude))
    ].copy()

    if solar.empty:
        return 50.0, {}

    unique_cves = solar["cve_id"].nunique()
    critical = solar.loc[solar["cvss_score"].fillna(0) >= 9.0, "cve_id"].nunique()
    kev = solar.loc[solar["cisa_kev"] == 1, "cve_id"].nunique()
    max_cvss = solar["cvss_score"].fillna(0).max()
    avg_cvss = solar["cvss_score"].fillna(0).mean()

    pressure = (
        0.35 * (max_cvss / 10.0)
        + 0.25 * (critical / unique_cves if unique_cves else 0)
        + 0.20 * (kev / unique_cves if unique_cves else 0)
        + 0.20 * (avg_cvss / 10.0)
    ) * 100

    stats = {
        "solar_cve_count": unique_cves,
        "solar_critical_cve_count": critical,
        "solar_kev_cve_count": kev,
        "solar_vendor_count": solar["vendor"].nunique(),
        "solar_avg_cvss": round(avg_cvss, 4),
        "solar_max_cvss": round(max_cvss, 4),
    }
    return round(pressure, 2), stats


# ── Feature engineering ─────────────────────────────────────────────────────
def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """Add income interaction, age sweet spot, and state-weighted cyber pressure."""

    # 1. Map ZCTAs to states
    df["state"] = df["geo_id"].map(zip_to_state)
    print(f"  State mapping: {df['state'].notna().sum():,} / {len(df):,} mapped")
    print(f"  Unique states: {df['state'].nunique()}")

    # 2. EIA solar capacity weights
    capacity = load_eia_capacity()
    weights = compute_state_solar_weight(capacity)
    df["state_solar_weight"] = df["state"].map(weights).fillna(0.1)

    # Show weight distribution
    top_states = df.groupby("state")["state_solar_weight"].first().sort_values(ascending=False).head(10)
    print(f"\n  State solar weights (top 10):")
    for st, w in top_states.items():
        gw = capacity.get(st, 0)
        print(f"    {st}: {w:.3f}  ({gw:.1f} GW)")

    # 3. State-weighted cyber pressure (replaces global constant)
    base_pressure, cyber_stats = compute_base_cyber_pressure_simple()
    df["solar_cyber_pressure_score"] = (base_pressure * df["state_solar_weight"]).round(2)
    print(f"\n  Cyber pressure range: {df['solar_cyber_pressure_score'].min():.1f} – {df['solar_cyber_pressure_score'].max():.1f}")

    # Carry forward cyber stats columns
    for k, v in cyber_stats.items():
        df[k] = v

    # 4. Income × solar candidate interaction
    # Normalise income to 0–1 scale, then multiply with solar_candidate_share
    income_norm = df["median_household_income"].fillna(df["median_household_income"].median())
    income_norm = (income_norm - income_norm.min()) / (income_norm.max() - income_norm.min() + 1e-9)
    df["income_solar_interaction"] = (income_norm * df["solar_candidate_share"]).round(4)

    # 5. Property age sweet-spot scoring
    # Peak risk: 15–35 year old housing (built 1991–2011) — first/second gen inverters
    # Bell curve centered at 25 years, sigma=12
    age = df["median_property_age"].fillna(df["median_property_age"].median())
    df["age_risk_factor"] = np.exp(-0.5 * ((age - 25) / 12) ** 2).round(4)

    return df


def compute_base_cyber_pressure_simple() -> tuple[float, dict]:
    """Compute base cyber pressure directly from CSVs (no import dependency)."""
    cves = pd.read_csv(OUTPUT / "vulnerability_cves.csv", low_memory=False)
    products = pd.read_csv(OUTPUT / "vulnerability_affected_products.csv", low_memory=False)

    cves["cvss_score"] = pd.to_numeric(cves["cvss_score"], errors="coerce")
    cves["cisa_kev"] = pd.to_numeric(cves["cisa_kev"], errors="coerce").fillna(0).astype(int)
    products["vendor"] = products["vendor"].fillna("").astype(str).str.strip().str.lower()
    products["is_vulnerable"] = pd.to_numeric(products["is_vulnerable"], errors="coerce").fillna(1).astype(int)

    solar_vendors = {
        "growatt", "sungrowpower", "sungrow", "sma", "sma_solar_technology_ag",
        "solarview", "goodwe", "enphase", "ginlong", "solis", "deye", "bosswerk",
        "fronius", "solaredge", "tesla", "huawei", "fusionsolar",
    }
    exclude = {"canonical", "linux", "oracle", "sun", "solarwinds", "envoyproxy",
               "austin_group", "redhat", "cncf", "cilium", "pomerium", "istio"}

    merged = products.merge(cves, on="cve_id", how="left")
    solar = merged[
        (merged["is_vulnerable"] == 1)
        & (merged["vendor"].isin(solar_vendors))
        & (~merged["vendor"].isin(exclude))
    ].copy()

    if solar.empty:
        return 50.0, {}

    unique_cves = solar["cve_id"].nunique()
    critical = solar.loc[solar["cvss_score"].fillna(0) >= 9.0, "cve_id"].nunique()
    kev = solar.loc[solar["cisa_kev"] == 1, "cve_id"].nunique()
    max_cvss = float(solar["cvss_score"].fillna(0).max())
    avg_cvss = float(solar["cvss_score"].fillna(0).mean())

    pressure = (
        0.35 * (max_cvss / 10.0)
        + 0.25 * (critical / unique_cves if unique_cves else 0)
        + 0.20 * (kev / unique_cves if unique_cves else 0)
        + 0.20 * (avg_cvss / 10.0)
    ) * 100

    stats = {
        "solar_cve_count": unique_cves,
        "solar_critical_cve_count": critical,
        "solar_kev_cve_count": kev,
        "solar_vendor_count": int(solar["vendor"].nunique()),
        "solar_avg_cvss": round(avg_cvss, 4),
        "solar_max_cvss": round(max_cvss, 4),
    }
    return round(pressure, 2), stats


# ── Scoring ─────────────────────────────────────────────────────────────────
def compute_enhanced_scores(df: pd.DataFrame) -> pd.DataFrame:
    """
    Enhanced risk scoring with new features.

    solar_readiness_score (0–100):
        0.30 × single_family_share
      + 0.20 × residential_share
      + 0.15 × solar_candidate_share
      + 0.15 × income_solar_interaction    (NEW)
      + 0.10 × age_risk_factor             (NEW)
      + 0.10 × high_value_share

    community_risk_prior_score:
        0.55 × solar_readiness + 0.45 × state-weighted cyber pressure
    """
    df["solar_readiness_score"] = (
        0.30 * df["single_family_share"].fillna(0)
        + 0.20 * df["residential_share"].fillna(0)
        + 0.15 * df["solar_candidate_share"].fillna(0)
        + 0.15 * df["income_solar_interaction"].fillna(0)
        + 0.10 * df["age_risk_factor"].fillna(0)
        + 0.10 * df["high_value_share"].fillna(0)
    ) * 100

    df["solar_readiness_score"] = df["solar_readiness_score"].round(2)

    df["community_risk_prior_score"] = (
        0.55 * df["solar_readiness_score"]
        + 0.45 * df["solar_cyber_pressure_score"]
    ).round(2)

    return df


# ── K-Means clustering ─────────────────────────────────────────────────────
def run_clustering(df: pd.DataFrame, n_clusters: int = 5) -> pd.DataFrame:
    """
    K-Means clustering on the feature set for ML-derived risk tiers.

    Uses the enhanced features to identify natural groupings of communities.
    """
    cluster_features = [
        "single_family_share",
        "owner_occupancy_rate",
        "solar_candidate_share",
        "income_solar_interaction",
        "age_risk_factor",
        "high_value_share",
        "state_solar_weight",
        "median_property_age",
    ]

    # Fill NaN with median for clustering
    X = df[cluster_features].copy()
    for col in cluster_features:
        X[col] = X[col].fillna(X[col].median())

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    km = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    df["cluster_id"] = km.fit_predict(X_scaled)

    # Sort clusters by mean risk score so cluster 0 = lowest, 4 = highest
    cluster_means = df.groupby("cluster_id")["community_risk_prior_score"].mean()
    rank_map = {c: r for r, c in enumerate(cluster_means.sort_values().index)}
    df["risk_cluster"] = df["cluster_id"].map(rank_map)

    # Label clusters
    labels = {0: "MINIMAL", 1: "LOW", 2: "MODERATE", 3: "ELEVATED", 4: "CRITICAL"}
    df["risk_cluster_label"] = df["risk_cluster"].map(labels)

    # Build cluster profiles
    profiles = (
        df.groupby("risk_cluster")
        .agg(
            label=("risk_cluster_label", "first"),
            count=("geo_id", "count"),
            avg_risk_score=("community_risk_prior_score", "mean"),
            avg_solar_readiness=("solar_readiness_score", "mean"),
            avg_cyber_pressure=("solar_cyber_pressure_score", "mean"),
            avg_sf_share=("single_family_share", "mean"),
            avg_owner_rate=("owner_occupancy_rate", "mean"),
            avg_solar_candidate=("solar_candidate_share", "mean"),
            avg_income_interaction=("income_solar_interaction", "mean"),
            avg_age_factor=("age_risk_factor", "mean"),
            avg_state_weight=("state_solar_weight", "mean"),
            median_home_value=("median_home_value", "median"),
            median_income=("median_household_income", "median"),
        )
        .round(3)
        .reset_index()
    )

    print(f"\n  K-Means cluster profiles (k={n_clusters}):")
    print(profiles[["risk_cluster", "label", "count", "avg_risk_score",
                     "avg_solar_readiness", "avg_cyber_pressure"]].to_string(index=False))

    return df, profiles


# ── Main ────────────────────────────────────────────────────────────────────
def main() -> None:
    print("=== Enhanced Risk Model ===\n")

    # Load base Census features
    print("Loading Census community features...")
    df = pd.read_csv(PROCESSED / "census_community_features_by_zip.csv", dtype={"geo_id": str})
    df["geo_id"] = df["geo_id"].str.zfill(5)
    print(f"  {len(df):,} ZCTAs loaded")

    # Engineer new features
    print("\nEngineering features...")
    df = engineer_features(df)

    # Compute enhanced scores
    print("\nComputing enhanced scores...")
    df = compute_enhanced_scores(df)

    # Drop uninhabited
    df = df[df["total_housing_units"].fillna(0) > 0].copy()
    df = df.sort_values("community_risk_prior_score", ascending=False).reset_index(drop=True)

    print(f"\n  Score range: {df['community_risk_prior_score'].min():.1f} – {df['community_risk_prior_score'].max():.1f}")
    print(f"  Mean: {df['community_risk_prior_score'].mean():.1f}  Std: {df['community_risk_prior_score'].std():.1f}")

    # K-Means clustering
    print("\nRunning K-Means clustering...")
    df, profiles = run_clustering(df, n_clusters=5)

    # Save
    out_path = PROCESSED / "community_model_inputs_census_nationwide.csv"
    df.to_csv(out_path, index=False)
    print(f"\nSaved {len(df):,} ZCTAs -> {out_path}")

    profiles_path = PROCESSED / "cluster_profiles.csv"
    profiles.to_csv(profiles_path, index=False)
    print(f"Saved cluster profiles -> {profiles_path}")

    # Top 10
    print("\n=== Top 10 Highest Risk ZCTAs ===")
    top = df[["geo_id", "state", "community_risk_prior_score", "solar_readiness_score",
              "solar_cyber_pressure_score", "risk_cluster_label",
              "solar_candidate_share", "median_home_value"]].head(10)
    print(top.to_string(index=False))

    # Score distribution by state
    print("\n=== Top 10 States by Mean Risk Score ===")
    state_means = (
        df.groupby("state")["community_risk_prior_score"]
        .agg(["mean", "count"])
        .sort_values("mean", ascending=False)
        .head(10)
    )
    print(state_means.round(1).to_string())


if __name__ == "__main__":
    main()
