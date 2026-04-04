#!/usr/bin/env python3
"""
Build modeling inputs by joining community property features with curated solar vulnerability priors.

This script does not claim parcel-to-CVE linkage. Instead it creates:
  - a high-confidence solar CVE subset
  - vendor-level cyber risk priors
  - community-level modeling inputs that combine property/geography features
    with global cyber priors suitable for a v1 ranking model
"""

from __future__ import annotations

import re
from pathlib import Path

import pandas as pd


REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = REPO_ROOT / "output"
PROCESSED_DIR = REPO_ROOT / "data" / "processed"
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

CVE_PATH = OUTPUT_DIR / "vulnerability_cves.csv"
AFFECTED_PRODUCTS_PATH = OUTPUT_DIR / "vulnerability_affected_products.csv"
COMMUNITY_CENSUS_PATH = PROCESSED_DIR / "community_features_by_census.csv"
COMMUNITY_ZIP_PATH = PROCESSED_DIR / "community_features_by_zip.csv"
COMMUNITY_FIPS_PATH = PROCESSED_DIR / "community_features_by_fips.csv"

SOLAR_VENDOR_ALLOWLIST = {
    "growatt": "Growatt",
    "sungrowpower": "Sungrow",
    "sungrow": "Sungrow",
    "sma": "SMA",
    "sma_solar_technology_ag": "SMA",
    "solarview": "SolarView",
    "goodwe": "GoodWe",
    "enphase": "Enphase",
    "ginlong": "Ginlong",
    "solis": "Solis",
    "deye": "Deye",
    "bosswerk": "Bosswerk",
    "fronius": "Fronius",
    "solaredge": "SolarEdge",
    "tesla": "Tesla",
    "huawei": "Huawei",
    "fusionsolar": "Huawei",
}

STRONG_SOLAR_TERMS = [
    "growatt",
    "sungrow",
    "sma",
    "solarview",
    "goodwe",
    "enphase",
    "ginlong",
    "solis",
    "deye",
    "fusionsolar",
    "sunny portal",
    "sunny webbox",
    "isolarcloud",
    "winet",
    "shinelan",
    "shinewifi",
    "solaredge",
    "fronius",
    "bosswerk",
    "revolt",
    "microinverter",
]


def load_inputs() -> tuple[pd.DataFrame, pd.DataFrame]:
    cves = pd.read_csv(CVE_PATH, low_memory=False)
    products = pd.read_csv(AFFECTED_PRODUCTS_PATH, low_memory=False)

    cves["cvss_score"] = pd.to_numeric(cves["cvss_score"], errors="coerce")
    cves["cisa_kev"] = pd.to_numeric(cves["cisa_kev"], errors="coerce").fillna(0).astype(int)
    products["vendor"] = products["vendor"].fillna("").astype(str).str.strip().str.lower()
    products["product"] = products["product"].fillna("").astype(str).str.strip()
    products["is_vulnerable"] = pd.to_numeric(products["is_vulnerable"], errors="coerce").fillna(1).astype(int)
    return cves, products


def is_relevant_text(text: str) -> bool:
    lowered = (text or "").lower()
    for term in STRONG_SOLAR_TERMS:
        pattern = r"\b" + re.escape(term) + r"\b"
        if re.search(pattern, lowered):
            return True
    return False


def curate_solar_products(products: pd.DataFrame, cves: pd.DataFrame) -> pd.DataFrame:
    merged = products.merge(cves, on="cve_id", how="left")
    merged["vendor_match"] = merged["vendor"].isin(SOLAR_VENDOR_ALLOWLIST.keys())
    merged["text_match"] = (
        merged["product"].map(is_relevant_text)
        | merged["description"].fillna("").map(is_relevant_text)
    )
    curated = merged[(merged["is_vulnerable"] == 1) & (merged["vendor_match"] | merged["text_match"])].copy()
    curated["vendor_canonical"] = curated["vendor"].map(SOLAR_VENDOR_ALLOWLIST).fillna(curated["vendor"].str.title())
    curated = curated[
        ~curated["vendor"].isin(
            {
                "canonical",
                "linux",
                "oracle",
                "sun",
                "solarwinds",
                "envoyproxy",
                "austin_group",
                "redhat",
                "cncf",
                "cilium",
                "pomerium",
                "istio",
            }
        )
    ].copy()
    curated["critical_flag"] = curated["cvss_score"].fillna(0).ge(9.0)
    curated["high_flag"] = curated["cvss_score"].fillna(0).ge(7.0)
    curated["vuln_weight"] = (
        curated["cvss_score"].fillna(5.0) / 10.0
        + curated["cisa_kev"].fillna(0) * 0.5
        + curated["critical_flag"].astype(int) * 0.25
    )
    curated = curated.drop_duplicates(
        subset=[
            "cve_id",
            "vendor_canonical",
            "product",
            "cpe_uri",
            "version_start_including",
            "version_start_excluding",
            "version_end_including",
            "version_end_excluding",
        ]
    )
    curated = curated.sort_values(["vendor_canonical", "cvss_score", "cve_id"], ascending=[True, False, True])
    return curated


def build_vendor_priors(curated: pd.DataFrame) -> pd.DataFrame:
    grouped_rows = []
    for vendor, group in curated.groupby("vendor_canonical"):
        grouped_rows.append(
            {
                "vendor": vendor,
                "cve_count": group["cve_id"].nunique(),
                "product_count": group["product"].nunique(),
                "critical_cve_count": group.loc[group["critical_flag"], "cve_id"].nunique(),
                "high_or_worse_count": group.loc[group["high_flag"], "cve_id"].nunique(),
                "kev_cve_count": group.loc[group["cisa_kev"] == 1, "cve_id"].nunique(),
                "avg_cvss": group["cvss_score"].mean(),
                "max_cvss": group["cvss_score"].max(),
                "avg_vuln_weight": group["vuln_weight"].mean(),
            }
        )

    priors = pd.DataFrame(grouped_rows).sort_values(
        ["avg_vuln_weight", "cve_count", "vendor"], ascending=[False, False, True]
    )
    priors["vendor_risk_score"] = (
        35 * (priors["max_cvss"].fillna(0) / 10.0)
        + 25 * (priors["critical_cve_count"] / priors["cve_count"].clip(lower=1))
        + 20 * (priors["kev_cve_count"] / priors["cve_count"].clip(lower=1))
        + 20 * (priors["avg_cvss"].fillna(0) / 10.0)
    ).round(2)
    return priors


def build_global_cyber_priors(curated: pd.DataFrame, vendor_priors: pd.DataFrame) -> dict:
    unique_cves = curated["cve_id"].nunique()
    critical_cves = curated.loc[curated["critical_flag"], "cve_id"].nunique()
    kev_cves = curated.loc[curated["cisa_kev"] == 1, "cve_id"].nunique()
    max_cvss = curated["cvss_score"].fillna(0).max()
    avg_cvss = curated["cvss_score"].fillna(0).mean()
    avg_vendor_risk = vendor_priors["vendor_risk_score"].mean() if not vendor_priors.empty else 0

    cyber_pressure = (
        0.35 * (max_cvss / 10.0)
        + 0.25 * (critical_cves / unique_cves if unique_cves else 0)
        + 0.20 * (kev_cves / unique_cves if unique_cves else 0)
        + 0.20 * (avg_cvss / 10.0 if pd.notna(avg_cvss) else 0)
    ) * 100

    return {
        "solar_cve_count": unique_cves,
        "solar_critical_cve_count": critical_cves,
        "solar_kev_cve_count": kev_cves,
        "solar_vendor_count": curated["vendor_canonical"].nunique(),
        "solar_avg_cvss": round(avg_cvss, 4) if pd.notna(avg_cvss) else None,
        "solar_max_cvss": round(max_cvss, 4) if pd.notna(max_cvss) else None,
        "solar_avg_vendor_risk": round(avg_vendor_risk, 4) if pd.notna(avg_vendor_risk) else None,
        "solar_cyber_pressure_score": round(cyber_pressure, 2),
    }


def enrich_community_table(path: Path, geo_col: str, global_priors: dict) -> pd.DataFrame:
    df = pd.read_csv(path, low_memory=False)
    for key, value in global_priors.items():
        df[key] = value

    df["solar_readiness_score"] = (
        0.35 * df["single_family_share"].fillna(0)
        + 0.25 * df["residential_share"].fillna(0)
        + 0.20 * df["solar_candidate_share"].fillna(0)
        + 0.10 * (df["high_value_share"].fillna(0))
        + 0.10 * (df["garage_share"].fillna(0))
    ) * 100

    df["community_risk_prior_score"] = (
        0.55 * df["solar_readiness_score"]
        + 0.45 * df["solar_cyber_pressure_score"]
    ).round(2)

    df = df.sort_values("community_risk_prior_score", ascending=False).reset_index(drop=True)
    df = df.rename(columns={geo_col: "geo_id"})
    return df


def main() -> None:
    cves, products = load_inputs()
    curated = curate_solar_products(products, cves)
    vendor_priors = build_vendor_priors(curated)
    global_priors = build_global_cyber_priors(curated, vendor_priors)

    curated_out = OUTPUT_DIR / "high_confidence_solar_affected_products.csv"
    vendor_out = OUTPUT_DIR / "vendor_risk_priors.csv"
    curated[
        [
            "cve_id",
            "vendor_canonical",
            "product",
            "cvss_score",
            "cvss_severity",
            "cisa_kev",
            "published_date",
            "description",
            "cpe_uri",
            "version_start_including",
            "version_start_excluding",
            "version_end_including",
            "version_end_excluding",
        ]
    ].rename(columns={"vendor_canonical": "vendor"}).to_csv(curated_out, index=False)
    vendor_priors.to_csv(vendor_out, index=False)

    census = enrich_community_table(COMMUNITY_CENSUS_PATH, "effective_census_key_decennial", global_priors)
    zip_table = enrich_community_table(COMMUNITY_ZIP_PATH, "ZipCode", global_priors)
    fips_table = enrich_community_table(COMMUNITY_FIPS_PATH, "effective_fips_code", global_priors)

    census_out = PROCESSED_DIR / "community_model_inputs_by_census.csv"
    zip_out = PROCESSED_DIR / "community_model_inputs_by_zip.csv"
    fips_out = PROCESSED_DIR / "community_model_inputs_by_fips.csv"

    census.to_csv(census_out, index=False)
    zip_table.to_csv(zip_out, index=False)
    fips_table.to_csv(fips_out, index=False)

    print(f"Saved curated solar products: {curated_out}")
    print(f"Saved vendor priors: {vendor_out}")
    print(f"Saved census model inputs: {census_out}")
    print(f"Saved ZIP model inputs: {zip_out}")
    print(f"Saved FIPS model inputs: {fips_out}")
    print(
        "Summary:",
        {
            "curated_rows": len(curated),
            "curated_unique_cves": int(curated["cve_id"].nunique()),
            "curated_vendors": int(curated["vendor_canonical"].nunique()),
            "community_rows_census": len(census),
        },
    )


if __name__ == "__main__":
    main()
