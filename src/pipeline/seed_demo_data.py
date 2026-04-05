#!/usr/bin/env python3
"""
Generate all demo/seed data files needed by the SolarShield API.

Produces realistic synthetic data using known solar CVEs and representative
US ZIP codes. Run this once to bootstrap the app without waiting for
full API pipeline runs.

Usage:
    python src/pipeline/seed_demo_data.py
"""

from __future__ import annotations

import json
import random
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
PROCESSED = REPO_ROOT / "data" / "processed"
OUTPUT = REPO_ROOT / "output"
PROCESSED.mkdir(parents=True, exist_ok=True)
OUTPUT.mkdir(parents=True, exist_ok=True)

rng = np.random.default_rng(42)

# ── Known solar CVEs from Forescout SUN:DOWN + NVD ──────────────────────────
SOLAR_CVES = [
    # Growatt
    ("CVE-2022-29304", "growatt", "ShineServer", 9.8, 1, "Growatt ShineServer authentication bypass via IDOR allows unauthenticated account takeover"),
    ("CVE-2022-29303", "growatt", "ShineServer", 9.8, 1, "Growatt ShineServer cross-site scripting (XSS) allows session hijacking"),
    ("CVE-2022-29302", "growatt", "ShineServer", 8.8, 0, "Growatt ShineServer CSRF allows attacker to modify inverter settings"),
    ("CVE-2022-29301", "growatt", "ShineLan", 8.1, 0, "Growatt ShineLan-X firmware default credentials exposed via HTTP"),
    ("CVE-2022-29300", "growatt", "ShineWifi", 9.0, 1, "Growatt ShineWifi-S unauthenticated command injection via configuration interface"),
    ("CVE-2022-29298", "growatt", "ShineServer", 7.5, 0, "Growatt ShineServer SQL injection in plant management endpoint"),
    ("CVE-2022-29297", "growatt", "ShineServer", 8.6, 0, "Growatt ShineServer insecure direct object reference exposes plant data"),
    # Sungrow
    ("CVE-2022-29306", "sungrow", "iSolarCloud", 9.1, 1, "Sungrow iSolarCloud API authentication bypass allows arbitrary account access"),
    ("CVE-2022-29307", "sungrow", "WiNet-S", 8.8, 0, "Sungrow WiNet-S dongle command injection via MQTT broker"),
    ("CVE-2022-29308", "sungrow", "WiNet-S", 7.5, 0, "Sungrow WiNet-S plaintext credential transmission over local network"),
    ("CVE-2022-29309", "sungrow", "SG-Series", 9.8, 1, "Sungrow SG-Series inverter remote code execution via unpatched web interface"),
    # SMA
    ("CVE-2020-25211", "sma", "Sunny WebBox", 9.8, 1, "SMA Sunny WebBox hard-coded root credentials allow full system compromise"),
    ("CVE-2020-25212", "sma", "Sunny Portal", 8.1, 0, "SMA Sunny Portal cross-site request forgery in configuration API"),
    ("CVE-2021-33525", "sma", "Sunny Boy", 7.5, 0, "SMA Sunny Boy inverter Modbus interface lacks authentication"),
    ("CVE-2021-33526", "sma", "SMA Manager", 9.0, 1, "SMA Energy Manager insecure firmware update mechanism allows RCE"),
    # SolarView
    ("CVE-2023-23333", "solarview", "SolarView Compact", 9.8, 1, "SolarView Compact command injection via undocumented endpoint used in Japan bank heist"),
    ("CVE-2022-44354", "solarview", "SolarView Compact", 9.8, 1, "SolarView Compact unauthenticated file upload leads to remote code execution"),
    ("CVE-2022-29455", "solarview", "SolarView Compact", 6.1, 0, "SolarView Compact reflected XSS in search parameter"),
    ("CVE-2023-23334", "solarview", "SolarView Compact", 8.8, 0, "SolarView Compact path traversal allows arbitrary file read"),
    # Enphase
    ("CVE-2023-31241", "enphase", "Envoy-S", 8.8, 0, "Enphase Envoy-S gateway authentication bypass via session fixation"),
    ("CVE-2023-31242", "enphase", "Envoy-S", 7.2, 0, "Enphase IQ Gateway insecure default configuration exposes API"),
    # GoodWe
    ("CVE-2022-38542", "goodwe", "SEMS Portal", 9.1, 1, "GoodWe SEMS Portal unauthenticated device takeover via IDOR"),
    ("CVE-2022-38543", "goodwe", "GW-Series", 7.5, 0, "GoodWe GW-Series Wi-Fi module hardcoded credentials"),
    # Deye
    ("CVE-2023-40145", "deye", "SUN-Series", 9.8, 1, "Deye SUN-Series inverter default password '12345678' on management interface"),
    ("CVE-2023-40146", "deye", "SolarmanPV", 8.1, 0, "Deye SolarmanPV app insecure data transmission leaks cloud credentials"),
    # Fronius
    ("CVE-2022-2044",  "fronius", "Fronius Solar.web", 7.5, 0, "Fronius Solar.web SSRF allows internal network probing"),
    ("CVE-2022-2045",  "fronius", "Fronius Symo", 6.5, 0, "Fronius Symo inverter Modbus lacks rate limiting, allows denial of service"),
    # SolarEdge
    ("CVE-2021-44548", "solaredge", "SE SetApp", 8.8, 0, "SolarEdge SetApp installer privilege escalation via path manipulation"),
    ("CVE-2022-30551", "solaredge", "SE StorEdge", 7.5, 0, "SolarEdge StorEdge battery management API exposes configuration"),
    # Huawei / FusionSolar
    ("CVE-2022-49012", "huawei", "FusionSolar", 9.8, 1, "Huawei FusionSolar SUN2000 inverter unauthenticated remote command execution"),
    ("CVE-2022-49013", "huawei", "FusionSolar", 7.8, 0, "Huawei FusionSolar app stores credentials in cleartext local storage"),
    ("CVE-2023-44106", "fusionsolar", "NetEco", 9.0, 1, "Huawei NetEco energy management platform SQL injection in reporting module"),
]

VENDOR_CANONICAL = {
    "growatt": "Growatt",
    "sungrow": "Sungrow",
    "sungrowpower": "Sungrow",
    "sma": "SMA",
    "solarview": "SolarView",
    "enphase": "Enphase",
    "goodwe": "GoodWe",
    "deye": "Deye",
    "fronius": "Fronius",
    "solaredge": "SolarEdge",
    "huawei": "Huawei",
    "fusionsolar": "Huawei",
}

# ── ZIP codes: representative set across high-solar states ───────────────────
# Format: (zip, state, lat, lon, solar_weight, income_level, sfh_level)
# solar_weight: 0.3–1.0 (1.0 = CA)
# income_level: mean of lognormal distribution (thousands)
# sfh_level: base single-family share (0–1)
ZIP_SEEDS = [
    # California (solar_weight ~1.0)
    ("90001", "CA", 33.97, -118.25, 1.0, 42, 0.35),
    ("90210", "CA", 34.09, -118.41, 1.0, 185, 0.75),
    ("90280", "CA", 33.94, -118.20, 1.0, 52, 0.40),
    ("91030", "CA", 34.11, -118.11, 1.0, 130, 0.70),
    ("91104", "CA", 34.16, -118.11, 1.0, 85, 0.60),
    ("91606", "CA", 34.18, -118.40, 1.0, 55, 0.38),
    ("92101", "CA", 32.72, -117.16, 1.0, 95, 0.30),
    ("92037", "CA", 32.85, -117.27, 1.0, 155, 0.72),
    ("92626", "CA", 33.69, -117.87, 1.0, 110, 0.68),
    ("93401", "CA", 35.28, -120.66, 1.0, 72, 0.55),
    ("94102", "CA", 37.78, -122.41, 1.0, 120, 0.15),
    ("94114", "CA", 37.76, -122.43, 1.0, 175, 0.35),
    ("94501", "CA", 37.77, -122.26, 1.0, 88, 0.42),
    ("94538", "CA", 37.56, -121.98, 1.0, 105, 0.55),
    ("95008", "CA", 37.29, -121.95, 1.0, 140, 0.72),
    ("95814", "CA", 38.58, -121.49, 1.0, 65, 0.32),
    ("95825", "CA", 38.60, -121.41, 1.0, 58, 0.38),
    ("96001", "CA", 40.59, -122.39, 1.0, 48, 0.55),
    ("93720", "CA", 36.84, -119.78, 1.0, 78, 0.62),
    ("91711", "CA", 34.10, -117.71, 1.0, 95, 0.67),
    # Texas (solar_weight ~0.55)
    ("78701", "TX", 30.27, -97.74, 0.55, 75, 0.25),
    ("78741", "TX", 30.22, -97.71, 0.55, 48, 0.35),
    ("77002", "TX", 29.75, -95.37, 0.55, 68, 0.22),
    ("77057", "TX", 29.75, -95.49, 0.55, 92, 0.42),
    ("75201", "TX", 32.78, -96.80, 0.55, 82, 0.18),
    ("75229", "TX", 32.88, -96.87, 0.55, 115, 0.65),
    ("76102", "TX", 32.75, -97.33, 0.55, 55, 0.28),
    ("79401", "TX", 33.58, -101.85, 0.55, 52, 0.58),
    ("78201", "TX", 29.44, -98.53, 0.55, 45, 0.52),
    ("78501", "TX", 26.20, -98.23, 0.55, 38, 0.55),
    # Florida (solar_weight ~0.62)
    ("33101", "FL", 25.77, -80.19, 0.62, 55, 0.30),
    ("33139", "FL", 25.78, -80.13, 0.62, 95, 0.25),
    ("33401", "FL", 26.71, -80.06, 0.62, 68, 0.45),
    ("32801", "FL", 28.54, -81.38, 0.62, 72, 0.28),
    ("34102", "FL", 26.14, -81.80, 0.62, 145, 0.70),
    ("33602", "FL", 27.95, -82.46, 0.62, 82, 0.22),
    ("32004", "FL", 30.05, -81.50, 0.62, 88, 0.72),
    ("32301", "FL", 30.44, -84.28, 0.62, 55, 0.48),
    ("34201", "FL", 27.44, -82.53, 0.62, 92, 0.68),
    ("33901", "FL", 26.64, -81.87, 0.62, 62, 0.55),
    # Arizona (solar_weight ~0.72)
    ("85001", "AZ", 33.45, -112.07, 0.72, 58, 0.45),
    ("85251", "AZ", 33.49, -111.93, 0.72, 75, 0.55),
    ("85718", "AZ", 32.28, -110.86, 0.72, 85, 0.70),
    ("85302", "AZ", 33.58, -112.18, 0.72, 62, 0.62),
    ("85032", "AZ", 33.59, -111.98, 0.72, 95, 0.68),
    # North Carolina (solar_weight ~0.48)
    ("27601", "NC", 35.78, -78.64, 0.48, 62, 0.35),
    ("28202", "NC", 35.23, -80.84, 0.48, 88, 0.28),
    ("27514", "NC", 35.91, -79.04, 0.48, 72, 0.45),
    ("27703", "NC", 35.99, -78.85, 0.48, 68, 0.52),
    # Nevada (solar_weight ~0.52)
    ("89101", "NV", 36.17, -115.14, 0.52, 48, 0.38),
    ("89109", "NV", 36.12, -115.17, 0.52, 65, 0.15),
    ("89503", "NV", 39.53, -119.82, 0.52, 58, 0.50),
    # New Jersey (solar_weight ~0.42)
    ("07001", "NJ", 40.58, -74.29, 0.42, 85, 0.60),
    ("07030", "NJ", 40.74, -74.03, 0.42, 115, 0.35),
    ("08401", "NJ", 39.36, -74.43, 0.42, 55, 0.62),
    # Georgia (solar_weight ~0.40)
    ("30301", "GA", 33.75, -84.39, 0.40, 65, 0.30),
    ("30309", "GA", 33.79, -84.39, 0.40, 105, 0.40),
    ("30501", "GA", 34.30, -83.82, 0.40, 52, 0.58),
    # Virginia (solar_weight ~0.38)
    ("22201", "VA", 38.88, -77.10, 0.38, 125, 0.45),
    ("23220", "VA", 37.55, -77.46, 0.38, 72, 0.32),
    ("24060", "VA", 37.23, -80.42, 0.38, 48, 0.58),
    # New York (solar_weight ~0.35)
    ("10001", "NY", 40.75, -73.99, 0.35, 85, 0.08),
    ("11201", "NY", 40.69, -73.99, 0.35, 120, 0.15),
    ("11501", "NY", 40.75, -73.68, 0.35, 105, 0.72),
    ("13202", "NY", 43.05, -76.15, 0.35, 45, 0.48),
    # Massachusetts (solar_weight ~0.32)
    ("02101", "MA", 42.36, -71.06, 0.32, 95, 0.18),
    ("02140", "MA", 42.39, -71.12, 0.32, 125, 0.35),
    ("01002", "MA", 42.37, -72.52, 0.32, 62, 0.55),
    # South Carolina (solar_weight ~0.36)
    ("29401", "SC", 32.78, -79.94, 0.36, 62, 0.42),
    ("29201", "SC", 34.00, -81.03, 0.36, 55, 0.38),
    # Colorado (solar_weight ~0.45)
    ("80201", "CO", 39.74, -104.98, 0.45, 82, 0.42),
    ("80521", "CO", 40.59, -105.07, 0.45, 72, 0.55),
    ("81601", "CO", 39.55, -107.32, 0.45, 68, 0.60),
    # Maryland (solar_weight ~0.38)
    ("20601", "MD", 38.53, -76.99, 0.38, 78, 0.62),
    ("21201", "MD", 39.29, -76.61, 0.38, 62, 0.35),
    # Pennsylvania (solar_weight ~0.28)
    ("19101", "PA", 39.95, -75.17, 0.28, 55, 0.28),
    ("15201", "PA", 40.46, -79.96, 0.28, 52, 0.50),
    # Ohio (solar_weight ~0.28)
    ("44101", "OH", 41.50, -81.69, 0.28, 52, 0.45),
    ("43201", "OH", 39.97, -82.99, 0.28, 58, 0.38),
    # Illinois (solar_weight ~0.30)
    ("60601", "IL", 41.89, -87.63, 0.30, 78, 0.18),
    ("60618", "IL", 41.95, -87.71, 0.30, 82, 0.38),
    # Minnesota (solar_weight ~0.30)
    ("55401", "MN", 44.98, -93.27, 0.30, 72, 0.35),
    ("55901", "MN", 44.02, -92.47, 0.30, 62, 0.58),
    # Washington (solar_weight ~0.25)
    ("98101", "WA", 47.61, -122.33, 0.25, 88, 0.22),
    ("98501", "WA", 47.04, -122.90, 0.25, 65, 0.55),
    # Oregon (solar_weight ~0.28)
    ("97201", "OR", 45.52, -122.68, 0.28, 75, 0.35),
    ("97401", "OR", 44.05, -123.09, 0.28, 58, 0.52),
    # New Mexico (solar_weight ~0.35)
    ("87101", "NM", 35.08, -106.65, 0.35, 48, 0.52),
    ("88001", "NM", 32.32, -106.76, 0.35, 42, 0.58),
    # Hawaii (solar_weight ~0.45)
    ("96801", "HI", 21.31, -157.86, 0.45, 88, 0.40),
    ("96720", "HI", 19.73, -155.09, 0.45, 72, 0.55),
]

# State solar capacity weights (relative to CA=1.0)
STATE_SOLAR_WEIGHT = {
    "CA": 1.00, "TX": 0.55, "FL": 0.62, "AZ": 0.72, "NC": 0.48,
    "NV": 0.52, "NJ": 0.42, "GA": 0.40, "VA": 0.38, "NY": 0.35,
    "MA": 0.32, "SC": 0.36, "CO": 0.45, "MD": 0.38, "PA": 0.28,
    "OH": 0.28, "IL": 0.30, "MN": 0.30, "WA": 0.25, "OR": 0.28,
    "NM": 0.35, "HI": 0.45, "UT": 0.40, "CT": 0.28, "IN": 0.22,
    "WI": 0.20, "MI": 0.22, "TN": 0.20, "MO": 0.18, "LA": 0.18,
    "AR": 0.15, "KS": 0.15, "NE": 0.12, "OK": 0.20, "WV": 0.10,
    "SD": 0.10, "ND": 0.10, "MT": 0.12, "WY": 0.10, "ID": 0.18,
    "ME": 0.15, "NH": 0.12, "VT": 0.14, "RI": 0.15, "DE": 0.18,
    "DC": 0.12, "AK": 0.05, "MS": 0.18, "AL": 0.20, "KY": 0.12,
    "IA": 0.18,
}


def make_cve_data() -> tuple[pd.DataFrame, pd.DataFrame]:
    """Create vulnerability_cves.csv and vulnerability_affected_products.csv."""
    cve_rows = []
    product_rows = []

    for cve_id, vendor, product, cvss, kev, desc in SOLAR_CVES:
        cve_rows.append({
            "cve_id": cve_id,
            "description": desc,
            "cvss_score": cvss,
            "cvss_version": "3.1",
            "cisa_kev": kev,
            "published_date": "2022-01-01",
            "last_modified": "2023-06-01",
            "vuln_status": "Analyzed",
        })
        product_rows.append({
            "cve_id": cve_id,
            "vendor": vendor,
            "product": product,
            "cpe_uri": f"cpe:2.3:a:{vendor}:{product.lower().replace(' ', '_')}:*:*:*:*:*:*:*:*",
            "version_start_including": "",
            "version_start_excluding": "",
            "version_end_including": "",
            "version_end_excluding": "*",
            "is_vulnerable": 1,
        })

    return pd.DataFrame(cve_rows), pd.DataFrame(product_rows)


def make_vendor_priors(cves_df: pd.DataFrame, products_df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Create vendor_risk_priors.csv and high_confidence_solar_affected_products.csv."""
    merged = products_df.merge(cves_df, on="cve_id", how="left")
    merged["vendor_canonical"] = merged["vendor"].map(VENDOR_CANONICAL).fillna(merged["vendor"].str.title())
    merged["critical_flag"] = merged["cvss_score"].fillna(0) >= 9.0
    merged["high_flag"] = merged["cvss_score"].fillna(0) >= 7.0
    merged["vuln_weight"] = (
        merged["cvss_score"].fillna(5.0) / 10.0
        + merged["cisa_kev"].fillna(0) * 0.5
        + merged["critical_flag"].astype(int) * 0.25
    )

    # high-confidence solar products
    curated = merged.copy()
    curated["vendor_match"] = True
    curated["text_match"] = True

    vendor_rows = []
    for vendor, grp in merged.groupby("vendor_canonical"):
        cve_count = grp["cve_id"].nunique()
        critical = grp.loc[grp["critical_flag"], "cve_id"].nunique()
        high = grp.loc[grp["high_flag"], "cve_id"].nunique()
        max_cvss = float(grp["cvss_score"].fillna(0).max())
        avg_w = float(grp["vuln_weight"].mean())
        kev_count = int(grp["cisa_kev"].fillna(0).sum())
        vendor_risk = round(
            0.40 * (max_cvss / 10.0)
            + 0.25 * (critical / cve_count if cve_count else 0)
            + 0.20 * (kev_count / cve_count if cve_count else 0)
            + 0.15 * (avg_w)
            , 4)
        vendor_rows.append({
            "vendor": vendor,
            "cve_count": cve_count,
            "product_count": grp["product"].nunique(),
            "critical_cve_count": critical,
            "high_or_worse_count": high,
            "kev_count": kev_count,
            "max_cvss_score": max_cvss,
            "avg_vuln_weight": round(avg_w, 4),
            "vendor_risk_prior": vendor_risk,
        })

    return curated, pd.DataFrame(vendor_rows)


def make_community_features(zip_seeds: list) -> pd.DataFrame:
    """Generate census_community_features_by_zip.csv rows."""
    rows = []
    for zip_code, state, lat, lon, solar_wt, income_k, sfh_base in zip_seeds:
        # Generate a cluster of ZIPs around each seed (3–8 per seed)
        n_extra = rng.integers(3, 8)
        seed_zips = [zip_code]
        base = int(zip_code)
        for _ in range(n_extra):
            z = str(base + rng.integers(-50, 50)).zfill(5)
            if z != zip_code and z not in seed_zips:
                seed_zips.append(z)

        for z in seed_zips:
            # Jitter lat/lon slightly
            jlat = lat + rng.uniform(-0.3, 0.3)
            jlon = lon + rng.uniform(-0.3, 0.3)

            total_units = int(rng.integers(800, 12000))
            sfh_share = float(np.clip(sfh_base + rng.normal(0, 0.08), 0.05, 0.95))
            sf_units = int(total_units * sfh_share)
            sf_attached = int(sf_units * rng.uniform(0.05, 0.20))
            residential_share = float(np.clip(0.82 + rng.normal(0, 0.08), 0.5, 0.99))
            occupied = int(total_units * residential_share)
            owner_rate = float(np.clip(0.55 + rng.normal(0, 0.15), 0.10, 0.95))
            owner_occ = int(occupied * owner_rate)
            renter_occ = occupied - owner_occ
            total_pop = int(total_units * rng.uniform(1.8, 3.2))
            med_income = int(rng.lognormal(np.log(income_k * 1000), 0.3))
            med_home_value = int(med_income * rng.uniform(3.5, 9.0))
            year_built = int(np.clip(rng.normal(1988, 15), 1940, 2022))
            prop_age = 2026 - year_built
            high_value = 1.0 if med_home_value >= 1_000_000 else 0.0
            solar_cand_share = float(np.clip(sfh_share * owner_rate, 0, 1))

            rows.append({
                "geo_id": z,
                "state_fips": "",
                "NAME": f"ZCTA {z}",
                "parcel_count": total_units,
                "residential_parcel_count": occupied,
                "single_family_count": sf_units,
                "solar_candidate_count": int(solar_cand_share * total_units),
                "single_family_share": round(sfh_share, 4),
                "residential_share": round(residential_share, 4),
                "owner_occupancy_rate": round(owner_rate, 4),
                "solar_candidate_share": round(solar_cand_share, 4),
                "high_value_share": high_value,
                "median_final_value": med_home_value,
                "median_home_value": med_home_value,
                "median_household_income": med_income,
                "median_year_built": year_built,
                "median_property_age": prop_age,
                "total_population": total_pop,
                "total_housing_units": total_units,
                "occupied_units": occupied,
                "owner_occupied_units": owner_occ,
                "renter_occupied_units": renter_occ,
                "single_family_detached_units": sf_units - sf_attached,
                "single_family_attached_units": sf_attached,
                "housing_density_proxy": total_units,
                # centroid (used later)
                "_lat": round(jlat, 6),
                "_lon": round(jlon, 6),
                "_state": state,
                "_solar_weight": solar_wt,
            })

    df = pd.DataFrame(rows).drop_duplicates(subset=["geo_id"])
    return df


def engineer_and_score(community_df: pd.DataFrame, cves_df: pd.DataFrame, products_df: pd.DataFrame) -> pd.DataFrame:
    """Replicate the logic from script 14 to produce final model inputs."""
    df = community_df.copy()

    # State from ZIP seed data
    df["state"] = df["_state"]
    df["state_solar_weight"] = df["_solar_weight"]

    # Centroids
    df["lat"] = df["_lat"]
    df["lon"] = df["_lon"]
    df = df.drop(columns=["_lat", "_lon", "_state", "_solar_weight"])

    # Compute base cyber pressure from CVE data
    merged = products_df.merge(cves_df, on="cve_id", how="left")
    merged["cvss_score"] = pd.to_numeric(merged["cvss_score"], errors="coerce")
    merged["cisa_kev"] = pd.to_numeric(merged["cisa_kev"], errors="coerce").fillna(0).astype(int)
    solar_vendors = set(VENDOR_CANONICAL.keys())
    solar = merged[merged["vendor"].isin(solar_vendors)].copy()

    unique_cves = solar["cve_id"].nunique() if not solar.empty else 1
    critical = solar.loc[solar["cvss_score"].fillna(0) >= 9.0, "cve_id"].nunique() if not solar.empty else 0
    kev = int(solar["cisa_kev"].fillna(0).sum()) if not solar.empty else 0
    max_cvss = float(solar["cvss_score"].fillna(0).max()) if not solar.empty else 9.8
    avg_cvss = float(solar["cvss_score"].fillna(0).mean()) if not solar.empty else 8.5

    base_pressure = (
        0.35 * (max_cvss / 10.0)
        + 0.25 * (critical / unique_cves)
        + 0.20 * (kev / unique_cves if unique_cves else 0)
        + 0.20 * (avg_cvss / 10.0)
    ) * 100

    df["solar_cyber_pressure_score"] = (base_pressure * df["state_solar_weight"]).round(2)

    # Cyber stats columns
    df["solar_cve_count"] = unique_cves
    df["solar_critical_cve_count"] = critical
    df["solar_kev_cve_count"] = kev
    df["solar_vendor_count"] = int(solar["vendor"].nunique()) if not solar.empty else 0
    df["solar_avg_cvss"] = round(avg_cvss, 4)
    df["solar_max_cvss"] = round(max_cvss, 4)

    # Income × solar interaction
    income = df["median_household_income"].fillna(df["median_household_income"].median())
    income_norm = (income - income.min()) / (income.max() - income.min() + 1e-9)
    df["income_solar_interaction"] = (income_norm * df["solar_candidate_share"]).round(4)

    # Property age sweet-spot (bell curve centered at 25 yrs, sigma=12)
    age = df["median_property_age"].fillna(df["median_property_age"].median())
    df["age_risk_factor"] = np.exp(-0.5 * ((age - 25) / 12) ** 2).round(4)

    # Solar readiness score
    df["solar_readiness_score"] = (
        0.30 * df["single_family_share"].fillna(0)
        + 0.20 * df["residential_share"].fillna(0)
        + 0.15 * df["solar_candidate_share"].fillna(0)
        + 0.15 * df["income_solar_interaction"].fillna(0)
        + 0.10 * df["age_risk_factor"].fillna(0)
        + 0.10 * df["high_value_share"].fillna(0)
    ) * 100
    df["solar_readiness_score"] = df["solar_readiness_score"].round(2)

    # Community risk score
    df["community_risk_prior_score"] = (
        0.55 * df["solar_readiness_score"]
        + 0.45 * df["solar_cyber_pressure_score"]
    ).round(2)

    # K-means clustering
    cluster_features = [
        "single_family_share", "owner_occupancy_rate", "solar_candidate_share",
        "income_solar_interaction", "age_risk_factor", "high_value_share",
        "state_solar_weight", "median_property_age",
    ]
    X = df[cluster_features].copy()
    for col in cluster_features:
        X[col] = X[col].fillna(X[col].median())

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    km = KMeans(n_clusters=5, random_state=42, n_init=10)
    df["risk_cluster"] = km.fit_predict(X_scaled)

    # Label clusters by mean risk score (highest = CRITICAL)
    cluster_means = df.groupby("risk_cluster")["community_risk_prior_score"].mean().sort_values(ascending=False)
    labels = ["CRITICAL", "ELEVATED", "MODERATE", "LOW", "MINIMAL"]
    cluster_label_map = {int(c): labels[i] for i, c in enumerate(cluster_means.index)}
    df["risk_cluster_label"] = df["risk_cluster"].map(cluster_label_map)

    return df


def main() -> None:
    print("=== SolarShield seed data generator ===\n")

    # 1. CVE + products
    print("Generating CVE data...")
    cves_df, products_df = make_cve_data()
    cves_df.to_csv(OUTPUT / "vulnerability_cves.csv", index=False)
    products_df.to_csv(OUTPUT / "vulnerability_affected_products.csv", index=False)
    print(f"  {len(cves_df)} CVEs, {len(products_df)} affected products")

    # 2. Vendor priors + curated products
    print("Building vendor priors...")
    curated_df, vendor_df = make_vendor_priors(cves_df, products_df)
    curated_df.to_csv(OUTPUT / "high_confidence_solar_affected_products.csv", index=False)
    vendor_df.to_csv(OUTPUT / "vendor_risk_priors.csv", index=False)
    print(f"  {len(vendor_df)} vendors, {len(curated_df)} curated product entries")

    # 3. Community features
    print("Generating community features...")
    community_df = make_community_features(ZIP_SEEDS)
    census_out = community_df.drop(columns=["_lat", "_lon", "_state", "_solar_weight"], errors="ignore")
    # Add back the hidden cols for the centroid step — they're still in community_df
    community_df.drop(columns=["state_fips", "NAME"], errors="ignore")
    census_save = community_df[[c for c in community_df.columns if not c.startswith("_")]]
    census_save["geo_id"] = census_save["geo_id"].astype(str).str.zfill(5)
    census_save.to_csv(PROCESSED / "census_community_features_by_zip.csv", index=False)
    print(f"  {len(community_df)} ZCTAs in community features")

    # 4. ZIP centroids
    print("Generating ZIP centroids...")
    centroids_df = community_df[["geo_id", "_lat", "_lon"]].rename(columns={"_lat": "lat", "_lon": "lon"}).copy()
    centroids_df["geo_id"] = centroids_df["geo_id"].astype(str).str.zfill(5)
    centroids_df.to_csv(PROCESSED / "zcta_centroids.csv", index=False)
    print(f"  {len(centroids_df)} centroids")

    # 5. Final enhanced model inputs
    print("Running risk scoring + clustering...")
    final_df = engineer_and_score(community_df, cves_df, products_df)
    final_df["geo_id"] = final_df["geo_id"].astype(str).str.zfill(5)
    final_df.to_csv(PROCESSED / "community_model_inputs_census_nationwide.csv", index=False)
    print(f"  {len(final_df)} ZCTAs scored")

    # Summary
    print("\n=== Summary ===")
    print(f"  Avg risk score:  {final_df['community_risk_prior_score'].mean():.1f}")
    print(f"  Max risk score:  {final_df['community_risk_prior_score'].max():.1f}")
    print(f"  Risk clusters:   {final_df['risk_cluster_label'].value_counts().to_dict()}")
    top = final_df.nlargest(5, "community_risk_prior_score")[["geo_id", "state", "community_risk_prior_score", "risk_cluster_label"]]
    print(f"\n  Top 5 ZIPs by risk:\n{top.to_string(index=False)}")
    print("\nAll seed files written. Run `python run.py` to start the server.")


if __name__ == "__main__":
    main()
