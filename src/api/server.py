"""
SolarShield API — FastAPI backend for the terminal dashboard.

Serves risk data as JSON and proxies Melissa property lookups
(keeping the license key server-side).

Run from repo root:
    python run.py
    # or: uvicorn src.api.server:app --reload --port 8000
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pandas as pd
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "src" / "api"))

# Load .env
try:
    from dotenv import load_dotenv
    load_dotenv(REPO_ROOT / ".env")
except ImportError:
    pass

from melissa_lookup import lookup_property  # noqa: E402

app = FastAPI(title="SolarShield API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Data loading ─────────────────────────────────────────────────────────────
PROCESSED = REPO_ROOT / "data" / "processed"
OUTPUT = REPO_ROOT / "output"

_risk_df: pd.DataFrame | None = None
_vendors_df: pd.DataFrame | None = None
_cves_df: pd.DataFrame | None = None


def get_risk_data() -> pd.DataFrame:
    global _risk_df
    if _risk_df is None:
        risk = pd.read_csv(PROCESSED / "community_model_inputs_census_nationwide.csv", dtype={"geo_id": str})
        risk["geo_id"] = risk["geo_id"].str.zfill(5)
        centroids = pd.read_csv(PROCESSED / "zcta_centroids.csv", dtype={"geo_id": str})
        centroids["geo_id"] = centroids["geo_id"].str.zfill(5)
        _risk_df = risk.merge(centroids, on="geo_id", how="inner")
    return _risk_df


def get_vendors() -> pd.DataFrame:
    global _vendors_df
    if _vendors_df is None:
        _vendors_df = pd.read_csv(OUTPUT / "vendor_risk_priors.csv")
    return _vendors_df


def get_cves() -> pd.DataFrame:
    global _cves_df
    if _cves_df is None:
        _cves_df = pd.read_csv(OUTPUT / "high_confidence_solar_affected_products.csv")
    return _cves_df


# ── Routes ───────────────────────────────────────────────────────────────────

@app.get("/")
def index():
    return FileResponse(REPO_ROOT / "src" / "dashboard" / "index.html")


@app.get("/api/risk-data")
def risk_data():
    """Return all ZCTA risk data as compact JSON for deck.gl."""
    df = get_risk_data()
    cols = [
        "geo_id", "lat", "lon",
        "community_risk_prior_score", "solar_readiness_score",
        "solar_cyber_pressure_score",
        "solar_candidate_share", "single_family_share", "owner_occupancy_rate",
        "median_home_value", "median_household_income",
        "total_housing_units", "total_population",
        "high_value_share", "median_property_age",
        "state", "risk_cluster", "risk_cluster_label",
        "state_solar_weight", "income_solar_interaction", "age_risk_factor",
    ]
    cols = [c for c in cols if c in df.columns]
    records = df[cols].fillna("").to_dict(orient="records")
    return JSONResponse(records)


@app.get("/api/stats")
def stats():
    """Return aggregate statistics for KPI cards."""
    df = get_risk_data()
    vendors = get_vendors()
    cves = get_cves()

    # Cluster counts
    cluster_counts = {}
    if "risk_cluster_label" in df.columns:
        for label in ["CRITICAL", "ELEVATED", "MODERATE", "LOW", "MINIMAL"]:
            cluster_counts[label.lower() + "_count"] = int((df["risk_cluster_label"] == label).sum())

    return {
        "total_zctas": len(df),
        **cluster_counts,
        "total_cves": int(cves["cve_id"].nunique()),
        "critical_cves": int((pd.to_numeric(cves["cvss_score"], errors="coerce") >= 9.0).sum()),
        "vendor_count": len(vendors),
        "max_cvss": float(pd.to_numeric(cves["cvss_score"], errors="coerce").max()),
        "avg_risk_score": round(float(df["community_risk_prior_score"].mean()), 1),
        "cyber_pressure_range": f"{df['solar_cyber_pressure_score'].min():.1f}-{df['solar_cyber_pressure_score'].max():.1f}",
    }


@app.get("/api/vendors")
def vendor_data():
    """Return vendor risk priors."""
    vendors = get_vendors()
    return vendors.to_dict(orient="records")


@app.get("/api/top-zips")
def top_zips(n: int = Query(default=25, le=100)):
    """Return top N highest risk ZCTAs."""
    df = get_risk_data().nlargest(n, "community_risk_prior_score")
    cols = [
        "geo_id", "lat", "lon",
        "community_risk_prior_score", "solar_readiness_score",
        "solar_candidate_share", "owner_occupancy_rate", "single_family_share",
        "median_home_value", "median_household_income", "total_housing_units",
    ]
    return df[cols].fillna("").to_dict(orient="records")


@app.get("/api/lookup")
def property_lookup(
    address: str = Query(...),
    city: str = Query(default=""),
    state: str = Query(default=""),
    zip_code: str = Query(default="", alias="zip"),
):
    """Proxy Melissa property lookup — license key stays server-side."""
    result = lookup_property(
        address=address,
        city=city,
        state=state.upper(),
        zip_code=zip_code,
    )

    if not result.success:
        return JSONResponse({"success": False, "error": result.error}, status_code=400)

    # Find community data for this ZIP
    df = get_risk_data()
    zip_match = df[df["geo_id"] == result.zip_code]
    community = None
    if not zip_match.empty:
        row = zip_match.iloc[0]
        community = {
            "geo_id": row["geo_id"],
            "state": row.get("state", ""),
            "risk_score": round(float(row["community_risk_prior_score"]), 1),
            "solar_readiness": round(float(row["solar_readiness_score"]), 1),
            "cyber_pressure": round(float(row.get("solar_cyber_pressure_score", 0)), 1),
            "risk_cluster": row.get("risk_cluster_label", ""),
            "solar_candidate_share": round(float(row["solar_candidate_share"]), 3),
            "single_family_share": round(float(row["single_family_share"]), 3),
            "owner_occupancy_rate": round(float(row["owner_occupancy_rate"]), 3),
            "median_home_value": row["median_home_value"] if pd.notna(row["median_home_value"]) else None,
            "median_income": row["median_household_income"] if pd.notna(row["median_household_income"]) else None,
            "total_units": int(row["total_housing_units"]),
            "lat": float(row["lat"]),
            "lon": float(row["lon"]),
        }

    return {
        "success": True,
        "property": {
            "address": result.address,
            "city": result.city,
            "state": result.state,
            "zip_code": result.zip_code,
            "lat": result.lat,
            "lon": result.lon,
            "year_built": result.year_built,
            "property_type": result.property_type,
            "structure_style": result.structure_style,
            "bedrooms": result.bedrooms,
            "baths": result.baths,
            "sq_ft": result.sq_ft,
            "lot_size": result.lot_size,
            "stories": result.stories,
            "owner_name": result.owner_name,
            "owner_occupied": result.owner_occupied,
            "assessed_value": result.assessed_value,
            "market_value": result.market_value,
            "last_sale_price": result.last_sale_price,
            "last_sale_date": result.last_sale_date,
        },
        "community": community,
    }


# Serve static files
static_dir = REPO_ROOT / "src" / "dashboard"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=True)
