#!/usr/bin/env python3
"""
Download ZCTA centroid coordinates from the Census Gazetteer.

The Gazetteer file is a tab-delimited Census publication (~2 MB) that maps
every ZCTA to its internal-point lat/lon — the geographic center used for
map plotting.

Output:
    data/processed/zcta_centroids.csv   (geo_id, lat, lon)

Usage:
    python scripts/13_fetch_zip_centroids.py
"""

from __future__ import annotations

import io
from pathlib import Path

import pandas as pd
import requests

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
PROCESSED_DIR = REPO_ROOT / "data" / "processed"
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

# Census Gazetteer — 2022 ZCTA file (tab-delimited, ~2 MB)
GAZETTEER_URL = "https://www2.census.gov/geo/docs/maps-data/data/gazetteer/2022_Gazetteer/2022_Gaz_zcta_national.zip"
OUT_PATH = PROCESSED_DIR / "zcta_centroids.csv"


def fetch_centroids() -> pd.DataFrame:
    print("Downloading Census ZCTA Gazetteer...")
    resp = requests.get(GAZETTEER_URL, timeout=60)
    resp.raise_for_status()

    # The zip contains a single tab-delimited .txt file
    import zipfile
    with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
        name = z.namelist()[0]
        with z.open(name) as f:
            gaz = pd.read_csv(f, sep="\t", dtype={"GEOID": str}, encoding="latin-1")

    print(f"  {len(gaz):,} ZCTAs in Gazetteer")
    print(f"  Columns: {list(gaz.columns)}")

    # Normalise column names — vary slightly across Gazetteer vintages
    gaz.columns = gaz.columns.str.strip()
    lat_col = next(c for c in gaz.columns if "INTPTLAT" in c.upper())
    lon_col = next(c for c in gaz.columns if "INTPTLONG" in c.upper())

    centroids = pd.DataFrame({
        "geo_id": gaz["GEOID"].str.zfill(5),
        "lat":    pd.to_numeric(gaz[lat_col], errors="coerce"),
        "lon":    pd.to_numeric(gaz[lon_col], errors="coerce"),
    }).dropna()

    return centroids


def main() -> None:
    centroids = fetch_centroids()
    centroids.to_csv(OUT_PATH, index=False)
    print(f"Saved {len(centroids):,} centroids -> {OUT_PATH}")


if __name__ == "__main__":
    main()
