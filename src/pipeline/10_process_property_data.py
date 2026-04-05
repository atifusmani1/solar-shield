#!/usr/bin/env python3
"""
Aggregate raw property assessment, AVM, and US geo data into processed modeling tables.

Inputs:
  - data/raw/PropertyAssessmentData.csv
  - data/raw/AVM.csv
  - data/raw/USGeoData.csv

Outputs:
  - data/processed/property_parcels_enriched.csv
  - data/processed/community_features_by_census.csv
  - data/processed/community_features_by_zip.csv
  - data/processed/community_features_by_fips.csv
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import pandas as pd


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RAW_DIR = REPO_ROOT / "data" / "raw"
PROCESSED_DIR = REPO_ROOT / "data" / "processed"
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

ASSESSMENT_PATH = RAW_DIR / "PropertyAssessmentData.csv"
AVM_PATH = RAW_DIR / "AVM.csv"
US_GEO_PATH = RAW_DIR / "USGeoData.csv"


def normalize_text(value: object) -> str:
    if pd.isna(value):
        return ""
    text = str(value).strip().lower()
    text = re.sub(r"[^a-z0-9 ]+", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def normalize_zip(value: object) -> str:
    if pd.isna(value):
        return ""
    digits = re.sub(r"\D", "", str(value))
    return digits[:5].zfill(5) if digits else ""


def normalize_zip4(value: object) -> str:
    if pd.isna(value):
        return ""
    digits = re.sub(r"\D", "", str(value))
    return digits[:4].zfill(4) if digits else ""


def normalize_fips(value: object) -> str:
    if pd.isna(value):
        return ""
    digits = re.sub(r"\D", "", str(value))
    return digits[:5].zfill(5) if digits else ""


def numeric_series(series: pd.Series) -> pd.Series:
    return pd.to_numeric(series, errors="coerce")


def build_address_key(address: pd.Series, city: pd.Series, state: pd.Series, zip_code: pd.Series) -> pd.Series:
    return (
        address.map(normalize_text)
        + "|"
        + city.map(normalize_text)
        + "|"
        + state.fillna("").astype(str).str.upper().str.strip()
        + "|"
        + zip_code.map(normalize_zip)
    )


def load_assessment() -> pd.DataFrame:
    df = pd.read_csv(ASSESSMENT_PATH, low_memory=False)
    df = df.rename(columns={"RecordId": "record_id"})
    df["State"] = df["State"].fillna("").astype(str).str.upper().str.strip()
    df["ZipCode"] = df["ZipCode"].map(normalize_zip)
    df["ZipCodePlus4"] = df["ZipCodePlus4"].map(normalize_zip4)
    df["FIPSCode"] = df["FIPSCode"].map(normalize_fips)
    df["address_key"] = build_address_key(df["PropertyAddress"], df["City"], df["State"], df["ZipCode"])
    df["geo_join_key"] = df["State"] + "|" + df["ZipCode"] + "|" + df["ZipCodePlus4"]
    df["TotalAssessedValue"] = numeric_series(df["TotalAssessedValue"])
    df["SalesPriceFromAssessment"] = numeric_series(df["SalesPriceFromAssessment"])
    df["LotSizeOrArea"] = numeric_series(df["LotSizeOrArea"])
    df["YearBuilt"] = numeric_series(df["YearBuilt"])
    df["TotalNumberOfRooms"] = numeric_series(df["TotalNumberOfRooms"])
    df["NumberOfBedrooms"] = numeric_series(df["NumberOfBedrooms"])
    df["NumberOfBaths"] = numeric_series(df["NumberOfBaths"])
    df["NumberOfPartialBaths"] = numeric_series(df["NumberOfPartialBaths"])
    df["NumberOfBuildings"] = numeric_series(df["NumberOfBuildings"])
    df["NumberOfUnits"] = numeric_series(df["NumberOfUnits"])
    df["GarageParkingNumberOfCars"] = numeric_series(df["GarageParkingNumberOfCars"])
    df["is_residential"] = df["CountyLandUseDescription"].fillna("").str.contains("residential", case=False, na=False)
    df["is_single_family"] = df["CountyLandUseDescription"].fillna("").str.contains("single family", case=False, na=False)
    df["property_age"] = 2026 - df["YearBuilt"]
    return df


def load_geo() -> pd.DataFrame:
    geo = pd.read_csv(US_GEO_PATH, low_memory=False)
    geo = geo.rename(columns={"RecordID": "record_id_geo"})
    geo["State"] = geo["State"].fillna("").astype(str).str.upper().str.strip()
    geo["ZipCode"] = geo["ZipCode"].map(normalize_zip)
    geo["ZipCodePlus4"] = geo["ZipCodePlus4"].map(normalize_zip4)
    geo["FIPSCode"] = geo["FIPSCode"].map(normalize_fips)
    geo["geo_join_key"] = geo["State"] + "|" + geo["ZipCode"] + "|" + geo["ZipCodePlus4"]
    geo["Latitude"] = numeric_series(geo["Latitude"])
    geo["Longitude"] = numeric_series(geo["Longitude"])
    geo = (
        geo.sort_values(["geo_join_key", "record_id_geo"])
        .drop_duplicates(subset=["geo_join_key"], keep="first")
        [["geo_join_key", "FIPSCode", "CensusKey", "CensusKeyDecennial", "Latitude", "Longitude"]]
        .rename(
            columns={
                "FIPSCode": "geo_fips_code",
                "CensusKey": "geo_census_key",
                "CensusKeyDecennial": "geo_census_key_decennial",
                "Latitude": "geo_latitude",
                "Longitude": "geo_longitude",
            }
        )
    )
    return geo


def load_avm_for_assessment(assessment: pd.DataFrame, chunk_size: int = 100_000) -> pd.DataFrame:
    needed_states = set(assessment["State"].dropna().unique())
    needed_zips = set(assessment["ZipCode"].dropna().unique())
    chunks: list[pd.DataFrame] = []

    for chunk in pd.read_csv(AVM_PATH, chunksize=chunk_size, low_memory=False):
        chunk = chunk.rename(columns={"RecordId": "record_id_avm"})
        chunk["State"] = chunk["State"].fillna("").astype(str).str.upper().str.strip()
        chunk["ZipCode"] = chunk["ZipCode"].map(normalize_zip)
        chunk = chunk[chunk["State"].isin(needed_states) & chunk["ZipCode"].isin(needed_zips)].copy()
        if chunk.empty:
            continue
        chunk["address_key"] = build_address_key(chunk["Address"], chunk["City"], chunk["State"], chunk["ZipCode"])
        chunk["ZipCodePlus4"] = chunk["ZipCodePlus4"].map(normalize_zip4)
        chunk["FIPSCode"] = chunk["FIPSCode"].map(normalize_fips)
        chunk["FinalValue"] = numeric_series(chunk["FinalValue"])
        chunk["HighValue"] = numeric_series(chunk["HighValue"])
        chunk["LowValue"] = numeric_series(chunk["LowValue"])
        chunks.append(
            chunk[
                [
                    "record_id_avm",
                    "address_key",
                    "County",
                    "Address",
                    "City",
                    "State",
                    "ZipCode",
                    "ZipCodePlus4",
                    "Latitude",
                    "Longitude",
                    "FIPSCode",
                    "FinalValue",
                    "HighValue",
                    "LowValue",
                    "ValuationDate",
                ]
            ]
        )

    if not chunks:
        return pd.DataFrame(
            columns=[
                "record_id_avm",
                "address_key",
                "County",
                "Address",
                "City",
                "State",
                "ZipCode",
                "ZipCodePlus4",
                "Latitude",
                "Longitude",
                "FIPSCode",
                "FinalValue",
                "HighValue",
                "LowValue",
                "ValuationDate",
            ]
        )

    avm = pd.concat(chunks, ignore_index=True)
    avm = avm.sort_values(["address_key", "ValuationDate"], ascending=[True, False]).drop_duplicates("address_key")
    return avm


def combine_data() -> pd.DataFrame:
    assessment = load_assessment()
    geo = load_geo()
    avm = load_avm_for_assessment(assessment)

    merged = assessment.merge(
        avm.add_prefix("avm_"),
        left_on="address_key",
        right_on="avm_address_key",
        how="left",
    )
    merged = merged.merge(geo, on="geo_join_key", how="left")

    merged["matched_avm"] = merged["avm_record_id_avm"].notna()
    merged["matched_geo"] = merged["geo_census_key"].notna()
    merged["final_value"] = merged["avm_FinalValue"]
    merged["value_spread"] = merged["avm_HighValue"] - merged["avm_LowValue"]
    merged["effective_fips_code"] = merged["FIPSCode"].where(merged["FIPSCode"] != "", merged["geo_fips_code"])
    merged["effective_census_key"] = merged["CensusKey"].where(merged["CensusKey"].notna(), merged["geo_census_key"])
    merged["effective_census_key_decennial"] = merged["CensusKeyDecennial"].where(
        merged["CensusKeyDecennial"].notna(), merged["geo_census_key_decennial"]
    )
    merged["effective_latitude"] = merged["Latitude"].fillna(merged["geo_latitude"])
    merged["effective_longitude"] = merged["Longitude"].fillna(merged["geo_longitude"])
    merged["assessed_to_avm_ratio"] = merged["TotalAssessedValue"] / merged["final_value"]
    merged["has_garage"] = merged["GarageParkingNumberOfCars"].fillna(0) > 0
    merged["high_value_home"] = merged["final_value"].fillna(merged["TotalAssessedValue"]).ge(1_000_000)
    merged["solar_candidate_home"] = (
        merged["is_residential"].fillna(False)
        & merged["NumberOfUnits"].fillna(0).le(2)
        & merged["effective_latitude"].notna()
        & merged["effective_longitude"].notna()
    )

    keep_columns = [
        "record_id",
        "PropertyAddress",
        "City",
        "State",
        "ZipCode",
        "ZipCodePlus4",
        "effective_fips_code",
        "effective_census_key",
        "effective_census_key_decennial",
        "effective_latitude",
        "effective_longitude",
        "CountyLandUseDescription",
        "TotalAssessedValue",
        "AssessmentYear",
        "SalesPriceFromAssessment",
        "final_value",
        "avm_HighValue",
        "avm_LowValue",
        "value_spread",
        "avm_ValuationDate",
        "LotSizeOrArea",
        "LotSizeAreaUnit",
        "YearBuilt",
        "property_age",
        "TotalNumberOfRooms",
        "NumberOfBedrooms",
        "NumberOfBaths",
        "NumberOfPartialBaths",
        "NumberOfStories",
        "NumberOfBuildings",
        "NumberOfUnits",
        "GarageParkingNumberOfCars",
        "HasSecurityAlarm",
        "is_residential",
        "is_single_family",
        "has_garage",
        "high_value_home",
        "solar_candidate_home",
        "matched_avm",
        "matched_geo",
        "assessed_to_avm_ratio",
    ]
    return merged[keep_columns].copy()


def build_community_aggregates(df: pd.DataFrame, group_col: str) -> pd.DataFrame:
    valid = df[df[group_col].notna() & (df[group_col].astype(str).str.strip() != "")].copy()

    grouped = (
        valid.groupby(group_col, dropna=False)
        .agg(
            parcel_count=("record_id", "count"),
            residential_parcel_count=("is_residential", "sum"),
            single_family_count=("is_single_family", "sum"),
            solar_candidate_count=("solar_candidate_home", "sum"),
            matched_avm_count=("matched_avm", "sum"),
            matched_geo_count=("matched_geo", "sum"),
            median_assessed_value=("TotalAssessedValue", "median"),
            mean_assessed_value=("TotalAssessedValue", "mean"),
            median_final_value=("final_value", "median"),
            mean_final_value=("final_value", "mean"),
            median_lot_size=("LotSizeOrArea", "median"),
            median_year_built=("YearBuilt", "median"),
            median_property_age=("property_age", "median"),
            median_bedrooms=("NumberOfBedrooms", "median"),
            median_baths=("NumberOfBaths", "median"),
            avg_units=("NumberOfUnits", "mean"),
            avg_buildings=("NumberOfBuildings", "mean"),
            garage_share=("has_garage", "mean"),
            high_value_share=("high_value_home", "mean"),
        )
        .reset_index()
    )

    grouped["residential_share"] = grouped["residential_parcel_count"] / grouped["parcel_count"]
    grouped["single_family_share"] = grouped["single_family_count"] / grouped["parcel_count"]
    grouped["solar_candidate_share"] = grouped["solar_candidate_count"] / grouped["parcel_count"]
    grouped["avm_match_rate"] = grouped["matched_avm_count"] / grouped["parcel_count"]
    grouped["geo_match_rate"] = grouped["matched_geo_count"] / grouped["parcel_count"]
    return grouped


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", default=None, help="Optional state filter, e.g. CA")
    args = parser.parse_args()

    df = combine_data()
    if args.state:
        df = df[df["State"] == args.state.upper()].copy()

    df = df.sort_values(["State", "ZipCode", "City", "PropertyAddress"]).reset_index(drop=True)

    census = build_community_aggregates(df, "effective_census_key_decennial")
    zip_summary = build_community_aggregates(df, "ZipCode")
    fips_summary = build_community_aggregates(df, "effective_fips_code")

    parcel_out = PROCESSED_DIR / "property_parcels_enriched.csv"
    census_out = PROCESSED_DIR / "community_features_by_census.csv"
    zip_out = PROCESSED_DIR / "community_features_by_zip.csv"
    fips_out = PROCESSED_DIR / "community_features_by_fips.csv"

    df.to_csv(parcel_out, index=False)
    census.to_csv(census_out, index=False)
    zip_summary.to_csv(zip_out, index=False)
    fips_summary.to_csv(fips_out, index=False)

    print(f"Saved parcel-level file: {parcel_out}")
    print(f"Saved census aggregates: {census_out}")
    print(f"Saved ZIP aggregates: {zip_out}")
    print(f"Saved FIPS aggregates: {fips_out}")
    print(f"Rows written: parcels={len(df)}, census={len(census)}, zip={len(zip_summary)}, fips={len(fips_summary)}")


if __name__ == "__main__":
    main()
