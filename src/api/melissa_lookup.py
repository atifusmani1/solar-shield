"""
Melissa Property API helper — single-address lookup.

Docs: https://www.melissa.com/developer/property
Base: https://property.melissadata.net/v4/WEB/LookupProperty

Set MELISSA_LICENSE_KEY in .env or pass directly.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

import requests

MELISSA_BASE = "https://property.melissadata.net/v4/WEB/LookupProperty"

# ACS columns that give us the most useful property intelligence
DEFAULT_COLS = (
    "GrpPropertyDetail,"
    "GrpPropertyType,"
    "GrpAssessmentInfo,"
    "GrpSaleInfo,"
    "GrpOwnerInfo,"
    "GrpGeocode"
)


@dataclass
class PropertyResult:
    """Parsed result from a single Melissa property lookup."""
    success: bool
    address: str = ""
    zip_code: str = ""
    city: str = ""
    state: str = ""
    lat: float | None = None
    lon: float | None = None

    # Property characteristics
    year_built: int | None = None
    property_type: str = ""
    structure_style: str = ""
    bedrooms: int | None = None
    baths: float | None = None
    sq_ft: int | None = None
    lot_size: float | None = None
    stories: int | None = None

    # Ownership & value
    owner_name: str = ""
    owner_occupied: bool | None = None
    assessed_value: float | None = None
    market_value: float | None = None
    last_sale_price: float | None = None
    last_sale_date: str = ""

    # Meta
    raw: dict = field(default_factory=dict)
    error: str = ""


def lookup_property(
    address: str,
    city: str = "",
    state: str = "",
    zip_code: str = "",
    license_key: str | None = None,
) -> PropertyResult:
    """
    Look up a single property address via the Melissa Property API.

    Parameters
    ----------
    address   : Street address, e.g. "123 Main St"
    city      : City name (optional if ZIP is provided)
    state     : Two-letter state abbreviation
    zip_code  : 5-digit ZIP (optional if city+state provided)
    license_key : Melissa license key — falls back to MELISSA_LICENSE_KEY env var
    """
    key = license_key or os.environ.get("MELISSA_LICENSE_KEY", "")
    if not key:
        return PropertyResult(
            success=False,
            error="No Melissa license key. Set MELISSA_LICENSE_KEY in .env or pass license_key=",
        )

    params = {
        "id":   key,
        "cols": DEFAULT_COLS,
        "a1":   address,
        "city": city,
        "state": state,
        "postal": zip_code,
        "format": "json",
    }

    try:
        resp = requests.get(MELISSA_BASE, params=params, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        return PropertyResult(success=False, error=str(e))

    records = data.get("Records", [])
    if not records:
        return PropertyResult(success=False, error="No records returned", raw=data)

    rec = records[0]
    results = rec.get("Results", "")

    # Melissa result codes:
    #   AS01/AS02 = address verified (Address API)
    #   YS02 = property record found (Property API)
    #   YC01 = record matched
    has_match = any(code in results for code in ("AS01", "AS02", "YS02", "YC01"))
    if not has_match:
        return PropertyResult(
            success=False,
            error=f"Address not matched (Results: {results})",
            raw=rec,
        )

    def safe_int(val: object) -> int | None:
        try:
            v = int(val)
            return v if v > 0 else None
        except (TypeError, ValueError):
            return None

    def safe_float(val: object) -> float | None:
        try:
            v = float(val)
            return v if v > 0 else None
        except (TypeError, ValueError):
            return None

    # Helper to get values from nested or flat response structure
    def get(key: str, *nested_paths: tuple[str, str]) -> str:
        """Try flat key first, then nested group.field paths."""
        val = rec.get(key, "")
        if val:
            return str(val)
        for group, field in nested_paths:
            grp = rec.get(group, {})
            if isinstance(grp, dict):
                val = grp.get(field, "")
                if val:
                    return str(val)
        return ""

    # Owner occupied: Melissa returns "Y"/"N" or "O"/"R" in some fields
    occ_raw = get("OwnerOccupied", ("PrimaryOwner", "OwnerOccupied"))
    owner_occupied = True if occ_raw in ("Y", "O") else (False if occ_raw in ("N", "R") else None)

    # Parse address — may be flat or nested
    addr_line = get("AddressLine1", ("Address", "AddressLine1")) or address
    zip_val = get("PostalCode", ("Address", "PostalCode")) or zip_code
    city_val = get("City", ("Address", "City")) or city
    state_val = get("State", ("Address", "State")) or state

    return PropertyResult(
        success=True,
        address=addr_line,
        zip_code=zip_val[:5] if zip_val else zip_code,
        city=city_val,
        state=state_val,
        lat=safe_float(get("Latitude", ("GeoCode", "Latitude"))),
        lon=safe_float(get("Longitude", ("GeoCode", "Longitude"))),

        year_built=safe_int(get("YearBuilt", ("PropertyUseInfo", "YearBuilt"))),
        property_type=get("PropertyType", ("PropertyUseInfo", "PropertyType")),
        structure_style=get("StructureStyle", ("PropertyUseInfo", "StructureStyle")),
        bedrooms=safe_int(get("Bedrooms", ("IntRoomInfo", "BedroomsCount"))),
        baths=safe_float(get("BathsTotal", ("IntRoomInfo", "BathCount"))),
        sq_ft=safe_int(get("AreaBuilding", ("PropertySize", "AreaBuilding"))),
        lot_size=safe_float(get("LotAcres", ("PropertySize", "AreaLotAcres"))),
        stories=safe_int(get("Stories", ("IntRoomInfo", "StoriesCount"))),

        owner_name=get("OwnerName1", ("PrimaryOwner", "Name1Full")),
        owner_occupied=owner_occupied,
        assessed_value=safe_float(get("AssessedValueTotal", ("Tax", "AssessedValueTotal"))),
        market_value=safe_float(get("MarketValueTotal", ("Tax", "MarketValueTotal"), ("Valuation", "EstimatedValue"))),
        last_sale_price=safe_float(get("SaleAmount", ("SaleInfo", "DeedLastSalePrice"), ("SaleInfo", "AssessorLastSaleAmount"))),
        last_sale_date=get("SaleDate", ("SaleInfo", "DeedLastSaleDate"), ("SaleInfo", "AssessorLastSaleDate")),

        raw=rec,
    )


def parse_address_string(full_address: str) -> tuple[str, str, str, str]:
    """
    Naively split a free-form address string into components.
    Works for: "123 Main St, Danville, CA 94528"
    Returns: (street, city, state, zip)
    """
    import re
    parts = [p.strip() for p in full_address.split(",")]
    street = parts[0] if len(parts) > 0 else ""
    city   = parts[1] if len(parts) > 1 else ""

    state, zip_code = "", ""
    if len(parts) > 2:
        state_zip = parts[2].strip()
        m = re.match(r"([A-Za-z]{2})\s*(\d{5})?", state_zip)
        if m:
            state    = m.group(1).upper()
            zip_code = m.group(2) or ""

    return street, city, state, zip_code
