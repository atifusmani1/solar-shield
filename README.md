# SolarShield

SolarShield predicts which U.S. communities are most likely to contain vulnerable residential solar inverter infrastructure before a single device is scanned.

Instead of asking only "which internet-exposed inverters can we find right now?", this project asks a more operationally useful question:

**Given what we know about a neighborhood's properties, people, and geography, how likely is it that vulnerable solar inverters are present and exposed on the grid?**

That shift matters for utilities, emergency managers, and grid operators. CVE reports tell us which vendors and products are vulnerable. Shodan tells us some of what is already exposed. But neither tells us where vulnerable solar infrastructure is most concentrated at the ZIP code, tract, neighborhood, or utility-service level. SolarShield is designed to fill that gap with predictive risk modeling.

## Problem Statement

Residential solar adoption is accelerating across the United States, but the inverters connecting these systems to the grid carry documented cybersecurity weaknesses. A CVE might tell us that Growatt, Sungrow, SMA, or SolarView devices are vulnerable. It does not tell us which communities are most likely to host those devices at scale.

SolarShield combines:

- Property characteristics such as home value, structure type, building age, and owner occupancy
- Demographic indicators such as income, housing density, and mortgage patterns
- Geographic signals such as solar irradiance, latitude, and climate zone
- Known solar adoption patterns across U.S. housing markets
- Cybersecurity intelligence from CVE records and Shodan observations

The result is a ranked community-level risk surface that helps prioritize outreach, inspection, remediation, and defensive planning before attackers discover the same patterns.

## What This Repo Does Today

This repository already contains the building blocks for a predictive risk workflow:

- `scripts/01_fetch_nvd_cves.py` pulls solar-related vulnerability intelligence from NIST NVD
- `scripts/02_fetch_eia_grid_data.py` pulls U.S. solar capacity context from EIA
- `scripts/03_shodan_search.py` collects passive exposure signals from publicly indexed Shodan data
- `scripts/04_risk_score.py` converts device-level signals into comparable risk scores
- `scripts/05_fleet_aggregator.py` rolls findings up into region and vendor summaries

In the new framing, these components serve three roles:

- Vulnerability priors: which vendors and products are known to be risky
- Exposure labels: where passive internet evidence suggests vulnerable infrastructure is already visible
- Calibration context: how neighborhood-level predictions connect to broader grid impact

## Predictive Workflow

The intended end-to-end workflow is:

1. Build a community-level feature table from property, demographic, and geographic data.
2. Use CVE and Shodan intelligence to label or weakly supervise areas that likely contain vulnerable solar infrastructure.
3. Train a model that estimates the probability that a community contains vulnerable and potentially exposed inverter populations.
4. Aggregate predictions into ZIP code, tract, county, or utility-service summaries.
5. Prioritize the highest-risk communities for outreach, field validation, or deeper technical review.

## Why This Is Different

Most solar cybersecurity work is reactive:

- find exposed devices
- confirm vulnerabilities
- respond after exposure is visible

SolarShield is proactive:

- infer where vulnerable devices are likely concentrated
- rank communities before direct discovery
- help utilities spend limited response capacity where it matters most

## Repository Structure

```text
solar-inverter-scanner/
|-- data/
|   |-- cve_database.json
|   `-- grid_capacity.json
|-- output/
|   `-- nvd_cves.json
|-- queries/
|   `-- shodan_web_queries.txt
|-- scripts/
|   |-- 01_fetch_nvd_cves.py
|   |-- 02_fetch_eia_grid_data.py
|   |-- 03_shodan_search.py
|   |-- 04_risk_score.py
|   `-- 05_fleet_aggregator.py
|-- .env.example
|-- IMPLEMENTATION.md
|-- PropertyData_Sample.txt
|-- README-solar-hack.md
|-- README.md
`-- requirements.txt
```

## Current Inputs

The repo currently includes or references:

- Solar-related CVE intelligence from NVD
- Grid context from EIA and local fallback data
- Vendor-specific Shodan search queries
- Local JSON reference data for scoring and aggregation
- A sample property data file that can inform the future feature engineering layer

## Near-Term Build Direction

The next evolution of the project is to add a community-level modeling layer on top of the existing scripts:

- Ingest parcel, property, census, and irradiance data
- Engineer features associated with rooftop solar adoption and inverter vendor mix
- Use passive exposure and vulnerability signals as training labels or calibration targets
- Produce probability scores by geography
- Export ranked intervention lists for utilities and public-sector partners

## Running The Existing Pipeline

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the current scripts individually:

```bash
python scripts/01_fetch_nvd_cves.py
python scripts/02_fetch_eia_grid_data.py
python scripts/03_shodan_search.py --all-queries --limit 100
python scripts/04_risk_score.py
python scripts/05_fleet_aggregator.py
```

Notes:

- `03_shodan_search.py` requires a Shodan API key
- the rest of the scripts operate on public APIs or local files
- today the outputs are device- and region-oriented; the docs now position those outputs as inputs to a predictive community-risk model

## Intended Outputs

As this repo evolves, the key product outputs should be:

- Community risk scores
- Ranked ZIP codes or census tracts
- Utility-facing priority maps
- Vendor and vulnerability concentration summaries
- Remediation and outreach queues for high-risk communities

## Ethics

SolarShield is designed around passive, publicly available, and aggregate analysis.

- No exploitation
- No unauthorized access
- No active interaction with solar equipment
- No claim that a specific home is compromised without validation

The goal is defensive prioritization: identify where risk is likely concentrated, then help stakeholders verify and remediate responsibly.

## Technical Plan

The updated technical blueprint lives in [IMPLEMENTATION.md](/c:/Users/16164/Documents/datathon-2026/solar-inverter-scanner/IMPLEMENTATION.md).
