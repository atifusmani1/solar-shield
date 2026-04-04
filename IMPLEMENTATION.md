# IMPLEMENTATION.md - SolarShield Predictive Risk Blueprint

This document reframes SolarShield as a community-level prediction system for vulnerable residential solar infrastructure in the United States.

The core idea is simple:

**Use property, demographic, geographic, solar-adoption, and cyber threat data to estimate where vulnerable solar inverters are most likely concentrated before direct discovery occurs.**

## 1. Objective

SolarShield is not just a scanner. It is a prioritization engine for utilities, grid operators, and public-sector defenders.

The model should answer:

**Which U.S. communities are most likely to contain dense clusters of vulnerable solar inverters, and where should defensive action happen first?**

Target output geographies can include:

- ZIP code
- census tract
- county
- utility service territory
- balancing authority footprint

## 2. Problem Framing

Current cyber intelligence sources answer only part of the problem:

- CVEs tell us which vendors and products are vulnerable
- Shodan tells us some devices are exposed
- Grid datasets tell us where solar penetration is high

What is still missing is a predictive layer that connects those signals to place.

The new project framing is:

1. Infer where residential solar is most likely deployed.
2. Estimate which communities are more likely to have vulnerable vendor footprints.
3. Use passive exposure data as calibration or weak supervision.
4. Rank communities by expected concentration of vulnerable infrastructure.

This turns a reactive device hunt into proactive geographic risk prediction.

## 3. System Overview

```text
Public Cyber Intel        Property + Demographic Data       Geographic + Solar Data
-------------------       -----------------------------     ------------------------
NVD CVEs                  Property records                  Solar irradiance
Shodan observations       Home value                        Latitude / climate zone
Vendor intelligence       Building age                      State / utility context
Known product issues      Owner occupancy                   EIA solar capacity
                          Housing density                   Adoption proxies
                          Mortgage patterns
                                      \                     /
                                       \                   /
                                        \                 /
                                         Feature Engine
                                               |
                                               v
                                  Community Risk Model
                                               |
                                               v
                              Ranked Communities + Priority Maps
                                               |
                                               v
                   Outreach, Inspection, Remediation, Utility Planning
```

## 4. Repository Assets And Their New Role

The current repo already supports part of this architecture.

### 4.1 `scripts/01_fetch_nvd_cves.py`

Purpose in the new system:

- maintain a current catalog of solar-related vulnerabilities
- extract severity, dates, status, and reference metadata
- support vendor-level and product-level risk priors

How to use it:

- treat CVEs as evidence that certain vendors or device families deserve higher baseline risk
- create features such as `vendor_max_cvss`, `vendor_critical_cve_count`, and `vendor_recent_cve_count`

### 4.2 `scripts/02_fetch_eia_grid_data.py`

Purpose in the new system:

- provide U.S. solar capacity context
- identify states with high solar dependency
- contextualize how community-level risk aggregates upward into grid relevance

How to use it:

- add geographic context features
- support demo outputs like "high-risk communities inside high-solar states"

### 4.3 `scripts/03_shodan_search.py`

Purpose in the new system:

- collect passive observations of exposed inverter interfaces and related solar management systems
- provide weak labels or calibration data for model training
- estimate observed exposure by vendor and geography

Important framing:

- this is not the whole product
- this is a label source and evidence stream for the predictive layer

### 4.4 `scripts/04_risk_score.py`

Purpose in the new system:

- create a device-level risk score from vulnerability and exposure indicators
- translate raw cyber signals into a normalized severity measure

How to use it:

- use device-level scores to create aggregate targets by geography
- derive outcomes such as average observed risk, critical-device counts, or vendor-specific observed threat

### 4.5 `scripts/05_fleet_aggregator.py`

Purpose in the new system:

- roll device observations up to a region
- connect local cyber evidence to larger grid implications

How to use it:

- adapt the aggregation logic from country-level summaries to ZIPs, tracts, counties, and utility territories
- turn community scores into action queues

## 5. Proposed Data Model

The prediction layer should operate on one record per geography.

### 5.1 Core Unit

Example unit:

```json
{
  "geo_id": "06073000100",
  "geo_type": "census_tract",
  "state": "CA",
  "county": "San Diego",
  "zip_codes": ["92101", "92102"],
  "utility": "SDG&E"
}
```

### 5.2 Feature Families

Each geography should have a feature vector assembled from five groups.

#### A. Property Features

- median home value
- share of detached single-family homes
- median building age
- owner-occupancy rate
- mortgage prevalence
- parcel size or roof-area proxies
- rooftop suitability proxy if available

Why they matter:

- residential solar adoption is strongly tied to housing type, ownership, and roof suitability

#### B. Demographic Features

- median household income
- educational attainment
- housing density
- household size
- share of owner-occupied units
- energy burden proxy

Why they matter:

- solar adoption tends to cluster in particular socioeconomic and housing-market profiles

#### C. Geographic And Climate Features

- annual solar irradiance
- latitude
- cooling and heating climate zone
- wildfire, storm, or resilience-related regional context if relevant
- urban, suburban, or rural classification

Why they matter:

- solar economics and deployment intensity vary materially by geography

#### D. Solar Adoption Proxies

- state-level installed solar capacity
- net-metering friendliness proxy
- local rooftop solar permit counts if available
- EV adoption rate as a correlated clean-energy adoption signal
- installer density or state incentive presence

Why they matter:

- these features estimate where solar hardware is likely to exist at residential scale

#### E. Cyber Threat Features

- vendor-level CVE severity priors
- observed Shodan exposures near or within the geography
- observed risky ports or protocols by region
- share of observed devices lacking TLS
- share of observed devices with default credential indicators
- recentness of relevant CVEs

Why they matter:

- these are the threat-intelligence layers that turn solar presence into solar cyber risk

## 6. Labeling Strategy

This is the hardest part of the project, so the labeling approach should be explicit.

### Option A: Weakly Supervised Exposure Labels

Use Shodan observations to create positive or semi-positive labels for geographies with known exposed devices.

Examples:

- `label_exposed = 1` if passive observations exist in or near the geography
- `label_high_risk = 1` if the area contains multiple high-severity vendor observations

Pros:

- simple
- grounded in observable data

Limitations:

- exposure is only a partial proxy for all vulnerable devices
- Shodan visibility is incomplete

### Option B: Continuous Risk Target

Create a continuous target such as:

- expected vulnerable inverter density
- expected observed-risk score per 1,000 homes
- expected vulnerable vendor concentration

Pros:

- better for ranking communities
- aligns well with operational prioritization

### Option C: Two-Stage Model

Recommended approach:

1. Predict probability of solar presence at meaningful residential scale.
2. Predict probability that the solar footprint includes vulnerable or exposed infrastructure.

Then combine them:

`community_risk = P(solar_presence) * P(vulnerable_footprint | solar_presence) * grid_weight`

This is the cleanest framing for judges and stakeholders because it separates adoption likelihood from cyber likelihood.

## 7. Modeling Approach

For a hackathon build, keep the first model practical and interpretable.

### Recommended v1

- gradient boosted trees such as XGBoost or LightGBM
- logistic regression baseline for explainability
- simple percentile ranking fallback if labels are sparse

### Why

- tabular features dominate this problem
- nonlinear interactions matter
- feature importance is useful for storytelling

### Example Targets

- binary: geography likely contains exposed vulnerable solar devices
- regression: estimated vulnerable-device density
- ranking: relative risk percentile by geography

## 8. Scoring Design

Final community score should combine three lenses.

### 8.1 Adoption Likelihood

How likely is this geography to have meaningful residential solar deployment?

Signals:

- owner-occupied single-family housing
- home value
- income
- irradiance
- state solar adoption context

### 8.2 Vulnerability Likelihood

How likely is the local solar footprint to include vendors or products with meaningful known cyber weaknesses?

Signals:

- vendor prevalence priors
- CVE severity counts
- firmware-risk assumptions where known
- recency and exploitability of known issues

### 8.3 Exposure Likelihood

How likely is remote access or public exposure to exist?

Signals:

- nearby observed Shodan evidence
- device types associated with exposed web interfaces
- TLS and default credential indicators in observed peers
- local broadband and remote-management adoption proxies if available

### Example Composite

```text
community_risk_score =
  0.40 * adoption_likelihood
  0.35 * vulnerability_likelihood
  0.25 * exposure_likelihood
```

For a utility-facing output, optionally multiply by a grid relevance factor:

```text
priority_score = community_risk_score * grid_relevance_multiplier
```

## 9. Pipeline Design

The recommended pipeline is below.

### Stage 1: Threat Intelligence Ingestion

Inputs:

- NVD CVEs
- local vendor intelligence
- Shodan query outputs

Outputs:

- normalized vulnerability catalog
- vendor/product risk priors
- observed exposure evidence

### Stage 2: Community Feature Assembly

Inputs:

- property datasets
- census and ACS-like demographic data
- solar irradiance and climate layers
- EIA state solar data

Outputs:

- one tabular row per geography
- engineered predictors for solar adoption and cyber risk

### Stage 3: Label Construction

Inputs:

- passive Shodan observations
- scored device outputs from `04_risk_score.py`

Outputs:

- binary or continuous targets by geography

### Stage 4: Model Training

Outputs:

- trained prediction model
- calibrated probability scores
- feature importance summary

### Stage 5: Operational Aggregation

Outputs:

- ranked ZIP codes
- ranked tracts
- utility-specific priority lists
- state summaries

## 10. Example Feature Schema

```json
{
  "geo_id": "92126",
  "geo_type": "zip_code",
  "state": "CA",
  "median_home_value": 940000,
  "median_year_built": 1988,
  "owner_occupancy_rate": 0.71,
  "single_family_share": 0.63,
  "median_household_income": 128000,
  "housing_density": 4200,
  "solar_irradiance_index": 0.84,
  "climate_zone": "3B",
  "state_solar_gw": 50.0,
  "clean_energy_adoption_proxy": 0.77,
  "vendor_risk_prior": 0.81,
  "nearby_observed_exposure_count": 6,
  "nearby_avg_device_risk": 74.5,
  "nearby_default_creds_rate": 0.17,
  "nearby_no_tls_rate": 0.51,
  "community_risk_score": 82.3,
  "risk_percentile": 96
}
```

## 11. Output Products

The project should generate outputs that are useful in a demo and in operations.

### A. Community Leaderboard

Columns:

- geography
- predicted risk score
- percentile
- estimated vulnerable solar density
- top contributing features

### B. Utility Priority Queue

Columns:

- utility
- high-risk geographies served
- estimated household solar concentration
- likely vendor risk profile
- recommended outreach action

### C. GeoJSON Or CSV Map Layer

Useful for:

- choropleths
- hotspot maps
- service-area overlays

### D. Executive Summary

Should answer:

- where risk is highest
- why those places rank highly
- what action should happen first

## 12. Demo Narrative

The demo should tell a clear story in five steps.

1. Solar adoption is rising, and inverter vulnerabilities are real.
2. Existing cyber data tells us what is vulnerable, not where it is concentrated.
3. SolarShield fuses property, demographic, geographic, and cyber signals.
4. The model ranks communities before direct device discovery.
5. Utilities can focus scarce outreach and remediation on the highest-risk areas first.

Good demo screens:

- ranked map of U.S. communities
- top 10 highest-risk ZIP codes
- feature explanation for one hotspot
- vendor/CVE context panel
- utility-specific action list

## 13. Practical Implementation Roadmap

### Phase 1: Reframe Existing Scripts

- keep current CVE, EIA, Shodan, scoring, and aggregation scripts
- relabel them in docs and outputs as calibration and intelligence layers

### Phase 2: Add Community Data Ingestion

- ingest sample property data
- create a canonical geography table
- join census and climate features

### Phase 3: Engineer Labels

- convert Shodan outputs into geography-level labels
- derive target variables from observed risk intensity

### Phase 4: Train First Model

- start with interpretable baselines
- validate on held-out geographies
- rank, not overclaim

### Phase 5: Build Delivery Layer

- export CSV and GeoJSON
- generate map-ready files
- produce stakeholder-ready summaries

## 14. What Success Looks Like

For the hackathon, success is not proving the exact number of vulnerable inverters in every ZIP code.

Success is demonstrating that:

- community characteristics can predict likely solar cyber risk concentration
- passive cyber intelligence can calibrate that prediction
- the output is operationally actionable
- the approach moves defenders from reactive scanning to proactive prioritization

## 15. Guardrails And Claims

The project should be careful about what it claims.

Safe claims:

- this model estimates where vulnerable solar infrastructure is more likely to be concentrated
- this ranking helps prioritize validation and remediation
- CVE and Shodan data are used as evidence streams, not as a complete census

Claims to avoid:

- this proves a specific home has a vulnerable inverter
- this proves exploitation is occurring in a given neighborhood
- this is a complete inventory of exposed solar devices

## 16. Immediate Next Changes For The Codebase

Recommended next implementation steps:

1. Add a `community_features` build script that transforms property and demographic data into one row per geography.
2. Add a `community_labels` build script that converts scored Shodan observations into geography-level targets.
3. Add a `train_model` script that outputs calibrated community risk scores.
4. Add export scripts for ranked CSV and map-ready GeoJSON.
5. Update naming in code and outputs from device-scanning language to prediction and prioritization language where appropriate.

This is the new operating thesis for SolarShield:

**Don't wait to find every vulnerable inverter. Predict where they are most likely to matter, and help defenders act first.**
