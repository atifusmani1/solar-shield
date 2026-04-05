# SolarShield

**Hackers only need to control 2% of Europe's inverters to trigger a blackout — and the default password is "123456".**

SolarShield predicts which U.S. communities are most likely to contain vulnerable residential solar inverter infrastructure — before a single device is scanned.

Instead of asking only "which internet-exposed inverters can we find right now?", this project asks a more operationally useful question:

**Given what we know about a neighborhood's properties, demographics, and geography, how likely is it that vulnerable solar inverters are present and concentrated on the grid?**

That shift matters for utilities, emergency managers, and grid operators. CVE reports tell us which vendors are vulnerable. Shodan tells us some of what is already exposed. Neither tells us *where* vulnerable solar infrastructure is most concentrated. SolarShield fills that gap.

---

## The Problem

Solar inverters are the bridge between rooftop panels and the power grid. Over 270GW of installed solar capacity in Europe alone, and the U.S. is accelerating fast. These devices are increasingly internet-connected — and routinely deployed with security as an afterthought:

- The world's third-largest inverter manufacturer shipped devices with a default password of **"123456"**
- Forescout's SUN:DOWN research uncovered **46 new vulnerabilities** across the top 3 manufacturers (Sungrow, Growatt, SMA)
- **35,000 solar devices** from 42 vendors were found publicly exposed on the internet
- **80% of known solar CVEs** are rated high or critical severity (CVSS 9.8–10)
- 800 SolarView Compact devices in Japan were **hijacked and used for bank theft** — and exposures of that same device grew 350% in the two years after the incident

Academic research shows that controlling just **4.5GW** of solar capacity — less than **2% of European inverters** — is enough to crash grid frequency below 49Hz and trigger cascading blackouts.

This is not theoretical. The tools to find these devices are free. The vulnerabilities are documented. The default credentials are public.

---

## Our Approach

We built a similar tool before — for cargo ships. In 5 hours we found our first vulnerability on a Nigerian oil tanker. Within 18 hours we found 10 more vessels representing ~$1.5B in assets at risk. We notified the owners; they patched within days.

SolarShield applies the same methodology to the power grid, with a predictive layer that cargo ship scanning didn't need:

1. **Discover** — pull CVE and Shodan intelligence to understand which vendors are vulnerable and where devices are exposed
2. **Model** — combine property, demographic, and geographic features to predict community-level solar adoption and inverter density
3. **Score** — rank ZIP codes by the intersection of solar infrastructure concentration and known cyber risk
4. **Prioritize** — surface the highest-risk communities for utilities and public-sector partners before attackers get there

---

## Pipeline Overview

### Stage 1 — Cyber threat intelligence (`scripts/00–05`)

| Script | What it does |
|--------|-------------|
| `00_sync_vulnerability_data.py` | Syncs NVD CVEs + CISA KEV to local SQLite (`data/vuln.sqlite`) |
| `01_fetch_nvd_cves.py` | Fetches solar-related CVEs from NIST NVD |
| `02_fetch_eia_grid_data.py` | Pulls U.S. solar capacity context from EIA |
| `03_shodan_search.py` | Collects passive exposure signals from Shodan |
| `04_risk_score.py` | Scores each device 0–100 on CVEs, default creds, TLS, protocol, firmware, geo |
| `05_fleet_aggregator.py` | Rolls device findings up to region and vendor summaries |

### Stage 2 — Community risk modeling (`scripts/10–12`)

| Script | What it does |
|--------|-------------|
| `10_process_property_data.py` | Aggregates Melissa parcel data into community features by ZIP, census tract, FIPS |
| `11_build_model_inputs.py` | Joins community features with CVE priors; computes `community_risk_prior_score` |
| `12_fetch_census_community_features.py` | Fetches nationwide community features from Census ACS (no key required) |

Script 12 is the primary path to nationwide coverage. It queries the U.S. Census ACS 5-year estimates for ~15,000 ZCTAs across the top 20 solar states and produces a feature table compatible with script 11.

---

## Quick Start

```bash
git clone https://github.com/atifusmani1/grid-watch.git
cd grid-watch
pip install -r requirements.txt
cp .env.example .env   # Add your API keys
```

### Run the cyber intel pipeline

```bash
python scripts/00_sync_vulnerability_data.py
python scripts/02_fetch_eia_grid_data.py
python scripts/03_shodan_search.py --all-queries --limit 100   # requires Shodan key
python scripts/04_risk_score.py
python scripts/05_fleet_aggregator.py
```

### Fetch nationwide community features

```bash
# Top 20 solar states (~20 API calls, ~30s, no key needed)
python scripts/12_fetch_census_community_features.py

# All 50 states
python scripts/12_fetch_census_community_features.py --all-states

# Specific states
python scripts/12_fetch_census_community_features.py --states CA TX FL AZ
```

### Build model inputs and risk scores

```bash
python scripts/11_build_model_inputs.py
# Outputs: data/processed/community_model_inputs_census_nationwide.csv
```

---

## Scoring

**Community risk prior score** = 0.55 × solar readiness + 0.45 × cyber pressure

- **Solar readiness** — weighted combination of single-family share, residential share, solar candidate share (owner-occupied SF homes), high-value home share, and garage share
- **Cyber pressure** — derived from the CVE corpus: max CVSS, critical CVE rate, CISA KEV rate, average CVSS across solar vendors

The top-ranked communities are those most likely to have owner-occupied single-family homes with rooftop solar, combined with the highest cyber pressure from known inverter vulnerabilities.

---

## Repository Structure

```
grid-watch/
├── data/
│   ├── cve_database.json          # Solar CVE reference catalog
│   ├── grid_capacity.json         # EIA regional capacity fallback
│   └── vuln.sqlite                # Local CVE/KEV database (gitignored)
├── output/                        # Script outputs (gitignored)
├── queries/
│   └── shodan_web_queries.txt     # Shodan query strings by vendor
├── scripts/
│   ├── 00_sync_vulnerability_data.py
│   ├── 01_fetch_nvd_cves.py
│   ├── 02_fetch_eia_grid_data.py
│   ├── 03_shodan_search.py
│   ├── 04_risk_score.py
│   ├── 05_fleet_aggregator.py
│   ├── 10_process_property_data.py
│   ├── 11_build_model_inputs.py
│   └── 12_fetch_census_community_features.py
├── .env.example
├── IMPLEMENTATION.md
├── requirements.txt
└── README.md
```

---

## Data Sources

| Source | What It Provides | Access |
|--------|-----------------|--------|
| NIST NVD | CVE entries with CVSS scores | Public API |
| CISA KEV | Actively exploited vulnerability catalog | Public |
| Shodan | Internet-exposed device banners, ports, geolocation | API (free/paid) |
| EIA | U.S. state-level installed solar capacity | Public |
| U.S. Census ACS | Community-level housing, income, demographics | Public API |
| Melissa Data | Parcel-level property assessment and AVM data | Licensed |

---

## Ethics & Legal

SolarShield is a **passive reconnaissance and predictive modeling tool**. It does not interact with any device directly.

**What we do:**
- Query publicly indexed databases (Shodan, Censys) that have already crawled these devices
- Analyze banners, headers, and metadata from those indexes
- Cross-reference findings against public CVE databases
- Model community-level risk from public property and demographic data
- Follow responsible disclosure practices for any specific findings

**What we never do:**
- Attempt to log in to any device
- Send commands, packets, or requests to any inverter
- Exploit any vulnerability
- Perform active network scanning without authorization
- Access any non-public data
- Claim a specific home is compromised without direct validation

---

## Key References

- [Forescout SUN:DOWN (2025)](https://www.forescout.com/blog/grid-security-new-vulnerabilities-in-solar-power-systems-exposed/) — 46 vulnerabilities in Sungrow, Growatt, SMA
- [Forescout Internet-Exposed Solar Devices (2025)](https://www.forescout.com/blog/the-security-risks-of-internet-exposed-solar-power-systems/) — 35,000 exposed devices from 42 vendors
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [NIST National Vulnerability Database](https://nvd.nist.gov/)
- [NIST Smart Inverter Cybersecurity Guidelines](https://www.nist.gov/)

---

## Technical Plan

Full architecture and implementation details: [IMPLEMENTATION.md](./IMPLEMENTATION.md)
