# SolarShield — Solar Inverter Fleet Scanner

**Hackers only need to control 2% of Europe's inverters to trigger a blackout — and the default password is '123456'.**

SolarShield is an open-source intelligence tool that scans publicly indexed internet data to identify vulnerable solar inverters, scores their risk, and helps notify owners before attackers exploit them. No devices are touched. No systems are accessed. Everything runs on data that's already public.

---

## Motivation

### The Problem

Solar inverters are the bridge between rooftop panels and the power grid. They're everywhere — over 270GW of installed solar capacity in Europe alone — and they're increasingly connected to the internet for remote monitoring.

But many of these devices were deployed with security as an afterthought:

- The world's third-largest inverter manufacturer shipped devices with a default password of **"123456"**
- Forescout's SUN:DOWN research uncovered **46 new vulnerabilities** across the top 3 manufacturers (Sungrow, Growatt, SMA)
- **35,000 solar devices** from 42 vendors were found publicly exposed on the internet
- **80% of known solar CVEs** are rated high or critical severity (CVSS 9.8–10)
- 800 SolarView Compact devices in Japan were **hijacked and used for bank theft** — and exposures of that same device grew 350% in the two years that followed

Academic research has shown that controlling just **4.5GW** of solar capacity — less than **2% of European inverters** — would be enough to crash grid frequency below 49Hz, triggering load shedding and potentially cascading blackouts.

This is not theoretical. The tools to find these devices are free. The vulnerabilities are documented. The default credentials are public. The only missing piece is someone scanning at scale and telling owners to fix it.

### Our Approach

We built this before — for cargo ships. In 5 hours we found our first vulnerability on a Nigerian oil tanker. Within 18 hours we found 10 more ships representing ~$1.5B in assets at risk. We notified the owners, and they patched within days.

SolarShield applies the same methodology to the power grid:

1. **Discover** exposed solar inverters using publicly indexed data (Shodan, Censys)
2. **Identify** vulnerabilities by cross-referencing device fingerprints against the CVE database
3. **Score** risk based on severity, exposure, and grid impact potential
4. **Notify** device owners with specific remediation steps
5. **Visualize** the aggregate threat to regional power grids

---

## Features

- **Device Discovery** — Queries Shodan/Censys for exposed solar inverter management interfaces across all major vendors
- **CVE Matching Engine** — Automatically maps discovered devices to known vulnerabilities from the NIST National Vulnerability Database
- **Risk Scoring** — Assigns each device a 0–100 risk score based on CVE severity, default credentials, encryption status, protocol exposure, and firmware age
- **Blackout Calculator** — Aggregates exposed capacity by region and calculates what percentage of the local grid is at risk, benchmarked against the 2% destabilization threshold
- **Vendor Intelligence** — Tracks firmware versions in the wild and flags devices running pre-patch versions
- **Notification Pipeline** — Generates per-device vulnerability reports and identifies owner contacts via WHOIS/ISP abuse databases
- **AI Remediation** — Produces device-specific remediation plans with exact configuration steps
- **Live Dashboard** — Interactive map and stats panel showing global exposure in real time

---

## Quick Start

### Prerequisites

```bash
Python 3.10+
Node.js 18+ (for dashboard)
Shodan API key (free tier works, academic tier recommended)
```

### Installation

```bash
git clone https://github.com/your-org/solarshield.git
cd solarshield

# Backend
cd backend
pip install -r requirements.txt
cp .env.example .env   # Add your Shodan API key here

# Frontend
cd ../dashboard
npm install
```

### Run a Scan

```bash
# Discover exposed solar inverters
python scanner/discover.py --vendor growatt --output results/growatt_scan.json

# Enrich with CVE data
python scanner/enrich.py --input results/growatt_scan.json --output results/growatt_enriched.json

# Score risk
python scanner/score.py --input results/growatt_enriched.json --output results/growatt_scored.json

# Generate reports
python scanner/report.py --input results/growatt_scored.json --output reports/
```

### Launch Dashboard

```bash
cd dashboard
npm run dev
# Open http://localhost:3000
```

---

## Project Structure

```
solarshield/
├── scanner/
│   ├── discover.py          # Shodan/Censys device discovery
│   ├── enrich.py            # CVE and metadata enrichment
│   ├── score.py             # Risk scoring engine
│   ├── report.py            # Vulnerability report generator
│   └── notify.py            # Owner notification pipeline
├── data/
│   ├── cve_database.json    # Solar-specific CVE catalog
│   ├── vendor_firmware.json # Known firmware versions + patch status
│   └── grid_capacity.json   # Regional solar capacity data (EIA, IRENA)
├── dashboard/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Map.jsx              # Global exposure heatmap
│   │   │   ├── BlackoutCalculator.jsx  # Grid impact simulator
│   │   │   ├── RiskTable.jsx        # Device-level risk breakdown
│   │   │   └── VendorChart.jsx      # Firmware distribution charts
│   │   └── App.jsx
│   └── package.json
├── ai/
│   └── remediation.py       # AI-powered fix generation
├── tests/
├── .env.example
├── requirements.txt
└── README.md
```

---

## Data Sources

| Source | What It Provides | Access |
|--------|-----------------|--------|
| Shodan | Internet-exposed device banners, ports, geolocation | API (free/paid) |
| Censys | Alternative device discovery and certificate data | API (free/paid) |
| NIST NVD | CVE entries with CVSS scores | Public API |
| CISA KEV | Actively exploited vulnerability catalog | Public |
| EIA | U.S. state-level installed solar capacity | Public |
| IRENA | Global renewable energy statistics | Public |
| SolarPower Europe | European solar capacity data | Public reports |

---

## Ethics & Legal

SolarShield is a **passive reconnaissance tool**. It does not interact with any device directly.

**What we do:**
- Query publicly indexed databases (Shodan, Censys) that have already crawled these devices
- Analyze banners, headers, and metadata from those indexes
- Cross-reference findings against public CVE databases
- Generate remediation guidance for device owners
- Follow responsible disclosure practices

**What we never do:**
- Attempt to log in to any device
- Send commands, packets, or requests to any inverter
- Exploit any vulnerability
- Perform active network scanning without authorization
- Access any non-public data

All findings are reported through proper channels: ISP abuse contacts, national CERTs, and vendor security teams.

---

## Key References

- [Forescout SUN:DOWN Research (2025)](https://www.forescout.com/blog/grid-security-new-vulnerabilities-in-solar-power-systems-exposed/) — 46 vulnerabilities in Sungrow, Growatt, SMA
- [Forescout Internet-Exposed Solar Devices (2025)](https://www.forescout.com/blog/the-security-risks-of-internet-exposed-solar-power-systems/) — 35,000 exposed devices from 42 vendors
- [NIST Smart Inverter Cybersecurity Guidelines](https://www.nist.gov/) — Federal recommendations for inverter security
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [NIST National Vulnerability Database](https://nvd.nist.gov/)

---

## Contributing

We welcome contributions. See [IMPLEMENTATION.md](./IMPLEMENTATION.md) for the full technical plan and architecture details.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'Add your feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

---

## License

MIT

---

## Team

Built by the same team that found vulnerabilities on 11 cargo ships worth ~$1.5B in 18 hours. Now we're scanning the power grid.
