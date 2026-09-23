# ATLAS

### AI-Powered Email Threat Detection & Forensic Intelligence Platform

ATLAS is an email security and digital forensics platform designed to investigate suspicious email messages through **header analysis, SMTP relay reconstruction, authentication verification, IOC extraction, threat intelligence enrichment, infrastructure correlation, and explainable risk analysis**.

The platform preserves the original `.eml` evidence while transforming raw email data into structured forensic findings that can be investigated through a web-based security dashboard.

---

## Overview

Email-based attacks frequently combine social engineering, authentication abuse, suspicious infrastructure, malicious links, and deceptive routing.

ATLAS provides a unified investigation workflow:

```text
                    ┌─────────────────────┐
                    │     .EML Evidence   │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Email Parsing     │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
       Header Forensics   Authentication    IOC Extraction
              │                │                │
              ▼                ▼                ▼
       SMTP Relay Chain   SPF/DKIM/DMARC   IP / URL / Domain
              │                │                │
              └────────────────┼────────────────┘
                               ▼
                    ┌─────────────────────┐
                    │ Threat Intelligence │
                    │     & GeoIP         │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Infrastructure      │
                    │ Correlation & Graph │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Risk & XAI Analysis │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Investigation       │
                    │ Dashboard & Reports │
                    └─────────────────────┘
````

---

## Core Capabilities

### Email Forensics

* `.eml` ingestion and parsing
* SHA-256 evidence integrity
* Header extraction
* Message-ID and timestamp analysis
* From / Reply-To / Return-Path comparison
* MIME and attachment inspection

### SMTP Relay Reconstruction

ATLAS analyzes `Received` headers to reconstruct the observed mail-routing path.

The investigation timeline includes:

* Hop number
* Sending hostname
* Receiving hostname
* IPv4 addresses
* RFC 2822 timestamps
* Transit delays
* Raw `Received` header evidence
* Origin-candidate indication

The platform distinguishes between **observed evidence, inferred relationships, and enriched intelligence** rather than automatically attributing an IP address to an attacker.

### Authentication Forensics

Authentication results are analyzed across:

* SPF
* DKIM
* DMARC
* DMARC policy
* Alignment indicators
* From / Reply-To inconsistencies
* From / Return-Path inconsistencies

### IOC Extraction

ATLAS extracts and structures:

* IP addresses
* URLs
* Domains
* Suspicious TLDs
* Brand impersonation indicators
* Anchor-text mismatches
* Attachment hashes

### Threat Intelligence & GeoIP

Extracted infrastructure indicators can be enriched with:

* Country
* City
* ASN
* Organization
* Reputation
* Intelligence source

The project includes a controlled intelligence dataset for reproducible evaluation and presentation scenarios.

### Infrastructure Graph

ATLAS represents relationships between infrastructure entities:

```text
Email
  │
  ▼
Domain
  │
  ▼
IP Address
  │
  ├──────► ASN
  │          │
  │          ▼
  │      Organization
  │
  └──────► Location
```

NetworkX is used to construct and analyze the infrastructure relationship graph.

### Correlation

Infrastructure indicators can be correlated across investigations to identify relationships such as:

```text
Domain A ──┐
           ├──► Shared Infrastructure IP
Domain B ──┘
```

Correlation findings represent infrastructure relationships and **do not by themselves establish attribution**.

### Explainable Risk Analysis

ATLAS combines forensic findings into a structured risk assessment containing:

* Global risk score
* Network score
* Semantic score
* Dynamic analysis score
* Risk classification
* Investigation findings
* SOAR-style priority tags
* Explainable findings

---

# System Architecture

```text
┌───────────────────────────────────────────────────────────┐
│                    ATLAS Dashboard                       │
│                 React + TypeScript + Vite                │
└───────────────────────────┬───────────────────────────────┘
                            │ REST API
                            ▼
┌───────────────────────────────────────────────────────────┐
│                    FastAPI Backend                        │
├───────────────────────────────────────────────────────────┤
│                                                           │
│  Email Parser                                             │
│       │                                                   │
│       ├── Header Forensics                                │
│       ├── SMTP Relay Reconstruction                       │
│       ├── Authentication Analysis                         │
│       ├── IOC Extraction                                  │
│       ├── Threat Intelligence                             │
│       ├── Infrastructure Graph                            │
│       ├── Correlation                                     │
│       └── Risk / XAI                                      │
│                                                           │
└───────────────────────────┬───────────────────────────────┘
                            │
                            ▼
                 Structured Investigation
                            │
             ┌──────────────┴──────────────┐
             ▼                             ▼
       JSON / Markdown               Dashboard Evidence
             │                             │
             └──────────────┬──────────────┘
                            ▼
                    Investigation Report
```

---

# Investigation Workflow

```text
1. Upload .eml
       ↓
2. Preserve & hash evidence
       ↓
3. Parse email structure
       ↓
4. Analyze headers
       ↓
5. Reconstruct SMTP relay chain
       ↓
6. Verify SPF / DKIM / DMARC
       ↓
7. Extract IOCs
       ↓
8. Enrich infrastructure
       ↓
9. Build infrastructure graph
       ↓
10. Correlate indicators
       ↓
11. Calculate risk
       ↓
12. Explain findings
       ↓
13. Generate investigation reports
```

---

# Technology Stack

## Backend

| Technology             | Purpose              |
| ---------------------- | -------------------- |
| Python                 | Core forensic engine |
| FastAPI                | REST API             |
| NetworkX               | Infrastructure graph |
| email / MIME           | Email parsing        |
| Pydantic / dataclasses | Structured results   |
| Uvicorn                | API server           |
| pytest                 | Testing              |

## Frontend

| Technology | Purpose             |
| ---------- | ------------------- |
| React      | Dashboard UI        |
| TypeScript | Type-safe frontend  |
| Vite       | Development & build |
| CSS        | Interface styling   |

---

# Repository Structure

```text
ATLAS/
│
├── Backend/
│   ├── api.py
│   ├── main.py
│   ├── requirements.txt
│   │
│   ├── examples/
│   │   └── *.eml
│   │
│   ├── data/
│   │   └── scoring_weights.json
│   │
│   └── src/
│       ├── ai_analyzer.py
│       ├── auth_validator.py
│       ├── correlation.py
│       ├── email_parser.py
│       ├── infrastructure_graph.py
│       ├── network_forensics.py
│       ├── reporter.py
│       ├── sandbox_detonator.py
│       ├── static_extractor.py
│       └── threat_intel.py
│
├── Frontend/
│   ├── package.json
│   ├── vite.config.ts
│   │
│   └── src/
│       ├── App.tsx
│       ├── index.css
│       ├── main.tsx
│       └── types/
│           └── forensic.ts
│
├── .gitignore
└── README.md
```

---

# Running ATLAS Locally

## Backend

```bash
cd Backend

py -3.12 -m pip install -r requirements.txt

py -3.12 -m uvicorn api:app --reload
```

Backend:

```text
http://127.0.0.1:8000
```

API health check:

```text
GET /api/health
```

---

## Frontend

Open another terminal:

```bash
cd Frontend

npm install

npm run dev
```

Dashboard:

```text
http://localhost:5173
```

---

# CLI Investigation

ATLAS can also be used directly from the command line.

```bash
cd Backend

py -3.12 main.py \
  -f examples/ATLAS-PHISH-001_password_reset.eml \
  --no-sandbox \
  --lang en
```

The CLI produces structured investigation results and reports without requiring the web dashboard.

---

# API

### Health

```http
GET /api/health
```

### Analyze Email

```http
POST /api/analyze
Content-Type: multipart/form-data
```

Example:

```bash
curl -X POST \
  http://127.0.0.1:8000/api/analyze \
  -F "file=@examples/ATLAS-PHISH-001_password_reset.eml"
```

### Demo Samples

```http
GET /api/demo/samples
```

### Analyze Sample

```http
POST /api/demo/{id}
```

### Reports

```http
GET /api/reports/{filename}
```

---

# Evidence & Reporting

Each investigation can produce structured results containing:

```text
Incident ID
Timestamp
Source SHA-256
Risk Score
Risk Classification
Authentication Results
Relay Chain
Network Findings
Semantic Findings
Dynamic Findings
IOCs
Infrastructure Intelligence
SOAR Tags
```

Reports are available in multiple formats for investigation and presentation workflows.

---

# Security Considerations

ATLAS is designed around a defensive investigation workflow.

Current safeguards include:

* `.eml` file validation
* Upload size restrictions
* Filename sanitization
* Restricted CORS configuration
* No API secrets exposed in the frontend
* Original evidence hashing
* Attachment metadata extraction without automatic execution
* Separation of observed evidence and inferred/enriched data

External sandbox or threat-intelligence services should only be enabled with appropriately configured credentials.

---

# Sample Investigations

The repository contains controlled `.eml` samples covering different investigation scenarios:

```text
ATLAS-PHISH-001_password_reset.eml
ATLAS-BEC-002_payment_change.eml
ATLAS-MAL-003_invoice_attachment.eml
ATLAS-LEGIT-004_security_notice.eml
ATLAS-LEGIT-005_invoice_export.eml
```

These samples are intended for testing and reproducible demonstrations.

---

# Design Principles

### Evidence First

Original email evidence is preserved and hashed before forensic processing.

### Explainable Findings

The platform exposes the evidence contributing to an investigation rather than presenting an unexplained classification.

### Correlation ≠ Attribution

Infrastructure relationships are represented as relationships between observed indicators. A shared IP, domain, ASN, or organization does not independently establish threat-actor attribution.

### Modular Investigation Pipeline

Each forensic stage is separated into reusable backend components, allowing the system to evolve as additional intelligence and analysis capabilities are integrated.

---

# Project Status

ATLAS currently provides:

* [x] EML ingestion
* [x] Email header forensics
* [x] SMTP relay reconstruction
* [x] SPF / DKIM / DMARC analysis
* [x] IOC extraction
* [x] Threat intelligence enrichment
* [x] GeoIP representation
* [x] Infrastructure graph
* [x] Infrastructure correlation
* [x] Risk scoring
* [x] Explainable findings
* [x] FastAPI integration
* [x] React dashboard
* [x] Investigation reports
* [x] Sample EML investigations

---

# Disclaimer

Threat intelligence and geolocation values included in controlled presentation/test scenarios may use synthetic data. Such values are intended for reproducible evaluation and do not represent verified attribution of real-world threat actors or organizations.

---

# License

This project is developed for research, education, cybersecurity experimentation, and defensive email investigation.

````

### And for the GitHub **About** section

Keep it much shorter:

> **AI-powered email threat detection and forensic intelligence platform for phishing, BEC, authentication, SMTP relay, IOC, and infrastructure analysis.**

**Topics:**

```text
cybersecurity
email-security
email-forensics
phishing-detection
threat-intelligence
digital-forensics
fastapi
python
react
typescript
networkx
ai
````
