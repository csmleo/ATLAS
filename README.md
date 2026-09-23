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
