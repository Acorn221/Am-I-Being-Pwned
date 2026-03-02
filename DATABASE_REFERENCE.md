# CWS Scraper Database Reference

This document describes the PostgreSQL database (`cws_scraper`) used by the Chrome Web Store extension security analysis pipeline. It is intended to give an AI agent full context to query and understand this database.

**Connection**: `psycopg2.connect(dbname='cws_scraper', user='acorn221')` (local, no password)

---

## Table Overview

| Table | Rows | Description |
|-------|------|-------------|
| `extensions` | 26,341 | All discovered Chrome extensions with metadata |
| `analysis_reports` | 1,739 | LLM-generated security analysis reports |
| `static_analysis_results` | 3,281 | Automated static analysis (Babel AST analyzer) |
| `reviews` | 60,286 | User reviews scraped from Chrome Web Store |
| `vt_results` | 629 | VirusTotal scan results |
| `web_accessible_resources` | 59,457 | WAR entries from extension manifests |
| `categories` | 18 | Chrome Web Store categories |
| `top_domains` | 1,000,000 | Top 1M domains (for endpoint validation) |
| `extension_permissions` | 0 | (unused, permissions stored as JSONB in extensions) |
| `analysis_reports_backup` | 1,233 | Backup of old reports (ignore) |

---

## Schema

### `extensions` (primary table)

```sql
id                VARCHAR(32)   PRIMARY KEY  -- Chrome extension ID (e.g. "nkbihfbeogaeaoehlefnkodbefgpgknn")
name              VARCHAR(500)  NOT NULL
slug              VARCHAR(500)
description       TEXT
short_description TEXT
version           VARCHAR(50)
author            VARCHAR(500)
author_url        VARCHAR(1000)
rating            FLOAT                      -- 1.0 - 5.0
rating_count      INT
user_count        INT                        -- install count
category_id       INT           FK -> categories.id
last_updated      TIMESTAMPTZ
size              VARCHAR(50)
icon_url          VARCHAR(1000)
screenshots       JSONB
permissions       JSONB                      -- array of permission strings
discovered_at     TIMESTAMPTZ   DEFAULT now()
scraped_at        TIMESTAMPTZ
reviews_scraped_at TIMESTAMPTZ
embedding         VECTOR                     -- pgvector embedding (unused currently)
processed         BOOLEAN       DEFAULT false -- has been analyzed
triage_verdict    VARCHAR(20)                -- manual triage override
risk_level        VARCHAR(20)                -- CRITICAL, HIGH, MEDIUM, LOW, CLEAN
analyzed_by       VARCHAR
excluded          BOOLEAN       DEFAULT false
tags              TEXT[]        DEFAULT '{}'
website_filtered  BOOLEAN       DEFAULT false -- included in website export
processing_at     TIMESTAMPTZ                -- batch processing lock timestamp
processing_by     TEXT                       -- batch processing lock owner
video             BOOLEAN       DEFAULT false -- has dynamic analysis video
video_url         TEXT
```

**Key indexes**: `idx_ext_risk_level`, `idx_ext_user_count`

#### Risk level distribution
| Risk Level | Extensions | Total Users |
|------------|-----------|-------------|
| CRITICAL | 37 | 30,950,000 |
| HIGH | 106 | 29,191,275 |
| MEDIUM | 334 | 574,390,000 |
| LOW | 453 | 358,525,764 |
| CLEAN | 748 | 1,422,901,963 |
| unrated | 24,663 | — |

**Processed**: 1,678 / 26,341 extensions have been analyzed.

#### Sample row
```json
{
  "id": "ngkjielajlecigijlijjkhkhlhmmcgfh",
  "name": "Troywell VPN Pro - High-speed and safe VPN",
  "user_count": "30000",
  "rating": "3.4",
  "risk_level": "CRITICAL",
  "processed": true,
  "tags": ["malware:extension_killing", "malware:residential_proxy", "malware:cookie_harvesting", "malware:data_exfil"],
  "website_filtered": true,
  "category_id": 42
}
```

---

### `analysis_reports` (LLM security reports)

```sql
id                SERIAL        PRIMARY KEY
extension_id      VARCHAR(32)   NOT NULL FK -> extensions.id
report_type       VARCHAR(50)   NOT NULL     -- 'llm_analysis' (primary), 'VULN_REPORT' (legacy)
content           TEXT          NOT NULL     -- full markdown report
risk_level        VARCHAR(20)               -- CRITICAL, HIGH, MEDIUM, LOW, CLEAN
source_path       TEXT
analyzed_at       TIMESTAMPTZ   DEFAULT now()
structured_report JSONB                     -- parsed report.json content
corrected_at      TIMESTAMPTZ              -- set when manually corrected (survives re-ingest)
updated_at        TIMESTAMPTZ   DEFAULT now()
extension_version VARCHAR(50)   NOT NULL
manifest_version  SMALLINT
summary           TEXT                      -- 1-2 sentence verdict
flag_categories   TEXT[]        DEFAULT '{}' -- e.g. ['data_exfiltration', 'remote_config']
vuln_count_low    SMALLINT      DEFAULT 0
vuln_count_medium SMALLINT      DEFAULT 0
vuln_count_high   SMALLINT      DEFAULT 0
vuln_count_critical SMALLINT    DEFAULT 0
endpoints         TEXT[]        DEFAULT '{}' -- external domains contacted
tags              TEXT[]        DEFAULT '{}'
can_publish       BOOLEAN       DEFAULT true
```

**Unique constraint**: `(extension_id, report_type, extension_version)` — version-tracked reports.
**Corrected reports**: 490 reports have `corrected_at IS NOT NULL` (won't be overwritten by re-ingest unless `--force`).

#### Report types
| Type | Count | Notes |
|------|-------|-------|
| `llm_analysis` | 1,156 | Primary report format (current) |
| `VULN_REPORT` | 535 | Older format |
| `ANALYSIS` | 28 | Legacy |
| Others | ~19 | One-off report types |

#### Top flag categories
| Flag | Count |
|------|-------|
| remote_config | 397 |
| data_exfiltration | 371 |
| postmessage_no_origin | 319 |
| dynamic_function | 288 |
| dynamic_eval | 143 |
| dynamic_tab_url | 140 |
| keylogging | 124 |
| ad_injection | 121 |
| cookie_harvesting | 120 |
| csp_unsafe_inline | 86 |

#### Sample row
```json
{
  "id": 11260,
  "extension_id": "fckonodhlfjlkndmedanenhgdnbopbmh",
  "report_type": "llm_analysis",
  "content": "# Vulnerability Report: WalkMe Extension\n\n## Metadata\n...",
  "risk_level": "MEDIUM",
  "extension_version": "4.0.296",
  "summary": "Enterprise digital adoption platform that collects broad cross-site behavioral telemetry (URL, tab title, keydown/mouse/scroll counts, system ID) transmitted to WalkMe's event collector on all visited websites, and dynamically loads code from CDN without integrity verification.",
  "flag_categories": ["data_exfiltration", "remote_config"],
  "vuln_count_low": 2,
  "vuln_count_medium": 2,
  "endpoints": ["ec.walkme.com", "eu-ec.walkme.com", "papi.walkme.com", "eu-papi.walkme.com", "cdn.walkme.com", "eu-cdn.walkme.com"],
  "can_publish": true,
  "is_corrected": false
}
```

---

### `static_analysis_results` (automated AST analysis)

```sql
id                 SERIAL       PRIMARY KEY
extension_id       VARCHAR(32)  NOT NULL FK -> extensions.id
analyzer_version   VARCHAR(50)  NOT NULL
risk_score         INT          NOT NULL   -- 0-100
critical_count     INT          NOT NULL
high_count         INT          NOT NULL
medium_count       INT          NOT NULL
low_count          INT          NOT NULL
exfil_flows        INT          NOT NULL   -- data flows from sensitive source to network sink
code_exec_flows    INT          NOT NULL   -- flows reaching eval/Function/executeScript
total_flow_paths   INT          NOT NULL
open_message_handlers INT       NOT NULL
has_wasm           BOOLEAN      NOT NULL
has_obfuscation    BOOLEAN      NOT NULL
files_analyzed     INT          NOT NULL
analysis_time_ms   INT          NOT NULL
manifest_version   INT
raw_report         JSONB                   -- full structured output from ext-analyzer
llm_report         TEXT                    -- text-format report for LLM consumption
analyzed_at        TIMESTAMPTZ  DEFAULT now()
```

**Unique constraint**: `(extension_id, analyzer_version)`

#### Sample row
```json
{
  "id": 850,
  "extension_id": "dldjpboieedgcmpkchcjcbijingjcgok",
  "analyzer_version": "1.0.0",
  "risk_score": 85,
  "high_count": 6,
  "exfil_flows": 4,
  "code_exec_flows": 0,
  "total_flow_paths": 4,
  "open_message_handlers": 2,
  "has_wasm": true,
  "has_obfuscation": true,
  "files_analyzed": 15,
  "analysis_time_ms": 86300
}
```

---

### `reviews` (user reviews from CWS)

```sql
id                SERIAL       PRIMARY KEY
extension_id      VARCHAR(32)  NOT NULL FK -> extensions.id
author_name       VARCHAR(500)
author_id         VARCHAR(500)
author_avatar_url VARCHAR(1000)
rating            INT          NOT NULL   -- 1-5
text              TEXT
created_at        TIMESTAMPTZ
helpful_count     INT
scraped_at        TIMESTAMPTZ  DEFAULT now()
embedding         VECTOR                  -- pgvector embedding
```

#### Sample row
```json
{
  "id": 477,
  "extension_id": "aicmkgpgakddgnaphhhpliifpcfhicfo",
  "author_name": "Mathavan",
  "rating": 1,
  "text": "extension is useless now :(",
  "created_at": "2024-07-19T16:37:41+00:00"
}
```

---

### `vt_results` (VirusTotal scans)

```sql
id               SERIAL       PRIMARY KEY
extension_id     VARCHAR(32)  NOT NULL FK -> extensions.id
sha256           VARCHAR(64)  NOT NULL
malicious        INT          DEFAULT 0   -- engines flagging as malicious
suspicious       INT          DEFAULT 0
undetected       INT          DEFAULT 0
harmless         INT          DEFAULT 0
timeout          INT          DEFAULT 0
total_engines    INT          DEFAULT 0
detection_ratio  REAL         DEFAULT 0.0 -- malicious / total_engines
vt_first_seen    TIMESTAMPTZ
vt_last_analysis TIMESTAMPTZ
community_score  INT
status           VARCHAR(20)  DEFAULT 'unknown'  -- 'found', 'not_found', 'unknown'
raw_response     JSONB
scanned_at       TIMESTAMPTZ  DEFAULT now()
uploaded_at      TIMESTAMPTZ
```

**Unique constraint**: `(extension_id, sha256)`
**Stats**: 10 / 629 scanned extensions flagged as malicious by at least 1 engine.

#### Sample row
```json
{
  "id": 187,
  "extension_id": "afdfpkhbdpioonfeknablodaejkklbdn",
  "sha256": "c1f263bd88facd43ca461221849e275b101d994e6bb46531f65c84240cbfac2b",
  "malicious": 24,
  "total_engines": 61,
  "detection_ratio": 0.393,
  "status": "found"
}
```

---

### `web_accessible_resources`

```sql
id              SERIAL       PRIMARY KEY
extension_id    VARCHAR(32)  NOT NULL FK -> extensions.id
resource_path   VARCHAR(1000) NOT NULL
```

**Unique constraint**: `(extension_id, resource_path)`

---

### `categories`

```sql
id            SERIAL       PRIMARY KEY
slug          VARCHAR(100) NOT NULL UNIQUE
name          VARCHAR(200) NOT NULL
url           VARCHAR(500) NOT NULL
created_at    TIMESTAMPTZ  DEFAULT now()
discovered_at TIMESTAMPTZ
```

All 18 categories:
| ID | Slug | Name |
|----|------|------|
| 25 | productivity/communication | Communication |
| 26 | productivity/developer | Developer Tools |
| 27 | productivity/education | Education |
| 28 | productivity/tools | Tools |
| 29 | productivity/workflow | Workflow & Planning |
| 30 | lifestyle/art | Art & Design |
| 31 | lifestyle/entertainment | Entertainment |
| 32 | lifestyle/games | Games |
| 33 | lifestyle/household | Household |
| 34 | lifestyle/fun | Fun |
| 35 | lifestyle/news | News & Weather |
| 36 | lifestyle/shopping | Shopping |
| 37 | lifestyle/social | Social & Communication |
| 38 | lifestyle/travel | Travel |
| 39 | lifestyle/well_being | Well-being |
| 40 | make_chrome_yours/accessibility | Accessibility |
| 41 | make_chrome_yours/functionality | Functionality |
| 42 | make_chrome_yours/privacy | Privacy & Security |

---

### `top_domains`

```sql
rank             SERIAL       PRIMARY KEY
domain           VARCHAR(500) NOT NULL UNIQUE
meta_title       TEXT
meta_description TEXT
embedding        VECTOR
scraped_at       TIMESTAMPTZ
```

1M rows. Used to validate whether endpoints found in extensions are real domains vs JS code artifacts.

---

## Common Queries

```sql
-- Find all CRITICAL/HIGH extensions with reports
SELECT e.id, e.name, e.user_count, ar.risk_level, ar.summary, ar.endpoints
FROM extensions e
JOIN analysis_reports ar ON ar.extension_id = e.id AND ar.report_type = 'llm_analysis'
WHERE ar.risk_level IN ('CRITICAL', 'HIGH')
ORDER BY e.user_count DESC;

-- Extensions with exfiltration flows in static analysis
SELECT e.name, e.user_count, s.risk_score, s.exfil_flows, s.code_exec_flows
FROM static_analysis_results s
JOIN extensions e ON e.id = s.extension_id
WHERE s.exfil_flows > 0
ORDER BY s.risk_score DESC;

-- Cross-reference: static analysis vs LLM risk
SELECT e.id, e.name, s.risk_score, ar.risk_level
FROM extensions e
JOIN static_analysis_results s ON s.extension_id = e.id
JOIN analysis_reports ar ON ar.extension_id = e.id AND ar.report_type = 'llm_analysis'
ORDER BY s.risk_score DESC;

-- Extensions flagged by VirusTotal
SELECT e.name, e.user_count, v.malicious, v.total_engines, v.detection_ratio
FROM vt_results v
JOIN extensions e ON e.id = v.extension_id
WHERE v.malicious > 0
ORDER BY v.malicious DESC;

-- Find extensions by flag category
SELECT e.name, e.user_count, ar.risk_level, ar.flag_categories
FROM analysis_reports ar
JOIN extensions e ON e.id = ar.extension_id
WHERE 'cookie_harvesting' = ANY(ar.flag_categories)
ORDER BY e.user_count DESC;
```

---

## Key Relationships

```
extensions (1) ──< analysis_reports (many, per version+type)
extensions (1) ──< static_analysis_results (many, per analyzer version)
extensions (1) ──< reviews (many)
extensions (1) ──< vt_results (many, per sha256)
extensions (1) ──< web_accessible_resources (many)
extensions (many) >── categories (1)
```
