# Vulnerability Report: Bibcitation Bibliography & Citation Generator

## Metadata
- **Extension ID**: cnjkoanefhlhkagbpofjbafaonfejpgc
- **Extension Name**: Bibcitation Bibliography & Citation Generator
- **Version**: 0.0.0.15
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Bibcitation is a legitimate citation and bibliography generator extension that helps users create citations for websites, journal articles, and other sources in MLA, APA, Chicago, and other formats. The extension collects webpage content (HTML, URLs, metadata) from pages users are viewing to generate citations, then sends this data to the bibcitation.com backend API for processing. This data collection is fully disclosed and directly aligned with the extension's stated purpose as a citation generator.

The static analyzer flagged one exfiltration flow (document.getElementById → fetch), but this is a false positive in context. The extension's Next.js-based popup UI reads page content and sends it to the scraper API endpoint for citation generation. All network endpoints are owned by the same bibcitation.com service, and the functionality is transparent to users. No credentials, browsing history, or data beyond what users explicitly cite is collected.

## Vulnerability Details

### No Vulnerabilities Identified

After thorough analysis of the deobfuscated code, manifest permissions, and static analysis results, no security or privacy vulnerabilities were found.

## False Positives Analysis

### 1. Static Analyzer "Exfiltration" Finding

The ext-analyzer tool reported:
```
EXFILTRATION (1 flow):
  [HIGH] document.getElementById → fetch(n)    underscorenext/static/chunks/main-8e5faabb7218f51b.js
```

**Analysis**: This is a false positive. The flagged code is part of the Next.js framework's standard DOM manipulation and routing logic (Next.js prefetching routes). The actual data flow for citation generation is:

1. User opens popup on a webpage they want to cite
2. Chrome extension reads the current tab's URL via chrome.tabs API
3. The popup UI (chrome-7cdfd3db7b89daec.js) fetches the page content
4. Content is sent to `scraper.bibcitation.com` API endpoints for citation parsing
5. Parsed citation data is returned and displayed to the user

This is **disclosed functionality** — users install the extension specifically to generate citations from web pages, which inherently requires reading and processing page content.

### 2. Webpack Bundling

The code includes Next.js/React webpack-bundled code, which appears minified but is **not obfuscated malware**. The `.bak` files show the original minified webpack output, and the deobfuscated versions show standard React/Next.js patterns.

### 3. Multiple API Endpoints

The extension communicates with three bibcitation.com subdomains:
- `api.bibcitation.com` - Main API for citation management
- `scraper.bibcitation.com` - Web scraping/parsing service
- `www.bibcitation.com` - Main website

And one Google API:
- `books/v1/volumes` - Google Books API for ISBN/book citation lookups

All of these are legitimate, documented services that align with citation generation functionality.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://api.bibcitation.com | Citation list management, styles API | User citations, formatting preferences | None - disclosed functionality |
| https://scraper.bibcitation.com | Web page content parsing for citation generation | Page HTML, URL, content type | None - core feature, disclosed |
| https://www.bibcitation.com | Main website resources | Standard web requests | None |
| https://www.googleapis.com/books/v1/volumes | Google Books API for book citations | Book search queries, ISBNs | None - public API |

## Code Analysis

### Background Script (background.js)
- **Lines 2-10**: Cleans up chrome.storage.local entries when tabs are reloaded (removes cached data)
- **Lines 12-17**: Cleans up storage when tabs are closed
- **Purpose**: Simple housekeeping to prevent storage bloat
- **Risk**: None

### Popup UI (chrome-7cdfd3db7b89daec.js)
- **Lines 811-831**: Main scraping logic
  - Reads current tab's URL and content
  - Sends HTML or PDF content to scraper API
  - Uses progress callbacks to show upload status
  - Handles both HTML (`m.$x`) and PDF (`m.fz`) content types
- **Lines 838-851**: Caches citation data in chrome.storage.local by tab ID
- **Purpose**: Generate citation metadata from current page
- **Risk**: None - disclosed feature

### API Helpers (_app-9cac96c36b4b1f52.js)
- **Lines 13366, 13374, 13382**: API URL builders for bibcitation.com domains
- **Lines 15464-15490**: API request functions:
  - `d` (`$x`): Sends HTML content for parsing
  - `m` (`fz`): Sends PDF content for parsing
  - `p` (`eR`): Progress tracking via Server-Sent Events (SSE)
  - `l`, `c`: Journal/article search by DOI
  - `u`: Google Books API integration
- **Purpose**: Client library for bibcitation backend
- **Risk**: None

### Permissions Analysis
- **tabs**: Read current tab URL for citation generation ✓
- **storage**: Cache citation data per tab ✓
- **webNavigation**: Detect tab reloads to clear stale cache ✓
- **scripting**: Not actively used in code (likely future feature)
- **activeTab**: Access current tab content for citation ✓

All permissions are justified and minimal for the stated functionality.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:

Bibcitation is a well-implemented, legitimate citation generator extension. The data collection (webpage URLs, content, and metadata) is:

1. **Disclosed**: The extension description explicitly states it helps "cite websites and journal articles"
2. **Minimal**: Only collects data from pages users explicitly interact with via the popup
3. **Purposeful**: All data is used solely for generating citations
4. **Transparent**: Open communication with known bibcitation.com endpoints
5. **Standard**: Uses common patterns for browser extensions and web apps

The static analyzer findings are false positives stemming from legitimate Next.js framework code. The webpack bundling is standard modern JavaScript build tooling, not malicious obfuscation. The extension does not:

- Collect data in the background without user action
- Access sensitive credentials or cookies
- Inject ads or affiliate links
- Track browsing history beyond citation generation
- Communicate with unknown third-party domains

**Recommendation**: This extension is safe for users who need citation generation tools. No security concerns identified.
