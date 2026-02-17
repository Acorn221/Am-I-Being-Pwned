# Vulnerability Report: minerBlock

## Metadata
- **Extension ID**: emikbbbebcdfohonlaifafnoanocnebl
- **Extension Name**: minerBlock
- **Version**: 1.2.18
- **Users**: ~80,000
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

minerBlock is a legitimate browser extension designed to protect users from cryptocurrency mining scripts (cryptojacking). The extension employs two blocking mechanisms: (1) URL-based blocking using a comprehensive blacklist of 748+ mining domains and script patterns, and (2) runtime detection that scans the page context for known mining script APIs (CoinHive, Mineralt, Webminerpool) and terminates them. The extension is open-source and has been recommended by multiple national CERTs worldwide. Analysis reveals no security or privacy concerns.

The extension's permissions (<all_urls>, webRequest, webRequestBlocking) are appropriate for its stated purpose of blocking mining scripts across all websites. No data collection, exfiltration, or malicious behavior was identified.

## Vulnerability Details

No vulnerabilities identified.

## False Positives Analysis

**webRequest API with <all_urls>**: The extension uses `chrome.webRequest.onBeforeRequest` with blocking mode to intercept network requests matching mining script patterns. This is the standard mechanism for content blocking extensions and is essential for the extension's stated purpose. The filter list (assets/filters.txt) contains 748 entries specifically targeting cryptocurrency mining domains and script paths.

**Content Script Injection**: The extension injects `minerkill.js` via content script on all pages. This script scans the global window object for properties matching known mining script APIs (checking for specific method signatures like `isRunning()`, `stop()`, `_siteKey`, etc.). When detected, it calls `stop()` on the miner object and nullifies it. This is legitimate defensive behavior, not malicious code execution.

**Code Execution via Script Injection**: The content script dynamically injects `minerkill.js` into the page context using `document.createElement('script')`. This is necessary because content scripts run in an isolated context and cannot directly access page-level JavaScript objects where mining scripts reside. The injected script is a static file bundled with the extension, not remotely loaded code.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| chrome.runtime.getURL('assets/filters.txt') | Load mining domain blacklist | None (local file) | None |

No external API endpoints contacted. All operations are local.

## Technical Analysis

### Architecture
- **Background script**: Manages webRequest blocking, maintains per-tab miner block counters, handles whitelist management
- **Content script**: Injects mining detection script into page context and relays detection events back to background
- **Injected script (minerkill.js)**: Scans window object for mining API signatures and terminates detected miners

### Blocking Mechanisms
1. **URL Blacklist**: 748 filter rules in `assets/filters.txt` targeting wildcard patterns (e.g., `*://*/*coinhive.min.js*`) and specific domains (e.g., `*.coin-hive.com/*`)
2. **Runtime Detection**: Pattern matching against known mining library APIs:
   - CoinHive: checks for `isRunning()`, `stop()`, `_siteKey`/`_sitek`/`_newSiteKey`/`_address` properties
   - Mineralt: checks for `db()`, `getlf()`, `stop()`, `hps()` methods
   - Webminerpool: checks for `addWorker()`, `startMining()`, `stopMining()`, `totalhashes` property

### User Controls
- Toggle extension on/off
- Per-domain whitelist (allows users to exempt sites from blocking)
- Counter badge showing number of blocked miner domains per tab
- User-defined custom filter rules

### Data Handling
All settings stored locally via `chrome.storage.local`:
- `mbSettings`: user preferences (run status, show counter, whitelist, custom filters)
- No data transmitted to external servers
- No analytics or tracking

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**: minerBlock is a legitimate, well-designed security extension that performs exactly as advertised. The code is clean, with no obfuscation, data exfiltration, or malicious behavior. The broad permissions are necessary and appropriately scoped for blocking cryptocurrency mining scripts across all websites. The extension is open-source (https://github.com/xd4rker/MinerBlock) and has been endorsed by multiple national Computer Emergency Response Teams (CERTs). No security or privacy concerns identified.
