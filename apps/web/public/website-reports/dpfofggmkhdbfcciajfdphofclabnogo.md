# Vulnerability Report: Block Site - Site Blocker & Focus Mode

## Metadata
- **Extension ID**: dpfofggmkhdbfcciajfdphofclabnogo
- **Extension Name**: Block Site - Site Blocker & Focus Mode
- **Version**: 1.0.7
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Block Site is a legitimate productivity extension that allows users to block specific websites and words, and provides a focus mode feature with configurable work/break cycles. The extension uses standard Chrome APIs appropriately and does not exhibit any malicious behavior. All code is transparent, well-structured React/TypeScript code compiled via Vite, with no obfuscation beyond normal bundling. The static analyzer flagged one potential exfiltration flow (`document.querySelectorAll → fetch`) which is a false positive related to module preloading in the Vite build system, not actual data exfiltration.

The extension operates entirely locally using Chrome's storage API, implements its advertised functionality (site blocking, focus timers, password protection), and makes no network requests beyond legitimate modulepreload optimizations in the bundled code.

## Vulnerability Details

No security or privacy vulnerabilities were identified in this extension.

## False Positives Analysis

### 1. Module Preload Flow (querySelectorAll → fetch)
**Flagged by ext-analyzer**: The static analyzer detected a flow from `document.querySelectorAll` to `fetch` in RateUsModalProvider.js.

**Analysis**: This is standard Vite module preloading code that runs on page load to optimize JavaScript module loading:
```javascript
for (const o of document.querySelectorAll('link[rel="modulepreload"]')) r(o);
// ...
function r(o) {
  if (o.ep) return;
  o.ep = !0;
  const i = n(o);
  fetch(o.href, i)  // Prefetches module scripts
}
```

**Verdict**: False positive. This code reads `<link rel="modulepreload">` elements from the page and prefetches the referenced JavaScript modules to improve load performance. It only operates on the extension's own HTML pages and fetches the extension's own bundled modules (e.g., getRoutePath.js, RateUsModalProvider.js). No user data or sensitive information is involved.

### 2. Webpack/Vite Bundling
The extension uses modern build tooling (Vite) which bundles React, React-DOM, Lodash, and Ant Design UI components. The resulting code has minified variable names but is not obfuscated maliciously.

**Verdict**: Standard modern JavaScript development practice. All third-party libraries are legitimate and properly licensed (React: MIT, Lodash: MIT, Ant Design: MIT).

## Core Functionality Analysis

### Background Service Worker
The background script (`background.js`) implements the core blocking logic:
- Monitors changes to stored configuration (blocked sites, blocked words, focus mode settings)
- Redirects tabs to the extension's blocked page when URLs match block rules
- Manages focus mode timers using Chrome's alarms API
- No network communication or external data transmission

### Content Script
The content script (`content.js`) is a bundled React application that runs on `<all_urls>`. However, it appears to be primarily used for rendering the extension's UI in embedded contexts and does not perform any invasive operations on web pages.

### Storage
All data is stored locally using `chrome.storage.local`:
- Blocked sites list
- Blocked keywords
- Focus mode configuration (minutes, cycles, break settings)
- Password for protected settings
- UI state (current cycle, views amount)

No data is synchronized to external servers.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| None | N/A | N/A | N/A |

The extension makes no network requests to external endpoints. The only `fetch` calls are for loading the extension's own bundled modules via Vite's modulepreload optimization.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:
This extension implements exactly what it advertises - a site blocking and focus mode tool. It uses appropriate Chrome APIs (storage, tabs, alarms) for its functionality, operates entirely locally without external communication, and contains no malicious code patterns. The static analyzer's exfiltration flag was a false positive related to module preloading. The extension's permissions are minimal and appropriate for its functionality. The codebase is clean, well-structured, and poses no security or privacy risks to users.

**Recommended Actions**: None. This is a legitimate productivity tool.
