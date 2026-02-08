# Vulnerability Report: Blocknative Gas Fee Estimator

## Extension Metadata
- **Name:** Blocknative Gas Fee Estimator for Ethereum, Base, Arbitrum, and More
- **Extension ID:** ablbagjepecncofimgjmdpnhnfjiecfm
- **Version:** 0.12.3
- **User Count:** ~30,000
- **Manifest Version:** 3

## Executive Summary

The Blocknative Gas Fee Estimator is a legitimate browser extension that provides real-time gas price estimates for Ethereum and other blockchain networks. The extension communicates with Blocknative's official API endpoints to fetch gas price data and displays it to users via a popup interface.

**Overall Risk Assessment: CLEAN**

The extension demonstrates clean security practices with minimal permissions, legitimate API usage, and no malicious behavior. All network calls are directed to official Blocknative API endpoints for gas price data retrieval. The extension includes optional user authentication features for premium Blocknative services but does not exhibit any suspicious data collection or exfiltration patterns.

## Manifest Analysis

### Permissions
```json
"permissions": ["storage"]
```

**Assessment:** Minimal and appropriate permissions. The extension only requests `storage` permission, which is used to cache user preferences, gas price data, and optional API keys for authenticated users.

### Content Security Policy
- **No custom CSP defined** - relies on MV3 defaults
- **No content scripts** - extension operates entirely through popup UI and background service worker
- **No host permissions** - does not inject into web pages

### Background Service Worker
- Service worker loads from `service-worker-loader.js`
- Minimal background logic focused on:
  - Polling gas price data when popup is open
  - Chrome storage event listeners
  - Runtime message passing for popup communication

## Code Analysis

### Network Communication

All network requests are directed to legitimate Blocknative API endpoints:

**Base URL:** `https://api.blocknative.com`

**Endpoints:**
1. `/gasprices/blockprices` - Current gas price estimates
2. `/gasprices/recent-blocks` - Historical block data
3. `/gasprices/by-date` - Gas prices by date range
4. `/chains` - List of supported blockchain networks
5. `/oracles` - Oracle service information
6. `/rewards/contract-addresses` - Rewards program data

**Asset CDN:** `https://bnc-assets.com` - Chain icons and static assets

**Verdict:** All endpoints are official Blocknative services. No unauthorized external endpoints detected.

### API Authentication

The extension supports optional API key authentication for Blocknative premium features:

```javascript
// Authorization header added when API key present
headers: { Authorization: t }
```

**Behavior:**
- API keys stored in `chrome.storage.local` as `defaultApiKey`
- Keys only sent to official Blocknative endpoints
- Extension functions without authentication (free tier)
- No hardcoded API keys or secrets in code

**Verdict:** Standard OAuth-style authentication pattern. No security concerns.

### Data Storage

Chrome storage usage:
- `network` - Selected blockchain network
- `progress` - UI state
- `selectedConf` - Confidence level preference (70-99%)
- `favoriteChains` - User's favorite networks
- `historicalGasData` - Cached gas price history
- `defaultApiKey` - Optional user API key (if authenticated)

**Verdict:** All stored data is functional and user-controlled. No sensitive PII collection.

### Background Service Worker Logic

```javascript
// Polling only when popup is open
chrome.runtime.onConnect.addListener(t => {
  if (t.name === "bn-ext-open") {
    // Start polling
    t.onDisconnect.addListener(() => {
      // Stop polling when popup closes
    })
  }
})
```

**Key Features:**
- Efficient polling (only when UI is active)
- Interval-based gas price updates (10 seconds default)
- Storage listeners for cross-tab synchronization
- No persistent background activity

**Verdict:** Well-architected, minimal resource usage. No suspicious background behavior.

### Third-Party Libraries

**Detected Libraries:**
- RxJS - Observable streams for reactive data flow
- Highcharts - Chart rendering for gas price visualization
- Svelte - UI framework
- Anime.js - Animation library

**Verdict:** All legitimate, widely-used libraries. No malicious code injection detected.

## Vulnerability Assessment

### V1: Potential XSS via SVG innerHTML (FALSE POSITIVE)
**Severity:** N/A
**Files:** `assets/popup.html.68e5a036.js`
**Details:**
```javascript
// SVG elements created programmatically
const svg = '<svg viewBox="0 0 20 20"...></svg>'
```

**Analysis:** SVG strings are hardcoded template literals used by Svelte for icon rendering. Not user-controlled input.

**Verdict:** FALSE POSITIVE - Known FP (React/Svelte SVG innerHTML pattern)

### V2: Document Manipulation (BENIGN)
**Severity:** INFO
**Files:** `assets/popup.html.68e5a036.js`
**Count:** 47 references

**Details:** Standard DOM manipulation for popup UI rendering (chart creation, button clicks, form inputs).

**Verdict:** BENIGN - Normal UI framework behavior

## False Positive Table

| Pattern | Context | Reason for FP |
|---------|---------|---------------|
| SVG innerHTML | Svelte icon rendering | Hardcoded templates, not user input |
| document.querySelector | Highcharts initialization | Standard charting library behavior |
| password field | User authentication form | Legitimate login functionality |
| Authorization header | API authentication | Standard OAuth pattern to official API |

## API Endpoints Summary

| Endpoint | Purpose | Data Sent | Verdict |
|----------|---------|-----------|---------|
| api.blocknative.com/gasprices/blockprices | Gas estimates | chainId, system, network | CLEAN |
| api.blocknative.com/chains | Network list | None (GET) | CLEAN |
| api.blocknative.com/gasprices/recent-blocks | Historical data | chainId, system, network | CLEAN |
| api.blocknative.com/gasprices/by-date | Historical data | chainId, system, network, dateRange | CLEAN |
| bnc-assets.com | CDN assets | None | CLEAN |

## Data Flow Summary

1. **User Opens Popup** → Background service worker starts polling
2. **Gas Price Request** → Fetch from Blocknative API with selected network parameters
3. **Data Caching** → Store results in `chrome.storage.local` for offline access
4. **UI Rendering** → Display gas prices with Highcharts visualization
5. **Popup Closes** → Polling stops, cached data persists

**Privacy Assessment:**
- No PII collection beyond optional email for authentication
- No tracking pixels or analytics SDKs detected
- No third-party data sharing
- All data stays within Blocknative ecosystem

## Security Strengths

1. **Minimal Permissions** - Only requests `storage`, no host permissions
2. **No Content Scripts** - Cannot access user browsing data
3. **Official API Only** - All network calls to verified Blocknative endpoints
4. **Efficient Architecture** - Polling only when UI is active
5. **No Obfuscation** - Clean, readable code with standard bundling
6. **MV3 Compliant** - Uses modern manifest v3 standards

## Recommendations

No security improvements required. Extension follows best practices.

**Optional Enhancements:**
- Consider implementing Subresource Integrity (SRI) for CDN assets
- Add rate limiting for API calls to prevent abuse
- Implement CSP header in popup.html for defense-in-depth

## Overall Risk Rating

**CLEAN**

### Justification

The Blocknative Gas Fee Estimator is a well-designed, security-conscious extension that:
- Serves its stated purpose (gas price estimation) without overreach
- Uses minimal, appropriate permissions
- Communicates only with official Blocknative infrastructure
- Contains no malicious code, data exfiltration, or privacy violations
- Follows Chrome extension best practices and MV3 standards

The extension is safe for users and poses no security or privacy risks. All functionality is transparent and aligned with its advertised purpose.
