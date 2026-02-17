# G-calize Security Analysis Report

**Extension ID:** piiljfhidimfponnkjlkecnpjhdijfde
**Version:** 2.3.2
**Users:** ~200,000
**Risk Level:** CLEAN
**Analysis Date:** 2026-02-06

---

## Executive Summary

G-calize is a **CLEAN** extension with no malicious behavior detected. The extension is a legitimate Google Calendar customization tool that allows users to colorize weekdays, weekends, and holidays. All network requests are directed to official Google APIs, the hardcoded API key is properly scoped to public calendar access only, and there are no suspicious patterns such as data exfiltration, ad injection, or user tracking.

---

## Extension Overview

**Stated Purpose:**
Customizes Google Calendar appearance by allowing users to set custom colors for different days of the week, today highlighting, and holiday highlighting.

**Primary Functionality:**
- Color customization for weekdays (Sunday-Saturday)
- Custom highlighting for "today"
- Holiday calendar import from Google Calendar directory
- Dark/Light theme support

**Target Pages:**
`calendar.google.com/calendar/*` (both HTTP and HTTPS)

---

## Manifest Analysis

### Permissions
```json
"permissions": [
  "tabs",
  "storage",
  "contextMenus"
]
```

**Assessment:** Minimal and appropriate permissions:
- `tabs` - Used to send messages to active tab and enable/disable extension icon based on URL
- `storage` - Used to persist user color preferences and holiday data locally
- `contextMenus` - Adds "Open Settings" context menu item on Google Calendar pages

### Optional Host Permissions
```json
"optional_host_permissions": [
  "http://calendar.google.com/calendar/*",
  "https://calendar.google.com/calendar/*"
]
```

**Assessment:** Properly scoped to only Google Calendar pages. No broad host permissions.

### Content Security Policy
```json
"content_security_policy": {
  "extension_pages": "script-src 'self'; object-src 'self'"
}
```

**Assessment:** Strong CSP with no unsafe-eval or unsafe-inline. Only allows scripts from the extension package.

### Background Service Worker
```json
"background": {
  "service_worker": "js/service-worker.js",
  "type": "module"
}
```

**Assessment:** Uses modern Manifest V3 service worker architecture.

---

## Code Analysis

### Service Worker (`js/service-worker.js`)
**Size:** 2,889 bytes
**Functions:**
1. Message handling for saving/retrieving config and holiday data
2. Storage operations (chrome.storage.local)
3. Extension icon enable/disable based on active tab URL
4. Context menu creation on install

**Key Findings:**
- No network requests
- No external API calls
- Simple CRUD operations for local storage
- Validates URLs before enabling extension icon (regex: `/^https?:\/\/calendar.google.com\/calendar/`)
- Message handlers: `getSaveData`, `saveConfig`, `saveHoliday`, `reset`

**Suspicious Patterns:** NONE

### Content Script (`js/content-script.js`)
**Size:** 172,234 bytes
**Functions:**
1. Web Components polyfill (~first 550 lines)
2. Lit Element framework for settings UI
3. Holiday calendar fetching from Google Calendar API
4. Dynamic CSS injection for color customization
5. DOM observation to apply colors to calendar elements

#### Network Requests

**1. Google Calendar API v3 - Holiday Data Fetch**
```javascript
// Line 1633-1634
let n = `https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(t)}`;
n += "/events?orderBy=startTime&singleEvents=true"
n += "&fields=description%2Citems(description%2Cend%2Cstart%2Cstatus%2Csummary%2Cupdated%2Cvisibility)%2CnextPageToken%2Csummary"
n += `&timeMin=${o}&timeMax=${r}&maxResults=9999&key=${e}`
```

**Assessment:**
- **Endpoint:** `https://www.googleapis.com/calendar/v3/calendars/[calendarID]/events`
- **Method:** GET with no-cache
- **Purpose:** Fetches holiday events for 3 years before/after current year
- **User-controlled input:** Calendar ID (validated with regex `/^\S+@\S+\.\S+$/`)
- **Legitimate:** Yes - standard Google Calendar API usage

**2. Google Calendar Directory - Holiday List**
```javascript
// Line 3293
fetch("https://calendar.google.com/calendar/directory", {
  method: "POST",
  cache: "no-cache",
  body: e  // URLSearchParams with "did=holiday/official"
})
```

**Assessment:**
- **Endpoint:** `https://calendar.google.com/calendar/directory`
- **Method:** POST
- **Body:** `did=holiday/official`
- **Purpose:** Retrieves list of official Google holiday calendars
- **Response:** JSON array of holiday calendar metadata (title, did/cid)
- **Legitimate:** Yes - public Google Calendar directory API

#### Hardcoded API Key

**Location:** Line 3012
```javascript
apiKey: "AIzaSyDXobUokTiR0mW2UMTlBxVNdjYLZLEsBEg"
```

**Security Analysis:**
- **Type:** Google Calendar API v3 key
- **Scope:** Public calendar data read-only access
- **Risk Assessment:** LOW
  - This is a **browser API key** intended for client-side use
  - Properly scoped to only read public calendar events
  - No sensitive operations (write, delete, private calendar access)
  - Standard practice for client-side Google Calendar integrations
  - Key can be restricted to specific referrers (calendar.google.com) in Google Cloud Console

**Conclusion:** This is NOT a security vulnerability. Google's public API keys for read-only calendar access are designed to be embedded in client applications. The key is properly used and poses no security risk.

#### DOM Manipulation

**querySelector/getElementById Usage:**
- **Pattern:** Standard DOM queries for Google Calendar page elements
- **Targets:** Calendar grid cells, date elements, mini-month navigator
- **Purpose:** Apply custom color styling via CSS

**innerHTML Usage:**
- **Count:** 9 occurrences
- **Context:** All within Web Components polyfill for custom element registration
- **Assessment:** Part of standard Custom Elements polyfill, not malicious

**Dynamic CSS Injection:**
```javascript
// Lines 3047-3056
function Je(e) {
  const t = document.querySelector(`#${e}`);
  if (t && t.sheet)
    for (let a = t.sheet.cssRules.length - 1; a >= 0; a--)
      t.sheet.deleteRule(a)
}

function Xe(e, t) {
  const a = document.querySelector(`#${t}`);
  a && a.sheet && a.sheet.insertRule(e)
}
```

**Assessment:**
- Creates `<style>` elements with specific IDs
- Inserts CSS rules to colorize calendar elements based on user preferences
- All CSS targets are scoped to Google Calendar DOM structure
- No malicious CSS injection detected

#### MutationObserver

**Location:** Lines 3353-3372
```javascript
new MutationObserver((e => {
  e.forEach((e => {
    // Re-apply colors when calendar DOM changes
    // Monitor for view changes, date navigation
  }))
})).observe(document.body, {
  attributes: !0,
  childList: !0,
  subtree: !0
})
```

**Purpose:** Watches for Google Calendar DOM changes (navigation, view switching) to re-apply custom colors
**Assessment:** Legitimate - required because Google Calendar is a dynamic SPA

---

## Security Checks

### Extension Enumeration/Killing
**Search:** `chrome.management`, extension disable/uninstall patterns
**Result:** NONE FOUND

### XHR/Fetch Hooking
**Search:** `XMLHttpRequest.prototype`, `window.fetch` patching
**Result:** NONE FOUND
**Note:** All fetch calls are standard API requests, no interception

### Remote Configuration
**Search:** Remote config URLs, dynamic script loading
**Result:** NONE FOUND
**Note:** All configuration stored locally in chrome.storage

### Data Exfiltration
**Search:** Telemetry endpoints, analytics, tracking pixels
**Result:** NONE FOUND
**Note:** Zero external domains contacted except Google's official APIs

### Cookie/Credential Harvesting
**Search:** `document.cookie`, localStorage access beyond own data
**Result:** NONE FOUND

### Ad/Coupon Injection
**Search:** Ad network domains, affiliate IDs, coupon engines
**Result:** NONE FOUND
**Note:** The PayPal donation link (`https://www.paypal.com/paypalme/piayo/1000JPY`) is user-visible in settings UI, not injected

### eval/Function() Dynamic Code
**Search:** `eval(`, `new Function(`, code generation patterns
**Result:** NONE FOUND

### WebSocket/Proxy Infrastructure
**Search:** WebSocket connections, proxy configurations
**Result:** NONE FOUND

### AI Conversation Scraping
**Search:** ChatGPT, Claude, Gemini, AI platform patterns
**Result:** NONE FOUND

### Market Intelligence SDKs
**Search:** Sensor Tower, Pathmatics, analytics SDKs
**Result:** NONE FOUND

---

## Privacy Assessment

### Data Collection
**User Data Collected:**
- Color preferences for each day of the week
- Holiday calendar selection and cached holiday data (3 years)
- Theme preference (light/dark)
- View size preference

**Storage Location:**
- `chrome.storage.local` only
- No server-side storage
- No user identification

**Third-Party Data Sharing:**
- NONE

### Network Communication
**All Network Requests:**
1. `https://www.googleapis.com/calendar/v3/calendars/[ID]/events` - Fetch holiday events
2. `https://calendar.google.com/calendar/directory` - List holiday calendars

**Assessment:**
- Only communicates with official Google APIs
- No third-party analytics
- No tracking
- No telemetry

---

## Code Quality & Legitimacy Indicators

### Positive Indicators
1. **Copyright notices:** `@license Copyright (C) piayo.`
2. **Framework usage:** Lit Element (modern web components framework)
3. **Clean architecture:** Separation of concerns (service worker, content script, UI components)
4. **Proper error handling:** Try-catch blocks, user-facing error messages
5. **Internationalization:** 30+ language support via `_locales/` directory
6. **No obfuscation:** Code is beautified, variable names are readable
7. **Standard libraries:** Uses Web Components polyfill, Lit Element

### Developer Identity
**Name:** piayo
**Contact:** Visible in copyright notices
**Donation Link:** https://www.paypal.com/paypalme/piayo/1000JPY

---

## Comparison to Known Malicious Patterns

### False Positive Checks

**Web Components Polyfill:**
- Lines 0-550 contain Custom Elements polyfill
- Patches `createElement`, `innerHTML`, `querySelector` for custom element support
- **Verdict:** Standard polyfill, NOT malicious monkey-patching

**Lit Element Framework:**
- Template literal rendering (`R\`...\``)
- Property decorators (`@property`, `@state`)
- **Verdict:** Legitimate framework usage

**querySelector Usage:**
- All queries target Google Calendar DOM elements for styling
- No credential fields, input boxes, or sensitive elements targeted
- **Verdict:** NOT DOM scraping

---

## Risk Assessment

### Threat Level: CLEAN

**Severity:** None
**Exploitability:** N/A
**Impact:** N/A
**User Risk:** MINIMAL

### Breakdown by Category

| Category | Risk | Notes |
|----------|------|-------|
| Data Exfiltration | NONE | Zero external tracking/telemetry |
| Network Surveillance | NONE | Only Google API calls for stated functionality |
| Credential Theft | NONE | No password/cookie access |
| Ad Injection | NONE | No ads, no affiliate links (donation is user-visible) |
| Extension Interference | NONE | No enumeration/killing of other extensions |
| Remote Control | NONE | No remote config or kill switches |
| Privacy Violation | NONE | No PII collection, no tracking |
| Code Injection | NONE | No eval/dynamic scripts |

---

## Recommendations

### For Users
**Verdict:** SAFE TO USE

This extension:
- Does exactly what it claims (colorize Google Calendar)
- Has minimal permissions
- Makes no external requests outside Google's official APIs
- Collects no personal data
- Has no hidden functionality

### For Reviewers
**No action required.** This is a legitimate, well-designed extension.

### For Developer
**Suggestions (optional):**
1. Consider adding GitHub link for transparency
2. Document the API key usage in privacy policy
3. Add source code repository for community audit

---

## Technical Details

### File Structure
```
deobfuscated/
├── js/
│   ├── service-worker.js (2.9KB)
│   └── content-script.js (172KB - includes Lit Element framework)
├── _locales/ (30+ languages)
├── img/ (icons)
└── manifest.json
```

### Code Breakdown (content-script.js)
- Lines 0-550: Web Components polyfill
- Lines 550-1400: Lit Element framework base classes
- Lines 1400-1750: Translation strings (ja, zh-TW, zh-CN, ko)
- Lines 1575-1668: Holiday calendar loader class
- Lines 2500-3045: Settings UI component (Lit Element)
- Lines 3045-3280: CSS injection functions
- Lines 3280-3373: Main initialization and MutationObserver

### Dependencies
- **Lit Element:** Modern reactive web components library
- **Custom Elements Polyfill:** Browser compatibility for Web Components
- **No external CDN scripts:** All code bundled

---

## Conclusion

**G-calize is a CLEAN extension with zero security concerns.**

The extension performs exactly as advertised: it customizes Google Calendar colors. The code is well-structured, uses modern web standards (Lit Element, Web Components), and has no malicious functionality. The hardcoded Google API key is properly scoped for public calendar read-only access and is standard practice for client-side calendar integrations.

All network requests go to official Google APIs for legitimate calendar functionality. There is no tracking, no data exfiltration, no ad injection, and no hidden behavior. The extension respects user privacy and operates entirely within the stated functionality.

**Recommendation:** This extension can be trusted and used without security concerns.

---

## Appendix: Network Request Examples

### Holiday Calendar List Request
```http
POST https://calendar.google.com/calendar/directory
Content-Type: application/x-www-form-urlencoded

did=holiday/official
```

**Response:** JSON array of holiday calendars (e.g., US Holidays, UK Holidays)

### Holiday Events Request
```http
GET https://www.googleapis.com/calendar/v3/calendars/en.usa%23holiday%40group.v.calendar.google.com/events?orderBy=startTime&singleEvents=true&fields=description%2Citems(description%2Cend%2Cstart%2Cstatus%2Csummary%2Cupdated%2Cvisibility)%2CnextPageToken%2Csummary&timeMin=2023-01-01T00:00:00.000Z&timeMax=2029-12-31T23:59:59.000Z&maxResults=9999&key=AIzaSyDXobUokTiR0mW2UMTlBxVNdjYLZLEsBEg
```

**Response:** JSON with calendar events (holidays) for specified date range

---

**Analyst Notes:**
- No red flags detected
- Code quality is high
- Framework usage is appropriate
- API key handling is correct
- Privacy-respecting design
- Transparent functionality

**Status:** APPROVED - CLEAN
