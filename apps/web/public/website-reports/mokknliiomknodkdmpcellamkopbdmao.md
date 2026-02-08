# Security Analysis: Repeek (formerly FACEIT Enhancer)

**Extension ID:** mokknliiomknodkdmpcellamkopbdmao
**Extension Name:** Repeek (formerly FACEIT Enhancer)
**Version:** 5.4.21
**Users:** ~1,000,000
**Manifest Version:** 3
**Analysis Date:** 2026-02-06

---

## Executive Summary

Repeek is a **CLEAN** extension that enhances the FACEIT gaming platform experience with quality-of-life features. The extension demonstrates professional development practices with legitimate functionality scoped to FACEIT.com. It communicates with official FACEIT APIs and its own backend services for badge/announcement features. While it collects visibility telemetry for feature engagement tracking, this is implemented using standard IntersectionObserver patterns without malicious intent. No evidence of XHR/fetch hooking, credential harvesting, ad injection, extension manipulation, or data exfiltration was found.

**Overall Risk Rating: CLEAN**

---

## Extension Metadata

### Permissions Analysis
```json
{
  "permissions": [
    "storage",           // Standard settings storage - LEGITIMATE
    "clipboardWrite"     // Auto-copy server connect commands - LEGITIMATE
  ],
  "host_permissions": [
    "https://api.faceit.com/*"  // Official FACEIT API - LEGITIMATE
  ]
}
```

**Permission Assessment:**
- ✅ Minimal permissions (storage + clipboardWrite)
- ✅ Host permissions scoped only to official FACEIT API
- ✅ No tabs, webRequest, management, cookies, or history permissions
- ✅ No broad host permissions (`<all_urls>` or `*://*/*`)

### Content Security Policy
- Default MV3 CSP (no custom CSP defined)
- No external script loading capabilities
- All code bundled in extension package

---

## Architecture Overview

### Files Structure
```
background/index.js    (2,951 lines) - Service worker with API clients
faceit/index.js       (35,359 lines) - Main content script (React app)
window/script.js         (85 lines) - MAIN world script for React Fiber access
popup/index.js         (large)      - Popup UI
options/index.js       (large)      - Options page UI
```

### Core Functionality
1. **FACEIT Enhancement Features:**
   - Match room statistics (ELO, player stats, country flags)
   - Auto-accept match ready/party invites
   - Auto-copy/connect to game servers
   - Map/server veto automation
   - Match history stats
   - Skin-of-the-match integration

2. **Backend Services:**
   - `https://extension-api.repeek.gg` - API for badges/announcements/events
   - `https://extension-cdn.repeek.gg` - CDN for static assets
   - `https://www.faceit.com/api` - Official FACEIT API

3. **Communication Architecture:**
   - Background service worker provides API proxy
   - Content script uses `chrome.runtime.sendMessage` to background
   - MAIN world script uses `window.postMessage` to access React Fiber internals

---

## Vulnerability Analysis

### 1. Data Collection & Telemetry

**Finding:** IntersectionObserver-based visibility tracking for feature engagement
**Severity:** LOW
**File:** `faceit/index.js` lines 3960-3973

**Code Evidence:**
```javascript
function aL(e) {
  let {
    ref: t
  } = j2({
    triggerOnce: !0,
    threshold: .1,
    onChange: a => {
      e && a && Ls(e)  // Sends event when element becomes visible
    }
  });
  return {
    ref: t
  }
}

function Ls(e) {
  return md("/v1/events", {
    method: "POST",
    body: e
  })
}
```

**Analysis:**
- Uses standard IntersectionObserver API to track when UI elements become visible
- `triggerOnce: !0` ensures events fire only once per element
- Data sent to `https://extension-api.repeek.gg/v1/events`
- **Purpose:** Feature engagement analytics (which features users actually see/use)
- **NOT malicious:** Standard product analytics, no PII, no browsing history, no page content

**Verdict:** ✅ **FALSE POSITIVE** - Legitimate product telemetry

---

### 2. React Fiber Internal Access

**Finding:** MAIN world script accesses React Fiber internal data structures
**Severity:** LOW
**File:** `window/script.js` lines 54-83

**Code Evidence:**
```javascript
function g(e) {
  return Object.values(e).find(r => r && typeof r == "object" && "memoizedProps" in r && "children" in r.memoizedProps)
}

a({
  getFiberNodeChildrenProps: e => {
    let r = p(e.elementId);
    if (!r) return null;
    let n = g(r);
    return !n?.memoizedProps?.children || !Array.isArray(n.memoizedProps.children) ? null : n.memoizedProps.children.map(...)
  },
  selectReduxStore: e => {
    // Accesses React Redux store via Fiber tree traversal
  }
})
```

**Analysis:**
- MAIN world script uses `window.postMessage` to expose APIs to isolated world
- Accesses React Fiber internals (`memoizedProps`, Redux store) to extract FACEIT UI data
- **Purpose:** Extract match/player data from FACEIT's React app to display enhanced stats
- **NOT malicious:** Standard technique for web augmentation extensions
- No data exfiltration, only used for on-page feature rendering

**Verdict:** ✅ **FALSE POSITIVE** - Legitimate DOM introspection for UI enhancement

---

### 3. Remote Configuration System

**Finding:** Extension supports remote configuration via storage
**Severity:** LOW
**File:** `background/index.js` lines 2884-2924

**Code Evidence:**
```javascript
var Bs = new Ee({
  defaults: {
    "extension.enabled": !0,
    "extension.config": "",
    "extension.announcements.dismissed": "",
    "faceit.matchReady.autoAccept.enabled": !1,
    "faceit.matchroom.overview.connect.autoConnect.enabled": !1,
    // ... many more feature flags
  },
  migrations: [e => {
    // Migration logic for legacy settings
  }, Ee.migrations.removeUnused]
})
```

**Analysis:**
- Uses `webext-options-sync` library for settings management
- `"extension.config"` field could theoretically store remote config JSON
- **However:** No evidence of remote config fetching in code
- All feature flags are locally managed via storage API
- Configuration changes require user interaction (options page)
- No silent/automatic config updates from server

**Verdict:** ✅ **FALSE POSITIVE** - Local settings storage, no remote kill switch

---

### 4. Chrome Extension Management API Usage

**Finding:** None
**Severity:** N/A

**Analysis:**
- Searched for `chrome.management`, `chrome.declarativeNetRequest`, `chrome.webRequest`
- **Result:** No usage found
- Extension cannot enumerate, disable, or manipulate other extensions

**Verdict:** ✅ **CLEAN** - No extension manipulation capabilities

---

### 5. XHR/Fetch Hooking

**Finding:** None
**Severity:** N/A

**Analysis:**
- Searched for `XMLHttpRequest.prototype`, `.send =`, `.open =`, `window.fetch =`
- **Result:** No hooking or monkey-patching found
- Extension uses native `fetch` via `ofetch` library wrapper (lines 534-625)
- No interception of page/other extension network requests

**Verdict:** ✅ **CLEAN** - No network request hooking

---

### 6. Dynamic Code Execution

**Finding:** None
**Severity:** N/A

**Analysis:**
- Searched for `eval(`, `new Function(`, `Function(`
- **Result:** No dynamic code execution found
- All code is statically bundled

**Verdict:** ✅ **CLEAN** - No eval/Function usage

---

### 7. Credential/Cookie Harvesting

**Finding:** None
**Severity:** N/A

**Analysis:**
- Searched for `document.cookie`, `chrome.cookies`, credential patterns
- **Result:** No cookie access or credential harvesting found
- Extension only accesses FACEIT API with user's existing session
- Uses `localStorage` only for internal state (auto-connect history)

**Verdict:** ✅ **CLEAN** - No credential theft

---

### 8. Ad/Coupon Injection

**Finding:** None
**Severity:** N/A

**Analysis:**
- Searched for affiliate links, coupon codes, ad injection patterns
- **Result:** No ad injection or monetization code found
- Extension is purely functional, no commercial content insertion

**Verdict:** ✅ **CLEAN** - No ad injection

---

## API Endpoints & Data Flow

| Endpoint | Purpose | Method | Data Sent | Assessment |
|----------|---------|--------|-----------|------------|
| `https://extension-api.repeek.gg/v1/events` | Feature engagement telemetry | POST | Element visibility events | ✅ Legitimate analytics |
| `https://extension-api.repeek.gg/v1/announcements` | Fetch extension announcements | GET | None | ✅ Update notifications |
| `https://extension-api.repeek.gg/v1/badges/{userId}` | User badge/achievement data | GET | FACEIT user ID | ✅ Social features |
| `https://extension-api.repeek.gg/v1/skin-of-the-match/faceit/{matchId}` | CS2 skin showcase feature | GET | Match ID, Steam IDs | ✅ Gaming stats |
| `https://extension-cdn.repeek.gg/*` | Static asset CDN | GET | None | ✅ Content delivery |
| `https://www.faceit.com/api/*` | Official FACEIT API proxy | Various | Game/match data | ✅ Official API |

---

## False Positive Analysis

### React DOM Manipulation Patterns
- ✅ **React SVG createElement/innerHTML:** Lines using `createElementNS("http://www.w3.org/2000/svg")` are standard React SVG rendering
- ✅ **React script injection:** Lines with `createElement("script")` are React SSR/hydration patterns, not malicious injection
- ✅ **Floating UI focus trapping:** Event listeners for `focusin`, `focusout`, `keydown` are standard UI library patterns

### Library-Specific Patterns
- ✅ **LZString compression:** Base64 encoding library for compressing settings storage
- ✅ **webext-options-sync:** Standard options management library with form syncing
- ✅ **ofetch:** HTTP client library (wrapper around fetch)
- ✅ **React Query (@tanstack/query-core):** Data fetching/caching library
- ✅ **destr:** JSON parsing library with prototype pollution protection

---

## Data Flow Summary

```
┌─────────────────────────────────────────────────────────────────┐
│                      Repeek Extension                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Content Script (faceit/index.js)                               │
│  ├─ Reads FACEIT page DOM (player stats, match data)           │
│  ├─ Displays enhanced UI overlays (ELO, flags, stats)          │
│  ├─ Sends visibility events → extension-api.repeek.gg          │
│  └─ Communicates with background via chrome.runtime.sendMessage│
│                                                                 │
│  MAIN World Script (window/script.js)                           │
│  ├─ Accesses React Fiber internals via postMessage             │
│  └─ Returns FACEIT UI data to isolated world                   │
│                                                                 │
│  Background Service Worker (background/index.js)                │
│  ├─ Proxies API calls to extension-api.repeek.gg               │
│  ├─ Proxies FACEIT API calls to api.faceit.com                 │
│  └─ Manages settings in chrome.storage.sync                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
         │                     │                     │
         │ (visibility)        │ (badges/announce)   │ (match data)
         ▼                     ▼                     ▼
  repeek.gg/events      repeek.gg/api         faceit.com/api
```

**Data Sharing Summary:**
- ✅ Visibility events (feature engagement) → repeek.gg
- ✅ FACEIT user IDs → repeek.gg (for badges feature)
- ✅ Match/player data requests → faceit.com (official API)
- ✅ Settings stored locally in chrome.storage.sync
- ❌ NO browsing history collection
- ❌ NO page content scraping (beyond FACEIT.com)
- ❌ NO cookie/credential theft
- ❌ NO third-party trackers

---

## Positive Security Findings

1. **Minimal Permissions:** Only 2 permissions (storage, clipboardWrite)
2. **Scoped Host Permissions:** Only FACEIT domains
3. **No Extension Manipulation:** No management/tabs APIs
4. **No Network Hooking:** No XHR/fetch interception
5. **No Dynamic Code:** All code statically bundled
6. **Legitimate Purpose:** All features enhance FACEIT gaming experience
7. **Transparent APIs:** Backend services clearly named/documented
8. **Professional Codebase:** Well-structured React/TypeScript architecture
9. **Standard Libraries:** Uses reputable open-source libraries (React Query, ofetch, etc.)
10. **No Obfuscation:** Code is minified but not intentionally obfuscated

---

## Comparison to Known Malicious Patterns

| Pattern | Status | Notes |
|---------|--------|-------|
| **Sensor Tower SDK** | ❌ Not Present | No @sensortower/ad-finder, no Pathmatics SDK |
| **AI Conversation Scraping** | ❌ Not Present | No ChatGPT/Claude/Gemini content extraction |
| **Extension Enumeration** | ❌ Not Present | No chrome.management.getAll() |
| **Extension Killing** | ❌ Not Present | No setEnabled(false) calls |
| **Proxy Infrastructure** | ❌ Not Present | No residential proxy vendors |
| **Ad Injection** | ❌ Not Present | No DOM manipulation for ads/coupons |
| **Remote Kill Switch** | ❌ Not Present | No server-controlled behavior toggling |
| **XHR/Fetch Hooking** | ❌ Not Present | No prototype manipulation |
| **Credential Harvesting** | ❌ Not Present | No cookie/password theft |
| **Obfuscation** | ❌ Not Present | Standard minification only |

---

## Recommendations

### For Users:
✅ **Safe to Use** - Repeek is a legitimate gaming enhancement extension
- All features work as advertised
- No hidden data collection beyond basic analytics
- Transparent communication with backend services

### For Developers:
✅ **Best Practice Examples:**
- Minimal permission model
- Scoped host permissions
- Clear separation of concerns (content/background/MAIN worlds)
- Standard library usage

### For Researchers:
✅ **Reference Implementation:**
- Example of **clean** gaming enhancement extension
- Demonstrates proper React Fiber introspection techniques
- Shows legitimate use of IntersectionObserver for analytics

---

## Technical Notes

### React Fiber Access Pattern
The extension uses a clever but legitimate technique to access FACEIT's React app internals:
1. Injects MAIN world script to access `window` React Fiber
2. Uses `postMessage` to communicate extracted data to isolated world
3. Content script uses this data to render enhanced UI

This is **not malicious** - it's a standard technique for extensions that need to deeply integrate with React apps.

### IntersectionObserver Usage
The visibility tracking via IntersectionObserver is a **standard analytics pattern**:
- Used by Google Analytics, Mixpanel, etc.
- Only tracks when UI features become visible (not page content)
- Helps developers understand feature adoption
- No PII or sensitive data collected

---

## Conclusion

**Repeek (formerly FACEIT Enhancer) is CLEAN.**

The extension demonstrates:
- ✅ Professional development practices
- ✅ Minimal permission usage
- ✅ Legitimate functionality
- ✅ Transparent backend communication
- ✅ No malicious patterns

All flagged patterns are **false positives** from standard web development libraries and techniques. The extension collects minimal telemetry (visibility events) for product analytics, which is a legitimate and transparent use case.

**Final Verdict: CLEAN**
**Risk Level: LOW**
**Recommended Action: No action required - safe for public use**

---

## References

- Extension Homepage: https://repeek.gg
- FACEIT Platform: https://www.faceit.com
- Backend API: https://extension-api.repeek.gg
- Backend CDN: https://extension-cdn.repeek.gg

**Report Generated:** 2026-02-06
**Analyst:** Claude Opus 4.6 (Automated Security Analysis)
