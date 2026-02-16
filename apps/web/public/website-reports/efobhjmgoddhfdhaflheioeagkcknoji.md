# Security Analysis: Vertical Tabs (efobhjmgoddhfdhaflheioeagkcknoji)

## Extension Metadata
- **Name**: Vertical Tabs
- **Extension ID**: efobhjmgoddhfdhaflheioeagkcknoji
- **Version**: 2.2.11
- **Manifest Version**: 3
- **Estimated Users**: ~60,000
- **Developer**: samihaddad (GitHub: https://github.com/samihaddad/vertical-tabs-chrome-extension)
- **Analysis Date**: 2026-02-14

## Executive Summary
Vertical Tabs is a legitimate open-source tab management extension with **LOW** risk. The extension provides a vertical sidebar interface for managing browser tabs and tab groups. Analysis revealed minimal privacy concerns: the extension uses Google Analytics for usage tracking (extension version, session ID, and error events) and GrowthBook for A/B testing feature flags. One low-severity vulnerability exists with postMessage lacking origin validation, but this is limited to internal session replay functionality and poses minimal real-world risk. No browsing data, URLs, or user content is exfiltrated to external servers.

**Overall Risk Assessment: LOW**

## Vulnerability Assessment

### 1. postMessage Without Origin Check
**Severity**: LOW
**Files**: `/assets/index.html-hh-JdZcB.js` (line 26084)

**Analysis**:
The extension contains a postMessage call that uses wildcard origin (`"*"`), which could allow any frame to receive messages:

**Code Evidence**:
```javascript
window.parent.postMessage(se, "*")
```

**Context**:
This postMessage is part of a session replay library (likely rrweb or similar) embedded in the extension's bundle. The message contains replay event data:
```javascript
const se = {
  type: "rrweb",
  event: ne(ee),
  origin: window.location.origin,
  isCheckout: J
};
```

**Risk Mitigation Factors**:
- The extension does not inject content scripts into web pages
- The postMessage occurs within the extension's own side panel (index.html)
- The side panel is isolated from web content by Chrome's extension security model
- Messages contain only session replay metadata, not sensitive user data
- No evidence of this being exploitable in the current architecture

**Recommended Fix**: Replace `"*"` with specific origin validation, though real-world exploitability is minimal given the isolated context.

**Verdict**: **LOW SEVERITY** - Theoretical vulnerability with minimal practical risk.

---

### 2. Google Analytics Tracking
**Severity**: N/A (Expected Behavior, Privacy Concern)
**Files**: `/assets/ga-analytics-DAVYAz52.js`

**Analysis**:
The extension includes custom Google Analytics implementation for usage tracking.

**Code Evidence**:
```javascript
const f = "https://www.google-analytics.com/mp/collect",
  u = "G-PWTSXRQH0X",
  m = "DyNrnsxiTyqDSUIi-vz_9w";

async fireEvent(e, t = {}) {
  await fetch(`${f}?measurement_id=${u}&api_secret=${m}`, {
    method: "POST",
    body: JSON.stringify({
      client_id: await this.getOrCreateClientId(),
      events: [{
        name: e,
        params: t
      }]
    })
  })
}
```

**Data Transmitted**:
- **Client ID**: Random UUID generated locally (stored in `chrome.storage.local`)
- **Session ID**: Timestamp-based session identifier (30-minute timeout)
- **Extension version**: Manifest version (e.g., "2.2.11")
- **Heap size**: JavaScript memory usage (`performance.memory.usedJSHeapSize`)
- **Event types**: "install", "experiment_viewed", "extension_error", "page_view"
- **Error data**: Error message and stack trace (only for crashes)

**Events Tracked**:
1. **Install event**: Fired once on installation
2. **Experiment viewed**: A/B test variant assignments (from GrowthBook)
3. **Extension errors**: Unhandled promise rejections with stack traces
4. **Page views**: Side panel navigation (internal to extension)

**NOT Transmitted**:
- Tab URLs or titles
- Browsing history
- User identifiers (email, name, etc.)
- Page content
- Cookies
- Any web page data

**Verdict**: **NOT MALICIOUS** - Standard usage analytics with minimal data collection. All tracking is limited to extension behavior, not user browsing.

---

### 3. GrowthBook Feature Flag System (Remote Config)
**Severity**: N/A (Expected Behavior)
**Files**: `/assets/index.html-hh-JdZcB.js` (lines 30701, 30720, 31877)

**Analysis**:
The extension uses GrowthBook SDK for A/B testing and feature flag management.

**Code Evidence**:
```javascript
FC = new hH({
  apiHost: "https://cdn.growthbook.io",
  clientKey: "sdk-KHFvDTyaf7HmgCQ",
  enableDevMode: !1,
  trackingCallback: (e, t) => {
    st.fireEvent("experiment_viewed", {
      experiment_id: e.key,
      variation_id: t.variationId
    })
  }
})
```

**Endpoints**:
- `https://cdn.growthbook.io/api/features/sdk-KHFvDTyaf7HmgCQ` - Feature flag configuration download
- `https://rt.growthbook.io/?key=[key]&events=[data]` - Real-time event reporting (A/B test exposures)

**Data Transmitted to GrowthBook**:
- Feature flag evaluation events (which experiments user is exposed to)
- Event data: `{key: "feature_name", on: true/false}`
- **No user identifiers, URLs, or browsing data**

**Purpose**:
GrowthBook enables gradual feature rollouts and A/B testing for UI improvements. For example, testing different layouts or button placements within the side panel.

**Safety Indicators**:
- Read-only feature flags (no remote code execution)
- All features are part of the bundled extension code
- GrowthBook only controls which features are enabled/disabled
- Standard practice for modern web applications

**Verdict**: **NOT MALICIOUS** - Legitimate A/B testing infrastructure with minimal privacy impact.

---

### 4. Sentry Error Tracking (Debug IDs)
**Severity**: N/A (Expected Behavior)
**Files**: All deobfuscated JS files contain Sentry debug ID headers

**Analysis**:
The extension includes Sentry debug identifiers for source map resolution during error reporting.

**Code Evidence**:
```javascript
(function() {
  try {
    var e = typeof window < "u" ? window : typeof global < "u" ? global : typeof self < "u" ? self : {},
      n = new e.Error().stack;
    n && (e._sentryDebugIds = e._sentryDebugIds || {},
          e._sentryDebugIds[n] = "a9f206d3-1b21-4301-a7a2-7a4e2fdcc4e0")
  } catch {}
})();

d.SENTRY_RELEASE = { id: "2.2.11" };
```

**Purpose**:
These debug IDs link production errors to source maps, allowing developers to see original source code in error reports instead of minified/obfuscated code.

**No Evidence of Active Sentry Integration**:
- No Sentry API calls found in code
- No `Sentry.init()` or similar initialization
- Debug IDs are inert without corresponding Sentry.captureException() calls
- Error reporting appears to use only Google Analytics (`fireErrorEvent()`)

**Verdict**: **NOT A CONCERN** - Metadata only, no active error transmission to Sentry detected.

---

## Tab Data Access Analysis

### Permissions Usage

| Permission | Purpose | Data Accessed | Transmitted? |
|------------|---------|---------------|--------------|
| `tabs` | Query and manage browser tabs | Tab title, URL, favicon, pinned/muted status | **NO** |
| `tabGroups` | Manage tab groups | Group ID, title, color | **NO** |
| `sidePanel` | Display vertical tab UI | N/A (UI only) | **NO** |
| `storage` | Store user preferences | Settings, GA client ID | **NO** |
| `favicon` | Display tab favicons | Favicon URLs | **NO** |
| `contextMenus` | Add "Vertical Tabs" menu item | N/A | **NO** |

### Tab Query Operations

**Code Evidence** (`index.html-hh-JdZcB.js`, lines 30043, 30318):
```javascript
// Query tabs in a specific group
const J = await chrome.tabs.query({ groupId: L });

// Query all tabs in current window
const M = await chrome.tabs.query({ currentWindow: !0 });
```

**Data Flow**:
1. Extension queries tabs via `chrome.tabs.query()`
2. Tab objects include: `id`, `title`, `url`, `favIconUrl`, `pinned`, `muted`, `groupId`, `index`
3. Data displayed in side panel UI for tab management
4. **No network requests with tab data**
5. **All data stays local to the browser**

### Favicon Handling

**Code Evidence** (`index.html-hh-JdZcB.js`, line 12292):
```javascript
const g2 = e => {
  const t = new URL(chrome.runtime.getURL("/_favicon/"));
  t.searchParams.set("pageUrl", e);
  t.searchParams.set("size", "32");
  return t.toString()
};
```

**Mechanism**:
- Uses Chrome's internal `chrome://favicon/` API (exposed as `/_favicon/` in extensions)
- Favicons are fetched by Chrome itself, not the extension
- Page URLs passed to Chrome's favicon service (local, not network request)
- Standard practice for displaying tab favicons

**Verdict**: **NO PRIVACY CONCERN** - Uses browser's built-in favicon cache.

---

## Network Activity Analysis

### External Endpoints

| Domain | Purpose | Data Transmitted | Frequency |
|--------|---------|------------------|-----------|
| `www.google-analytics.com/mp/collect` | Usage analytics | Client ID, session ID, extension version, event names | Per event (install, error, etc.) |
| `cdn.growthbook.io/api/features/*` | Feature flag config | None (GET request with SDK key in URL) | On load / periodic refresh |
| `rt.growthbook.io/?key=*` | A/B test event tracking | Experiment exposure events | Batched every 2 seconds |
| `github.com` | Developer repository link | None (user-initiated navigation) | User clicks "Report Issue" |
| `buymeacoffee.com` | Donation link | None (user-initiated navigation) | User clicks donation link |

### Data Exfiltration Analysis

**ext-analyzer Findings**:
The static analyzer flagged 7 exfiltration flows:
1. `fetch()` calls to `google-analytics.com` (GA tracking)
2. `fetch()` calls to `growthbook.io` (feature flags + event tracking)
3. `chrome.tabs.query() → *.src(www.w3.org)` (FALSE POSITIVE - SVG namespace attribute, not data exfiltration)

**Manual Code Review**:
```javascript
// GA tracking - only metadata, no browsing data
await fetch("https://www.google-analytics.com/mp/collect", {
  body: JSON.stringify({
    client_id: uuid,
    events: [{
      name: "install",
      params: { extension_version: "2.2.11", heap_size: 1234567 }
    }]
  })
})

// GrowthBook events - only A/B test exposures
window.fetch("https://rt.growthbook.io/?key=X&events=" +
  encodeURIComponent(JSON.stringify([{key: "feature_x", on: true}])))
```

**Verdict**: **NO SENSITIVE DATA EXFILTRATION**
- All network requests transmit only extension metadata and feature flag events
- Tab URLs, titles, and browsing history are **never** sent to external servers
- User preferences stored locally in `chrome.storage.local`

---

## Comparison to Malicious Patterns

| Malicious Pattern | Present? | Evidence |
|-------------------|----------|----------|
| Extension enumeration/killing | ✗ No | No `chrome.management` API usage |
| XHR/fetch hooking | ✗ No | No prototype modifications |
| Residential proxy infrastructure | ✗ No | No proxy configuration |
| Browsing history collection | ✗ No | Tab data used only for UI display |
| Cookie harvesting | ✗ No | No cookie API access |
| Hidden data exfiltration | ✗ No | All network calls are transparent |
| Remote code execution | ✗ No | No `eval()`, `Function()`, or external script loading |
| Content script injection | ✗ No | Extension runs only in side panel |
| Ad/coupon injection | ✗ No | No DOM manipulation on web pages |
| Keylogging | ✗ No | No input monitoring |

---

## Privacy Impact Assessment

### Data Collection Summary

**Locally Stored (Never Transmitted)**:
- User preferences (tab sorting, grouping settings)
- Side panel UI state
- Feature flag cache

**Transmitted to First Parties**:
- Google Analytics: Client ID, session ID, extension version, error events
- GrowthBook: A/B test exposure events (which features are enabled)

**Never Collected or Transmitted**:
- Tab URLs or titles
- Browsing history
- Cookies
- Form data
- Search queries
- User identifiers (email, name, IP address)
- Page content

### User Privacy Rating: **MINIMAL IMPACT**

The extension accesses tab metadata to display the vertical tab UI but does not transmit this data externally. Analytics tracking is limited to basic usage metrics (install events, errors) without any personally identifiable information or browsing behavior.

---

## Code Quality Observations

### Positive Indicators
1. **Open source**: Code available at https://github.com/samihaddad/vertical-tabs-chrome-extension
2. **No dynamic code execution**: No `eval()`, `Function()`, or `setTimeout(string)`
3. **No external script loading**: All code bundled with extension
4. **Manifest V3 compliant**: Uses modern extension architecture with service worker
5. **Sentry integration is dormant**: Debug IDs present but no active error transmission
6. **Clean separation**: Side panel UI isolated from web content
7. **Standard build tools**: Built with Vite/React (modern web tooling)
8. **Transparent analytics**: GA implementation is readable, no obfuscated tracking

### Build Artifacts
- **Obfuscation level**: Moderate - Vite production build with minification
- **WebAssembly**: Flag present but no WASM files detected in bundle
- **React**: Uses React 18 for UI rendering
- **Material-UI**: Uses MUI component library for design
- **Lines of code**: ~32,000 (primarily third-party libraries)

---

## Open Source Verification

**Repository**: https://github.com/samihaddad/vertical-tabs-chrome-extension

The extension is open source, allowing users to:
1. Verify the code matches the published CWS version
2. Build from source and compare hashes
3. Submit security issues to the developer
4. Fork and self-host if desired

**Transparency Score**: HIGH

---

## Overall Risk Assessment

### Risk Level: **LOW**

**Justification**:
1. **Minimal privacy impact** - Only basic usage analytics, no browsing data exfiltration
2. **One low-severity vulnerability** - postMessage without origin check (minimal exploitability)
3. **Legitimate functionality** - All features match user expectations
4. **Open source** - Code is publicly auditable
5. **No malicious patterns** - Clean code with standard web practices
6. **MV3 compliant** - Uses latest security architecture

### Vulnerability Breakdown
- **Critical**: 0
- **High**: 0
- **Medium**: 0
- **Low**: 1 (postMessage wildcard origin)

### Recommendations

**For Users**:
- **Safe to use** - Extension operates as advertised
- Be aware that basic usage analytics (install events, errors) are sent to Google Analytics
- All tab management features work locally without transmitting browsing data

**For Developer**:
1. Replace `window.parent.postMessage(se, "*")` with origin validation
2. Consider making analytics opt-in or disclosing in privacy policy
3. Document GrowthBook A/B testing in extension description
4. Add Content Security Policy to manifest (though MV3 provides defaults)

---

## Technical Summary

**Architecture**: React-based side panel with Chrome Tab API integration
**External Dependencies**: React, Material-UI, GrowthBook SDK, session replay library
**Remote Services**: Google Analytics, GrowthBook Cloud
**Data Storage**: `chrome.storage.local` and `chrome.storage.session`
**Dynamic Code**: None
**Content Scripts**: None

---

## Conclusion

Vertical Tabs is a **low-risk, legitimate tab management extension** with transparent, minimal analytics. The extension provides vertical tab organization in a side panel without exfiltrating browsing data. One low-severity postMessage vulnerability exists but poses minimal real-world risk given the isolated side panel context. The use of Google Analytics and GrowthBook for product analytics is standard practice for modern web applications, though users should be aware of basic usage tracking.

The open-source nature of the project allows full code auditability, further supporting its legitimacy.

**Final Verdict: LOW RISK** - Safe for use by ~60,000 users with minor privacy considerations.
