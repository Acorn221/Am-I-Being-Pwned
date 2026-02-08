# Security Analysis Report: Custom New Tab

## Extension Metadata
- **Name**: Custom New Tab
- **Extension ID**: lfjnnkckddkopjfgmbcpdiolnmfobflj
- **User Count**: ~40,000
- **Version**: 1.10
- **Manifest Version**: 3
- **Developer**: dictanote.co

## Executive Summary

Custom New Tab is a simple Chrome extension that allows users to customize their new tab page by redirecting to a custom URL. The extension has minimal permissions, clean functionality aligned with its purpose, and uses PostHog analytics for legitimate product telemetry. While it collects anonymous analytics data, this is standard practice and clearly part of the extension's operational needs. No malicious behavior, privacy violations, or security vulnerabilities were identified.

**Overall Risk Assessment: CLEAN**

## Vulnerability Analysis

### 1. Analytics Tracking (Low Concern - Legitimate Use)

**Severity**: Informational
**Files**: `background.js` (lines 1761-1815), `options.js` (lines 1-98)
**Code Evidence**:
```javascript
// background.js line 1761
const Fe = "phc_sdq9LiSJIczre8YzDNPnCZBd6wlmX85wfp3HIlO48bt";

// background.js lines 1778-1786
async function Z(w, t) {
  $ || ($ = new be(Fe, {
    disableGeoip: !1
  })), E || await Se(), $.capture({
    distinctId: E,
    event: w,
    properties: t
  }), console.log("[PH]", w, t)
}
```

**Analysis**: The extension uses PostHog (https://us.i.posthog.com) for analytics tracking with events such as:
- Installation tracking (`"install"` event with version number)
- User actions (`"url"` event with configured URL and focus settings)
- Page views (`"$pageview"` event)
- JavaScript/Promise errors for debugging

**Data Collected**:
- Anonymous client ID (8-character random string stored in chrome.storage.local)
- Event types and basic usage patterns
- Extension version
- Configured URLs (only when user saves settings)
- Error information for debugging

**Verdict**: This is **legitimate product analytics**. The extension:
- Generates an anonymous client ID rather than using personally identifiable information
- Tracks minimal usage data to understand how users interact with the extension
- Does not collect browsing history, cookies, or sensitive user data
- Uses a standard, open-source analytics platform (PostHog)
- Developer domain (dictanote.co) is consistent across manifest homepage, uninstall URL, and externally_connectable domains

### 2. Minimal Permission Model

**Severity**: N/A (Positive Security Posture)
**Files**: `manifest.json`
**Permissions Requested**:
- `storage` - Required to save user's custom URL preference
- `optional_host_permissions: ["file:///*"]` - Optional, only if user wants to set local file as new tab
- `chrome_url_overrides.newtab` - Core functionality to override new tab page

**Analysis**: The extension requests the absolute minimum permissions needed for its stated functionality. No sensitive permissions like `cookies`, `webRequest`, `tabs` (with full access), `history`, or `bookmarks` are requested.

**Verdict**: Excellent security posture with minimal attack surface.

### 3. External Connectivity

**Severity**: Informational
**Files**: `manifest.json`
**externally_connectable Configuration**:
```json
"externally_connectable": {
  "matches": [
    "https://*.dictanote.co/*",
    "https://dictanote.co/*",
    "http://localhost:8000/*"
  ]
}
```

**Analysis**: The extension allows external messaging only from:
- Developer's own domain (dictanote.co)
- Localhost (for development)

The message handler in `background.js` (lines 1810-1813) only responds to a version check:
```javascript
function Ce(w, t, e) {
  w && w.message && w.message === "version" && e({
    version: 1
  })
}
```

**Verdict**: Safe and minimal external connectivity for legitimate integration purposes.

### 4. Code Injection Risk Assessment

**Severity**: None Detected
**Files**: All JavaScript files reviewed

**Analysis**: Searched for dangerous dynamic code patterns:
- No `eval()` calls
- No `Function()` constructor usage
- No `innerHTML` manipulation
- No `document.write()` calls
- No remote script loading

The extension uses standard Chrome APIs for tab navigation:
```javascript
// newtab.js lines 34-36
chrome.tabs.update(t.id, {
  url: e.url
})
```

**Verdict**: No code injection vulnerabilities detected.

### 5. Data Storage Security

**Severity**: N/A (Secure)
**Files**: `options.js`, `background.js`
**Storage Usage**:
```javascript
// Stores only: user's custom URL, focus preference, and anonymous client ID
await chrome.storage.local.set({
  url: n,
  focus: t
})
```

**Analysis**: The extension stores minimal data locally:
- Custom URL configuration (user-provided)
- Focus checkbox state (boolean)
- Anonymous client ID for analytics

No sensitive data like passwords, cookies, or browsing history is stored.

**Verdict**: Secure and appropriate use of chrome.storage API.

## False Positives Table

| Pattern/Finding | File | Line(s) | Why It's a False Positive |
|----------------|------|---------|---------------------------|
| PostHog SDK bundled code | background.js | 1-1760 | Standard open-source analytics library (PostHog) - not obfuscation or malware |
| SHA-1 hash implementation | background.js | 1-500 | Part of bundled library dependencies, not used for malicious purposes |
| `fetch` API calls | background.js | 867, 1000, 1119, 1133 | PostHog SDK making legitimate analytics API calls to us.i.posthog.com |
| Random ID generation | background.js | 1765-1769 | Generates anonymous client ID for analytics, not tracking actual user identity |
| File URL access | manifest.json, newtab.js | N/A | Optional permission allowing users to set local HTML files as new tab (legitimate feature) |
| localhost in externally_connectable | manifest.json | N/A | Development/testing configuration, common and harmless |

## API Endpoints Table

| Endpoint | Purpose | Data Sent | Risk Level |
|----------|---------|-----------|------------|
| https://us.i.posthog.com/e/ | PostHog event ingestion (form mode) | Event name, anonymous client ID, event properties (version, configured URL, error details) | Low - Standard analytics |
| https://us.i.posthog.com/batch/ | PostHog batch events (JSON mode) | Batched analytics events | Low - Standard analytics |
| https://us.i.posthog.com/decide/ | PostHog feature flags | Anonymous client ID, group properties | Low - Feature flag evaluation |
| https://dictanote.co/custom-new-tab/feedback/ | Uninstall feedback page | None (browser navigation only) | None - User-facing page |

## Data Flow Summary

1. **User Interaction**:
   - User installs extension → Anonymous client ID generated and stored locally
   - User opens new tab → Extension checks stored URL configuration
   - User configures custom URL → Saved to chrome.storage.local

2. **Analytics Flow**:
   - Installation event → PostHog (with version number)
   - Configuration changes → PostHog (with URL and focus setting)
   - Page views → PostHog (with page URL within extension)
   - Errors → PostHog (for debugging)

3. **Core Functionality**:
   - New tab opened → Extension redirects browser to user-configured URL
   - No data collection during normal browsing
   - No interaction with page content (no content scripts)

## Security Strengths

1. **Minimal Permissions**: Only requests `storage` permission (required for functionality)
2. **No Content Scripts**: Cannot access or manipulate web page content
3. **No Network Interception**: No webRequest, proxy, or cookies permissions
4. **Simple Codebase**: Small, focused code with clear purpose
5. **Manifest V3**: Uses modern, more secure extension platform
6. **Legitimate Analytics**: Uses well-known, open-source analytics platform
7. **Optional File Access**: file:// permission is optional and only needed for specific use case
8. **Secure External Messaging**: Limited to developer's own domain with minimal message handling

## Recommendations

None. The extension follows security best practices for its intended functionality.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Rationale**:
- Extension performs exactly as advertised: customizing the new tab page
- Minimal permissions appropriate for functionality
- Analytics tracking is transparent, minimal, and uses anonymous identifiers
- No malicious code, data exfiltration, or privacy violations detected
- No security vulnerabilities identified
- Developer identity is consistent and legitimate (dictanote.co)
- While the extension collects analytics data, this is clearly for product improvement and is implemented using industry-standard, privacy-conscious methods

**Final Verdict**: Custom New Tab is a legitimate, safe extension that provides its stated functionality without malicious behavior or significant privacy concerns. The analytics implementation is standard practice for extension developers to understand usage patterns and improve their product.
