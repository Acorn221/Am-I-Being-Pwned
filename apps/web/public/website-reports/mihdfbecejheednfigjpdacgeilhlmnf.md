# Vulnerability Assessment Report: Huntr - Job Search Tracker & Autofill

## Metadata
- **Extension Name**: Huntr - Job Search Tracker & Autofill
- **Extension ID**: mihdfbecejheednfigjpdacgeilhlmnf
- **Version**: 2.0.43
- **User Count**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

Huntr is a legitimate job search tracking extension developed by huntr.co that helps users save and organize job applications across the web. The extension operates as a productivity tool connecting to the vendor's backend API at huntr.co. After thorough analysis, **no critical security vulnerabilities or malicious behavior were identified**. The extension follows standard Chrome extension security practices with appropriate permission usage for its stated functionality.

The extension collects job application data from websites users visit and syncs it with the Huntr platform. All data transmission occurs over HTTPS to legitimate Huntr domains. Third-party analytics (Mixpanel) is present but standard for SaaS products.

## Vulnerability Details

### 1. No Critical Issues Found
**Severity**: N/A

No critical security vulnerabilities were identified during analysis.

---

### 2. Analytics Tracking (Mixpanel)
**Severity**: LOW
**Files**: `background.bundle.js` (lines 1305-1347)

**Description**:
The extension uses Mixpanel analytics to track user events:

```javascript
var r = n(27).a.MP_API_URL,
  o = "1d6f823f8d5432354b55fc0af879343c",  // Mixpanel token
  track: function(t, e) {
    // ... tracking implementation
    return fetch("".concat(r, "track/?data=").concat(u))
  }
```

Tracked events include:
- Extension installation/updates
- Job additions
- Upgrade prompts
- User actions

**Verdict**: ACCEPTABLE - Standard analytics for a SaaS product. Token is not sensitive (client-side tracking token). No PII is explicitly sent in tracking calls beyond what Mixpanel collects automatically.

---

### 3. Broad Host Permissions
**Severity**: LOW
**Files**: `manifest.json` (lines 45-54)

**Description**:
The extension requests broad host permissions:
```json
"host_permissions": [
  "http://*/*",
  "https://*/*",
  ...
]
```

**Verdict**: ACCEPTABLE - Required for the extension's core functionality of saving jobs from any website. The extension needs to access job posting content across all domains. Content scripts are properly declared and don't exhibit malicious behavior.

---

### 4. Third-Party API Keys Embedded
**Severity**: LOW
**Files**: `background.bundle.js` (lines 4050, 4083)

**Description**:
Hardcoded API keys found:
- Google Maps API key: `AIzaSyCfW7fJOYk5ueDavpnOU3xvYh5IcwmCn2o`
- LocationIQ API key: `9a84a5ada25b3c`

```javascript
var I = "AIzaSyCfW7fJOYk5ueDavpnOU3xvYh5IcwmCn2o";
// Used for place autocomplete/geocoding

Object(w.a)("https://us1.locationiq.com/v1/search.php?q=...&key=9a84a5ada25b3c...")
```

**Verdict**: ACCEPTABLE - Standard practice for client-side geocoding services. These are rate-limited public API keys, not security credentials. LocationIQ key appears to be a free tier key.

---

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| `new Function` | background.bundle.js:1354, 1362 | Webpack/polyfill boilerplate, not dynamic code execution |
| `innerHTML` usage | content.bundle.js (React) | React virtual DOM rendering (standard library behavior) |
| `postMessage` | content.bundle.js:33608, 33618 | MessageChannel for Redux state sync between extension contexts |
| keydown/keyup listeners | content.bundle.js:57980-58860 | React synthetic event system (standard) |
| `addEventListener` | content.bundle.js | jQuery, Quill editor, React event delegation (legitimate libraries) |
| Token references | content.bundle.js:3607+ | Lexer/parser tokens (not auth tokens), part of CSS parser library |

## API Endpoints

| Endpoint | Method | Purpose | Authentication |
|----------|--------|---------|----------------|
| `https://huntr.co/*` | GET/POST | Main application API | Bearer token |
| `/verify-token` | POST | Token validation | Bearer token |
| `/user/load/chrome-v2` | GET | Load user data | Bearer token |
| `/job` | POST | Save job application | Bearer token |
| `/organization/{id}/job-posts` | POST | Create organization job post | Bearer token |
| `/user/find-job` | GET | Check for duplicate jobs | Bearer token |
| `/board/{id}/chrome` | GET | Load board data | Bearer token |
| `/user/plan` | GET | Check subscription plan | Bearer token |
| `http://api.mixpanel.com/track/` | GET | Analytics tracking | API token (public) |
| `https://maps.googleapis.com/maps/api/*` | GET | Geocoding/autocomplete | API key (public) |
| `https://us1.locationiq.com/v1/search.php` | GET | Location search fallback | API key (public) |

## Data Flow Summary

### Collected Data
1. **Job Posting Information**: Title, company name, description, location, URL, salary (extracted from web pages)
2. **User Authentication**: Token and userId stored in chrome.storage.local
3. **User Profile**: Name, email, boards, lists, organization memberships
4. **Extension Telemetry**: Install/update events, feature usage, errors

### Storage
- **chrome.storage.local**: User authentication (token, userId), Redux state cache, board/list preferences
- **No cookies accessed**: No `document.cookie` manipulation detected
- **No localStorage/sessionStorage**: No direct web storage access from content scripts

### Transmission
- All user data transmitted to `https://huntr.co/*` over HTTPS
- Analytics transmitted to `http://api.mixpanel.com/*` (HTTP for tracking beacon)
- Authentication via Bearer tokens in Authorization headers
- No evidence of data exfiltration to unauthorized domains

### Privileged Operations
1. **chrome.tabs**: Query tabs, send messages, create new tabs (for onboarding/errors)
2. **chrome.scripting**: Dynamic injection of content scripts on all tabs (executeScript, insertCSS)
3. **chrome.webNavigation**: Check iframe context for job board detection
4. **chrome.storage**: Store user preferences and authentication state
5. **chrome.alarms**: Periodic data refresh and token validation

## Security Strengths

1. **HTTPS Communication**: All sensitive data transmitted over HTTPS to huntr.co
2. **No Dynamic Code Execution**: No eval(), Function constructor abuse, or remote code loading
3. **Proper CSP**: No manifest CSP specified (relies on default MV3 restrictions)
4. **No Web Request Interception**: Does not use webRequest, proxy, or declarativeNetRequest APIs
5. **Scoped External Connectivity**: `externally_connectable` properly restricted to huntr.co domains
6. **Token Validation**: Periodic token verification with automatic logout on 401 (lines 4484-4486)
7. **No XHR/Fetch Hooking**: Does not intercept or modify browser network APIs

## Privacy Considerations

- **Analytics**: Mixpanel tracks extension usage events (installs, job saves, errors)
- **Data Access**: Extension can read content from all websites where users click the extension button
- **Legitimate Use**: Data collection aligns with stated purpose (job application tracking)
- **User Control**: Requires explicit user action (clicking extension button) to save jobs
- **No Background Scraping**: Does not automatically harvest data; user-initiated only

## Overall Risk Assessment: CLEAN

**Justification**:
- Zero malicious indicators detected
- Legitimate business purpose aligned with functionality
- Standard SaaS extension architecture
- Appropriate permission usage for stated features
- No data exfiltration, proxy infrastructure, or obfuscated malware
- Well-established vendor (huntr.co) with transparent job tracking service
- No XSS vulnerabilities, remote config kill switches, or extension fingerprinting
- Proper authentication and token management

**Recommendation**: Safe for use. This is a legitimate productivity extension with no security concerns.
