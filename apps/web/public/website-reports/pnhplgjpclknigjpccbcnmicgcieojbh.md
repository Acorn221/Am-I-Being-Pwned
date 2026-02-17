# Security Analysis: Diigo Web Collector - Capture and Annotate

**Extension ID:** pnhplgjpclknigjpccbcnmicgcieojbh
**Users:** ~300,000
**Version:** 3.5.0
**Risk Level:** LOW
**Analysis Date:** 2026-02-06

## Executive Summary

Diigo Web Collector is a legitimate web annotation and bookmarking tool that communicates with Diigo's own services. The extension was analyzed for malicious patterns including XHR/fetch hooking, extension enumeration, AI conversation scraping, market intelligence SDKs, and residential proxy infrastructure. **No significant security issues were found.** The extension follows standard security practices for its functionality.

## Manifest Analysis

### Permissions (Legitimate Use)
- `contextMenus` - For right-click annotation options
- `tabs` - For tracking bookmarks and annotations across tabs
- `cookies` - For Diigo authentication (limited to diigo.com)
- `storage` - For local preferences and cached data
- `scripting` - For injecting annotation UI
- `pageCapture` - For saving full page archives (legitimate feature)
- `downloads` (optional) - For exporting annotations
- `identity` (optional) - For Google Drive integration

### Content Security Policy
```json
"extension_pages": "script-src 'self'; object-src 'self'"
"sandbox": "sandbox allow-scripts; script-src 'self' https://toolbar3.diigo.com https://apis.google.com https://www.google-analytics.com; object-src 'self'"
```
**Assessment:** Standard CSP. Allows Google Analytics and Google APIs for Drive integration.

### Host Permissions
- `https://www.diigo.com/` - Primary service
- `<all_urls>` - Required for annotation on any page (legitimate for annotation tool)

### OAuth2 Configuration
```json
"client_id": "354731456810-spke6uqg1sbpi12vt6toinoqc29bukko.apps.googleusercontent.com"
"scopes": ["https://www.googleapis.com/auth/drive.readonly", "profile", "email"]
```
**Assessment:** Read-only Google Drive access for importing documents. Legitimate use case.

## Background Script Analysis

**File:** `/js/background.js` (imports multiple modules)

### Network Communication

All network requests go to legitimate Diigo services:
- `https://www.diigo.com/*` - Main API endpoints
- `https://toolbar3.diigo.com/*` - Toolbar assets (referenced in CSP)
- `https://api.bit.ly/shorten` - URL shortening (uses Diigo's API key: `R_051efe0ca04a325db066155db77c2d08`)

**Key Finding:** No remote config endpoints, no third-party analytics beyond Google Analytics.

### Cookie Access Pattern

**bg2.js:676-678, 1037, 1587, 2086-2108**
```javascript
chrome.cookies.get({
  url: "https://www.diigo.com",
  name: "diigoandlogincookie"
}, function(c) {
  // Extract username for authentication
})
```
**Assessment:** Cookie access is scoped to diigo.com only. Used for authentication state management. No cookie harvesting detected.

### Cross-Extension Communication

**extensionmessage.js:4-52** - Hardcoded extension IDs for Diigo's own extension family:
```javascript
RLF_ID = "decdfngdidijkdjgbknlnepdljfaepji"  // Research Library
AW_ID = "alelhddbbhepgpmgidjdcjakblofbmce"   // Awesome Screenshot
QN_ID = "mijlebbfndhelmdnpmllgcfadlkankhok"  // Quick Notes
DIIGO_ID = "oojbgadfejifecebmdnhhkbhdjaphole"
```

Functions: `sendsettingtoother()`, `getsettingformother()`

**Assessment:** This communicates only with Diigo's own extensions to sync settings (SearchO feature toggle). Not malicious extension enumeration. Uses `chrome.runtime.sendMessage(EXTENSION_ID, ...)` which only succeeds if extension is installed. No broad enumeration attempts.

### Twitter OAuth Integration

**twitter.js:572-803** - Full OAuth 1.0a implementation for Twitter sharing:
```javascript
comsuerKey: "jPjTPeXVlxhx5Zqw3uTmGw"
consumerSecret: "eLOSDUs7aHHn4p1ocSYz2xRUVNUfkDSjtf2DQlKUY"
```

**Assessment:** Standard OAuth flow. Credentials stored with ROT13 obfuscation (weak but not malicious). User-initiated Twitter sharing feature.

### Analytics & Telemetry

**bg2.js:2077-2080**
```javascript
function sendAnalysisData(a) {
  fetch("https://www.diigo.com/stats", {
    method: "POST",
    body: JSON.stringify(a)
  })
}
```

**onInstalled handler (2083-2118)** sends:
- Extension version
- Previous version (for upgrade tracking)
- Whether user has visited diigo.com (cookie check)

**Assessment:** Standard installation analytics. No PII beyond version tracking.

## Content Script Analysis

### Main Injection Points

**manifest.json:48-68** - Content scripts run on all pages:
- `js/jquery-1.8.0.min.js` - jQuery 1.8.0 (outdated but not malicious)
- `js/content/main.js` - Empty stub file (1 line)
- `js/content/diigolet.js` - Main annotation UI (9,972 lines)
- `js/content/dragresize.js` - Resizable UI elements

### DOM Manipulation

**diigolet.js** contains extensive DOM manipulation for annotation features:
- Highlighting text selections
- Adding sticky notes
- Canvas-based annotation rendering
- Floating toolbar injection

**Assessment:** All DOM manipulation is for legitimate annotation UI. No ad injection, no form field manipulation, no input interception.

### Keyboard Event Listeners

**comboSearch.js, diigolet.js** - Keyboard shortcuts for activating annotation tools.

**Assessment:** Standard UI shortcuts. No keylogger behavior - events are not captured or sent to server. FP pattern from Floating UI focus trapping rules out as false positive.

### Search Integration Feature

**comboSearch.js:1-167** - "ComboSearch" feature:
- Detects Google/Bing/Yahoo search pages
- Extracts search query from URL parameters
- Injects Diigo search results sidebar
- Uses `chrome.scripting.insertCSS` and `executeScript`

**Assessment:** Legitimate feature to show user's Diigo bookmarks alongside search results. No search hijacking - only augments existing results. User can disable via settings.

## XHR/Fetch Hook Analysis

**No XHR/fetch prototype patching detected.** All fetch calls are direct API requests:
- `bg2.js:1253` - bit.ly URL shortening
- `bg2.js:1401` - Page archive upload
- `bg2.js:1861, 1948` - Image/screenshot processing
- `bg2.js:2007, 2077` - Diigo API calls

**Assessment:** No interception framework like Sensor Tower Pathmatics, no response harvesting. Clean.

## Dynamic Code Execution

**Grep results show 34 files with innerHTML/eval/Function:**
- jQuery 1.8.0 contains standard dynamic code for animation parsing
- Readability.js (content extraction library) uses innerHTML for DOM cleaning
- ZeroClipboard (deprecated Flash clipboard library) uses eval for legacy support
- jquery-ui uses innerHTML for widget rendering

**Assessment:** All dynamic code is in third-party libraries for legitimate purposes. No runtime eval of remote code detected.

## Third-Party Integrations

### Google Analytics
Included in CSP for basic usage tracking. Standard implementation.

### Google Drive API
OAuth2 read-only access for importing documents to annotate. User consent required.

### Twitter API
OAuth 1.0a for sharing annotations. User-initiated.

### Bit.ly API
URL shortening for shared bookmarks. Uses Diigo's API key, not user data exfiltration.

## Privacy Concerns (Informational)

### Data Sent to Diigo Servers:
1. **Annotations & Highlights** - Stored on Diigo's servers (core feature)
2. **Bookmarked URLs** - For synchronization across devices
3. **Page snapshots** (pageCapture permission) - Full page archives uploaded
4. **Search queries** (ComboSearch feature) - To match against user's bookmarks

### Local Storage:
- User preferences
- Cached annotations
- Twitter OAuth tokens (ROT13 encoded)

**Assessment:** All data collection is disclosed in Diigo's service model (social bookmarking/annotation platform). No covert data harvesting.

## False Positives Ruled Out

✅ **No Sensor Tower/Pathmatics SDK** - Grep for "Sensor Tower", "Pathmatics", "ad-finder" returned no results
✅ **No AI Conversation Scraping** - No targeting of ChatGPT/Claude/Gemini/Copilot domains
✅ **No Market Intelligence SDKs** - No ad creative interception patterns
✅ **No Residential Proxy Infrastructure** - No PAC files, no SOCKS proxy setup
✅ **No Extension Enumeration** - Only communicates with 3 known Diigo extensions for settings sync
✅ **No XHR/Fetch Hooking** - No prototype patching detected
✅ **No Remote Kill Switch** - No remote configuration endpoints
✅ **No Cookie Harvesting** - Cookie access scoped to diigo.com authentication only

## Known Vulnerabilities

### 1. Outdated jQuery (1.8.0)
**Severity:** Medium
**Issue:** jQuery 1.8.0 (released 2012) has known XSS vulnerabilities
**Impact:** Could allow XSS if malicious data passed to jQuery DOM methods
**Recommendation:** Upgrade to jQuery 3.x

### 2. Weak OAuth Token Storage
**Severity:** Low
**Issue:** Twitter OAuth tokens stored with ROT13 obfuscation (trivially reversible)
**Impact:** Malicious extension could steal Twitter access tokens from storage
**Recommendation:** Use Chrome's secure storage APIs or encrypt with user-derived key

### 3. Bit.ly API Key Hardcoded
**Severity:** Low
**Issue:** Diigo's bit.ly API key visible in source: `R_051efe0ca04a325db066155db77c2d08`
**Impact:** Could be abused for rate-limit exhaustion or tracking Diigo-shortened URLs
**Recommendation:** Move to server-side URL shortening

## Comparison to Known Threats

### vs. Urban VPN (HIGH RISK)
- Urban VPN: XHR/fetch hooking on all pages, social media data harvesting
- Diigo: No hooking, only annotation data sent to own service ✅

### vs. StayFree/StayFocusd (MED-HIGH RISK)
- StayFree: Sensor Tower Pathmatics SDK, AI conversation scraping
- Diigo: No market intelligence SDKs, no conversation scraping ✅

### vs. VeePN (MED-HIGH RISK)
- VeePN: Extension enumeration + killing, GA IP unmasking
- Diigo: Only communicates with own extensions for settings sync ✅

## Conclusion

**Diigo Web Collector is CLEAN.** This is a legitimate annotation and bookmarking tool with no evidence of:
- Malicious data harvesting beyond its disclosed functionality
- Third-party SDKs for market intelligence or ad tracking
- Extension interference or proxy infrastructure
- AI conversation scraping or covert behavior modification

The extension does have broad permissions (`<all_urls>`, `pageCapture`) but these are necessary for its core annotation functionality and align with its stated purpose.

**Risk Level: LOW**

**Recommendation:** Safe to use. Users should be aware that annotations and page snapshots are uploaded to Diigo's servers as part of the service model. Consider updating jQuery dependency.

---

## Technical Indicators

| Indicator | Status |
|-----------|--------|
| XHR/Fetch Hooking | ❌ Not present |
| Extension Enumeration | ⚠️ Limited (3 own extensions) |
| Cookie Harvesting | ❌ Not present |
| AI Conversation Scraping | ❌ Not present |
| Market Intelligence SDK | ❌ Not present |
| Remote Config/Kill Switch | ❌ Not present |
| Residential Proxy | ❌ Not present |
| Dynamic Code Injection | ⚠️ Only in third-party libs |
| Obfuscated Code | ❌ Not present |
| Suspicious Domains | ❌ Not present |

**Files Analyzed:** 100+ JavaScript files, manifest.json, CSP, OAuth configs
**Lines of Code:** ~20,000+ (including libraries)
**Primary Backend:** diigo.com (legitimate service since 2006)
