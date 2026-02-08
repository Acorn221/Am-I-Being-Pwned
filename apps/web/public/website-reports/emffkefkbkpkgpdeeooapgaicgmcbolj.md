# Security Analysis Report: Wikiwand - Elevate Wikipedia with AI

## Extension Metadata
- **Extension ID**: emffkefkbkpkgpdeeooapgaicgmcbolj
- **Name**: Wikiwand - Elevate Wikipedia with AI
- **Version**: 10.1.0
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-06

## Executive Summary

Wikiwand is an extremely lightweight Wikipedia enhancement extension that redirects Wikipedia pages to Wikiwand's formatted website. The extension contains **only 118 lines of clean, readable JavaScript** with minimal permissions and no content scripts. After comprehensive analysis, this extension demonstrates **exemplary security practices** and poses **no security risk** to users.

The entire codebase consists of a single service worker that:
1. Intercepts Wikipedia navigation to redirect to Wikiwand.com
2. Adds a context menu for searching selected text
3. Opens welcome/update tabs on install/update
4. Allows Wikiwand.com to detect extension installation

**No malicious behavior, data collection, tracking, or privacy violations were found.**

## Manifest Analysis

### Permissions (Minimal)
```json
"permissions": ["webNavigation", "contextMenus"]
```

- **webNavigation**: Used solely to intercept Wikipedia URLs for redirection
- **contextMenus**: Creates "Search in Wikiwand" right-click menu
- **NO** storage, cookies, history, tabs (read), webRequest, or management permissions
- **NO** host permissions (does not inject content scripts)

### Externally Connectable (Transparent)
```json
"externally_connectable": {
  "matches": ["*://localhost/*", "https://*.wikiwand.com/*"]
}
```

**Purpose**: Allows Wikiwand.com website to detect if extension is installed
**Implementation**: Simple `isInstalled` message handler (lines 29-44)
**Risk**: NONE - read-only detection, no data exchange

### Content Security Policy
- **No custom CSP defined** - uses MV3 defaults (secure)
- **No inline scripts** possible
- **No eval/Function()** in codebase

### Web Accessible Resources
```json
"web_accessible_resources": [{
  "resources": ["web-accessible-resources/*"],
  "matches": ["https://*.wikiwand.com/*"]
}]
```

**Contents**: Single icon file (icon-16x16.png)
**Risk**: NONE - cosmetic resource only

## Code Analysis

### Service Worker (`service-worker.js` - 118 lines)

#### Core Functionality

**1. Wikipedia URL Interception (lines 52-96)**
```javascript
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  // Intercepts wikipedia.org, wikiquote.org, wiktionary.org
  // Redirects to https://www.wikiwand.com/{lang}/{bucket}/{title}
}, filter);
```
- Filters: `.wikipedia.org|.wikiquote.org|.wiktionary.org`
- Respects `oldformat=true` parameter (skips redirect)
- Handles Google redirect URLs (`www.google.com/url?url=...`)
- Clean URL parsing with no exfiltration

**2. Context Menu Search (lines 104-118)**
```javascript
chrome.contextMenus.onClicked.addListener(getSelection);
async function getSelection({ selectionText, menuItemId }, tab) {
  const url = new URL(`https://www.wikiwand.com/${lang}/search`);
  url.searchParams.append("q", selectionText);
  chrome.tabs.create({ url: url.toString() });
}
```
- Creates search URL with selected text
- Uses browser language for localization
- No text exfiltration or tracking

**3. Install/Update Handlers (lines 10-27)**
```javascript
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason == "install") {
    chrome.tabs.create({ url: "https://www.wikiwand.com?extension=installed" });
    chrome.runtime.setUninstallURL("https://forms.gle/5TMJSzNEJLJrgXRE7");
  }
  if (details.reason == "update") {
    chrome.tabs.create({ url: "https://www.wikiwand.com?extension=update" });
  }
});
```
- Opens welcome/update pages (standard UX pattern)
- Uninstall feedback form (Google Forms - not tracking)

**4. Extension Detection (lines 29-44)**
```javascript
chrome.runtime.onMessageExternal.addListener(function (request, sender, sendResponse) {
  if (request.message == "isInstalled") {
    sendResponse({ isInstalled: true });
  }
  return true;
});
```
- Simple presence detection for Wikiwand.com
- No data collection or telemetry

### Network Activity Analysis

**All Network Calls**:
1. `https://www.wikiwand.com` - redirected Wikipedia pages
2. `https://www.wikiwand.com/{lang}/search?q={query}` - context menu search
3. `https://forms.gle/5TMJSzNEJLJrgXRE7` - uninstall survey (user-initiated)

**Zero Background Telemetry**:
- No analytics SDKs (Google Analytics, Mixpanel, Sentry, etc.)
- No tracking pixels or beacons
- No XHR/fetch calls from extension code
- No third-party API endpoints

### Data Collection Analysis

**User Data Accessed**: NONE
- No chrome.storage (no local data storage)
- No chrome.cookies (no cookie access)
- No chrome.history (no browsing history)
- No chrome.tabs.query (no tab enumeration)
- No document.querySelector (no DOM scraping - no content scripts)

**User Data Transmitted**: NONE
- Selected text sent to Wikiwand search (user-initiated action only)
- No background data exfiltration
- No behavioral tracking
- No fingerprinting

### Malicious Pattern Check

| Pattern | Found | Details |
|---------|-------|---------|
| XHR/Fetch Hooking | NO | Zero fetch/XMLHttpRequest references |
| Extension Enumeration | NO | No chrome.management API usage |
| Extension Killing | NO | No setEnabled calls |
| Residential Proxy | NO | No proxy configuration |
| Remote Config/Kill Switch | NO | No dynamic code loading |
| Market Intelligence SDK | NO | No Sensor Tower/Pathmatics/similar |
| AI Conversation Scraping | NO | No content scripts at all |
| Ad/Coupon Injection | NO | No DOM manipulation |
| Keylogger/Input Monitoring | NO | No addEventListener in codebase |
| Cookie Harvesting | NO | No cookie permissions or access |
| Obfuscation | NO | Clean, readable code |
| eval/Function() | NO | No dynamic code execution |
| Hardcoded Secrets | NO | No API keys or tokens |

## Vulnerability Assessment

### FINDINGS: ZERO VULNERABILITIES

No security vulnerabilities, privacy violations, or malicious behavior detected.

## False Positives

No false positive patterns triggered. Extension is genuinely clean.

## API Endpoints

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://www.wikiwand.com | Wikipedia redirect destination | URL parameters (lang, article title) | NONE - user navigation |
| https://www.wikiwand.com/{lang}/search | Context menu search | Selected text query | NONE - user-initiated |
| https://forms.gle/5TMJSzNEJLJrgXRE7 | Uninstall feedback survey | User-submitted feedback (optional) | NONE - Google Forms |

## Data Flow Summary

```
User visits Wikipedia page
  ↓
Extension intercepts navigation (chrome.webNavigation)
  ↓
Redirects to https://www.wikiwand.com/{lang}/articles/{title}
  ↓
User browses Wikiwand (no extension involvement)

[Alternative Flow]
User right-clicks selected text → "Search in Wikiwand"
  ↓
Opens https://www.wikiwand.com/{lang}/search?q={selected_text}
```

**No data leaves user's browser except through user-initiated navigation.**

## Code Quality Assessment

**Exceptional**:
- Clean, well-structured code
- No obfuscation or minification (beyond standard bundling)
- Commented debugging statements left in (transparency)
- Minimal dependencies (zero third-party libraries)
- Efficient implementation (118 lines for entire extension)
- No dead code or unused permissions

## Privacy Analysis

**Data Collection**: NONE
**Third-Party Sharing**: NONE
**Tracking**: NONE
**Consent Mechanisms**: N/A (no data collection)

The extension acts purely as a URL redirector. All user interaction happens on Wikiwand's website, outside extension's scope.

## Comparison to Known Malicious Extensions

Unlike malicious extensions in this research project:

| Malicious Pattern | Wikiwand | Typical Malicious Extension |
|-------------------|----------|----------------------------|
| Extension Killing | NO | VeePN, Troywell, Urban VPN, YouBoost |
| XHR/Fetch Hooking | NO | StayFree, StayFocusd (Sensor Tower SDK) |
| AI Conversation Scraping | NO | StayFree, StayFocusd, Flash Copilot |
| Ad Injection | NO | YouBoost, Troywell (CityAds) |
| Residential Proxy | NO | Troywell |
| Remote Kill Switch | NO | Troywell ("thanos"), YouBoost |
| Analytics SDKs | NO | Most commercial extensions |
| Cookie Harvesting | NO | Urban VPN |
| Content Script Injection | NO | Almost all malicious extensions |

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

### Justification
1. **Minimal Attack Surface**: 118 lines of code, 2 permissions, 0 content scripts
2. **Transparent Behavior**: URL redirection is explicit and matches extension description
3. **Zero Data Collection**: No storage, cookies, history, or network telemetry
4. **No Third-Party Code**: No SDKs, libraries, or external dependencies
5. **Legitimate Business Model**: Redirects to Wikiwand.com (their own service)
6. **User Control**: Extension can be disabled/removed without side effects
7. **No Obfuscation**: Clean, auditable code

### Recommendations
- **For Users**: Safe to use. Extension does exactly what it claims.
- **For Researchers**: Excellent example of minimal, well-scoped extension.
- **For Developers**: Reference implementation for simple redirect extensions.

## Conclusion

Wikiwand represents the **gold standard** for browser extension security:
- **Principle of Least Privilege**: Only requests necessary permissions
- **Transparency**: Code behavior matches user expectations
- **Privacy by Design**: No data collection infrastructure
- **Simplicity**: Minimal codebase reduces vulnerability surface

**This extension poses zero security or privacy risk to users.**

---

**Analyst Notes**: This is the cleanest extension analyzed in the entire CWS research project. No further investigation needed.
