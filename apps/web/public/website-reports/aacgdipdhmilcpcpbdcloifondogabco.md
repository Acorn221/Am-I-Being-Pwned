# Security Analysis: Url Shortener for Google Chrome

**Extension ID:** aacgdipdhmilcpcpbdcloifondogabco
**User Count:** ~200,000
**Version Analyzed:** 3.0.0
**Analysis Date:** 2026-02-06
**Overall Risk:** CLEAN

---

## Executive Summary

The Url Shortener for Google Chrome extension is a **CLEAN** extension with no significant security vulnerabilities. It provides a straightforward URL shortening service using the TinyURL API and Google Charts API for QR code generation. The extension follows secure development practices with minimal permissions, no content scripts, and transparent functionality.

---

## Manifest Analysis

### Permissions Audit

```json
"permissions": [
    "activeTab",
    "storage"
]
```

**Assessment:** Minimal and appropriate permissions.
- `activeTab`: Required to get the current tab URL for shortening
- `storage`: Used only for theme preference (day/night mode) and install timestamp

### Host Permissions

```json
"host_permissions": [
    "https://chart.googleapis.com/*",
    "https://tinyurl.com/*"
]
```

**Assessment:** Legitimate and transparent.
- `chart.googleapis.com`: Used for QR code generation
- `tinyurl.com`: Official TinyURL API endpoint for URL shortening

### Content Security Policy

**Status:** Uses Manifest V3 defaults (no custom CSP defined)

**Assessment:** Secure. No dangerous directives present.

### Additional Manifest Attributes

- **No content_scripts**: Extension has no content script injection
- **No web_accessible_resources**: No resources exposed to web pages
- **No externally_connectable**: No external website communication allowed
- **Background worker**: Simple service worker with minimal functionality

---

## Architecture Analysis

### File Structure

```
├── manifest.json
├── js/
│   ├── bg-worker.js          # Service worker entry point
│   └── welcome.js            # Welcome/uninstall page handler
├── data/
│   ├── background.js         # Main background logic
│   ├── popup/index.html      # Popup UI
│   ├── js/
│   │   ├── popup.js          # Popup functionality
│   │   └── rate.js           # Rating link generation
│   ├── libs/
│   │   ├── jquery.js         # jQuery 3.2.1
│   │   ├── info.js           # UAParser.js library
│   │   ├── lazyload.js       # Image lazy loading
│   │   └── Localize.js       # i18n helper
│   └── mdl/
│       └── material.min.js   # Material Design Lite
```

**Total Files:** 57 (46 locale files, 11 functional files)

---

## Code Analysis

### Background Scripts

#### 1. Service Worker (`js/bg-worker.js`)

```javascript
importScripts("/js/welcome.js");
importScripts("/data/background.js");
```

**Assessment:** Minimal and secure. Only imports two scripts.

#### 2. Welcome Page Handler (`js/welcome.js`)

**Functionality:**
- Opens welcome page on install (`homepage_url/welcome`)
- Sets uninstall URL (`homepage_url/uninstall`)

**Network Calls:** None (uses manifest homepage_url)

**Assessment:** Standard welcome/uninstall flow. No suspicious behavior.

#### 3. Main Background Logic (`data/background.js`)

**Functionality:**
- Stores install timestamp in `chrome.storage.sync`
- Sets default theme to "day"
- Opens popup in new tab when action clicked

**Storage Usage:**
```javascript
chrome.storage.sync.set({
    currentTheme: "day",
    di: (new Date()).getTime()  // install timestamp
});
```

**Assessment:** Minimal data collection. No PII stored. No network calls.

### Popup Scripts

#### 1. Main Popup Logic (`data/js/popup.js`)

**Core Functionality:**

```javascript
// Get current tab URL
chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
    const tab = tabs[0];
    var longUrl = tab.url;
    // ... process URL
});

// Shorten URL via TinyURL API
const apiUrl = `https://tinyurl.com/api-create.php?sclient=gws-wiz&url=` +
    encodeURIComponent(longUrl);

const res = await fetch(apiUrl, { method: "GET" });
const alias = await res.text();

// Generate QR code
var qr_code = 'https://chart.googleapis.com/chart?cht=qr&chs=300x300&choe=UTF-8&chld=H&chl=' + alias;
```

**Network Endpoints:**
1. `https://tinyurl.com/api-create.php` - URL shortening (public API)
2. `https://chart.googleapis.com/chart` - QR code generation (Google service)

**Data Handling:**
- Gets active tab URL using `activeTab` permission
- Sends URL to TinyURL API (standard service behavior)
- Generates QR code via Google Charts API
- No data sent to developer's servers

**Assessment:** Transparent functionality. All network calls are to legitimate, public APIs. No data exfiltration.

#### 2. Rating Link (`data/js/rate.js`)

```javascript
const storeUrl = (updateUrl && updateUrl.includes("microsoft")) ?
    `https://microsoftedge.microsoft.com/addons/detail/` + id :
    `https://chrome.google.com/webstore/detail/${id}/reviews`;
```

**Assessment:** Standard rating link. No tracking or analytics.

### Third-Party Libraries

1. **jQuery 3.2.1** - Standard DOM manipulation library
2. **Material Design Lite** - Google's UI framework
3. **UAParser.js v0.7.20** - User agent parsing (unused in codebase)
4. **LazyLoad 2.0.0-beta.2** - Image lazy loading library

**Assessment:** All legitimate open-source libraries. No modifications detected.

---

## Threat Assessment

### ✅ CLEAN - No Issues Found

#### Extension Enumeration/Killing
- **Status:** Not present
- No `chrome.management` API usage
- No extension disabling functionality

#### XHR/Fetch Hooking
- **Status:** Not present
- Standard `fetch()` usage for legitimate API calls only
- No monkey-patching of network primitives

#### Market Intelligence SDKs
- **Status:** Not present
- No Sensor Tower, Pathmatics, or similar tracking SDKs
- No conversation scraping or ad harvesting

#### Ad/Coupon Injection
- **Status:** Not present
- No content scripts
- No DOM manipulation on web pages

#### Remote Configuration
- **Status:** Not present
- No remote code loading
- No dynamic behavior changes

#### Data Exfiltration
- **Status:** Not present
- No developer-controlled servers
- All data sent to public, documented APIs (TinyURL, Google Charts)
- No analytics or tracking

#### Cookie/Credential Harvesting
- **Status:** Not present
- No `chrome.cookies` API usage
- No credential access

#### Obfuscation
- **Status:** Not present
- Code is readable and well-structured
- Material Design Lite is minified (standard library)

#### Dynamic Code Execution
- **Status:** Not present
- No `eval()` or `Function()` constructors
- No dynamic script injection

---

## Privacy Analysis

### Data Collection

**User Data Collected:**
1. **Theme preference** (day/night mode) - stored locally in `chrome.storage.sync`
2. **Install timestamp** - stored locally in `chrome.storage.sync`

**URLs Processed:**
- Current tab URL is sent to TinyURL API for shortening
- This is the expected and documented behavior of the extension

**Third-Party Data Sharing:**
- TinyURL receives user-provided URLs (standard URL shortening service)
- Google Charts API receives shortened URLs for QR code generation
- No other third-party data sharing

### Network Activity

**All Network Calls:**

1. **TinyURL API:**
   - Endpoint: `https://tinyurl.com/api-create.php?sclient=gws-wiz&url=<encoded_url>`
   - Method: GET
   - Purpose: URL shortening
   - Data sent: User's current tab URL

2. **Google Charts API:**
   - Endpoint: `https://chart.googleapis.com/chart?cht=qr&chs=300x300&choe=UTF-8&chld=H&chl=<shortened_url>`
   - Method: GET (via img src)
   - Purpose: QR code generation
   - Data sent: Shortened URL

3. **Welcome/Uninstall Pages:**
   - Base URL: `https://url-shortener.freebusinessapps.net/`
   - Only opened on install/uninstall (user notification)

**Assessment:** All network activity is transparent and necessary for core functionality.

---

## Comparison to Known Malicious Patterns

### Pattern Checklist

| Pattern | Present | Notes |
|---------|---------|-------|
| Extension enumeration | ❌ No | No `chrome.management` usage |
| Extension disabling | ❌ No | No competitive extension killing |
| XHR/fetch hooking | ❌ No | Only standard fetch usage |
| Residential proxy infrastructure | ❌ No | No proxy functionality |
| Market intelligence SDKs | ❌ No | No Sensor Tower, Pathmatics, etc. |
| AI conversation scraping | ❌ No | No content scripts at all |
| Chatbot scraping | ❌ No | No widget monitoring |
| Ad injection | ❌ No | No content scripts or DOM access |
| Coupon injection | ❌ No | No e-commerce manipulation |
| Remote config/kill switches | ❌ No | No remote code loading |
| Hardcoded secrets | ❌ No | No API keys or tokens |
| Beacon exfiltration | ❌ No | No analytics beacons |
| Session token theft | ❌ No | No cookie/storage access |
| Screenshot capture | ❌ No | No `chrome.tabs.captureVisibleTab` |
| Browsing history collection | ❌ No | No `chrome.history` permission |

---

## False Positive Analysis

### Patterns That Could Trigger Alerts

1. **Material Design Lite "OBFUSCATOR":**
   - **Pattern:** References to "obfuscator" in code
   - **Reality:** Material Design Lite drawer overlay CSS class
   - **Assessment:** False positive - standard UI component naming

2. **jQuery XHR References:**
   - **Pattern:** `XMLHttpRequest`, `.send()` in jquery.js
   - **Reality:** Standard jQuery AJAX implementation
   - **Assessment:** False positive - unmodified library code

3. **UAParser.js Library:**
   - **Pattern:** User agent parsing
   - **Reality:** Unused library (imported but not invoked)
   - **Assessment:** Dead code - no privacy concern

---

## Developer Attribution

**Homepage:** https://url-shortener.freebusinessapps.net
**Publisher:** Not specified in manifest (individual developer)
**Chrome Web Store:** https://chrome.google.com/webstore/detail/aacgdipdhmilcpcpbdcloifondogabco

---

## Recommendations

### For Users
✅ **SAFE TO USE** - This extension operates as advertised with no hidden functionality.

**Privacy Considerations:**
- URLs you shorten are sent to TinyURL (expected behavior)
- QR codes are generated via Google Charts API
- No browsing history or other data is collected

### For Developers
**Best Practices Observed:**
- ✅ Minimal permissions (only what's needed)
- ✅ Manifest V3 compliance
- ✅ No content script injection
- ✅ Transparent network calls to documented APIs
- ✅ Clean, readable code

**Minor Improvements:**
- Remove unused UAParser.js library to reduce extension size
- Consider adding Content Security Policy to manifest for extra hardening
- Document privacy policy on extension homepage

---

## Technical Details

### Permissions Justification

| Permission | Purpose | Necessary |
|------------|---------|-----------|
| activeTab | Get current tab URL for shortening | ✅ Yes |
| storage | Store theme preference | ✅ Yes |
| chart.googleapis.com | Generate QR codes | ✅ Yes |
| tinyurl.com | Shorten URLs via API | ✅ Yes |

### Chrome APIs Used

- `chrome.runtime.getManifest()` - Read manifest data
- `chrome.runtime.onInstalled` - Detect installation
- `chrome.runtime.setUninstallURL()` - Set uninstall page
- `chrome.tabs.create()` - Open welcome page / popup in tab
- `chrome.tabs.query()` - Get active tab URL
- `chrome.storage.sync.get/set()` - Store theme preference
- `chrome.action.onClicked` - Handle toolbar button click
- `chrome.i18n.getMessage()` - Localization

**Assessment:** All API usage is appropriate and necessary.

### Code Quality

- **Lines of Code:** ~500 (excluding libraries)
- **Complexity:** Low
- **Readability:** High
- **Obfuscation:** None (except minified MDL library)
- **Comments:** Minimal but adequate
- **Error Handling:** Basic try/catch present in API calls

---

## Verification Steps Performed

1. ✅ Manifest permission analysis
2. ✅ Background script review
3. ✅ Popup script analysis
4. ✅ Network endpoint identification
5. ✅ Third-party library audit
6. ✅ Data flow analysis
7. ✅ Chrome API usage review
8. ✅ Content script check (none present)
9. ✅ Dynamic code execution check (none present)
10. ✅ Obfuscation analysis (clean)

---

## Conclusion

**VERDICT: CLEAN**

The Url Shortener for Google Chrome extension is a legitimate, transparent tool that performs exactly as described. It uses minimal permissions, makes network calls only to documented public APIs (TinyURL and Google Charts), and contains no malicious or deceptive functionality.

**Risk Level:** LOW
**Recommendation:** SAFE FOR INSTALLATION
**Confidence:** HIGH

This extension exemplifies good extension development practices with:
- Minimal permission requests
- Transparent functionality
- No hidden data collection
- Clean, readable code
- Manifest V3 compliance

No security issues or privacy concerns were identified during this analysis.

---

**Analyst Notes:**

This is a textbook example of a clean extension. Unlike the malicious VPN extensions and productivity tools previously analyzed (Urban VPN, StayFree, StayFocusd with Sensor Tower SDKs), this extension:
- Has no content scripts
- Doesn't enumerate or disable other extensions
- Doesn't hook XHR/fetch on web pages
- Doesn't collect browsing data
- Doesn't communicate with developer-controlled servers
- Uses only public, documented APIs

The only data "leakage" is the intentional sending of URLs to TinyURL for shortening, which is the core functionality users expect.
