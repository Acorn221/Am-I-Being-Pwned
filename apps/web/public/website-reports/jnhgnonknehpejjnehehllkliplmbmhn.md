# Security Analysis Report: Web Scraper - Free Web Scraping

## Extension Metadata
- **Extension ID**: jnhgnonknehpejjnehehllkliplmbmhn
- **Name**: Web Scraper - Free Web Scraping
- **Version**: 1.106.7
- **Estimated Users**: ~800,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-06

## Executive Summary

Web Scraper is a **CLEAN** extension with legitimate web scraping functionality. The extension provides a point-and-click interface for extracting data from websites via DevTools panel integration. While it has broad permissions and collects usage telemetry, all data collection is **opt-in**, sent to legitimate first-party domains, and appears to serve legitimate product improvement purposes. No malicious behavior, data harvesting, or third-party tracking SDKs were identified.

**Overall Risk Level**: **CLEAN**

The extension operates transparently, all network communications are to webscraper.io domains, and there is no evidence of malicious intent or privacy violations.

---

## Vulnerability Assessment

### 1. Usage Statistics Collection
**Severity**: LOW (Benign Analytics)
**Files**: `background_script.js` (lines 10088-10400)
**Status**: ✅ CLEAN - Opt-in telemetry for product improvement

**Details**:
The extension collects anonymous usage statistics sent to `https://stats.webscraper.io/post-stats` every 3 days. Collection is controlled by user preference:

```javascript
// Stats only collected if user enables it
if (!(yield o.Config.get("enableDailyStats"))) return;

// Data collected includes:
{
    statId: "<random-60-char-id>",
    extensionId: chrome.runtime.id,
    extensionVersion: "1.106.7",
    scrapingJobsRun: 0,
    pagesScraped: 0,
    sitemapsCreated: 0,
    sitemapsDeleted: 0,
    sitemapsImported: 0,
    webScraperOpened: false,
    webScraperUsageMinutes: 0,
    selectorCountPerSitemap: {...},
    selectorUsageCount: {...}
}
```

**Verdict**: ✅ **FALSE POSITIVE** - This is legitimate opt-in analytics. The data is aggregated usage metrics (sitemap counts, selector types used) with no PII, browsing history, or scraped data. Users can disable via `enableDailyStats` config option.

---

### 2. XHR/Fetch Request Interception (WebRequest API)
**Severity**: LOW (Legitimate Scraping Feature)
**Files**: `background_script.js` (lines 18670-18748)
**Status**: ✅ CLEAN - Required for scraping XMLHttpRequest responses

**Details**:
The extension uses `chrome.webRequest` API to intercept AJAX requests on scraped pages:

```javascript
// TabNetworkRequestListener intercepts XMLHttpRequests only
chrome.webRequest.onBeforeRequest.addListener(this.onBeforeRequestListener, {
    urls: [ "<all_urls>" ],
    tabId: e,
    types: [ "xmlhttprequest" ]  // Only XHR, not main_frame or sub_frame
}, [ "requestBody" ]);

chrome.webRequest.onCompleted.addListener(this.onCompletedListener, t, [ "responseHeaders" ]);
```

The intercepted requests are **replayed** (re-fetched) to extract JSON data for scraping purposes:

```javascript
// Replays captured XHR requests to extract API responses
const r = yield fetch(e.url, {
    method: e.method,
    body: "post" === e.method.toLowerCase() ? e.body : void 0,
    cache: "force-cache",
    headers: t,
    signal: AbortSignal.timeout(30 * s.TIME.ONE_SECOND_MS)
});
```

**Verdict**: ✅ **FALSE POSITIVE** - This is a legitimate scraping feature. Modern SPAs load data via AJAX, so the extension needs to intercept XHR to scrape dynamic content. The requests are only replayed (not modified), limited to the active scraping tab (`tabId: e`), and not exfiltrated. This is the core functionality of a web scraper.

---

### 3. Content Script Injection
**Severity**: LOW (Required for UI Overlay)
**Files**: `background_script.js` (lines 12783-12800)
**Status**: ✅ CLEAN - Injects UI for element selection

**Details**:
The extension injects content scripts on all pages to provide the scraping interface:

```javascript
static injectContentScriptInTab(e) {
    if ("about:blank" !== e.url) try {
        yield chrome.scripting.executeScript({
            target: { tabId: e.id },
            files: [ "content_script.js" ],
            injectImmediately: !0
        });
        yield chrome.scripting.insertCSS({
            target: { tabId: e.id },
            files: [ "content_script.css" ]
        });
    } catch (e) {}
}
```

The content script provides:
- Visual element highlighting (SVG overlays)
- Point-and-click selector generation
- Element preview UI

**Verdict**: ✅ **CLEAN** - The content script only adds UI overlays for element selection. It does not scrape data autonomously, log keystrokes, or exfiltrate information. The `content_script.js` (19,803 lines) is primarily React UI code with MobX state management.

---

### 4. Cloud Sync Authentication
**Severity**: LOW (Opt-in Premium Feature)
**Files**: `background_script.js` (lines 10660, 10855-10943, 11082-11106)
**Status**: ✅ CLEAN - Secure token storage for cloud features

**Details**:
The extension offers optional cloud sync via `cloud.webscraper.io`:

```javascript
// Opens auth page for cloud sync
const t = `https://cloud.webscraper.io/extension-api-auth?extension_id=${chrome.runtime.id}`;

// Stores auth token in chrome.storage.local (encrypted by Chrome)
static addToken(e) {
    yield i.ChromeStorageLocal.set("extensionAPIToken", e.wsAuthToken);
}

// API calls include token as query param
n.search = new URLSearchParams({
    extension_api_token: r
}).toString();
```

**Verdict**: ✅ **CLEAN** - This is an optional premium feature. The token is stored in `chrome.storage.local` (encrypted by browser), only used for authenticating sitemap sync API calls, and can be removed via `disconnectFromCloud()`. No evidence of token abuse.

---

### 5. Broad Host Permissions
**Severity**: LOW (Required for Scraping)
**Files**: `manifest.json` (line 48)
**Status**: ✅ JUSTIFIED - Necessary for universal scraper

**Details**:
```json
"host_permissions": ["<all_urls>"]
```

**Verdict**: ✅ **JUSTIFIED** - A web scraper by definition must work on any website. The extension only activates when the user explicitly opens the DevTools panel and creates a sitemap. No background scraping occurs.

---

### 6. Declarative Net Request for Redirects
**Severity**: LOW (Link Extraction Feature)
**Files**: `background_script.js` (lines 11365-11372, 18619-18622)
**Status**: ✅ CLEAN - Used for following redirects during scraping

**Details**:
```javascript
chrome.declarativeNetRequest.updateDynamicRules(e, (() => {...}));
chrome.declarativeNetRequest.updateSessionRules(e, (() => {...}));
```

Used to track redirect chains when scraping links (e.g., shortened URLs, tracking links).

**Verdict**: ✅ **CLEAN** - This is a legitimate feature for link scraping. Rules are dynamically added/removed during scraping sessions only.

---

## False Positives Analysis

| Pattern | Files | Reason | Verdict |
|---------|-------|--------|---------|
| **MobX `trackingDerivation`** | `content_script.js`, `devtools_panel.js`, `sidepanel.js`, `scraper.js` | State management library for React UI (MobX 6) | ✅ FP - Framework code |
| **bcrypt library** | `background_script.js` (lines 6-196) | Used for password hashing in sitemap website login automation feature | ✅ FP - Security library |
| **CryptoJS** | `content_script.js` (lines 5-190) | Used for hashing/encoding scraped data locally | ✅ FP - Crypto library |
| **jQuery** | All scripts | DOM manipulation library used by scraper core | ✅ FP - Legacy dependency |
| **JSZip/pako** | `background_script.js`, `devtools_panel.js` | For exporting scraped data as ZIP/Excel files | ✅ FP - Export functionality |
| **localForage** | Multiple files | IndexedDB wrapper for storing sitemaps locally | ✅ FP - Storage library |

---

## API Endpoints & Data Flow

### Outbound Connections (All First-Party)

| Endpoint | Purpose | Data Sent | Frequency |
|----------|---------|-----------|-----------|
| `stats.webscraper.io/post-stats` | Usage analytics | Sitemap counts, selector usage stats, extension version | Every 3 days (opt-in) |
| `cloud.webscraper.io/extension-api-auth` | Cloud sync auth | Extension ID for OAuth flow | User-initiated |
| `cloud.webscraper.io/extension-api/v1/sitemaps/*` | Sitemap cloud sync | Sitemap configurations (user content) | User-initiated |
| `sitemap-generator.webscraper.io/api/generateSelectors` | AI selector suggestions | Page HTML, URL | User-initiated (experimental feature) |
| `surveys.webscraper.io/surveys/extension-uninstall` | Exit survey redirect | Sitemap count, record count, uninstall reason | On uninstall |

**No third-party domains identified.** All endpoints are subdomains of `webscraper.io`.

---

## Data Flow Summary

```
User Action (Open DevTools Panel)
    ↓
Extension Injects Content Script (UI overlays)
    ↓
User Clicks Elements → Selectors Generated
    ↓
User Starts Scraping → chrome.webRequest Intercepts XHR
    ↓
Scraped Data Stored Locally (IndexedDB via localForage)
    ↓
[OPTIONAL] User Syncs to Cloud → cloud.webscraper.io
    ↓
[OPTIONAL] Usage Stats → stats.webscraper.io (if enabled)
```

**Key Privacy Characteristics**:
- ✅ No autonomous data collection (user must initiate scraping)
- ✅ Scraped data stored locally by default
- ✅ Cloud sync is opt-in
- ✅ Analytics are opt-in via `enableDailyStats` config
- ✅ No third-party trackers or SDKs
- ✅ No keylogging, form harvesting, or credential theft

---

## Permissions Analysis

| Permission | Justification | Risk |
|------------|---------------|------|
| `tabs` | Navigate tabs during scraping, inject content scripts | ✅ Required |
| `storage` | Store sitemaps locally | ✅ Required |
| `unlimitedStorage` | Store large scraped datasets | ✅ Justified |
| `declarativeNetRequest` | Track redirects during link scraping | ✅ Legitimate |
| `scripting` | Inject content script for UI overlays | ✅ Required |
| `sidePanel` | MV3 side panel UI | ✅ UI feature |
| `webRequest` (optional) | Intercept XHR for AJAX scraping | ✅ Core feature |
| `<all_urls>` | Scrape any website | ✅ Universal scraper |

---

## Code Quality & Obfuscation

- **Obfuscation Level**: Moderate (Webpack bundling with minification)
- **Identifiable Libraries**: React, MobX, jQuery, bcrypt, CryptoJS, JSZip, localForage
- **Code Size**: 301,352 lines (mostly library code)
- **Suspicious Patterns**: None detected

The code is standard Webpack-bundled React application. No unusual packing, string obfuscation, or anti-analysis techniques observed.

---

## Security Strengths

1. ✅ **First-party infrastructure** - All API calls to webscraper.io domains
2. ✅ **Local-first architecture** - Data stored locally by default
3. ✅ **Opt-in telemetry** - Analytics controlled by user preference
4. ✅ **Transparent permissions** - All permissions justified by features
5. ✅ **No malicious SDKs** - No Sensor Tower, analytics trackers, or ad networks
6. ✅ **Secure token storage** - Auth tokens in `chrome.storage.local` (encrypted)
7. ✅ **CSP enforcement** - `script-src 'self'; object-src 'self'`

---

## Recommendations

### For Users:
- ✅ **Safe to use** - This is a legitimate web scraping tool
- If privacy-conscious, disable "Enable Daily Stats" in options (if exposed)
- Cloud sync is optional - sitemaps can be stored locally only

### For Developers:
- Consider adding explicit privacy settings UI to control `enableDailyStats`
- Document cloud sync auth flow in privacy policy
- Add user-facing indicator when XHR interception is active

---

## Comparison to Malicious Extensions

Unlike malicious VPN extensions analyzed in this project (StayFree, StayFocusd, Urban VPN), Web Scraper:

| Feature | Web Scraper | Malicious Extensions |
|---------|-------------|---------------------|
| Third-party SDKs | ❌ None | ✅ Sensor Tower Pathmatics, analytics trackers |
| AI conversation scraping | ❌ No | ✅ ChatGPT, Claude, Gemini |
| XHR/fetch hooking | ⚠️ Yes (legitimate) | ✅ Yes (data harvesting) |
| Background data collection | ❌ No | ✅ Continuous scraping |
| Remote kill switches | ❌ No | ✅ "thanos" mode, server configs |
| Extension enumeration | ❌ No | ✅ Kills ad blockers |

---

## Final Verdict

**CLEAN** - Web Scraper is a legitimate tool with no evidence of malicious activity. All permissions and data collection serve documented features. The extension operates transparently with opt-in cloud sync and analytics.

**Recommended Action**: ✅ **Safe for continued use**

---

## Technical Artifacts

### Key Files Analyzed:
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/jnhgnonknehpejjnehehllkliplmbmhn/deobfuscated/manifest.json`
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/jnhgnonknehpejjnehehllkliplmbmhn/deobfuscated/background_script.js` (20,553 lines)
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/jnhgnonknehpejjnehehllkliplmbmhn/deobfuscated/content_script.js` (19,803 lines)
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/jnhgnonknehpejjnehehllkliplmbmhn/deobfuscated/devtools_panel.js` (70,885 lines)

### Analysis Methodology:
- Static analysis of deobfuscated JavaScript
- Manifest permission review
- Network endpoint enumeration
- Data flow tracking
- Comparison against known malicious patterns (Sensor Tower SDK, AI scrapers, extension killers)

---

**Report Generated**: 2026-02-06
**Analyst**: Claude Sonnet 4.5
**Project**: CWS Scraper Security Research
