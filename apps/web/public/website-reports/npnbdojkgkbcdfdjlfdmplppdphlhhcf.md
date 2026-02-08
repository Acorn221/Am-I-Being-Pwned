# Security Analysis Report: ProWritingAid Grammar Checker & Paraphrasing Tool

## Extension Metadata
- **Extension ID**: npnbdojkgkbcdfdjlfdmplppdphlhhcf
- **Extension Name**: ProWritingAid: Grammar Checker & Paraphrasing Tool
- **Version**: 2.7.33339
- **User Count**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-06

## Executive Summary

ProWritingAid is a legitimate grammar checking and writing assistance browser extension with CLEAN security posture. The extension uses extensive permissions appropriately for its documented grammar checking, paraphrasing, and writing analysis functionality. All network communication goes to legitimate ProWritingAid infrastructure. No evidence of malicious behavior, data harvesting beyond documented functionality, third-party SDKs, extension killing, or other suspicious patterns was found.

**Risk Level: CLEAN**

The extension's broad permissions (cookies, clipboard, scripting, host_permissions on all sites) are justified by its core functionality: analyzing text across web pages, syncing user settings/dictionaries via cookies, and providing copy/paste integration. Google Docs integration uses documented MAIN world injection for reading document text.

---

## Vulnerability Analysis

### 1. Remote Configuration System
**Severity**: LOW (Legitimate Feature)
**Files**: `background.js` (lines 23615-23696, 56519-56520)
**Pattern**: Remote settings/rules fetching

**Details**:
The extension fetches remote configuration from Azure Blob Storage:
```javascript
this.remoteSettings = new d.RemoteStorageSettings({
  refreshUrl: "https://prowritingaid.blob.core.windows.net/cdn/browserextension/rules.json",
  interval: O.HOUR,
  localStorageKey: f.DEFAULT_REMOTE_SETTINGS_KEY,
  notifyUsAboutChanges: !0,
  shippedRules: (0, p.getShippedRules)()
});
```

The `RemoteStorageSettings` class (lines 23622-23696) fetches grammar rules from the CDN endpoint every hour using standard `fetch()` API. Configuration is stored in `chrome.storage.local` with key `pwa-remote-settings`. Debug function `window.reloadSettings()` allows manual rule reloading.

**Verdict**: LEGITIMATE - Remote rules configuration is appropriate for a grammar checker that needs to update language rules without requiring extension updates. Uses Microsoft Azure CDN (legitimate infrastructure), falls back to shipped rules if fetch fails, and only updates read-only grammar rules (line 23659: `e.ReadOnly = !0`). No evidence of remote code execution or behavior modification.

---

### 2. Extensive Permissions
**Severity**: LOW (Justified by Functionality)
**Files**: `manifest.json`

**Permissions Analysis**:
```json
"permissions": [
  "tabs",           // Used for identifying active tabs for grammar checking
  "cookies",        // Used for authentication with ProWritingAid backend
  "storage",        // Used for user settings, custom dictionaries
  "clipboardRead",  // Used for reading pasted text for analysis
  "clipboardWrite", // Used for copying corrected text
  "scripting"       // Used for injecting content scripts on web pages
],
"host_permissions": [
  "http://*/*",
  "https://*/*"
]
```

**Cookie Usage** (`background.js` lines 81249-81267, `prepare.js` line 2166):
- `chrome.cookies.get()` and `chrome.cookies.getAll()` are scoped to ProWritingAid domain via `getAuthCookiesDomain()`
- Used for session management and authentication tokens
- No evidence of cookie stealing from arbitrary domains

**Clipboard Usage** (`content_script.js` lines 36890-36894, 73225-73228):
```javascript
navigator.clipboard.write([new ClipboardItem({
  "text/plain": i
})])
```
Clipboard access is used bidirectionally for copying corrected text back to user. No evidence of silent clipboard monitoring or data exfiltration.

**Verdict**: LEGITIMATE - All permissions are appropriately used for documented grammar checking functionality across web pages.

---

### 3. Google Docs MAIN World Injection
**Severity**: LOW (Documented Feature)
**Files**: `manifest.json` (line 71), `gdocs-patch.js` (lines 40-150)

**Details**:
```json
{
  "matches": ["*://docs.google.com/document/*"],
  "js": ["./gdocs-patch.js"],
  "world": "MAIN"
}
```

The `gdocs-patch.js` script sets `window._docs_annotate_canvas_by_ext = "npnbdojkgkbcdfdjlfdmplppdphlhhcf"` (line 42) and uses deep object property inspection to locate Google Docs internal text accessor APIs (`findInitialKixAppKey()`, `discoverFullTextPaths()`, `discoverSelectionObjectPaths()`). This allows reading document text and selection ranges for grammar analysis.

**Verdict**: LEGITIMATE - MAIN world injection is necessary for accessing Google Docs internal text representation. The extension hardcodes its own extension ID and uses documented techniques for Google Docs integration. No malicious behavior detected. Similar patterns exist for Microsoft Word Online (`msword-patch.js`), Salesforce (`salesforce-patch.js`), LinkedIn (`linkedin-patch.js`), and Facebook Draft.js (`facebook-draftjs-patch.js`).

---

### 4. Dynamic Script Injection
**Severity**: LOW (Standard Content Script Loading)
**Files**: `background.js` (lines 74214-74225), `prepare.js` (lines 9085-9096)

**Details**:
```javascript
chrome.scripting.executeScript({
  target: Object.assign({
    tabId: t.tabId
  }, null !== (o = t.frameIds) && void 0 !== o ? o : {}),
  files: t.scriptFile ? [t.scriptFile] : []
})
```

Script injection is used for loading content scripts into frames. All injected files are extension-bundled (no remote scripts). Supports both Manifest V2 (`chrome.tabs.executeScript`) and V3 (`chrome.scripting.executeScript`) APIs.

**Verdict**: LEGITIMATE - Standard content script injection pattern. No evidence of remote code execution or eval-based dynamic code.

---

### 5. Extension Management APIs
**Severity**: N/A (Not Used)
**Files**: None

**Details**: Searched for `chrome.management` across all files - no matches found. Extension does NOT enumerate or disable other extensions.

**Verdict**: CLEAN - No extension killing behavior.

---

### 6. Network Communication Endpoints
**Severity**: LOW (All First-Party)
**Files**: `background.js`

**Identified Endpoints**:
1. **ProWritingAid API** (inferred from `apiServerBaseUrl` variable and API wrappers):
   - Dictionary API: `/api/ignorepatterns` (lines 183-188)
   - Team Analytics API: `/api/teamanalytics` (line 20526)
   - User authentication endpoint (via `getWebsiteEndPoint()`)

2. **Azure CDN**:
   - `https://prowritingaid.blob.core.windows.net/cdn/browserextension/rules.json`

3. **Uninstall Tracking** (line 56606):
   - `chrome.runtime.setUninstallURL()` pointing to ProWritingAid website with version/browser params

All network traffic goes to legitimate ProWritingAid infrastructure. No third-party analytics SDKs, tracking pixels, or suspicious external domains detected.

**Verdict**: LEGITIMATE - All endpoints are first-party ProWritingAid services.

---

## False Positive Analysis

| Pattern | Location | Explanation |
|---------|----------|-------------|
| `eval()` / `Function()` | All files (242 occurrences) | Standard webpack/bundler helpers (`__webpack_require__`, generator functions). No dynamic code execution. |
| `innerHTML` | Multiple files (150 occurrences) | Legitimate DOM manipulation for rendering grammar suggestions and UI components. |
| `document.querySelector` | Multiple files (46 occurrences) | Standard DOM querying for finding text input fields to analyze. |
| `postMessage()` | Multiple files (50 occurrences) | Legitimate communication between content scripts, background, and popup. |
| `addEventListener('keydown')` | `vendor-3rdparty.js` (line 63884) | Focus trapping for modal dialogs (Enter/Escape/Tab handling). NOT a keylogger. |
| `XMLHttpRequest` / `fetch()` | Multiple files (195 occurrences) | Standard HTTP client code for API communication. No XHR/fetch hooking detected. |
| `chrome.cookies.getAll()` | Multiple files | Scoped to ProWritingAid domains only. No arbitrary cookie harvesting. |
| `navigator.clipboard` | `content_script.js` | Bidirectional clipboard access for copy/paste of corrected text. No silent monitoring. |
| `window.location` references | Multiple files (40 occurrences) | URL reading for determining which grammar checks to enable (e.g., disable on email sites). |

---

## API Endpoints Summary

| Endpoint | Purpose | Method | Data Sent |
|----------|---------|--------|-----------|
| `https://prowritingaid.blob.core.windows.net/cdn/browserextension/rules.json` | Grammar rules CDN | GET | None |
| `[baseUrl]/api/ignorepatterns` | User dictionary (add word) | POST | Word, category, subCategory |
| `[baseUrl]/api/ignorepatterns/{userId}/{category}` | Get dictionary entries | GET | None (params in URL) |
| `[baseUrl]/api/ignorepatterns` | Remove dictionary word | DELETE | Entry ID |
| `[baseUrl]/api/teamanalytics/alltime` | Team writing statistics | GET | None |
| `[baseUrl]/api/teamanalytics/insights` | Team insights | GET | None |
| Uninstall URL | Extension removal tracking | GET (browser) | Version, browser name |

**Note**: `[baseUrl]` is determined by `getWebsiteEndPoint()` function (appears to be `prowritingaid.com` based on context).

---

## Data Flow Summary

### Data Collection:
1. **Text Analysis**: User-typed text on web pages is sent to ProWritingAid API for grammar checking
2. **User Dictionary**: Custom words added to dictionary are synced via ProWritingAid API
3. **Authentication**: Session cookies from `prowritingaid.com` domain for user authentication
4. **Settings**: Extension preferences stored in `chrome.storage.local` (local only)
5. **Remote Rules**: Grammar rules fetched hourly from Azure CDN (public, read-only)

### Data Storage:
- **Local Storage Keys**:
  - `pwa-extension-settings` - User preferences
  - `pwa-remote-settings` - Downloaded grammar rules
  - `pwa-extension-first-disable-key` - First-time disable flag
  - `pwa-extension-show-feature-alert-popup` - Feature alert state
- **Cookies**: Authentication cookies scoped to `prowritingaid.com` domain

### Data Transmission:
- All user text submitted for analysis goes to ProWritingAid servers
- Custom dictionary words synced to ProWritingAid account
- No data sent to third parties
- No browsing history collection beyond current page URL for context-aware grammar rules

---

## Security Strengths

1. **No Third-Party SDKs**: No Sensor Tower, analytics frameworks, or market intelligence SDKs detected
2. **No Extension Killing**: Does not enumerate or disable other extensions
3. **First-Party Only**: All network traffic confined to ProWritingAid infrastructure
4. **Manifest V3**: Uses modern security model with service workers
5. **Content Security Policy**: Reasonable CSP with `script-src: 'self'` (sandbox allows inline for iframe-loader)
6. **No Obfuscation**: Clean webpack-bundled code, no packer/obfuscation beyond standard minification
7. **No Remote Code**: No eval-based remote code execution or fetch-then-eval patterns
8. **Transparent Permissions**: All permissions have clear, documented use cases

---

## Security Weaknesses

1. **Broad Host Permissions**: `http://*/*` and `https://*/*` allow injection on all sites, but justified by grammar checking functionality
2. **Clipboard Access**: Could theoretically read clipboard contents, but implementation shows legitimate copy/paste only
3. **Google Docs Deep Inspection**: Relies on undocumented internal APIs that could break with Google updates, but no malicious use
4. **Remote Config**: Grammar rules fetched from remote CDN hourly - potential supply chain risk if CDN compromised, but mitigated by:
   - Legitimate Azure infrastructure
   - Fallback to shipped rules
   - Read-only flag enforcement
   - No code execution, only data

---

## Recommendations

### For Users:
- Extension is safe to use for its intended grammar checking purpose
- Be aware that text you check is sent to ProWritingAid servers for analysis (expected for cloud-based grammar checking)
- Extension requires broad permissions to work across all websites

### For Developers:
- Consider implementing Subresource Integrity (SRI) for remote rules fetching
- Add content hash validation for downloaded grammar rules
- Consider narrowing host_permissions to user-specified sites (with opt-in for all sites)
- Implement rate limiting on clipboard API usage to prevent accidental overuse

---

## Overall Risk Assessment

**CLEAN** - ProWritingAid is a legitimate, professionally developed grammar checking extension with appropriate security practices. All identified patterns have benign explanations consistent with documented functionality. No malicious behavior detected.

### Risk Breakdown:
- **Data Exfiltration**: None (beyond documented grammar checking)
- **Malicious Code**: None detected
- **Third-Party SDKs**: None
- **Extension Interference**: None
- **Remote Code Execution**: None
- **Privacy Violations**: None (data collection disclosed in product description)
- **Supply Chain Risk**: LOW (remote config is data-only, not code)

---

## Comparison to Known Malicious Patterns

Unlike malicious extensions in the corpus (Urban VPN, StayFree, StayFocusd, YouBoost):
- ❌ No Sensor Tower Pathmatics SDK
- ❌ No XHR/fetch hooking on arbitrary pages
- ❌ No AI conversation scraping
- ❌ No browsing history harvesting
- ❌ No extension enumeration/killing
- ❌ No residential proxy infrastructure
- ❌ No ad injection
- ❌ No dark patterns
- ❌ No undisclosed third-party data sharing

ProWritingAid behaves exactly as expected for a premium grammar checking service.

---

## Conclusion

ProWritingAid: Grammar Checker & Paraphrasing Tool is **CLEAN**. The extension is a legitimate commercial product with appropriate permissions for its documented functionality. Security posture is strong with no evidence of malicious behavior. Users can safely install this extension for grammar checking purposes with the understanding that text content will be sent to ProWritingAid's servers for analysis (standard for cloud-based writing assistants).
