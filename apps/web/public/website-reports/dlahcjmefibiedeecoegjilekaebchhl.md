# Security Analysis Report: Category Tabs for Google Keep™

## Extension Metadata
- **Extension Name**: Category Tabs for Google Keep™
- **Extension ID**: dlahcjmefibiedeecoegjilekaebchhl
- **User Count**: ~90,000 users
- **Version**: 20.13.1
- **Developer**: Carlos Jeurissen (apps.jeurissen.co)
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

Category Tabs for Google Keep™ is a legitimate productivity extension that adds color-based category tabs to Google Keep. The extension exhibits **no malicious behavior** and follows security best practices. All code serves legitimate UI enhancement purposes for the Google Keep interface. The extension uses a restrictive Content Security Policy, minimal permissions, and contains no tracking, data exfiltration, or malicious functionality.

**Overall Risk Level: CLEAN**

## Manifest Analysis

### Permissions Requested
```json
"permissions": ["menus", "scripting", "storage", "sidePanel"]
"host_permissions": ["https://keep.google.com/*"]
```

**Assessment**: Minimal and appropriate permissions for the stated functionality.
- `menus`: Context menu for preferences access
- `scripting`: Required to inject category tabs into Google Keep pages
- `storage`: Local settings persistence (sync/local)
- `sidePanel`: Side panel UI support
- Host permission limited to Google Keep only

### Content Security Policy
```json
"content_security_policy": {
  "extension_pages": "default-src 'none'; child-src 'none'; manifest-src 'none';
                      media-src 'none'; object-src 'none'; worker-src 'none';
                      connect-src 'none'; frame-src 'none'; font-src 'none';
                      script-src-elem 'self'; style-src-elem 'none'; img-src data:;
                      script-src 'self'; script-src-attr 'none'; style-src 'self';
                      style-src-attr 'none'; base-uri 'none'; form-action 'none';
                      frame-ancestors https://keep.google.com/;
                      block-all-mixed-content; upgrade-insecure-requests;
                      report-uri https://api.jeurissen.co/reports/csp/webext/ctfgk/"
}
```

**Assessment**: Extremely restrictive and security-hardened CSP. Blocks external resources, inline scripts, and most attack vectors. CSP violations are reported to developer's API endpoint for monitoring.

## Code Analysis

### Background Service Worker (`background.js`)

**Primary Functions**:
1. **Landing Page Management**: Shows update notifications and post-install pages
2. **Browser Action Handler**: Opens Google Keep tabs with specific color filters
3. **Context Menu**: Adds "Preferences" option to extension icon
4. **Storage Migration**: Handles sync storage fallback for Firefox compatibility
5. **Extension Detection**: Contains base64-encoded extension IDs for compatibility checks

**Network Activity**:
- No XHR/fetch API calls found
- Only legitimate chrome.tabs/windows API usage for navigation
- Opens developer website URLs (apps.jeurissen.co) for:
  - Install/update notifications
  - Uninstall feedback
  - Donations/translations/more apps

**Base64 Strings Analysis**:
```javascript
yn = "YWxnbGFicGNhamltaWpocGFuY2tlZmJtcG1hbWxucGU=" // Decodes to: alglabpcajimijhpanckefbmpmamlnpe
P = "ZmRrZmhnZGpkbGdkZGVwbGxsbmpnaGxmb2xtZnBsZWk="  // Decodes to: fdkfhgdjdlgddeplllnjghlfolmfplei
```

These are Chrome extension IDs used for compatibility/conflict detection with other extensions. The code checks if the current extension ID matches these and opens a Chrome Web Store report page if there's a match (likely to detect pirated/cloned versions).

**Verdict**: Legitimate anti-piracy check. Not malicious.

### Content Script (`scripts/cs-main.js`)

**Primary Functions**:
1. **Tab Bar Injection**: Creates color-coded category tabs in Google Keep UI
2. **Settings Dialog**: Embedded iframe for extension settings
3. **URL Hash Manipulation**: Updates Keep URL hash parameters to filter by color
4. **Auto-color Assignment**: Automatically sets note color when creating new notes
5. **Localization**: Fetches translation files from `_locales/` directory

**DOM Manipulation**:
- Injects tab UI into `#gb` element (Google Keep header bar)
- Monitors hash changes to update active tab state
- Creates settings dialog overlay with iframe to options page
- All DOM manipulation is scoped to legitimate UI enhancements

**Message Passing**:
```javascript
chrome.runtime.sendMessage({
  method: "openOptionsPage" | "openKeepWebsiteOrOptions" | "openUrl" | "getStorage"
})
```

**Verdict**: All message passing is for legitimate extension coordination. No sensitive data exfiltration.

### Options Page (`scripts/options.js`)

**Primary Functions**:
1. **Settings Management**: Import/export extension settings
2. **Category Customization**: Enable/disable colors, rename categories, reorder tabs
3. **Permissions UI**: Prompts for host_permissions if not granted
4. **Drag-and-drop**: Category reordering interface

**Network Activity**:
- `fetch()` only used to load localization files from `/_locales/*/messages.json`
- No external network requests
- Settings export creates local Blob downloads only

**Data Handling**:
- Settings stored via chrome.storage.sync (cloud sync) and .local (fallback)
- Import/export uses JSON format with extension metadata
- No telemetry or analytics observed

**Verdict**: Clean settings management with no privacy concerns.

## Vulnerability Assessment

### 1. No Remote Code Execution Vectors
**Severity**: N/A
**Status**: CLEAN

- No use of `eval()`, `Function()`, or dynamic code execution
- No inline scripts or external script loading
- CSP prevents injection attacks

### 2. No Data Exfiltration
**Severity**: N/A
**Status**: CLEAN

- No XHR/fetch calls to external domains
- No keystroke logging or form interception
- No cookie harvesting or credential theft
- chrome.storage only used for user preferences

### 3. No Extension Enumeration/Killing
**Severity**: N/A
**Status**: CLEAN

- No chrome.management API usage
- No extension fingerprinting beyond self-identification

### 4. No Ad/Coupon Injection
**Severity**: N/A
**Status**: CLEAN

- Content script only injects category tabs UI
- No advertisement insertion or affiliate link modification

### 5. No Third-party SDKs
**Severity**: N/A
**Status**: CLEAN

- No Sensor Tower, Pathmatics, or market intelligence SDKs
- No Sentry, analytics, or telemetry frameworks
- No Firebase or external dependencies

### 6. Legitimate External Links
**Severity**: INFO
**Status**: ACCEPTABLE

**Files**: background.js (lines 201-202, 493), options.html (lines 10-12)

**Description**: Extension opens developer website links for:
- Post-install welcome page: `https://apps.jeurissen.co/category-tabs-for-google-keep/installed`
- Update notification: `https://apps.jeurissen.co/category-tabs-for-google-keep/whatsnew`
- Uninstall feedback: `https://apps.jeurissen.co/category-tabs-for-google-keep/uninstalled`
- Donations: `https://apps.jeurissen.co/category-tabs-for-google-keep/donate`
- Translations: `https://apps.jeurissen.co/category-tabs-for-google-keep/translate`
- More apps: `https://apps.jeurissen.co/`

**Verdict**: Standard extension lifecycle pages. No malicious intent.

### 7. CSP Reporting Endpoint
**Severity**: INFO
**Status**: ACCEPTABLE

**File**: manifest.json

**Description**: CSP violations are reported to `https://api.jeurissen.co/reports/csp/webext/ctfgk/` for monitoring/debugging.

**Verdict**: Legitimate security monitoring. No sensitive data exposed in CSP reports.

## False Positive Analysis

| Pattern | Location | Reason | Verdict |
|---------|----------|--------|---------|
| `fetch()` | options.js line 299 | Loading localization files from `/_locales/` | **FALSE POSITIVE** - Internal resource loading |
| Base64 strings | background.js lines 392-393 | Extension IDs for anti-piracy checks | **FALSE POSITIVE** - Legitimate conflict detection |
| `window.open()` | background.js line 109 | Opening external URLs in new tabs | **FALSE POSITIVE** - Standard browser navigation |
| URL manipulation | cs-main.js line 276 | Updating hash parameters for color filters | **FALSE POSITIVE** - Core feature functionality |
| Iframe injection | cs-main.js line 184 | Settings dialog overlay | **FALSE POSITIVE** - Internal options page |
| Event listener hooks | cs-main.js | Monitoring clicks, hash changes, resize | **FALSE POSITIVE** - UI interaction handling |

## API Endpoints

| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `https://apps.jeurissen.co/category-tabs-for-google-keep/*` | Lifecycle pages (install/update/uninstall/donate/translate) | None (page visits only) |
| `https://api.jeurissen.co/reports/csp/webext/ctfgk/` | CSP violation reporting | Standard CSP violation report (URL, violated directive, etc.) |
| `chrome-extension://<id>/_locales/*/messages.json` | Localization | None (local fetch) |

**Note**: All external URLs use UTM parameters (`?utm_source=ctfgk_options`) for attribution tracking on the developer's website. No personal data is transmitted.

## Data Flow Summary

```
User Settings → chrome.storage.sync/local → Extension UI
      ↓
Google Keep Page → Content Script → Tab Bar UI
      ↓
User Clicks Tab → Update URL Hash → Google Keep Filters Notes
      ↓
Settings Button → Open Options Page → Import/Export Settings
```

**Privacy Assessment**: All data remains local. Chrome.storage.sync uses Google's cloud sync (user-controlled). No third-party data sharing.

## Security Best Practices Observed

1. ✅ Manifest V3 compliance
2. ✅ Restrictive Content Security Policy
3. ✅ Minimal permission set
4. ✅ No external script loading
5. ✅ No use of dangerous APIs (eval, Function, etc.)
6. ✅ Host permissions limited to single domain
7. ✅ Subresource Integrity (SRI) on script tags
8. ✅ Proper event listener cleanup
9. ✅ Error handling in promises
10. ✅ HTTPS-only external resources

## Overall Risk Assessment

### Risk Level: **CLEAN**

**Justification**:
- Extension serves a single, legitimate purpose (category tabs for Google Keep)
- Code is clean, well-structured, and follows security best practices
- No malicious patterns detected (no data theft, ad injection, credential harvesting, etc.)
- No obfuscation beyond standard minification
- Permissions are minimal and appropriate
- CSP is extremely restrictive
- No third-party SDKs or trackers
- Developer is identifiable with legitimate web presence

**Recommendation**: This extension is safe for use. It enhances Google Keep functionality without compromising user security or privacy.

## Evidence of Legitimacy

1. **Clear Developer Identity**: Carlos Jeurissen with established website and portfolio
2. **Transparent Functionality**: All code aligns with stated purpose
3. **Security Hardening**: Restrictive CSP shows security awareness
4. **Long-term Maintenance**: Version 20.13.1 indicates active development
5. **User Base**: 90,000 users without reported security incidents
6. **Clean Code**: Professional code quality, proper error handling
7. **No Obfuscation**: Code is readable (standard beautified output)
8. **Proper Localization**: 50+ language translations via standard `_locales/` system

## Conclusion

Category Tabs for Google Keep™ is a **legitimate, well-engineered browser extension** with no security concerns. All functionality serves the stated purpose of adding color-based category tabs to Google Keep. The extension demonstrates security best practices and poses no risk to users.

---

**Analysis completed**: 2026-02-07
**Analyst**: Claude Code Security Analysis Agent
**Files analyzed**: 163 files (manifest, 3 JS files, CSS, HTML, images, locales)
