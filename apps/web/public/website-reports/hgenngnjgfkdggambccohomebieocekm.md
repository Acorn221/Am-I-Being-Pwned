# Security Analysis: Bulk URL Opener Extension

**Extension ID:** hgenngnjgfkdggambccohomebieocekm
**Extension Name:** Bulk URL Opener Extension
**Version:** 2.7.0.0
**Users:** ~300,000
**Developer:** Melanto Ltd. (https://melanto.com)
**Analysis Date:** 2026-02-06

---

## EXECUTIVE SUMMARY

**OVERALL RISK: LOW**

The Bulk URL Opener Extension is a legitimate productivity tool that allows users to open multiple URLs simultaneously. The extension shows minimal security concerns and exhibits clean coding practices with no evidence of malicious behavior, data exfiltration, or suspicious network activity.

**Key Findings:**
- No network exfiltration or telemetry beyond standard Chrome Web Store practices
- No content scripts injected into web pages
- Minimal permissions appropriate for stated functionality
- No obfuscation or dynamic code execution
- No third-party analytics, tracking SDKs, or market intelligence frameworks
- Transparent operation with clear user-facing features
- Simple clipboard access (clipboard read/write) used only for URL list management

---

## MANIFEST ANALYSIS

### Permissions
```json
"permissions": [
  "clipboardRead",
  "clipboardWrite",
  "storage",
  "activeTab",
  "scripting"
]
```

**Assessment:** Minimal and appropriate permissions for the extension's functionality.

- **clipboardRead/clipboardWrite**: Used for paste/copy URL list functionality in the popup UI. Legitimate use case.
- **storage**: Chrome local storage for saving user preferences and URL lists (optional feature).
- **activeTab**: Required for the "Extract from Current Tab" feature to read links from the active page.
- **scripting**: Used to inject a single script that extracts links from the current page when user clicks "From Current" button.

### Content Security Policy
No custom CSP defined - uses Chrome MV3 defaults, which is secure.

### Background Service Worker
- Single background script: `background.js` (13.2 KB)
- No persistent background page
- Manifest V3 compliant

### Content Scripts
**NONE** - This extension does NOT inject any content scripts into web pages by default, which significantly reduces attack surface.

---

## CODE ANALYSIS

### Background Script (`background.js`)

**Primary Functions:**
1. **Settings Management**: Saves/loads user preferences (opening mode, delays, icon colors)
2. **URL Opening Logic**: Three modes:
   - Open all URLs in new tabs
   - Open each URL in separate windows
   - Group URLs by hostname into separate windows
   - "One by One" sequential mode with timeout
3. **Install/Uninstall Handlers**: Opens documentation pages on install/update/uninstall

**Network Activity:**
- **Install**: Opens `https://melanto.com/bulk-url-opener/`
- **Update**: Opens `https://melanto.com/bulk-url-opener-version-2-7/`
- **Uninstall**: Sets uninstall URL to `https://melanto.com/bulk-url-opener-removed/`

All network calls are transparent to the user (visible tab openings) and limited to the developer's domain for documentation purposes only.

**No Evidence Of:**
- XHR/fetch calls to remote servers
- Telemetry or analytics beacons
- Data exfiltration
- Extension enumeration/killing
- Cookie harvesting
- Residential proxy infrastructure
- Remote configuration fetching
- Third-party SDK injection

### Popup Script (`index.js`)

**Primary Functions:**
1. **URL List Management**:
   - Paste/copy/clear/import/export URL lists
   - Extract URLs from text (regex-based with TLD validation)
   - Remove duplicates
   - Count lines
2. **Settings UI**: Radio buttons and checkboxes for opening modes
3. **Extract from Current Tab**: Uses `chrome.scripting.executeScript()` to inject a simple link extraction function:

```javascript
function getPageLinks() {
  const links = Array.from(document.querySelectorAll("a")).map(
    (link) => link.href
  );
  const uniqueLinks = [...new Set(links)];
  return uniqueLinks;
}
```

This is a benign, one-time script injection that only extracts `<a>` tag hrefs and does NOT:
- Hook XHR/fetch
- Listen for user input
- Access cookies or storage
- Manipulate the DOM beyond reading
- Persist across page loads

**Clipboard Usage:**
```javascript
document.execCommand("paste");  // Paste button
document.execCommand("copy");   // Copy button
```

Uses deprecated but legitimate `execCommand` API for clipboard operations within the popup context. This does NOT access clipboard data from other pages.

**File Operations:**
- Import: `FileReader` to load text files
- Export: `Blob` + `URL.createObjectURL()` to download URL list as `.txt` file

All file operations are user-initiated and transparent.

### Storage Usage

**chrome.storage.local:**
- `cleanerSettings`: User preferences (opening modes, delays, icon choices)
- `URLs`: Optional saved URL list if "Remember the URL List" is enabled

No sensitive data collection. All storage is local and user-controlled.

---

## PERMISSIONS JUSTIFICATION

| Permission | Usage | Risk Level |
|------------|-------|------------|
| clipboardRead | Paste button functionality | LOW - Popup context only |
| clipboardWrite | Copy button functionality | LOW - Popup context only |
| storage | Save user settings and URL lists | LOW - Local storage only |
| activeTab | Extract links from current page | LOW - User-initiated, one-time script |
| scripting | Inject link extraction script | LOW - Minimal, read-only DOM access |

---

## POTENTIAL CONCERNS

### 1. Clipboard Permissions (MINOR)
**Issue:** `clipboardRead` permission could theoretically access clipboard contents.

**Mitigation:**
- Clipboard access is only triggered by explicit user button clicks in the popup
- No automatic clipboard reading
- No evidence of clipboard data exfiltration

**Verdict:** Acceptable use case for productivity extension.

### 2. Content Script Injection (MINIMAL)
**Issue:** `chrome.scripting.executeScript()` allows arbitrary code injection.

**Mitigation:**
- Only used for "From Current" button
- Injected script is simple, transparent, and read-only
- User-initiated action required
- No injection on sensitive pages (chrome://, chrome-extension://, chromewebstore)

**Verdict:** Legitimate use case with proper safeguards.

### 3. Deprecated execCommand (TECHNICAL)
**Issue:** `document.execCommand()` is deprecated.

**Verdict:** Not a security issue, just outdated API. Should migrate to Clipboard API in future.

### 4. No CSP in Manifest (INFORMATIONAL)
**Issue:** No explicit Content Security Policy defined.

**Verdict:** MV3 defaults are secure. Not a concern.

---

## COMPARISON TO KNOWN MALICIOUS PATTERNS

| Malicious Pattern | Present | Notes |
|-------------------|---------|-------|
| Extension Enumeration | NO | No `chrome.management` calls |
| Extension Disabling | NO | No attempts to disable other extensions |
| XHR/Fetch Hooking | NO | No network interception |
| Cookie Harvesting | NO | No `chrome.cookies` API usage |
| Residential Proxy Infra | NO | No proxy configuration |
| Market Intelligence SDKs | NO | No Sensor Tower, Pathmatics, etc. |
| AI Conversation Scraping | NO | No content scripts monitoring AI platforms |
| Remote Config/Kill Switch | NO | No dynamic configuration fetching |
| Ad/Coupon Injection | NO | No DOM manipulation on external pages |
| Obfuscation | NO | Clean, readable code |
| Dynamic Code Execution | NO | No `eval()`, `Function()`, `atob()`, etc. |
| Google Analytics Bypass | NO | No VPN proxy exclusion patterns |
| Browsing History Collection | NO | No `chrome.history` API usage |

---

## FALSE POSITIVES IDENTIFIED

**None.** This extension does not exhibit any of the known false positive patterns:
- No React/Vue framework innerHTML patterns
- No Floating UI focus trapping
- No Sentry SDK duplication
- No AdGuard/uBlock scriptlets
- No MobX Proxy objects
- No Firebase public keys
- No OpenTelemetry instrumentation

---

## THIRD-PARTY DEPENDENCIES

**None detected.** The extension appears to be custom-written without external libraries beyond standard JavaScript and Chrome APIs.

---

## OUTBOUND NETWORK CONNECTIONS

**Summary:** Only user-visible tab navigations to developer's domain.

1. **Install Event**: `https://melanto.com/bulk-url-opener/`
2. **Update Event**: `https://melanto.com/bulk-url-opener-version-2-7/`
3. **Uninstall Event**: `https://melanto.com/bulk-url-opener-removed/`

All connections are transparent (visible browser tabs) and limited to documentation/feedback purposes.

**No background telemetry, analytics, or data exfiltration.**

---

## DATA COLLECTION & PRIVACY

**Data Collected:** None beyond Chrome Web Store standard metrics.

**Local Storage:**
- User settings (opening modes, delays, icon preference)
- Optional URL list (if "Remember the URL List" is enabled)

**Data Shared:** None. No external APIs or analytics services detected.

**Privacy Assessment:** Excellent. Extension operates entirely locally with no tracking.

---

## DYNAMIC BEHAVIOR ANALYSIS

### Install Flow
1. Extension installed
2. Default settings saved to `chrome.storage.local`
3. Documentation tab opens: `https://melanto.com/bulk-url-opener/`
4. Icon set based on user preference (default: blue)

### URL Opening Flow (Example: Open All)
1. User pastes/types URLs into popup textarea
2. User clicks "Open All" button
3. Background script receives message with URLs and settings
4. For each URL:
   - Validates/normalizes URL (adds `https://` if missing)
   - Calls `chrome.tabs.create()` or `chrome.windows.create()`
   - Applies delay if configured
5. Popup optionally closes if "Auto close" is enabled
6. Opened URLs optionally removed from list if "Remove opened URLs" is enabled

**No external network calls during this flow.**

### "One by One" Sequential Mode
1. Creates dedicated window
2. Opens URLs one-by-one in the same tab
3. Waits for page load (configurable timeout: 1-60 seconds)
4. Updates badge text with remaining URL count
5. User can cancel anytime

**Legitimate use case for sequential page loading (e.g., avoiding rate limits, automation).**

---

## MONETIZATION

**Revenue Model:** Donation-based.

The popup includes a "Buy me a Coffee" link to Stripe donation page:
```html
<a href="https://donate.stripe.com/6oEcPE0q4dsS8gw9AA" target="_new">Buy me a Coffee</a>
```

**Assessment:** Transparent, user-friendly monetization. No ads, affiliate links, or hidden revenue streams.

---

## CODE QUALITY

**Positive Indicators:**
- Clear copyright headers
- Descriptive function names
- Inline comments explaining logic
- Consistent coding style
- No obfuscation or minification (deobfuscated code is readable)
- Error handling with user-facing error messages

**Areas for Improvement:**
- Migrate from deprecated `execCommand` to Clipboard API
- Add explicit CSP in manifest for defense-in-depth
- Consider Manifest V3 alarm API instead of `setTimeout` for background delays

---

## CONCLUSION

**VERDICT: CLEAN**

The Bulk URL Opener Extension is a legitimate productivity tool with minimal security concerns. The extension:

1. **Does NOT engage in malicious behavior** such as data exfiltration, extension killing, cookie harvesting, or ad injection.
2. **Uses minimal, appropriate permissions** for its stated functionality.
3. **Operates transparently** with all network activity visible to the user.
4. **Respects user privacy** with no telemetry, analytics, or third-party tracking.
5. **Exhibits clean coding practices** with no obfuscation or dynamic code execution.

The only external connections are transparent documentation page opens to the developer's domain upon install/update/uninstall.

**Recommended Actions:**
- **No user action required** - Extension is safe to use.
- **Optional:** Review clipboard permissions if concerned about paste functionality, though current usage is benign.

**Risk Rating: LOW**

---

## TECHNICAL DETAILS

**Files Analyzed:**
- `/deobfuscated/manifest.json` (932 bytes)
- `/deobfuscated/background.js` (13,205 bytes)
- `/deobfuscated/index.js` (32,239 bytes)
- `/deobfuscated/index.html` (8,582 bytes)
- `/deobfuscated/settings.html` (5,582 bytes)
- `/deobfuscated/index.css` (16,568 bytes)

**Total Code Size:** ~76 KB (excluding images)

**Analysis Tools:**
- Static code analysis (grep, manual review)
- Manifest permission audit
- Network activity monitoring (static)
- Chrome API usage tracking

**Analyst:** Claude Opus 4.6 (Sonnet 4.5 analysis framework)
**Analysis Depth:** Comprehensive (all JavaScript files reviewed line-by-line)
**Confidence Level:** High

---

## APPENDIX: URL EXTRACTION FUNCTION

The injected content script for "From Current" button:

```javascript
function getPageLinks() {
  const links = Array.from(document.querySelectorAll("a")).map(
    (link) => link.href
  );
  const uniqueLinks = [...new Set(links)];
  return uniqueLinks;
}
```

**Analysis:**
- Read-only DOM access
- No event listeners
- No persistence
- No data transmission (returns to popup directly)
- Blocked on sensitive Chrome pages (chrome://, chromewebstore, etc.)

**Verdict:** Benign, legitimate use case.

---

## REFERENCES

- Chrome Web Store: https://chrome.google.com/webstore/detail/hgenngnjgfkdggambccohomebieocekm
- Developer Website: https://melanto.com/apps/bulk-url-opener/
- Help Documentation: https://melanto.com/apps/bulk-url-opener/help-info.html
