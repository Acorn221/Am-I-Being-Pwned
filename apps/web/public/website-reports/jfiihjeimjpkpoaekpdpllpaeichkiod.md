# Page Marker (jfiihjeimjpkpoaekpdpllpaeichkiod) - Vulnerability Report

## Extension Metadata
- **ID:** jfiihjeimjpkpoaekpdpllpaeichkiod
- **Name:** Page Marker - Draw on Web
- **Version:** 5.7
- **Users:** ~1,000,000
- **Manifest Version:** 3
- **Permissions:** `activeTab`, `storage`, `scripting`
- **Developer Domain:** pagemarker.org

## Executive Summary

Page Marker is a web page annotation extension that allows users to draw, highlight, and add text/shapes to any website using the Fabric.js HTML5 canvas library. The extension operates on-demand (user must click the extension icon) and includes a screenshot capture feature for saving annotated pages locally.

**After comprehensive analysis by three parallel security agents examining the manifest, background scripts, and content scripts, this extension is assessed as CLEAN with NO malicious behavior detected.** All three agents independently confirmed:

- Zero data exfiltration mechanisms
- No XHR/fetch monkey-patching or API hooking
- No tracking SDKs or analytics platforms
- Minimal permission footprint (activeTab instead of broad host_permissions)
- User-initiated functionality only (no auto-injection)
- Local-only screenshot processing (no upload to servers)
- Transparent, readable code with no obfuscation

The extension represents a best-practice example of minimal permissions, user-initiated operation, and privacy-respecting design. It monetizes ethically through an optional donation link shown 50% of the time in the UI.

## Vulnerability Details

### No Critical or High Vulnerabilities Found

After exhaustive analysis across manifest permissions, background service worker, and content scripts, **NO security vulnerabilities were identified.**

### Minor Observations (Non-Vulnerabilities)

#### OBS-01: Web Accessible Resources Fingerprinting
- **Severity:** INFORMATIONAL
- **File:** manifest.json lines 29-34
- **Pattern:**
```json
"web_accessible_resources": [{
  "resources": ["main.css", "marker.png", ...],
  "matches": ["<all_urls>"]
}]
```
- **Analysis:** Static assets (CSS and PNG icons) are exposed to all websites via `<all_urls>` match pattern. This allows any website to detect the extension's presence by attempting to fetch these resources.
- **Risk Assessment:** MINIMAL - No JavaScript files are exposed, only visual assets required for the drawing UI. While this enables fingerprinting, it poses no security risk.
- **Verdict:** ACCEPTABLE PATTERN - Standard practice for content script UI assets

#### OBS-02: Message Handler Lacks Sender Authentication
- **Severity:** INFORMATIONAL
- **File:** background.js lines 47-54
- **Code:**
```javascript
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
  if (request.from == 'content_script') {
    chrome.tabs.captureVisibleTab(null, {}, function (image) {
      sendResponse({screenshot: image});
    });
  }
  return true;
});
```
- **Analysis:** The message handler checks `request.from == 'content_script'` but this is a string provided by the sender, not authenticated by Chrome. Theoretically, any content script could request a screenshot. However, `chrome.tabs.captureVisibleTab()` requires the `activeTab` permission which only grants access to the current tab when the user clicks the extension icon.
- **Risk Assessment:** LOW - The `activeTab` permission model mitigates abuse. An attacker would need to trick the user into clicking the extension icon on a malicious page, at which point the screenshot would only capture what's already visible to the user.
- **Verdict:** FALSE POSITIVE - Permission model provides sufficient protection

## False Positive Analysis

| Flag | File | Assessment |
|------|------|------------|
| innerHTML usage | marker.js:188 | FP - Static hardcoded HTML for toolbar UI, no user input or XSS vector |
| Random code injection | marker.js:190 | FP - Probabilistic (50%) display of donation banner, hardcoded Ko-fi link |
| Keydown listener | marker.js:329-350 | FP - Keyboard shortcuts for drawing tools (Shift+D, Shift+H, etc.), NOT a keylogger, no data transmission |
| XMLHttpRequest in library | fabric.min.js:1221 | FP - Part of Fabric.js `fabric.util.request()` helper for loading SVG/images, never invoked by extension |
| Math.random() | marker.js:190 | FP - A/B test for donation button visibility, not fingerprinting or tracking |
| screen.height access | marker.js:171,312 | FP - Dynamic canvas sizing for responsive layout on tall pages |
| window.open() | marker.js:65 | FP - Opens blob URL preview of locally-generated screenshot |

## API Endpoints & Domains

| Domain | Protocol | Purpose | Risk | Data Sent | Verification |
|--------|----------|---------|------|-----------|--------------|
| pagemarker.org/installed | HTTPS | Post-install welcome page | LOW | None (tab navigation only) | User-visible |
| pagemarker.org/redirect/uninstall | HTTPS | Uninstall feedback survey | LOW | None (tab navigation only) | User-visible |
| pagemarker.org/donate | HTTPS | Ko-fi donation link (50% random) | LOW | None (user-initiated click) | User-visible |

**No API Endpoints:** Extension makes ZERO programmatic HTTP requests (no fetch, no XHR, no beacons).

**No Third-Party Domains:** All network activity confined to developer's own domain.

**No Analytics/Tracking:** No Google Analytics, Sentry, Mixpanel, Segment, or any telemetry platforms detected.

**No Market Intelligence SDKs:** No Sensor Tower Pathmatics, IAS, or similar data harvesting frameworks.

## Data Flow Summary

### Data Collected Locally
- **User Preferences** (via `chrome.storage.sync`)
  - Pen color (default: #FF0000)
  - Pen thickness (default: 5px)
  - Highlighter thickness (default: 22px)
  - Eraser thickness (default: 30px)
  - Text size (default: 20px)
  - **Storage Scope:** Chrome sync storage (synced across user's devices)
  - **Retention:** Persistent until user changes settings or uninstalls extension

- **Canvas State** (in-memory only)
  - Drawing objects (lines, shapes, text)
  - Undo/redo stack
  - **Storage Scope:** Page memory (destroyed on navigation)
  - **Retention:** Ephemeral - lost when user navigates away

- **Screenshots** (user-initiated)
  - Captured via `chrome.tabs.captureVisibleTab()` when user clicks "Save" button
  - Processed locally as base64 PNG data URL
  - Auto-downloaded to user's machine
  - Preview opened in new tab (blob URL)
  - **Retention:** Local filesystem only

### Sent to Server
**NONE** - Zero data transmission to any server.

### Not Collected
- Browsing history
- Visited URLs (except install/uninstall redirects)
- Form data
- Keystrokes (keyboard shortcuts tracked locally only)
- Cookies
- Authentication tokens
- DOM content from host pages
- Extension IDs of other installed extensions
- User identity or tracking IDs

### Data Flow Diagrams

**User Preferences Flow:**
```
User modifies settings in options.html
  → options.js: chrome.storage.sync.set()
  → Chrome Sync Storage (local + cloud sync)
  → marker.js: chrome.storage.sync.get() on activation
  → Applied to Fabric.js drawing tools
```
**No external transmission.**

**Screenshot Flow:**
```
User clicks "Save" button in marker.js UI
  → marker.js: chrome.runtime.sendMessage({from: 'content_script'})
  → background.js: chrome.tabs.captureVisibleTab()
  → Returns base64 PNG to marker.js via sendResponse()
  → marker.js creates <a download> element
  → Auto-download to user's filesystem
  → Blob URL preview opened in new tab
```
**No external transmission - 100% local processing.**

## Chrome API Usage Analysis

| API | Method | Justification | Legitimate Use |
|-----|--------|---------------|----------------|
| chrome.action | onClicked | Trigger canvas injection when user clicks icon | YES - User-initiated |
| chrome.scripting | executeScript | Inject Fabric.js library and marker.js | YES - Required for drawing functionality |
| chrome.scripting | insertCSS | Inject UI styles (main.css) | YES - Required for toolbar styling |
| chrome.tabs | captureVisibleTab | Screenshot feature | YES - User clicks "Save" button |
| chrome.tabs | create | Open welcome page on install | YES - Standard onboarding UX |
| chrome.tabs | onUpdated/onRemoved | State management | YES - Prevents memory leaks |
| chrome.runtime | setUninstallURL | Feedback survey | YES - Standard feedback mechanism |
| chrome.runtime | onMessage | Receive screenshot requests | YES - Content-background communication |
| chrome.storage.sync | get/set | User preferences | YES - Drawing tool settings only |

**No Dangerous APIs Used:**
- No `chrome.cookies` (not in permissions)
- No `chrome.webRequest` (not in permissions)
- No `chrome.management` (no extension enumeration)
- No `chrome.history` (not in permissions)
- No `chrome.downloads` (uses native <a download> instead)

## Comparison to Known Malicious Patterns

Reference: Project MEMORY.md - VPN Extension Malware Patterns

| Malicious Pattern | Page Marker | Malicious Examples |
|-------------------|-------------|-------------------|
| Extension enumeration | ❌ NO | ✅ VeePN, Troywell, Urban VPN |
| chrome.management API | ❌ NO | ✅ VeePN, Troywell |
| XHR/fetch monkey-patching | ❌ NO | ✅ Urban VPN, StayFree, StayFocusd |
| AI conversation scraping | ❌ NO | ✅ StayFree, Flash Copilot |
| Browsing history upload | ❌ NO | ✅ StayFree, StayFocusd |
| Remote config domains | ❌ NO | ✅ VeePN, Troywell, YouBoost |
| Obfuscated endpoints | ❌ NO | ✅ VeePN, Troywell |
| Hardcoded secrets/keys | ❌ NO | ✅ Flash Copilot |
| Dynamic code execution (eval) | ❌ NO in extension code | ✅ YouBoost |
| Sensor Tower Pathmatics SDK | ❌ NO | ✅ StayFree, StayFocusd |
| Ad injection | ❌ NO | ✅ YouBoost |
| Server-controlled behavior | ❌ NO | ✅ Troywell "thanos", YouBoost |

**Result:** Page Marker exhibits ZERO malicious patterns found in the 162 VPN extensions analyzed in this research project.

## Third-Party Dependencies

### Fabric.js v4.6.0
- **Purpose:** HTML5 canvas drawing library
- **Size:** 10,040 lines (minified, 415 KB)
- **License:** MIT (open-source)
- **Official Repo:** https://github.com/fabricjs/fabric.js
- **Modifications:** NONE - Matches official release
- **Network Activity:** Contains `fabric.util.request()` helper for loading SVG/images, but **NOT invoked by Page Marker extension**
- **Security Assessment:** CLEAN - Standard, widely-used canvas library with no modifications

**No other dependencies** - No React, Vue, jQuery, analytics SDKs, or ad networks.

## Content Security Policy

**Declared CSP:** None (uses Manifest v3 default)

**Effective CSP (MV3 default):**
```
script-src 'self'; object-src 'self'
```

**Security Assessment:**
- ✅ No `unsafe-inline` - Prevents inline script XSS
- ✅ No `unsafe-eval` - Prevents eval-based code execution
- ✅ No remote script sources
- ✅ No plugin execution allowed

**Result:** SECURE - Restrictive default CSP with no weakening directives

## Attack Surface Summary

### What This Extension CAN Do
- Inject drawing canvas onto current tab (when user clicks icon)
- Capture screenshot of visible tab content (when user clicks "Save")
- Store 5 user preferences locally (pen color, thickness, sizes)
- Open developer's website on install/uninstall events
- Display optional donation link (50% probability)

### What This Extension CANNOT Do
- Access tabs automatically without user clicking the icon
- Read page content or DOM persistently
- Intercept/modify network requests (no webRequest permission)
- Access cookies or authentication tokens (no cookies permission)
- Communicate with external servers (no fetch/XHR calls in code)
- Execute remote code (strict CSP enforced)
- Access browser history (no history permission)
- Monitor clipboard (no clipboard permission)
- Enumerate or disable other extensions (no management permission)

### Exploitability Assessment
- **XSS Risk:** NONE - Secure CSP, safe innerHTML usage (static HTML only)
- **Data Exfiltration:** NONE - No network communication channels
- **Privilege Escalation:** NONE - Minimal permissions (activeTab model)
- **Screenshot Abuse:** LOW - Only captures when user activates extension + clicks save
- **Keylogging:** NONE - Keyboard listener for shortcuts only, no data transmission
- **Malicious Update Risk:** MEDIUM - Relies on Chrome Web Store validation (standard for all extensions)

## Manifest Permissions Analysis

### Requested Permissions
```json
"permissions": [
  "activeTab",    // Access current tab when user clicks icon
  "storage",      // Store user preferences
  "scripting"     // Inject scripts/CSS
]
```

### Permission Justification

| Permission | Required Capability | Legitimate Use | Over-Reaching |
|------------|-------------------|----------------|---------------|
| activeTab | Inject canvas on demand | YES - Drawing tool needs DOM access | NO - User-initiated only |
| storage | Save tool settings | YES - Persist pen color/size preferences | NO - 5 settings only |
| scripting | Inject Fabric.js + marker.js | YES - Dynamic injection required for MV3 | NO - Replaces content_scripts |

### What Extension COULD Request but DOESN'T
- ❌ `<all_urls>` or broad host_permissions (uses activeTab instead)
- ❌ `tabs` (full access - only uses activeTab subset)
- ❌ `webRequest` / `webRequestBlocking`
- ❌ `cookies`
- ❌ `history`
- ❌ `management`
- ❌ `downloads` (uses native <a download> instead)
- ❌ `clipboardRead` / `clipboardWrite`
- ❌ `geolocation`
- ❌ `notifications`
- ❌ `proxy`

**Principle of Least Privilege:** HIGH COMPLIANCE - Requests only necessary permissions

## Privacy Assessment

### Data Minimization
- ✅ Collects only functional data (5 drawing tool settings)
- ✅ No PII (personally identifiable information)
- ✅ No tracking IDs or user fingerprinting
- ✅ No browsing history collection
- ✅ No form data harvesting

### Transparency
- ⚠️ No privacy policy link in manifest (minor issue)
- ✅ Clear extension description
- ✅ All network activity user-visible (tab navigations)

### User Control
- ✅ User initiates all actions (icon click to activate)
- ✅ User controls when screenshots are taken
- ✅ Screenshots processed locally (user downloads them)
- ✅ Settings editable via options page

### Third-Party Sharing
- ✅ NONE - No data sent to any third party
- ✅ No analytics platforms
- ✅ No ad networks
- ✅ No market intelligence SDKs

**Privacy Impact:** MINIMAL - Extension respects user privacy

## Code Quality & Transparency

### Obfuscation Analysis
- **background.js** (62 lines): Human-readable, well-structured
- **marker.js** (355 lines): Minified but clean variable names, no obfuscation
- **options.js** (69 lines): Human-readable
- **fabric.min.js** (10,040 lines): Standard library minification (expected)

**No Malicious Obfuscation:**
- ❌ No `atob()` / `btoa()` encoding
- ❌ No `String.fromCharCode()` character assembly
- ❌ No hex escapes (`\x41\x42...`)
- ❌ No eval() or Function() constructors (except in Fabric.js library)

### Dynamic Code Execution
**Status:** NONE in extension code

**Search Results:**
- `eval()`: Not found in background.js, marker.js, or options.js
- `new Function()`: Not found
- `importScripts()`: Not found (not applicable in MV3)
- `document.createElement('script')`: Not found

**Fabric.js Note:** Contains eval() for performance optimization in minified library code - this is standard and NOT used by the extension's logic.

## Overall Risk Assessment

**Risk Level: CLEAN**

### Justification

**Security Strengths:**
1. **Minimal Permission Footprint** - Uses `activeTab` instead of persistent host_permissions, requests only 3 permissions (activeTab, storage, scripting)
2. **User-Initiated Operation** - All functionality requires explicit user action (icon click)
3. **No Data Collection** - Zero telemetry, analytics, or user tracking
4. **No Network Activity** - Makes no programmatic HTTP requests (fetch/XHR)
5. **Local Processing Only** - Screenshots processed and downloaded locally, never uploaded
6. **Secure CSP** - Default MV3 CSP with no unsafe directives
7. **Transparent Code** - Readable source with no obfuscation (except standard library minification)
8. **Legitimate Library** - Uses unmodified Fabric.js v4.6.0 (MIT licensed)
9. **Proper MV3 Migration** - Service worker architecture, no persistent background pages

**Privacy Strengths:**
1. No PII collection
2. No browsing history access
3. No cookie/storage harvesting
4. No cross-site tracking
5. Settings stored locally only
6. No third-party data sharing

**Minor Observations (Non-Issues):**
1. Web accessible resources exposed to `<all_urls>` - enables fingerprinting but poses no security risk
2. Message handler lacks sender authentication - mitigated by activeTab permission model
3. Optional donation link shown 50% of time - ethical monetization, fully transparent

**Comparison to Malicious Extensions:**
Page Marker exhibits ZERO patterns found in the 31 SUSPECT VPN extensions analyzed in this research project (Urban VPN, VeePN, Troywell, StayFree, StayFocusd, Flash Copilot, etc.). It represents a textbook example of clean extension development.

### Recommendation

**CLEAN** - Safe for use without security or privacy concerns.

Page Marker is a legitimate, privacy-respecting browser extension that performs exactly one function (web page annotation) with minimal permissions and zero data collection. It can be used as a reference implementation for security best practices in Chrome extension development.

**For Users:**
- ✅ Safe to install and use
- ✅ No privacy risks
- ⚠️ Review screenshots before sharing (may contain sensitive info from the page you're annotating)
- ✅ Donation link is optional (can be ignored)

**For Researchers:**
- Use as clean baseline for comparison testing
- Example of proper `activeTab` permission usage
- Demonstrates local-only screenshot processing
- Shows ethical monetization via optional donation link

**For Security Auditors:**
- No further investigation required
- All three analysis agents (manifest, background, content) independently confirmed clean status
- No follow-up actions needed

---

## Analysis Metadata

**Analysis Date:** 2026-02-06
**Analysis Method:** Parallel multi-agent analysis (3 agents)
**Agent 1:** Manifest & Permissions Analysis
**Agent 2:** Background Script & Network Analysis
**Agent 3:** Content Scripts & Injection Surface Analysis
**Total Files Analyzed:** 8 (manifest.json, background.js, marker.js, options.js, options.html, popup.html, main.css, fabric.min.js)
**Lines of Code Reviewed:** 10,581 lines
**False Positives Identified:** 7
**True Vulnerabilities Found:** 0

**Analyst Consensus:** CLEAN (3/3 agents agree)
