# Vulnerability Report: HP Wolf Security Extension

## Metadata
- **Extension Name:** HP Wolf Security Extension
- **Extension ID:** gpmlagmcbcnjhkdjiofoenkfbaclgjkk
- **Users:** ~4,000,000
- **Version:** 32.1.2.3
- **Manifest Version:** 3
- **Publisher:** HP Development Company, L.P. (formerly Bromium)
- **Analysis Date:** 2026-02-08

## Executive Summary

HP Wolf Security (formerly HP Sure Click / Bromium) is a legitimate enterprise endpoint security extension designed to protect users from phishing, credential theft, malicious file downloads, and unsafe URL navigations. The extension communicates with a native host helper application (`com.bromium.hosthelper`) installed on the endpoint and with HP's threat intelligence cloud services. While the permission set is broad, every permission is clearly justified by the extension's security protection functionality. No malicious behavior, data exfiltration, ad injection, proxy infrastructure, or suspicious patterns were found.

## Permissions Analysis

| Permission | Justification | Risk |
|---|---|---|
| `<all_urls>` (host) | Needed to inspect all web navigations for phishing/malware | Expected for security extension |
| `webRequest` + `webRequestBlocking` | Intercepts navigations to block phishing/untrusted URLs before they load | Core functionality |
| `tabs` | Tracks tab navigation sequences, manages blocked page redirects | Core functionality |
| `nativeMessaging` | Communicates with `com.bromium.hosthelper` native app for endpoint security decisions | Core functionality |
| `storage` + `unlimitedStorage` | Caches phishing lists, URL statuses, config, domain age data | Expected |
| `downloads` | Monitors file downloads for malicious content | Core functionality |
| `contextMenus` | "Open in Secure Browser" context menu option | Expected |
| `history` | Seeds identity protection allow-list from browsing history; removes extension page history entries | Expected |
| `alarms` | Periodic tasks: list refresh, heartbeat, cache cleanup | Expected |

## Vulnerability Details

### 1. INFORMATIONAL: Broad Permissions Appropriate for Security Extension

- **Severity:** INFORMATIONAL
- **Files:** `manifest.json`
- **Details:** The extension requests `<all_urls>`, `webRequestBlocking`, `tabs`, `nativeMessaging`, `history`, and `downloads`. While this is an extremely broad set, every permission maps directly to a legitimate security feature (phishing protection, link protection, download protection, credential protection, URL filtering).
- **Verdict:** FALSE POSITIVE - Expected for enterprise security product.

### 2. INFORMATIONAL: Content Script Runs on All URLs with Input Monitoring

- **Severity:** INFORMATIONAL
- **Files:** `scripts/content-script/main.js`
- **Details:** The content script injects into all frames on all URLs. It monitors DOM for password fields and "interesting input elements" to detect potential credential phishing pages. When it detects a suspicious page (uncategorized/blocked domain + password field), it can disable input elements to prevent credential entry. It also monitors for focus/input events on password fields and requests screenshot analysis from the background script.
- **Verdict:** FALSE POSITIVE - This is the identity protection / anti-phishing feature. No data is exfiltrated; the content script only communicates categorization signals and detection events to the background script via chrome.runtime ports.

### 3. INFORMATIONAL: Native Messaging to Host Helper

- **Severity:** INFORMATIONAL
- **Files:** `main.js` (lines 12820-12821)
- **Code:** `chrome.runtime.connectNative(hostConstants.hostHelperId)` where `hostHelperId = "com.bromium.hosthelper"`
- **Details:** The extension connects to a native host application for: phishing report submission, URL categorization, config management, secure browser launching, heartbeat monitoring, and download protection. The native app must be separately installed on the endpoint (typical HP Wolf Security enterprise deployment).
- **Verdict:** FALSE POSITIVE - Standard native messaging for enterprise endpoint security.

### 4. INFORMATIONAL: Cloud API Calls for Threat Intelligence

- **Severity:** INFORMATIONAL
- **Files:** `main.js`
- **Endpoints contacted:**
  - `{threatCloudOrigin}/identity-protection/domain-whois/` - Domain age checks
  - `{threatCloudOrigin}/url-status/status/` - URL safety classification
  - `{threatCloudOrigin}/deviceapi/credential-protection-url-list/` - Phishing blocklist
  - `{threatCloudOrigin}/identity-protection/url-classification/` - URL classification
  - `https://brcl-sureclick.bromium-online.com` - Default cloud origin
  - `https://hpwolfsecurity-help.hpwolf.com/extension/` - Help pages
- **Details:** All cloud endpoints use config-provided origin + auth params. The URLs queried are the ones the user navigates to (sent for classification). This is standard threat intelligence lookup behavior for security products.
- **Verdict:** FALSE POSITIVE - Expected for cloud-based threat intelligence.

### 5. INFORMATIONAL: Screenshot Capture Capability

- **Severity:** INFORMATIONAL
- **Files:** `main.js` (line 11378), `scripts/content-script/main.js`
- **Code:** `chrome.tabs.captureVisibleTab(tab.windowId, screenshotData => ...)`
- **Details:** The extension can capture screenshots of the visible tab when a phishing detection is triggered. Screenshots are sent to the native host helper as part of phishing reports. This is triggered only when the content script detects a suspicious page with credential input fields.
- **Verdict:** FALSE POSITIVE - Standard enterprise phishing report evidence collection.

## False Positive Table

| Pattern | Location | Why It's a False Positive |
|---|---|---|
| `<all_urls>` permissions | manifest.json | Required for security scanning of all web traffic |
| `webRequestBlocking` | manifest.json | Needed to block phishing/malicious navigations before loading |
| DOM monitoring for inputs | content-script/main.js | Anti-phishing credential protection, not keylogging |
| `chrome.history.search` | main.js | Seeds identity protection allow-list from browsing history |
| `chrome.history.deleteUrl` | main.js | Removes extension's own blocked-page URLs from history |
| `chrome.tabs.captureVisibleTab` | main.js | Phishing report screenshot evidence only |
| `chrome.runtime.connectNative` | main.js | Enterprise native host for security decisions |
| `chrome.downloads.onCreated/onChanged` | main.js | Download protection feature |
| `chrome.runtime.sendMessage` to other extensions | main.js | Link Protection Service sends block events to configured consumer extensions (e.g., HP Sure Click Secure Browser) |
| URL sends to cloud API | main.js | Threat intelligence classification lookups |

## API Endpoints Table

| Endpoint | Purpose | Data Sent |
|---|---|---|
| `{origin}/identity-protection/domain-whois/?...&domains=` | Domain age check | Hostname of navigated URL |
| `{origin}/url-status/status/?...&urls=` | URL safety classification | Full URL |
| `{origin}/deviceapi/credential-protection-url-list/` | Fetch BEC phishing blocklist | If-Modified-Since header |
| `{origin}/identity-protection/url-classification/?...&urls=` | URL category classification | Full URL |
| `https://hpwolfsecurity-help.hpwolf.com/extension/{version}/{locale}/` | Help page content | None (static page fetch) |

## Data Flow Summary

1. **Configuration:** Native host helper sends config to extension on startup via native messaging port. Config includes: enabled features, operation mode, threat cloud origin, auth params, trusted/untrusted URL lists, blocked categories.

2. **Navigation Protection:** `webRequest.onBeforeRequest` intercepts all main-frame navigations. URLs are categorized against: HP Cloud blocklist, customer BEC list, endpoint categorization (via native host), domain age checks, user allow-list, and navigation sequence pattern detection. Untrusted/phishing URLs are redirected to a blocked page or launched in HP Secure Browser.

3. **Credential Protection:** Content script monitors pages for password/input fields. On phishing-categorized pages, inputs can be disabled. When detection is tripped, a phishing report is prepared and sent via native messaging to the endpoint security platform.

4. **Download Protection:** Monitors `chrome.downloads` events and notifies the native host about new/completed downloads for scanning.

5. **URL Filtering:** Post-navigation, URLs are checked against HP's cloud threat intelligence for safety status and category blocking.

6. **Screenshot Analysis:** When a suspicious page with credential inputs is detected, the extension captures a tab screenshot and sends it to the native host for logo analysis (detecting impersonation of protected brands).

## Overall Risk Assessment

**CLEAN**

This is a legitimate enterprise endpoint security extension from HP (formerly Bromium). The broad permissions are fully justified by its security protection features: phishing detection, credential protection, link protection, download protection, URL filtering, and secure browser integration. All data flows are to HP's own threat intelligence infrastructure and the locally-installed native host helper. No evidence of:

- Data exfiltration or excessive data collection
- Cookie/credential harvesting
- Keylogging
- Ad/coupon injection
- Proxy/residential proxy infrastructure
- Remote code execution or dynamic code loading
- Market intelligence SDKs
- Extension enumeration or killing
- Obfuscation (code is webpack-bundled but cleanly deobfuscated)

The `externally_connectable` manifest field has empty `ids` and `matches` arrays, meaning no external websites or extensions can communicate with it. The extension only communicates outward to configured consumer extensions via the Link Protection Service.
