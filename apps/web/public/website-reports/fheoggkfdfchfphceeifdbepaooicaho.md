# Vulnerability Report: McAfee WebAdvisor

## Metadata
- **Extension Name:** McAfee WebAdvisor
- **Extension ID:** fheoggkfdfchfphceeifdbepaooicaho
- **Version:** 8.1.0.8572
- **Manifest Version:** 3
- **User Count:** ~143,000,000
- **Analysis Date:** 2026-02-08

## Executive Summary

McAfee WebAdvisor is a legitimate security extension from McAfee LLC that provides web protection features including URL reputation checking, phishing/typosquatting detection, form field classification (IDPS), remote access tool detection, download scanning, and search annotation. The extension is highly invasive in terms of permissions and data collection, but all observed behaviors serve its stated security purpose. No malicious behavior, credential theft, ad injection, proxy infrastructure, or market intelligence SDK was found.

The extension communicates with McAfee's infrastructure (`threat.api.mcafee.com`, `mip.api.mcafeewebadvisor.com`, `sadownload.mcafee.com`, `einstein-core.awscommon.mcafee.com`, `analytics.apis.mcafee.com`, `report.api.mcafee.com`), all of which are first-party McAfee domains consistent with its security product functionality.

## Permissions Analysis

| Permission | Justification |
|---|---|
| `activeTab` | Site status checking on current tab |
| `alarms` | Scheduled tasks (engine updates, feature flag checks, telemetry) |
| `declarativeNetRequest` | Blocking malicious URLs via dynamic rules |
| `downloads` | Download scanning, native installer download |
| `nativeMessaging` | Communication with McAfee WPS native helper |
| `scripting` | Injecting content scripts for phishing/form detection |
| `storage` | Storing settings, caches, whitelists |
| `tabs` | Tab monitoring for navigation events |
| `unlimitedStorage` | Large datasets (typosquatting lists, engine data) |
| `webRequest` | Monitoring navigation for threat detection |
| `<all_urls>` (host) | URL reputation checking on all sites |

**Verdict:** Permissions are extensive but justified for a comprehensive web security product.

## Vulnerability Details

### MEDIUM - externally_connectable with ids: ["*"]

- **Severity:** MEDIUM
- **File:** `manifest.json` (line 56-58)
- **Code:** `"externally_connectable": { "ids": ["*"], "matches": ["https://*.mcafee.com/*"] }`
- **Details:** The manifest declares `ids: ["*"]` which means ANY Chrome extension can send messages to WebAdvisor. However, the actual code mitigates this by maintaining a hardcoded whitelist of approved McAfee extension IDs (`_initExtensionList()`). Unsupported extensions are forcefully disconnected: `"Unsupported external entity ${e.sender.id} is forcefully disconnected"`. Website connections are limited to `*.mcafee.com` origins and also validated against a supported URL list.
- **Verdict:** Low effective risk due to code-level validation, but the manifest-level `ids: ["*"]` is overly broad. A defense-in-depth approach would restrict to specific IDs in the manifest as well.

### MEDIUM - Feature Collection / Sailor Data Telemetry

- **Severity:** MEDIUM
- **Files:** `background.js`, `scripts/Sailer-Package/feature_collector.js`
- **Code:** `FEATURE_COLLECTION_ENABLED`, `DAILY_GREEN_URLS_TO_COLLECT`, `HERON_REPORT_ENABLED`
- **Details:** The "Sailor" feature collector extracts page features (DOM structure, form fields, link patterns, etc.) using WASM and sends them to McAfee's Heron API for ML-based phishing detection model training. This is gated behind `FEATURE_COLLECTION_ENABLED` (default `false`) and `DAILY_GREEN_URLS_TO_COLLECT` (default `0`), controlled by native settings from the McAfee WPS client. A domain blocklist prevents collection on sensitive domains. Data is sent with sampling rates.
- **Verdict:** Legitimate security ML training pipeline but represents significant page-level telemetry when enabled. Users may not be fully aware of this data collection.

### LOW - Remote Config via Feature Flags

- **Severity:** LOW
- **File:** `background.js`
- **Code:** Feature flag system fetching from `sadownload.mcafee.com/products/SA/Win/extensions/waextension/featureflag`
- **Details:** The extension has a feature flag system that can remotely modify extension behavior including toggling features, appending/replacing/removing settings, and triggering `chrome.runtime.reload()`. The flags are fetched from McAfee's own infrastructure.
- **Verdict:** Standard remote configuration pattern for enterprise security software. All URLs are first-party McAfee domains. The reload capability could theoretically be abused if McAfee's CDN were compromised, but this applies to any auto-updating extension.

### LOW - WebSocket to localhost

- **Severity:** LOW
- **File:** `background.js`
- **Code:** `ws://127.0.0.1:${this.port}/`
- **Details:** The extension establishes WebSocket connections to localhost for communication with the McAfee native helper (WPS) for features like MockingBird (deepfake detection) audio streaming. This is standard native messaging supplementation.
- **Verdict:** Expected behavior for an extension that integrates with a native desktop security product.

### LOW - Native Messaging / connectNative

- **Severity:** LOW
- **File:** `background.js`
- **Code:** `chrome.runtime.connectNative(this.nativeConnectionString)`
- **Details:** The extension connects to a native messaging host for communicating with McAfee's local security product. Settings, scan requests, and telemetry are exchanged. The native host can trigger extension reload (`RESTART` message type) and URL redirects (`REDIRECT_URL`).
- **Verdict:** Expected for enterprise security software with a desktop companion product. The native host is McAfee's own product.

## False Positive Table

| Pattern | Location | Reason |
|---|---|---|
| `innerHTML` reads | `background.js` (Sailor feature collector) | Reading DOM for phishing page classification, not writing |
| `document.cookie` read | `content_annotation.js` | Checking Bing secure search partner code in cookie, not harvesting |
| Form field XPath patterns | `background.js` (embedded JSON) | Training data for ML form classifier - known login/CC pages for model validation |
| `chrome.management.uninstallSelf` | `background.js` | Self-uninstall only, not enumerating other extensions |
| `btoa()` / Base64 encoding | `background.js` | Encoding URLs for API queries (reputation lookup), NPS survey RSA encryption |
| `wasm-unsafe-eval` in CSP | `manifest.json` | Required for WASM modules (typosquatting detection, cryptographic operations) |
| `Reflect.apply` | `background.js` | MockingBird hooking of video element methods for deepfake detection, not malicious hooking |
| Yahoo search suggestion URL | `background.js` | McAfee Secure Search integration - search suggestions via Yahoo partnership |

## API Endpoints Table

| Endpoint | Purpose | Method |
|---|---|---|
| `threat.api.mcafee.com` | URL reputation lookup, HTI reports | GET/POST |
| `image.threat.api.mcafee.com` | Site favicon/image service | GET |
| `mip.api.mcafeewebadvisor.com/v1/typosquatting` | Typosquatting detection API | GET |
| `sadownload.mcafee.com/products/SA/Win/extensions/` | Engine updates, feature flags, typosquatting lists, anti-tracker data | GET |
| `analytics.apis.mcafee.com` | Product telemetry/analytics | POST |
| `report.api.mcafee.com` | HTI threat reports | POST |
| `csptoken.ccs.mcafee.com/auth/token` | CSP authentication token | POST |
| `auth.api.mcafee.com/auth/v1/jwt` | JWT authentication | POST |
| `einstein-core.awscommon.mcafee.com` | Einstein API (subscription, app config) | GET/POST |
| `securitymgmt.unifiedapis.mcafee.com` | Security management, auth tokens | POST |
| `identity.unifiedapis.mcafee.com/breach/v1/BreachCount` | Data breach monitoring | GET |
| `publicsuffix.org/list/public_suffix_list.dat` | Public suffix list for domain parsing | GET |
| `data.iana.org/TLD/tlds-alpha-by-domain.txt` | TLD list | GET |
| `us.search.yahoo.com/sugg/gossip/gossip-us-partner` | Yahoo search suggestions (Secure Search) | GET |
| `ws://127.0.0.1:{port}` | Local native helper communication | WebSocket |

## Data Flow Summary

1. **URL Reputation:** On every navigation, the URL is sent to `threat.api.mcafee.com` for reputation scoring (GREEN/YELLOW/RED/PHISHING/TYPOSQUATTING). Blocked pages show a warning with override option.
2. **Form Detection (IDPS):** Content scripts use ML-based form field classification (CRF model with transition probabilities embedded in background.js) to identify login forms, credit card forms, and signup forms. This feeds into McAfee's Identity Protection Service for password reuse warnings and breach monitoring.
3. **Typosquatting Detection:** WASM module checks visited URLs against an encrypted typosquatting list (downloaded from McAfee CDN) and also queries the typosquatting API for real-time checks.
4. **Feature Collection (Sailor):** When enabled by native settings, the Sailer feature collector extracts page-level features (DOM structure, form nodes, link patterns) via WASM for McAfee's phishing ML model training. Data goes to the Heron API. Gated behind feature flags and sampling.
5. **MockingBird (Deepfake Detection):** Hooks video/audio elements to detect deepfake content. Audio streamed to local native helper via WebSocket for analysis.
6. **RAT Detection:** Identifies remote access tool websites (tech support scam pages) using a blacklist and shows warnings.
7. **Search Annotation:** Annotates search results on major search engines (Google, Bing, Yahoo) with safety ratings.
8. **Telemetry:** Extensive product analytics sent to `analytics.apis.mcafee.com` tracking feature usage, block events, search interactions, and extension health metrics.
9. **Native Communication:** Bidirectional messaging with McAfee WPS desktop product for settings sync, download scanning, and security state management.

## Overall Risk Assessment

**Risk: CLEAN**

McAfee WebAdvisor is a legitimate, well-known security product from a major cybersecurity company. While it requests extensive permissions and collects significant telemetry data, all observed behaviors are consistent with its stated purpose as a comprehensive web protection tool. Key findings:

- **No eval/new Function/dynamic code execution** (0 instances)
- **No credential theft or password exfiltration** - form detection is for classification/protection only
- **No ad injection or coupon injection**
- **No proxy/residential proxy infrastructure**
- **No market intelligence SDKs (Sensor Tower, Pathmatics, etc.)**
- **No extension enumeration** (only `management.uninstallSelf`)
- **No XHR/fetch hooking** for data interception
- **All API endpoints are first-party McAfee domains**
- **External messaging is validated** against hardcoded extension ID whitelist despite `ids: ["*"]` in manifest

The extension is invasive by nature (security product monitoring all web activity) but serves its intended purpose with no clear malicious behavior or exploitable vulnerabilities.
