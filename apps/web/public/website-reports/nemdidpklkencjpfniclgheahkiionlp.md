# Vulnerability Report: Advanced Ad Blocker

## Metadata
- **Extension ID**: nemdidpklkencjpfniclgheahkiionlp
- **Extension Name**: Advanced Ad Blocker
- **Version**: 2.0.2
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Advanced Ad Blocker is a legitimate ad-blocking extension that uses declarativeNetRequest and content script injection to block advertisements. The extension contacts advancedadblocker.com to fetch updated blocking rules and maintain a unique installation identifier (enuid). While the extension collects a unique user identifier on installation, this appears to be for update management purposes rather than tracking. The extension implements standard ad-blocking functionality with CSS injection, extended CSS selectors, scriptlet injection, and declarative network request rules. No evidence of data exfiltration, malicious behavior, or privacy violations beyond the stated ad-blocking purpose was found.

The extension uses legitimate ad-blocking techniques similar to popular ad blockers like uBlock Origin and AdGuard, including remote filter list updates, CSS-based element hiding, and network request blocking via declarativeNetRequest.

## Vulnerability Details

### 1. LOW: Remote Configuration Without Explicit User Consent
**Severity**: LOW
**Files**: service_worker.js, adscb_updater.js, adscb_net_updater.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: On installation, the extension generates a unique user identifier (enuid) by fetching from `https://advancedadblocker.com/start/`. This identifier is sent with all subsequent update requests to fetch new blocking rules. The identifier is also sent as an uninstall tracking URL.

**Evidence**:
```javascript
// service_worker.js
chrome.runtime.onInstalled.addListener(async e=>{
  if(e.reason===chrome.runtime.OnInstalledReason.INSTALL){
    var n=await(await fetch("https://advancedadblocker.com/start/")).json();
    await chrome.storage.local.set({enuid:n.enuid});
    chrome.runtime.setUninstallURL("https://advancedadblocker.com/bye/?enuid="+n.enuid)
  }
});
```

**Verdict**: This is a common practice for ad blockers to track update requests and uninstall rates. The enuid appears to be session-based and used for analytics rather than cross-site tracking. However, the extension does not explicitly disclose this identifier generation in the Chrome Web Store description. This is a minor privacy concern but does not constitute malicious behavior.

### 2. LOW: Content Script Injection in All Frames
**Severity**: LOW
**Files**: manifest.json, service_worker.js
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension injects content scripts into all frames (`all_frames: true`) and matches `<all_urls>`, including `match_about_blank: true`. While necessary for comprehensive ad blocking, this provides broad access to web page content.

**Evidence**:
```json
"content_scripts": [{
  "match_about_blank": true,
  "all_frames": true,
  "js": ["layunvvh.js", "adscb_rule_cache.js", "adscb_adblocker.js", "dxnuit.js"],
  "run_at": "document_start",
  "matches": ["*://*/*"]
}]
```

Additionally, the service worker dynamically registers scripts into both MAIN and ISOLATED worlds:
```javascript
await chrome.scripting.registerContentScripts([
  {id:"id_cs_main", js:["/adscb_scriptlets.js"], world:"MAIN", ...n},
  {id:"id_cs_isolated", js:["/adscb_adblocker.js"], world:"ISOLATED", ...n}
])
```

**Verdict**: This is standard and necessary for ad-blocking functionality. Injecting into the MAIN world is required to run scriptlets that can intercept and block ads that check for ad blocker detection. The extension uses these permissions appropriately for its stated purpose.

## False Positives Analysis

1. **Remote code execution**: The extension fetches blocking rules from remote servers, but these are CSS selectors, scriptlet names, and declarativeNetRequest rules stored as JSON data. No arbitrary JavaScript code is fetched and executed.

2. **Data exfiltration**: The enuid identifier is sent with update requests, but no browsing data, cookies, or personal information is transmitted. The static analyzer found no exfiltration flows.

3. **Obfuscation**: The code uses minified variable names typical of webpack builds, but this is standard for production extensions, not intentional obfuscation to hide malicious behavior.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| advancedadblocker.com/start/ | Generate unique installation ID | None | Low - identifier generation |
| advancedadblocker.com/updates/list/ | Fetch list of available filter updates | enuid parameter | Low - update check |
| advancedadblocker.com/updates/netlist/ | Fetch declarativeNetRequest rule updates | enuid parameter | Low - filter list update |
| advancedadblocker.com/bye/?enuid={id} | Track uninstalls | enuid in URL | Low - uninstall analytics |

All endpoints use HTTPS and belong to the extension's operator. No third-party analytics or tracking services detected.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**: This extension implements legitimate ad-blocking functionality using standard Chrome extension APIs. While it generates a unique identifier for tracking installations and updates, this is a common practice among ad blockers and does not constitute privacy invasion. The extension does not collect browsing history, intercept credentials, exfiltrate user data, or engage in any malicious behavior. The remote configuration updates are limited to ad-blocking filter lists (CSS selectors, network blocking rules, and scriptlet names) rather than executable code.

The extension's behavior is consistent with its stated purpose of blocking advertisements. All network requests are to the extension operator's domain for legitimate update purposes. The use of declarativeNetRequest for network blocking is privacy-preserving, as it does not require reading request content. The extension follows modern Chrome extension best practices by using Manifest V3 and declarativeNetRequest instead of the deprecated webRequest API.

**Recommendation**: The extension is safe to use. Users concerned about the unique identifier should be aware that most ad blockers use similar techniques to manage filter updates and measure adoption.
