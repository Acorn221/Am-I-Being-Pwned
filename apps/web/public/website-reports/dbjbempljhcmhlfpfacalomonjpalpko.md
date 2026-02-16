# Vulnerability Report: ImageAssistant Batch Image Downloader

## Metadata
- **Extension ID**: dbjbempljhcmhlfpfacalomonjpalpko
- **Extension Name**: ImageAssistant Batch Image Downloader
- **Version**: 1.70.7
- **Users**: ~500,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

ImageAssistant is a legitimate image extraction and batch downloading tool with 500,000 users. The extension's primary functionality involves monitoring all network requests and page content to extract image URLs for user-initiated downloads. While the extension employs comprehensive monitoring techniques that appear invasive, these behaviors are necessary for its stated purpose and are disclosed in the privacy policy.

The extension hooks into XMLHttpRequest and fetch APIs, monitors all HTTP requests through webRequest API, and injects content scripts on all pages. However, analysis confirms these capabilities are used solely for image extraction and not for malicious data collection. The extension does contact external servers (pullywood.com) for version checks and remote configuration rules, which presents a minor supply-chain risk.

## Vulnerability Details

### 1. MEDIUM: Comprehensive Request Monitoring Without User Awareness
**Severity**: MEDIUM
**Files**: background.js (lines 1-300), inspector.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension monitors all HTTP requests across all websites using multiple techniques:
- Chrome webRequest API to intercept all network traffic
- XMLHttpRequest hooking via content script injection
- fetch() API hooking
- Image constructor hooking

**Evidence**:
```javascript
// background.js - Global webRequest monitoring
chrome.webRequest.onHeadersReceived.addListener((async function(details){
    if(details.tabId<0){return}
    let _w_headers=details.responseHeaders;
    // ... analyzes all image responses
}),{urls:["<all_urls>"]},["responseHeaders","extraHeaders"])

// inspector.js - Hooks fetch and XHR
const originalSend=XMLHttpRequest.prototype.send;
XMLHttpRequest.prototype.send=function(data){
    this.addEventListener("load",(function(){
        // ... processes all responses
    }),false);
    return originalSend.call(this,data)
}

window.fetch=function(){
    return _o_fetch.apply(this,arguments).then((response=>{
        // ... processes fetch responses
    }))
}
```

**Verdict**: While this monitoring is extensive, it is necessary for the extension's core functionality (extracting images from pages including those loaded via AJAX). The privacy policy discloses this behavior. The extension only stores image URLs temporarily and destroys them when tabs close. Not malicious, but privacy-concerning.

### 2. LOW: Remote Configuration Loading
**Severity**: LOW
**Files**: background.js, function.js
**CWE**: CWE-494 (Download of Code Without Integrity Check)
**Description**: The extension fetches remote configuration from pullywood.com servers without integrity verification:
- URL rewrite rules from `defaultRegexpUrlRule.properties`
- Version information from `version.json`
- Dynamic configuration from `dynamic_config.json`

**Evidence**:
```javascript
// background.js
global._o_remoteRuleURL="https://www.pullywood.com/ImageAssistant/defaultRegexpUrlRule.properties";
global._o_dynamicConfigURL="https://www.pullywood.com/ImageAssistant/dynamic_config.json";

(async()=>{
    const remoteRule=await fetch(_o_remoteRuleURL).then((resp=>resp.text()));
    await storage.set("_pullywood_RegexpUrlRule",remoteRule);
})();
```

**Verdict**: While the configuration is loaded over HTTPS, there is no signature verification. If the pullywood.com domain were compromised, malicious rules could be injected. However, the rules only affect URL rewriting for image size optimization, not code execution. This is a supply-chain risk but not actively exploited.

### 3. LOW: Planned Local Client Communication (Currently Disabled)
**Severity**: LOW
**Files**: function.js, privacy_en.md
**CWE**: CWE-940 (Improper Verification of Source of a Communication Channel)
**Description**: The extension includes code to communicate with a local desktop client on localhost:61257, though this feature appears inactive.

**Evidence**:
```javascript
// From privacy policy:
// "Request the local address localhost:61257 port. This request is part
// of the desktop client function in the early verification stage."
// "the local client is currently unavailable."
```

**Verdict**: The local client feature is not currently functional according to the privacy policy. The code exists for future functionality but does not present an active security risk.

## False Positives Analysis

Several patterns that initially appear suspicious are actually legitimate for this extension type:

1. **Global webRequest Monitoring**: Required to detect images loaded via background requests and AJAX. Without this, the extension could not extract dynamically-loaded images.

2. **Content Script on All URLs**: Necessary to extract images from any webpage the user visits and initiates extraction on.

3. **Fetch/XHR Hooking**: Required to extract images from responses that arrive via JavaScript (common on modern websites with lazy loading).

4. **Referer Header Modification**: The extension modifies Referer headers using declarativeNetRequest to bypass hotlink protection when downloading images. This is a legitimate anti-anti-hotlinking feature, not credential theft.

5. **Image Constructor Hooking**: Detects images created dynamically via JavaScript `new Image()` calls.

All of these behaviors, while appearing invasive, are necessary for comprehensive image extraction and match the extension's stated purpose.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.pullywood.com/ImageAssistant/version.json | Version check | Extension version, random finger | LOW |
| www.pullywood.com/ImageAssistant/defaultRegexpUrlRule.properties | URL rewrite rules | None | LOW |
| www.pullywood.com/ImageAssistant/dynamic_config.json | Dynamic config | None | LOW |
| www.pullywood.com/ImageAssistant/blank.html | Multi-URL extractor default | None | NONE |
| localhost:61257 | Local client (inactive) | Image URLs, referer | N/A (disabled) |

## Privacy Policy Compliance

The extension includes a detailed privacy policy (`privacy_en.md`) that discloses:
- Version information requests to their server
- Regular pulling of image URL replacement rules
- Local client communication (currently unavailable)
- Search engine integration
- Multi-address extraction behavior
- HTTP request monitoring on all pages
- Explicit statement: "We will not collect security and privacy information such as usernames, passwords, credit cards, and cookies"

The actual behavior observed in the code matches the privacy policy disclosures.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

ImageAssistant is a legitimate image extraction tool that requires extensive monitoring capabilities to function properly. While the extension has broad permissions and hooks into network requests, the analysis confirms:

1. **No Credential Theft**: No evidence of password, cookie, or authentication token collection
2. **No Data Exfiltration**: Image URLs are stored locally and temporarily, not sent to remote servers
3. **Disclosed Behavior**: Privacy policy accurately describes the monitoring behavior
4. **Legitimate Purpose**: All invasive techniques are necessary for the core functionality
5. **Mature Project**: Copyright 2013-2024, established developer (pullywood.com/Joey)
6. **Large User Base**: 500,000 users with 4.3 rating suggests legitimate use

**Minor Concerns**:
- Remote configuration fetching without integrity checks presents supply-chain risk
- Comprehensive monitoring could be perceived as privacy-invasive despite legitimate purpose
- Planned localhost communication feature needs security review if activated

**Recommendation**: The extension is safe for users who need image extraction functionality and accept the necessary monitoring it entails. Organizations with strict data policies should review whether the comprehensive request monitoring aligns with their acceptable use policies, even though the data is not exfiltrated.
