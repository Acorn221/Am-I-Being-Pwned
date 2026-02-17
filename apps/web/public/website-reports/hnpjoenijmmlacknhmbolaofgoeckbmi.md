# Vulnerability Report: Youtube Unblocked

## Metadata
- **Extension ID**: hnpjoenijmmlacknhmbolaofgoeckbmi
- **Extension Name**: Youtube Unblocked
- **Version**: 1.1.1
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Youtube Unblocked is a proxy-based website unblocking extension that routes user traffic through third-party proxy servers to bypass network restrictions. The extension fetches proxy configurations dynamically from remote servers (`auth.unblockd.org`) and establishes authenticated proxy connections through services hosted at `browsebetter.io`.

The primary security concerns are: (1) the extension operates as a residential proxy service where user traffic is routed through proxy infrastructure without full transparency about the backend proxy model, (2) remote configuration fetching means proxy behavior can be altered post-installation, (3) multiple postMessage handlers without proper origin validation, and (4) detection and warning about other proxy extensions which constitutes extension enumeration.

While the extension appears to provide its stated functionality (YouTube unblocking), the lack of transparency about whether users may also serve as exit nodes for other users raises medium-level privacy concerns.

## Vulnerability Details

### 1. MEDIUM: Residential Proxy Functionality with Unclear User Consent
**Severity**: MEDIUM
**Files**: background.js, off_screen.js, checkkey.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension fetches proxy server configurations remotely from `https://auth.unblockd.org/v1/proxy/bridge` and routes user traffic through these proxies. The architecture supports tiered plans (Free, Speed, Quantum) with different proxy server pools and credentials fetched from the backend.

**Evidence**:
```javascript
// off_screen.js:6-27
const BRIDGE_URL = 'https://auth.unblockd.org/v1/proxy/bridge';
// ... creates iframe to fetch proxy config
if (event.data && event.data.type === 'PROXY_CONFIG') {
    cleanup();
    resolve(event.data.payload);
}
```

```javascript
// background.js:83-103
async function setIPs() {
    const config = await fetchProxyConfig();
    if (!config) { return; }
    const result = await chrome.storage.local.get(["plan_details"]);

    if (result.plan_details == "Speed" && config.speed) {
        proxyList = [...config.speed.servers];
    } else if (result.plan_details == "Quantum" && config.quantum) {
        proxyList = [...config.quantum.servers];
    } else if (config.free) {
        proxyList = [...config.free.servers];
    }
}
```

**Verdict**: While the extension's purpose is proxy-based unblocking, the remote configuration mechanism and tiered proxy architecture raise questions about transparency. The privacy policy should clearly disclose whether free-tier users serve as exit nodes for other users. This is a common monetization strategy for "free VPN" services but requires explicit user consent.

### 2. MEDIUM: Remote Configuration Control
**Severity**: MEDIUM
**Files**: background.js, off_screen.js
**CWE**: CWE-494 (Download of Code Without Integrity Check)
**Description**: Proxy server lists, credentials, and routing behavior are fetched dynamically from remote endpoints without integrity validation. This allows the backend to change proxy behavior post-installation.

**Evidence**:
```javascript
// background.js:11-34
async function fetchProxyConfig() {
    if (proxyConfig) return proxyConfig;

    const response = await chrome.runtime.sendMessage({
        action: 'fetchProxyConfig'
    });

    proxyConfig = response.data;
    return proxyConfig;
}
```

The proxy configuration includes server addresses, ports, usernames, and passwords - all controlled by the remote endpoint.

**Verdict**: Remote configuration is common for proxy services but represents a trust boundary. Users must trust the operator not to route traffic through malicious infrastructure. No code signing or integrity verification is performed on the fetched configuration.

### 3. MEDIUM: postMessage Handlers Without Origin Validation
**Severity**: MEDIUM
**Files**: yt2.js:58, workerscript.js:1, off_screen.js:29
**CWE**: CWE-940 (Improper Verification of Source of a Communication Channel)
**Description**: Multiple files implement `window.addEventListener("message")` handlers without proper origin validation, though impact is limited.

**Evidence**:
```javascript
// yt2.js:36-54
function handleMessage(event) {
    if (event.origin.indexOf("chrome-extension://" + chrome.runtime.id) != -1) {
        console.log('Received message:', event.data);
        if(event.data == "Close the yt-ub-rating boxx nao") {
            document.getElementById("yt_unblock_ratingbx").remove();
            chrome.storage.local.set({ "installdate": 1 });
        }
    }
}
```

**Verdict**: The handler in yt2.js checks for extension origin but uses `indexOf` instead of exact match (`===`). While the accepted message only closes a rating box (low impact), proper origin validation should use strict equality: `event.origin === "chrome-extension://" + chrome.runtime.id`.

The off_screen.js handler does validate origin correctly:
```javascript
// off_screen.js:21
if (event.origin !== 'https://auth.unblockd.org') return;
```

### 4. LOW: Extension Enumeration
**Severity**: LOW
**Files**: popup.js
**CWE**: CWE-200 (Exposure of Sensitive Information)
**Description**: The extension detects when other proxy extensions control the proxy settings and alerts the user to disable them.

**Evidence**:
```javascript
// popup.js:150-162
if(config[key] == "controlled_by_other_extensions") {
    var alrt = chrome.i18n.getMessage("misc_alert");
    if(alrt && alrt != undefined && alrt != null && alrt != "" && alrt != " ") {
        alert(alrt);
    } else {
        alert("For a seamless operation, please turn off other web-unblocking browser extensions.");
    }
}
```

**Verdict**: This is standard behavior for proxy/VPN extensions that need exclusive control of proxy settings. Not a security vulnerability but noted for completeness as extension enumeration.

## False Positives Analysis

**Web Worker Fetch Operations**: The workerscript.js performs fetch operations to `s3.browsebetter.io/checkcors.html` as a connectivity test. This is legitimate proxy testing, not data exfiltration.

**Offscreen Document**: The extension uses an offscreen document to run web workers, which is a legitimate MV3 pattern since service workers don't support web workers directly.

**Activation Key Validation**: The extension validates paid plan activation keys against `api.unblockd.org/v1/user/subscription`. This is normal for freemium software.

**Rating Box Injection**: After 3 days of use, the extension injects a rating prompt overlay on YouTube. While potentially annoying, this is common practice and the user can dismiss it.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| auth.unblockd.org/v1/proxy/bridge | Fetch proxy configuration | None (fetched via iframe bridge) | Medium - Controls proxy behavior |
| api.unblockd.org/v1/user/subscription | Validate activation keys | uniqueKey parameter | Low - Standard auth |
| s3.browsebetter.io/checkcors.html | Proxy connectivity test | None | Low - Test endpoint |
| s3.browsebetter.io (proxy routes) | All proxied traffic | All user traffic for unblocked sites | High - Privacy impact |
| unblockd.org/upgrade | Upgrade page | None | Low - Marketing |
| unblockd.org/feedback | Uninstall feedback | None | Low - Analytics |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

Youtube Unblocked is a functional proxy service that operates as advertised - it unblocks YouTube and user-specified websites by routing traffic through third-party proxies. However, it raises medium-level privacy concerns due to:

1. **Residential Proxy Architecture**: The tiered proxy system (Free/Speed/Quantum) with dynamically fetched credentials suggests a commercial proxy infrastructure. Free-tier users may unknowingly serve as exit nodes for other users, which is common in freemium proxy services but requires transparent disclosure.

2. **Remote Control**: All proxy behavior is controlled via remote configuration from `auth.unblockd.org`, allowing post-installation changes to routing behavior without user knowledge or consent.

3. **Privacy Impact**: All traffic to unblocked websites (YouTube by default, plus custom URLs) flows through third-party proxies operated by browsebetter.io. This exposes browsing activity to the proxy operator.

4. **Limited Security Issues**: The postMessage origin validation weakness is minor given the low-impact message handling.

The extension is NOT classified as HIGH risk because:
- Its proxy functionality is clearly stated in the name and description
- No evidence of hidden data exfiltration beyond the stated proxy behavior
- No credential theft or malicious code injection
- Users actively enable the proxy by clicking "Unblock"

However, users should be aware they are routing traffic through third-party infrastructure, and the privacy policy should clearly disclose whether free users participate in a residential proxy network.

**Recommendation**: Review the extension's privacy policy and terms of service to determine if the residential proxy model is adequately disclosed. If users serve as exit nodes without explicit consent, the risk level should be elevated to HIGH.
