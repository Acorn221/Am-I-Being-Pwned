# Vulnerability Report: hide.me Proxy

## Metadata
- **Extension ID**: ohjocgmpmlfahafbipehkhbaacoemojp
- **Extension Name**: hide.me Proxy
- **Version**: 1.3.0
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

hide.me Proxy is a legitimate VPN/proxy browser extension from hide.me, a well-known VPN provider. The extension provides proxy functionality to allow users to route their browser traffic through hide.me's proxy servers. The extension uses standard Chrome proxy and privacy APIs to configure SOCKS5 proxies and manage WebRTC settings to prevent IP leaks.

Analysis reveals that this is a clean implementation of proxy functionality with appropriate user consent and no hidden malicious behavior. The extension fetches proxy server configurations from remote endpoints, which is standard and expected for this type of service. All network communication is transparent and serves the extension's stated purpose.

## Vulnerability Details

### 1. LOW: Remote Configuration Fetching
**Severity**: LOW
**Files**: servers.js
**CWE**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
**Description**: The extension fetches proxy server lists from remote endpoints without verification. It retrieves server configurations from both a hardcoded IP address (`http://188.166.142.39/servers/list`) and a GitHub repository (`https://raw.githubusercontent.com/hidemevpn/proxy/master/config.json`).

**Evidence**:
```javascript
// servers.js
Servers.proxyAPIServerIP = "188.166.142.39";
Servers.fallbackServersListURL = "https://raw.githubusercontent.com/hidemevpn/proxy/master/config.json";

Servers.pullServerList = async function(callback) {
    await Servers.setServerListAndFlagsDefaults();
    let url = `http://${Servers.proxyAPIServerIP}/servers/list`;
    Servers.pullRemoteList(url, callback);
};

Servers.pullFallbackList = function (callback) {
    Servers.pullRemoteList(Servers.fallbackServersListURL, callback);
};
```

**Verdict**: This is standard behavior for a VPN/proxy service. The extension needs to fetch updated server lists to provide current proxy endpoints. This is not a vulnerability in the context of a legitimate proxy service, as users install the extension specifically to use hide.me's proxy infrastructure. The remote configuration is controlled by the extension publisher (hide.me).

## False Positives Analysis

### Content Script on All URLs
The extension injects a content script on all URLs (`*://*/*`), which might appear suspicious. However, this script (`content.js`) only detects whether the current page was fetched via HTTP/2 or QUIC protocols to provide privacy checkup information to users. It does not collect browsing data or inject ads:

```javascript
// content.js - only checks protocol information
function connectionInfo() {
  if (window.PerformanceNavigationTiming) {
    const ntEntry = performance.getEntriesByType('navigation')[0];
    return ntEntry.nextHopProtocol;
  }
}
```

This is a legitimate privacy feature to help users verify their connection security.

### Host Permissions `<all_urls>`
The extension requests `<all_urls>` host permissions, which is necessary for proxy extensions to route all browser traffic through the proxy. This is standard and expected for VPN/proxy extensions.

### Privacy API Usage
The extension uses `chrome.privacy.network.webRTCIPHandlingPolicy` to disable WebRTC, which prevents IP leakage when using the proxy. This is a privacy-enhancing feature, not a vulnerability:

```javascript
// privacy.js
Privacy.hidemeWebRTCDisablePolicy = "disable_non_proxied_udp";

Privacy.disableWebRTC = function() {
    Privacy.clearWebRTCError();
    Privacy.checkAndSetWebRTCIPHandlingPolicy(Privacy.hidemeWebRTCDisablePolicy);
    Utils.setStorage({'_webrtc_disabled': true});
};
```

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| http://188.166.142.39/servers/list | Fetch available proxy servers | None (GET request) | Low - legitimate server list endpoint |
| https://raw.githubusercontent.com/hidemevpn/proxy/master/config.json | Fallback proxy server list | None (GET request) | Low - fallback configuration |
| socks.hide.me:1080 | SOCKS proxy endpoint | All browser traffic (when proxy enabled) | Low - expected proxy behavior with user consent |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
This is a legitimate proxy extension from a reputable VPN provider (hide.me). The extension implements standard proxy functionality using Chrome's proxy API. While it fetches configuration from remote servers and has broad permissions, all of this is necessary and expected for a proxy service.

The single low-severity issue identified (remote configuration) is standard practice for VPN/proxy services and poses minimal risk given:
1. The extension is from a known VPN provider
2. Users explicitly install it to use hide.me's proxy service
3. The functionality is transparent and matches the stated purpose
4. No evidence of data exfiltration, hidden tracking, or malicious behavior
5. Privacy features (WebRTC blocking) are implemented to protect users

The extension properly implements error handling, checks for conflicting extensions, and provides user-facing settings for configuration. The code is clean, well-structured, and does not contain obfuscation or suspicious patterns.

**Recommendation**: Safe for use. Users should understand they are routing their traffic through hide.me's infrastructure when the extension is active, which is the explicit purpose of installing a proxy extension.
