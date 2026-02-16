# Vulnerability Report: Youtube Unblocked

## Metadata
- **Extension ID**: apmbfchnaiociljffgngpjkhplkengck
- **Extension Name**: Youtube Unblocked
- **Version**: 5.1
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Youtube Unblocked presents itself as a YouTube proxy/VPN extension to help users bypass regional restrictions. However, the extension operates a residential proxy network that routes YouTube traffic through proxy servers while collecting and exfiltrating device identifiers and user IP addresses to remote servers. The extension fetches proxy configuration from a remote GitHub repository (`raw.githubusercontent.com/vpn-naruzhu/public/main/uboost-extension`) and sends device fingerprinting data to dynamically configured API endpoints. While the extension's stated purpose is legitimate proxy functionality, the lack of transparency around data collection, device tracking, and the potential for turning user browsers into proxy nodes without explicit consent raises significant privacy concerns.

The extension contains hardcoded proxy configurations for multiple server options and dynamically fetches additional proxy settings from remote sources, which could be modified at any time without user notification. The data exfiltration patterns include sending unique device IDs (generated and stored locally) and public IP addresses to third-party servers.

## Vulnerability Details

### 1. HIGH: Undisclosed Device Fingerprinting and Data Exfiltration

**Severity**: HIGH
**Files**: background.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**: The extension generates a persistent unique device identifier (UUID) and collects the user's public IP address, then exfiltrates both to remote servers without clear disclosure in the extension's privacy policy or user consent flow. This occurs during proxy setup operations.

**Evidence**:
```javascript
function r() {
  const r = "xxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (function(r) {
    const o = 16 * Math.random() | 0;
    return ("x" === r ? o : 3 & o | 8).toString(16)
  }));
  return chrome.storage.local.set({
    deviceId: r
  }, (function() {})), r
}

// Fetches public IP
fetch("https://api.ipify.org?format=json").then((r => r.json())).then((r => {
  o(r.ip)
}))

// Exfiltrates device ID and IP to remote API
fetch(`https://${a}/api/v1/get-proxy`, {
  method: "POST",
  headers: {
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    device_id: r || "unknown",
    device_ip: o || "unknown"
  })
})
```

**Verdict**: The extension tracks users via persistent device IDs and collects public IP addresses, sending them to remote servers. This constitutes privacy-invasive behavior that is not clearly disclosed to users in the extension's description.

### 2. HIGH: Remote Configuration via Untrusted Source

**Severity**: HIGH
**Files**: background.js
**CWE**: CWE-494 (Download of Code Without Integrity Check)

**Description**: The extension fetches proxy configuration from a remote GitHub repository without integrity verification. The remote configuration determines which API endpoint receives user data and controls proxy behavior. This creates a risk of configuration hijacking or malicious updates.

**Evidence**:
```javascript
fetch("https://raw.githubusercontent.com/vpn-naruzhu/public/main/uboost-extension")
  .then((r => r.json()))
  .then((o => {
    const a = o.apiBaseUrl;
    console.log(a, "apiBaseUrl result")
    // Uses dynamically fetched API base URL for subsequent requests
    fetch(`https://${a}/api/v1/get-proxy`, {
      // ... sends device data to this endpoint
    })
  }))
```

**Verdict**: The extension's behavior can be modified remotely by updating a JSON file on GitHub. There is no cryptographic signature verification, allowing potential man-in-the-middle attacks or unauthorized configuration changes by anyone with access to the GitHub repository.

### 3. MEDIUM: Residential Proxy Operation Without Clear Consent

**Severity**: MEDIUM
**Files**: background.js
**CWE**: CWE-506 (Embedded Malicious Code)

**Description**: While the extension markets itself as a VPN/proxy for accessing YouTube, the architecture suggests it may be part of a residential proxy network. The extension fetches dynamic proxy endpoints from remote servers after sending device identification data, which is a common pattern for residential proxy services that route traffic through user devices.

**Evidence**:
```javascript
// Multiple hardcoded proxy servers embedded in PAC scripts
const serverConfigs = {
  server1: 'function FindProxyForURL(url, host) { ... return "PROXY 92.255.105.70:52158"; }',
  server2: '... return "PROXY 193.233.100.40:61931"; ...',
  server3: '... dynamically configured from API response ...',
  // etc.
}

// Connection tracking
function incrementProxyConnectionCount() {
  chrome.storage.local.get("connectionCount", (r => {
    let o = r.connectionCount || 0;
    chrome.storage.local.set({
      connectionCount: o + 1
    })
  }))
}
```

**Verdict**: The extension appears to connect users to a residential proxy network. While presented as a VPN service to unblock YouTube, the tracking of connection counts, device IDs, and dynamic proxy configuration suggests commercial proxy infrastructure. Users may unknowingly be providing bandwidth to a proxy service.

## False Positives Analysis

**Legitimate Proxy Functionality**: The extension's core purpose is to act as a proxy for YouTube traffic, so the use of `chrome.proxy` API and PAC (Proxy Auto-Configuration) scripts is expected and necessary for this functionality.

**IP Address Collection for Proxy Setup**: Collecting the user's public IP address via `api.ipify.org` could be legitimate for proxy server selection (choosing geographically closer servers), though this is not clearly disclosed.

**Server Selection Options**: The multiple server configurations (server1-server5) in the popup UI are legitimate features for a VPN/proxy extension, allowing users to switch servers if one is slow or blocked.

**Content Script Advertising**: The content script on YouTube pages injects promotional content for "GEMERA VPN" service, which appears to be a related commercial VPN offering. While potentially annoying, this is standard affiliate/upsell behavior for free proxy extensions.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| raw.githubusercontent.com/vpn-naruzhu/public/main/uboost-extension | Fetch remote proxy configuration | None (GET request) | High - No integrity check, can be modified |
| api.ipify.org | Fetch user's public IP address | None (IP revealed via connection) | Medium - Third-party IP disclosure |
| `${apiBaseUrl}/api/v1/get-proxy` | Request proxy server assignment | device_id (UUID), device_ip (public IP) | High - Device fingerprinting and tracking |
| t.me/gemera_vpn_bot | Telegram bot for upsell | None (user navigation) | Low - Marketing link |
| gemera-vpn.com | Uninstall redirect | None | Low - Analytics/exit survey |
| swaponline.notion.site | Onboarding pages | None | Low - Documentation |
| chromewebstore.google.com | Review requests | None | Low - Standard practice |

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**:

This extension presents significant privacy risks through undisclosed data collection and device fingerprinting. While the proxy functionality itself is legitimate, the following factors elevate the risk to HIGH:

1. **Undisclosed Data Exfiltration**: The extension generates unique device IDs and collects public IP addresses, sending them to remote servers without clear disclosure in the extension description or obtaining explicit user consent.

2. **Remote Configuration Vulnerability**: Critical configuration is fetched from an external GitHub repository without integrity verification, allowing the extension's behavior to be modified at any time.

3. **Residential Proxy Indicators**: The architecture (device tracking, connection counting, dynamic proxy assignment based on device ID) suggests this may be part of a residential proxy network, potentially using users' bandwidth without full transparency.

4. **Lack of Transparency**: The extension description focuses on "unblocking YouTube" and "maintaining privacy" but does not disclose the device tracking, data collection, or the potential for residential proxy operations.

While the extension does not engage in outright malicious behavior like credential theft or hidden malware installation, the combination of undisclosed data collection, device fingerprinting, and potential residential proxy operation without clear user consent justifies a HIGH risk rating. Users install this extension believing it's a simple YouTube unblocker but unknowingly become part of a tracked proxy network with persistent device identification.

**Recommendation**: Users should be clearly informed about device ID generation, IP address collection, remote configuration sources, and whether their connection is being used as part of a proxy network. Without such disclosures, this extension violates user privacy expectations.
