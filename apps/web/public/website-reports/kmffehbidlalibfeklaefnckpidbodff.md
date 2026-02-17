# Vulnerability Report: iboss cloud Enterprise

## Metadata
- **Extension ID**: kmffehbidlalibfeklaefnckpidbodff
- **Extension Name**: iboss cloud Enterprise
- **Version**: 5.4.15
- **Users**: ~100,000
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

iboss cloud Enterprise is a legitimate enterprise web filtering and security solution designed for managed Chrome OS and enterprise browser deployments. The extension enforces web security policies through proxy configuration, collects user identification data (email, device UUID, internal IP addresses), and registers devices with cloud-based filtering services. The extension operates transparently within its intended enterprise monitoring context and uses proper enterprise APIs (`chrome.enterprise.deviceAttributes`, `chrome.identity.email`).

While the extension has extensive permissions and data collection capabilities, these are consistent with its stated purpose as an enterprise security solution and would be disclosed to users in managed deployment scenarios. The primary privacy consideration is that this is explicitly an enterprise monitoring tool that tracks user web activity through mandatory proxy enforcement.

## Vulnerability Details

### 1. LOW: WebRTC IP Address Extraction
**Severity**: LOW
**Files**: 78fjh45jhg4g545.min.js (lines 296-316)
**CWE**: CWE-200 (Exposure of Sensitive Information)
**Description**: The extension uses WebRTC's RTCPeerConnection API to extract the device's internal IP address for device registration purposes.

**Evidence**:
```javascript
refreshIpAddress: function() {
  var e = new(window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection)({
      iceServers: []
    }),
    t = ir.currentIpAddress;
  e.createDataChannel("", {
    reliable: !1
  }), e.createOffer(function(t) {
    e.setLocalDescription(t)
  }, function(e) {}), e.onicecandidate = function(r) {
    if (r && r.candidate && r.candidate.candidate) {
      var o = ir.ipExtractExp.exec(r.candidate.candidate);
      // ... extracts IP and sends to cloud registration
    }
  }
}
```

**Verdict**: This is a standard technique for obtaining local IP addresses and is appropriate for enterprise device management. The IP address is used for network location detection and device registration with the iboss cloud filtering service. This is expected behavior for enterprise security software.

### 2. LOW: Unsafe Eval in CSP
**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-1188 (Insecure Default Initialization of Resource)
**Description**: The manifest includes `'unsafe-eval'` in the Content Security Policy, which can enable dynamic code execution risks.

**Evidence**:
```json
"content_security_policy": "script-src 'self' 'unsafe-eval'; object-src 'self'"
```

**Verdict**: While `unsafe-eval` weakens CSP protections, the extension is deployed in managed enterprise environments where the code is controlled and audited. No actual usage of `eval()` or `Function()` constructor was detected in the analyzed code. The CSP directive may be included for compatibility or future functionality but does not present an immediate exploitable vulnerability in the current codebase.

## False Positives Analysis

**Enterprise Device Identification**: The extension collects user email via `chrome.identity.getProfileUserInfo()` and device UUID via `chrome.enterprise.deviceAttributes.getDirectoryDeviceId()`. These are legitimate enterprise APIs designed specifically for managed device deployment and are not privacy violations in this context.

**Proxy Configuration**: The extension uses `chrome.proxy.settings` APIs to enforce web filtering. This is the core functionality of the product and is expected in enterprise security software.

**WebRequest Blocking**: The extension intercepts web requests via `chrome.webRequest.onBeforeRequest` to enforce filtering policies. This is standard for content filtering solutions and not malicious.

**Cloud Registration**: The extension registers devices with the iboss cloud service (lines 1053-1073), sending username, device UUID, and IP address. This is necessary for cloud-based filtering and would be documented in enterprise deployment guides.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| `${Gen4ProxyHost}:${Gen4AutoRegisterSecurePort}/autoLogin?ibssoidreg=` | Device registration with iboss cloud | Username (email), device UUID, IP address, security group names, Chrome OS build info, extension version, MITM cert checksum | LOW - Expected enterprise monitoring |
| `www.msftncsi.com/ncsi.txt` | Captive portal detection | None (GET request to check for portal interception) | CLEAN - Standard network connectivity check |
| `clients3.google.com/generate_204` | Network connectivity check | None (GET request for 204 response) | CLEAN - Google's standard connectivity check |
| `127.0.0.1:${PACServerPort}` | Local proxy configuration | None (local proxy traffic) | CLEAN - Local service |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

This is a legitimate enterprise security product that operates within the bounds of its documented functionality. The MEDIUM risk rating reflects the extensive data collection and monitoring capabilities rather than malicious behavior:

**Why MEDIUM (not HIGH or CRITICAL)**:
- This is a legitimate enterprise product from iboss (established cybersecurity vendor)
- All sensitive APIs used (`chrome.enterprise.deviceAttributes`, `chrome.identity.email`) require enterprise enrollment and cannot be exploited on personal devices
- Data collection is transparent and expected for enterprise web filtering solutions
- No hidden exfiltration, no undisclosed tracking, no credential theft

**Why MEDIUM (not LOW or CLEAN)**:
- The extension collects user email addresses, device UUIDs, and internal IP addresses
- Enforces mandatory web proxy that routes all HTTP/HTTPS traffic through filtering servers
- Blocks or redirects web requests based on enterprise policies
- Maintains persistent connection to cloud services with device identification
- Has extensive permissions including `webRequestBlocking`, `proxy`, and `<all_urls>`

**Context-Dependent Risk**: For end users installing this on personal devices, this would be HIGH risk due to comprehensive monitoring. However, this extension is designed exclusively for managed enterprise deployments where:
1. Users are informed of monitoring policies
2. The extension is force-installed via enterprise policy
3. IT administrators control configuration via managed storage
4. The purpose is legitimate network security and compliance

The risk is appropriately categorized as MEDIUM because while the monitoring capabilities are extensive, they are disclosed, expected, and appropriate for the enterprise security context in which this extension operates.
