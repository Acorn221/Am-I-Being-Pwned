# Vulnerability Report: Hide My IP

## Metadata
- **Extension ID**: pekcnopmdcbjdgmpnpkndppflpldnkkp
- **Extension Name**: Hide My IP
- **Version**: 2.0.9
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Hide My IP is a VPN/proxy extension that provides IP address masking through configurable proxy servers. The extension communicates with the vendor's API to retrieve proxy server lists and validate user license keys. Static analysis identified one medium-severity privacy concern regarding license key transmission, and one low-severity issue with credential handling. The extension's behavior is consistent with its stated purpose as a commercial VPN/proxy service, though it does transmit user subscription information to remote servers.

## Vulnerability Details

### 1. MEDIUM: License Key Transmission to Remote API

**Severity**: MEDIUM
**Files**: background.js (lines 30-34, 124-128), popup.js (lines 286-306, 371-396)
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension sends the user's license key to api.hide-my-ip.com for validation and authentication. This allows the vendor to track which users are accessing which proxy servers and when.

**Evidence**:
```javascript
// background.js lines 30-34
chrome.storage.local.get('key', (result) => {
  const key = result.key;
  let url = `https://api.hide-my-ip.com/chrome.cgi`;
  if (key) {
    url += `?key=${key}`;
  }
```

```javascript
// background.js lines 124-128
chrome.storage.local.get('key', (result) => {
  const key = result.key;
  let url = `https://api.hide-my-ip.com/chrome.cgi?ip=${ip}`;
  if (key) {
    url += `&key=${key}`;
  }
```

```javascript
// popup.js lines 286-306
function checkKey(key, callback) {
  const url = `https://api.hide-my-ip.com/chrome.cgi?action=keycheck&key=${key}`;
  fetch(url)
    .then(response => {
      if (!response.ok) throw new Error('Primary API request failed');
      return response.text();
    })
    .then(result => {
      callback(result.trim().endsWith(': 1'));
    })
```

**Verdict**: This is a disclosed privacy concern consistent with commercial VPN services. The license key transmission enables server-side authentication and subscription validation, which is expected behavior for a paid proxy service. However, it does allow the vendor to correlate user activity with subscription accounts.

### 2. LOW: Proxy Credentials Reused as Username and Password

**Severity**: LOW
**Files**: background.js (lines 138-142, 192-197)
**CWE**: CWE-798 (Use of Hard-coded Credentials)
**Description**: The extension uses the same value for both username and password when authenticating to proxy servers.

**Evidence**:
```javascript
// background.js lines 138-142
.then(credentials => {
  const username = credentials.trim();
  const password = credentials.trim();
  chrome.storage.local.set({ lastauth: username });
```

```javascript
// background.js lines 192-197
callback({
  authCredentials: {
    username: creds,
    password: creds,
  },
});
```

**Verdict**: While this appears unusual from a security perspective, it may be an intentional design choice by the proxy service provider where the credential token serves as both username and password. This is low severity as it's a vendor-controlled authentication mechanism and doesn't introduce additional risk beyond the proxy service's design.

## False Positives Analysis

1. **WebRTC IP Leak Prevention (lines 1-19 in background.js)**: This is a legitimate privacy feature that prevents IP address leaks through WebRTC when using the proxy. It sets `chrome.privacy.network.webRTCIPHandlingPolicy` to disable non-proxied UDP, which is expected behavior for a VPN/proxy extension.

2. **Proxy Configuration (lines 113-123 in popup.js)**: The extension configures browser proxy settings using `chrome.proxy.settings.set()`, which is the standard and expected behavior for a VPN/proxy extension. The bypass list includes the extension's own API endpoints to prevent circular dependencies.

3. **Backup API Domain (location-list.wendysgolang.workers.dev)**: This Cloudflare Workers domain serves as a fallback endpoint when the primary API is unavailable. The backup URL includes a base64-encoded version of the primary URL, which is a reasonable failover strategy.

4. **Test Request to ipchicken.com (line 144)**: The extension makes a test request to ipchicken.com after configuring proxy credentials, likely to validate that the proxy connection is working correctly. This is common practice for VPN/proxy extensions.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.hide-my-ip.com | Primary API for proxy server lists and key validation | User license key (if present), IP addresses for authentication | MEDIUM - Transmits subscription identifier |
| location-list.wendysgolang.workers.dev | Backup API endpoint (Cloudflare Workers) | Base64-encoded primary API URL | LOW - Failover mechanism only |
| ipchicken.com | IP address verification service | None (GET request only) | MINIMAL - Public IP checking service |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

This extension functions as advertised - a commercial VPN/proxy service that requires authentication with the vendor's servers. The primary privacy concern is the transmission of user license keys to remote APIs, which allows the vendor to track subscription usage patterns. However, this behavior is disclosed and expected for a commercial proxy service.

The extension does not engage in hidden data collection, malicious activity, or credential theft. It uses appropriate Chrome APIs for proxy configuration and WebRTC leak prevention. The code is well-structured and does not contain obfuscation beyond standard webpack bundling.

The MEDIUM risk rating reflects the data exfiltration of user subscription information (license key) to the vendor, which is inherent to the commercial nature of the service. Users should be aware that their proxy usage is trackable by the service provider through their license key.

For a free VPN/proxy extension making similar API calls without user disclosure, this would rate HIGH. However, given this is a commercial service where users pay for access and authentication is necessary, MEDIUM is appropriate.
