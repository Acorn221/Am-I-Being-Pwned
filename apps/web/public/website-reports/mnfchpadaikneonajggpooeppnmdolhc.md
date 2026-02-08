# TorGuard VPN Extension - Security Analysis Report

## Extension Metadata

- **Extension ID**: mnfchpadaikneonajggpooeppnmdolhc
- **Name**: TorGuard VPN Extension
- **Version**: 3.0
- **Users**: ~20,000
- **Publisher**: TorGuard LLC
- **Homepage**: https://torguard.net

## Executive Summary

TorGuard VPN Extension is a legitimate commercial VPN browser extension from TorGuard LLC, a well-known VPN service provider. The extension provides proxy/VPN functionality, ad blocking, and HTML5 geolocation spoofing. While the extension performs its advertised functionality, there are **MEDIUM severity security concerns** related to:

1. **Weak CSP with HTTP endpoint whitelisting** - The manifest CSP allows HTTP endpoints which could be exploited
2. **HTTP remote configuration endpoints** - Critical configuration data fetched over unencrypted HTTP
3. **Local password encryption using weak XOR cipher** - User credentials stored with reversible XOR encryption
4. **Hardcoded external IP in CSP** - Non-TorGuard infrastructure referenced in security policy

The extension's core VPN functionality is legitimate and it does not contain malware, keyloggers, residential proxy infrastructure, or data exfiltration mechanisms beyond what's expected for a VPN service. However, the security implementation issues create attack surface that could be exploited by network-level adversaries.

**Overall Risk Assessment: MEDIUM**

## Vulnerability Details

### 1. Weak Content Security Policy with HTTP Endpoint

**Severity**: MEDIUM
**Category**: Security Misconfiguration
**CVSS**: 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N)

**Location**: `manifest.json` lines 40-43

```json
"content_security_policy": {
    "extension_pages": "script-src 'self'; object-src 'self'",
    "sandbox": "sandbox allow-scripts; script-src 'self' 'http://143.110.208.40' 'https://updates.torguard.biz'; object-src 'self'"
}
```

**Description**: The manifest CSP includes an HTTP endpoint (143.110.208.40) in the sandbox policy. This creates a security risk as:
- HTTP traffic is unencrypted and vulnerable to MITM attacks
- The IP address 143.110.208.40 is a DigitalOcean VPS, not confirmed to be official TorGuard infrastructure
- An attacker performing MITM could potentially serve malicious scripts that would be allowed by the CSP

**Verdict**: VULNERABLE - CSP should only include HTTPS endpoints from verified TorGuard domains.

---

### 2. Unencrypted Remote Configuration Endpoints

**Severity**: MEDIUM
**Category**: Insecure Data Transmission
**CVSS**: 5.9 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N)

**Location**: `background.js` lines 9-10, 12-52

```javascript
var iplistServer = "http://143.110.208.40/proxy/update/newiplist4.json";
var blackurllist = "http://143.110.208.40/proxy/update/blackurls.list";

fetch(iplistServer)
  .then((response) => response.json())
  .then((data) => {
        if (data && data.iplist) {
            chrome.storage.local.set({iplist: data.iplist});
            ipList = data.iplist;
        }
  });

fetch(blackurllist)
  .then((response) => response.json())
  .then((data) => {
        if (data) {
            chrome.storage.local.set({"blacklist": data.blk.split(/,/)});
        }
  });
```

**Description**: The extension fetches two critical configuration files over unencrypted HTTP:
1. **VPN Server List** (`newiplist4.json`) - Contains list of proxy servers, ports, and geolocation data
2. **Blocklist** (`blackurls.list`) - Contains list of domains to block when ad-blocking is enabled

A network-level attacker could:
- Inject malicious proxy servers into the server list, routing user traffic through attacker-controlled infrastructure
- Modify the blocklist to allow ads/trackers or block legitimate sites
- Remove legitimate servers from the list

Fallback to local files (`/res/newiplist3.json`, `/res/blacklist.json`) is present but only activates if the remote fetch fails.

**Verdict**: VULNERABLE - Critical configuration should use HTTPS with certificate validation.

---

### 3. Weak Password Storage (XOR Encryption)

**Severity**: LOW
**Category**: Weak Cryptography
**CVSS**: 3.3 (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Location**: `popup/popup.js` lines 1054-1071, `background.js` lines 190-211

```javascript
function encrypt(s) {
    var a = 0;
    var myString = '';
    var textLen = s.length;
    var pwLen = pw.length;

    for (var i = 0; i < textLen; i++) {
        a = parseInt(s.charCodeAt(i));
        a = a ^ (pw.charCodeAt(i % pwLen));  // XOR with runtime ID
        a = a + "";
        while (a.length < 3)
            a = '0' + a;
        myString += a;
    }
    return myString;
}

function decrypt(s) {
    // ... XOR reversal using chrome.runtime.id
}
```

**Description**: User VPN credentials (username and password) are "encrypted" using a simple XOR cipher with the Chrome extension ID (`chrome.runtime.id`) as the key. This is a weak encryption scheme because:
- The extension ID is public and static for all installations
- XOR encryption is easily reversible with a known key
- No salt, no proper key derivation function
- Stored in `chrome.storage.local` which is accessible to other extensions with storage permission

An attacker with local access (malware, other malicious extensions, or forensics) could easily decrypt stored credentials.

**Verdict**: VULNERABLE - Should use proper encryption (AES with WebCrypto API) or rely on browser's credential manager.

---

### 4. Hardcoded External IP Address in CSP

**Severity**: LOW
**Category**: Security Misconfiguration
**CVSS**: 3.1 (CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N)

**Location**: `manifest.json` line 42

```json
"sandbox": "sandbox allow-scripts; script-src 'self' 'http://143.110.208.40' 'https://updates.torguard.biz'; object-src 'self'"
```

**Description**: The CSP includes a hardcoded IP address (143.110.208.40) which:
- Resolves to a DigitalOcean VPS
- Is not directly associated with TorGuard's official domain
- Uses HTTP instead of HTTPS
- Creates trust issues - users cannot verify this is official TorGuard infrastructure

This could be:
- An internal development/staging server that was accidentally left in production
- A CDN endpoint
- Legitimate infrastructure but poorly documented

**Verdict**: QUESTIONABLE - Should use official TorGuard domains with HTTPS. Needs verification from publisher.

---

## False Positives

| Pattern Detected | File | Reason for False Positive |
|-----------------|------|---------------------------|
| XMLHttpRequest hooking | `lib/ajaxproxy.js` | Unused library file for AWS Lambda proxy functionality, not injected or executed |
| eval/Function in jQuery | `lib/jquery-3.2.1.min.js` | Standard jQuery 3.2.1 library, not malicious |
| setTimeout in sweetAlert | `lib/sweetAlert/sweetalert2.js` | Standard UI library for alerts, legitimate use |
| Geolocation override | `geo_override.js` | Advertised feature - spoofs HTML5 geolocation to match VPN location |
| Proxy settings manipulation | `background.js`, `popup/popup.js` | Core VPN functionality - expected behavior |

## API Endpoints Analysis

| Endpoint | Protocol | Purpose | Risk Level |
|----------|----------|---------|------------|
| `http://143.110.208.40/proxy/update/newiplist4.json` | HTTP | Fetch VPN server list | HIGH - Unencrypted, unknown IP |
| `http://143.110.208.40/proxy/update/blackurls.list` | HTTP | Fetch ad-blocking blocklist | MEDIUM - Unencrypted |
| `http://143.110.208.40/cgi-bin/whatismyip.pl` | HTTP | Check current IP address | LOW - Read-only operation |
| `https://updates.torguard.biz/cgi-bin/whatismyip.pl` | HTTPS | Fallback IP check | LOW - Encrypted, verified domain |
| `https://o6xa1qdc4k.execute-api.eu-west-1.amazonaws.com/default/ProxyLambda` | HTTPS | Unused AWS Lambda proxy | N/A - Code present but not executed |
| `*.secureconnect.me` (various subdomains) | HTTPS | VPN proxy servers | LOW - Encrypted connections |

## Permissions Analysis

### High-Risk Permissions

1. **`<all_urls>` host permission** - Required for VPN proxy to intercept all traffic (legitimate for VPN)
2. **`proxy` permission** - Required to configure browser proxy settings (core VPN functionality)
3. **`privacy` permission** - Used to configure WebRTC IP leak prevention (legitimate VPN security feature)
4. **`webRequest` permission** - Used for authentication and potential ad-blocking (legitimate)
5. **`declarativeNetRequestWithHostAccess`** - Used to block ad domains dynamically

### Permission Usage Verdict

All permissions are used for their stated purposes and are appropriate for a VPN extension. No evidence of abuse.

## Data Flow Summary

### Inbound Data
1. **User Credentials**: Username/password entered in popup, XOR-encrypted with extension ID, stored in `chrome.storage.local`
2. **VPN Server List**: Fetched from `http://143.110.208.40/proxy/update/newiplist4.json` over HTTP
3. **Ad Blocklist**: Fetched from `http://143.110.208.40/proxy/update/blackurls.list` over HTTP
4. **User Settings**: Exclude list, proxy preferences, ad-block toggle stored locally

### Outbound Data
1. **Authentication to VPN Servers**: Username/password sent to selected proxy server (*.secureconnect.me) over HTTPS
2. **IP Check Requests**: HTTP/HTTPS requests to check user's current IP address
3. **Proxy Traffic**: All user browsing traffic routed through selected TorGuard proxy server (expected VPN behavior)

### Data Storage
- User credentials: `chrome.storage.local.user` (XOR encrypted)
- Current proxy configuration: `chrome.storage.local.curProxy`
- Server list: `chrome.storage.local.iplist`
- Blocklist: `chrome.storage.local.blacklist`
- User preferences: `chrome.storage.local` (exclude list, toggle states)

**Verdict**: No unexpected data exfiltration. All data transmission is consistent with VPN functionality.

## Features Analysis

### Legitimate Features
1. **VPN/Proxy Functionality**: Routes browser traffic through TorGuard proxy servers using Chrome proxy API
2. **Ad Blocking**: Blocks domains from a remotely-updated blocklist using declarativeNetRequest API
3. **HTML5 Geolocation Spoofing**: Overrides `navigator.geolocation` API to match VPN server location
4. **WebRTC Leak Prevention**: Configures `webRTCIPHandlingPolicy` to prevent IP leaks
5. **Always-On Mode**: Maintains proxy connection across browser restarts
6. **Custom Proxy Support**: Allows users to add custom proxy servers

### No Evidence of Malicious Features
- ✅ No keylogging or form interception
- ✅ No cookie harvesting beyond normal VPN operation
- ✅ No residential proxy infrastructure indicators
- ✅ No extension enumeration/killing (VPN mode doesn't conflict)
- ✅ No market intelligence SDKs (Sensor Tower, Pathmatics, etc.)
- ✅ No ad/coupon injection
- ✅ No AI conversation scraping
- ✅ No cryptocurrency mining

## Code Quality Observations

1. **Commented-out code**: Several unused code blocks remain (lines 292-293 in background.js)
2. **Mixed infrastructure**: Uses both torguard.biz and unknown IP addresses
3. **No HTTPS enforcement**: Critical endpoints use HTTP instead of HTTPS
4. **Basic encryption**: XOR cipher instead of industry-standard encryption
5. **No input validation**: User-provided proxy IPs/hostnames not strictly validated

## Recommendations for Publisher

### Critical Priority
1. **Switch to HTTPS**: Change all remote configuration endpoints to HTTPS
2. **Use official domains**: Replace IP address 143.110.208.40 with official TorGuard domains
3. **Remove HTTP from CSP**: Update CSP to only allow HTTPS endpoints

### High Priority
4. **Implement proper encryption**: Replace XOR cipher with WebCrypto API (AES-GCM)
5. **Add certificate pinning**: Pin TorGuard server certificates to prevent MITM
6. **Implement subresource integrity**: Add SRI hashes for remote configuration files

### Medium Priority
7. **Add input validation**: Validate proxy server entries to prevent injection
8. **Remove dead code**: Clean up commented-out and unused code blocks
9. **Add error handling**: Improve error handling for network failures

## Overall Risk Assessment

**Risk Level: MEDIUM**

### Justification
TorGuard VPN Extension is a **legitimate commercial VPN service** that performs its advertised functionality without malicious intent. However, the security implementation has notable weaknesses:

**Positive Factors:**
- No malware, spyware, or data theft mechanisms
- Legitimate business with established reputation
- All permissions used appropriately for VPN functionality
- No residential proxy or market intelligence infrastructure
- No injection of ads, trackers, or malicious scripts

**Negative Factors:**
- HTTP endpoints for critical configuration (MEDIUM severity)
- Weak XOR encryption for stored credentials (LOW severity)
- Hardcoded external IP in CSP (LOW severity)
- Potential for MITM attacks on configuration updates

### Verdict

**MEDIUM** - The extension is NOT malicious but has security vulnerabilities that create exploitable attack surface. These issues should be addressed but do not constitute immediate threat under normal usage. Users on trusted networks are at low risk, but users on hostile networks (public WiFi, adversarial states) face increased risk of MITM attacks on configuration updates.

The extension can be used safely with awareness of these limitations, but publisher should address the HTTP configuration endpoints and weak credential storage as priority fixes.

## Summary

TorGuard VPN Extension provides legitimate VPN/proxy functionality with HTML5 geolocation spoofing and ad-blocking features. While it performs its advertised purpose without malicious behavior, security implementation weaknesses (HTTP configuration endpoints, weak credential encryption) create medium-level risk primarily for users on untrusted networks. No evidence of malware, data theft, or deceptive practices.
