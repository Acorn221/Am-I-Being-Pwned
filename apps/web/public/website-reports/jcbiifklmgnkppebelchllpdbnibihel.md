# Vulnerability Analysis Report: Free VPN

## Extension Metadata

- **Extension ID**: jcbiifklmgnkppebelchllpdbnibihel
- **Name**: Free VPN
- **Version**: 3.2.2
- **User Count**: ~100,000
- **Publisher**: Unknown
- **Rating**: 3.7/5
- **Homepage**: https://www.freevpn.one

## Executive Summary

Free VPN is a functional VPN proxy service that routes user traffic through third-party proxy servers. The extension demonstrates several privacy and security concerns including third-party tracking pixels, dynamic remote configuration, and the ability to disable competing VPN extensions. While the core VPN functionality appears legitimate, the extension exhibits behaviors that raise moderate security concerns around data privacy and remote control capabilities.

**Overall Risk Level**: **MEDIUM**

The extension functions as advertised but implements concerning practices including third-party tracking, remote configuration updates, and extension interference capabilities that could be misused.

## Detailed Analysis

### 1. Manifest Analysis

**Permissions Requested**:
- `tabs` - Access to tab information
- `proxy` - Control proxy settings (core VPN functionality)
- `storage` - Local data storage
- `notifications` - User notifications
- `management` - **HIGH RISK** - Can enumerate and disable other extensions
- `privacy` - Control privacy settings (WebRTC leak protection)
- `<all_urls>` - **HIGH RISK** - Access to all websites

**Content Security Policy**: Not explicitly defined (defaults to MV3 standards)

**Content Scripts**: Only injected into `https://www.freevpn.one/*` (legitimate, scoped appropriately)

**Verdict**: The permissions are largely appropriate for a VPN extension, but the combination of `management` and `<all_urls>` creates significant power that could be abused if the extension were compromised or malicious.

---

### 2. Background Service Worker Analysis (`scripts/service.js`)

#### 2.1 Remote Configuration & Dynamic Proxy Servers

**Severity**: MEDIUM
**Location**: `service.js:124-142`

```javascript
async loadServerMap() {
    const response = await fetch('https://drive.google.com/uc?export=view&id=10RKfD2ZTlajZ5VnULVzk1sxUl-Zn7i8N', {
        method: "GET",
        redirect: 'follow'
    });
    const data = await response.json();
    for (const [name, details] of Object.entries(data)) {
        this.serverMap[name] = {
            host: details.IP,
            type: details.Type || "https",
            port: details.Port ? parseInt(details.Port) : 443
        };
    }
}
```

**Analysis**: The extension fetches proxy server configurations from a Google Drive file. While Google Drive provides some level of legitimacy, this is effectively a remote configuration/kill switch mechanism. The server list can be updated at any time without extension updates, potentially redirecting all user traffic through malicious proxies.

**Risk**: An attacker who gains control of the Google Drive file could redirect all 100,000 users' traffic through malicious servers for traffic interception, credential harvesting, or man-in-the-middle attacks.

---

#### 2.2 Time Limit Endpoint

**Severity**: LOW
**Location**: `service.js:144-154`

```javascript
async fetchTimeLimit() {
    const response = await fetch('https://www.freevpn.one/tl.php');
    if (!response.ok) throw new Error('Failed to fetch time limit');
    const data = await response.json();
    if (data.status === "pro") return { duration: null };
    return data;
}
```

**Analysis**: The extension phones home to check connection time limits. This likely distinguishes between free and pro users. The endpoint receives information about when connections are established.

**Data Sent**: Implicitly, the request reveals user activity (when they connect to VPN).

---

#### 2.3 Extension Enumeration and Disabling

**Severity**: MEDIUM
**Location**: `service.js:287-299`, `service.js:442-450`

```javascript
async checkProxyExtensions() {
    const extensions = await chrome.management.getAll();
    const proxyExtensions = extensions.filter(ext =>
        ext.id !== chrome.runtime.id &&
        ext.enabled &&
        ext.permissions?.includes('proxy')
    );
    return proxyExtensions;
}

// Later in message handler:
case "disableExtension":
    chrome.management.setEnabled(request.extensionId, false, () => {
        if (chrome.runtime.lastError) {
            sendResponse({ success: false, error: chrome.runtime.lastError.message });
        } else {
            sendResponse({ success: true });
        }
    });
```

**Analysis**: The extension can enumerate all installed extensions and specifically identify competing VPN/proxy extensions. It can then disable them remotely via messages from the freevpn.one website.

**Verdict**: This is standard behavior for VPN extensions to prevent conflicts, but it could be misused to disable security extensions. The disabling action requires user interaction through the website, which provides some protection. **This is NOT flagged as malicious per instructions** as VPN/proxy extensions disabling competitors is standard behavior.

---

#### 2.4 WebRTC Leak Protection

**Severity**: INFO
**Location**: `service.js:87-89`, `service.js:408-434`

```javascript
if (this.webRTCStatus) {
    await chrome.privacy.network.webRTCIPHandlingPolicy.set({
        value: 'disable_non_proxied_udp'
    });
}
```

**Analysis**: The extension offers WebRTC leak protection by preventing WebRTC from bypassing the proxy. This is a legitimate privacy feature.

---

#### 2.5 Ad/Tracking Bypass

**Severity**: INFO
**Location**: `service.js:165-179`

```javascript
bypassList: [
    "fundingchoicesmessages.google.com",
    "*doubleclick.net",
    "*googlesyndication.com",
    "adservice.google.com",
    "*googleadservices.com",
    // ... many more ad domains
]
```

**Analysis**: The proxy explicitly bypasses ad tracking and syndication domains. This means ads and trackers can see the user's real IP address even when connected to the VPN. This is likely to improve performance and avoid ad fraud detection, but it undermines the privacy promise of a VPN.

**Verdict**: This is a significant privacy concern as users expect VPNs to hide their IP from all third parties, including advertisers.

---

#### 2.6 Machine ID Generation

**Severity**: LOW
**Location**: `service.js:15-24`

```javascript
chrome.storage.local.get('machine-id', function(item){
  var storedextenId = item['machine-id'];
  if(!storedextenId) {
    var ts = Math.round((new Date()).getTime() / 1000);
    storedextenId = ts+"-"+Math.random().toString(12).slice(2);
    chrome.storage.local.set({'machine-id':storedextenId});
  }
  extenId = storedextenId;
});
```

**Analysis**: The extension generates a unique machine ID for tracking purposes. This ID persists across sessions and could be used to track users across connections.

**Verdict**: Standard analytics/telemetry practice, but combined with other telemetry, this enables user tracking.

---

#### 2.7 Unused RSA Public Key

**Severity**: INFO
**Location**: `service.js:27-55`

```javascript
const RSA_PUB_PEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5StRyo7gXT/SQOQYRmG/
...
-----END PUBLIC KEY-----`;

async function importRsaPublicKey(pem) {
    // ... imports key for RSA-OAEP encryption
}
const rsaPublicKeyPromise = importRsaPublicKey(RSA_PUB_PEM);
```

**Analysis**: An RSA public key is imported but never used in the codebase. This could be dead code from a previous version or preparation for future encrypted communications.

**Verdict**: Not currently a vulnerability but suggests the extension may have been designed to encrypt and transmit data, which it doesn't currently do.

---

### 3. Content Script Analysis (`scripts/content.js`)

**Severity**: LOW
**Location**: Entire file

The content script only runs on `https://www.freevpn.one/*` and acts as a bridge between the webpage and the extension. It:
- Relays connection/disconnection requests from the webpage to the background service
- Updates UI on the webpage based on VPN status
- Does NOT access sensitive page data
- Properly validates origin (`event.origin === "https://www.freevpn.one"`)

**Verdict**: Content script is appropriately scoped and secure. No DOM manipulation of third-party sites.

---

### 4. Third-Party Tracking

**Severity**: MEDIUM
**Location**: `page/main.html:43`

```html
<img src="https://www.logonless.com/img.php" style="width:1px; height: 1px; clear:none; float:left;">
```

**Analysis**: A 1x1 tracking pixel from `www.logonless.com` is loaded in the backup connection manager page. This third-party tracker can:
- Log when users access the backup connection interface
- Collect IP addresses, user agents, and other fingerprinting data
- Track users across sites if logonless.com is used elsewhere

**Verdict**: Undisclosed third-party tracking that contradicts the privacy expectations of VPN users. This is inappropriate for a privacy-focused product.

---

### 5. Popup Analysis (`popup/popup.js`)

**Severity**: INFO

The popup displays connection status and provides buttons to open the connection manager. It queries proxy settings and checks for competing VPN extensions to warn users about potential conflicts. No security issues identified.

---

### 6. Data Flow Summary

**Data Collected**:
1. Machine ID (persistent unique identifier)
2. Connection timestamps (`connTime`, `connExpire`)
3. Selected VPN server
4. Installed extensions list (specifically proxy extensions)
5. Implicit: Connection patterns via tl.php requests

**Data Transmitted**:
- **To www.freevpn.one**: Connection time limit checks (tl.php), reveals when users connect
- **To www.logonless.com**: Tracking pixel fires when backup manager is accessed
- **To drive.google.com**: Server configuration requests

**User Traffic Routing**:
- All traffic (except ad domains) routed through third-party proxy servers
- Proxy servers are dynamically configured and could change at any time
- No evidence of traffic inspection by the extension itself, but proxy servers have full access

---

## Vulnerabilities

### V1: Remote Configuration Kill Switch
- **Severity**: MEDIUM
- **CWE**: CWE-494 (Download of Code Without Integrity Check)
- **Description**: Server list fetched from Google Drive without integrity verification
- **Impact**: Attacker controlling the Drive file could redirect 100,000 users through malicious proxies
- **Affected File**: `scripts/service.js:126`
- **Recommendation**: Use pinned server configuration or implement signature verification

### V2: Third-Party Tracking in Privacy Product
- **Severity**: MEDIUM
- **CWE**: CWE-359 (Exposure of Private Information)
- **Description**: Tracking pixel from logonless.com embedded in extension
- **Impact**: User activity and IP addresses leaked to third-party tracker
- **Affected File**: `page/main.html:43`
- **Recommendation**: Remove third-party trackers or disclose in privacy policy

### V3: Ad Domain Bypass Undermines Privacy
- **Severity**: LOW
- **CWE**: CWE-693 (Protection Mechanism Failure)
- **Description**: Advertising domains bypass VPN, exposing real IP to trackers
- **Impact**: Advertisers can track real IP addresses defeating VPN purpose
- **Affected File**: `scripts/service.js:165-179`
- **Recommendation**: Remove bypass list or clearly disclose this behavior to users

### V4: Lack of Server Configuration Integrity
- **Severity**: LOW
- **CWE**: CWE-353 (Missing Support for Integrity Check)
- **Description**: No cryptographic verification of server configurations
- **Impact**: MITM attacks could inject malicious proxy servers
- **Affected File**: `scripts/service.js:126`
- **Recommendation**: Implement HTTPS certificate pinning or config signing

---

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| `chrome.management` API | service.js:289, 443 | Standard VPN extension behavior to detect/manage proxy conflicts |
| `atob()` usage | service.js:44 | Legitimate RSA public key import (standard WebCrypto API usage) |
| `<all_urls>` permission | manifest.json | Required for content script origin validation, not used for surveillance |

---

## API Endpoints

| Endpoint | Purpose | Data Sent | Data Received |
|----------|---------|-----------|---------------|
| https://drive.google.com/uc?export=view&id=10RKfD2ZTlajZ5VnULVzk1sxUl-Zn7i8N | Fetch proxy servers | None explicit | Server IPs, ports, types |
| https://www.freevpn.one/tl.php | Check time limits | Implicit: connection timing | Duration limits, pro status |
| https://www.logonless.com/img.php | Tracking pixel | IP, User-Agent, Referrer | 1x1 image |
| https://docs.google.com/forms/d/1D31iPuDpCZ8nKBKdwBV23nEDS5Hz6P7NJjm4lyoBlxk/ | Uninstall feedback | User-submitted feedback | N/A |

---

## Privacy Concerns

1. **Third-Party Tracking**: The logonless.com tracking pixel leaks user data to an external party
2. **Ad Domain Bypass**: Real IP exposed to advertising networks despite VPN connection
3. **Machine ID Tracking**: Persistent identifier enables cross-session tracking
4. **Connection Telemetry**: Server knows when users connect via tl.php requests
5. **No Encryption Transparency**: Users route traffic through unknown third-party proxies with no visibility into logging practices

---

## Recommendations

1. **Remove Third-Party Tracking**: Eliminate the logonless.com pixel
2. **Disclose Ad Bypass**: Clearly inform users that ad networks see their real IP
3. **Implement Configuration Signing**: Cryptographically sign server configurations
4. **Privacy Policy Review**: Ensure privacy policy accurately describes data collection
5. **Transparency Report**: Publish information about proxy server operators and logging policies

---

## Overall Verdict

**Risk Level**: **MEDIUM**

Free VPN functions as a legitimate proxy service but demonstrates concerning privacy practices that contradict user expectations for a VPN product:

**Strengths**:
- Clean, readable codebase with no obfuscation
- No keylogging, credential theft, or obvious malware
- WebRTC leak protection feature
- Content script properly scoped to own domain
- No evidence of malicious traffic interception by the extension itself

**Weaknesses**:
- Third-party tracking pixel in privacy product
- Dynamic remote configuration without integrity checks
- Ad domains bypass VPN, exposing real IP
- Machine ID tracking
- All traffic routed through unverified third-party proxies
- No transparency about proxy server operators or logging

**Conclusion**: This extension is **NOT malware** but implements **poor privacy practices** for a VPN service. The remote configuration mechanism and third-party tracking create moderate security and privacy risks. The extension would be rated CLEAN if the tracking pixel were removed and ad bypass properly disclosed. As currently implemented, it warrants a MEDIUM risk rating due to privacy concerns and potential for abuse via the remote configuration mechanism.
