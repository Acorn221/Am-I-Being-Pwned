# Security Analysis: CK-Express TP

**Extension ID:** allahmdcdojnlikmpkdpcopgmjfdafch
**Version:** 3.2
**Users:** 300,000
**Risk Level:** MEDIUM
**Manifest Version:** 3

## Executive Summary

CK-Express TP is a legitimate enterprise content filtering and web security solution by ContentKeeper Technologies. The extension collects user email addresses, device serial numbers, and browsing metadata to enforce organization-level content filtering policies. While data collection is extensive, it appears disclosed and appropriate for its intended enterprise use case. However, the extension contains security vulnerabilities including an insecure postMessage handler and uses WebAssembly with unsafe-eval CSP.

**Primary Concerns:**
1. **postMessage vulnerability** - No origin validation on message handler
2. **Extensive data collection** - User email, device serial, browsing history (disclosed for enterprise filtering)
3. **WebAssembly with unsafe CSP** - Uses wasm-unsafe-eval

## Risk Assessment

| Category | Count | Severity |
|----------|-------|----------|
| Critical | 0 | - |
| High | 0 | - |
| Medium | 2 | postMessage vulnerability, enterprise data collection |
| Low | 1 | CSP unsafe-eval for WASM |

**Overall Risk: MEDIUM** - Enterprise tool with disclosed monitoring capabilities but contains exploitable postMessage vulnerability.

## Detailed Findings

### 1. postMessage Vulnerability (MEDIUM)

**File:** `dsl.js`
**Issue:** The extension registers a global message event handler without validating the message origin, creating an XSS attack vector.

```javascript
window.addEventListener("message", function(event) {
    // No origin check - accepts messages from ANY source
    handleDslMessage(event.data);
});
```

**Impact:** Malicious websites could send crafted messages to the extension's web-accessible `dsl.js` script, potentially triggering unintended behavior or injecting code.

**Recommendation:** Implement strict origin validation:
```javascript
window.addEventListener("message", function(event) {
    if (event.origin !== "chrome-extension://" + chrome.runtime.id) {
        return; // Reject messages from untrusted origins
    }
    handleDslMessage(event.data);
});
```

### 2. Enterprise Data Collection (MEDIUM)

**Files:** `ckAuth.js`, `ckClassificationServer.js`, `serviceWorker.js`

The extension collects and transmits extensive user and device data to ContentKeeper classification servers:

#### Data Collected:
1. **User Email** - Via `chrome.identity.getProfileUserInfo()`
   ```javascript
   chrome.identity.getProfileUserInfo(function(userInfo) {
       globals.user.email = userInfo.email;
   });
   ```

2. **Device Serial Number** - Via `chrome.enterprise.deviceAttributes`
   ```javascript
   chrome.enterprise.deviceAttributes.getDeviceSerialNumber(function (sn) {
       globals.device.serialNumber = sn;
   });
   ```

3. **Browsing Activity** - URL classification requests
   ```javascript
   let data = `<a>${globals.user.email}</a><os>1</os>`;
   data += globals.device.serialNumber ? `<did>${globals.device.serialNumber}</did>` : "";
   const encryptedData = this.#encryptDecryptServerData(data, classificationServer, true);
   ```

4. **IP Address** - Device IP collected during proxy authentication
   ```javascript
   const data = `${globals.user.email},${String(secondsSinceEpoch)}`;
   const encryptedMessage = CKUtils.encryptData(data);
   ```

#### Transmission Endpoints:
- `https://*.contentkeeper.net/cloud/dsl/cfg` - DSL configuration (sends email + device serial)
- `https://*.contentkeeper.net/ceDslWl` - Whitelist management
- DNS-over-HTTPS servers - Configuration lookups
- Classification servers (dynamically configured)

**Disclosure Assessment:** This appears to be **disclosed enterprise monitoring**. The extension description states "ContentKeeper Technologies Cloud-based Internet Filtering and Security System" which clearly indicates its monitoring purpose. The use of `enterprise.deviceAttributes` permission confirms it's designed for managed enterprise deployments.

**Risk Level:** MEDIUM - While data collection is extensive, it's appropriate for enterprise content filtering and appears disclosed. However, organizations should be aware of the full scope of monitoring.

### 3. Content Security Policy - unsafe-eval (LOW)

**File:** `manifest.json`

```json
"content_security_policy": {
    "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'"
}
```

**Issue:** The CSP allows `wasm-unsafe-eval` to support WebAssembly encryption/decryption functions. While necessary for WASM functionality, this weakens content security.

**WASM Usage:** The extension uses WebAssembly for cryptographic operations:
```javascript
static encryptData(data) {
    const encryptOutputPtr = Module._malloc(1024);
    const encryptedOutputLength = window.ckEncryptData(data, encryptOutputPtr);
    const encryptedData = UTF8ToString(encryptOutputPtr);
    Module._free(encryptOutputPtr);
    return encryptedData;
}
```

**Impact:** LOW - The WASM is used for legitimate encryption purposes and is bundled with the extension (not loaded from remote sources).

## Technical Architecture

### Proxy Configuration
The extension implements enterprise content filtering via Chrome's proxy API:
- Intercepts all web requests via `<all_urls>` host permissions
- Routes traffic through ContentKeeper proxy servers
- Performs real-time URL classification
- Enforces organization filtering policies

### Authentication Flow
1. Collects user email via Chrome Identity API
2. Collects device serial number (ChromeOS enterprise only)
3. Encrypts credentials using WASM crypto
4. Sends encrypted auth data to ContentKeeper servers every 30 seconds
5. Receives proxy configuration and filtering rules

### Data Encryption
All sensitive data (email, device ID, IP) is encrypted using WebAssembly-based encryption before transmission:
```javascript
const data = `${globals.user.email},${String(secondsSinceEpoch)}`;
const messageResult = CKUtils.encryptData(data); // WASM encryption
```

## Permissions Analysis

| Permission | Purpose | Risk |
|------------|---------|------|
| `identity`, `identity.email` | Collect user email for authentication | MEDIUM - Required for enterprise auth |
| `enterprise.deviceAttributes` | Device serial number (ChromeOS) | MEDIUM - Enterprise device tracking |
| `enterprise.hardwarePlatform` | Platform identification | LOW |
| `proxy` | Configure filtering proxy | HIGH - Full traffic interception |
| `webRequest`, `webRequestBlocking` | URL classification | HIGH - Monitor all browsing |
| `tabs` | Tab management for blocked content | MEDIUM |
| `<all_urls>` | Access all websites | HIGH - Required for filtering |

## Network Endpoints

1. **ContentKeeper Classification Servers** (dynamically configured)
   - Purpose: Real-time URL filtering decisions
   - Data sent: Encrypted user email, device serial, visited URLs

2. **DNS-over-HTTPS Servers**
   - `https://cloudflare-dns.com/dns-query`
   - `https://dns.google/resolve`
   - `https://doh.contentkeeper.net/dns-query`
   - Purpose: Retrieve filtering configuration via DNS TXT records

3. **On-Premise Detection**
   - `http://192.0.2.12` (RFC 5737 TEST-NET-1 address)
   - Purpose: Detect if device is on enterprise network vs remote

## Privacy Considerations

### What the Extension Can See:
- Every URL visited (via webRequest)
- User's email address (via identity API)
- Device serial number (ChromeOS only)
- User's IP address
- All browsing metadata (timestamps, headers, etc.)

### Data Retention:
Not disclosed in code - data handling is server-side at ContentKeeper.

### User Control:
This is an enterprise-managed extension. End users typically cannot disable it or opt out of monitoring. Installation and configuration are controlled by IT administrators via Chrome's managed policies (schema.json shows managed storage for service key).

## Recommendations

### For ContentKeeper (Vendor):
1. **FIX CRITICAL:** Add origin validation to postMessage handler in `dsl.js`
2. **Improve transparency:** Add in-extension privacy notice about data collection
3. **Minimize data:** Consider whether device serial number is strictly necessary
4. **Audit logging:** Implement client-side logging of all data transmission events

### For Enterprise Administrators:
1. **Disclose monitoring:** Ensure users are informed about the extent of monitoring
2. **Review privacy policy:** Verify ContentKeeper's data retention and handling practices
3. **Scope deployment:** Only deploy to managed enterprise devices, not personal devices
4. **Test configurations:** Verify the extension properly handles DNS failures (has "airgap" fallback mode)

### For End Users:
1. This is enterprise software - contact your IT department for privacy questions
2. Assume all browsing activity is monitored when this extension is active
3. This extension is typically force-installed by employers - you cannot remove it from managed devices

## Conclusion

CK-Express TP is a legitimate enterprise content filtering solution with extensive monitoring capabilities that appear disclosed and appropriate for its intended use case. The primary security concern is the unvalidated postMessage handler which creates an exploitable XSS vector. The data collection, while extensive, is typical for enterprise monitoring tools and appears to be disclosed in the extension's description.

**Risk Rating: MEDIUM** - Appropriate for enterprise environments with informed users, but the postMessage vulnerability should be addressed immediately.

## Flag Categories

- `enterprise_monitoring` - Designed for workplace surveillance
- `postmessage_vulnerability` - Insecure message handler without origin validation
- `wasm_usage` - Uses WebAssembly with unsafe-eval CSP
- `user_email_collection` - Collects and transmits user email addresses
- `device_fingerprinting` - Collects device serial numbers and hardware info

## Metadata

- **Analysis Date:** 2026-02-15
- **Analyzer Version:** ext-analyzer + manual review
- **Static Analysis Risk Score:** 45/100
- **Extension Build:** 28
