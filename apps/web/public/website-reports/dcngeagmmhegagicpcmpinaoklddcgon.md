# Security Analysis: Web PKI (dcngeagmmhegagicpcmpinaoklddcgon)

## Extension Metadata
- **Name**: Web PKI
- **Extension ID**: dcngeagmmhegagicpcmpinaoklddcgon
- **Version**: 2.17.0
- **Manifest Version**: 3
- **Estimated Users**: ~3,000,000
- **Developer**: Lacuna Software
- **Analysis Date**: 2026-02-14

## Executive Summary
Web PKI is a legitimate digital certificate management extension developed by Lacuna Software with **LOW** risk assessment. The extension provides digital certificate functionality for webpages by bridging browser JavaScript APIs with a native PKI component installed on the user's system. The four postMessage handlers flagged by the static analyzer are **false positives** — they are internal to the Forge.js cryptography library (setImmediate polyfill and Web Worker communication). The actual content script message handler properly validates message sources using custom events and port-based messaging. The extension communicates with Lacuna Software's infrastructure for SignalR-based remote device coordination and retrieval of home page data.

**Overall Risk Assessment: LOW**

## Vulnerability Assessment

### 1. postMessage Handlers in forge-cipher.js (FALSE POSITIVE)
**Severity**: N/A (Not a Vulnerability)
**Files**:
- `/scripts/forge-cipher.js` (lines 169, 3002, 6559)

**Analysis**:
The ext-analyzer flagged three `window.addEventListener("message")` calls in `forge-cipher.js` as potential security vulnerabilities. Detailed code inspection reveals these are **benign library internals** from the Forge.js cryptographic library:

#### Handler 1: Line 169 - setImmediate Polyfill
```javascript
// Polyfill for setImmediate using postMessage
var msg = 'forge.setImmediate';
var callbacks = [];
util.setImmediate = function(callback) {
    callbacks.push(callback);
    if(callbacks.length === 1) {
        window.postMessage(msg, '*');
    }
};
function handler(event) {
    if(event.source === window && event.data === msg) {
        event.stopPropagation();
        var copy = callbacks.slice();
        callbacks.length = 0;
        copy.forEach(function(callback) {
            callback();
        });
    }
}
window.addEventListener('message', handler, true);
```

**Purpose**: This is a standard polyfill pattern for `setImmediate()` used in environments where native `setImmediate` is unavailable. It uses `postMessage` to schedule asynchronous callbacks.

**Security Validation**:
- `event.source === window` — validates message is from same window (not cross-origin)
- `event.data === msg` — validates message contains exact string 'forge.setImmediate'
- `event.stopPropagation()` — prevents event bubbling
- Only executes internal callbacks, no external data processed

**Verdict**: **NOT MALICIOUS** - Standard async task scheduling pattern

#### Handler 2: Line 3002 - Web Worker Concurrency Detection
```javascript
self.addEventListener('message', function(e) {
    // run worker for 4 ms
    var st = Date.now();
    var et = st + 4;
    while(Date.now() < et);
    self.postMessage({st: st, et: et});
});
```

**Purpose**: This code runs **inside a Web Worker** (created from a Blob URL) to measure CPU concurrency. It's part of Forge.js's core detection logic to determine optimal parallelization.

**Security Context**:
- Runs in isolated Web Worker context (not main thread)
- No access to DOM, cookies, or extension APIs
- Only processes timing data

**Verdict**: **NOT MALICIOUS** - CPU concurrency measurement

#### Handler 3: Line 6559 - PRNG Seed Communication
```javascript
if(worker === self) {
    ctx.seedFile = function(needed, callback) {
        function listener(e) {
            var data = e.data;
            if(data.forge && data.forge.prng) {
                self.removeEventListener('message', listener);
                callback(data.forge.prng.err, data.forge.prng.bytes);
            }
        }
        self.addEventListener('message', listener);
        self.postMessage({forge: {prng: {needed: needed}}});
    };
}
```

**Purpose**: This handles pseudo-random number generator (PRNG) seed exchange between the main thread and Web Workers for cryptographic operations.

**Security Validation**:
- `data.forge && data.forge.prng` — validates message structure
- Removes listener after first message (one-time use)
- Only processes random bytes, not user data

**Verdict**: **NOT MALICIOUS** - Cryptographic random number seeding

---

### 2. Content Script postMessage Handler (SECURE IMPLEMENTATION)
**Severity**: N/A (Properly Secured)
**Files**: `/scripts/content-script.js` (line 32)

**Analysis**:
The fourth handler flagged by the analyzer is in the content script, but it implements **proper origin validation**:

```javascript
// Firefox/non-Chrome browsers use window.postMessage
window.addEventListener('message', function (event) {
    if (event && event.data && event.data.port === requestEventName) {
        onPageMessage(event.data.message);
    }
});
```

**Security Context**:
- This handler only runs on Firefox (Chrome/Edge use CustomEvent instead)
- Validates `event.data.port === requestEventName` where `requestEventName = 'com.lacunasoftware.WebPKI.RequestEvent'`
- Messages are forwarded to background page via `chrome.runtime.connect()` port
- Background page validates sender URL and extracts domain from `port.sender.tab.url`

**Chrome/Edge Implementation** (lines 28-30):
```javascript
if (browserId === 'chrome' || browserId === 'edge') {
    document.addEventListener(requestEventName, function (event) {
        onPageMessage(event.detail);
    });
}
```

**Security Model**:
1. Webpage posts message to content script via custom event system
2. Content script validates port name and forwards to background page
3. Background page extracts domain from sender URL: `var m = /\/\/([^\/:]*)/.exec(tabUrl);`
4. All PKI operations are scoped to the requesting domain
5. Domain-based trust model stored in `chrome.storage.sync` with keys like `trust:domain.com:certThumbprint`

**Verdict**: **SECURE** - Proper message validation and domain-scoped trust model

---

### 3. Native Messaging Component
**Severity**: Low (Requires Separate Installation)
**Files**: `/event-page.js` (lines 496-503)

**Analysis**:
The extension uses `nativeMessaging` permission to communicate with a native application `com.lacunasoftware.webpki` installed on the user's system.

**Security Boundaries**:
```javascript
page.nativePort = browser.runtime.connectNative(nativeApplicationName);
page.nativePort.onMessage.addListener(function (message) {
    onNativeMessage(page, message);
});
```

**Native Component Purpose**:
- Accesses local digital certificates (PKCS#11, Windows Certificate Store)
- Performs cryptographic signing operations
- Requires separate user installation (not bundled with extension)

**Risk Mitigation**:
- Native component not installed by default (extension detects and prompts user)
- Separate installation requires explicit user consent
- Native messaging is a secure Chrome API with OS-level process isolation
- Extension validates native component version before use

**Verdict**: **LOW RISK** - Standard PKI architecture pattern, requires explicit user installation

---

### 4. SignalR WebRTC-Based Remote Device Coordination
**Severity**: Low (Intentional Feature)
**Files**: `/event-page.js` (lines 3345, 46-47)

**Analysis**:
The extension uses SignalR client library to communicate with Lacuna's cloud service for remote device coordination (e.g., using smartphone as PKI token).

**Implementation**:
```javascript
importScripts("scripts/signalr-client-1.0.4.js");
_p._signalServerUrl = 'https://cloud.lacunasoftware.com/';
```

**Feature Purpose**:
- Allows users to use mobile devices as remote PKI tokens
- Coordinates certificate operations between browser and mobile app
- Uses WebRTC-style signaling for peer discovery

**Security Considerations**:
- Communication goes through Lacuna's cloud infrastructure
- User must explicitly configure remote devices in extension settings
- Device IDs stored in `chrome.storage.sync` under `remoteDevices` key

**Data Transmitted**:
- Device registration/pairing data
- Certificate operation requests/responses
- No browsing history or unrelated user data

**Verdict**: **LOW RISK** - Intentional feature for remote PKI token functionality

---

### 5. Remote Configuration Endpoint
**Severity**: Low (Read-Only Analytics/Config)
**Files**: `/event-page.js` (lines 3509-3520)

**Analysis**:
The extension fetches configuration data from Lacuna's cloud service on startup:

```javascript
function getWebPkiHomeData() {
    var ep = 'https://fx.lacunasoftware.com/api/home-data?code=VGc6L0JxptpjgJXKLyWu11e9G07OgvrG5FBXte6Smeyo3tmc6Phcyw==';
    if (ep && ep !== 'undefined') {
        try {
            httpGet(ep, function (data) {
                wpkiHomeData = data;
            });
        } catch (e) {
            console.log('[EventPage] Home error', e);
        }
    }
}
```

**Purpose**: Fetches home page data (likely feature flags, announcements, or blocklists)

**Security Analysis**:
- HTTPS endpoint (encrypted)
- No sensitive user data sent (GET request with static auth code)
- Failure is caught and logged (non-critical)
- Data stored in `wpkiHomeData` global variable

**Potential Data Retrieved**:
- Feature toggles
- Extension/native component version compatibility info
- Blacklist for compromised certificates or malicious domains
- Service status/announcements

**Verdict**: **LOW RISK** - Standard remote configuration pattern for enterprise software

---

## Network Endpoints Summary

### Lacuna Software Infrastructure
- `get.webpkiplugin.com` — Extension installation/setup page
- `getwebpkibeta.lacunasoftware.com` — Beta setup page
- `getwebpkialpha.lacunasoftware.com` — Alpha setup page
- `cloud.lacunasoftware.com` — SignalR hub for remote device coordination
- `fx.lacunasoftware.com/api/home-data` — Remote configuration endpoint

### RestPKI Service Endpoints
- `restpki.lacunasoftware.com` (primary)
- `restpkibeta.azurewebsites.net` (beta)
- `pki.rest` (alternate)
- `restpki.com` (alternate)
- `www.restpki.com` (alternate)

**Purpose**: RestPKI is Lacuna's cloud-based PKI service for certificate validation and signing operations.

### Chrome Web Store
- `chromewebstore.google.com` — Extension update checks and installation links

**Purpose**: The extension redirects users to Chrome Web Store during installation/update flows.

---

## Data Flow Analysis

### User Data Handling
**Certificates**:
- Certificate thumbnails (SHA-1 hashes) stored in `chrome.storage.sync`
- Certificate content cached with keys like `certCache:thumbprint`
- Subject/Issuer names stored for UI display
- Domain-based trust relationships stored as `trust:domain:thumbprint`

**PKCS#11 Modules**:
- User-configured PKCS#11 module paths stored in `chrome.storage.local`
- Used to access hardware tokens (smart cards, HSMs)

**Remote Devices**:
- Device IDs and metadata stored in `chrome.storage.sync`
- Synced across user's Chrome instances
- Used for mobile-as-token functionality

### External Data Transmission
1. **Native Component**: Certificate operations, signatures, file operations (local IPC)
2. **RestPKI Services**: Optional cloud-based certificate validation/signing
3. **Cloud SignalR Hub**: Remote device coordination messages
4. **Home Data Endpoint**: Extension receives config/flags (no user data sent)

**No Data Exfiltration Detected**:
- No browsing history collection
- No form data interception
- No credential harvesting
- No analytics/tracking beyond basic usage events (currently disabled: `function gaEvent() { // Analytics disabled }`)

---

## Code Quality & Obfuscation

**Obfuscation Status**: Moderate (webpack bundling only)
- `main.js` and `event-page.js` are webpack bundles (Angular/TypeScript compiled)
- `forge-cipher.js` is minified Forge.js library (standard distribution)
- Variable names preserved in business logic
- No malicious obfuscation detected

**Libraries Identified**:
- Forge.js (cryptography) — `scripts/forge-cipher.js`
- SignalR Client 1.0.4 — `scripts/signalr-client-1.0.4.js`
- SJCL (Stanford JavaScript Crypto Library) — `scripts/sjcl.js`
- Angular (web UI framework) — `main.js`

---

## Permissions Analysis

### Granted Permissions
- **nativeMessaging**: Required for communicating with native PKI component
- **storage**: Stores certificate trust relationships and user preferences
- **downloads**: Allows saving signed documents to user-selected folders
- **tabs**: Required to inject content script and manage extension installation flow

### Content Script Injection
- **Matches**: `["http://*/*", "https://*/*"]`
- **Frames**: `all_frames: true`
- **Scripts**: `scripts/content-script.js` (2.7KB, minimal footprint)

**Purpose**: The content script acts as a message bridge between webpages and the extension background page. It injects a meta tag to signal extension presence and forwards PKI operation requests.

**Risk**: Low — Content script is minimal and does not intercept/modify page content

---

## Threat Model Assessment

### Attack Scenarios Considered

#### 1. Malicious Webpage Abuse
**Scenario**: Malicious webpage attempts to trigger unauthorized certificate operations

**Mitigations**:
- Domain-based trust model requires explicit user approval per domain+certificate pair
- Trust relationships stored in `chrome.storage.sync` with keys like `trust:domain.com:certHash`
- User prompted for certificate selection via native component UI
- Operations scoped to requesting domain (extracted from `port.sender.tab.url`)

**Risk**: LOW

#### 2. Cross-Origin Message Injection
**Scenario**: Attacker iframe posts messages to compromise message handlers

**Mitigations**:
- Firefox handler validates `event.data.port === requestEventName` (namespaced string)
- Chrome/Edge use CustomEvent (not subject to cross-origin injection)
- Background page validates sender URL from port metadata
- Forge.js handlers validate `event.source === window` and exact message strings

**Risk**: LOW

#### 3. Native Component Compromise
**Scenario**: Malicious native component replacement

**Mitigations**:
- Native component installed separately (not bundled)
- Chrome OS-level validation of native messaging manifests
- Extension validates native component version and OS compatibility
- Native component signed by Lacuna Software (standard OS code signing)

**Risk**: LOW (requires separate installation and OS-level compromise)

---

## Recommendations

### For Users
1. **Verify Native Component Source**: Only install the native component from official Lacuna Software website (`get.webpkiplugin.com`)
2. **Review Trust Relationships**: Periodically audit certificate permissions in extension settings
3. **Keep Updated**: Ensure both extension and native component are current versions

### For Developers (Lacuna Software)
1. **Implement CSP**: Add Content Security Policy to `manifest.json` to restrict script sources
2. **Remove Hardcoded Auth Code**: The `fx.lacunasoftware.com` endpoint uses hardcoded auth code in URL — consider rotating or using extension ID-based authentication
3. **Add Subresource Integrity**: Use SRI for third-party libraries (Forge.js, SignalR, SJCL)
4. **Document Remote Config**: Publish schema/purpose of `home-data` endpoint for transparency

### For Auditors
1. **Verify Native Component**: Full security audit requires reviewing the native component code (not included in this analysis)
2. **Review Cloud Services**: Assess security of `cloud.lacunasoftware.com` SignalR hub and `restpki.lacunasoftware.com` services
3. **Test Trust Model**: Verify domain-based trust isolation prevents cross-domain certificate abuse

---

## Conclusion

Web PKI is a **legitimate, professionally-developed digital certificate management extension** with appropriate security controls for its PKI functionality. The postMessage handlers flagged by static analysis are false positives from the Forge.js cryptography library and do not represent security vulnerabilities. The extension implements proper domain-based trust isolation and requires explicit user consent for certificate operations.

**Final Risk Rating: LOW**

**Confidence Level**: High (based on thorough code review and architecture analysis)

**Recommended Action**: Safe for use in enterprise environments requiring PKI/digital certificate functionality. Users should verify native component authenticity and keep software updated.
