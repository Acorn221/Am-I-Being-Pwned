# Vulnerability Report: Windows Remix ClickOnce Helper

## Metadata
- **Extension ID**: dgpgholdldjjbcmpeckiephjigdpikan
- **Extension Name**: Windows Remix ClickOnce Helper
- **Version**: 1.5.2
- **Users**: ~200,000
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

Windows Remix ClickOnce Helper is a browser extension designed to enable ClickOnce application support in Chrome by bridging to a native Windows application. While the extension serves a legitimate technical purpose (enabling .NET ClickOnce deployment technology in Chrome after NPAPI deprecation), it introduces security concerns through its implementation.

The extension automatically downloads and prompts users to execute a native binary (winmixClickOnceHelper-v1.4.0.0.exe) from a remote server (windowsremix.com) during installation. This creates a potential supply chain attack vector where compromise of the distribution server could lead to malware distribution to 200,000+ users. Additionally, the extension uses broad permissions including webRequest blocking across all URLs and native messaging without adequate security controls or binary verification mechanisms.

## Vulnerability Details

### 1. HIGH: Automatic Native Binary Download Without Verification

**Severity**: HIGH
**Files**: install/install.js, install/nativeclient.html
**CWE**: CWE-494 (Download of Code Without Integrity Check)

**Description**: The extension automatically downloads a native executable from a remote server on installation/update without implementing cryptographic verification of the binary's integrity or authenticity.

**Evidence**:
```javascript
// install/install.js
window.onload = function() {
  var a = document.createElement("iframe");
  a.style.display = "none";
  a.src = "https://www.windowsremix.com/files/winmixClickOnceHelper-v1.4.0.0.exe";
  document.body.appendChild(a);
  // ...
}
```

The installation page automatically triggers download of an executable via hidden iframe without:
- Cryptographic signature verification
- Hash validation (SHA-256, etc.)
- Certificate pinning
- Secure update channel validation

**Verdict**: While the extension itself appears legitimate, this implementation creates a supply chain risk. If windowsremix.com were compromised, attackers could distribute malware to 200,000+ users. The extension should implement code signing verification and hash validation before instructing users to execute the downloaded binary.

### 2. MEDIUM: Native Messaging Without Security Boundaries

**Severity**: MEDIUM
**Files**: background.js
**CWE**: CWE-923 (Improper Restriction of Communication Channel to Intended Endpoints)

**Description**: The extension uses native messaging to communicate with a local Windows application without implementing adequate security controls or origin validation.

**Evidence**:
```javascript
// background.js
function startClickOnce(a) {
  return console.log("Launching ClickOnce: " + a),
    chrome.runtime.sendNativeMessage("winmix.clickonce.helper", {
      url: a
    }), {
      redirectUrl: "javascript:void(0)"
    }
}
```

The extension passes URLs directly to the native host without:
- URL validation or sanitization
- Allowlist of permitted domains
- Rate limiting to prevent abuse
- User confirmation for untrusted sources

**Verdict**: While ClickOnce is the stated purpose, the broad permission scope (*://*/*) means any website could potentially trigger native message passing. This could be abused if the native host has vulnerabilities or if malicious websites attempt to exploit the native messaging channel.

### 3. LOW: Overly Broad Web Request Permissions

**Severity**: LOW
**Files**: background.js, manifest.json
**CWE**: CWE-250 (Execution with Unnecessary Privileges)

**Description**: The extension requests blocking webRequest permissions on all URLs when it only needs to detect ClickOnce applications.

**Evidence**:
```javascript
// manifest.json
"permissions": [
  "webRequest",
  "webRequestBlocking",
  "nativeMessaging",
  "*://*/*",
  "declarativeContent"
]

// background.js
chrome.webRequest.onBeforeRequest.addListener(function(a) {
  var b = document.createElement("a");
  b.href = a.url;
  if (b.pathname.match(/\.application$/i)) {
    return startClickOnce(a.url);
  }
}, {
  urls: ["<all_urls>"]
}, ["blocking"]);
```

**Verdict**: While the implementation only inspects for .application file extensions and MIME types, the broad permission scope creates unnecessary attack surface. The extension could be more security-conscious by using declarativeNetRequest or limiting permissions to specific protocols/patterns.

## False Positives Analysis

The following patterns are present but legitimate for this extension type:

1. **Native Messaging**: Required for the stated purpose of launching ClickOnce applications via a native Windows helper
2. **WebRequest Blocking**: Necessary to intercept .application file requests before they download
3. **Content Script Injection on all_urls**: Used only to inject a detection script that adds navigator plugin spoofing for ClickOnce detection
4. **Navigator Plugin Manipulation**: The detect.js file adds fake navigator.plugins entries to make websites believe ClickOnce is supported - this is legitimate browser feature detection spoofing for compatibility

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| ssl.google-analytics.com | Analytics tracking | Button click events, page views | Low - Standard analytics |
| www.windowsremix.com | Binary download, website links | None (download only) | Medium - Unverified binary source |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

The extension serves a legitimate technical purpose and appears to be a genuine utility for enabling ClickOnce support in Chrome. The code is relatively clean and does not exhibit malicious behavior patterns such as data exfiltration, credential theft, or hidden network communication.

However, the extension is rated MEDIUM risk rather than LOW due to the following factors:

1. **Supply Chain Vulnerability**: The automatic download of a native executable from a remote server without cryptographic verification creates a significant supply chain attack vector. With 200,000+ users, compromise of the distribution server would have serious impact.

2. **Native Code Execution**: The extension explicitly instructs users to execute downloaded binaries, and this creates inherent risk regardless of the developer's intentions.

3. **Broad Permission Scope**: The combination of blocking webRequest on all URLs plus native messaging provides extensive capabilities that could be abused if the extension were compromised via update.

4. **Trust Model**: Users must trust both the extension and the native binary it downloads, with no technical controls to verify integrity.

**Recommendations**:
- Implement code signing verification for the native binary download
- Add SHA-256 hash validation before instructing users to execute
- Consider using declarativeNetRequest instead of blocking webRequest where possible
- Implement URL allowlisting for native message passing
- Add user confirmation prompts for ClickOnce launches from untrusted sources
- Consider migrating to Manifest V3 with more restrictive permission model
