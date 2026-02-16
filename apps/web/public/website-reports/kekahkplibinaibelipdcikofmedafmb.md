# Vulnerability Report: ClickOnce for Google Chrome

## Metadata
- **Extension ID**: kekahkplibinaibelipdcikofmedafmb
- **Extension Name**: ClickOnce for Google Chrome
- **Version**: 2.1
- **Users**: ~300,000
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

ClickOnce for Google Chrome is a legitimate utility extension that enables ClickOnce application support in Chrome by intercepting .application file downloads and passing them to a native messaging host. The extension automatically downloads and prompts users to install a Windows executable (ClickOnceForGoogleChome.exe, distributed as a .dat file) during installation or update. While the functionality is legitimate for its stated purpose, the extension presents a **MEDIUM** security risk due to its use of native messaging with a locally installed executable, broad host permissions, and the practice of bundling/auto-downloading executable files within browser extensions.

The primary concerns are: (1) native messaging introduces potential local privilege escalation vectors if the native host is compromised, (2) the extension requires users to manually execute a downloaded .exe file which trains unsafe security behavior, and (3) broad webRequest permissions on all URLs create a large attack surface if the extension were compromised.

## Vulnerability Details

### 1. MEDIUM: Native Messaging with Locally Installed Executable
**Severity**: MEDIUM
**Files**: clickonce.js, manifest.json, ClickOnceForGoogleChome.dat
**CWE**: CWE-494 (Download of Code Without Integrity Check)
**Description**: The extension uses native messaging to communicate with a local Windows executable (`menarva.utils.clickonceforgooglechrome`) that must be manually installed by the user. During installation/update, the extension automatically downloads a 125KB .NET executable (disguised as .dat file) and instructs users to run it. This creates multiple security concerns:

1. The executable is bundled within the extension package without cryptographic signature verification
2. Users are trained to download and execute files from browser extensions
3. The native messaging host runs with local user privileges and could be exploited for privilege escalation
4. There is no integrity checking of the native host after installation

**Evidence**:
```javascript
// clickonce.js - Native messaging call
chrome.runtime.sendNativeMessage('menarva.utils.clickonceforgooglechrome',
  { clickonce: details.url });
```

```javascript
// nativedownload.js - Automatic executable download on install
window.onload = function() {
    var anchorObj = document.body.children.namedItem('helper-download');
    anchorObj.href = chrome.extension.getURL('ClickOnceForGoogleChome.dat');
    // Programmatically trigger download
    var evt = document.createEvent("MouseEvents");
    evt.initMouseEvent("click", true, true, window, 0, 0, 0, 0, 0, false, false, false, false, 0, null);
    var allowDefault = anchorObj.dispatchEvent(evt);
};
```

**Verdict**: While native messaging is a legitimate Chrome extension feature, the combination of automatic executable download, manual execution requirement, and lack of integrity verification creates unnecessary security risks. A more secure implementation would use Windows Store or signed installer packages with proper code signing.

### 2. MEDIUM: Overly Broad Host Permissions
**Severity**: MEDIUM
**Files**: manifest.json, clickonce.js
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension requests webRequest and webRequestBlocking permissions on all HTTP/HTTPS URLs (`http://*/*`, `https://*/*`) when it only needs to intercept .application file downloads. While functionally necessary for intercepting any ClickOnce application URL, this creates a large attack surface:

1. The extension can inspect all HTTP traffic across all websites
2. If the extension were compromised via update or the publisher account, it could intercept sensitive data
3. The blocking permission allows modifying or canceling arbitrary requests

**Evidence**:
```json
"permissions": [ "webRequest", "webRequestBlocking", "nativeMessaging", "http://*/*", "https://*/*" ]
```

```javascript
chrome.webRequest.onBeforeRequest.addListener(function(details) {
    if (details.url.indexOf('.application') != -1) {
        // Only acts on .application URLs, but listens to ALL traffic
    }
}, { urls: ['http://*/*', 'https://*/*'] }, ['blocking']);
```

**Verdict**: The permissions are technically necessary for the functionality but represent excessive privileges from a least-privilege security perspective. Chrome's webRequest API does not support content-type-based filtering before the request completes, forcing this broad permission scope.

### 3. LOW: Insecure Redirect Pattern
**Severity**: LOW
**Files**: clickonce.js
**CWE**: CWE-601 (URL Redirection to Untrusted Site)
**Description**: When intercepting .application URLs, the extension redirects to `javascript:void(0)` to prevent the browser from downloading the file. While this works, using javascript: URLs in redirects is generally discouraged as it can trigger CSP violations and represents a code smell.

**Evidence**:
```javascript
return {redirectUrl: 'javascript:void(0)'};
```

**Verdict**: This is a minor issue that does not present a direct security vulnerability but represents poor practice. A better approach would be using `chrome:extension-invalid` or canceling the request via `{cancel: true}`.

## False Positives Analysis

1. **Executable bundling**: While bundling executables in browser extensions is unusual and generally suspicious, it is the legitimate purpose of this extension (to install native messaging host support). The .dat extension is merely obfuscation of the .exe file.

2. **Broad permissions**: The `webRequest` and `webRequestBlocking` permissions on all URLs appear excessive but are technically necessary because Chrome does not provide a way to filter webRequest listeners by content-type or file extension before the request is made.

3. **Native messaging**: This is a legitimate Chrome API designed for extensions that need to interact with native applications. The extension's use case (launching ClickOnce applications) requires this functionality.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| menarva.utils.clickonceforgooglechrome (Native) | Native messaging host for launching ClickOnce apps | URL of .application file clicked | MEDIUM - Local executable with user privileges |
| chrome-extension://[id]/ClickOnceForGoogleChome.dat | Bundled .NET executable | N/A (local file) | MEDIUM - User must manually execute |

No external network endpoints are contacted by the extension code itself. All functionality is local.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

ClickOnce for Google Chrome is a legitimate utility extension performing its stated function of enabling ClickOnce application support in Chrome. However, it receives a **MEDIUM** risk rating due to:

1. **Native Messaging Security Model**: The requirement to download and manually execute a bundled Windows executable introduces significant risk. If either the extension or the native host were compromised in an update, attackers could gain local code execution with user privileges across 300,000 installations.

2. **Excessive Permissions**: While technically necessary, the ability to intercept and block all HTTP/HTTPS requests across all websites creates a large attack surface for potential abuse if the extension were compromised.

3. **User Security Training**: The extension explicitly instructs users to download and run executable files, which trains unsafe security behavior. Users conditioned to trust and execute files from browser extensions are more vulnerable to malicious extensions.

4. **Lack of Modern Security Features**: No code signing verification, no integrity checks of the native host, and use of deprecated javascript: URLs in redirects.

**Mitigating Factors**:
- The extension code itself contains no malicious functionality
- Published by an identifiable company (Menarva Ltd)
- The functionality matches the stated purpose
- No evidence of data exfiltration or privacy violations
- Clean static analysis results from ext-analyzer

**Recommendations for Users**:
- Only install if ClickOnce application support is genuinely needed
- Verify the ClickOnceForGoogleChome.exe file signature before execution
- Monitor the extension for unexpected updates
- Consider uninstalling if not actively using ClickOnce applications

**Recommendations for Developer**:
- Implement code signing for the native messaging host
- Add integrity verification of the native host executable
- Consider Windows Store distribution for the native component
- Use `{cancel: true}` instead of javascript: redirect
- Add manifest V3 migration plan (native messaging support continues in MV3)
