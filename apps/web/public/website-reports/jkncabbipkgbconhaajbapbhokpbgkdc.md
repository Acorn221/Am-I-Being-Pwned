# Vulnerability Report: Cegid Peoplenet ClickOnce launcher

## Metadata
- **Extension ID**: jkncabbipkgbconhaajbapbhokpbgkdc
- **Extension Name**: Cegid Peoplenet ClickOnce launcher
- **Version**: 2.0
- **Users**: ~500,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

The Cegid Peoplenet ClickOnce launcher is an enterprise extension designed to enable ClickOnce application launching in Chrome by intercepting `.application` downloads and passing them to a native Windows executable. While the extension serves a legitimate enterprise purpose (enabling Microsoft ClickOnce apps in Chrome), it exhibits significant security concerns due to overly broad permissions, automatic native binary installation, and the creation of a privileged native messaging bridge that could be exploited if compromised.

The primary concern is the combination of `<all_urls>` host permissions with automatic execution of a downloaded native binary. While the extension's stated functionality is benign, the attack surface created by these permissions and the native messaging channel represents a high-risk deployment pattern, particularly given the 500,000+ user base.

## Vulnerability Details

### 1. HIGH: Overly Broad Host Permissions
**Severity**: HIGH
**Files**: manifest.json, service_worker.js
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension requests `<all_urls>` host permissions, which grants access to all websites. However, the actual functionality only requires intercepting `.application` file downloads, which could be accomplished with more targeted permissions or with the `downloads` permission alone.

**Evidence**:
```json
"host_permissions": [
    "<all_urls>"
]
```

**Verdict**: The `<all_urls>` permission is excessive for the stated functionality. The extension only needs to monitor downloads via `chrome.downloads.onDeterminingFilename`, which is already granted by the `downloads` permission. This represents a violation of the principle of least privilege and unnecessarily expands the attack surface if the extension is compromised.

### 2. HIGH: Automatic Native Binary Execution
**Severity**: HIGH
**Files**: nativeinstall.js, nativeinstall.html, m4clickoncehelper.dat
**CWE**: CWE-494 (Download of Code Without Integrity Check)
**Description**: Upon installation or update, the extension automatically downloads a Windows PE32 executable (m4clickoncehelper.dat, 54KB) and prompts the user to run it. This binary is distributed as a web-accessible resource from the extension package with no integrity verification beyond the extension's signature.

**Evidence**:
```javascript
// service_worker.js
chrome.runtime.onInstalled.addListener(function(details) {
	if (details.reason === 'install' || details.reason === 'update'){
		var installUrl = chrome.runtime.getURL('nativeinstall.html');
		chrome.tabs.create({url: installUrl});
    }
});

// nativeinstall.js
window.onload = function() {
	var anchorObj = document.body.children.namedItem('helper-download');
	anchorObj.href = chrome.runtime.getURL('m4clickoncehelper.dat');
	anchorObj.click();
};
```

File analysis:
```
m4clickoncehelper.dat: PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections
```

**Verdict**: While the binary appears legitimate (Cegid-branded .NET assembly for ClickOnce handling), the pattern of bundling executables in browser extensions and automatically prompting users to run them creates significant risk. If an attacker compromises the extension update mechanism or performs a supply chain attack, they could distribute malicious executables to 500,000+ users. Additionally, there is no cryptographic verification of the binary beyond Chrome's extension signature validation.

### 3. MEDIUM: Native Messaging Bridge with Broad Permissions
**Severity**: MEDIUM
**Files**: service_worker.js, manifest.json
**CWE**: CWE-923 (Improper Restriction of Communication Channel to Intended Endpoints)
**Description**: The extension creates a native messaging channel (`meta4.clickonce.clickoncehelper`) that can be invoked from any website matching the download pattern. While the current implementation only sends URLs, this creates a privileged IPC channel between web content and native code.

**Evidence**:
```javascript
const analyzeClickOnceLaunchOnDownload = (downloadItem, suggest) => {
    const regexPattern = /https?:\/\/([^/]+\/)+[^/]+\.application(\?.*)?/;
    if (downloadItem.state === "in_progress" && downloadItem.mime === "application/x-ms-application" && regexPattern.test(downloadItem.finalUrl)) {
        chrome.runtime.sendNativeMessage('meta4.clickonce.clickoncehelper',
            { url: downloadItem.finalUrl })
            .catch(err => { /* alert */ });
    }
}
```

**Verdict**: The native messaging implementation is reasonably secure in its current form - it validates the MIME type and URL pattern before sending data to the native host. However, the combination of native messaging with `<all_urls>` creates a privileged bridge that could be exploited if either the extension or native binary has vulnerabilities. The risk is mitigated by the fact that only URLs are passed (not arbitrary commands), but the broad permissions still create unnecessary exposure.

## False Positives Analysis

- **ClickOnce File Interception**: The core functionality of intercepting `.application` downloads and passing them to a native helper is legitimate and expected for this extension type. This is the standard pattern for enabling Microsoft ClickOnce applications in Chrome.
- **Native Messaging Permission**: The `nativeMessaging` permission is required and appropriate for the extension's stated purpose.
- **data: URL Alert**: The use of `data:text/html` URLs in `chrome.windows.create()` for displaying alerts is a common pattern and not inherently malicious, though it could be replaced with a popup page for better CSP compliance.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| None | Extension operates locally | N/A | N/A |

The extension does not communicate with any external API endpoints. All functionality is local (native messaging to system binary).

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**:

While the extension serves a legitimate enterprise purpose and does not exhibit overtly malicious behavior, it demonstrates a high-risk deployment pattern that violates security best practices:

1. **Excessive Permissions**: The `<all_urls>` permission is unnecessary for the extension's functionality and violates the principle of least privilege.

2. **Native Binary Distribution**: Bundling and auto-downloading a native Windows executable creates significant supply chain risk. If the extension's update mechanism is compromised, attackers could distribute malicious executables to 500,000+ users.

3. **Large Attack Surface**: The combination of broad host permissions, native messaging, and automatic binary installation creates multiple attack vectors that could be exploited.

4. **Enterprise Deployment Concerns**: While appropriate for controlled enterprise environments where IT departments can vet the extension and native binary, the broad public availability (500K users) of this pattern is concerning.

**Recommendations**:
- Remove `<all_urls>` permission - not required for download interception
- Implement cryptographic verification of the native binary beyond Chrome's extension signature
- Consider alternative deployment models (e.g., IT-managed installation of the native component separately)
- Add runtime integrity checks of the native messaging host
- Restrict extension distribution to enterprise-only channels rather than public Chrome Web Store

**For Enterprise Users**: This extension is likely safe when deployed through managed enterprise channels with proper IT oversight. The Cegid brand is legitimate and the functionality matches the stated purpose. However, verify the native binary source and consider network-level monitoring of any ClickOnce applications launched through this mechanism.
