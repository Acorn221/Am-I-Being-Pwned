# Vulnerability Report: IObit Surfing Protection

## Metadata
- **Extension ID**: imgpenhngnbnmhdkpdfnfhdpmfgmihdn
- **Extension Name**: IObit Surfing Protection
- **Version**: 3.1.6
- **Users**: ~400,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

IObit Surfing Protection is a security extension that provides malicious website detection, ad blocking, and browser fingerprint protection. The extension utilizes native messaging to communicate with a local application (`com.ascplugin.protect`) that performs the actual URL scanning and threat detection. While the extension's stated purpose is legitimate, the architecture introduces opacity concerns as all scanning decisions and potential data transmission occur in the native host application, which is outside the browser's security sandbox and cannot be audited through the extension code alone.

The extension implements legitimate anti-fingerprinting features by injecting noise into Canvas, WebGL, and AudioContext APIs to prevent tracking. However, the heavy reliance on native messaging for core functionality means that the security guarantees depend entirely on the trustworthiness of the companion desktop software.

## Vulnerability Details

### 1. MEDIUM: Native Messaging Without Transparency
**Severity**: MEDIUM
**Files**: Plugin/background.js, adblock/js/background.js
**CWE**: CWE-925 (Improper Verification of Intent by Broadcast Receiver)
**Description**: The extension uses native messaging to communicate with `com.ascplugin.protect`, sending all visited URLs to the native host for scanning. While this architecture is necessary for the extension's stated purpose, it creates a trust boundary issue where user browsing data is transmitted to a native application that cannot be audited through the extension code.

**Evidence**:
```javascript
// adblock/js/background.js:7
var port = chrome.runtime.connectNative(hostname);

// Plugin/background.js:452
port.postMessage({ CMD: "Scan", ScanURL: details.url, ScanType: 2, tabid: details.id });

// Plugin/background.js:473
port.postMessage({ CMD: "Scan", ScanURL: request.ScanURL, ScanType: 2, tabid: tabId });
```

All URL scanning is delegated to the native host:
```javascript
// adblock/js/background.js:590-593
else if (msg.input.CMD == 'Scan') {
    var tabid = msg.input.tabid;
    var ScanResult = msg.result;
```

**Verdict**: The extension sends browsing URLs to a native application for security scanning. This is expected behavior for a security tool, but creates a medium-level privacy concern because the native host's behavior cannot be verified from the extension code alone. Users must trust both the extension and the IObit desktop software.

### 2. MEDIUM: Broad Content Script Injection on All Sites
**Severity**: MEDIUM
**Files**: manifest.json, Plugin/Ex.js, Plugin/FingerPrint.js
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension injects content scripts on `<all_urls>` with `run_at: document_start`, giving it early access to all web pages. While necessary for the security and ad-blocking features, this represents a broad attack surface.

**Evidence**:
```json
"content_scripts": [
    {
        "all_frames": true,
        "js": [
            "Plugin/Ex.js",
            "Plugin/FingerPrint.js",
            "adblock/content/ewe-content.js"
        ],
        "matches": ["*://*/*"],
        "run_at": "document_start"
    }
]
```

The content scripts inject UI elements into search results and fingerprint protection code:
```javascript
// Plugin/Ex.js - modifies search engine results pages (Google, Bing, Baidu, etc.)
// Plugin/FingerPrint.js - injects anti-fingerprinting code
```

**Verdict**: The broad content script permissions are consistent with the extension's stated purpose (protecting users on all sites), but they provide the technical capability to monitor all browsing activity. This is mitigated by the fact that the extension appears to use these capabilities only for security features.

### 3. LOW: Code Injection via Web Accessible Resources
**Severity**: LOW
**Files**: Plugin/FingerPrint.js, Plugin/Test.js
**CWE**: CWE-94 (Improper Control of Generation of Code)
**Description**: The extension injects JavaScript code into web pages through a web-accessible resource to implement fingerprint protection. While the purpose is legitimate, this pattern can potentially be exploited by malicious websites.

**Evidence**:
```javascript
// Plugin/FingerPrint.js:6-15
function overrideMethods() {
    var script = document.createElement("script");
    script.id = 'iobit_Finger_Print';
    script.src = chrome.runtime.getURL("Plugin/Test.js");
    script.onload = function () {
        this.remove();
    };
    (document.head || document.documentElement).appendChild(script);
    script.remove();
}
```

Plugin/Test.js modifies Canvas, WebGL, and Audio APIs:
```javascript
// Plugin/Test.js:90-156 - Canvas fingerprint protection
inject_canvas(prefix);
inject_audio(prefix);
inject_webgl(prefix);
```

**Verdict**: The code injection is used for anti-fingerprinting protection, which is a legitimate security feature. The injected code modifies browser APIs to add random noise, preventing tracking. This is a standard technique used by privacy extensions and does not represent a security vulnerability in this context.

## False Positives Analysis

The static analyzer flagged the extension as "obfuscated," but upon review, the code appears to use standard minification and bundling (webpack) rather than malicious obfuscation. The extension's core functionality involves:

1. **Native Messaging**: Expected for a security tool that needs desktop integration
2. **Search Engine Result Modification**: The extension adds safety icons next to search results, which is a documented feature
3. **Fingerprint Protection**: The API overrides (Canvas, WebGL, Audio) are defensive measures to prevent tracking
4. **Ad Blocking**: Standard declarativeNetRequest usage for content blocking

These patterns are consistent with the extension's advertised purpose as a security and privacy tool.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| Native Host (com.ascplugin.protect) | URL scanning, threat detection | Visited URLs, email addresses, links | Medium - depends on native app trustworthiness |

**Note**: The extension does not make direct HTTP requests. All network communication is delegated to the native host application, which means the actual endpoints contacted cannot be determined from the extension code alone.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

IObit Surfing Protection is a legitimate security extension from a known software vendor (IObit), but it operates using a native messaging architecture that inherently requires users to trust both the extension and the companion desktop software. The extension itself does not contain malicious code, but the design creates opacity around data handling:

**Positive Factors**:
- Published by IObit, an established security software company
- Implements genuine anti-fingerprinting protection
- No direct evidence of data exfiltration in extension code
- Features match advertised functionality (threat protection, ad blocking)
- Uses standard APIs appropriately

**Risk Factors**:
- All browsing URLs are sent to native application for scanning
- Native application behavior cannot be audited from extension code
- Broad permissions (nativeMessaging, <all_urls>, scripting)
- 400,000 users depend on the trustworthiness of the desktop software

**Rating: MEDIUM** because while the extension appears to function as advertised, the native messaging architecture means that security guarantees depend on trusting software outside the browser sandbox. Users should be aware that their browsing activity is shared with IObit's desktop application for security scanning purposes.
