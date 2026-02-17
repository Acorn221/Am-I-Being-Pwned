# Vulnerability Report: JoinNow MultiOS

## Metadata
- **Extension ID**: makojehmiedfbnephoffkknopflhddbc
- **Extension Name**: JoinNow MultiOS
- **Version**: 2.8.1.4
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

JoinNow MultiOS is a legitimate enterprise WiFi onboarding extension by SecureW2 designed for Chromebook deployment. The extension helps users configure WiFi network settings, particularly for WPA-EAP/TLS authentication in enterprise and educational environments. While it serves a legitimate purpose, it collects extensive device information (MAC address, IP address, Chrome version, OS details, device ID) and transmits this data to service.securew2.com for telemetry/reporting purposes. The extension also has postMessage handlers without origin validation, which could allow malicious web pages to trigger unauthorized actions.

The primary privacy concern is that device information collection occurs automatically when reporting is enabled by the organization, without explicit per-user consent displayed in the UI. However, this is a business/enterprise tool where the IT administrator controls the configuration, making this data collection behavior expected for this category of extension.

## Vulnerability Details

### 1. MEDIUM: Extensive Device Fingerprinting and Telemetry

**Severity**: MEDIUM
**Files**: background.js (lines 1169-1341), contentscript.js (lines 511-574)
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**:
The extension collects comprehensive device information including MAC address, IP address, Chrome version, OS version, device ID (SHA1 hash of MAC + random padding), browser language, and user descriptions. This data is sent to `https://service.securew2.com/PaladinServlet/Report` when reporting is enabled in the organization's configuration.

**Evidence**:
```javascript
// background.js lines 1279-1341
function reportingJSON(reportUserDescription) {
    var report = {};
    report.type = "deviceReport";
    report.source = "device";

    var dev = {};
    dev.clientId = getLocalStorage("deviceId");
    dev.applicationFriendlyName = "JoinNow for Chrome";
    dev.applicationVersion = chrome.manifest.version;
    dev.buildModel = getOperatingSystem();
    dev.operatingSystem = getOperatingSystem();
    dev.osVersion = chrome_version;
    dev.osFriendlyName = osFriendlyName;
    dev.osBuild = buildVersion;

    if (reportUserDescription) {
        dev.userDescription = reportUserDescription;
    }

    if (mac !== null && mac !== "") {
        var adapters = {};
        var wirelessAdapters = [];
        var wirelessAdapter = {};
        wirelessAdapter.macAddress = mac;  // MAC address collected
        wirelessAdapter.name = "wlan0";
        wirelessAdapter.description = "wlan0";
        wirelessAdapters.push(wirelessAdapter);
        adapters.wireless = wirelessAdapters;
        dev.adapters = adapters;
    }

    if (reportIP) {
        report.ipAddress = ip;  // IP address collected
    }

    var configInfo = {}
    configInfo.organizationId = org;
    configInfo.deviceConfigId = parseInt(devconfigId);
    configInfo.profileId = profileUUID;

    report.configInfo = configInfo;
    report.device = dev;

    var reportString = JSON.stringify(report);
    fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        },
        body: reportString
    })
}

// Device ID generation (line 1575-1580)
if (getLocalStorage("deviceId") == null) {
    var randomPadding = forge.random.getBytes(32);
    var md = forge.md.sha1.create();
    md.update(mac + randomPadding);
    var deviceId = md.digest().toHex();
    setLocalStorage("deviceId", deviceId);
}
```

**Verdict**:
This is MEDIUM severity rather than HIGH because:
1. The extension's stated purpose is enterprise network onboarding, where IT telemetry is expected
2. Reporting is controlled by organization configuration, not automatic for all users
3. The data is sent to the legitimate SecureW2 service (service.securew2.com)
4. This is standard behavior for enterprise network management tools

However, it remains a privacy concern because individual users aren't explicitly informed about what data is collected.

### 2. MEDIUM: postMessage Handlers Without Origin Validation

**Severity**: MEDIUM
**Files**: forge.bundle.js (lines 3246, 10209), forge/prime.worker.js (line 18)
**CWE**: CWE-346 (Origin Validation Error)

**Description**:
The extension uses the Forge cryptography library which registers multiple `window.addEventListener("message")` handlers without validating the origin of incoming messages. This could allow malicious web pages to send crafted messages to trigger unintended behavior.

**Evidence**:
From ext-analyzer output:
```
[HIGH] window.addEventListener("message") without origin check    forge.bundle.js:3246
[HIGH] window.addEventListener("message") without origin check    forge.bundle.js:10209
[HIGH] window.addEventListener("message") without origin check    forge/prime.worker.js:18
```

**Verdict**:
This is MEDIUM severity because:
1. The vulnerable handlers are in the Forge cryptography library, not custom extension code
2. The Forge library is widely used and these handlers are for web worker communication
3. Content script injection on all URLs means any malicious page could potentially send messages
4. However, exploitation would require understanding the specific message format expected by Forge

This is a design weakness but not necessarily exploitable for serious attacks without significant reverse engineering.

### 3. LOW: Content Security Policy Allows WASM Evaluation

**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-1188 (Insecure Default Initialization of Resource)

**Description**:
The extension's CSP includes `'wasm-unsafe-eval'` which allows WebAssembly code compilation. While this enables legitimate WASM functionality, it also expands the attack surface.

**Evidence**:
```json
"content_security_policy":{
    "extension_pages": "script-src 'self' 'wasm-unsafe-eval' ; object-src 'self'"
}
```

**Verdict**:
This is LOW severity because:
1. WASM execution is restricted to extension pages, not arbitrary code
2. The extension uses the Forge cryptography library which may require WASM for performance
3. No actual WASM files were found in the extension
4. `'wasm-unsafe-eval'` is less dangerous than `'unsafe-eval'` and is commonly needed for crypto libraries

## False Positives Analysis

1. **Obfuscation Flag**: The ext-analyzer flagged the extension as "obfuscated," but this is actually the bundled Forge.js cryptography library (28,227 lines). This is a legitimate, well-known open-source library, not intentional obfuscation.

2. **Broad Host Permissions**: The extension requires `http://*/*` and `https://*/*` permissions, which appears excessive. However, this is necessary because the extension must inject configuration capabilities into the organization's landing pages across different domains for WiFi onboarding.

3. **Downloads Permission**: The extension downloads `.onc` (Open Network Configuration) files for ChromeOS network setup. This is the standard mechanism for configuring enterprise WiFi on ChromeOS devices.

4. **PageCapture Permission**: Used to capture chrome://net-internals and chrome://system pages to verify network configuration status and extract system information. This is necessary for automated ChromeOS network setup.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| service.securew2.com | Primary backend for WiFi enrollment and certificate signing | User credentials, device attributes (MAC, IP, OS version, device ID), CSR for certificate enrollment | MEDIUM - Contains PII but necessary for service function |
| service.securew2.com/PaladinServlet/Report | Telemetry/reporting endpoint | Device fingerprint data (MAC, IP, Chrome version, OS details, organization ID) | MEDIUM - Extensive device data collection for analytics |
| service.securew2.com/PaladinServlet/Main | Configuration reporting | Error codes, device configuration status | LOW - Diagnostic data only |
| [Organization-configured connector URL] | Certificate enrollment endpoint | CSR (Certificate Signing Request), username, password challenges | MEDIUM - Handles authentication credentials |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
JoinNow MultiOS is a legitimate enterprise tool for WiFi network onboarding on ChromeOS devices. The extension collects extensive device information (MAC address, IP address, system details) and sends it to SecureW2's servers, which represents a privacy concern. However, this behavior is expected and disclosed for enterprise network management tools where IT administrators deploy and configure the extension.

The key concerns are:
1. **Device fingerprinting and telemetry** without per-user consent (MEDIUM severity)
2. **PostMessage handlers without origin validation** in the Forge library (MEDIUM severity)
3. **Broad permissions** necessary for its function but increase attack surface (LOW severity)

The extension is NOT malware. It's a commercially available enterprise product by SecureW2 (a recognized vendor in the WiFi security space). Organizations deploying this extension should be aware that it collects device telemetry and ensure this is disclosed in their privacy policies.

**Recommendation**: Organizations using this extension should:
- Inform users about the device data collection
- Review the reporting configuration to minimize unnecessary data transmission
- Ensure the data collection complies with privacy regulations (GDPR, CCPA, etc.)
- Consider the privacy implications of MAC address and IP address collection
