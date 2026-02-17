# Vulnerability Report: Microsoft Bing Homepage

## Metadata
- **Extension ID**: obkbegmlhbcannjaipgolkppiccljkof
- **Extension Name**: Microsoft Bing Homepage
- **Version**: 0.0.0.10
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Microsoft Bing Homepage is an official Microsoft extension that sets Bing as the user's homepage and startup page. The extension collects basic telemetry data (extension version, browser version, OS, language, machine ID) and sends it to Microsoft's telemetry endpoint (g.ceipmsn.com). It also manages tracking cookies for affiliate attribution purposes.

The extension is legitimate and performs functions consistent with its stated purpose. The telemetry collection is standard practice for enterprise software, though not explicitly disclosed in the Chrome Web Store description. There are no critical security vulnerabilities or malicious behaviors.

## Vulnerability Details

### 1. LOW: Undisclosed Telemetry Collection

**Severity**: LOW
**Files**: ping.js (lines 219-249)
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension collects and transmits telemetry data to Microsoft servers without explicit disclosure in the extension description. The data includes:
- Machine ID (randomly generated GUID)
- Extension ID and version
- Browser version
- Operating system
- Browser language
- Channel and PC tracking codes

**Evidence**:
```javascript
function SendPingDetails(status, pc, channel, dpc, machineId) {
    var OS = navigator.userAgent.substring(startIndex + 1, endIndex).replace(/\s/g, '');
    var browserLanguage = navigator.language;
    var ExtensionVersion = manifestData.version;
    var BrowserVersion = navigator.userAgent.substr(navigator.userAgent.indexOf("Chrome")).split(" ")[0].replace("/", "");

    var pingURL = 'http://g.ceipmsn.com/8SE/44?';
    var tVData = 'TV=is' + _pc + '|pk' + ExtensionName + '|tm' + browserLanguage + '|bv' + BrowserVersion + '|ex' + ExtensionId + '|es' + status;

    pingURL = pingURL + 'MI=' + machineId + '&LV=' + ExtensionVersion + '&OS=' + OS + '&TE=37&' + tVData;
    fetch(pingURL);
}
```

**Verdict**: While not explicitly disclosed, this telemetry is standard for Microsoft products and falls under their broader privacy policy. The data collected is not personally identifiable and is used for product improvement. This is a minor transparency issue rather than a security vulnerability.

## False Positives Analysis

Several patterns that might appear suspicious are actually legitimate for this extension:

1. **Cookie manipulation**: The extension reads and removes PCCode and channel cookies from browserdefaults.microsoft.com, then stores them in local storage. This is legitimate affiliate tracking, not malicious cookie harvesting.

2. **`chrome.management` permission**: Used only to detect when the extension is enabled/disabled, not for malicious extension enumeration.

3. **Uninstall URL tracking**: Sets a feedback URL when the extension is uninstalled, including the machine ID. This is standard practice for collecting uninstall feedback.

4. **Daily pings**: The extension sends daily activity pings to track active installations. This is standard telemetry for enterprise software.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| http://g.ceipmsn.com/8SE/44 | Telemetry endpoint | Machine ID, extension version, browser version, OS, language, channel codes | Low - Standard Microsoft telemetry |
| https://www.bing.com | Homepage redirect | PC tracking code in URL parameter | Low - Affiliate tracking |
| https://browserdefaults.microsoft.com | Tracking cookie source | None sent, cookies read | Low - Legitimate tracking |
| https://go.microsoft.com/fwlink/?linkid=2138838 | Uninstall feedback | Extension ID, market, machine ID, browser | Low - Feedback collection |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**: This is a legitimate Microsoft extension that performs its stated function (setting Bing as homepage) without any malicious behavior. The telemetry collection is standard for Microsoft products, though it could be more transparently disclosed. The extension uses appropriate permissions and does not access sensitive user data beyond basic browser metadata. The affiliate tracking through PC codes is a normal business practice for homepage/search extensions. No security vulnerabilities were identified that would put users at risk.
