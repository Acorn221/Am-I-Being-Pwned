# Vulnerability Report: FortiDLP Browser Extension

## Metadata
- **Extension ID**: gbojkjpincgojijodbnliimgeggnomai
- **Extension Name**: FortiDLP Browser Extension
- **Version**: 3.5.6
- **Users**: ~400,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

FortiDLP Browser Extension is an enterprise data loss prevention (DLP) tool developed by Fortinet that monitors web-based activities to protect against insider threats. The extension intercepts and reports browsing behavior, file uploads, clipboard operations, credentials, storage changes, downloads, and navigation events to a native messaging host (local agent). While the extension's surveillance capabilities are extensive and align with its disclosed enterprise security purpose, the implementation contains two medium-severity security issues: missing origin validation on postMessage handlers and extensive cookie tracking capabilities.

The extension operates as expected for an enterprise DLP solution with disclosed monitoring purposes. However, organizations deploying this tool should be aware of the attack surface created by the missing origin checks and ensure proper endpoint security controls are in place.

## Vulnerability Details

### 1. MEDIUM: Missing Origin Validation on postMessage Handlers

**Severity**: MEDIUM
**Files**: upload_injected.js, upload_element_creation.js
**CWE**: CWE-346 (Origin Validation Error)

**Description**:
The extension uses `window.addEventListener("message")` without validating the origin of incoming messages. While the code does check that `e.source === window` and `e.origin === window.location.origin` for some message types, the static analyzer flagged two instances where origin validation may be insufficient or missing for certain message types.

**Evidence**:
```javascript
// upload_injected.js line 1
window.addEventListener("message", handler)

// upload_element_creation.js line 1
window.addEventListener("message", handler)
```

From content_script.js:
```javascript
const z=e=>{
  e.source===window&&e.origin===window.location.origin&&
  ("fortiDlpFirefoxReplayLoaded"===e.data.type&&(e.stopImmediatePropagation(),
   e.preventDefault(),P.firefoxReplayLoaded=!0),
  "fortiDlpWebkitPatchLoaded"===e.data.type&&(e.stopImmediatePropagation(),
   e.preventDefault(),P.webkitGetAsEntryPatchLoaded=!0))
}
```

**Verdict**:
While the code does implement origin checks for most message types, the attack surface exists if any message type is processed before validation. An attacker-controlled page could potentially send crafted messages to interfere with the extension's upload monitoring or file access tracking mechanisms. This is a standard vulnerability pattern in extensions that use postMessage for communication between content scripts and page context.

### 2. MEDIUM: Extensive Cookie Access and Tracking

**Severity**: MEDIUM
**Files**: background.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**:
The extension has extensive cookie manipulation capabilities, including reading, setting, and tracking cookies across all domains. It uses cookies to maintain tracking IDs (`__reveal_ut`) and profile IDs (`__reveal_pt`) for monitoring user activity. While this is disclosed functionality for a DLP tool, it creates significant privacy implications.

**Evidence**:
```javascript
const y="__reveal_ut",I="__reveal_pt",k="https://reveal.nextdlp.com/plugin/browser/profile"
```

The extension:
- Sets tracking cookies with 90-day expiration (`expirationDate:Math.floor(Date.now()/1e3)+7776e3`)
- Prevents deletion of tracking cookies by re-creating them when removed
- Maintains cookie overrides per tab to bypass standard cookie policies
- Monitors all cookie stores including incognito mode

**Verdict**:
This is expected behavior for an enterprise DLP solution, but organizations should be aware that this extension has complete visibility into all cookie data across all websites. The tracking cookies persist across sessions and are automatically restored if deleted. This is disclosed in the extension description ("security analytics to protect against web-based insider threats"), but the scope is extensive.

## False Positives Analysis

The static analyzer flagged the extension as "obfuscated," but this is webpack-bundled production code, not malicious obfuscation. The minified code is standard for modern JavaScript applications and does not indicate intent to hide malicious behavior.

The extension's extensive monitoring of clipboard, passwords, file uploads, and navigation is not a vulnerability—it's the core functionality of a DLP tool. These capabilities are disclosed in the description and are necessary for the extension's stated purpose.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://reveal.nextdlp.com/plugin/browser/profile | Profile cookie management | Profile tracking ID | LOW - Expected DLP functionality |
| Native Messaging Host (com.jazznetworks.browserextension) | Local agent communication | All monitored events (browsing, uploads, clipboard, credentials, etc.) | LOW - Enterprise deployment with local agent |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
FortiDLP Browser Extension is a legitimate enterprise DLP tool with disclosed surveillance capabilities. The MEDIUM risk rating is based on two factors:

1. **Missing Origin Validation (MEDIUM)**: The postMessage handlers create an attack surface that could potentially be exploited by malicious web pages to interfere with upload monitoring or inject crafted events. While the code does implement origin checks, the pattern flagged by the static analyzer suggests potential edge cases where validation may be bypassed.

2. **Extensive Cookie Tracking (MEDIUM)**: The extension has complete access to all cookies across all domains and implements persistent tracking mechanisms. While disclosed and expected for a DLP tool, this creates significant privacy implications and requires organizational trust.

The extension operates within its disclosed purpose of monitoring web-based activities for enterprise security. The low user rating (1.1) likely reflects user dissatisfaction with workplace monitoring rather than security concerns. Organizations deploying this extension should:
- Ensure proper disclosure to employees
- Verify the security of the local native messaging host
- Implement network security controls to protect data sent to reveal.nextdlp.com
- Consider the privacy implications of comprehensive activity monitoring

The extension is NOT malware and does NOT exhibit hidden data exfiltration. All monitoring capabilities align with the stated enterprise DLP purpose.
