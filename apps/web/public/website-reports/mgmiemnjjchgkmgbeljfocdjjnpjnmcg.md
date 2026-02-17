# Vulnerability Report: Awesome New Tab Page

## Metadata
- **Extension ID**: mgmiemnjjchgkmgbeljfocdjjnpjnmcg
- **Extension Name**: Awesome New Tab Page
- **Version**: 2025.415.73
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Awesome New Tab Page (ANTP) is a legitimate browser extension that replaces Chrome's default new tab page with a customizable interface featuring widgets, shortcuts, and apps. The extension communicates with official ANTP API endpoints (api.antp.co and static.antp.co) to fetch default configurations and third-party widget listings. The code is well-structured, uses standard Angular framework patterns, and does not exhibit malicious behavior.

The extension requests broad permissions including `<all_urls>`, `management`, and `tabs`, which are appropriate for its functionality as a new tab page replacement that manages Chrome apps and displays favicons. Data handling is limited to local storage for user configurations, with no evidence of undisclosed data collection or exfiltration. The only security concerns are minor CSP weaknesses in sandboxed contexts and the inherent risks of loading external iframe widgets.

## Vulnerability Details

### 1. LOW: Weak Content Security Policy in Sandbox
**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-1021 (Improper Restriction of Rendered UI Layers or Frames)
**Description**: The extension's sandbox CSP allows `unsafe-eval` and `unsafe-inline`, which could enable code execution vulnerabilities if the sandboxed context is compromised. However, this is limited to the sandbox environment and does not affect the main extension pages.

**Evidence**:
```json
"content_security_policy": {
  "extension_pages": "script-src 'self'; object-src 'self';",
  "sandbox": "sandbox allow-scripts allow-forms allow-popups allow-modals; script-src 'self' 'unsafe-inline' 'unsafe-eval'; child-src 'self';"
}
```

**Verdict**: This is a minor configuration issue. The main extension pages have a strict CSP. The sandbox policy is weaker but sandboxed contexts are isolated by design.

### 2. LOW: Third-Party Widget Loading via iframes
**Severity**: LOW
**Files**: extension/javascript/angular/antp.js, main-KVOWN43Q.js
**CWE**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
**Description**: The extension loads third-party widgets from external sources via iframes using the Penpal library for cross-frame communication. While this is the intended functionality, it introduces potential risks if widget sources are compromised.

**Evidence**:
```javascript
// From antp.js line 389
$http({
  method: 'GET',
  url: `https://api.antp.co/widgets?extensionVersion=${_getChromeVersion()}`
}).then(function (response) {
  $.each(response.data, function (index, widget) {
    widget.id = widget.uuid;
    widget.external = true;
    external_widgets[widget.uuid] = widget;
  })
})
```

**Verdict**: This is expected behavior for a widget platform. The extension only loads widgets from the official api.antp.co API and uses Penpal for secure cross-frame communication with origin validation. Users explicitly choose which widgets to add.

## False Positives Analysis

1. **Broad Permissions (<all_urls>, management, tabs)**: These permissions appear excessive at first glance but are necessary for the extension's core functionality:
   - `<all_urls>` is required to access `chrome://favicon/` URLs for displaying website favicons on shortcuts
   - `management` is needed to enumerate and launch Chrome apps displayed on the new tab page
   - `tabs` is required for creating/updating tabs when users click shortcuts

2. **External API Communication**: The extension communicates with api.antp.co and static.antp.co, which are the official ANTP service domains. This is disclosed functionality for fetching default configurations and widget metadata.

3. **Dynamic Code Patterns**: Angular framework code and RxJS library code contain patterns that look like dynamic code execution, but these are standard framework implementations, not malicious obfuscation.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.antp.co/defaults/v1/antp | Fetch default tile configuration | Extension version | Low - Read-only configuration |
| api.antp.co/widgets | Fetch available third-party widgets | Extension version, browser type | Low - Widget catalog listing |
| static.antp.co/widgets/* | Load widget HTML/resources | None | Low - Static content CDN |
| static.antp.co/shortcuts/* | Load shortcut images | None | Low - Static images |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

Awesome New Tab Page is a legitimate extension with appropriate permissions for its stated functionality. The extension does not collect or exfiltrate user data beyond what is necessary for its operation. All external communication is with official ANTP infrastructure for configuration and widget loading.

The minor security concerns identified (weak sandbox CSP and external widget loading) are inherent to the extension's design as a customizable widget platform and do not pose significant risks to users. The extension uses modern framework patterns (Angular, RxJS), proper storage APIs (chrome.storage.local), and secure cross-frame communication (Penpal with origin validation).

The code quality is professional, includes proper copyright notices, and shows no signs of malicious intent or undisclosed functionality. The extension has been around since at least 2011 (based on copyright notices) and appears to be actively maintained with a recent version number (2025.415.73).
