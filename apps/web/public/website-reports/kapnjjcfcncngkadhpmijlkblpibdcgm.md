# Vulnerability Report: Viewport Resizer: Ultimate Device Emulator & Website Testing Tool

## Metadata
- **Extension ID**: kapnjjcfcncngkadhpmijlkblpibdcgm
- **Extension Name**: Viewport Resizer: Ultimate Device Emulator & Website Testing Tool
- **Version**: 2.0.4
- **Users**: ~80,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Viewport Resizer is a legitimate developer tool designed to emulate different device viewports for responsive web design testing. The extension modifies HTTP response headers to remove Content Security Policy (CSP) and X-Frame-Options headers, which is necessary for its core functionality of embedding websites in test frames. While this behavior could weaken page security protections, it is done in a controlled manner only on tabs where the user explicitly activates the extension, and serves the stated purpose of the tool.

The extension shows no evidence of malicious data exfiltration, credential harvesting, or unauthorized data collection. The single external endpoint (github.com) is used for loading configuration presets, which is a legitimate feature for a developer tool. The static analyzer flagged an exfiltration flow to www.w3.org, but this is a false positive - it's merely an SVG namespace declaration in inline SVG icons, not an actual network request.

## Vulnerability Details

### 1. MEDIUM: Security Header Removal via declarativeNetRequest

**Severity**: MEDIUM
**Files**: background.js
**CWE**: CWE-693 (Protection Mechanism Failure)

**Description**: The extension uses declarativeNetRequest to strip CSP and X-Frame-Options headers from web pages. This is done to allow the extension to embed target websites in iframes for viewport testing purposes.

**Evidence**:
```javascript
// background.js lines 44-47
responseHeaders: [
  { header: "x-frame-options", operation: "remove" },
  { header: "content-security-policy", operation: "remove" }
]
```

The extension creates dynamic rules that apply to the origin of the active tab:
```javascript
// background.js lines 38-55
const tabUrl = new URL((await chrome.tabs.get(activeTabId)).url).origin + '/*';
const rule = {
  id: customRuleId,
  priority: 1,
  action: {
    type: "modifyHeaders",
    responseHeaders: [
      { header: "x-frame-options", operation: "remove" },
      { header: "content-security-policy", operation: "remove" }
    ],
    requestHeaders: requestHeaders
  },
  condition: {
    resourceTypes: ["main_frame", "sub_frame"],
    urlFilter: tabUrl,
    isUrlFilterCaseSensitive: false
  }
};
```

**Verdict**: This behavior is **expected and necessary** for a viewport testing tool. The extension:
- Only activates when the user explicitly clicks the extension icon
- Only affects the specific tab where it's activated (tracked via activeTabId)
- Properly cleans up rules when deactivated
- Saves state to allow restoration after browser restart
- Displays a badge to indicate when active

The security risk is mitigated by:
1. User consent - the tool only activates on explicit user action
2. Limited scope - only affects tabs where the user chooses to test
3. Transparency - badge indicator shows when the extension is active
4. Clean state management - rules are removed when the extension is closed

## False Positives Analysis

### Static Analyzer Exfiltration Flag
The ext-analyzer reported: `document.getElementById → fetch(www.w3.org)` as an exfiltration flow. This is a **false positive**. The www.w3.org references are SVG namespace declarations in inline SVG markup for UI icons, not actual network requests:

```javascript
D = '<svg xmlns="http://www.w3.org/2000/svg" height="24px" viewBox="0 -960 960 960" width="24px">...</svg>'
```

These are standard XML namespace declarations required by SVG specification and do not result in any network traffic.

### Obfuscation Flag
The ext-analyzer flagged the extension as "obfuscated." This appears to be webpack-bundled code (lib/responsive-toolbar.esm.js is 10,567 lines), which is standard for modern JavaScript applications. The code uses regenerator runtime for async/await transpilation, which creates generator-based state machines that may appear obfuscated but are actually standard build output.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| github.com/responsive-toolbar/config-presets | Device configuration presets | None (read-only link) | LOW |

The GitHub URL is only used as a hyperlink in the settings panel to invite users to contribute device presets. No automated requests are made to this endpoint.

The fetch() function in the code (lines 7732-7737) is a generic HTTP client utility that accepts URLs as parameters. There is no evidence of hardcoded external API calls for data exfiltration.

## Privacy Assessment

**Data Collection**: None observed
**Storage Usage**: The extension stores:
- User configuration preferences (device presets, appearance settings)
- Active tab ID (for state restoration)

No sensitive user data, browsing history, cookies, or credentials are accessed or transmitted.

## Permissions Justification

| Permission | Justification | Risk |
|------------|---------------|------|
| activeTab | Required to inject content script and modify headers on user-activated tab | Appropriate |
| scripting | Required to inject viewport testing UI into target pages | Appropriate |
| declarativeNetRequest | Required to remove CSP/X-Frame-Options for iframe embedding | Appropriate |
| storage | Required to save user preferences and restore state | Appropriate |
| host_permissions: <all_urls> | Broad but necessary - users may test any website | Appropriate |

All permissions are justified by the extension's stated purpose as a web developer testing tool.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
While the extension modifies security-critical HTTP headers (CSP and X-Frame-Options), this behavior is:
1. Necessary for its legitimate function as a viewport testing tool
2. Limited in scope to user-activated tabs
3. Transparent with clear UI indicators
4. Not used for malicious purposes

The MEDIUM rating reflects that the extension does weaken security protections, but in a controlled, user-initiated manner for a legitimate developer tool purpose. This is similar to other developer tools like browser DevTools which also bypass certain security mechanisms.

**Recommendation**: Safe for use by web developers who understand the security implications. Users should ensure they only activate the extension on trusted websites during testing.
