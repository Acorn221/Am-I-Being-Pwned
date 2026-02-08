# Xodo | PDF Editor, Converter & Merger - Security Analysis Report

## Extension Metadata

- **Extension Name**: Xodo | PDF Editor, Converter & Merger
- **Extension ID**: lpkaodjnpmklkcjlchephbdfoaeliohm
- **Version**: 1.8
- **User Count**: ~40,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-08

## Executive Summary

Xodo PDF Editor is an extremely minimal Chrome extension that functions solely as a launcher for the Xodo web-based PDF tools. The extension contains **zero** malicious code, tracking mechanisms, or security vulnerabilities. It consists of a single popup interface with buttons that redirect users to https://xodo.com services.

**Key Findings:**
- No background scripts, content scripts, or service workers
- No network requests made by the extension code
- No permissions requested beyond basic extension functionality
- No data collection, tracking, or analytics
- No obfuscated code
- No external dependencies or third-party libraries
- Code is trivial and fully transparent

**Overall Risk Assessment**: CLEAN

This extension is a straightforward browser UI wrapper around the Xodo web platform with no security concerns.

## Manifest Analysis

### Permissions & CSP

**Requested Permissions**: NONE

The manifest.json declares:
- No `permissions` array
- No `host_permissions`
- No `optional_permissions`
- No custom Content Security Policy

**Web Accessible Resources**:
```json
"web_accessible_resources": [{
  "resources": ["/images/icon.png"],
  "matches": ["<all_urls>"]
}]
```

This only exposes a single icon image file and is standard practice for extension icons.

**Action Configuration**:
- Default popup: `popup.html`
- No background/service worker declared
- No content scripts

### Manifest Security Verdict

✅ **CLEAN** - Minimal manifest with no concerning permissions or configurations.

## Code Analysis

### popup.js (53 lines)

The extension contains only a single JavaScript file with two functions:

**1. MacOS Secondary Monitor Workaround (lines 6-37)**
```javascript
// Detects secondary monitor on macOS and applies CSS animation workaround
if (window.screenLeft < 0 || window.screenTop < 0 || ...) {
  chrome.runtime.getPlatformInfo(function (info) {
    if (info.os === 'mac') {
      // Apply CSS animation to fix Chrome rendering bug
    }
  })
}
```

This is a well-documented workaround for Chromium bug #971701 affecting popup redraws on secondary monitors. Source referenced: https://stackoverflow.com/questions/57484619/chrome-extension-input-lags

**2. Navigation Links (lines 39-52)**
```javascript
const links = [
  {key: 'crop-pdf', url: 'https://xodo.com/crop-pdf?e=1'},
  {key: 'pdf-to-word', url: 'https://xodo.com/pdf-to-word-converter?e=1'},
  {key: 'pdf-to-pdfa', url: 'https://xodo.com/pdf-to-pdfa?e=1'},
  {key: 'merge-pdf', url: 'https://xodo.com/merge-pdf?e=1'},
  {key: 'view-edit-pdf', url: 'https://xodo.com/pdf-editor?e=1'},
  {key: 'more-tools', url: 'https://xodo.com/tools?e=1'}
];

for (const link of links) {
  document.getElementById(link.key).addEventListener('click', () => {
    chrome.tabs.create({ url: link.url });
  });
}
```

Simple event listeners that open Xodo web tools in new tabs when buttons are clicked. The `?e=1` query parameter likely indicates traffic came from the extension (for analytics on Xodo's website, not in the extension).

### Chrome API Usage

The extension uses only 2 Chrome APIs:
1. `chrome.runtime.getPlatformInfo()` - Detect OS type for UI workaround
2. `chrome.tabs.create()` - Open new tabs with URLs

Both are harmless and require no special permissions in MV3.

### popup.html (45 lines)

Standard HTML with button elements linking to:
- Crop PDF
- PDF to Word
- PDF to PDF/A
- Merge PDF
- View and Edit PDF
- More tools link

No inline scripts, no embedded tracking pixels, no third-party resources.

## Threat Assessment

### Extension Enumeration/Killing
❌ NOT PRESENT - No code attempts to detect or interfere with other extensions

### XHR/Fetch Hooking
❌ NOT PRESENT - No network request code whatsoever

### Residential Proxy Infrastructure
❌ NOT PRESENT - No proxy or network traffic manipulation

### Remote Config/Kill Switches
❌ NOT PRESENT - Extension is entirely static with hardcoded URLs

### Market Intelligence SDKs
❌ NOT PRESENT - No analytics libraries (Sensor Tower, Pathmatics, etc.)

### AI Conversation Scraping
❌ NOT PRESENT - No content scripts to access page data

### Ad/Coupon Injection
❌ NOT PRESENT - No content scripts

### Data Exfiltration
❌ NOT PRESENT - No network requests or data collection

### Obfuscation
❌ NOT PRESENT - Code is plain, readable JavaScript

### Dynamic Code Execution
❌ NOT PRESENT - No `eval()`, `Function()`, or dynamic imports

## Additional Files Review

### polaris.yml
Synopsys Polaris configuration file for static analysis scanning. Indicates the developer uses professional security scanning tools (Coverity). Server: `pdftron.polaris.synopsys.com`

PDFTron (now Apryse) is the parent company of Xodo, which explains this configuration.

### README.md
Developer notes about manifest version decisions. States they're using MV3 but notes previous challenges with MV2 to MV3 migration related to PDF handling in browser tabs.

## False Positives

| Pattern | Context | Verdict |
|---------|---------|---------|
| CSS animation injection | MacOS secondary monitor workaround | ✅ Legitimate bug fix |
| Query parameters (?e=1) | Extension traffic identifier for web analytics | ✅ Benign tracking parameter |

## API Endpoints

| Domain | Purpose | Data Sent | Risk |
|--------|---------|-----------|------|
| xodo.com | PDF web tools destination | None (browser navigates) | ✅ Clean |

The extension doesn't make any API calls itself - it simply opens web pages.

## Data Flow Analysis

```
User clicks button in popup
    ↓
popup.js event listener fires
    ↓
chrome.tabs.create() opens xodo.com URL
    ↓
Browser navigates to Xodo website
    ↓
(Extension involvement ends)
```

**Data Collected by Extension**: NONE

**Data Transmitted by Extension**: NONE

All data processing happens on xodo.com after the user is redirected, which is outside the extension's scope.

## Invasiveness Assessment

The extension requests zero permissions and has no access to:
- User browsing history
- User data on websites
- Cookies
- Downloads
- Bookmarks
- Tabs content
- Network requests

It is functionally equivalent to a browser bookmark toolbar - just a UI launcher.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification:**
This extension is a minimal browser UI wrapper with no security concerns. It serves its stated purpose (providing quick access to Xodo PDF tools) without requesting unnecessary permissions, collecting data, or exhibiting any malicious behavior patterns.

The extension is architecturally equivalent to a "New Tab" bookmarks page - it simply provides clickable links to web services. The fact that it's packaged as an extension (rather than just telling users to bookmark the website) provides minimal added value but is not malicious.

**Developer Trust Indicators:**
- Uses Synopsys Coverity static analysis
- Clean, well-documented code with bug fix references
- Affiliated with PDFTron/Apryse (legitimate PDF software company)
- Transparent functionality matching description

## Recommendations

**For Users:**
- Extension is safe to use
- Be aware that clicking buttons opens xodo.com web pages where standard web privacy policies apply
- Extension itself provides no functionality beyond navigation

**For Developers:**
- Consider whether this extension is necessary vs. browser bookmarks
- The `?e=1` parameter suggests Xodo tracks extension-originated traffic on their website

## Conclusion

Xodo PDF Editor extension poses no security risk. It is one of the cleanest extensions analyzed - containing minimal code with no permissions, no data collection, and no attack surface. The extension serves as a simple launcher for legitimate web-based PDF tools.

**FINAL VERDICT: CLEAN**
