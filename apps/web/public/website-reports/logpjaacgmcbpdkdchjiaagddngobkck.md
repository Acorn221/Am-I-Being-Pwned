# Vulnerability Report: Shortkeys (Custom Keyboard Shortcuts)

## Metadata
- **Extension ID**: logpjaacgmcbpdkdchjiaagddngobkck
- **Extension Name**: Shortkeys (Custom Keyboard Shortcuts)
- **Version**: 4.1.4
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Shortkeys is a keyboard shortcut customization extension that allows users to create custom keyboard shortcuts for common browser actions (tab management, navigation, scrolling, etc.). The extension has extensive permissions to support its wide range of functionalities, but analysis reveals no security or privacy concerns. The static analyzer flagged a false positive where the "searchgoogle" action (which creates Google search URLs from selected text) was incorrectly identified as data exfiltration. All code is clean, well-structured, and operates within the documented scope of the extension.

## Vulnerability Details

No vulnerabilities were identified during the analysis.

## False Positives Analysis

### Static Analyzer Flag: "chrome.storage.local.get → fetch(www.google.com)"

The ext-analyzer flagged a HIGH severity exfiltration flow, but this is a false positive. The flow represents the "searchgoogle" action which:

1. Retrieves stored keyboard shortcut configurations from `chrome.storage.local`
2. When triggered, gets the user's selected text via `window.getSelection()`
3. Creates a Google search URL: `https://www.google.com/search?q={encodeURIComponent(selectedText)}`
4. Opens this URL in a new tab

**Evidence from service_worker.js (lines 276-290):**
```javascript
else if ("searchgoogle" === e) t((() => window.getSelection().toString())).then((function(e) {
  const t = e[0].result;
  if (t) {
    let e = encodeURIComponent(t);
    h.tabs.query({currentWindow: !0, active: !0}).then((function(t) {
      h.tabs.create({
        url: "https://www.google.com/search?q=" + e,
        index: t[0].index + 1
      })
    }))
  }
}));
```

This is not data exfiltration - it's the documented "Search Google for selected text" feature (visible in manifest.json command "26-searchgoogle"). No `fetch()` call actually occurs; the URL is opened in a browser tab via `tabs.create()`.

### Obfuscation Flag

The static analyzer flagged the code as obfuscated, but this is standard webpack/minification bundling. The deobfuscated code shows:
- Clean variable names and logic flow
- Standard libraries (Mousetrap for keyboard handling, UUID generation)
- No attempts to hide malicious behavior
- Readable business logic for all 50+ keyboard shortcuts

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://www.google.com/search | Google search via user-triggered action | User-selected text (only when user explicitly triggers "searchgoogle" shortcut) | NONE - Standard browser navigation |
| https://clients2.google.com/service/update2/crx | Chrome Web Store auto-update | N/A (browser-managed) | NONE - Standard update mechanism |

## Permission Analysis

All permissions are justified for the extension's functionality:

- **downloads, browsingData**: Clear downloads functionality
- **storage**: Store user's custom keyboard shortcut configurations
- **tabs**: Tab management (switch, close, create, move, duplicate, etc.)
- **clipboardWrite**: "Copy URL" shortcut
- **bookmarks**: Open bookmarks via shortcuts
- **sessions**: Reopen closed tabs
- **management**: Launch apps via shortcuts
- **debugger**: Screenshot capture functionality (uses debugger API to capture full-page screenshots)
- **scripting**: Execute scroll/navigation commands in page context
- **userScripts**: Register custom JavaScript actions defined by user
- **host_permissions (*://*/*)**: Required to inject content scripts for keyboard shortcuts on all sites
- **activeTab**: Page interaction for shortcuts

## Code Quality Assessment

**Positive indicators:**
- Uses standard libraries (Mousetrap for keyboard handling)
- Proper event-driven architecture
- All actions map to documented commands in manifest.json
- CSP is reasonably configured (only 'unsafe-inline' for styles from CDNs)
- Site blacklist/whitelist filtering for per-site shortcut customization
- No remote code execution beyond user-defined JavaScript shortcuts (stored locally, user-controlled)

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**: This extension performs exactly as advertised - it provides customizable keyboard shortcuts for browser actions. All permissions are necessary and appropriately used. The static analyzer flag was a false positive from misinterpreting the "searchgoogle" feature. No data collection, no exfiltration, no malicious behavior detected. The extension is well-designed, properly scoped, and poses no security or privacy risks to users.
