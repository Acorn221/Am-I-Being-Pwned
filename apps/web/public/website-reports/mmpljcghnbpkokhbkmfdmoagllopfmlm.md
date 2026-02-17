# Vulnerability Report: Allow Copy - Select & Enable Right Click

## Metadata
- **Extension ID**: mmpljcghnbpkokhbkmfdmoagllopfmlm
- **Extension Name**: Allow Copy - Select & Enable Right Click
- **Version**: 1.1.9
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

"Allow Copy - Select & Enable Right Click" is a legitimate utility extension designed to bypass website copy-protection mechanisms and enable right-click context menus on protected websites. The extension uses standard DOM manipulation techniques to remove event listeners that prevent text selection and copying.

Analysis of the codebase reveals no security or privacy concerns. The extension operates entirely locally through DOM manipulation and does not collect, transmit, or exfiltrate any user data. The single network call identified by static analysis is a benign prefetch operation for module loading. The extension functions exactly as advertised with no hidden functionality.

## Vulnerability Details

No vulnerabilities were identified in this extension.

## False Positives Analysis

### 1. Static Analyzer "Exfiltration" Finding
The static analyzer flagged one exfiltration flow: `document.querySelectorAll → fetch` in `popup.js`.

**Analysis**: This is a false positive. The code in question (lines 27-50 of popup.js) implements a browser-native module preload optimization:

```javascript
for (const o of document.querySelectorAll('link[rel="modulepreload"]')) r(o);
// ...
function r(o) {
  if (o.ep) return;
  o.ep = !0;
  const i = n(o);
  fetch(o.href, i)  // Fetching module resources from same origin
}
```

This is a standard Vite build tool pattern that prefetches JavaScript modules to improve performance. The `fetch()` calls retrieve local module files from the extension's own resources, not external data exfiltration.

### 2. Obfuscation Flag
The static analyzer flagged the extension as "obfuscated." However, examination reveals this is standard webpack/React bundling with minified library code (React, ReactDOM, Lodash). The core functionality code (lines 11437-11499 in contentScript.js) is clearly readable and implements straightforward DOM manipulation.

## Core Functionality Analysis

The extension's primary logic (function `hy()` starting at line 11437 of contentScript.js) performs the following operations:

1. **Event Handler Removal**: Clears inline event handlers (`onselectstart`, `oncopy`, `oncontextmenu`, etc.) from document elements
2. **CSS Override**: Applies `user-select: text !important` styles to enable text selection
3. **Event Listener Installation**: Adds event listeners that prevent propagation, effectively neutralizing anti-copy scripts
4. **jQuery Cleanup**: If jQuery is present, removes jQuery-bound copy-protection handlers

These operations are completely local and align with the extension's stated purpose.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| chrome.google.com/webstore/detail/ | Opens Chrome Web Store page when user clicks "Rate" button | Extension ID only | None - user-initiated action |

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:
This extension is a legitimate utility tool with no security or privacy concerns. It:

- Contains no data exfiltration code
- Makes no unauthorized network requests
- Does not access sensitive user data beyond what's necessary for DOM manipulation
- Functions transparently as advertised
- Uses appropriate manifest v3 permissions (storage for settings, tabs for detecting active tab)
- Employs standard web development practices (React, module bundling)

The host permissions (`https://*/*`, `http://*/*`) are necessary for the content script to run on all websites where users want to bypass copy protection, which is the core purpose of the extension.

All flagged findings from static analysis are false positives resulting from standard build tooling patterns. The extension poses no risk to users.
