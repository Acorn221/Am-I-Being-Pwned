# Vulnerability Report: Squarespace ID Finder

## Metadata
- **Extension ID**: igjamfnifnkmecjidfbdipieoaeghcff
- **Extension Name**: Squarespace ID Finder
- **Version**: 0.0.8
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Squarespace ID Finder is a legitimate developer utility extension designed to help web developers and designers identify CSS selectors and element IDs on Squarespace websites. The extension injects a visual overlay that displays collection, section, and block IDs, allowing users to copy these selectors for use in custom code or styling.

After thorough analysis of the codebase, including static analysis with ext-analyzer and manual review of all JavaScript files, no security or privacy concerns were identified. The extension operates entirely locally within the browser, does not make any external network requests, does not collect or transmit user data, and functions exactly as advertised in its description.

## Vulnerability Details

No vulnerabilities identified.

## False Positives Analysis

### Host Permission `<all_urls>`
The extension requires `<all_urls>` host permission to inject its ID finder UI into Squarespace websites. This is appropriate for its stated functionality as a developer tool. The permission is only used when the user explicitly clicks the extension icon on a Squarespace page.

### Code Injection via `chrome.scripting.executeScript`
The extension uses `chrome.scripting.executeScript` to inject `inject.js` into the active tab when clicked. This is the standard and appropriate method for browser extensions to interact with web pages. The injected code:
- Only runs when explicitly triggered by user action (clicking the extension icon)
- Creates visual overlays to display element IDs
- Provides copy-to-clipboard functionality for CSS selectors
- Does not modify page functionality or exfiltrate data

### `document.execCommand('copy')`
The extension uses the deprecated `document.execCommand('copy')` API to copy selectors to the clipboard. While this API is deprecated in favor of the Clipboard API, it poses no security risk and is used appropriately for its intended functionality of copying CSS selectors.

### Access to iframes
The code accesses Squarespace's preview iframe (`iframe#sqs-site-frame`) when working in the Squarespace editor environment. This is necessary functionality to display IDs in both the editor preview and live sites.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| None | N/A | N/A | N/A |

No external API endpoints are contacted by this extension. All functionality is local.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:
This extension is a legitimate developer tool with no security or privacy concerns. Key findings:

1. **No data exfiltration**: The extension makes zero network requests and does not collect, store, or transmit any user data.

2. **Appropriate permissions**: The `scripting` permission and `<all_urls>` host permission are necessary and properly scoped for the extension's stated purpose.

3. **User-initiated actions only**: All functionality requires explicit user interaction (clicking the extension icon).

4. **Transparent functionality**: The extension does exactly what it advertises - it displays Squarespace element IDs to help developers write custom code.

5. **Clean code**: The JavaScript is well-structured, readable, and contains no obfuscation, eval statements, or suspicious patterns.

6. **No third-party dependencies**: All code is contained within the extension with no external libraries or scripts loaded.

7. **Legitimate use case**: This is a genuine developer productivity tool published by a known Squarespace developer (will-myers.com).

The ext-analyzer flagged the extension as "obfuscated" but this is a false positive - the code is cleanly formatted and easily readable. There are no actual security findings.
