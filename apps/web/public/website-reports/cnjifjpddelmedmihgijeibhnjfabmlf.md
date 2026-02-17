# Vulnerability Report: Obsidian Web Clipper

## Metadata
- **Extension ID**: cnjifjpddelmedmihgijeibhnjfabmlf
- **Extension Name**: Obsidian Web Clipper
- **Version**: 0.12.0
- **Users**: ~300,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Obsidian Web Clipper is the official web clipping extension for Obsidian.md, a popular note-taking application. The extension allows users to save web content, highlights, and screenshots to their local Obsidian vaults using the `obsidian://` protocol.

After thorough analysis using static analysis tools and manual code review, this extension appears to be CLEAN with no significant security or privacy concerns. The extension operates entirely locally, communicating only with the user's local Obsidian application via the obsidian:// protocol handler. It does not make any external network requests or collect user data. The broad permissions requested (activeTab, scripting, <all_urls>) are legitimately required for its core functionality of extracting and processing web page content.

## Vulnerability Details

### No Critical or High Vulnerabilities Found

The static analysis revealed no exfiltration flows, no code execution vulnerabilities, and no attack surface issues beyond the intended functionality. The ext-analyzer tool reported "No suspicious findings."

## False Positives Analysis

### 1. Broad Host Permissions (<all_urls>)
**Why it looks suspicious**: The extension requests access to all URLs which is often a red flag.

**Why it's legitimate**: As a web clipper, the extension needs to extract content from any website the user visits. This is core to its functionality - users can clip content from any webpage they're viewing. The extension uses content scripts to extract page content, which requires the broad host permissions.

### 2. Content Script Injection
**Why it looks suspicious**: The extension dynamically injects content scripts and executes scripts on pages.

**Why it's legitimate**: The extension needs to inject scripts to:
- Extract page content for clipping
- Enable the highlighter feature for marking text
- Toggle reader mode for better content extraction
- Provide the embedded iframe interface

All script injection is tied to user-initiated actions (clicking the extension icon, using context menus, or keyboard shortcuts).

### 3. Scripting Permission
**Why it looks suspicious**: The `scripting` permission allows arbitrary code execution.

**Why it's legitimate**: Used exclusively for injecting the extension's own scripts (content.js, reader-script.js) to enable clipping functionality. No dynamic code generation or eval usage was found outside of the browser polyfill library.

### 4. Web-Accessible Resources
**Why it looks suspicious**: Several resources are exposed as web-accessible with extension_ids: "*".

**Why it's legitimate**: The resources (reader.css, reader-script.js, browser-polyfill.min.js, style.css, side-panel.html) are needed for the extension's UI components like the reader mode overlay and side panel. Making them web-accessible allows content scripts to load these resources.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| obsidian://advanced-uri (local protocol) | Opens Obsidian app locally | Clipped content, page metadata | None - Local only |
| https://obsidian.md/ | Homepage URL in manifest | None | None - No requests made |
| https://clients2.google.com/service/update2/crx | Chrome Web Store updates | None (standard Chrome update mechanism) | None |

**Note**: The extension makes NO network requests to external servers. All communication is with the user's local Obsidian application via the obsidian:// protocol handler.

## Privacy Analysis

### Data Collection: NONE
The extension does not collect, transmit, or store any user data externally. All data processing happens locally:
- Web page content is extracted locally
- Highlights are stored in chrome.storage.local
- Settings are stored in chrome.storage.local
- Clipped content is sent directly to the local Obsidian application

### Storage Usage
The extension uses `chrome.storage.local` to store:
- User preferences and settings
- Template configurations
- Highlight data
- Usage statistics (stored locally only)

This is appropriate and privacy-preserving.

## Code Quality Analysis

### Positive Findings:
1. **Modern Manifest V3**: Uses the latest manifest version with appropriate security policies
2. **Content Security Policy**: Properly configured CSP with `script-src 'self'; object-src 'self'`
3. **No eval() or Function() constructor**: Apart from the browser polyfill, no dynamic code execution
4. **Local-First Architecture**: All data stays on the user's device
5. **Open Source**: The extension appears to be built from open-source code (webpack bundled)
6. **Well-Structured Code**: Clear separation between background, content, and UI scripts

### Minor Observations:
1. **Large Bundle Size**: The bundled JavaScript files are quite large (popup.js: 1.5MB, reader-script.js: 1.7MB, settings.js: 1.2MB). This is typical for modern webpack-bundled applications but could be optimized.
2. **ext-analyzer "obfuscated" flag**: The tool flagged the code as obfuscated, but this appears to be webpack minification/bundling, not intentional obfuscation for malicious purposes.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:
The Obsidian Web Clipper is a legitimate, well-designed browser extension that operates entirely locally with no privacy or security concerns. The extension:

1. Makes no external network requests
2. Does not collect or transmit user data
3. Uses all requested permissions appropriately for its stated functionality
4. Implements proper security measures (CSP, MV3)
5. Has transparent operation - all clipped content goes directly to the user's local Obsidian application
6. Is published by the official Obsidian team (homepage_url: https://obsidian.md/)

The broad permissions are legitimately required for a web clipping tool, and the extension uses them responsibly. This is a safe extension for users to install, particularly those already using the Obsidian note-taking application.

**Recommendation**: No action needed. This extension can be safely used.
