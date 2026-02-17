# Vulnerability Report: YouTube Auto HD + FPS

## Metadata
- **Extension ID**: fcphghnknhkimeagdglkljinmpbagone
- **Extension Name**: YouTube Auto HD + FPS
- **Version**: 1.13.5
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

YouTube Auto HD + FPS is a legitimate browser extension that automatically sets video quality on YouTube based on frame rate (FPS). The extension is open-source (GitHub: avi12/youtube-auto-hd), well-maintained, and verified by Google. After comprehensive analysis of both static code analysis and manual review, no security or privacy concerns were identified. The extension operates entirely within YouTube's domain, uses minimal permissions appropriately, and does not collect, transmit, or exfiltrate any user data.

The extension uses the `cookies` permission solely to read YouTube's `wide` cookie to detect the user's current theater mode preference (cinema vs default view) for the auto-resize feature. This is a legitimate use case with no privacy implications.

## Vulnerability Details

No vulnerabilities were identified in this extension.

## False Positives Analysis

### Cookie Access
The static analyzer flagged the extension for accessing `document.cookie` in the resize content script. Investigation reveals this is a false positive:
- **Location**: `content-scripts/resize.js` line 677
- **Code**: `const r = document.cookie.match(/wide=([10])/);`
- **Purpose**: Reads YouTube's native `wide` cookie to detect current view mode (0=default, 1=cinema)
- **Verdict**: Legitimate functionality. The extension reads this single first-party YouTube cookie to determine if the user has manually toggled theater mode, allowing it to sync the auto-resize feature with user preferences. No cookies are sent to external domains.

### Obfuscation Flag
The static analyzer marked the extension as "obfuscated." This is a false positive:
- The code is minified/bundled using modern JavaScript build tools (WXT framework with Vite)
- All variable names follow predictable patterns from webpack/rollup bundling
- No actual obfuscation techniques are present (no string encoding, control flow flattening, etc.)
- The extension is verified by Google with confirmed source code hashes

### Storage API Usage
The extension extensively uses Chrome's `storage` API (sync, local, session areas) to persist user preferences:
- Quality settings per frame rate (30/50/60 FPS)
- Auto-resize preferences
- Enhanced bitrate toggles
- Super resolution preferences
- All storage is local to the user's browser; no data is transmitted externally

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| None | N/A | N/A | None |

**Analysis**: The extension makes zero external network requests. All URLs found in the code are either:
- Static documentation links (GitHub repo, browser extension stores, PayPal donation)
- YouTube domain URLs (legitimate host permissions)
- Svelte framework error documentation URLs (never executed in production)

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:
This extension exemplifies best practices for browser extension development:

1. **Minimal Permissions**: Only requests `cookies` and `storage` permissions, both used appropriately
2. **Scoped Host Permissions**: Restricted to YouTube domains only
3. **No Data Exfiltration**: Zero external network requests; all functionality is client-side
4. **Open Source**: Publicly auditable code on GitHub
5. **Google Verified**: Extension has valid verified_contents.json signature
6. **Manifest V3**: Uses modern security model with service worker
7. **Legitimate Functionality**: All code serves the stated purpose of quality/FPS management
8. **No Dynamic Code**: No use of eval(), Function(), or chrome.scripting.executeScript
9. **Appropriate Cookie Usage**: Single first-party cookie read for legitimate UX feature

The extension contains zero security vulnerabilities and zero privacy concerns. Users can install this extension with confidence.
