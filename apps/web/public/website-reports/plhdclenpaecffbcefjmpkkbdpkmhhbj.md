# Vulnerability Report: Discrub

## Metadata
- **Extension ID**: plhdclenpaecffbcefjmpkkbdpkmhhbj
- **Extension Name**: Discrub
- **Version**: 1.12.11
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Discrub is a Discord data manipulation and export tool that enables users to mass edit, delete, filter, and export Discord messages in multiple formats (HTML, CSV, JSON). The extension is open-source and developed by prathercc with active maintenance on GitHub.

While the extension serves a legitimate utility purpose for Discord power users, it employs authentication token extraction techniques that represent a security concern. The extension accesses Discord authentication tokens from localStorage by creating a hidden iframe and reading the token from the page's storage context. This technique, while necessary for the extension's functionality, represents a medium-severity privacy concern as it handles sensitive authentication credentials.

## Vulnerability Details

### 1. MEDIUM: Discord Authentication Token Extraction

**Severity**: MEDIUM
**Files**: assets/content.js-1273dc67.js
**CWE**: CWE-522 (Insufficiently Protected Credentials)

**Description**:
The extension extracts Discord authentication tokens from browser localStorage using an iframe-based technique. When the extension receives a "GET_TOKEN" message, it creates a hidden iframe, accesses the iframe's contentWindow.localStorage, and retrieves the Discord token stored there.

**Evidence**:
```javascript
case "GET_TOKEN":
  window.dispatchEvent(new Event("beforeunload"));
  const r = document.body.appendChild(document.createElement("iframe")).contentWindow.localStorage;
  return r.token ? o(JSON.parse(r.token)) : o(null), !0
```

The code:
1. Dispatches a "beforeunload" event (likely to ensure token persistence)
2. Creates an iframe appended to the document body
3. Accesses the iframe's localStorage to read the token
4. Returns the parsed token value or null

**Verdict**:
This is EXPECTED behavior for a Discord data manipulation tool - the extension requires authentication to perform its stated functions (editing, deleting, exporting messages). However, token extraction always represents elevated risk as these credentials provide full account access. The extension is open-source and has been actively maintained since its release, with positive user reviews (4.5/5 with 220+ reviews), suggesting legitimate intent.

**Risk Assessment**: MEDIUM - Token extraction is necessary for functionality but represents inherent security risk. Users should understand they are granting full Discord account access.

## False Positives Analysis

### Bundled React Framework Code
The extension uses a modern React-based build system (Vite) with significant bundled dependencies including:
- React and React DOM
- Material-UI date pickers
- Service worker utilities

The large main.js file (2.1MB) contains minified React framework code, not obfuscated malware. Lines flagged for "password" and "localStorage" in bundled React libraries are framework utilities, not malicious code.

### CDN Discord Fetch Calls
The ext-analyzer flagged multiple fetch() calls to cdn.discordapp.com as potential exfiltration. These are LEGITIMATE API calls to Discord's official CDN for:
- Loading user avatars and media
- Fetching message attachments
- Standard Discord API operations

These endpoints are expected for any Discord-integrated tool.

### Service Worker Download Mechanism
The service worker (background.js) implements a client-side file download system using ReadableStream and MessageChannel. This is a standard pattern for browser extensions implementing download functionality without server storage, not data exfiltration.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| cdn.discordapp.com | Discord CDN for avatars, attachments | Standard Discord API requests with auth token | Low - Official Discord endpoint |
| www.w3.org | SVG/web standards resources | None (resource loading) | None - Standard web resources |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
Discrub is a legitimate, open-source Discord utility with transparent functionality. The token extraction technique is necessary for the extension's stated purpose of managing Discord messages. However, several factors warrant a MEDIUM risk classification:

1. **Token Access**: Direct extraction of Discord authentication tokens represents inherent security risk, as these credentials provide full account access
2. **Broad Permissions**: The extension operates on all discord.com pages with content script injection
3. **User Awareness**: Users may not fully understand they are granting complete Discord account access
4. **Attack Surface**: If the extension were compromised or maliciously modified in the future, it would have complete access to user Discord accounts

**Recommendation**:
This extension is appropriate for technical users who understand the security implications of granting token access. The open-source nature and active maintenance reduce but do not eliminate risks. Users should:
- Verify they're installing from official sources (Chrome Web Store, GitHub)
- Understand the extension has full Discord account access
- Monitor the extension's permissions and update history
- Consider revoking access when not actively using the tool

The extension is NOT malware, but represents elevated privilege access that users should consciously accept.
