# Gyazo Extension Security Analysis

## Metadata
- **Extension Name**: Gyazo - Share new screenshots. Instantly.
- **Extension ID**: ffdaeeijbbijklfcpahbghahojgfgebo
- **User Count**: ~100,000
- **Analysis Date**: 2026-02-07
- **Version Analyzed**: 5.16.0

## Executive Summary

Gyazo is a screenshot capture and sharing extension developed by Helpfeel Inc. The extension provides legitimate functionality for capturing screenshots (full page, visible area, selected elements) and uploading them to the Gyazo service. The code quality is professional with proper error handling and OAuth2 authentication flow.

**Key Finding**: The extension embeds OAuth2 client credentials (client_id and client_secret) directly in the client-side code, which is a **security anti-pattern** but common in browser extensions. However, analysis indicates this is the legitimate Gyazo extension with no evidence of malicious behavior.

**Overall Risk Assessment**: LOW

The extension operates as advertised with no evidence of data exfiltration, privacy violations, or malicious functionality beyond the security concern of embedded credentials.

## Vulnerability Details

### 1. OAuth2 Client Secret Exposure in Client-Side Code
**Severity**: MEDIUM
**File**: `main.js` (lines 427-428)
**Code**:
```javascript
body: JSON.stringify({
  client_id: "qdHa0zMPj-m8lJ6Xz1zjN9NKVv7ZX8nIUt8wfWvd0cQ",
  client_secret: "EsoxWFqiDzCLRcqCTQjX7Kxd-VGIMKel0QPe_fwtR3c",
  redirect_uri: "https://gyazo.com/oauth/onboarding/extension",
  grant_type: "authorization_code",
  code: e
})
```

**Description**: The OAuth2 client secret is hardcoded in the extension's background script. In OAuth2 best practices, client secrets should only be used in confidential clients (server-side applications), not public clients like browser extensions.

**Impact**:
- An attacker could extract these credentials and potentially abuse the Gyazo API
- However, the OAuth flow still requires user authorization, limiting the attack surface
- The secret is scoped to the extension's redirect URI, which provides some protection

**Verdict**: **ACCEPTED RISK** - This is a common pattern in browser extensions due to architectural constraints. The risk is mitigated by:
1. OAuth redirect URI validation
2. User authorization requirement
3. Access tokens stored locally (not the secret itself being used directly)
4. This appears to be the official Gyazo extension

### 2. Broad Host Permissions
**Severity**: LOW
**File**: `manifest.json`
**Code**:
```json
"host_permissions": ["<all_urls>"]
```

**Description**: The extension requests access to all websites to enable screenshot capture functionality on any page.

**Impact**: This is necessary for the extension's core functionality (capturing screenshots on any website).

**Verdict**: **LEGITIMATE** - Required for screenshot capture across all sites. The extension only uses scripting APIs for screenshot functionality, not for data collection.

## False Positive Analysis

| Pattern | Location | Explanation |
|---------|----------|-------------|
| `innerHTML` usage | `sidePanel/contextMenu.ts` | Used for legitimate UI rendering (copy button SVG icon) |
| Browser polyfill code | `main.js`, `content.js` | Standard webextension-polyfill library for cross-browser compatibility |
| `chrome.scripting.executeScript` | `main.js` (lines 1835, 1905) | Used to inject content script for screenshot capture, necessary functionality |
| OAuth client credentials | `main.js` (lines 427-428) | Standard pattern for browser extensions (see vulnerability #1) |

## API Endpoints & Data Flow

| Endpoint | Purpose | Data Sent | Authentication |
|----------|---------|-----------|----------------|
| `https://api.gyazo.com/oauth/token` | OAuth2 token exchange | Authorization code | Client credentials |
| `https://api.gyazo.com/api/users/me` | User profile check | Access token | Bearer token |
| `https://upload.gyazo.com/api/v2/upload` | Screenshot upload | Image blob, metadata, access token | Bearer token |
| `https://gyazo.com/user/teams` | Team management | None (GET request) | Session cookies |
| `https://api.gyazo.com/api/images` | Fetch user's screenshots | Access token, pagination params | Bearer token |

**Data Flow Summary**:
1. User authenticates via OAuth2 flow (redirects to gyazo.com)
2. Extension receives authorization code, exchanges for access token
3. Access token stored in `chrome.storage.sync` or `chrome.storage.local`
4. Screenshots captured using `chrome.tabs.captureVisibleTab` API
5. Images uploaded to Gyazo servers with user's access token
6. No third-party analytics, tracking, or data exfiltration detected

## Permissions Analysis

**Declared Permissions**:
- `activeTab`: For capturing current tab screenshots
- `contextMenus`: Right-click menu integration
- `storage`: Storing access tokens and user preferences
- `scripting`: Injecting content scripts for UI overlays
- `offscreen`: Clipboard operations in MV3
- `sidePanel`: Side panel UI for recent screenshots

**Optional Permissions**:
- `clipboardWrite`: Copy screenshot URLs to clipboard

**Assessment**: All permissions are justified and used for advertised functionality. No excessive or suspicious permissions.

## Content Security Policy

The manifest does not define a custom CSP, defaulting to the Manifest V3 standard CSP which is secure.

## Code Quality & Obfuscation

- Code is minified/bundled but not maliciously obfuscated
- Uses standard webpack/build tooling
- Readable function/variable names after deobfuscation
- Proper error handling throughout
- No eval() or dynamic code execution detected

## Third-Party Dependencies

- **webextension-polyfill**: Browser API compatibility layer (legitimate)
- **Bowser**: User-agent detection library (legitimate)
- No suspicious third-party SDKs or trackers detected

## Overall Risk Assessment

**Risk Level**: **LOW**

**Rationale**:
1. **Legitimate Functionality**: Extension performs exactly as advertised - screenshot capture and upload to Gyazo
2. **No Malicious Patterns**: No evidence of data theft, credential harvesting, or unauthorized API calls
3. **Proper Authentication**: Uses standard OAuth2 flow with user consent
4. **Minimal Attack Surface**: Only communicates with Gyazo's own APIs
5. **Clean Data Flow**: Screenshots only uploaded with user action, no background data collection
6. **Professional Code Quality**: Well-structured, error-handled code consistent with legitimate software

**Concerns (Non-Critical)**:
- Embedded OAuth client secret (industry-standard pattern for extensions, but not ideal)
- Broad host permissions (necessary for functionality)

**Recommendation**: **CLEAN** - This extension is safe for general use. It's the legitimate Gyazo screenshot tool with no malicious behavior detected.
