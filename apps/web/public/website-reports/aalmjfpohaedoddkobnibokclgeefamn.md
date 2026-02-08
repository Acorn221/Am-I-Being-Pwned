# Vulnerability Report: Gumbo: Twitch Companion

## Metadata
- **Extension ID**: aalmjfpohaedoddkobnibokclgeefamn
- **Extension Name**: Gumbo: Twitch Companion
- **Version**: 1.21.2
- **User Count**: ~20,000
- **Developer**: seldszar (https://gumbo.seldszar.fr)
- **Analysis Date**: 2026-02-07

## Executive Summary

Gumbo: Twitch Companion is a legitimate Chrome extension designed to help users track their followed Twitch streams and receive notifications when channels go live. The extension uses the official Twitch API with OAuth2 authentication and operates as intended.

**Overall Risk Assessment**: CLEAN

The extension demonstrates good security practices with minimal permissions, no content script injection, proper OAuth flow implementation, and transparent data handling. No malicious behavior, vulnerabilities, or privacy concerns were identified.

## Vulnerability Details

### No Critical or High Severity Issues Found

After comprehensive analysis of the extension's manifest, background scripts, and API interactions, no security vulnerabilities or malicious behavior patterns were detected.

## Security Analysis

### 1. Permissions Analysis
**Manifest Permissions:**
- `alarms` - Used for periodic stream status checks (1-minute intervals)
- `notifications` - Desktop notifications for live streams
- `storage` - Local storage for settings and cached data

**Host Permissions:**
- `https://gumbo.seldszar.fr/*` - OAuth callback URL only

**Assessment**: Minimal permissions model. No broad host permissions, no content script injection, no cookie access, no webRequest interception.

### 2. API Endpoint Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://api.twitch.tv/helix/* | Twitch API queries | OAuth token, user ID filters | LOW - Official API |
| https://id.twitch.tv/oauth2/authorize | OAuth authorization | Client ID, scopes, redirect URI | LOW - Standard OAuth |
| https://id.twitch.tv/oauth2/validate | Token validation | Bearer token | LOW - Token health check |
| https://id.twitch.tv/oauth2/revoke | Token revocation | Client ID, token | LOW - Logout flow |

**Client ID**: `f2s32e14j29t0onam56mfhqgfnl9na` (Twitch-registered public client)

### 3. Authentication Flow
- **Method**: OAuth2 implicit grant flow
- **Scope**: `user:read:follows` (read-only access to followed channels)
- **Storage**: Access tokens stored in `chrome.storage.local`
- **Validation**: Automatic token validation with re-authorization on expiry
- **Revocation**: Proper logout implementation with token revocation

**Verdict**: Secure OAuth implementation following Twitch's documented practices.

### 4. Data Flow Summary

**Data Collection:**
- User's Twitch access token (stored locally)
- List of followed streams (cached in session storage)
- User preferences (notification settings, UI preferences, muted channels)

**Data Transmission:**
- All external requests go to official Twitch API endpoints
- No third-party analytics or tracking services detected
- No data sent to developer's servers beyond OAuth callback

**Data Storage:**
- Local storage: Settings, collections, access tokens, muted users
- Session storage: Current user info, followed streams cache
- No sensitive data exposed

### 5. Background Script Behavior

**Key Functions:**
- `eg()` - Refresh function runs every 1 minute via chrome.alarms
- `Q()` - Fetches followed streams from Twitch API
- `er()` - Filters streams for notifications based on user preferences
- `eo()` - Creates desktop notifications for new live streams

**Network Calls:**
- All fetch() calls restricted to Twitch API domains
- Proper error handling and rate limiting via pagination
- No dynamic code execution or eval() usage

**Verdict**: Clean background script behavior with no suspicious patterns.

### 6. Content Security Policy
No CSP explicitly defined in manifest, which is acceptable for MV3 extensions that don't inject content scripts. The extension operates entirely through popup UI and background service worker.

### 7. Code Quality
- Modern JavaScript (ES6+)
- Uses browser extension polyfill for cross-browser compatibility
- Bundled with rspack 1.3.12
- Minified but deobfuscated cleanly
- No obfuscation or code hiding techniques detected

## False Positive Analysis

| Pattern | Location | Explanation | Verdict |
|---------|----------|-------------|---------|
| WebExtension Polyfill | background.js:1-857 | Standard Mozilla webextension-polyfill library for cross-browser compatibility | Known Library - Safe |
| Proxy objects | background.js:712-748 | Polyfill uses Proxy for API wrapping - not data interception | Known Pattern - Safe |
| Storage access | Multiple locations | Legitimate use of chrome.storage for user settings and cache | Intended Functionality |
| Tab creation/update | background.js:1208-1222 | Opens Twitch URLs when user clicks notifications/stream links | Intended Functionality |

## Overall Risk Assessment

**Risk Level**: CLEAN

**Justification**:
1. **Minimal Attack Surface**: No content scripts, no broad permissions, no external scripts
2. **Transparent Functionality**: All features align with stated purpose (Twitch companion)
3. **Privacy-Respecting**: No telemetry, no third-party tracking, no unnecessary data collection
4. **Secure Authentication**: Proper OAuth2 implementation with token validation
5. **No Malicious Patterns**: No cookie stealing, no proxy behavior, no credential harvesting
6. **Open Source Spirit**: Clean, readable code with references to GitHub repository
7. **Good Development Practices**: Modern tooling, proper error handling, logical code structure

## Recommendations

None. The extension follows Chrome Web Store best practices and demonstrates exemplary security hygiene for its category.

## Additional Notes

- Extension appears to be open source (references to github.com/seldszar/gumbo in code comments)
- Supports internationalization (14 locales)
- Donation links present but optional (PayPal, Coinbase)
- No premium features or monetization that would incentivize data collection
- Developer domain: seldszar.fr

## Conclusion

Gumbo: Twitch Companion is a well-designed, security-conscious browser extension that fulfills its stated purpose without compromising user privacy or security. It serves as a good example of how extensions should handle API authentication and user data.
