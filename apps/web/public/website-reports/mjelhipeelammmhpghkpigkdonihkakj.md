# GCalPlus Security Analysis Report

## Metadata
- **Extension Name**: GCalPlus
- **Extension ID**: mjelhipeelammmhpghkpigkdonihkakj
- **Version**: 3.0.13
- **User Count**: ~60,000 users
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

GCalPlus is a legitimate Google Calendar enhancement extension that provides additional customization options for Google Calendar's web interface. The extension implements OAuth2 authentication to access Google Calendar APIs and adds UI enhancements like busy date highlighting, weekend coloring, event copying, calendar switching, and transparency toggling.

**Overall Assessment**: The extension demonstrates **CLEAN** security posture with standard Google Calendar API integration patterns. All network requests are directed to legitimate Google endpoints, and the extension follows proper OAuth2 authentication flows. No malicious behavior, data exfiltration, or suspicious third-party integrations were detected.

## Security Findings

### API Endpoints Analysis

| Endpoint | Purpose | Risk Level |
|----------|---------|------------|
| `https://www.googleapis.com/calendar/v3/*` | Google Calendar API operations (read/write events, calendars, settings) | BENIGN |
| `https://accounts.google.com/o/oauth2/*` | OAuth2 authentication and token management | BENIGN |
| `https://www.gcaltools.com` | Developer website link (opened in popup.js) | BENIGN |

All network requests are exclusively to Google's official APIs. No third-party tracking, analytics, or data collection services detected.

### Permissions Analysis

**Declared Permissions**:
- `scripting` - Used to inject CSS for UI customization (weekend colors, borders)
- `activeTab` - Access to the active Google Calendar tab
- `storage` - Store user preferences and cached calendar data
- `identity` - OAuth2 authentication with Google
- `webNavigation` - Clear calendar cache on page reload
- `declarativeContent` - Enable extension only on calendar.google.com

**Host Permissions**:
- `https://www.googleapis.com/*` - Google Calendar API
- `https://calendar.google.com/calendar` - Content script injection
- `https://accounts.google.com/o/oauth2/v2/auth` - OAuth2 flow

**OAuth2 Scopes**:
- `openid`, `email`, `profile` - Basic user identification
- `https://www.googleapis.com/auth/calendar.events` - Read/write calendar events
- `https://www.googleapis.com/auth/calendar.settings.readonly` - Read calendar settings (week start, hide weekends)
- `https://www.googleapis.com/auth/calendar.readonly` - Read calendar data

**Assessment**: Permissions are appropriate and minimal for the extension's stated functionality. OAuth2 implementation follows Google's best practices with proper token refresh and revocation.

### Content Security Policy (CSP)

No custom CSP defined in manifest.json - uses default Manifest V3 CSP which blocks inline scripts and external script loading. This is a secure configuration.

### Code Analysis

#### 1. Authentication & Token Management (background.js)

**Pattern**: Standard OAuth2 implementation
```javascript
// Lines 548-771: OAuth2 flow with refresh token support
- Proper token storage in chrome.storage.local
- Automatic token refresh on expiration
- Token revocation on sign-out
- No hardcoded credentials except OAuth2 client config (normal for extensions)
```

**Findings**:
- ✅ Tokens stored securely in chrome.storage.local (not accessible to web pages)
- ✅ Client secret in manifest is expected for OAuth2 installed applications
- ✅ Proper error handling and token refresh logic
- ✅ Token revocation implemented in signout.js

**Embedded API Key**: `AIzaSyDfX9-dAwL9KoxzvGu3IzA1zu0oDQ-cJfw` (line 422 of background.js)
- This is a Google Calendar API key for the copyEvent operation
- Public API keys in extensions are standard practice
- No security risk as it's rate-limited and scoped to the extension

#### 2. Data Storage & Privacy

**Storage Usage**:
- User preferences (UI colors, toggle states)
- OAuth2 access/refresh tokens
- Cached calendar list data (1-hour TTL)
- Temporary event cache for tooltips
- Navigation state flags

**Findings**:
- ✅ No sensitive user data collection beyond OAuth tokens
- ✅ Calendar cache has reasonable TTL (1 hour)
- ✅ No tracking or telemetry
- ✅ localStorage only used for navigation state flags
- ✅ No cookies accessed or manipulated

#### 3. DOM Manipulation & XSS Risk

The extension heavily manipulates Google Calendar's DOM to add features:

**innerHTML Usage** (popup.js):
- Lines 105, 1098, 1311, 1916, 1928, 1967, 1994, 2057, 2116, 2497, 2585
- All instances use static strings or sanitized user preference data
- No user-controlled input passed to innerHTML

**Dynamic Element Creation**:
- Extensive use of `document.createElement()` for button injection
- SVG elements created with `createElementNS()`
- Text content set via `.textContent` rather than `.innerHTML`

**Findings**:
- ✅ No dynamic code execution (eval, Function, etc.)
- ✅ innerHTML usage limited to static templates
- ✅ Event listeners properly attached, no inline event handlers
- ✅ No postMessage usage or cross-origin communication

#### 4. Background Script Security

**Chrome API Usage**:
- `chrome.runtime.sendMessage` - Internal extension messaging only
- `chrome.storage.local` - Secure local storage
- `chrome.identity` - OAuth2 authentication
- `chrome.scripting.executeScript` - Injects CSS files only (lines 822-1696 of popup.js)
- `chrome.webNavigation.onCommitted` - Clears cache on page navigation

**Findings**:
- ✅ No chrome.webRequest modification
- ✅ No debugger or proxy usage
- ✅ executeScript only used for CSS injection (appearance customization)
- ✅ No arbitrary code injection

#### 5. Third-Party Libraries

**Included Libraries**:
- jQuery 3.7.1 (legitimate, minified)
- jQuery UI (legitimate, minified)
- Moment.js & moment-timezone (legitimate date library)
- Coloris (color picker library)
- jQuery UI Multidatespicker plugin

**Findings**:
- ✅ All libraries are legitimate, well-known packages
- ✅ No obfuscated or suspicious code in libraries
- ✅ Libraries match their official distributions

### False Positive Analysis

| Pattern | Location | Verdict | Reason |
|---------|----------|---------|---------|
| `innerHTML` usage | popup.js (multiple) | FALSE POSITIVE | Static HTML templates only, no user input |
| localStorage access | gcalplus.js:2134-2211 | FALSE POSITIVE | Navigation state flag only, cleared after use |
| OAuth client secret | manifest.json:59 | FALSE POSITIVE | Standard for OAuth2 installed applications |
| Public API key | background.js:422 | FALSE POSITIVE | Google Calendar API key, public by design |
| chrome.scripting.executeScript | popup.js (multiple) | FALSE POSITIVE | CSS-only injection for UI styling |

## Data Flow Summary

1. **User Authentication**:
   - User clicks "Connect" → OAuth2 flow initiated
   - Google OAuth consent screen → Authorization code
   - Extension exchanges code for access/refresh tokens
   - Tokens stored in chrome.storage.local

2. **Calendar Data Access**:
   - Extension fetches calendar list via Google Calendar API
   - Event data retrieved for busy date highlighting
   - Calendar settings (week start, hide weekends) fetched
   - All data cached locally with 1-hour TTL

3. **Feature Operations**:
   - UI preferences stored in chrome.storage.local
   - CSS injected into Google Calendar page for styling
   - Event operations (copy, move, transparency) via Google Calendar API
   - No data leaves the user's browser except to Google APIs

4. **Data Retention**:
   - Cached data cleared on page navigation
   - Tokens persisted until user signs out
   - No external data transmission

## Privacy Assessment

- ✅ **No Data Collection**: Extension does not collect, store, or transmit user data to third parties
- ✅ **No Tracking**: No analytics, telemetry, or user behavior tracking
- ✅ **No Ads**: No advertising or monetization mechanisms
- ✅ **Transparent Permissions**: All permissions have clear, documented purposes
- ✅ **Local Processing**: All data processing occurs locally in the browser
- ✅ **Official APIs Only**: All network requests go to Google's official APIs

## Vulnerability Summary

**No security vulnerabilities identified.**

The extension follows secure coding practices:
- Proper OAuth2 implementation
- No dynamic code execution
- Safe DOM manipulation
- Appropriate permission scope
- No third-party data sharing
- Secure content security policy
- Regular token refresh and expiration handling

## Risk Assessment

**Overall Risk Level**: **CLEAN**

**Justification**:
1. Extension source code is clean and well-structured
2. All functionality is legitimate calendar enhancement
3. No malicious patterns or suspicious behavior detected
4. Proper security practices implemented throughout
5. OAuth2 authentication follows Google's guidelines
6. No privacy concerns or data exfiltration
7. Permissions appropriately scoped to functionality
8. No obfuscated or hidden code

## Recommendations

For users:
- Extension is safe to use for Google Calendar enhancements
- Review OAuth permissions during installation (standard calendar access)
- Can revoke access at any time via Google Account settings

For developers:
- Consider adding CSP to manifest.json for additional hardening
- Implement sub-resource integrity (SRI) for bundled libraries
- Add code signing to verify extension integrity

## Conclusion

GCalPlus is a legitimate, well-developed Google Calendar enhancement extension with no security concerns. The extension demonstrates proper security practices, uses only official Google APIs, and respects user privacy. The codebase is clean, transparent, and free from malicious patterns. **Recommended as CLEAN for general use.**
