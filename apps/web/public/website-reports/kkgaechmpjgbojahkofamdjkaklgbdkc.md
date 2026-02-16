# Vulnerability Report: Planyway for Trello

## Extension Metadata
- **Name**: Planyway for Trello: Calendar, Timeline, Time Tracking
- **Extension ID**: kkgaechmpjgbojahkofamdjkaklgbdkc
- **Version**: 2.4.47.1
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

Planyway for Trello is a legitimate productivity extension that adds calendar, timeline, and time tracking features to Trello boards. The extension integrates with Google Calendar and Outlook, requiring broad OAuth scopes for calendar synchronization. Security analysis reveals **standard third-party analytics integration** (Amplitude, Intercom, Application Insights) and extensive DOM manipulation on Trello pages, but **no evidence of malicious behavior**. The extension follows reasonable security practices with a restrictive CSP and minimal permissions. Primary concerns are third-party analytics data collection and hardcoded API credentials.

**Overall Risk Level: LOW**

## Manifest Analysis

### Permissions
```json
"permissions": ["storage"]
"host_permissions": [
  "https://trello.com/*",
  "https://planyway.com/*"
]
```

**Assessment**: Minimal permissions model. Only requests storage and host access to its own domain and Trello. No access to cookies, webRequest, tabs, or other sensitive APIs.

### Content Security Policy
```json
"content_security_policy": {
  "extension_pages": "script-src 'self'; script-src-elem 'self'; object-src 'self';"
}
```

**Verdict**: ✅ **CLEAN** - Restrictive CSP blocks inline scripts and external script loading in extension pages.

### Content Scripts
- **Injection Target**: `https://trello.com/*` (excludes `https://trello.com/1/*`)
- **Run Time**: `document_start`
- **Script Count**: 27 content scripts injected into Trello pages
- **Additional Target**: `https://planyway.com/common/exchange.html*` (OAuth exchange page)

**Verdict**: ✅ **EXPECTED BEHAVIOR** - Content scripts inject Planyway UI widgets into Trello boards for calendar/timeline functionality.

### Web Accessible Resources
```json
"web_accessible_resources": [{
  "resources": ["icons*", "images/*", "videos/*", "scripts/*"],
  "matches": ["<all_urls>"]
}]
```

**Concern**: Scripts are web-accessible to all URLs. While this enables the extension's UI functionality, it could theoretically allow malicious websites to enumerate the extension or load its resources.

**Verdict**: ⚠️ **ACCEPTABLE** - Common pattern for extensions that inject UI components, though narrower matching would be preferable.

## API Endpoints & Network Traffic

### Legitimate Service Endpoints

| Endpoint | Purpose | Verdict |
|----------|---------|---------|
| `https://planyway.com/api/b` | Backend API for Planyway service | ✅ Own service |
| `https://files.planyway.com/` | Static assets (fonts, logos, config) | ✅ CDN resources |
| `https://trello.com/1/authorize` | Trello OAuth authorization | ✅ Required for Trello integration |
| `https://accounts.google.com/o/oauth2/v2/auth` | Google OAuth for calendar sync | ✅ Required for Google Calendar |
| `https://www.googleapis.com/calendar/v3` | Google Calendar API | ✅ Calendar synchronization |
| `https://people.googleapis.com/v1` | Google Contacts API | ✅ Contact lookup for calendar |
| `https://graph.microsoft.com/v1.0` | Microsoft Graph API | ✅ Outlook calendar sync |
| `https://graph.microsoft.com/beta` | Microsoft Graph Beta API | ✅ Outlook advanced features |

### Third-Party Analytics & Telemetry

| Service | Endpoint | Data Collected | Verdict |
|---------|----------|----------------|---------|
| **Amplitude** | `https://api.amplitude.com` | Usage analytics, event tracking | ⚠️ Standard analytics |
| **Intercom** | `https://api-iam.intercom.io` | Customer support chat, user data | ⚠️ Support platform |
| **Application Insights** | `https://dc.services.visualstudio.com/v2/track` | Performance telemetry (Microsoft) | ⚠️ Performance monitoring |

**Finding**: Extension integrates three third-party analytics/support services. While these are legitimate business tools, they represent data sharing with external parties.

**Evidence**:
```javascript
// File: 0a322fa7-4ba9-4813-95e7-a1d599756e1a.js
_ = "https://api.amplitude.com";
k = "https://dc.services.visualstudio.com/v2/track",
fe = "https://api-iam.intercom.io",
```

**Verdict**: ⚠️ **PRIVACY CONCERN** - Standard analytics integration, but users should be aware of third-party data sharing. Not malicious, but represents a privacy tradeoff.

## Credentials & API Keys Analysis

### Hardcoded Credentials Found

```javascript
// Trello API Key
r = "c05e9168828198b995a2175af18e5686"

// Google OAuth Client ID
o = "442776835437-hdtlsqk5d7vudej196jqomact0p2onj8.apps.googleusercontent.com"

// Intercom App ID
w = "yzpc1nmz"

// Microsoft/Outlook App ID
c = "637eb45a-8b43-4867-8d28-0611bdcca7fd"

// VAPID Public Key (Push notifications)
p = "BMtojXzd4NIHuVPeQRNc5KxFfi1ald8vaPAeX14AUpu6-b0JpZCVyA-TxquggLgPR1afbrJSSn6y8G3LdaHzino"
```

**Verdict**: ⚠️ **ACCEPTABLE** - These are public OAuth client IDs and API keys, not secrets. Hardcoding them in the extension is standard practice for OAuth flows. The Trello API key is publicly visible in the Trello authorization URL.

## OAuth Scopes Analysis

### Google OAuth Scopes
```javascript
scopes: [
  "https://www.googleapis.com/auth/calendar",
  "https://www.googleapis.com/auth/contacts.readonly",
  "https://www.googleapis.com/auth/userinfo.email",
  "https://www.googleapis.com/auth/userinfo.profile"
]
```

**Assessment**:
- `calendar` - Full calendar access (read/write) - **Justified** for calendar sync
- `contacts.readonly` - Read contacts - **Potentially excessive** (likely for calendar attendee lookup)
- `userinfo.email` + `userinfo.profile` - User identity - **Standard** for authentication

### Trello OAuth Scopes
```javascript
scope: "read,write,account"
```

**Assessment**: Full read/write access to Trello boards and user account. **Justified** for calendar/timeline functionality that modifies Trello cards.

**Verdict**: ⚠️ **BROAD BUT JUSTIFIED** - Scopes align with stated functionality (calendar sync, card management).

## Code Behavior Analysis

### Storage Usage
- Uses `localStorage` and `sessionStorage` via custom `StorageProxy` class
- Namespace prefix: `trello_`
- Stores user preferences, authentication tokens, cached data

**Verdict**: ✅ **CLEAN** - Standard local storage usage with namespace isolation.

### Dynamic Code Execution
**Search Results**: No evidence of `eval()`, `new Function()`, or `Function()` constructor calls for code execution.

**Note**: Found Angular `$evalAsync()` calls, which are part of the AngularJS digest cycle (not dynamic code evaluation).

**Verdict**: ✅ **CLEAN** - No dynamic code execution detected.

### DOM Manipulation
Extension injects extensive UI components into Trello pages:
- Calendar views
- Timeline widgets
- Card scheduling interfaces
- Settings panels

Uses AngularJS framework for UI rendering and React components for modern features.

**Verdict**: ✅ **EXPECTED** - Core functionality requires DOM manipulation to add calendar features to Trello.

### Message Passing
Uses `postMessage` for cross-origin communication with:
- OAuth exchange window (`https://planyway.com/common/exchange.html`)
- Intercom chat iframe
- Service worker communication

**Code Evidence**:
```javascript
// OAuth exchange messaging
window.addEventListener("message", listener, false)
checkOrigin: ["https://planyway.com"]

// Intercom iframe messaging
this.chatAvailable && this.chatInitialized &&
  $('.pw-js-intercom-iframe')[0].contentWindow.postMessage(...)
```

**Verdict**: ✅ **SAFE** - Origin checking implemented for OAuth exchange. Intercom iframe is from trusted domain.

### Extension Communication
- Uses `externally_connectable` restricted to `https://planyway.com/*`
- Allows the main Planyway web app to communicate with the extension

**Verdict**: ✅ **SAFE** - Properly scoped to own domain.

## Security Vulnerabilities

### None Detected

No evidence of:
- Extension enumeration/fingerprinting attacks
- Competitor extension killing
- XHR/fetch hooking
- Residential proxy infrastructure
- Remote kill switches (beyond standard config loading)
- Market intelligence SDKs (Sensor Tower, Pathmatics, etc.)
- AI conversation scraping
- Ad injection or coupon replacement
- Cookie harvesting
- Keylogging
- Credential theft
- Data exfiltration to suspicious domains

## False Positives Table

| Pattern | Location | Explanation | Verdict |
|---------|----------|-------------|---------|
| `innerHTML` usage | Multiple React/Angular components | Standard React SVG rendering, Angular template compilation | ✅ False Positive |
| `postMessage` calls | OAuth exchange, Intercom | Legitimate cross-origin communication with origin validation | ✅ False Positive |
| `window.open` | Auth flow | Opens OAuth authorization windows (Google, Outlook, Trello) | ✅ False Positive |
| `$evalAsync` | AngularJS digest cycle | Angular framework function, not `eval()` | ✅ False Positive |
| Third-party domains | Analytics/support | Amplitude, Intercom, Application Insights - standard SaaS tools | ⚠️ Privacy concern, not malicious |

## Data Flow Summary

1. **User Authentication Flow**:
   - User clicks "Connect Google/Outlook/Trello"
   - Extension opens OAuth window via `window.open()`
   - User authorizes on provider's domain
   - Auth code/token exchanged via `planyway.com/common/exchange.html`
   - Tokens sent to `planyway.com/api/b` backend
   - Tokens stored in extension localStorage (namespace: `trello_`)

2. **Calendar Synchronization**:
   - Extension fetches Trello cards via Trello API
   - Extension fetches calendar events from Google/Outlook APIs
   - Data synchronized bidirectionally through `planyway.com/api/b`
   - UI updates rendered in content scripts injected into `trello.com`

3. **Analytics Data Flow**:
   - Usage events (button clicks, feature usage) sent to Amplitude
   - User support interactions sent to Intercom
   - Performance metrics sent to Application Insights
   - All analytics use standard SDK integrations (no raw data scraping)

## Privacy Concerns

### Third-Party Data Sharing
- **Amplitude Analytics**: Receives usage telemetry (user actions, feature usage)
- **Intercom Support**: Receives user identity and support chat messages
- **Application Insights**: Receives performance/error telemetry

**Recommendation**: Users concerned about analytics should review Planyway's privacy policy. The extension does not provide opt-out controls within the UI.

### Broad OAuth Scopes
- Google Calendar: Full read/write access (required for sync)
- Google Contacts: Read access (potentially excessive, likely for calendar attendee lookup)
- Trello: Full board access (required for card management)

**Recommendation**: Users should verify they trust Planyway with these permissions before installation.

## Overall Assessment

### Risk Level: **LOW**

**Rationale**:
- ✅ Legitimate productivity tool with clear value proposition
- ✅ No evidence of malicious behavior or data theft
- ✅ Restrictive CSP and minimal Chrome permissions
- ✅ No dynamic code execution or obfuscation
- ✅ OAuth scopes align with stated functionality
- ⚠️ Third-party analytics integration (industry standard)
- ⚠️ Broad calendar/board permissions (required for features)

### Recommendations

**For Users**:
1. Review Planyway's privacy policy regarding third-party analytics
2. Ensure you trust the extension with full calendar and Trello board access
3. Consider the value of the feature set against the privacy tradeoffs

**For Developers**:
1. Consider narrowing `web_accessible_resources` matches to reduce exposure
2. Provide user controls for analytics opt-out
3. Document why Google Contacts scope is required (or remove if not essential)
4. Consider replacing Application Insights with a privacy-focused alternative

**For Security Researchers**:
- This extension represents a **clean, legitimate tool** with standard SaaS integrations
- Primary concerns are privacy-related, not security-related
- No evidence of malicious intent or deceptive practices

## Conclusion

Planyway for Trello is a **well-architected, legitimate browser extension** that provides genuine calendar and timeline functionality for Trello users. The extension follows modern security best practices (MV3, restrictive CSP, minimal permissions) and shows no signs of malicious behavior. Privacy-conscious users should be aware of third-party analytics integration, but this represents standard business practices rather than security vulnerabilities.

The extension can be considered **SAFE** for use by individuals and organizations who accept the privacy tradeoffs inherent in using a third-party productivity tool with calendar integration.
