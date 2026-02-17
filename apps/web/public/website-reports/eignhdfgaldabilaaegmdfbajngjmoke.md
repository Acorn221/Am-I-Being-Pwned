# Black Menu for Google™ - Security Analysis Report

## Extension Metadata
- **Extension ID**: eignhdfgaldabilaaegmdfbajngjmoke
- **Name**: Black Menu for Google™
- **Version**: 31.0.11
- **Users**: ~200,000
- **Author**: Carlos Jeurissen
- **Homepage**: https://apps.jeurissen.co/black-menu-for-google
- **Manifest Version**: 3

## Executive Summary

Black Menu for Google™ is a **CLEAN** extension that provides a navigation menu for accessing various Google services. The extension is a legitimate productivity tool developed by Carlos Jeurissen (a known extension developer in the Chrome ecosystem). After comprehensive analysis of the codebase, no malicious behavior was identified. The extension's permissions and functionality are appropriate for its stated purpose of providing quick access to Google services.

### Key Findings:
- ✅ Legitimate navigation utility for Google services
- ✅ No data exfiltration to third-party servers
- ✅ No tracking/analytics beyond Google's own services
- ✅ Cookie access limited to legitimate Google authentication
- ✅ Transparent OAuth2 flow for Google API access
- ✅ No obfuscation or hidden functionality
- ✅ No extension enumeration or manipulation
- ✅ Content Security Policy properly configured

## Detailed Analysis

### 1. Manifest Permissions Analysis

**Declared Permissions:**
- `activeTab` - Standard for interacting with current tab
- `contextMenus` - Used for right-click menu integration
- `cookies` - Used for Google authentication session management
- `declarativeNetRequestWithHostAccess` - Modern MV3 network filtering
- `scripting` - Standard for content script injection
- `sidePanel` - Chrome sidebar functionality
- `storage` - User preferences storage
- `webRequestBlocking` - Used for authentication flow handling

**Optional Permissions:**
- `management` - Requested only when needed (extension settings)
- `webRequest` - Legacy support for older browsers

**Host Permissions:**
- All permissions limited to `*.google.com/*`, `*.googleapis.com/*`, `*.googleusercontent.com/*`, `*.gstatic.com/*`
- Optional YouTube permissions for media features

**Verdict:** ✅ **CLEAN** - All permissions are justified for a Google services navigation tool.

### 2. Content Security Policy

```
default-src 'none';
child-src 'none';
connect-src chrome-extension: https://*.google.com/ https://chat.googleapis.com/ ...
script-src 'self';
img-src 'self' data: chrome://extension-icon/ https://*.google.com/ ...
```

**Verdict:** ✅ **EXCELLENT** - Very restrictive CSP that prevents remote code execution, only allows connections to Google domains.

### 3. Background Script Analysis

**File:** `/scripts/background.js` (832 lines)

**Key Functionality:**
- Extension lifecycle management (installation, updates)
- Landing page notifications for updates
- Context menu registration
- Popup and sidebar window management
- Tab and window creation helpers

**Network Activity:**
- Update notifications from `https://apps.jeurissen.co/black-menu-for-google/`
- Uninstall URL: `https://apps.jeurissen.co/black-menu-for-google/uninstalled`
- No analytics or tracking beacons

**Verdict:** ✅ **CLEAN** - Standard extension housekeeping, no malicious behavior.

### 4. Google Authentication Flow

**Files:** `/scripts/cjg-apis.js` (1,061 lines)

**Authentication Mechanisms:**
1. **Account Listing** - Queries `https://accounts.google.com/ListAccounts` to get user's Google accounts
2. **SAPISID Cookie** - Retrieves Google's authentication cookie for API requests
3. **OAuth2 Flow** - Uses legitimate OAuth2 with client ID from `g.carlosjeurissen.com/webext-auth`
4. **SAPISIDHASH Generation** - Creates SHA1-based authorization headers for Google API requests

**Client ID (base64 decoded):**
```
494086030851-93vje778kogr9dnfq2hhli2e918p4hha.apps.googleusercontent.com
```

**Key Code Patterns:**
```javascript
// Line 237: SAPISID cookie retrieval
function re() {
  return y("SAPISID", $)
}

// Line 990: SAPISIDHASH generation (standard Google API auth)
return "SAPISIDHASH " + n + "_" + function(e) { /* SHA1 hash */ }

// Line 1028: Google API request with credentials
i.credentials = "include"
r.Authorization = e
r["X-Goog-AuthUser"] = t.authuser
```

**Verdict:** ✅ **CLEAN** - Standard Google OAuth2 implementation, no credential theft.

### 5. Content Scripts Analysis

**141 page-specific content scripts** supporting Google services:
- Gmail, Drive, Calendar, Photos, YouTube, etc.
- Scripts inject UI elements for quick navigation
- Each script scoped to specific Google service URLs

**Example Pattern:**
```javascript
// cs-proxy.js - Handles cross-origin requests within Google domains
// Only operates on Google.com URLs with specific patterns
// Uses postMessage for secure iframe communication
```

**Verdict:** ✅ **CLEAN** - Scripts only operate on Google domains, no DOM scraping or keylogging.

### 6. Data Flow Analysis

**Data Storage (chrome.storage.local/sync):**
- User preferences (theme, language, service visibility)
- Account selection state
- Service usage statistics (for UI ordering)
- OAuth2 tokens (scoped to Google APIs)

**Network Requests:**
1. **Google APIs:**
   - `https://accounts.google.com/` - Account management
   - `https://oauth2.googleapis.com/` - Token management
   - `https://content.googleapis.com/` - Google service data
   - `https://www.googleapis.com/` - Various Google APIs

2. **Developer Domain:**
   - `https://apps.jeurissen.co/` - Extension website (install/uninstall/update pages)
   - `https://g.carlosjeurissen.com/webext-auth` - OAuth redirect URI

**Verdict:** ✅ **CLEAN** - No data exfiltration, all network activity to Google or developer's legitimate domains.

### 7. Security Features

**Positive Security Patterns Observed:**
1. **CSP Reporting** - Reports CSP violations to `https://api.jeurissen.co/reports/csp/`
2. **Security.txt** - Provides security contact: `security@apps.jeurissen.co`
3. **Cookie Security** - Properly handles cookie scoping and HTTPS-only
4. **WebRequest Fallbacks** - Detects when webRequest API is unavailable (Firefox)
5. **Frame Ancestor Protection** - Validates iframe origins to prevent clickjacking

### 8. Privacy Analysis

**Data Collection:** ✅ MINIMAL
- Service usage counts (stored locally for UI ordering)
- User theme/language preferences
- Account selection state

**Third-Party Sharing:** ✅ NONE
- No analytics SDKs
- No ad networks
- No market intelligence tools

**User Tracking:** ✅ NONE
- No fingerprinting
- No session recording
- No browsing history collection

## False Positive Analysis

| Pattern | Location | Explanation | Verdict |
|---------|----------|-------------|---------|
| `postMessage` usage | cs-proxy.js:32, cjg-popup.js:108 | Secure iframe communication between extension pages and Google domains | FALSE POSITIVE |
| `chrome.cookies.get` | cjg-apis.js:219 | Retrieves SAPISID for Google API authentication (standard pattern) | FALSE POSITIVE |
| `chrome.cookies.getAll` | cjg-apis.js:242 | Firefox-specific workaround for cookie retrieval (scoped to Google) | FALSE POSITIVE |
| `XMLHttpRequest` | cs-proxy.js:65 | Proxy requests through Google.com for same-origin compliance | FALSE POSITIVE |
| Base64 encoded string | cjg-apis.js:678 | OAuth2 client ID (public, not secret) | FALSE POSITIVE |

## API Endpoints Summary

| Domain | Purpose | Data Sent | Security |
|--------|---------|-----------|----------|
| accounts.google.com | Account listing, OAuth | Account authuser, pageId | HTTPS, Google-owned |
| oauth2.googleapis.com | Token generation/validation | OAuth tokens, scopes | HTTPS, Google-owned |
| content.googleapis.com | Google service APIs | Service-specific queries | HTTPS, Google-owned |
| apps.jeurissen.co | Developer website | Install/uninstall events | HTTPS, developer domain |
| g.carlosjeurissen.com | OAuth redirect URI | OAuth state tokens | HTTPS, developer domain |
| api.jeurissen.co | CSP violation reporting | CSP violation reports | HTTPS, developer domain |

## Vulnerability Assessment

### Critical Issues: NONE

### High Issues: NONE

### Medium Issues: NONE

### Low Issues: NONE

### Informational Observations:

1. **Optional `management` Permission**
   - **Severity**: INFO
   - **Location**: manifest.json:12
   - **Details**: Extension requests optional `management` permission for extension settings page functionality. This is transparently requested only when user visits settings.
   - **Risk**: NONE - User must explicitly grant this permission

2. **Developer Domains**
   - **Severity**: INFO
   - **Files**: background.js:295, cjg-apis.js:677
   - **Details**: Extension contacts developer domains (apps.jeurissen.co, g.carlosjeurissen.com) for OAuth redirect and update notifications
   - **Risk**: NONE - Standard practice for extension lifecycle management

3. **WebRequest Blocking**
   - **Severity**: INFO
   - **Files**: cjg-apis.js:106, cj-basics.js:536
   - **Details**: Uses `webRequest` blocking mode to inject `Origin` headers for Google API CORS compliance
   - **Risk**: NONE - Only modifies headers on Google domains for legitimate API access

## Overall Risk Assessment: **CLEAN**

### Risk Score: 0/100 (No Risk)

**Justification:**
Black Menu for Google™ is a legitimate, well-maintained extension that provides a navigation interface for Google services. The extension:
- Only operates on Google domains
- Uses standard Google OAuth2 for authentication
- Has no third-party integrations
- Includes proper security.txt and CSP reporting
- Is developed by a known Chrome extension developer (Carlos Jeurissen)
- Has transparent source code with no obfuscation

### Recommendations:
- ✅ Extension is safe for use
- ✅ No security concerns identified
- ✅ Privacy practices are acceptable
- ✅ Permissions are appropriate for functionality

## Technical Notes

**Developer Background:**
- Carlos Jeurissen is a recognized Chrome extension developer
- Maintains multiple legitimate productivity extensions
- Provides security contact and update transparency
- Open source mindset (deobfuscated code is readable)

**Code Quality:**
- Well-structured, modular codebase
- Defensive programming (error handling, fallbacks)
- Cross-browser compatibility (Chrome, Firefox, Safari, Opera)
- MV3 migration complete (modern API usage)

---

**Analysis Date:** 2026-02-06
**Analyst:** Claude (Automated Security Analysis)
**Report Version:** 1.0
