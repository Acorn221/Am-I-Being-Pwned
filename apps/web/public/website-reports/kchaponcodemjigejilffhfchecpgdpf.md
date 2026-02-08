# Vulnerability Report: Writesonic: AI Writing, SEO, and Keywords

## Extension Metadata
- **Extension ID**: kchaponcodemjigejilffhfchecpgdpf
- **Extension Name**: Writesonic: AI Writing, SEO, and Keywords
- **Version**: 1.0.0.92
- **Users**: ~80,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

Writesonic is a legitimate AI writing assistant extension from a reputable company. The extension provides writing assistance, SEO tools, and keyword research functionality across Google Search, various web platforms, and integrated services. After comprehensive analysis of the codebase, **no critical security vulnerabilities or malicious behavior were identified**. The extension follows Chrome extension best practices with appropriate permissions and transparent functionality.

The extension communicates exclusively with Writesonic's own backend infrastructure (api-azure.writesonic.com) for AI content generation and uses Mixpanel for legitimate analytics. All network communications are related to the extension's stated purpose.

## Vulnerability Assessment

### CRITICAL Severity Issues
**None identified**

### HIGH Severity Issues
**None identified**

### MEDIUM Severity Issues
**None identified**

### LOW Severity Issues

#### 1. Hardcoded Authentication Token (Low - Development Artifact)
**Severity**: LOW
**Location**: `js/background.js:103`
**Finding**:
```javascript
manual_token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjYwNTNmYTcxLThjNDgtNDhhNi1iNmQwLTZkZjA2NzM5ZDk0MyIsImV4cCI6MTY4ODExNjY4N30.6P8gWdATp2675xtmdniwpmmGv-EsQucK-hxLFiERoqU"
```

**Analysis**: A JWT token is hardcoded in the configuration object. Decoding the token reveals:
- User ID: `6053fa71-8c48-48a6-b6d0-6df06739d943`
- Expiration: 1688116687 (July 2023 - already expired)

**Verdict**: **Low Risk - False Positive**. This appears to be a development/testing artifact with an expired token that is never actually used in production code. No evidence of it being referenced or used for authentication bypasses.

---

#### 2. Broad Content Script Injection
**Severity**: LOW
**Location**: `manifest.json:41-46`
**Finding**:
```json
{
  "matches": ["https://*/*", "http://*/*", "file://*/*.pdf"],
  "js": ["js/content_main.js"],
  "css": ["css/main/main.css"],
  "all_frames": false,
  "run_at": "document_start"
}
```

**Analysis**: The extension injects content scripts on all HTTPS/HTTP URLs and PDF files. This is necessary for the "write anywhere" functionality that is the core feature of the extension.

**Verdict**: **Acceptable**. The broad injection is required for the extension's stated functionality and is standard for writing assistant tools. The content scripts only add UI elements and don't intercept or modify user data without user interaction.

---

#### 3. Chrome Tabs Permission Usage
**Severity**: LOW
**Location**: `js/background.js` (various locations)
**Finding**: The extension uses `chrome.tabs.query()`, `chrome.tabs.sendMessage()`, `chrome.tabs.create()`, and `chrome.tabs.reload()`.

**Analysis**: Tab permissions are used for:
- Sending messages between background and content scripts
- Opening authentication/billing pages when users click extension UI
- Managing iframe state across tab switches
- Cleaning up cached data when tabs close

**Verdict**: **Acceptable**. All tab API usage is legitimate and necessary for extension functionality. No evidence of tab enumeration for tracking or privacy violations.

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| Hardcoded token | `js/background.js:103` | Expired development token, not used in production |
| `chrome.tabs.query()` | Multiple locations | Legitimate message passing between extension components |
| Broad host permissions | `manifest.json` | Required for "write anywhere" core functionality |
| `chrome.storage` usage | Multiple files | Standard extension storage for user preferences and auth |
| `chrome.runtime.sendMessage()` | Multiple files | Standard extension messaging between components |

## API Endpoints & Network Communication

| Endpoint | Purpose | Security |
|----------|---------|----------|
| `https://api-azure.writesonic.com/v1/*` | Production AI API (content generation, user profiles, history) | ✅ HTTPS, Bearer token auth |
| `https://dev-backend.writesonic.com/v1/*` | Development API endpoint | ✅ HTTPS, Bearer token auth |
| `https://api.mixpanel.com/track` | Analytics tracking | ✅ HTTPS, standard analytics |
| `https://app.writesonic.com/*` | Web application (auth, billing) | ✅ HTTPS, first-party domain |
| `https://www.google.com/*` (queries) | Keyword autocomplete/suggestions | ✅ Read-only public API |

### API Authentication Flow
1. User authenticates via `app.writesonic.com` web interface
2. Auth token stored in `chrome.storage.local.sonic_token`
3. Token sent as `Authorization: Bearer <token>` header on API requests
4. Token validated on each request to backend

**Security Assessment**: All API communications use HTTPS. Authentication tokens are properly stored in extension storage (not localStorage/cookies accessible to web pages). No evidence of token leakage or insecure transmission.

## Data Flow Summary

### User Data Collected
- **Authentication**: User token (stored encrypted in chrome.storage)
- **Usage Analytics**: Mixpanel events (feature usage, error tracking)
- **User Content**: Text submitted for AI generation (sent to Writesonic API)
- **Preferences**: Theme mode, widget position, mood selections

### Data Transmission
1. **To Writesonic API**: User-submitted text prompts, authentication tokens
2. **To Mixpanel**: Anonymous usage events (no PII)
3. **From Google**: Public keyword suggestions (read-only)

### Privacy Assessment
- ✅ No keylogging or passive content harvesting detected
- ✅ No transmission of browsing history
- ✅ No cookie theft or credential exfiltration
- ✅ Data only sent when user explicitly interacts with extension
- ✅ No third-party tracking pixels or ad networks

## Content Security Policy
**Manifest CSP**: Not explicitly defined (uses default MV3 CSP)
- Default MV3 CSP prevents inline scripts and eval
- ✅ No evidence of CSP bypasses

## Permissions Analysis

| Permission | Justification | Risk |
|-----------|---------------|------|
| `storage` | Store user preferences and auth tokens | Low |
| `contextMenus` | Right-click menu for "Ask Writesonic" | Low |
| `host_permissions: https://*/*` | Write anywhere functionality | Low |

**Assessment**: All permissions are justified and minimal for the extension's functionality.

## Known Attack Patterns Checked

| Pattern | Status | Notes |
|---------|--------|-------|
| Extension fingerprinting | ❌ Not found | No chrome.runtime.id enumeration of other extensions |
| XHR/fetch hooking | ❌ Not found | No interception of page network requests |
| Residential proxy infrastructure | ❌ Not found | No proxy configuration |
| Remote code execution | ❌ Not found | No eval(), Function(), or remote script loading |
| Cookie harvesting | ❌ Not found | No cookie access |
| Clipboard scraping | ❌ Not found | ClipboardEvent only for paste functionality |
| AI conversation scraping | ❌ Not found | Only processes user-submitted content |
| Ad/coupon injection | ❌ Not found | No ad network integration |
| Kill switches | ❌ Not found | No remote config for disabling extension |
| Market intelligence SDKs | ❌ Not found | Only Mixpanel for first-party analytics |

## Code Quality & Obfuscation

- **Obfuscation Level**: Minified/bundled (webpack/parcel), but not maliciously obfuscated
- **Variable Names**: Standard minified (e, t, n) but code structure is analyzable
- **Build Tool**: Appears to be webpack/parcel based on bundle structure
- **License**: Contains React/other library licenses in .LICENSE.txt files

## Specific Integration Analysis

### Google Search Integration
- **Purpose**: Display keyword difficulty, trends, and SEO data on search results
- **Mechanism**: Content script injected on `google.com/search*` and `bing.com/search*`
- **Data Access**: Reads search queries to provide keyword insights
- **Verdict**: ✅ Legitimate SEO functionality, no data exfiltration

### Gmail/Email Integration
- **Purpose**: Writing assistant for email composition
- **Files**: `js/injected_gmail.js`, widget components
- **Mechanism**: Detects contenteditable fields, adds AI writing widgets
- **Verdict**: ✅ User-initiated assistance, no passive email monitoring

### Social Media Integration
- **Platforms**: Twitter, LinkedIn, Facebook, Instagram
- **Files**: `js/injected_twitter.js`, `js/content_alliframes.js`
- **Verdict**: ✅ Writing assistance widgets, no data harvesting

### Google Docs Integration
- **File**: `js/injected_gdocs.js`
- **Mechanism**: Integrates with Google Docs editor
- **Verdict**: ✅ Standard contenteditable manipulation for writing assistance

## Overall Risk Assessment

**Risk Level**: **CLEAN**

### Justification
1. ✅ Legitimate business model (freemium AI writing service)
2. ✅ Transparent functionality matching description
3. ✅ No malicious code patterns detected
4. ✅ Appropriate permissions for stated functionality
5. ✅ Secure communication (HTTPS, proper auth)
6. ✅ No evidence of data exfiltration beyond service functionality
7. ✅ Established company with public reputation
8. ✅ No obfuscation intended to hide malicious behavior

### Potential Concerns (Not Security Issues)
- Extension has access to all web page content (required for "write anywhere")
- User-submitted content is sent to Writesonic servers (expected for AI service)
- Broad content script injection (necessary for core functionality)

## Recommendations

### For Users
- ✅ **Safe to use** - No security concerns identified
- Extension requires trust in Writesonic's data handling (inherent to AI services)
- Be aware that text submitted to AI features is sent to Writesonic servers

### For Developers
- Consider removing hardcoded `manual_token` from production builds
- Add explicit CSP to manifest for defense-in-depth
- Consider more granular host permissions if possible (though broad access is needed)

## Conclusion

Writesonic is a **legitimate and safe** Chrome extension providing AI writing assistance. The extension follows security best practices for a MV3 extension and shows no evidence of malicious behavior, data theft, or privacy violations. All network communications are related to the extension's stated purpose of providing AI-powered writing assistance and SEO tools.

The broad permissions are justified by the extension's "write anywhere" functionality, and all data transmission occurs only when users explicitly interact with the extension's features.

---

**Report Generated**: 2026-02-07
**Analyst**: Claude (Automated Security Analysis)
**Confidence Level**: High
