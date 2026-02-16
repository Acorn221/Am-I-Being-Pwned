# Vulnerability Report: Maps Scraper & Leads Extractor - MapsLeads.net

## Metadata
- **Extension ID**: ghokiciomljbacchbkfhmnlmflbponlf
- **Extension Name**: Maps Scraper & Leads Extractor - MapsLeads.net
- **Version**: 12.6.1
- **User Count**: ~90,000
- **Analysis Date**: 2026-02-07
- **Manifest Version**: 3

## Executive Summary

Maps Scraper & Leads Extractor is a legitimate business leads extraction tool built with the Plasmo framework for scraping Bing Maps business data. The extension implements OAuth 2.0 authentication via Google Identity Platform and communicates with a backend API at `core.mapsleads.net`.

**Overall Risk Assessment: LOW**

The extension demonstrates standard functionality for a data scraping tool with appropriate permissions. No evidence of malicious behavior, residential proxy infrastructure, extension killing, market intelligence SDKs, AI conversation scraping, or ad/coupon injection was found. The extension uses legitimate OAuth flows and standard Vue.js/Element Plus UI framework patterns.

## Vulnerability Details

### 1. OAuth Authentication Implementation
**Severity**: INFO
**Files**: `background.93e42914.js`
**Verdict**: BENIGN

**Description**:
The extension implements Google OAuth 2.0 authentication using Chrome's identity API:

```javascript
chrome.identity.getRedirectURL(),
t=Math.random().toString(36).substring(2,15),
r=new URL("https://accounts.google.com/o/oauth2/v2/auth");
r.searchParams.set("client_id","1045436637864-mp9mgaioa4b3lekvskpcp1f0cae9qcvm.apps.googleusercontent.com"),
r.searchParams.set("response_type","id_token"),
r.searchParams.set("redirect_uri",e),
r.searchParams.set("scope","openid profile email"),
r.searchParams.set("nonce",t),
r.searchParams.set("prompt","consent")
```

**Assessment**: Standard OAuth 2.0 implementation requesting basic profile information (email, profile). The client ID matches the manifest oauth2 configuration. No excessive scope requests.

### 2. Message Passing Listeners
**Severity**: INFO
**Files**: `background.93e42914.js`
**Verdict**: BENIGN

**Description**:
The background script implements two message listeners:

```javascript
addListener)("LOGIN-OPTION",async(e,t)=>{
  let r;
  if("edge"===e.loginType)r=await (0,a.onEdgeLogin)();
  else if("anonymous"===e.loginType)r=await (0,a.onAnonymousLogin)();
  else throw Error("LOGIN-OPTION err data=",e);
  t({user:r})
})

addListener)("REFRESH-USERINFO",async(e,t)=>{
  t({user:await (0,a.getUserInfo)(!0,"fetch")})
})
```

**Assessment**: Standard Plasmo message passing implementation for authentication state management. No evidence of malicious message interception.

### 3. Base64 Encoding Usage
**Severity**: INFO
**Files**: `background.93e42914.js`
**Verdict**: FALSE POSITIVE

**Description**:
The extension uses `atob()` and `btoa()` functions for data encoding:

```javascript
atob(o)),"fetch").then(t=>{e(t)}).catch(e=>{console.error("edge remoteLogin:",e),t(e)})}
atob(e),r=new Uint8Array(t.length)
```

**Assessment**: Base64 encoding/decoding is used for standard data serialization, likely for JWT token parsing. This is a common pattern in OAuth implementations and Excel export functionality. No evidence of obfuscation or malicious payload decoding.

### 4. API Endpoint Communication
**Severity**: INFO
**Files**: `background.93e42914.js`
**Verdict**: BENIGN

**Description**:
The extension communicates with a single backend API:
- Base URL: `https://core.mapsleads.net`

**Assessment**: Legitimate API endpoint for the extension's backend services. No evidence of data exfiltration to suspicious third-party domains.

### 5. Extension Installation Handler
**Severity**: INFO
**Files**: `background.93e42914.js`
**Verdict**: BENIGN

**Description**:
```javascript
chrome.runtime.onInstalled.addListener(e=>{
  "install"===e.reason&&(
    chrome.runtime.setUninstallURL("https://mapsleads.net/suggestion/"),
    chrome.tabs.create({url:"https://mapsleads.net/"})
  )
})
```

**Assessment**: Standard onboarding flow - opens the product website on installation and sets an uninstall feedback URL. No malicious behavior.

### 6. Content Script DOM Manipulation
**Severity**: INFO
**Files**: `leads.d3b76e5f.js`
**Verdict**: BENIGN

**Description**:
Content script injects Vue.js-based UI overlay on Bing Maps:

```javascript
document.createElement("plasmo-csui")
createShadowRoot(t):t.attachShadow({mode:"open"})
document.querySelector(e.versionDetector)
```

**Assessment**: Standard Plasmo content script UI injection pattern. The extension creates a shadow DOM for its UI overlay on Bing Maps pages. No evidence of DOM manipulation for ad injection or data theft.

### 7. Local Storage Usage
**Severity**: INFO
**Files**: `leads.d3b76e5f.js`
**Verdict**: BENIGN

**Description**:
The content script uses `localStorage` and `sessionStorage` (8 instances found).

**Assessment**: Standard client-side storage for extension state persistence. No evidence of sensitive data theft via storage APIs.

### 8. Keyboard Event Listeners
**Severity**: INFO
**Files**: `leads.d3b76e5f.js`
**Verdict**: FALSE POSITIVE

**Description**:
Multiple keydown event listeners detected:

```javascript
addEventListener("keydown",i)
addEventListener("keydown",m)
addEventListener("keydown",k)
addEventListener("keydown",u)
```

**Assessment**: These are Element Plus UI framework keyboard navigation handlers (dialog focus trapping, menu navigation). Not keyloggers. This is expected behavior for accessibility and UI interaction.

### 9. Chrome Extension ID Enumeration
**Severity**: INFO
**Files**: `leads.d3b76e5f.js`
**Verdict**: BENIGN

**Description**:
```javascript
chrome.runtime.id}`):window.open(`https://chromewebstore.google.com/detail/${chrome.runtime.id}/reviews`)
```

**Assessment**: The extension uses its own runtime ID to construct Chrome Web Store review links. Not malicious extension enumeration.

### 10. Web Worker PostMessage
**Severity**: INFO
**Files**: `leads.d3b76e5f.js`
**Verdict**: FALSE POSITIVE

**Description**:
PostMessage usage detected in Web Worker context:

```javascript
postMessage(["SUCCESS",e])
postMessage(["ERROR",e])
postMessage([[...e]])
```

**Assessment**: Standard Web Worker communication pattern, likely for CSV parsing (Papa Parse library detected). Not malicious cross-origin messaging.

## False Positive Analysis

| Pattern | Context | Reason for FP |
|---------|---------|---------------|
| `eval` references | `evaluating:r`, `evaluate:G` | Property names in lodash/Vue.js libraries, not dynamic code execution |
| `atob/btoa` | JWT parsing, Excel export | Standard base64 encoding for OAuth tokens and file generation |
| `keydown` listeners | Element Plus UI | Framework keyboard navigation for dialogs, menus, and focus management |
| `postMessage` | Web Workers | Papa Parse CSV library worker communication |
| `inject*` functions | `injectCssInsert`, `injectToInstance` | Vue.js dependency injection system, not malicious injection |
| `chrome.runtime.id` | Review link construction | Legitimate self-referencing, not extension enumeration |
| `importScripts` | Web Worker context | Standard worker script loading |
| Shadow DOM | Plasmo framework | Isolated UI component rendering |

## API Endpoints

| Endpoint | Purpose | Risk Level |
|----------|---------|------------|
| `https://core.mapsleads.net` | Backend API for leads data | LOW - Legitimate service |
| `https://accounts.google.com/o/oauth2/v2/auth` | Google OAuth authentication | LOW - Standard OAuth flow |
| `https://mapsleads.net/` | Product website | LOW - Marketing site |
| `https://mapsleads.net/suggestion/` | Uninstall feedback | LOW - User feedback |
| `https://plus.codes/api?address=` | Google Plus Codes API | LOW - Geocoding service |

## Permissions Analysis

| Permission | Justification | Risk Assessment |
|------------|---------------|-----------------|
| `storage` | Store user preferences and scraped data | LOW - Standard usage |
| `identity` | Google OAuth authentication | LOW - Required for login |
| `https://*.bing.com/*` (host_permissions) | Inject content script on Bing Maps | LOW - Required for core functionality |
| `https://*.bing.com/*` (content_scripts) | Access Bing Maps DOM | LOW - Required for data scraping |

**Missing CSP**: No `content_security_policy` defined. While not required for MV3, this is acceptable as the extension doesn't load remote code.

## Data Flow Summary

1. **User Authentication**:
   - User initiates login (Edge/Google OAuth or anonymous)
   - Background script uses `chrome.identity.launchWebAuthFlow`
   - OAuth redirect returns ID token
   - Token sent to `core.mapsleads.net` for session creation
   - User info stored in `chrome.storage`

2. **Data Scraping**:
   - Content script activates on `https://*.bing.com/*`
   - Vue.js UI overlay injected via shadow DOM
   - User selects businesses on Bing Maps
   - Business data extracted from DOM
   - Data processed locally (CSV parsing via Web Worker)
   - Processed data sent to `core.mapsleads.net` API
   - Export functionality generates Excel files using SheetJS

3. **Network Communications**:
   - All API calls go to `core.mapsleads.net` with authorization headers
   - No third-party analytics or tracking domains
   - No residential proxy infrastructure detected
   - No market intelligence SDKs (Sensor Tower, Pathmatics, etc.)

## Security Strengths

1. **Modern Framework**: Built with Plasmo framework (MV3-native)
2. **Standard OAuth**: Proper implementation of Google Identity Platform
3. **Scoped Permissions**: Only requests necessary Bing Maps access
4. **Shadow DOM Isolation**: UI rendered in isolated shadow root
5. **No Remote Code Loading**: All code bundled in extension
6. **Legitimate Functionality**: Clear business purpose (B2B lead generation)

## Overall Risk Assessment

**RISK LEVEL: LOW**

This extension is a legitimate business tool for scraping Bing Maps business listings. The codebase demonstrates:

- ✅ No malicious behavior
- ✅ No residential proxy infrastructure
- ✅ No extension enumeration/killing
- ✅ No XHR/fetch hooking
- ✅ No remote config/kill switches
- ✅ No market intelligence SDKs
- ✅ No AI conversation scraping
- ✅ No ad/coupon injection
- ✅ No cookie harvesting beyond standard storage
- ✅ No obfuscation (beyond standard bundling/minification)

**Concerns**: None identified

**Recommendations**:
- Extension operates as advertised
- Users should review privacy policy at mapsleads.net regarding scraped data storage
- Standard data scraping tool risks apply (potential ToS violations with Bing Maps)

## Technical Stack

- **Framework**: Plasmo (Chrome Extension MV3 framework)
- **UI Library**: Vue.js 3, Element Plus
- **State Management**: Pinia
- **Build Tool**: Parcel
- **Data Processing**: Papa Parse (CSV), SheetJS (Excel)
- **HTTP Client**: Axios (inferred from patterns)

## Conclusion

Maps Scraper & Leads Extractor is a clean, purpose-built business intelligence tool with no security vulnerabilities or malicious functionality. All detected patterns are false positives from legitimate frameworks (Vue.js, Element Plus, Plasmo) and libraries (Papa Parse, SheetJS, lodash). The extension is safe for users who understand and consent to its business data scraping functionality.
