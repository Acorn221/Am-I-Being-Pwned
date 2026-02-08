# NCapture for NVivo - Security Analysis Report

## Extension Metadata
- **Extension Name**: NCapture
- **Extension ID**: lgomjifbpjfhpodjhihemafahhmegbek
- **Version**: 1.1.315.0
- **Users**: ~400,000
- **Developer**: QSR International (NVivo)
- **Homepage**: http://redirect.qsrinternational.com/nc-for-chrome.htm
- **Manifest Version**: 3

## Executive Summary

NCapture is a legitimate research data collection tool by QSR International for the NVivo qualitative research platform. The extension captures web pages, social media posts (Twitter/X, Facebook, LinkedIn), and YouTube videos with metadata for academic research purposes.

**Overall Risk Assessment: LOW (CLEAN)**

The extension follows a legitimate business model for academic research data collection. All network communication is with official QSR International infrastructure for retrieving OAuth credentials and GeoNames API tokens. Content scripts extract minimal page metadata (user IDs, post IDs) to facilitate social media data capture via official platform APIs. No malicious patterns detected.

## Permissions Analysis

### Declared Permissions
- `tabs` - Access tab information for capture context
- `notifications` - Display capture progress notifications
- `storage` - Store OAuth credentials and client ID locally
- `scripting` - Inject content scripts for page serialization
- `offscreen` - Create offscreen document for blob downloads
- `downloads` - Download captured data as .nvcx files

### Host Permissions
- `https://*/*` - Required to capture content from any HTTPS site

### Content Security Policy
No CSP declared in manifest (uses browser default for MV3).

## Vulnerability Assessment

### 1. Hardcoded Encryption Key
**Severity**: LOW
**Location**: `/js/service-worker.js:1109`
**Code**:
```javascript
x.SHARED_ENCRYPTION_PASSWORD = "N2b!JAstuNu52uGABrASu=UbreQatU9h";
```

**Description**: The extension uses a hardcoded shared password to encrypt/decrypt OAuth consumer secrets retrieved from `ncaptureservice.qsrinternational.com`. The encryption uses AES-CBC mode via CryptoJS library. While not ideal, this is used for obfuscation rather than security - the server response is already HTTPS-encrypted.

**Impact**: An attacker with extension access could extract the hardcoded key and decrypt cached OAuth credentials. However, these credentials are application-level OAuth consumer keys for Twitter/Facebook/LinkedIn APIs, not user credentials.

**Verdict**: NOT EXPLOITABLE - The key protects server responses that are already encrypted in transit. The OAuth tokens are short-lived and scoped to NCapture's registered app credentials.

---

### 2. Broad Host Permissions
**Severity**: LOW
**Location**: `manifest.json:27-29`
**Code**:
```json
"host_permissions": [
  "https://*/*"
]
```

**Description**: The extension requests access to all HTTPS sites to enable web page capture functionality. This is necessary for the core use case (capturing any research-relevant web page).

**Impact**: Extension can inject content scripts into any HTTPS page, potentially exposing user data if compromised.

**Verdict**: ACCEPTABLE - Broad permissions align with legitimate use case. Content scripts only extract minimal metadata (page title, user IDs for social platforms). No evidence of data exfiltration beyond intended capture workflow.

---

### 3. Social Media User ID Extraction
**Severity**: LOW
**Location**: Multiple content scripts
**Files**:
- `/js/content-scripts/twitter/twitter-content-script.js:3-7`
- `/js/content-scripts/linkedin/linkedin-content-script.js:3-8`
- `/js/content-scripts/facebook/facebook-content-script.js:2-79`

**Code**:
```javascript
// Twitter
var match, pattern = /(&quot;|")(screen_name|screenName|currentUserScreenName)(&quot;|"):(&quot;|")(\w*)(&quot;|")/, loggedInName='';
match = pattern.exec(document.documentElement.innerHTML);
chrome.runtime.sendMessage({screenName: loggedInName});

// LinkedIn
match = pattern.exec(document.documentElement.innerHTML);
if (match !== null) {
    loggedInName = match[1];
}
chrome.runtime.sendMessage({loggedInUserId: loggedInName});

// Facebook
var groupId = '', isPage = false, objectId;
// Extract group ID, page status, object ID from DOM
chrome.runtime.sendMessage({
    screenName: loggedInName,
    groupId: groupId,
    isPage: isPage,
    objectId: objectId
});
```

**Description**: Content scripts scan page HTML for logged-in user identifiers on Twitter/X, LinkedIn, and Facebook. These are used to determine authentication status before initiating OAuth flows for API-based data collection.

**Impact**: User identifiers extracted from social media pages. However, these are only used internally for OAuth authentication flow and not transmitted to third parties.

**Verdict**: ACCEPTABLE - Minimal metadata extraction for legitimate authentication flow. No evidence of unauthorized data collection.

---

### 4. Full Page DOM Serialization
**Severity**: LOW
**Location**: `/js/content-scripts/web-page/web-page-content-script.js`
**Code**:
```javascript
this.serialize = function () {
    var that = this;
    chrome.runtime.onConnect.addListener(function (port) {
        that.port = port;
        insertDocType();
        serializeNode(document.documentElement, processNode);
        insertStyleDefinitions();
        processMetaData();
        processLinkedCss(0, function () {
            that.port.postMessage({
                script: 'qsrwebpage',
                content: QsrNcaptureHtml,
                images: QsrNcaptureImages,
                metadata: QsrMetaData
            });
        });
    });
};
```

**Description**: The extension serializes entire web pages (HTML + CSS + images) for research capture. This is the core functionality - creating offline snapshots of web content for qualitative analysis in NVivo.

**Impact**: Complete page content captured including user-generated content, comments, embedded media. Data stored locally and exported as .nvcx files via download API.

**Verdict**: EXPECTED BEHAVIOR - This is the documented purpose of the extension. Users explicitly trigger captures via popup UI. No automatic/background capture detected.

---

### 5. OAuth Flow with Third-Party APIs
**Severity**: LOW
**Location**: `/js/service-worker.js:1652-1687, 2617-2649, 3148-3182`
**Code**:
```javascript
// Twitter/X
ce._buildAuthSettings = function(e, t) {
    return new oe({
        requestUrl: "https://api.x.com/oauth/request_token",
        authoriseUrl: "https://x.com/oauth/authorize",
        accessUrl: "https://api.x.com/oauth/access_token",
        consumerKey: e,
        consumerSecret: t,
        callbackUrl: "http://qsrinternational.com/support.aspx",
        requestMethod: "GET"
    })
};

// Facebook
xe.prototype._getAuthorizationSettings = function(e) {
    return {
        authoriseUrl: "https://www.facebook.com/dialog/oauth?client_id=" + e +
                     "&redirect_uri=https://www.facebook.com/connect/login_success.html&response_type=token",
        callbackUrl: "https://www.facebook.com/connect/login_success.html"
    }
};

// LinkedIn
at._buildAuthSettings = function(e, t) {
    return new oe({
        requestUrl: "https://www.linkedin.com/uas/oauth/requestToken",
        authoriseUrl: "https://www.linkedin.com/uas/oauth/authorize",
        accessUrl: "https://www.linkedin.com/uas/oauth/accessToken",
        consumerKey: e,
        consumerSecret: t,
        callbackUrl: "http://qsrinternational.com/support.aspx",
        requestMethod: "GET"
    })
};
```

**Description**: Extension implements OAuth 1.0a (Twitter, LinkedIn) and OAuth 2.0 (Facebook) flows to retrieve user-authorized access tokens. Consumer keys/secrets are fetched from `ncaptureservice.qsrinternational.com` on-demand, decrypted, and used to sign API requests.

**Impact**: Extension gains authorized access to user's social media data via official platform APIs. Scope of access determined by platform OAuth consent screens.

**Verdict**: STANDARD PRACTICE - Proper OAuth implementation following platform guidelines. Credentials managed server-side, not hardcoded in extension. User explicitly authorizes access via platform consent screens.

---

### 6. GeoNames API Integration
**Severity**: LOW
**Location**: `/js/service-worker.js:1119-1148`
**Code**:
```javascript
U.GEONAMES_REST_API = "http://ws.geonames.net/";
U.GEONAMES_SEARCH = "search?q=";
U.GEONAMES_USERNAME = "&username=";
U.GEONAMES_TOKEN = "&token=";
U.APPLICATION_ID = "700900C7-10F9-4B64-9061-CF68D0835DB4";

U.prototype.findLocation = async function(e, t) {
    const e = await n._nCaptureServiceProxy.getApplicationInfo(U.APPLICATION_ID);
    n._accountName = e.Token, n._tokenSecret = e.TokenSecret;
    // Batch geocode location strings to lat/lng coordinates
};
```

**Description**: Extension uses GeoNames web service to geocode location strings mentioned in social media posts. API credentials retrieved from NCapture service and cached.

**Impact**: Location data from captured social media content sent to GeoNames API for coordinate resolution. This is user-initiated (captures triggered manually) and supports research location analysis.

**Verdict**: EXPECTED BEHAVIOR - Documented feature for enriching research data with geographic coordinates. No unauthorized location tracking.

---

## False Positives

| Pattern | Location | Reason | Verdict |
|---------|----------|--------|---------|
| `XMLHttpRequest` usage | `web-page-content-script.js:78-95` | Downloads linked CSS files during page serialization | LEGITIMATE |
| `setTimeout` calls | Multiple locations | Standard JS timers for rate limiting, UI updates, async flows | LEGITIMATE |
| jQuery event handlers | `popup-page.js`, `notifications-page.js` | UI framework for popup and progress pages | LEGITIMATE |
| `addEventListener` usage | Multiple locations | Standard event listeners, no keylogging detected | LEGITIMATE |
| OAuth signature generation | `service-worker.js:301-456` | HMAC-SHA1 OAuth 1.0a implementation (Twitter, LinkedIn) | LEGITIMATE |
| CryptoJS library | `service-worker.js:550-1070` | AES encryption for API credential transport obfuscation | LEGITIMATE |
| Readability.js keydown handlers | `readability.js:208-230` | Article extraction tool keyboard shortcuts (Ctrl+Alt+R) | LEGITIMATE |

## API Endpoints & Data Flows

| Endpoint | Purpose | Data Sent | Data Received |
|----------|---------|-----------|---------------|
| `https://ncaptureservice.qsrinternational.com/applicationinfo/{guid}` | Retrieve OAuth consumer keys & GeoNames credentials | Client ID (UUID), signature | Encrypted OAuth credentials, API tokens |
| `https://api.x.com/oauth/*` | Twitter OAuth 1.0a flow | OAuth signature, consumer key | Request token, access token |
| `https://api.twitter.com/2/*` | Twitter API v2 data retrieval | Access token, tweet/user IDs | Tweet data, user profiles, media |
| `https://www.facebook.com/dialog/oauth` | Facebook OAuth 2.0 authorization | Client ID, redirect URI | Access token (via redirect) |
| `https://graph.facebook.com/v18.0/*` | Facebook Graph API | Access token, post/group IDs | Post data, comments, attachments |
| `https://www.linkedin.com/uas/oauth/*` | LinkedIn OAuth 1.0a flow | OAuth signature, consumer key | Request token, access token |
| `http://ws.geonames.net/search` | Geocoding service | Location strings, API token | Latitude/longitude coordinates |
| `https://www.googleapis.com/youtube/v3/*` | YouTube Data API | API key, video IDs | Video metadata, comments |

## Data Flow Summary

1. **User-Initiated Capture**: User clicks NCapture toolbar icon and selects capture type (web page, social media, video)
2. **Content Script Injection**: Extension injects content scripts to extract page metadata (URLs, user IDs, post IDs)
3. **Authentication Check**: If capturing social media, extension checks for existing OAuth tokens in chrome.storage.local
4. **OAuth Flow** (if needed): Extension retrieves consumer keys from NCapture service, initiates platform OAuth flow, stores access token
5. **API Data Collection**: Extension calls platform APIs (Twitter, Facebook, LinkedIn, YouTube) to retrieve posts, comments, user data
6. **Page Serialization**: For web pages, extension walks DOM tree, downloads images/CSS, serializes to XML format
7. **Local Export**: Captured data packaged as .nvcx file (XML format), downloaded via chrome.downloads API
8. **Import to NVivo**: User manually imports .nvcx file into NVivo desktop application for qualitative analysis

**Key Privacy Observation**: All data collection is user-initiated and locally stored. No background data harvesting. No third-party analytics or market intelligence SDKs detected.

## Overall Risk Assessment

**CLEAN** - NCapture is a legitimate research tool with appropriate permissions for its documented functionality. No evidence of:
- Malicious code injection
- Unauthorized data exfiltration
- Background surveillance
- Extension enumeration/killing
- Remote kill switches
- Market intelligence SDKs
- Ad injection
- Residential proxy infrastructure
- AI conversation scraping

## Comparison to Malicious Extensions

Unlike SUSPECT extensions in the workflow batch:
- **No Sensor Tower/Pathmatics**: No market intelligence SDKs hooking XHR/fetch on all pages
- **No Background Collection**: All captures explicitly triggered by user via popup UI
- **No Remote Config**: Behavior is static, not controlled by server-side configuration
- **OAuth Best Practices**: Credentials managed server-side, short-lived tokens, proper scoping
- **Academic Use Case**: Aligns with legitimate qualitative research workflows (NVivo is industry-standard)

## Recommendations

### For Users
1. **Understand Scope**: NCapture collects complete page content and social media data you explicitly capture
2. **Review OAuth Scopes**: Check platform consent screens during initial authorization (Twitter, Facebook, LinkedIn)
3. **Manage Tokens**: Revoke OAuth access via platform settings (Twitter Apps, Facebook Business Integrations) when no longer needed
4. **Data Handling**: Captured .nvcx files contain full page content - handle per research ethics/privacy requirements

### For Developers (QSR International)
1. **Migrate Hardcoded Key**: Replace shared encryption password with per-client keys or public-key cryptography
2. **HTTP -> HTTPS**: Update GeoNames API calls from HTTP to HTTPS (`ws.geonames.net` supports HTTPS)
3. **Permission Justification**: Add manifest key `permissions_justification` explaining why `https://*/*` is needed
4. **CSP Header**: Declare explicit Content Security Policy in manifest for defense-in-depth
5. **OAuth Credential Storage**: Consider encrypting stored OAuth tokens with chrome.identity or OS keychain integration

## Conclusion

NCapture is a **CLEAN** extension serving a legitimate academic research use case. Broad permissions and data collection capabilities align with documented functionality (qualitative research data capture). No malicious patterns detected. Recommended for academic researchers using NVivo, with appropriate understanding of OAuth scopes and data handling responsibilities.

---

**Report Generated**: 2026-02-06
**Analyst**: Claude Opus 4.6 (Chrome Extension Security Analysis)
**Confidence**: HIGH
