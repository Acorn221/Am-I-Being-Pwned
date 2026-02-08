# Security Analysis Report: Soda PDF Viewer Extension

## Extension Metadata
- **Extension ID**: achogidmbhmofkmpgamphmlebdhgkdhc
- **Name**: Soda PDF Viewer: Edit, Convert, Compress PDF files
- **Version**: 1.0.2.90
- **Manifest Version**: 3
- **Estimated Users**: ~600,000
- **Developer**: Soda PDF (Avanquest/LULU Software)

## Executive Summary

**Overall Risk Rating: LOW**

Soda PDF Viewer is a legitimate PDF management extension from an established software company (Avanquest). The extension serves as a browser interface to redirect PDF files to Soda PDF's online editing platform (tools.sodapdf.com).

**Key Findings:**
- **No malicious behavior detected** - Extension operates transparently as a PDF viewer/redirector
- **Legitimate telemetry** - Standard usage analytics via Google Analytics 4 and Avanquest tracking
- **Appropriate permissions** - All permissions are justified for PDF interception and user authentication
- **PDF interception is expected** - Extension intercepts PDFs to redirect to online editor (documented functionality)
- **No data harvesting** - No evidence of keylogging, XHR/fetch hooking, or SDK injection beyond standard telemetry
- **Clean authentication flow** - Uses standard OAuth2/OIDC for user login via accounts.avanquest.com

The extension is a clean, commercial product that functions as advertised - intercepting PDF files and redirecting them to Soda PDF's web-based editing platform.

---

## Detailed Vulnerability Analysis

### 1. PDF URL Interception (INFORMATIONAL)

**Severity**: INFORMATIONAL
**Files**: `background.js` (lines 2598-2664), `pdf-interceptor.js`
**Verdict**: EXPECTED BEHAVIOR - NOT A VULNERABILITY

**Description**:
Extension uses `chrome.webRequest.onHeadersReceived` to intercept PDF files and redirect to Soda PDF's online viewer.

**Code Evidence**:
```javascript
// background.js:2598
chrome.webRequest.onHeadersReceived.addListener(function (details) {
    const id = details.tabId;
    if (details.method !== 'GET' || !self.isPdfFile(details))
        return;
    let viewerUrl;
    if (!details.url.includes("file:///")) {
        if (details.url.includes("sodapdf.com/") || details.url.includes("chrome://downloads/")) {
            return;
        }
        else {
            viewerUrl = self.getViewerUrl(details.url);
            // Redirect to: https://tools.sodapdf.com/url?url={pdfUrl}&partner=chrome-ext
            chrome.tabs.update(findedTab.id, { url: viewerUrl });
        }
    }
}, {
    urls: ['<all_urls>'],
    types: ['main_frame', 'sub_frame'],
}, ['responseHeaders']);
```

**Analysis**:
- This is the **documented functionality** of a PDF viewer extension
- Extension transparently redirects PDFs to `tools.sodapdf.com/url?url={pdfUrl}&partner=chrome-ext`
- Does not exfiltrate PDF content directly - only redirects browser to online viewer
- User expects this behavior when installing a "PDF Viewer" extension
- Excludes own domains (sodapdf.com) and Chrome downloads to prevent loops

**Risk**: None - This is legitimate and expected behavior for a PDF viewer extension.

---

### 2. Cookie Synchronization (LOW)

**Severity**: LOW
**Files**: `main-AZSUOQ6L.js` (lines 35683-35688, 35852-35857), `background.js` (lines 2217-2226)
**Verdict**: LEGITIMATE - Session management for auth

**Description**:
Extension reads and writes cookies to synchronize authentication state between extension and web platform.

**Code Evidence**:
```javascript
// main-AZSUOQ6L.js:35683
chrome.cookies.getAll({
    domain: ".sodapdf.com"
}, cookies => {
    let sessionCookie = this.appConfig.authConfig.oidc?.sessionCookie ?? "";
    if (sessionCookie) {
        let cookie = cookies.find(c => c.name === sessionCookie);
        // Returns session ID
    }
});

// Cookie writing for auth sync
chrome.cookies.set({
    domain: ".sodapdf.com",
    url: `https://${_e.REDIRECT_URL}`,
    name: i.sessionCookie,
    value: sessionId
});

// Cookie change listener for session monitoring
chrome.cookies.onChanged.addListener(function(changeInfo) {
    const cookie = changeInfo.cookie;
    if (cookie.domain === '.sodapdf.com' && cookie.name === 'id.session') {
        // Track session changes
    }
});
```

**Analysis**:
- **Legitimate use case**: OAuth2/OIDC session synchronization between extension and web app
- **Scoped to own domain**: Only accesses `.sodapdf.com` cookies (not third-party domains)
- **Session cookie**: `id.session` is the OIDC session token
- **No credential harvesting**: Not reading cookies from external sites
- Standard practice for extensions that integrate with web authentication

**Risk**: Low - Normal session management for authenticated features.

---

### 3. Usage Analytics & Telemetry (LOW)

**Severity**: LOW
**Files**: `main-AZSUOQ6L.js` (lines 14489-14502, 14595-14606)
**Verdict**: LEGITIMATE - Standard commercial telemetry

**Description**:
Extension collects usage analytics via Google Analytics 4 and Avanquest proprietary tracking.

**Analytics Endpoints**:
1. **Google Analytics 4**: `https://www.google-analytics.com/mp/collect`
2. **Avanquest Tracking**: `https://avqservice.avanquest.com/api/v1/services/`

**Code Evidence**:
```javascript
// Google Analytics 4 integration
// main-AZSUOQ6L.js:14595
GA_ENDPOINT = "https://www.google-analytics.com/mp/collect";
MEASUREMENT_ID; // G-WHMBTXFZ7C
API_SECRET = "8UmfyhiZR6-jUcaBrQ8tmQ";

track(eventName, params) {
    fetch(`${this.GA_ENDPOINT}?measurement_id=${this.MEASUREMENT_ID}&api_secret=${this.API_SECRET}`, {
        method: "POST",
        body: JSON.stringify({
            client_id: await this.clientProvider.getOrCreateClientId(),
            events: [{ name: eventName, params: params }]
        })
    });
}

// Avanquest proprietary telemetry
// main-AZSUOQ6L.js:14489
send(eventType, data) {
    var endpoint = "https://avqservice.avanquest.com/api/v1/services/";
    fetch(endpoint + eventType, {
        method: "post",
        headers: {
            "Access-Control-Allow-Origin": "*",
            "Accept": "application/json",
            "Content-Type": "application/json"
        },
        body: data  // Contains: visitorId, culture, browser UA, click events, session info
    });
}

// Client ID generation (stored locally)
// main-AZSUOQ6L.js:14430
getOrCreateClientId() {
    let clientId = (await chrome.storage.local.get("clientId")).clientId;
    if (!clientId) {
        clientId = self.crypto.randomUUID();
        await chrome.storage.local.set({ clientId: clientId });
    }
    return clientId;
}
```

**Data Collected**:
- **User actions**: Click events (convert, merge, edit, compress, open)
- **Browser metadata**: User agent, culture/language
- **Session data**: Visitor ID (UUID), session ID, referral source
- **Extension events**: Button clicks, navigation events
- **NO sensitive data**: No keystrokes, page content, passwords, or personal info

**Analysis**:
- **Standard commercial telemetry** - Common for SaaS products to track feature usage
- **No exfiltration of user content** - Only tracks UI interactions and session metadata
- **Transparent endpoints** - Uses well-known GA4 and Avanquest's documented API
- **Hardcoded GA4 API secret** is a minor issue but not security-critical (public measurement protocol)

**Risk**: Low - Typical product analytics, no PII or sensitive data collection.

---

### 4. Content Script Behavior (CLEAN)

**Severity**: NONE
**Files**: `dom-listener.js`, `content-script.js`, `pdf-interceptor.js`
**Verdict**: CLEAN - Minimal, legitimate DOM interaction

**Description**:
Content scripts perform minimal, benign operations:

**Content Script 1 - dom-listener.js** (runs on `<all_urls>`):
```javascript
// Watches for Soda PDF button on sodapdf.com pages
const observer = new MutationObserver((mutations, observer) => {
    const button = body.querySelector('.button-extension');
    if (button) {
        button.setAttribute('id', 'installed-extension');
        button.addEventListener('click', () => {
            chrome.runtime.sendMessage({ message_key: 'notification' });
        });
        observer.disconnect();
    }
});
observer.observe(body, { childList: true, subtree: true });
```

**Content Script 2 - content-script.js** (runs on `https://*.sodapdf.com/silent-refresh.html*`):
```javascript
// OAuth silent refresh handler
chrome.runtime.sendMessage({
    message_key: MESSAGE_KEY.LOCATION_SEARCH,
    message_value: document.location.search
});
```

**Content Script 3 - pdf-interceptor.js** (runs on `file:///*.pdf`):
```javascript
// Detects local PDF files
if (document.contentType === 'application/pdf') {
    const pdfUrl = window.location.href;
    chrome.runtime.sendMessage({ pdfUrl: pdfUrl });
}
```

**Analysis**:
- **No keylogging** - No keyboard event listeners
- **No form scraping** - No input field monitoring
- **No XHR/fetch hooking** - No network interception in content scripts
- **No DOM scraping** - Only queries for own UI elements on sodapdf.com
- **No SDK injection** - No third-party scripts injected into pages
- **Scoped interactions** - Most scripts run only on own domains (sodapdf.com)

**Risk**: None - Clean, minimal content script behavior.

---

### 5. Third-Party Library Usage (INFORMATIONAL)

**Severity**: INFORMATIONAL
**Files**: `chunk-2F5QQJAW.js`, `polyfills-SCHOHYNV.js`
**Verdict**: CLEAN - Standard libraries

**Libraries Detected**:
1. **Lottie (Bodymovin)** - Animation library for SVG/Canvas animations (`chunk-2F5QQJAW.js`)
2. **RxJS** - Reactive extensions library for async operations (`background.js`)
3. **Angular 17** - Web framework for UI (`main-AZSUOQ6L.js`)
4. **Azure Storage SDK** - For cloud file storage integration (`main-AZSUOQ6L.js`)

**Analysis**:
- All libraries are legitimate, open-source, and widely used
- No malicious SDKs detected (no Sensor Tower, Pathmatics, etc.)
- Lottie library contains `eval()` for animation expressions (expected, not malicious)
- Azure SDK includes Proxy objects for API client (benign, standard SDK pattern)

**Risk**: None - Standard, legitimate dependencies.

---

### 6. Authentication Flow (CLEAN)

**Severity**: NONE
**Files**: `background.js` (lines 1881-1906), `main-AZSUOQ6L.js` (lines 13973-13993)
**Verdict**: CLEAN - Standard OAuth2/OIDC

**Authentication Configuration**:
```javascript
authConfig = {
    domain: '.sodapdf.com',
    oidc: {
        sessionCookie: 'id.session',
        config: {
            issuer: `https://accounts.avanquest.com`,  // OIDC provider
            redirectUri: `https://tools.sodapdf.com/silent-refresh.html`,
            clientId: 'sodapdf-browser-ext',
            responseType: 'code',
            scope: 'openid profile email offline_access pm-ms',
            silentRefreshRedirectUri: `https://tools.sodapdf.com/silent-refresh.html`
        }
    }
};
```

**Authentication Endpoints**:
- **OIDC Issuer**: `accounts.avanquest.com` (Avanquest's identity platform)
- **OAuth Domain**: `oauth.sodapdf.com` (OAuth2 authorization server)
- **API Domain**: `api-pw.sodapdf.com` (PDF processing API)
- **Redirect Domain**: `paygw.sodapdf.com` (Payment gateway)

**Analysis**:
- **Standard OAuth2/OIDC flow** - Industry best practice for authentication
- **No credential harvesting** - Extension doesn't handle passwords directly
- **Silent refresh** implemented for seamless session renewal
- **Appropriate scopes** - Only requests profile, email, and service access
- All domains controlled by Avanquest/Soda PDF (legitimate owner)

**Risk**: None - Properly implemented OAuth2/OIDC authentication.

---

### 7. Manifest Permissions Analysis (JUSTIFIED)

**Permissions Requested**:
```json
{
  "permissions": [
    "tabs",           // ✓ Required for PDF tab redirection
    "cookies",        // ✓ Required for auth session sync
    "storage",        // ✓ Required for settings & client ID
    "webRequest",     // ✓ Required for PDF interception
    "webNavigation",  // ✓ Required for navigation events
    "system.display"  // ✓ Required for popup positioning
  ],
  "host_permissions": [
    "*://*/*"         // ✓ Required to intercept PDFs from any domain
  ]
}
```

**Permission Justification**:
- **webRequest** - Core functionality: intercept PDF downloads to redirect to viewer
- **cookies** - Legitimate use: sync OAuth session between extension and web app
- **tabs** - Required to update tab URLs when redirecting PDFs
- **storage** - Stores user preferences and anonymous client ID
- **webNavigation** - Monitors navigation for login flow management
- **system.display** - Used for positioning popup windows
- **host_permissions** (*://*/*) - Necessary to intercept PDFs from any website

**No Content Security Policy** - Default MV3 CSP applies (no eval, inline scripts blocked)

**Analysis**: All permissions are justified and used for documented functionality. No excessive or suspicious permissions.

---

## False Positive Analysis

| Pattern | Location | Explanation | Verdict |
|---------|----------|-------------|---------|
| `eval()` in Lottie | chunk-2F5QQJAW.js:6824 | Lottie animation library uses eval for expression functions in After Effects animations | **False Positive** - Standard Lottie behavior |
| `Proxy` objects | main-AZSUOQ6L.js:17660, 17760 | Azure Storage SDK uses Proxy for HTTP client API | **False Positive** - Standard Azure SDK pattern |
| `postMessage` calls | chunk-2F5QQJAW.js | Lottie worker communication for rendering | **False Positive** - Web Worker messaging |
| Hardcoded API_SECRET | main-AZSUOQ6L.js:14597 | Google Analytics 4 Measurement Protocol API secret (8UmfyhiZR6-jUcaBrQ8tmQ) | **Not Critical** - GA4 MP secrets are semi-public for client-side tracking |
| Cookie access | Multiple files | OAuth session sync for own domain (.sodapdf.com) | **False Positive** - Legitimate auth flow |
| PDF interception | background.js | Core documented functionality of PDF viewer extension | **False Positive** - Expected behavior |

---

## API Endpoints & Data Flow Summary

### External API Endpoints

| Endpoint | Purpose | Data Transmitted | Frequency |
|----------|---------|------------------|-----------|
| `https://www.google-analytics.com/mp/collect` | Google Analytics 4 telemetry | Client ID (UUID), event names, UI interactions | On user actions |
| `https://avqservice.avanquest.com/api/v1/services/` | Avanquest proprietary analytics | Visitor ID, browser UA, click events, culture | On user actions |
| `https://avqtools.avanquest.com/js/v3/sodapdf.com.min.js` | Avanquest tracking script loader | N/A (script inclusion) | On extension load |
| `https://accounts.avanquest.com` | OAuth2/OIDC authentication | OAuth authorization codes (standard flow) | On login/refresh |
| `https://oauth.sodapdf.com/api` | Auth API | User auth tokens (Bearer) | On authenticated requests |
| `https://api-pw.sodapdf.com` | PDF processing API | PDF metadata, user session | When processing PDFs |
| `https://tools.sodapdf.com/url` | PDF viewer redirect target | PDF URL parameters | On PDF interception |
| `https://paygw.sodapdf.com` | Payment/subscription gateway | User subscription status | On premium features |

### Data Flow Summary

**Outbound Data**:
1. **User Actions** → Google Analytics 4 (anonymous usage metrics)
2. **User Actions** → Avanquest Analytics (session metadata, clicks)
3. **PDF URLs** → Soda PDF Viewer (redirect to online editor)
4. **OAuth Tokens** → Avanquest Auth Platform (standard auth flow)
5. **Client ID** (UUID) → Local storage (persisted)

**Inbound Data**:
1. **OAuth Tokens** ← Avanquest (for authenticated features)
2. **User Profile** ← Avanquest (name, email, photo)
3. **Subscription Status** ← Soda PDF API (premium features)

**No Evidence Of**:
- ❌ Keylogging or input monitoring
- ❌ XHR/fetch hooking or traffic interception
- ❌ Extension enumeration or killing
- ❌ Cookie harvesting from third-party sites
- ❌ Ad injection or search manipulation
- ❌ Residential proxy infrastructure
- ❌ Market intelligence SDKs (Sensor Tower, etc.)
- ❌ AI conversation scraping
- ❌ Browsing history collection (beyond PDF URLs)
- ❌ Remote kill switches or obfuscation

---

## Security Recommendations

### For Users:
1. **Extension works as advertised** - No hidden malicious functionality
2. **Privacy consideration** - PDF URLs you open are sent to Soda PDF servers for processing (expected for cloud PDF editor)
3. **Telemetry can be avoided** - Use uBlock Origin to block analytics domains if desired:
   - `||avqservice.avanquest.com^`
   - `||avqtools.avanquest.com^`
4. **Alternative** - If privacy is paramount, use local PDF viewers (e.g., browser built-in or desktop apps)

### For Developers (Soda PDF):
1. ✅ **Good**: Using OAuth2/OIDC for authentication (industry standard)
2. ✅ **Good**: Manifest V3 compliance
3. ⚠️ **Minor**: GA4 API_SECRET is hardcoded (low risk but could use environment variables)
4. ✅ **Good**: Minimal content script footprint
5. ✅ **Good**: No obfuscation beyond standard webpack bundling

---

## Overall Risk Assessment

### Risk Rating: **LOW / CLEAN**

**Breakdown**:
- **Malicious Behavior**: ❌ None detected
- **Data Exfiltration**: ✅ Only standard telemetry (usage analytics)
- **Privacy Impact**: 🟡 Low-Medium (PDF URLs shared with service, standard analytics)
- **Security Risks**: ✅ None identified
- **Legitimacy**: ✅ Established commercial product (Avanquest/LULU Software)
- **Transparency**: ✅ Functionality matches description

**Comparison to Known Threats**:
- **Unlike Urban VPN**: No social media scraping, no XHR/fetch hooking
- **Unlike StayFree/StayFocusd**: No Sensor Tower SDK, no AI conversation harvesting
- **Unlike Flash Copilot**: No ChatGPT session token theft, no screenshot exfiltration
- **Unlike VeePN**: No extension enumeration/killing, no GA proxy exclusion
- **Unlike YouBoost**: No ad injection, no search manipulation

**Verdict**: Soda PDF Viewer is a **legitimate, clean extension** that operates transparently as a PDF viewer/redirector to the company's online platform. All permissions and network activity are justified for the documented functionality. No malicious patterns detected.

---

## Files Analyzed

**Manifest & Config**:
- `/deobfuscated/manifest.json` - Manifest V3, appropriate permissions
- `/deobfuscated/background.js` (45,168 lines) - Service worker, PDF interception, auth
- `/deobfuscated/main-AZSUOQ6L.js` (37,268 lines) - Angular UI bundle

**Content Scripts**:
- `/deobfuscated/dom-listener.js` - Button detection on sodapdf.com
- `/deobfuscated/content-script.js` - OAuth silent refresh handler
- `/deobfuscated/pdf-interceptor.js` - Local PDF file detection

**Libraries**:
- `/deobfuscated/chunk-2F5QQJAW.js` - Lottie animation library
- `/deobfuscated/polyfills-SCHOHYNV.js` - Browser compatibility polyfills

**Other**:
- `/deobfuscated/open-dialog.js` - Settings dialog for file URL permissions

---

## Conclusion

**Soda PDF Viewer (achogidmbhmofkmpgamphmlebdhgkdhc) is CLEAN.**

This extension is a legitimate commercial product from Avanquest/LULU Software that intercepts PDF files and redirects them to Soda PDF's online editing platform. All functionality is transparent and matches the extension's description. Standard usage analytics are collected (Google Analytics + Avanquest telemetry), but no sensitive data harvesting, malicious SDKs, or suspicious behavior was detected.

**Recommendation**: Safe to use for general users. Privacy-conscious users should be aware that PDF URLs are sent to Soda PDF servers for processing (expected behavior for cloud PDF editors).

---

**Analysis Date**: 2026-02-06
**Analyst**: Claude Opus 4.6 via Claude Code
**Methodology**: Static code analysis, manifest review, network endpoint mapping, behavioral pattern detection
