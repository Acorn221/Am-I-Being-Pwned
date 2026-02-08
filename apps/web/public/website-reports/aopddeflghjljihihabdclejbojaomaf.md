# Vulnerability Report: AnyDoc Translator - Translate Web and PDF

## Extension Metadata
- **Extension ID**: aopddeflghjljihihabdclejbojaomaf
- **Extension Name**: AnyDoc Translator - Translate Web and PDF
- **Version**: 1.4.10
- **User Count**: ~7,000,000
- **Manifest Version**: 3
- **Developer**: WPS (Kingsoft Office)

## Executive Summary

AnyDoc Translator is a legitimate translation extension developed by WPS (Kingsoft Office) that provides document and web translation services. The extension implements XMLHttpRequest/fetch hooking for subtitle extraction on video platforms (YouTube, Prime Video, Ted, Coursera, Khan Academy), uses extensive permissions, and communicates with multiple WPS backend services. While the extension has broad access capabilities and hooks network requests, the functionality appears aligned with its stated purpose of translation services.

**Overall Risk Assessment: MEDIUM**

The extension is functionally legitimate but implements techniques (XHR hooking, broad permissions, extensive data collection) that warrant monitoring. The primary concerns are scope of data access rather than outright malicious behavior.

## Vulnerability Details

### 1. XMLHttpRequest and Fetch API Hooking
**Severity**: MEDIUM
**Files**: `/public/subtitle/script/inject.js`
**Verdict**: Legitimate but invasive

**Description**:
The extension injects code that completely overrides `XMLHttpRequest.prototype.open`, `XMLHttpRequest.prototype.send`, `XMLHttpRequest.prototype.setRequestHeader`, and `window.fetch` to intercept network traffic from specific video platforms.

**Code Evidence**:
```javascript
const c=XMLHttpRequest.prototype,H=c.open,g=c.send,v=c.setRequestHeader,R=window.fetch;
function w(){c.open=function(t,e,s,i,a){const n=this;return n._method=t,n._url=typeof e=="string"?e:e.toString(),n._requestHeaders={},n._startTime=new Date().toISOString(),H.call(this,t,e,s??!0,i,a)},
```

**Target Sites**:
- YouTube (`/youtube\.com\/api\/timedtext/`, `/youtube\.com\/youtubei\/v1\/player/`)
- Prime Video (`/cf-timedtext\.aux\.pv-cdn\.net/`, `/atv-ps-eu\.amazon\.co\.uk\/cdp\/catalog\/GetPlaybackResources/`)
- Ted (`/hls\.ted\.com\/project_masters\/.*?\/subtitles\/.*?\/full\.vtt/`)
- Coursera (`/coursera\.org\/api\/subtitleAssetProxy/`)
- Khan Academy (`/khanacademy\.org\/api\/internal\/graphql\/GetSubtitles/`)

**Analysis**: The hooking is specifically targeted at subtitle/caption endpoints for legitimate translation functionality. However, the technique grants complete visibility into network requests on these platforms, including request headers, response headers, and response data.

---

### 2. Excessive Permissions
**Severity**: MEDIUM
**Files**: `manifest.json`
**Verdict**: Overly broad but justified for functionality

**Permissions Requested**:
- `host_permissions: ["*://*/*"]` - Access to ALL websites
- `contextMenus` - Right-click menu integration
- `storage` + `unlimitedStorage` - Local data storage
- `clipboardWrite` - Clipboard access
- `tabs` + `activeTab` - Tab information
- `scripting` - Dynamic code injection
- `cookies` - Cookie access
- `nativeMessaging` - Native app communication

**Content Scripts**: Injected on `*://*/*` (all websites) with `all_frames: true`

**Analysis**: The permissions are extremely broad. While document/web translation justifies wide access, the `cookies` and `nativeMessaging` permissions combined with universal host access creates significant attack surface. Cookie access appears limited to WPS domains (`_anydoc_device_id`, `i18n_redirected`).

---

### 3. Extensive Third-Party Communication
**Severity**: LOW-MEDIUM
**Files**: Multiple asset files
**Verdict**: Expected for cloud translation service

**API Endpoints Identified**:

**WPS/Kingsoft Services**:
- `https://api.wps.com/ktranslator` - Translation API
- `https://api.wps.com/utils/geo/me` - Geolocation
- `https://account.wps.com/translateLogin` - Authentication
- `https://permits.wps.com` - Permissions/licensing
- `https://dcapi.wps.com/kstorage-api` - Storage API
- `https://ovs-shopwindow-server.wps.com` - Shop/upgrade prompts
- `https://params.wps.com` - Configuration parameters
- `https://checkout.wps.com` - Payment processing

**Third-Party Translation Engines**:
- `https://translate.googleapis.com/translate` - Google Translate
- `https://translate-pa.googleapis.com/v1/translateHtml` - Google Translate (HTML)
- `https://api-edge.cognitive.microsofttranslator.com/translate` - Microsoft Translator
- `https://edge.microsoft.com/translate/auth` - Microsoft auth
- `https://translate.yandex.net/api/v1/tr.json/translate` - Yandex Translate
- `https://transmart.qq.com/api/imt` - Tencent Transmart

**Analytics**:
- `https://www.google-analytics.com/mp/collect` - Google Analytics 4

**Analysis**: The extension uses multiple translation backends (Google, Microsoft, Yandex, Tencent) which is standard for quality/failover. All WPS endpoints use HTTPS. The extensive WPS infrastructure suggests comprehensive telemetry and usage tracking.

---

### 4. Cookie Access from WPS Domains
**Severity**: LOW
**Files**: `assets/academia-Cma1O4UX.js`
**Verdict**: Limited and appropriate

**Code Evidence**:
```javascript
cookies.get({url:`https://${te.webHost}`,name:"_anydoc_device_id"})
cookies.get({url:`https://${te.webHost}`,name:"i18n_redirected"})
```

**Analysis**: Cookie access is restricted to WPS-owned domains for device identification and localization preferences. No evidence of harvesting third-party cookies or session tokens from other sites.

---

### 5. Externally Connectable to Other Extensions
**Severity**: LOW
**Files**: `manifest.json`
**Verdict**: Potential inter-extension communication risk

**Configuration**:
```json
"externally_connectable": {
  "ids": [
    "kdpelmjpfafjppnhbloffcjpeomlnpah",
    "mjdgandcagmikhlbjnilkmfnjeamfikk"
  ]
}
```

**Analysis**: Allows two specific extensions to communicate with this extension. The extension IDs were not found referenced in the code, suggesting these may be related WPS products or legacy integrations. No evidence of exploitation, but creates potential attack surface if those extensions are compromised.

---

### 6. Online Parameter Fetching
**Severity**: LOW
**Files**: `assets/academia-Cma1O4UX.js`
**Verdict**: Standard remote configuration

**Evidence**: Extension includes `GET_ONLINE_PARAMS` message type for fetching remote configuration. Uses WPS `params.wps.com` and `ovs-shopwindow-server.wps.com` endpoints.

**Analysis**: Remote configuration is common for feature flags, A/B testing, and gradual rollouts. No evidence of kill switch or malicious remote code execution capabilities. Configuration appears limited to UI/UX parameters and shop promotions.

---

## False Positives

| Pattern | Reason | Verdict |
|---------|--------|---------|
| Vue.js framework code | Standard Vue 3 reactivity system | ✅ False Positive |
| SVG namespace references | Standard SVG/HTML manipulation for translation UI | ✅ False Positive |
| MathML namespace | Document format support | ✅ False Positive |
| Google Analytics integration | Standard telemetry for legitimate product | ✅ False Positive |
| Axios HTTP library | Standard HTTP client, no hooking beyond library internals | ✅ False Positive |

---

## API Endpoints Table

| Endpoint | Purpose | Risk Level |
|----------|---------|------------|
| api.wps.com/ktranslator | Translation service | LOW |
| permits.wps.com | License verification | LOW |
| account.wps.com/translateLogin | User authentication | LOW |
| ovs-shopwindow-server.wps.com | Upgrade promotions | LOW |
| translate.googleapis.com | Google translation | LOW |
| api-edge.cognitive.microsofttranslator.com | Microsoft translation | LOW |
| transmart.qq.com/api/imt | Tencent translation | LOW |
| translate.yandex.net | Yandex translation | LOW |
| www.google-analytics.com/mp/collect | Usage analytics | LOW |

---

## Data Flow Summary

1. **User Interaction**: User selects text, uploads document, or triggers translation
2. **Content Script**: Captures DOM content, text selection, or document data
3. **Background Service Worker**: Receives data, determines target language
4. **Translation Engine Selection**: Routes to appropriate backend (Google/Microsoft/Yandex/Tencent/WPS)
5. **API Request**: Sends text/document to translation service with language pair
6. **Response Processing**: Receives translation, applies to DOM or returns to popup
7. **Telemetry**: Usage data sent to WPS analytics and Google Analytics

**Data Collected**:
- Selected/translated text content
- Document content (PDFs, DOCs)
- Page URLs (for context)
- Language preferences
- Usage statistics
- Device identifiers
- Geolocation (country-level)

**Data Transmission**: All transmitted to WPS servers and third-party translation APIs. Privacy policy should be reviewed for data retention and usage terms.

---

## Observations

### Positive Security Practices
1. ✅ Uses Manifest V3 (modern security model)
2. ✅ All API endpoints use HTTPS
3. ✅ No eval/Function/new Function usage detected
4. ✅ No base64-encoded payload obfuscation
5. ✅ Cookie access limited to first-party WPS domains
6. ✅ XHR hooking targeted only at specific subtitle endpoints

### Security Concerns
1. ⚠️ Universal host permissions (`*://*/*`)
2. ⚠️ Content scripts injected on all websites with all_frames
3. ⚠️ Network request hooking (XMLHttpRequest/fetch override)
4. ⚠️ Native messaging permission (unused in reviewed code)
5. ⚠️ Extensive telemetry collection
6. ⚠️ Multiple third-party data processors (Google, Microsoft, Yandex, Tencent)

### Red Flags NOT Found
- ❌ No residential proxy infrastructure
- ❌ No extension enumeration/killing behavior
- ❌ No market intelligence SDKs (Sensor Tower, Pathmatics)
- ❌ No ad/coupon injection
- ❌ No cryptocurrency mining
- ❌ No credential harvesting beyond legitimate auth
- ❌ No keylogging beyond translation input fields
- ❌ No remote code execution mechanisms

---

## Overall Risk Assessment: MEDIUM

**Rationale**:
AnyDoc Translator is a legitimate translation extension from WPS (Kingsoft), a reputable office software company. The extension's broad permissions and XHR/fetch hooking are functionally justified for document translation and subtitle translation features. However, the scope of access (all websites, all frames, cookies, native messaging) combined with data transmission to multiple third parties creates significant privacy and security surface area.

The extension does NOT exhibit malicious behaviors such as:
- Data exfiltration beyond stated translation functionality
- Residential proxy operations
- Ad injection or affiliate hijacking
- Market intelligence data collection
- Extension interference
- Obfuscated malicious payloads

**Recommendation**:
- **For General Users**: ACCEPTABLE with privacy awareness. Users should understand that translated content is sent to WPS servers and third-party translation APIs (Google, Microsoft, Yandex, Tencent). Review WPS privacy policy.
- **For Privacy-Conscious Users**: CAUTION. The extension has visibility into all web traffic on video platforms and broad access to page content across all sites.
- **For Enterprise**: Evaluate data handling policies. Consider restricting to specific domains if DLP is a concern.

The MEDIUM risk rating reflects the extension's invasive technical implementation and broad data access, despite legitimate functionality. Users must trust WPS/Kingsoft and multiple translation service providers with their browsing data and translated content.

---

**Analysis Date**: 2026-02-08
**Analyst**: Claude Code Agent (Sonnet 4.5)
