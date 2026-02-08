# WPS PDF Extension Security Analysis

## Metadata
- **Extension Name**: WPS PDF - Read, Edit, Fill, Convert, and AI Chat PDF with Ease
- **Extension ID**: kdpelmjpfafjppnhbloffcjpeomlnpah
- **User Count**: ~8,000,000
- **Version**: 1.0.0.52
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-08

## Executive Summary

WPS PDF is a legitimate PDF viewer/editor extension with ~8M users that requests extensive permissions including `<all_urls>`, cookies, webRequest, native messaging, and more. The extension intercepts PDF downloads, injects content scripts into Google Scholar, and communicates with a native WPS desktop application. While the extension has invasive permissions and extensive data collection capabilities, it appears to serve its intended purpose of PDF viewing/editing. The primary concerns are the broad host permissions, comprehensive analytics tracking, native messaging without clear user disclosure, and PDF download interception that could confuse users.

**Risk Level: MEDIUM**

## Vulnerability Details

### 1. MEDIUM - Excessive Host Permissions with Broad Access
**Severity**: MEDIUM
**Files**: `manifest.json`
**Code**:
```json
"host_permissions": ["<all_urls>"],
"permissions": [
  "webRequest",
  "webNavigation",
  "storage",
  "tabs",
  "nativeMessaging",
  "declarativeNetRequest",
  "gcm",
  "cookies"
]
```

**Description**: The extension requests `<all_urls>` host permissions combined with webRequest, cookies, and tabs permissions. This grants the ability to intercept and modify network requests on all websites, access cookies across all domains, and manipulate tab behavior globally.

**Actual Usage**:
- Intercepts PDF downloads via `webRequest.onHeadersReceived` for HTTP/HTTPS URLs
- Intercepts file:// protocol PDF access via `webRequest.onBeforeRequest`
- Redirects users to WPS PDF viewer when PDFs are detected
- Injects UI elements on Google Scholar to open PDFs with WPS

**Verdict**: While the permissions are invasive, they are used for the extension's core PDF interception functionality. However, the broad scope creates significant attack surface if the extension were compromised.

---

### 2. MEDIUM - Comprehensive Analytics and User Tracking
**Severity**: MEDIUM
**Files**: `background.js`
**Code**:
```javascript
const J=async(e="",t={})=>{
  const n={...t},
  r=JSON.stringify({
    client_id:t.chrome_instance_id||"0",
    user_id:t.user_id||"0",
    events:[{name:e,params:n}]
  });
  return x("https://www.google-analytics.com/mp/collect?api_secret=fT9ipFNpRj64Htt2diqTCQ&measurement_id=G-05CH7KGQPS",
    {method:"POST",body:r})
};

#f=async(e="")=>{
  const t=await we(),  // getUserId
  n=await ye(),  // getInstallId
  r=await be(),  // getDeviceId
  i=await ge(),  // getChromeInstanceId
  o=await ve(),  // getCountryCode
  s=await xe(),  // getExtensionVersion
  a=await _e(),  // getBrowser
  c=await Se(),  // getBrowserVersion
  u=await Ee(),  // getChannel
  l=await Re(),  // getOS
  d=await Te(),  // getInstallSrc
  f=Oe();        // getSource
  return {
    user_id:t, install_id:n, device_id:r, chrome_instance_id:i,
    country_code:o, extension_version:s, browser:a, browser_version:c,
    channel:u, os:l, install_src:d, source:f, ...this.commonParams||{}
  }
};
```

**Description**: The extension collects extensive telemetry including user_id, device_id, chrome_instance_id, country_code, browser fingerprint, OS, and installation source. All events are sent to Google Analytics with detailed context.

**Tracked Events**:
- `oversea_pdf_plugin_installed` - Installation events
- `oversea_pdf_plugin_background_active` - Background script activation
- `oversea_pdf_plugin_adobe_detected` - Adobe PDF viewer detection
- `oversea_pdf_plugin_fe_intercept` - PDF interception
- `oversea_pdf_plugin_click` - Button clicks with button names
- `oversea_pdf_plugin_scholar_open` - Google Scholar PDF opens
- `oversea_pdf_plugin_page` - Page injection events

**Verdict**: The analytics are extensive but appear to be for product improvement and user behavior analysis. Users can disable this via preferences (`sendUsageData` flag). This is typical for a commercial product but should be more transparently disclosed.

---

### 3. MEDIUM - Native Messaging Without Clear Disclosure
**Severity**: MEDIUM
**Files**: `background.js`, `manifest.json`
**Code**:
```javascript
le=new class{
  constructor(e="com.wps.pdfextension",t=!1,n=void 0){
    this.#t(e,t,n)
  }
  connect=()=>new Promise((async(n,r)=>{
    this.#i=Q.connectNative(this.#r),  // Connect to native host
    this.#u()
  }));
  getInfo=async()=>{
    const t=F()?"edge":"chrome";
    e=await this.#a("get_info",{from:t});
    return e
  };
  getAutoLoginUrl=async()=>{
    const t=await this.#a("get_redirect_url",{url:"https://www.wps.com/"});
    e=X.hexStringToString(t.redirect_url)
  };
}("com.wps.pdfextension",!1)
```

**Description**: The extension uses native messaging to communicate with a desktop WPS PDF application (`com.wps.pdfextension`). This allows the extension to:
- Query device_id, host_version, channel from desktop app
- Request redirect URLs for auto-login functionality
- Call WPS functions via `do_wps_func_call`

**Security Implications**:
- Native messaging creates a bridge between browser and desktop application
- Desktop app could have broader system access than browser extension
- Auto-login URL generation could be used for session hijacking if native app is compromised
- No clear user disclosure about desktop app communication

**Verdict**: While native messaging is used legitimately to integrate with WPS desktop software, it creates an expanded attack surface. If the native host is compromised, the extension could be used as a vector for further attacks.

---

### 4. LOW - PDF Download Interception Could Confuse Users
**Severity**: LOW
**Files**: `background.js`
**Code**:
```javascript
const Ve=(e,t)=>{
  const n=(e=>{
    const t=$e(e,"content-type");
    return t?t.value.toLowerCase().split(";",1)[0].trim():null
  })(e),
  i="application/pdf"===n,
  o=Ke(t);
  if(i&&o)return!0;
  // Intercept PDF if content-type is PDF and not attachment
};

const Je=async(e,t)=>{
  const n=ke(t);  // Redirect to WPS viewer
  if(qe||await(async()=>{
    // Check if Adobe viewer is active
  })()){
    try{
      Me("oversea_pdf_plugin_fe_intercept",{button_name:"adobe_detect_intercept"})
    }catch(e){}
    for(let t=0;t<30;t++)
      try{
        await Fe.updateTabs(e,{url:`${n}&source=detect_intercept`})
      }catch(e){}
  }else Fe.updateTabs(e,{url:n})
};
```

**Description**: The extension automatically intercepts PDF downloads and redirects to WPS viewer. It also detects Adobe PDF viewer and attempts multiple tab updates to override it.

**User Experience Issues**:
- Automatic interception happens without explicit user consent for each PDF
- Multiple retry attempts (30 iterations) to override Adobe viewer
- User preference setting exists but defaults to interception enabled

**Verdict**: This is aggressive behavior but serves the extension's core purpose. Users install this to view PDFs, though the Adobe detection/override is somewhat invasive.

---

### 5. LOW - Google Scholar Content Script Injection
**Severity**: LOW
**Files**: `content-scripts/scholar.js`, `manifest.json`
**Code**:
```javascript
// Injects WPS PDF buttons on Google Scholar PDF links
const o=[
  {text:"Quick guide",mode:"chat_quick_guide",className:"wps-pdf-button"},
  {text:"Chat PDF",mode:"chat_chat",className:"wps-pdf-button chat-pdf"},
  {text:"Translate",mode:"translate",className:"wps-pdf-button translate"}
];

// Opens translator service
"translate"===n.mode?
  window.open(`https://anydoctranslator.toolsmart.ai/academia/translate?plugin=wpsPdf&is_academia=true&pdf_url=${encodeURIComponent(t)}`):
  e.sendMessage({action:"openPdf",url:t,mode:n.mode})
```

**Description**: Content script injects UI elements on Google Scholar pages to provide quick access to WPS PDF features including a translator service.

**Concerns**:
- Modifies third-party website (Google Scholar) UI
- "Translate" button redirects to external service `anydoctranslator.toolsmart.ai`
- PDF URLs are passed to third-party translation service

**Verdict**: This is a value-added feature for academic users. The translate service redirect should be more clearly disclosed, but appears to be a legitimate WPS partner service.

---

## False Positives

| Pattern | Reason | Verdict |
|---------|--------|---------|
| Axios library HTTP client | Standard HTTP client library for API calls | ✓ False Positive |
| CryptoJS library | Used for hashing/UUID generation, not malicious obfuscation | ✓ False Positive |
| UAParser library | Browser/OS detection for telemetry, standard practice | ✓ False Positive |
| Fetch polyfill | Compatibility shim for older browsers | ✓ False Positive |
| Vue.js framework code | Legitimate UI framework, heavily minified but not obfuscated | ✓ False Positive |
| Pinia state management | Standard Vue state library | ✓ False Positive |
| Google Analytics calls | Product analytics, user-configurable | ✓ False Positive |

## API Endpoints

| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `https://www.google-analytics.com/mp/collect` | Analytics/telemetry | User ID, device ID, browser fingerprint, event data |
| `https://api.wps.com/utils/geo/me` | Geolocation lookup | None (receives country code) |
| `https://anydoctranslator.toolsmart.ai/academia/translate` | PDF translation service | PDF URL, plugin identifier |
| `https://wdl1.pcfg.cache.wpscdn.com/` | CDN for WPS resources | None (resource downloads) |
| Native host: `com.wps.pdfextension` | Desktop app integration | Browser type, function calls |

## Data Flow Summary

1. **User Installation**:
   - Generates install_id, chrome_instance_id UUIDs
   - Queries native WPS desktop app for device_id, channel, host_version
   - Sends installation telemetry to Google Analytics
   - Sets uninstall feedback URL to `wps.com/pdf-extension/feedback`

2. **PDF Interception**:
   - Monitors HTTP/HTTPS responses for `Content-Type: application/pdf`
   - Monitors file:// protocol access for .pdf files
   - Redirects tab to WPS viewer: `chrome-extension://kdpelmjpfafjppnhbloffcjpeomlnpah/index.html?file=<url>`
   - Logs interception events to analytics

3. **Google Scholar Integration**:
   - Injects buttons on PDF links
   - For "Translate" action: redirects to `anydoctranslator.toolsmart.ai` with PDF URL
   - For other actions: opens PDF in WPS viewer
   - Logs all button clicks to analytics

4. **Analytics Collection**:
   - Every user action generates analytics event
   - Includes persistent identifiers: user_id, device_id, install_id, chrome_instance_id
   - Includes environment data: country, browser, OS, extension version
   - Sent to Google Analytics with API secret embedded in code
   - User can disable via preferences

5. **Native Messaging**:
   - Extension connects to `com.wps.pdfextension` native host on demand
   - Retrieves device information from desktop app
   - Can request auto-login URLs from desktop app
   - Can invoke WPS desktop functions via generic call mechanism

## Overall Risk Assessment

**MEDIUM**

### Justification:

This extension serves its intended purpose of PDF viewing/editing and does not exhibit clear malicious behavior. However, it has several concerning characteristics:

**Legitimate Functionality**:
- PDF interception and viewing is the core advertised feature
- Native messaging integration with WPS desktop app is reasonable for a PDF suite
- Google Scholar integration adds value for academic users
- Analytics are user-configurable

**Concerns**:
- **Excessive Permissions**: `<all_urls>` + webRequest + cookies + nativeMessaging is a powerful combination that could be abused
- **Comprehensive Tracking**: Persistent user identification across multiple dimensions (user_id, device_id, install_id, chrome_instance_id)
- **Native Messaging**: Creates bridge to desktop app without clear user disclosure; expanded attack surface
- **Third-party Data Sharing**: PDF URLs sent to translation service `anydoctranslator.toolsmart.ai`
- **Aggressive Behavior**: PDF interception defaults to on; Adobe viewer detection/override with retry loop

**Not Malicious Because**:
- No evidence of data exfiltration beyond disclosed analytics
- No credential harvesting or keylogging
- No ad injection or coupon replacement
- No extension enumeration or killing
- No residential proxy infrastructure
- No remote code execution or eval() of external code
- No cookie harvesting beyond declared permissions
- Analytics can be disabled by user

The extension is invasive and collects significant telemetry, but this aligns with its functionality as a commercial PDF viewing product with 8M users. The permissions are justified by features, though they should be more clearly disclosed. Mark as **MEDIUM** risk due to broad permissions and analytics scope, but it is not malware.

### Recommendations:

1. Users should review if they need PDF interception enabled by default
2. Users should disable analytics if privacy-conscious (`preferences.sendUsageData`)
3. WPS should more clearly disclose native messaging and what desktop app access entails
4. WPS should disclose that PDF URLs are sent to third-party translator service
5. Consider more granular host permissions rather than `<all_urls>`
