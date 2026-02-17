# Vulnerability Report: Amazon KW Index and Rank Tracker

## Extension Metadata
- **Extension ID**: dehlblnjjkkbapjemjbeafjhjpjoifii
- **Extension Name**: Amazon KW Index and Rank Tracker
- **Version**: 0.9.1
- **User Count**: ~60,000
- **Manifest Version**: 3
- **Developer**: amzdatastudio.com

## Executive Summary

The Amazon KW Index and Rank Tracker extension is a legitimate tool designed to help Amazon sellers check keyword rankings and indexing status. The extension uses **legitimate techniques** including cookie manipulation for "incognito mode" functionality and Google OAuth for user authentication. While the extension implements several powerful capabilities (cookie access, Amazon scraping, HTML storage), **all functionality appears aligned with its stated purpose** of ranking analysis.

The extension communicates exclusively with its legitimate backend API at amzdatastudio.com and Amazon domains. No evidence of malicious behavior, data exfiltration, or unauthorized tracking was found.

**Overall Risk: LOW**

## Vulnerability Analysis

### 1. Cookie Manipulation for Incognito Mode (SEVERITY: LOW - False Positive)

**Files**: `scripts/background.js`, `scripts/index.js`

**Description**: The extension implements save/delete/restore operations for Amazon cookies to enable "incognito mode" checking.

**Code Evidence**:
```javascript
// background.js lines 19-36
if ("saveAmazonCookies" === o.action) return (t = o.country, new Promise(function(o, r) {
  var c = n(t);
  chrome.cookies.getAll({
    domain: c
  }, function(n) {
    chrome.runtime.lastError ? r(chrome.runtime.lastError) : (e.set(c, n), o(n))
  })
}))

// Deletes cookies for "incognito" mode
if ("deleteAmazonCookies" === o.action) return function(e) {
  return new Promise(function(o, r) {
    var c = n(e);
    chrome.cookies.getAll({
      domain: c
    }, function(e) {
      // ... removes all Amazon cookies
    })
  })
}

// Restores cookies after incognito check
if ("restoreAmazonCookies" === o.action) return function(o) {
  return new Promise(function(r, c) {
    var t = n(o),
      i = e.get(t);
    // ... restores saved cookies
  })
}
```

**Analysis**: This functionality is a **legitimate feature** for Amazon sellers who want to check rankings without personalization/login influence. The extension:
- Only accesses Amazon cookies (domains restricted in manifest)
- Saves cookies temporarily in memory (Map object)
- Restores them after checking
- Requires user interaction (checkbox activation)

**Verdict**: FALSE POSITIVE - Legitimate ranking analysis feature

---

### 2. HTML Content Storage in IndexedDB (SEVERITY: LOW - False Positive)

**Files**: `scripts/index.js` (lines 493-518), `viewer.js`

**Description**: Extension saves Amazon search result HTML pages to IndexedDB for incognito mode viewing.

**Code Evidence**:
```javascript
// index.js lines 493-518
function(n, e, t, o) {
  return new Promise(function(i, r) {
    var a = function(n) {
      for (var e = (new DOMParser).parseFromString(n, "text/html"),
           t = e.querySelectorAll("script"), o = 0; o < t.length; o++)
        t[o].remove();  // Removes scripts before saving
      return e.documentElement.outerHTML
    }(t),
    c = {
      "keyword": n,
      "page": e,
      "sessionId": o,
      "html": a,  // Sanitized HTML (scripts removed)
      "timestamp": Date.now(),
      "country": $("#country").val()
    };
    s().then(function(n) {
      var e = n.transaction(["pages"], "readwrite").objectStore("pages").add(c);
      // ... stores in IndexedDB
    })
  })
}
```

**Viewer Display**:
```javascript
// viewer.js line 11
document.getElementById('content').innerHTML = html;
```

**Analysis**: This functionality:
- **Sanitizes HTML** by removing script tags before storage
- Stores locally in IndexedDB (not sent anywhere)
- Used to display saved search results in viewer.html
- Legitimate use case: allows users to reference their ranking checks later

**Security Note**: While innerHTML usage on line 11 could be XSS-prone, the HTML is pre-sanitized and stored locally - minimal risk since it's the user's own search data.

**Verdict**: FALSE POSITIVE - Legitimate caching feature with sanitization

---

### 3. Development-Only LiveReload WebSocket (SEVERITY: LOW - Build Artifact)

**Files**: `scripts/chromereload.js`

**Code Evidence**:
```javascript
var e=new WebSocket("ws://localhost:35729/livereload"),o=!1;
chrome.runtime.onInstalled.addListener(function(e){o=Date.now()}),
e.onerror=function(e){},
e.onmessage=function(e){
  if(e.data){
    var c=JSON.parse(e.data);
    if(c&&"reload"===c.command){
      var r=Date.now();
      o&&r-o>6e4&&(chrome.runtime.reload(),
        chrome.developerPrivate.reload(chrome.runtime.id,{"failQuietly":!0}))
    }
  }
};
```

**Analysis**: This is a **development tool** (LiveReload) that should have been removed before production release. However:
- Connects only to localhost
- Silently fails if LiveReload not running (onerror does nothing)
- No security impact for end users
- Common oversight in web development

**Verdict**: FALSE POSITIVE - Harmless build artifact, best practice would be to remove

---

### 4. Google OAuth Integration (SEVERITY: LOW - Legitimate)

**Files**: `scripts/index.js` (lines 215-245), `manifest.json` (lines 35-41)

**Code Evidence**:
```javascript
// manifest.json
"oauth2": {
  "client_id": "698734700157-pdq33j7rlaj6jus01cu5nqrlsoe2kvmj.apps.googleusercontent.com",
  "scopes": [
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/userinfo.email"
  ]
}

// index.js
chrome.identity.getAuthToken({
  "interactive": !0
}, function(o) {
  // ... sends access_token to backend API
  $.ajax({
    "type": "POST",
    "url": p.LOGININGOOGLE,  // amzdatastudio.com/api/user/loginByGoogleInChromeExtension
    "contentType": "application/json",
    "data": JSON.stringify({ "access_token": o }),
    // ...
  })
})
```

**Analysis**: Standard Google OAuth implementation for user authentication:
- Uses official Chrome Identity API
- Requests minimal scopes (profile + email only)
- Token sent to legitimate backend API
- Standard practice for SaaS extensions

**Verdict**: FALSE POSITIVE - Legitimate authentication mechanism

---

### 5. Post Code Modification for Geographic Testing (SEVERITY: LOW - Legitimate)

**Files**: `scripts/index.js` (lines 160-178)

**Code Evidence**:
```javascript
function k(n) {
  return new Promise(function(e, t) {
    var o = $("#country").val(),
      s = "locationType=LOCATION_INPUT&storeContext=sporting-goods&deviceType=web&pageType=Detail&actionSource=glow&almBrandId=undefined&zipCode=" + encodeURIComponent(n),
      i = "https://www.amazon." + o + "/portal-migration/hz/glow/address-change?actionSource=glow";
    $.ajax({
      "url": i,
      "method": "POST",
      "contentType": "application/x-www-form-urlencoded",
      "data": s,
      // ... validates and sets delivery address
    })
  })
}
```

**Analysis**: Changes Amazon delivery location to test rankings in different geographic areas:
- Uses Amazon's official address-change API
- Validates post code before setting
- Pro feature (requires subscription)
- Legitimate use case for sellers targeting multiple regions

**Verdict**: FALSE POSITIVE - Legitimate feature for geographic ranking analysis

---

## False Positive Summary

| Pattern | File | Reason for False Positive |
|---------|------|---------------------------|
| Cookie manipulation | background.js | Legitimate incognito mode for unbiased ranking checks |
| innerHTML usage | viewer.js | Displays sanitized, locally-stored HTML (user's own data) |
| WebSocket connection | chromereload.js | Development-only LiveReload artifact, localhost-only |
| Google OAuth | index.js | Standard authentication mechanism |
| Amazon API calls | index.js | Scraping Amazon search results (extension's core purpose) |
| IndexedDB storage | index.js | Local caching of search results for reference |

---

## API Endpoints

| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| https://amzdatastudio.com/api/user/login | Email/password login | username, password |
| https://amzdatastudio.com/api/user/loginByGoogleInChromeExtension | Google OAuth login | access_token |
| https://amzdatastudio.com/api/user/signup | User registration | username, password, name, lastname |
| https://amzdatastudio.com/api/user/logout | User logout | (session only) |
| https://amzdatastudio.com/api/chrome-extension-kw-index/userinfo | Get user subscription status | version, language, subscription status |
| https://amzdatastudio.com/api/chrome-extension-kw-index/search-volume | Get keyword search volume | keywords array, region, ASIN |
| https://www.amazon.[country]/s/?k=[keyword] | Search Amazon | Keyword searches (GET requests) |
| https://www.amazon.[country]/dp/[asin] | Get product variations | Product page scraping |
| https://www.amazon.[country]/portal-migration/hz/glow/address-change | Change delivery location | Post code (for pro users) |

---

## Data Flow Summary

### Data Collection
- **User credentials**: Sent to amzdatastudio.com for authentication
- **Keywords and ASINs**: Sent to amzdatastudio.com API for search volume lookup
- **Amazon cookies**: Stored temporarily in memory for incognito mode
- **Search result HTML**: Stored locally in IndexedDB (NOT sent to servers)

### Data Storage
- **Local Storage**: User language preference, subscription status
- **IndexedDB**: Amazon search result HTML pages (sanitized, temporary)
- **Memory (Map)**: Amazon cookies during incognito mode (temporary)

### Data Transmission
- All API calls to amzdatastudio.com use HTTPS
- No third-party analytics or tracking detected
- No data sent to unexpected domains
- Amazon scraping uses GET requests (standard web browsing)

---

## Permissions Analysis

### Declared Permissions
- **unlimitedStorage**: Used for IndexedDB storage of search results (legitimate)
- **identity**: Google OAuth authentication (legitimate)
- **cookies**: Cookie manipulation for incognito mode (legitimate)

### Host Permissions
- **Amazon domains** (11 countries): Required for scraping search results
- **amzdatastudio.com**: Backend API access

All permissions are appropriate for the extension's functionality.

---

## Content Security Policy
No CSP defined in manifest (MV3 defaults apply). No concerns detected.

---

## Overall Risk Assessment

**Risk Level: LOW**

### Why LOW vs CLEAN:
1. **Cookie manipulation** could theoretically be misused but is clearly for legitimate purposes
2. **innerHTML usage** with stored HTML presents minimal XSS risk (sanitized + local data)
3. **Development artifact** (chromereload.js) should have been removed
4. Extension has powerful capabilities but uses them appropriately

### Security Strengths:
- Scripts removed from stored HTML before display
- HTTPS for all API communications
- Limited OAuth scopes
- No obfuscation or dynamic code execution
- No third-party SDKs or tracking
- Permissions align with functionality

### Recommendations:
1. Remove chromereload.js from production builds
2. Consider using textContent instead of innerHTML where possible
3. Add Content Security Policy to manifest for defense-in-depth

---

## Conclusion

The Amazon KW Index and Rank Tracker extension is a **legitimate tool** for Amazon sellers. All detected patterns are false positives related to its core functionality of checking keyword rankings. The extension demonstrates good security practices (HTML sanitization, HTTPS, minimal OAuth scopes) and shows no evidence of malicious intent or unauthorized data collection.

**OVERALL RISK: LOW**
