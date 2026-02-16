# Security Analysis: eRail.in (aopfgjfeiimeioiajeknfidlljpoebgc)

## Extension Metadata
- **Name**: eRail.in
- **Extension ID**: aopfgjfeiimeioiajeknfidlljpoebgc
- **Version**: 9.10
- **Manifest Version**: 3
- **Estimated Users**: ~300,000
- **Developer**: Unknown
- **Analysis Date**: 2026-02-15

## Executive Summary
eRail.in is a companion browser extension for the eRail.in Indian railway information service. The extension enables enhanced user experience features including train availability checks, cookie management for railway booking sites (IRCTC, Indian Railways), and cross-origin data fetching. Analysis identified **MEDIUM** risk due to an unchecked `postMessage` handler that allows any website to trigger privileged operations including fetch requests and cookie access to Indian government railway booking sites. While the extension appears designed for legitimate railway information purposes, the vulnerability creates an attack surface for malicious websites to abuse extension permissions.

**Overall Risk Assessment: MEDIUM**

## Vulnerability Assessment

### 1. Unchecked postMessage Handler (MEDIUM SEVERITY)
**Severity**: MEDIUM
**Files**:
- `/js/contentscript.js` (lines 1)
- `/js/erailchrome.js` (lines 2-3, 7-8)

**Analysis**:
The extension injects a content script on ALL websites (`matches: ["http://*/*", "https://*/*"]`) that listens for `window.postMessage` events without validating the message origin. Any website can send messages to trigger background script operations.

**Code Evidence** (`contentscript.js`):
```javascript
window.addEventListener("message",function(a){
  void 0!=a.data&&(
    plugdata=a.data,
    void 0!=plugdata.Action&&(
      // ... UI updates ...
      chrome.runtime.sendMessage(plugdata,function(a){})
    )
  )
});
```

**Vulnerability Details**:
1. **No origin validation** - accepts messages from ANY source
2. **Universal content script injection** - runs on all HTTP/HTTPS pages
3. **Privileged operations** - forwards messages directly to background script
4. **Cookie access** - can retrieve/clear cookies for railway booking domains
5. **Arbitrary fetch requests** - can make authenticated requests to railway sites

**Attack Scenario**:
A malicious website could execute:
```javascript
window.postMessage({
  Action: "GETCOOKIE",
  URL: "irctc.co.in"
}, "*");
// Extension returns IRCTC session cookies
```

**Impact**:
- **Cookie theft** from IRCTC (Indian railway booking) and indianrail.gov.in
- **Arbitrary HTTP requests** to railway sites with extension's credentials
- **Session hijacking** potential for railway booking accounts
- **Privacy violation** by unauthorized data retrieval

**Recommended Fix**:
```javascript
window.addEventListener("message", function(event) {
  // Validate origin
  if (!event.origin.match(/^https:\/\/(.*\.)?erail\.in$/)) {
    return;
  }
  // Process message...
});
```

**Verdict**: **MEDIUM SEVERITY** - Significant vulnerability but limited to railway-related domains. Not full credential theft but could compromise railway booking sessions.

---

### 2. Unrestricted Cross-Origin Fetch (MEDIUM SEVERITY)
**Severity**: MEDIUM
**Files**: `/js/erailchrome.js` (lines 7-8)

**Analysis**:
The background script accepts arbitrary fetch requests with custom headers and body from content script messages, without URL validation.

**Code Evidence** (`erailchrome.js`):
```javascript
function DownloadData(){
  if(0!=RequestQ.length){
    var a=RequestQ[0];
    plugdata=a;
    var b=new Headers;
    if(void 0!=plugdata.headersList)
      for(var c=0;c<plugdata.headersList.length;c+=2)
        b.append(plugdata.headersList[c],plugdata.headersList[c+1]);

    fetch(a.URL,{
      method:a.FetchMethod?a.FetchMethod:"POST",
      headers:b,
      body:a.post,
      redirect:"follow"
    })
    // ... returns response to content script
  }
}
```

**Vulnerability Details**:
1. **Arbitrary URL fetching** - No validation of `a.URL` parameter
2. **Custom headers** - Allows injection of `headersList` (key-value pairs)
3. **POST body control** - Attacker controls request body via `a.post`
4. **Response returned** - Fetched data sent back to attacker's page

**Attack Scenario**:
Combined with vulnerability #1, a malicious website could:
```javascript
window.postMessage({
  Action: "GET",  // Triggers DownloadData()
  URL: "https://www.irctc.co.in/nget/booking/train-list",
  FetchMethod: "POST",
  headersList: ["Cookie", "stolen_session_cookie"],
  post: "malicious_payload"
}, "*");
```

**Impact**:
- **SSRF (Server-Side Request Forgery)** from extension context
- **Bypass CORS restrictions** for railway booking sites
- **Session riding** using extension's host permissions
- **Data exfiltration** from protected railway APIs

**Recommended Fix**:
Whitelist allowed URLs and validate against host_permissions:
```javascript
const ALLOWED_DOMAINS = [
  'erail.in', 'tripmgt.in', 'irctc.co.in', 'indianrail.gov.in'
];

function isAllowedUrl(url) {
  try {
    const hostname = new URL(url).hostname;
    return ALLOWED_DOMAINS.some(d => hostname === d || hostname.endsWith('.' + d));
  } catch {
    return false;
  }
}

// In DownloadData():
if (!isAllowedUrl(a.URL)) {
  return; // Reject request
}
```

**Verdict**: **MEDIUM SEVERITY** - Powerful SSRF capability but limited to railway-related domains by host_permissions.

---

### 3. Cookie Access Without Origin Validation (MEDIUM SEVERITY)
**Severity**: MEDIUM
**Files**: `/js/erailchrome.js` (lines 5-6)

**Analysis**:
The extension provides cookie retrieval and clearing for railway booking domains, controllable via unchecked messages.

**Code Evidence** (`erailchrome.js`):
```javascript
function GetIRCookie(a,b){
  chrome.cookies.getAll({domain:a.URL},function(c){
    var d=[];
    $(c).each(function(){
      d.push({
        name:this.name,
        value:this.value,
        domain:this.domain,
        secure:this.secure,
        path:this.path
      })
    });
    a.Data=JSON.stringify(d);
    SendMessage("ONRESULT",a,b)
  })
}

function ClearCookie(a,b){
  chrome.cookies.getAll({domain:a.URL},function(c){
    $(c).each(function(){
      chrome.cookies.remove({url:"http://"+this.domain,name:this.name},function(a){});
      chrome.cookies.remove({url:"http://"+this.domain+"/enquiry",name:this.name},function(a){})
    });
    a.Data=JSON.stringify([]);
    SendMessage("ONRESULT",a,b)
  })
}
```

**Vulnerability Details**:
1. **Cookie enumeration** - Returns all cookies for specified domain
2. **Cookie deletion** - Can clear railway booking session cookies
3. **No origin check** - Triggered by postMessage from any website
4. **Sensitive domains** - Targets IRCTC (government railway booking) and Indian Railways

**Attack Scenario**:
```javascript
// Malicious website steals IRCTC login cookies
window.postMessage({
  Action: "GETCOOKIE",
  URL: "irctc.co.in"
}, "*");

// Or performs denial-of-service by clearing cookies
window.postMessage({
  Action: "CLEARCOOKIE",
  URL: "irctc.co.in"
}, "*");
```

**Impact**:
- **Session token theft** from IRCTC railway booking accounts
- **Account compromise** via cookie hijacking
- **Denial of service** by clearing user sessions
- **Privacy violation** by exposing authentication state

**Recommended Fix**:
1. Validate message origin before cookie operations
2. Require user confirmation for sensitive operations
3. Limit cookie access to only necessary values (not full enumeration)

**Verdict**: **MEDIUM SEVERITY** - Direct access to government railway booking cookies, but scope limited to railway domains.

---

## False Positive Patterns Identified

| Pattern | Location | Reason for FP | Actual Purpose |
|---------|----------|---------------|----------------|
| None detected | - | - | - |

## Network Activity Analysis

### External Endpoints

All network activity is user-controllable via the fetch proxy mechanism. Based on host_permissions, the extension can access:

| Domain | Purpose | Data Transmitted | Frequency |
|--------|---------|------------------|-----------|
| `erail.in/*` | Railway information queries | User search queries, availability checks | User-initiated |
| `*.erail.in/*` | eRail.in subdomains | Railway data requests | User-initiated |
| `tripmgt.in/*` | Trip management service | Travel planning data | User-initiated |
| `*.irctc.co.in/*` | IRCTC railway booking | Booking queries, session cookies | User-initiated (vulnerable) |
| `*.indianrail.gov.in/*` | Indian Railways official | Railway information requests | User-initiated (vulnerable) |

### Data Flow Summary

**Data Collection**: Tab information, cookies from railway domains, arbitrary fetch responses
**User Data Transmitted**: Potentially railway booking session cookies (via vulnerability)
**Tracking/Analytics**: None detected
**Third-Party Services**: None (all requests to railway-related domains)

**Exfiltration Risk**:
The `chrome.tabs.query` → fetch flow detected by ext-analyzer shows tab information (likely containing railway search URLs) being sent to network endpoints. Combined with the postMessage vulnerability, this could allow unauthorized data exfiltration from railway booking sites.

**Code Evidence of Exfiltration Path** (`erailchrome.js`):
```javascript
chrome.runtime.onMessage.addListener(function(a,b,c){
  a.TabID=b.tab.id;
  plugdata=a;
  switch(a.Action){
    // ... processes message ...
    default:
      RequestQ.push(a),
      DownloadData(),  // Triggers fetch
      c({})
  }
});
```

## Permission Analysis

| Permission | Justification | Risk Level |
|------------|---------------|------------|
| `tabs` | Required for tab information and communication | Medium (combined with vulnerability) |
| `cookies` | Cookie management for railway booking sites | **HIGH** (vulnerable to theft) |
| `https://erail.in/*` | Access to eRail.in service | Low (legitimate) |
| `https://*.erail.in/*` | eRail.in subdomains | Low (legitimate) |
| `https://tripmgt.in/*` | Trip management companion | Low (legitimate) |
| `https://*.irctc.co.in/*` | **IRCTC railway booking (government)** | **HIGH** (vulnerable) |
| `https://*.indianrail.gov.in/*` | **Indian Railways official site** | **HIGH** (vulnerable) |

**Assessment**: Cookie permission combined with IRCTC/Indian Railways host permissions creates HIGH risk when exposed via postMessage vulnerability.

## Content Security Policy
```json
{
  "extension_pages": "script-src 'self'; object-src 'self';",
  "web_accessible_resources": "script-src 'self' 'unsafe-eval'; object-src 'self';"
}
```

**Issues**:
1. **'unsafe-eval' in web_accessible_resources CSP** - Allows eval() in WAR contexts (though no WARs declared, CSP key is malformed)
2. **CSP syntax error** - `web_accessible_resources` is not a valid CSP context key in MV3 (should be under `sandbox` if applicable)

**Note**: This appears to be a configuration error. MV3 does not support `web_accessible_resources` as a CSP context.

## Code Quality Observations

### Negative Indicators
1. **No input validation** on message handlers
2. **No origin checking** on postMessage
3. **Minified/obfuscated code** (detected by ext-analyzer)
4. **Unsafe message passing** architecture
5. **CSP configuration errors**
6. **Universal content script injection** (all_frames: true, all URLs)

### Positive Indicators
1. No dynamic code execution (`eval()`, `Function()`)
2. No external script loading
3. No third-party analytics or tracking
4. No ad injection or DOM manipulation
5. Limited to railway-related domains by host_permissions
6. Manifest V3 compliance

### Obfuscation Level
**MEDIUM** - Code is minified and variable names are shortened. Function logic is compressed but readable after formatting. No heavy obfuscation patterns detected beyond standard minification.

## Comparison to Known Malicious Patterns

| Malicious Pattern | Present? | Evidence |
|-------------------|----------|----------|
| Extension enumeration/killing | ✗ No | No `chrome.management` API usage |
| XHR/fetch hooking | ✗ No | No prototype modifications |
| Residential proxy infrastructure | ✗ No | No proxy configuration |
| AI conversation scraping | ✗ No | No API interception |
| Market intelligence SDKs | ✗ No | No Sensor Tower, Pathmatics, etc. |
| Ad/coupon injection | ✗ No | No DOM manipulation for ads |
| Remote config/kill switches | ✗ No | No remote code loading |
| Cookie harvesting for general sites | ✗ No | Limited to railway domains |
| GA/analytics proxy bypass | ✗ No | No analytics manipulation |
| Hidden data exfiltration | **⚠ Yes** | Unchecked postMessage enables exploitation |

## Overall Risk Assessment

### Risk Level: **MEDIUM**

**Justification**:
1. **Significant vulnerability** - Unchecked postMessage handler on all websites
2. **Sensitive permissions** - Cookie access to government railway booking sites (IRCTC)
3. **Session hijacking risk** - Could compromise railway booking accounts
4. **Limited scope** - Impact confined to railway-related domains (not universal tracking)
5. **No evidence of active exploitation** - Appears to be design flaw, not intentional backdoor
6. **Legitimate purpose** - Extension serves genuine railway information use case

### Scoring Breakdown:
- **postMessage vulnerability**: -20 points (no origin check with privileged operations)
- **Cookie access to sensitive domains**: -15 points (IRCTC booking sessions)
- **Arbitrary fetch capability**: -10 points (SSRF within railway domains)
- **Limited scope**: +15 points (only railway sites, not general tracking)
- **No active malice detected**: +10 points (design flaw vs. intentional)

**Final Score**: MEDIUM risk (vulnerabilities exist but scope is limited)

### Recommendations
1. **Immediate**: Add origin validation to postMessage handler (whitelist `erail.in` only)
2. **Immediate**: Validate fetch URLs against allowed domains
3. **Short-term**: Remove universal content script injection (limit to eRail.in domains)
4. **Short-term**: Require user confirmation for cookie access operations
5. **Long-term**: Implement Content Security Policy correctly for MV3
6. **Long-term**: Add message signing/HMAC to prevent message spoofing

### User Privacy Impact
**MEDIUM** - The extension has access to:
- Cookies from Indian railway booking sites (IRCTC, Indian Railways)
- Tab URLs on all websites (via universal content script)
- Railway search queries and booking information
- Potential for unauthorized cookie theft via vulnerability

**Exploitation Risk**: HIGH if user visits malicious website while extension is active - attacker could steal IRCTC session cookies and compromise railway booking account.

## Technical Summary

**Lines of Code**: 167 (deobfuscated, excluding jQuery)
**External Dependencies**: jQuery 3.2.1
**Third-Party Libraries**: jQuery (legitimate)
**Remote Code Loading**: None
**Dynamic Code Execution**: None
**Exfiltration Flows**: 1 (tabs.query → fetch, via vulnerable postMessage)
**Open Message Handlers**: 1 (window.addEventListener without origin check)

## ext-analyzer Output Summary

```
Risk Score: 50
Exfiltration Flows: 1
Code Execution Flows: 0
Open Message Handlers: 1
Obfuscated: Yes (minified)
WASM: No
```

**Key Finding**: The analyzer correctly identified the exfiltration path from `chrome.tabs.query` to `fetch`, reachable via the unchecked message handler in `contentscript.js`.

## Conclusion

eRail.in is a **companion extension for Indian railway information services** with **MEDIUM risk** due to security vulnerabilities rather than malicious intent. The unchecked `postMessage` handler creates an exploitable attack surface allowing any website to access IRCTC (Indian railway booking) cookies and make authenticated requests to railway sites. While the extension appears designed for legitimate railway information purposes, the vulnerability could enable session hijacking of railway booking accounts.

**The extension is NOT actively malicious** but has **significant security flaws** that could be exploited by malicious websites. Users visiting untrusted sites while this extension is active could have their IRCTC session cookies stolen, potentially compromising their railway booking accounts.

**Final Verdict: MEDIUM** - Vulnerable to exploitation but limited scope (railway domains only). Recommend security fixes before continued use.
