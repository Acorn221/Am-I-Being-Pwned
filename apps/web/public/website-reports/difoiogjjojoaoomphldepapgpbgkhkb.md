# Security Analysis Report: Sider AI Extension

## Metadata
- **Extension Name**: Sider: Chat with all AI: GPT-5, Claude, DeepSeek, Gemini, Grok
- **Extension ID**: difoiogjjojoaoomphldepapgpbgkhkb
- **Version**: 5.25.5
- **User Count**: ~5,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-08

## Executive Summary

Sider is a legitimate AI assistant extension that provides a sidebar interface for interacting with multiple AI models (ChatGPT, Claude, Gemini, etc.). The extension employs **highly invasive permissions** and implements some **concerning privacy practices**, but appears to serve its stated purpose without clear malicious intent.

**Key Findings**:
- Extensive permissions including `<all_urls>`, cookies, and scripting access
- Reads OpenAI authentication cookies (oai-did) to integrate with ChatGPT
- Hooks into XMLHttpRequest and JSON.parse on YouTube/Netflix for subtitle extraction
- Fetches encrypted remote configuration from proprietary domain
- Comprehensive telemetry/analytics sent to event.sider.ai
- No evidence of keylogging, credential theft, or malicious data exfiltration
- No market intelligence SDKs or extension enumeration detected

**Risk Assessment**: The extension requires invasive permissions to function as advertised (AI sidebar on all pages), but the privacy implications of cookie access and comprehensive analytics warrant scrutiny.

## Vulnerability/Risk Details

### 1. OpenAI Cookie Access
**Severity**: MEDIUM
**Files**: `background.js`
**Lines**: Various (minified)

**Description**:
The extension reads the `oai-did` cookie from OpenAI/ChatGPT domains:

```javascript
async function LL(){
  return(await chrome.cookies.get({url:Wa,name:"oai-did"}))?.value||te()
}
```

**Context**:
- Used to retrieve OpenAI device ID for header injection: `Oai-Device-Id`
- Part of ChatGPT integration functionality to maintain session continuity
- Cookie is read-only; no evidence of modification or exfiltration to third parties

**Verdict**: **NOT MALICIOUS** - This is necessary for the extension's core functionality of integrating with ChatGPT. The `oai-did` cookie is a device identifier, not an authentication token. The extension needs this to make authenticated requests to OpenAI's API on behalf of the user.

---

### 2. Page Script Injection and Function Hooking
**Severity**: MEDIUM-HIGH
**Files**: `inject-xhr-hack.js`, `inject-json-hack.js`
**Execution Context**: MAIN world (page context)

**Description**:
The extension hooks into native browser APIs on YouTube and Netflix:

**XHR Hook (YouTube)**:
```javascript
var u=window.XMLHttpRequest;
window.XMLHttpRequest=class extends u{
  open(e,t,...r){
    try{
      // Intercepts YouTube subtitle API calls
      if(e.startsWith("https://www.youtube.com/api/timedtext")){
        // Dispatches custom event with subtitle URL
        window.dispatchEvent(new CustomEvent("sider-onGetYtSubtitleUrl",{detail:{url:e}}))
      }
    }catch{}
    super.open(e,t,...r)
  }
}
```

**JSON.parse Hook (Netflix)**:
```javascript
var a=JSON.parse;
JSON.parse=function(e,...t){
  let r=a.bind(JSON)(e,...t);
  if(typeof r=="object"&&r!==null){
    window.dispatchEvent(new CustomEvent("sider-onParseJSON",{detail:{data:r}}))
  }
  return r
}
```

**Context**:
- YouTube hook captures subtitle URLs for AI summary/translation features
- Netflix hook intercepts JSON parsing for content metadata extraction
- Data is dispatched via CustomEvents to extension's isolated world for processing
- **No evidence of exfiltration** - appears used only for local AI features

**Verdict**: **INVASIVE BUT LEGITIMATE** - These hooks enable features like "summarize YouTube video" and "explain Netflix show". However, hooking JSON.parse globally on Netflix is overly broad and could inadvertently capture sensitive data.

---

### 3. Remote Configuration with Encryption
**Severity**: MEDIUM
**Files**: `background.js`
**Endpoint**: `https://apidomain.gptshere.com/api/static/v2/domain_list`

**Description**:
The extension fetches an encrypted domain list from a remote server:

```javascript
async function Hy(){
  let e=Date.now(),
      t=await fetch(sL,{method:"GET",headers:{iv:e.toString()}}),
      r=t.headers.get("kl");

  // Decrypts using AES-GCM with timestamp-based IV
  let n=parseInt(r,10);
  let i=await(await t.blob()).arrayBuffer(),
      s=new Uint8Array(i,0,n),  // key
      a=new Uint8Array(i,n),     // ciphertext
      A=await AL(e.toString()),  // derive IV from timestamp
      c=await crypto.subtle.importKey("raw",s,{name:Gy},!1,["decrypt"]),
      l=await crypto.subtle.decrypt({name:Gy,iv:A},c,a),
      g=new TextDecoder().decode(l),
      d=JSON.parse(g);

  return{apiDomainList:f,eventDomain:u}
}
```

**Context**:
- Returns `api_list` (array of API domains) and `event` (analytics domain)
- Used for dynamic API endpoint rotation (likely for load balancing/redundancy)
- Encryption prevents MITM inspection but enables kill-switch capability
- Domain list stored in `chrome.storage.local` under `domainPool` and `eventDomain`

**Verdict**: **SUSPICIOUS BUT NOT MALICIOUS** - Remote config is common for production apps, but the encryption makes it opaque. This could theoretically be used as a kill switch or to dynamically change backend endpoints. No evidence of abuse detected.

---

### 4. Comprehensive Telemetry and Analytics
**Severity**: MEDIUM
**Files**: `background.js`
**Endpoints**: `https://event.sider.ai/collect`, Google Analytics

**Description**:
Extensive event tracking sent to Sider's analytics backend:

```javascript
let a={
  app_id:Ly,
  event_type:o,
  event_id:te(),
  device_id:await cL(),
  unique_id:await lL(),
  timestamp:i,
  host_name:"sider.ai",
  locale:await q("language"),
  system_language:await q("language"),
  country_code:navigator.language.split("-")[1],
  zone_offset:-new Date().getTimezoneOffset()*6e4,
  screen_height:typeof window<"u"?window.screen.height:0,
  screen_width:typeof window<"u"?window.screen.width:0,
  viewport_height:typeof window<"u"?window.innerHeight:0,
  viewport_width:typeof window<"u"?window.innerWidth:0,
  sdk_name:"aws-solution-clickstream-sdk",
  sdk_version:"0.12.2",
  platform:"Extension",
  app_version:et,
  app_package_name:`Sider_${Ke?"edge":"chrome"}`,
  attributes:{
    ...t,
    os:gL(),
    user_id:await dL(),
    user_premium:await fL(),
    use_scenario:s
  }
}
```

**Data Collected**:
- Device fingerprinting (device_id, unique_id, screen dimensions)
- User account ID and premium status
- System locale, timezone, OS type
- Extension version and platform
- Custom event attributes (usage patterns)

**Context**:
- Uses AWS ClickStream SDK for analytics
- Persistent device IDs stored in local storage
- Dual analytics: event.sider.ai + Google Analytics
- No evidence of conversation content or browsing history being sent

**Verdict**: **PRIVACY INVASIVE BUT STANDARD PRACTICE** - This level of analytics is typical for freemium SaaS products but may concern privacy-conscious users. The extension discloses analytics in its privacy policy.

---

### 5. Extensive Permissions and Access Scope
**Severity**: HIGH (Capability Risk)
**Permissions**:
- `<all_urls>` - Access to all websites
- `cookies` - Read/write cookies on all sites
- `scripting` - Inject scripts into any page
- `tabs` - Access to tab information
- `storage`, `unlimitedStorage`
- `declarativeNetRequest` - Modify network requests
- `sidePanel`, `offscreen`, `alarms`
- Optional: `tabCapture` (screen recording)

**Context**:
- Required for core functionality (AI sidebar on all pages)
- Content scripts injected on all frames with `match_about_blank: true`
- Hosts permissions include `https://*.openai.com/`, `<all_urls>`
- No evidence of permission abuse (e.g., no cookie harvesting from unrelated sites)

**Verdict**: **INVASIVE BUT NECESSARY** - The extension's functionality (AI assistant available everywhere) inherently requires broad permissions. No evidence of misuse detected, but the attack surface is enormous.

---

## False Positives

| Pattern | Context | Reason for FP |
|---------|---------|---------------|
| `Function("return this")()` | Polyfill for global object access | Standard pattern in bundled libraries (likely core-js) |
| `innerHTML` usage | React rendering in bundled UI components | Standard React/DOM manipulation |
| Large obfuscated bundles | Webpack/bundler output | Standard build artifact, not intentional obfuscation |
| AWS SDK references | S3 bucket patterns in dependencies | Likely bundled AWS SDK for cloud features |
| Sentry SDK hooks | Error tracking | Standard error monitoring (Sentry) |

---

## API Endpoints and Domains

| Domain/Endpoint | Purpose | Sensitivity |
|-----------------|---------|-------------|
| `https://api.openai.com/v1` | ChatGPT API integration | HIGH - User queries |
| `https://api.anthropic.com` | Claude API integration | HIGH - User queries |
| `https://api.deepseek.com/v1` | DeepSeek API integration | HIGH - User queries |
| `https://api.groq.com/openai/v1` | Groq API integration | HIGH - User queries |
| `https://generativelanguage.googleapis.com` | Google Gemini API | HIGH - User queries |
| `https://chatgpt.com/api/auth/session` | ChatGPT session validation | HIGH - Auth tokens |
| `https://event.sider.ai/collect` | Analytics/telemetry | MEDIUM - Usage data |
| `https://apidomain.gptshere.com/api/static/v2/domain_list` | Remote config (encrypted) | MEDIUM - Config data |
| `https://sider.ai` | Main backend API | MEDIUM - Account data |
| `https://preview.sider.ai` | Preview/beta features | LOW |
| `https://www.google-analytics.com` | Google Analytics | MEDIUM - Analytics |

---

## Data Flow Summary

### Incoming Data:
1. **User Input**: AI queries from sidebar/context menus → Sent to respective AI APIs (OpenAI, Anthropic, etc.)
2. **Page Content**: Selected text, YouTube subtitles, Netflix metadata → Processed locally for AI context
3. **OpenAI Cookies**: `oai-did` device ID → Used for ChatGPT API authentication headers

### Outgoing Data:
1. **AI API Requests**: User queries + context → AI provider endpoints (encrypted HTTPS)
2. **Analytics Events**: Usage metrics, device fingerprints → event.sider.ai, Google Analytics
3. **Remote Config Fetch**: Timestamp-based request → Receives encrypted domain list

### Storage:
1. **Local Storage**: User preferences, device IDs, cached domain list
2. **Cookies**: No evidence of cookie manipulation (only reads oai-did)

**Critical Finding**: No evidence of conversation content being sent to Sider's backend beyond normal API proxying. All AI queries appear routed directly to respective providers (OpenAI, Anthropic, etc.).

---

## Security Strengths

1. **No Dynamic Code Execution**: No evidence of `eval()` or remote script loading
2. **No Credential Theft**: Does not steal passwords or auth tokens (only reads non-sensitive oai-did)
3. **No Extension Enumeration**: Does not fingerprint installed extensions
4. **No Keylogging**: No keyboard event listeners for credential capture
5. **HTTPS-Only**: All network requests use encrypted transport
6. **CSP Present**: Content Security Policy configured (though allows localhost dev server)

---

## Security Weaknesses

1. **Overly Broad Permissions**: `<all_urls>` + cookies grants enormous attack surface
2. **Global Function Hooking**: JSON.parse hook on Netflix is unnecessarily invasive
3. **Opaque Remote Config**: Encrypted domain list prevents transparency
4. **Extensive Analytics**: Device fingerprinting and usage tracking
5. **Third-Party API Keys**: Extension likely proxies API calls (unclear if using user's keys or Sider's)

---

## Overall Risk Assessment

**RISK LEVEL**: **MEDIUM**

### Justification:
This extension is a **legitimate commercial product** that provides AI assistant functionality. While it employs invasive permissions and comprehensive analytics, these are arguably necessary for its stated purpose. The extension does not exhibit clear malicious behavior such as:
- Credential theft or keylogging
- Cookie harvesting from unrelated sites
- Malware/ad injection
- Extension enumeration or killing
- Market intelligence SDK deployment
- Conversation exfiltration (beyond normal API usage)

However, the extension poses **significant privacy risks**:
- Reads OpenAI cookies (though only device ID, not auth tokens)
- Hooks into page-level JavaScript (XHR, JSON.parse)
- Fetches opaque encrypted configuration
- Sends extensive telemetry with device fingerprinting
- Requests `<all_urls>` access (required for functionality but risky)

### Recommendations for Users:
1. **Review Privacy Policy**: Understand what data is collected and how it's used
2. **Use with Caution**: Only install if you trust Sider AI with your browsing activity
3. **Prefer Official Clients**: Use ChatGPT/Claude web apps directly for sensitive queries
4. **Monitor Permissions**: Be aware this extension can access all website data
5. **Consider API Keys**: Check if you can use your own API keys instead of Sider's proxy

### Recommendations for Developers:
1. **Reduce Permission Scope**: Use `activeTab` instead of `<all_urls>` where possible
2. **Add Transparency**: Disclose what the encrypted domain list contains
3. **Narrow Function Hooks**: Make JSON.parse hook more targeted (specific to needed data)
4. **User-Controlled Analytics**: Add opt-out for telemetry
5. **Open Source Core**: Consider open-sourcing security-critical components

---

## Verdict

**CLEAN** (with caveats)

This extension serves its intended purpose as an AI assistant without clear malicious behavior. The invasive permissions and privacy-concerning practices are justifiable given the product's scope, though users should be fully informed of the tradeoffs. The extension falls into the category of "privacy-invasive but not malware."

The OpenAI cookie access, while concerning, is limited to reading a non-sensitive device identifier and is necessary for ChatGPT integration. The function hooking is overly broad but appears used for legitimate features (subtitle extraction, content summarization).

**Recommendation**: Mark as **CLEAN** but note the high privacy impact. Users installing this extension should understand they are trading privacy (extensive analytics, cookie access, all-site access) for convenience (AI assistant everywhere).
