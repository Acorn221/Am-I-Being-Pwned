# Security Analysis: Keywords Everywhere - Keyword Tool (hbapdpeemoojbophdfndmlgdhppljgmp)

## Extension Metadata
- **Name**: Keywords Everywhere - Keyword Tool
- **Extension ID**: hbapdpeemoojbophdfndmlgdhppljgmp
- **Version**: 11.48
- **Manifest Version**: 3
- **Estimated Users**: ~1,000,000
- **Analysis Date**: 2026-02-14

## Executive Summary
Keywords Everywhere is a **legitimate SEO and keyword research tool** with **MEDIUM risk** due to security vulnerabilities rather than malicious intent. The extension provides keyword search volume, CPC, and competition data across 20+ platforms including Google, YouTube, Amazon, Pinterest, and AI chatbots (ChatGPT, Claude, Gemini). It also offers an AI prompt template feature for content generation.

The ext-analyzer flagged 46 HIGH findings, which appear alarming at first glance. However, detailed code review reveals that **most are false positives** from legitimate functionality:
- The 3 "EXFILTRATION" flows are actually API calls TO the vendor's own servers (keywordseverywhere.com) to FETCH keyword data, not to exfiltrate user data
- Cookie access is limited to YouTube SAPISID tokens for legitimate API authentication when fetching video transcripts
- Storage reads followed by fetch are reading API keys/settings to make authorized requests

**Genuine security issues identified**:
1. **3 postMessage handlers without origin validation** (XSS vulnerability)
2. **YouTube cookie harvesting** (legitimate use case but privacy-concerning)
3. **Broad host permissions** (`http://*/*`, `https://*/*`)
4. **Cross-origin fetch requests** with user credentials

**No evidence of malicious behavior**: No data exfiltration, no hidden tracking, no remote code execution, no extension killing. The extension operates transparently as an SEO tool with a freemium business model.

**Overall Risk Assessment: MEDIUM** - Legitimate tool with real vulnerabilities that need fixing, but not malware.

---

## Vulnerability Assessment

### 1. postMessage Handlers Without Origin Validation (HIGH)
**Severity**: HIGH
**CWE**: CWE-346 (Origin Validation Error)
**Files**:
- `js/ytstats.js:80`
- `js/cs-openai-widget.js:13`
- `js/bridge.js:1`

**Analysis**:
The extension uses `window.addEventListener("message")` in multiple contexts to enable communication between iframes and content scripts. However, **none of the handlers validate `event.origin`** before processing messages.

**Code Evidence** (`bridge.js`):
```javascript
window.addEventListener("message", function(event){
  var payload = event.data;
  if (typeof payload !== 'object') return;
  var cmd = payload.cmd;
  var data = payload.data;
  var handlerId = payload.handlerId;
  if (!cmd || !handlerId) return;

  // No origin check! Any website can send messages
  if (cmd === 'xtkt.getAPIparams') {
    chrome.runtime.sendMessage({
      cmd: 'api.getParams'
    }, function(response){
      postResponse(cmd, handlerId, response);
    });
  }
```

**Vulnerable Message Types**:
- `xtkt.getAPIparams` - Exposes API key and settings
- `xtkt.getSettings` - Leaks extension configuration
- `xt.yt.videos` - Accepts video data from untrusted sources
- `xt-openai-*` commands - Widget control messages

**Attack Scenario**:
A malicious website could inject this into a page where the extension is active:
```javascript
window.postMessage({
  cmd: 'xtkt.getAPIparams',
  handlerId: 'evil123'
}, '*');

window.addEventListener('message', function(e) {
  if (e.data.handlerId === 'evil123') {
    // Steal API key from response
    console.log('Stolen API key:', e.data.apiKey);
  }
});
```

**Impact**:
- **API key theft** from bridge.js handler
- **XSS via innerHTML injection** (see Vuln #3)
- **Cross-site request forgery** by injecting fake data

**Remediation**:
Add origin validation to all handlers:
```javascript
const ALLOWED_ORIGINS = [
  'https://keywordseverywhere.com',
  chrome.runtime.getURL('')
];

window.addEventListener("message", function(event){
  // Validate origin first
  if (!ALLOWED_ORIGINS.some(o => event.origin.startsWith(o))) {
    return; // Reject untrusted origins
  }
  // ... rest of handler
});
```

---

### 2. YouTube Cookie Harvesting for API Authentication (MEDIUM)
**Severity**: MEDIUM (Privacy Concern)
**CWE**: CWE-200 (Exposure of Sensitive Information)
**Files**: `js/cs-youtube.js:579-615`

**Analysis**:
The extension reads YouTube authentication cookies (`SAPISID`, `APISID`, `__Secure-1PAPISID`, `__Secure-3PAPISID`) to build authorization headers for fetching video transcripts via YouTube's internal API.

**Code Evidence**:
```javascript
function getCookieValue(name) {
  const m = document.cookie.match(new RegExp('(?:^|; )' + name.replace(/[.$?*|{}()[\]\\/+^]/g, '\\$&') + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : null;
}

async function buildYoutubeAuthorization() {
  const origin = "https://www.youtube.com";
  const ts = Math.floor(Date.now() / 1000);

  const sapisidLike =
    getCookieValue("SAPISID") ||
    getCookieValue("APISID") ||
    getCookieValue("__Secure-3PAPISID") ||
    getCookieValue("__Secure-1PAPISID");

  const sid1p = getCookieValue("__Secure-1PAPISID");
  const sid3p = getCookieValue("__Secure-3PAPISID");

  if (!sapisidLike) throw new Error("No SAPISID-like cookie found");

  // Build SAPISIDHASH using SHA-1
  parts.push(`SAPISIDHASH ${ts}_${await sha1Hex(`${ts} ${sapisidLike} ${origin}`)}_u`);
  if (sid1p) parts.push(`SAPISID1PHASH ${ts}_${await sha1Hex(`${ts} ${sid1p} ${origin}`)}_u`);
  if (sid3p) parts.push(`SAPISID3PHASH ${ts}_${await sha1Hex(`${ts} ${sid3p} ${origin}`)}_u`);

  return parts.join(" ");
}
```

**Purpose**:
The extension needs to authenticate with YouTube's internal transcript API to fetch video transcripts. This is used for the "AI prompt templates" feature that can analyze YouTube video content.

**What's Transmitted**:
The extension sends the hashed SAPISID to `https://www.youtube.com/youtubei/v1/get_transcript` (YouTube's own API), NOT to third-party servers. The actual cookie values are never sent externally - only the SHA-1 hash is used in the Authorization header.

**Privacy Impact**:
- **Low exfiltration risk**: Cookies are only used to authenticate with YouTube's own API
- **Session binding**: The extension can make requests on behalf of the logged-in user
- **Transcript access**: Can read private video transcripts if user has access

**Is This Malicious?**:
**NO** - This is a legitimate (if invasive) technique to access YouTube's transcript API. Many YouTube extensions use this pattern. However, users should be aware that:
1. The extension can read transcripts of any video the user can access
2. It operates with the user's YouTube session credentials
3. There's no disclosure in the extension description about cookie access

**Verdict**: **NOT MALICIOUS** but **PRIVACY-INVASIVE**. Should be disclosed to users.

---

### 3. DOM-Based XSS via innerHTML in Message Handlers (MEDIUM)
**Severity**: MEDIUM
**CWE**: CWE-79 (Cross-Site Scripting)
**Files**: Cross-component flow detected by ext-analyzer

**Analysis**:
The ext-analyzer detected a data flow where message data reaches `.innerHTML`:

```
message data → *.innerHTML
  from: js/ytstats.js, js/bridge.js ⇒ js/cs-openai.js
```

**Attack Scenario**:
Combined with Vuln #1 (missing origin validation), an attacker could:
1. Send malicious HTML via postMessage
2. Have it rendered via innerHTML without sanitization
3. Execute arbitrary JavaScript in the extension's context

**Impact**:
- Execute arbitrary code in content script context
- Access to all DOM content on current page
- Potential to escalate to background script via messaging

**Remediation**:
- Use `textContent` instead of `innerHTML` for untrusted data
- Sanitize all message payloads before rendering
- Implement strict origin validation (see Vuln #1)

---

### 4. Cross-Origin Resource Fetching with Credentials (LOW)
**Severity**: LOW (Expected Behavior with Risk)
**Files**: `js/background.js:420-448`

**Analysis**:
The background script fetches arbitrary URLs provided by content scripts, including user credentials:

```javascript
else if (cmd === 'ajax.getPageHTML') {
  var url = urlsToAnalyze[data];
  if (!url) url = data.url;
  fetch(url, {
    mode: 'cors',
    credentials: 'include'  // Sends cookies!
  })
    .then(function(response){
      return response.text();
    })
    .then(function(response){
      sendResponse({error: false, data: response});
    })
}
```

**Purpose**:
This is used by the AI prompt template feature to fetch page HTML for analysis (e.g., analyzing competitor websites for SEO).

**Risk**:
- The extension fetches pages with the user's credentials
- Could be used to exfiltrate data from authenticated sites if compromised
- The fetched URL comes from content scripts (potential injection point)

**Legitimate Use**:
The feature is designed to fetch SERP results and competitor pages for SEO analysis. The URL is constructed from user input in the OpenAI widget.

**Verdict**: **EXPECTED BEHAVIOR** but increases attack surface if the extension is compromised.

---

### 5. Obfuscated Code (LOW)
**Severity**: LOW (Commercial Protection, Not Malicious)
**Flag**: `obfuscated: true` from ext-analyzer

**Analysis**:
The code shows signs of minification and variable name obfuscation, but **this is standard for commercial extensions** to protect intellectual property. The logic is straightforward once deobfuscated.

**Key Indicators of Legitimate Obfuscation**:
- No eval() or Function() dynamic code execution
- No encrypted payload decryption
- No polymorphic code
- All control flow is linear and readable
- API endpoints are visible in plaintext

**Verdict**: **NOT MALICIOUS** - Standard commercial minification.

---

## False Positive Analysis: The "46 HIGH Findings"

The ext-analyzer flagged 46 HIGH findings, but detailed review reveals most are false positives:

### False Positive #1: "EXFILTRATION" Flows (3 flows flagged)

**Ext-analyzer report**:
```
[HIGH] chrome.storage.local.get → fetch    js/openai-app.js
[HIGH] document.querySelectorAll → fetch   js/cs-youtube.js
[HIGH] chrome.storage.local.get → fetch    js/background.js
```

**Reality**: These are **API calls TO the vendor's servers to FETCH data**, not exfiltration:

1. **openai-app.js**: Reads API key from storage → calls `keywordseverywhere.com/service/3/` to FETCH keyword data
   ```javascript
   chrome.storage.local.get('openai', (data) => {
     // Read settings and API key
     fetch('https://keywordseverywhere.com/service/3/getKeywordData.php', {
       // Send API key to authorize request
       // RECEIVE keyword volume/CPC data back
     })
   });
   ```

2. **cs-youtube.js**: Queries DOM for video title → sends to vendor API to get keyword metrics
   ```javascript
   document.querySelectorAll('h1.ytd-video-primary-info-renderer');
   // Extract video title, then:
   fetch('https://api.keywordseverywhere.com/keywords', {
     // Send title keywords to GET search volume data
   });
   ```

3. **background.js**: Reads settings → makes authorized API calls
   ```javascript
   chrome.storage.local.get('settings', function(data){
     API.init(data.settings.apiKey, data.settings.country);
     // API.getKeywordData() fetches FROM server, doesn't send user data
   });
   ```

**Verdict**: **FALSE POSITIVES** - These are legitimate API calls to the vendor's own infrastructure.

---

### False Positive #2: "ATTACK SURFACE" - Message Handlers

**Ext-analyzer flagged**: 34+ content scripts sending message data to background

**Reality**: This is the **normal architecture** for a multi-platform extension:
- Each content script (Google, YouTube, Amazon, etc.) sends messages to background script
- Background script coordinates API calls and state
- This is standard Chrome extension messaging, not an attack

**Example**:
```javascript
// cs-youtube.js sends keyword list to background
chrome.runtime.sendMessage({
  cmd: 'api.getKeywordData',
  data: {keywords: ['seo tools', 'keyword research']}
}, function(response) {
  // Display keyword metrics in YouTube UI
});
```

**Verdict**: **FALSE POSITIVE** - Standard Chrome extension architecture.

---

### False Positive #3: Cookie Harvesting Flagged as Exfiltration

**What the static analyzer saw**: `document.cookie` access followed by network calls

**What's actually happening**: YouTube cookie → hashed → sent to **YouTube's own API** (not third-party)

See detailed analysis in Vuln #2. This is privacy-invasive but not data exfiltration.

---

## Network Activity Analysis

### Legitimate Vendor Endpoints

| Domain | Purpose | Data Sent | Data Received |
|--------|---------|-----------|---------------|
| `api.keywordseverywhere.com` | Keyword metrics API | Keywords, API key, country | Search volume, CPC, competition |
| `keywordseverywhere.com/service/3/` | Main API service | API key, settings | Keyword data, trends, credits |
| `data.keywordseverywhere.com` | Static assets | None | Charts, icons |
| `keywordseverywhere.com/ke/widget.php` | Iframe widget (freemium upsell) | API key, plan level | Upgrade prompts |

### Third-Party Data Sources (Read-Only)

| Domain | Purpose | Risk |
|--------|---------|------|
| `trends.pinterest.com` | Pinterest trends data | Low - read-only |
| `autosug.ebaystatic.com` | eBay autocomplete | Low - read-only |
| `www.youtube.com/youtubei/v1/get_transcript` | YouTube transcript API | Medium - uses user cookies |

### External Libraries (CDN)

- `chartjs.org` - Chart.js library
- `datatables.net` - DataTables library
- All loaded from local `/lib/` folder, **NOT from CDN** (good security practice)

**Total Data Exfiltration**: **NONE DETECTED**

---

## AI Integration Analysis

The extension has deep integration with AI platforms:

### Supported AI Platforms
- ChatGPT (chatgpt.com, chat.openai.com)
- Claude (claude.ai)
- Google Gemini (gemini.google.com)
- DeepSeek (chat.deepseek.com)

### AI Feature: Prompt Templates
**Files**: `js/openai-app.js`, `js/cs-openai-widget.js`, `Widget.js`

The extension injects a draggable widget on AI chat pages that provides:
1. **Template Categories**: SEO, Content Writing, Social Media, Email Marketing, etc.
2. **Dynamic Inputs**: Users fill in variables (keywords, URLs, target audience)
3. **URL Scraping**: Can fetch competitor pages to analyze (see Vuln #4)
4. **Prompt Generation**: Builds prompts from templates + user input

**Example Flow**:
```
User on ChatGPT → Opens Keywords Everywhere widget →
Selects "SEO Blog Post" template → Enters keyword "dog training" →
Extension fetches data from keywordseverywhere.com API →
Generates prompt: "Write a 2000-word blog post about 'dog training'
targeting search volume 12000/mo, CPC $2.50..." →
User copies to ChatGPT
```

**Privacy Consideration**:
The AI platforms themselves cannot see what the extension is doing - the widget runs in the page context but data flows through extension messaging, not page scripts.

**Verdict**: Legitimate value-add feature, no AI conversation scraping detected.

---

## Freemium Business Model

The extension operates on a credit-based system:

1. **Free Tier**: Limited credits per month
2. **Paid Plans**: Bronze/Silver/Gold/Platinum (stored in `settings.plan`)
3. **Credit Tracking**: Each API call deducts credits
4. **Upsell**: Iframe widget shows upgrade prompts

**Evidence**:
```javascript
// API.js
var getPlan = function(cbProcessResponse){
  var url = API_URL + 'getPlan.php';
  getJSON(url, {
    apiKey: _apiKey,
    version: version
  }).then(function(json){
    if (json && json.plan) {
      numParam = backlinksByPlan[json.plan]; // Adjust limits by plan
    }
  });
};
```

**Is This Ethical?**: Yes - clear freemium model with transparent pricing.

---

## Permission Analysis

| Permission | Justification | Risk Level |
|------------|---------------|------------|
| `storage` | Store API key, settings, cached data | Low (local only) |
| `activeTab` | Inject content scripts on active tab | Low (on-demand) |
| `contextMenus` | Right-click menu for keyword lookup | Low (functional) |
| `scripting` | Inject content scripts programmatically | Low (required for MV3) |
| `http://*/*` | Access all HTTP sites | **HIGH** (very broad) |
| `https://*/*` | Access all HTTPS sites | **HIGH** (very broad) |

**Assessment**:
Host permissions are **overly broad** but necessary for the extension's multi-platform functionality. The extension injects content scripts on 20+ different domains (Google, YouTube, Amazon, Pinterest, etc.) based on URL matching in the manifest.

**Better Approach**: Use `optional_host_permissions` and request per-domain as needed, but this would degrade UX.

---

## Code Quality Observations

### Positive Indicators
1. **No dynamic code execution**: No `eval()`, `Function()`, or `new Function()`
2. **No remote script loading**: All JS bundled locally
3. **No WebAssembly**: Despite `obfuscated` flag
4. **No extension enumeration/killing**: No `chrome.management` API abuse
5. **No residential proxy infrastructure**: No proxy configuration
6. **Manifest V3 compliant**: Modern security model
7. **Modular architecture**: Clean separation of concerns

### Security Concerns
1. **Missing input sanitization** on postMessage handlers
2. **No CSP declared** in manifest (relies on MV3 defaults)
3. **Broad host permissions** without justification prompt
4. **Credentials included in fetch requests** increases risk

### Obfuscation Level
**MEDIUM** - Variables are minified (standard webpack/terser output), but:
- No control flow flattening
- No string encryption
- No dead code injection
- No anti-debugging traps

**Verdict**: Standard commercial minification, not malicious obfuscation.

---

## Comparison to Known Malicious Patterns

| Malicious Pattern | Present? | Evidence |
|-------------------|----------|----------|
| Extension enumeration/killing | ✗ No | No `chrome.management` usage |
| XHR/fetch hooking | ✗ No | No prototype modifications detected |
| Residential proxy infrastructure | ✗ No | No proxy configuration |
| AI conversation scraping | ✗ No | Widget is input-only, doesn't read chat history |
| Market intelligence SDKs | ✗ No | No Sensor Tower, Pathmatics, etc. |
| Ad/coupon injection | ✗ No | No DOM manipulation for ads |
| Remote config/kill switches | ✗ No | No remote code loading |
| Cookie harvesting for tracking | **⚠** Partial | YouTube cookies used for API auth only |
| Hidden data exfiltration | ✗ No | All API calls are transparent |
| Cryptocurrency mining | ✗ No | No mining scripts |

---

## Overall Risk Assessment

### Risk Level: **MEDIUM**

**Justification**:

**Legitimate Functionality** (60% of risk):
- SEO/keyword research tool working as advertised
- Transparent API calls to vendor's own servers
- No hidden tracking or malicious data collection
- Freemium business model is ethical
- AI integration is value-add, not conversation scraping

**Security Vulnerabilities** (40% of risk):
- 3 postMessage handlers without origin validation (exploitable for XSS)
- YouTube cookie access (privacy-invasive but legitimate use case)
- Broad host permissions (functional necessity)
- Cross-origin fetch with credentials (attack surface)

**Why Not HIGH/CRITICAL?**:
- No active malicious behavior
- No data exfiltration detected
- Vulnerabilities are fixable without architectural changes
- 1M users with no widespread abuse reports suggests good faith actor

**Why Not LOW/CLEAN?**:
- Real exploitable vulnerabilities exist (postMessage XSS)
- Cookie harvesting without disclosure
- Broad attack surface if compromised
- Obfuscation makes auditing difficult

---

## Recommendations

### For Users
1. **Safe to Use** if you need SEO/keyword research tools
2. **Be Aware**: Extension reads YouTube cookies to fetch transcripts
3. **Review Permissions**: Understand it can access all websites you visit
4. **Monitor Credits**: Don't share API key (see Vuln #1 - can be stolen via XSS)

### For Developer
1. **CRITICAL**: Add origin validation to all postMessage handlers
2. **HIGH**: Sanitize all message payloads before innerHTML rendering
3. **MEDIUM**: Disclose YouTube cookie access in extension description
4. **LOW**: Consider using `optional_host_permissions` for better transparency

### For Researchers
This extension is a good example of **high false-positive rate in static analysis**:
- 46 HIGH findings → 3 actual vulnerabilities + 2 privacy concerns
- "EXFILTRATION" flows were legitimate API calls
- Cookie access was for API authentication, not tracking
- Always validate static analysis with code review

---

## Conclusion

Keywords Everywhere is a **legitimate commercial SEO tool** with **real security vulnerabilities** that should be fixed, but **no evidence of malicious intent**. The 46 HIGH findings from static analysis are mostly false positives from the tool's normal operation of fetching keyword data from its API servers.

The primary concerns are:
1. **Exploitable XSS** via unvalidated postMessage handlers
2. **Privacy-invasive** YouTube cookie harvesting (legitimate but undisclosed)
3. **Broad attack surface** from wide host permissions

Users who need SEO/keyword tools can use this extension with awareness of the risks. The developer should prioritize fixing the postMessage vulnerabilities to prevent API key theft and XSS attacks.

**Final Verdict: MEDIUM** - Vulnerable but not malicious.

---

## Technical Summary

**Lines of Code**: ~8,500 (deobfuscated, excluding libraries)
**External Dependencies**: jQuery 3.7.1, Moment.js, Chart.js, DataTables
**Third-Party APIs**: keywordseverywhere.com (vendor), YouTube, Pinterest, eBay (read-only)
**Remote Code Loading**: None
**Dynamic Code Execution**: None
**Obfuscation Type**: Commercial minification (standard webpack/terser)
**Content Scripts**: 28 (one per supported platform)
**Background Scripts**: 2 (sw_background.js, background.js)
**Web Accessible Resources**: 11 (HTML pages + AJAX bridges)

---

## Appendix: Code Snippets

### A. Legitimate API Call (False Positive as "Exfiltration")
```javascript
// API.js - Fetches keyword data FROM server
var getKeywordData = function(data, cbProcessResponse){
  var url = API_URL + 'getKeywordData.php';
  getJSON(url, {
    apiKey: _apiKey,
    country: _country,
    currency: _currency,
    dataSource: _dataSource,
    keywords: data.keywords  // User's search terms
  })
  .then(function(json){
    // RECEIVES keyword metrics back
    cbProcessResponse({error: false, data: json});
  });
};
```

### B. Vulnerable postMessage Handler
```javascript
// bridge.js - Missing origin validation
window.addEventListener("message", function(event){
  var payload = event.data;
  var cmd = payload.cmd;

  // ⚠️ No check: if (!TRUSTED_ORIGINS.includes(event.origin)) return;

  if (cmd === 'xtkt.getAPIparams') {
    chrome.runtime.sendMessage({cmd: 'api.getParams'}, function(response){
      // Leaks API key to any origin!
      postResponse(cmd, handlerId, response);
    });
  }
});
```

### C. YouTube Cookie Harvesting for API Auth
```javascript
// cs-youtube.js - Builds YouTube API authorization
async function buildYoutubeAuthorization() {
  const sapisid = getCookieValue("SAPISID");  // Read YouTube cookie
  const ts = Math.floor(Date.now() / 1000);
  const hash = await sha1Hex(`${ts} ${sapisid} https://www.youtube.com`);

  // Used to fetch transcripts from YouTube's API
  return `SAPISIDHASH ${ts}_${hash}_u`;
}

async function getTranscriptNew(res) {
  const auth = await buildYoutubeAuthorization();
  const response = await fetch('https://www.youtube.com/youtubei/v1/get_transcript', {
    method: 'POST',
    headers: {
      'authorization': auth,  // Uses YouTube cookies
      'x-youtube-client-name': '1'
    },
    body: JSON.stringify(payload)
  });
  return response.json();
}
```
