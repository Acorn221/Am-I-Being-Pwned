# Security Analysis Report: Keyword Surfer Extension

## Extension Metadata
- **Extension ID**: bafijghppfhdpldihckdcadbcobikaca
- **Extension Name**: Keyword Surfer
- **Version**: 6.5.1
- **Users**: ~600,000
- **Vendor**: SurferSEO (app.surferseo.com)
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-06

## Executive Summary

Keyword Surfer is a legitimate SEO keyword research tool that displays search volume data directly in Google search results and provides SEO insights within ChatGPT conversations. The extension hooks into ChatGPT's fetch API to extract search queries from AI responses, which raises **moderate privacy concerns** regarding AI conversation monitoring. However, the implementation is transparent, feature-relevant, and does not exhibit malicious patterns such as credential harvesting, extension killing, or unauthorized data exfiltration.

**Risk Level**: **MEDIUM**

**Key Findings**:
1. **ChatGPT Fetch Hooking**: Monitors ChatGPT API responses to extract search queries mentioned in AI conversations
2. **CSP Removal on ChatGPT**: Removes Content Security Policy headers to enable extension functionality
3. **Legitimate Integration**: Search queries are used to provide keyword research features within ChatGPT interface
4. **Google Analytics Tracking**: Standard usage analytics with client ID generation
5. **No Malicious Patterns**: No extension enumeration/killing, no credential theft, no hidden data exfiltration
6. **SurferSEO Integration**: Legitimate connection to vendor's SEO platform for authenticated users

## Vulnerability Analysis

### VULN-1: ChatGPT Conversation Monitoring via Fetch Hooking
**Severity**: MEDIUM
**CWE**: CWE-200 (Exposure of Sensitive Information)

**Location**:
- `/deobfuscated/injectHookFetch.js` (lines 11347-11451)
- `/deobfuscated/manifest.json` (lines 363-368)

**Description**:
The extension injects a script into ChatGPT's MAIN world context that hooks `window.fetch` to intercept API responses from ChatGPT's backend. It extracts search queries that ChatGPT mentions in its responses.

**Technical Details**:
```javascript
// Pattern matching ChatGPT conversation endpoints
const Rd = /^https:\/\/chatgpt\.com\/(?:.*\/)?conversation/

// Hooks window.fetch in MAIN world
window.fetch = function(t) {
  // Intercepts responses and extracts queries
  const i = (n, r, a) => {
    Bo ? window.postMessage({
      type: Vn,  // "KEYWORD_SURFER_NEW_FANOUT_QUERY"
      queries: n,
      chatId: r,
      gptResponseType: a
    }, window.location.origin)
  }
}

// Query extraction from response JSON
function Vo(e) {
  const t = re(e, "search_queries").map(o => o.q?.toString()).filter(Boolean),
        i = re(e, "search_model_queries").flatMap(o => o.queries || []);
  return Od([...t, ...i])  // Deduplicate and return
}
```

**Data Flow**:
1. User asks ChatGPT a question (e.g., "What's the best coffee maker?")
2. ChatGPT response includes search queries like `["best coffee maker 2026"]`
3. Extension extracts `search_queries` and `conversation_id` from JSON response
4. Queries sent via `postMessage` to content script world
5. Content script displays keyword research UI in ChatGPT interface

**Manifest Permission**:
```json
{
  "matches": ["https://chatgpt.com/*"],
  "js": ["injectHookFetch.js"],
  "world": "MAIN",
  "run_at": "document_start"
}
```

**Privacy Impact**:
- **What is collected**: Search query strings mentioned by ChatGPT, conversation IDs
- **What is NOT collected**: Full conversation content, user prompts, AI responses
- **Purpose**: Display keyword research data (search volume, related keywords) within ChatGPT UI
- **Exfiltration**: No evidence of queries being sent to external servers beyond intended feature use

**Verdict**: **LEGITIMATE with PRIVACY CONCERNS**

The fetch hooking is used for the extension's core feature (showing keyword data in ChatGPT), not for hidden surveillance. However, users may not be aware their ChatGPT search queries are being monitored.

---

### VULN-2: Content Security Policy Removal on ChatGPT
**Severity**: LOW
**CWE**: CWE-693 (Protection Mechanism Failure)

**Location**:
- `/deobfuscated/chat_rules.json` (lines 1-16)
- `/deobfuscated/manifest.json` (lines 370-377)

**Description**:
The extension uses declarativeNetRequest to strip CSP headers from ChatGPT pages, allowing the extension to inject UI elements and scripts.

**Technical Details**:
```json
{
  "id": 1,
  "priority": 1,
  "action": {
    "type": "modifyHeaders",
    "responseHeaders": [
      { "header": "content-security-policy", "operation": "remove" }
    ]
  },
  "condition": {
    "urlFilter": "https://chatgpt.com/*",
    "resourceTypes": ["main_frame"]
  }
}
```

**Security Impact**:
- Weakens ChatGPT's security posture on user's browser
- Could enable XSS if ChatGPT has vulnerabilities
- Standard practice for extensions needing to inject UI elements

**Verdict**: **ACCEPTABLE**

CSP removal is necessary for the extension's functionality and is scoped only to ChatGPT. This is a common pattern for UI-injecting extensions.

---

### VULN-3: Google Search Autocomplete Monitoring
**Severity**: LOW
**CWE**: CWE-200 (Exposure of Sensitive Information)

**Location**:
- `/deobfuscated/serviceWorker.js` (lines 27617-27629)

**Description**:
The extension monitors Google autocomplete requests to detect when users are typing searches, allowing it to inject keyword suggestions in real-time.

**Technical Details**:
```javascript
const I0 = /google.[^/]*\/search\?/;
chrome.webRequest.onBeforeRequest.addListener(function(e) {
  if (/\/complete/.exec(e.url)) {
    if (new URL(e.url).searchParams.get("q") === "") return;
    chrome.tabs.sendMessage(e.tabId, Mb(zu.AUTOCOMPLETE_BEFORE_REQUEST, e));
  }
}, { urls: ["<all_urls>"] }, [])
```

**Privacy Impact**:
- Monitors user typing in Google search box
- Used to display keyword suggestions in real-time
- No evidence of exfiltration beyond feature functionality

**Verdict**: **LEGITIMATE**

This is the extension's core feature - providing keyword insights during Google searches.

---

## False Positives Identified

| Pattern | Location | Reason for False Positive |
|---------|----------|---------------------------|
| `window.fetch` hooking | `injectHookFetch.js:11430` | Legitimate feature for ChatGPT integration, not surveillance SDK |
| React `innerHTML` with SVG | `popup.js:11665-11673` | Standard React namespace handling for SVG/MathML elements |
| Lodash library | `serviceWorker.js:93-102` | Standard utility library, not malicious |
| GraphQL library | `serviceWorker.js:17449-17458` | Apollo GraphQL client for API communication |
| MutationObserver | `injectChatGptKeywordSurfer.js:51195-51203` | Observing DOM to detect ChatGPT UI changes for extension UI injection |
| postMessage | Multiple files | Legitimate inter-script communication between content scripts |
| Google Analytics | `serviceWorker.js:16167-16175` | Standard usage analytics (G-VFJYCRK9HE) |

---

## API Endpoints and Data Flows

| Endpoint | Purpose | Data Sent | Data Received |
|----------|---------|-----------|---------------|
| `https://app.surferseo.com/*` | SurferSEO platform integration | User authentication, keyword queries | Keyword data, search volumes, SEO metrics |
| `https://keywordsur.fr/chatgpt-config` | Remote config for ChatGPT features | None (fetch only) | Feature flags, UI config |
| `https://www.google-analytics.com/mp/collect` | Usage analytics | Event names (e.g., `chatgpt_fanout_query_opened`), client ID, query counts | None |
| `https://chatgpt.com/` (intercepted) | Extract search queries from AI responses | None (passive monitoring) | Search queries, conversation IDs |

**Authentication Flow**:
- Uses `connect.surferseo.com` for OAuth/authentication
- Stores auth tokens in `chrome.storage.local`
- Cookies scoped to `.surferseo.com` domain

---

## Chrome Permissions Analysis

| Permission | Justification | Risk Level |
|------------|---------------|------------|
| `storage` | Store user preferences, auth tokens, client ID | LOW - Standard usage |
| `webRequest` | Monitor Google autocomplete requests | LOW - Scoped to feature |
| `scripting` | Inject keyword data UI into Google/ChatGPT pages | LOW - Core functionality |
| `declarativeNetRequest` | Remove CSP on ChatGPT | LOW - Necessary for UI injection |
| `cookies` | Authenticate with SurferSEO platform | LOW - Scoped to `.surferseo.com` |
| Host permissions (150+ Google domains) | Display keyword data in all Google regional domains | LOW - Transparent SEO tool |
| `https://chatgpt.com/*` | ChatGPT integration features | MEDIUM - Fetch hooking |
| `https://app.surferseo.com/*` | SurferSEO platform access | LOW - Vendor integration |

---

## Code Quality and Security Indicators

**Positive Indicators**:
- ✅ Manifest v3 (modern security model)
- ✅ No `eval()` or dynamic code execution
- ✅ No extension enumeration/killing behavior
- ✅ No credential harvesting from other sites
- ✅ No residential proxy infrastructure
- ✅ No ad injection or search manipulation
- ✅ Transparent vendor (SurferSEO is established SEO company)
- ✅ Uses standard libraries (React, Apollo GraphQL, Lodash)
- ✅ Source maps present (indicates legitimate build process)

**Negative Indicators**:
- ⚠️ Fetch hooking in MAIN world (powerful capability)
- ⚠️ CSP removal on ChatGPT
- ⚠️ Monitors typing in Google search box
- ⚠️ No clear privacy policy mention of ChatGPT monitoring in extension description

---

## Data Privacy Summary

**What Keyword Surfer Collects**:
1. **Google Search Queries**: User's search terms in Google (for keyword suggestion feature)
2. **ChatGPT Search Queries**: Query strings mentioned by ChatGPT in responses (for keyword research in AI conversations)
3. **Usage Analytics**: Event names, query counts (via Google Analytics)
4. **Client ID**: Generated UUID stored in `chrome.storage.local` as `ks_client_id`
5. **Conversation IDs**: ChatGPT conversation identifiers (for UI state management)

**What Keyword Surfer Does NOT Collect**:
- ❌ Full ChatGPT conversation content
- ❌ User prompts to ChatGPT
- ❌ ChatGPT's full AI responses
- ❌ Browsing history beyond Google/ChatGPT
- ❌ Credentials or authentication tokens from other sites
- ❌ Extension inventory

**Data Retention**:
- No evidence of long-term storage of queries
- Queries appear to be used ephemerally for UI display
- Analytics tracked with standard GA4 retention policies

---

## Recommendations

### For Users:
1. **Be Aware**: The extension monitors search queries mentioned in ChatGPT responses
2. **Review Permissions**: Understand that the extension can see queries in ChatGPT conversations
3. **Privacy Sensitive Users**: Consider if ChatGPT query monitoring aligns with privacy expectations
4. **Legitimate Use Case**: The monitoring serves the extension's stated purpose (keyword research)

### For Developers (SurferSEO):
1. **Transparency**: Clearly disclose ChatGPT conversation monitoring in extension description
2. **Privacy Policy**: Add explicit mention of fetch hooking and what data is processed
3. **Opt-In**: Consider making ChatGPT integration opt-in rather than default
4. **Minimize Scope**: Evaluate if conversation IDs need to be collected
5. **Documentation**: Provide clear documentation on data flows for security researchers

---

## Comparison to Malicious Extensions

Unlike malicious extensions found in this research (StayFree, StayFocusd, Flash Copilot), Keyword Surfer:
- ✅ **No Hidden SDKs**: No Sensor Tower Pathmatics or similar surveillance platforms
- ✅ **No Full Conversation Scraping**: Only extracts search query strings, not full AI responses
- ✅ **Transparent Vendor**: SurferSEO is a known SEO software company, not a data broker
- ✅ **Feature-Aligned**: Monitoring serves the extension's advertised functionality
- ✅ **No Remote Kill Switches**: No evidence of server-controlled behavior changes
- ✅ **No Extension Killing**: Does not disable competing extensions

---

## Overall Risk Assessment

### Risk Score: **MEDIUM** (4/10)

**Justification**:
- Core functionality is legitimate SEO keyword research
- ChatGPT fetch hooking is powerful but serves stated purpose
- No evidence of hidden data collection or malicious behavior
- Transparency concerns regarding ChatGPT monitoring
- Established vendor with legitimate business model

### Risk Breakdown:
- **Technical Risk**: LOW - Well-structured code, no malicious patterns
- **Privacy Risk**: MEDIUM - Monitors ChatGPT search queries without prominent disclosure
- **Security Risk**: LOW - No credential theft, no extension conflicts
- **Behavioral Risk**: LOW - No deceptive practices, features match description
- **Vendor Risk**: LOW - SurferSEO is established SEO company

---

## Verdict

**CLEAN - with PRIVACY ADVISORY**

Keyword Surfer is a **legitimate SEO tool** that provides genuine value to users researching keywords. The ChatGPT integration, while involving fetch hooking, is used transparently for the extension's core feature (displaying keyword data alongside AI responses).

However, users should be **aware** that the extension monitors search queries mentioned in ChatGPT conversations. This is not hidden surveillance, but rather an expected part of the extension's functionality - though it could be more clearly disclosed.

**Recommended for**: SEO professionals, content creators, marketers researching keywords
**Not recommended for**: Users highly sensitive to AI conversation monitoring

---

## Technical Artifacts

### Key Files Analyzed:
- `manifest.json` - Permissions and content script configuration
- `serviceWorker.js` (4.6MB) - Background service worker with webRequest monitoring
- `injectHookFetch.js` (1.5MB) - MAIN world script that hooks fetch for ChatGPT
- `injectChatGptKeywordSurfer.js` (7.9MB) - ChatGPT UI integration
- `injectGoogleKeywordSurfer.js` (13.8MB) - Google search results integration
- `chat_rules.json` - declarativeNetRequest rules for CSP removal

### Extension Architecture:
```
Service Worker (background.js)
    ├── Monitors Google autocomplete (webRequest API)
    ├── Google Analytics tracking
    └── SurferSEO API integration

ChatGPT Content Scripts
    ├── injectHookFetch.js (MAIN world) - Fetch hooking
    ├── injectChatGptKeywordSurfer.js - UI rendering
    └── injectGuidelinesInChatGptCanvas.js - Canvas integration

Google Search Content Scripts
    └── injectGoogleKeywordSurfer.js - Search results UI

Popup
    └── popup.js - Extension settings/options
```

### Build Information:
- **Framework**: Custom webpack build
- **UI Library**: React 18
- **GraphQL Client**: Apollo Client
- **Styling**: styled-components
- **Validation**: Zod schemas

---

## Conclusion

Keyword Surfer represents a **legitimate, feature-rich SEO tool** with a minor privacy consideration around ChatGPT conversation monitoring. Unlike malicious extensions that hide their data collection behind obfuscated SDKs, Keyword Surfer's behavior is architecturally aligned with its advertised functionality. The fetch hooking, while powerful, serves a clear purpose: providing keyword research data within AI conversations.

**Final Classification**: **CLEAN** with **MEDIUM privacy impact** requiring user awareness.
