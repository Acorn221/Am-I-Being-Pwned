# Security Analysis: Otter.ai Extension

## Extension Metadata
- **Extension ID**: bnmojkbbkkonlmlfgejehefjldooiedp
- **Name**: Otter.ai: Record & Transcribe Meetings - Google Meet & Web Audio
- **Version**: 3.8.2
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-06

## Executive Summary

**Overall Risk: LOW**

Otter.ai is a **legitimate transcription service extension** with appropriate permissions for its stated functionality. The extension provides meeting transcription, note-taking, and AI-powered interview assistance features. While it handles sensitive audio data and implements extensive telemetry, all functionality aligns with its advertised purpose. The extension uses industry-standard analytics (RudderStack, Statsig) and legitimate AI services (Claude) through Otter's backend infrastructure.

**Key Findings:**
- ✅ Legitimate business purpose (meeting transcription and AI assistance)
- ✅ No evidence of data exfiltration beyond stated functionality
- ✅ No XHR/fetch hooking on arbitrary pages
- ✅ No extension enumeration or killing behavior
- ✅ No residential proxy infrastructure
- ✅ No ad injection or search manipulation
- ⚠️ Audio recording requires explicit user permission (chrome.tabCapture)
- ⚠️ Extensive telemetry and analytics tracking (RudderStack, Statsig, OpenTelemetry)
- ⚠️ Cookie access limited to own domains (otter.ai, api.aisense.com)
- ⚠️ Prototype features for Greenhouse (interview feedback) and Gmail (email drafting)

## Permissions Analysis

### Declared Permissions
```json
"permissions": [
  "cookies",
  "declarativeNetRequest",
  "offscreen",
  "tabCapture",
  "activeTab"
]
```

### Host Permissions
```json
"host_permissions": [
  "https://otter.ai/*",
  "https://api.aisense.com/*",
  "*://meet.google.com/*"
]
```

### Permission Assessment
| Permission | Risk | Justification | Legitimate Use |
|------------|------|---------------|----------------|
| `cookies` | LOW | Limited to otter.ai and api.aisense.com | ✅ Session management for authentication |
| `declarativeNetRequest` | LOW | Only modifies Referer header for own API calls | ✅ CORS compatibility |
| `tabCapture` | MEDIUM | Captures audio from browser tabs | ✅ Core transcription functionality |
| `activeTab` | LOW | Injects UI when user clicks extension icon | ✅ User-initiated interaction |
| `<all_urls>` (content scripts) | MEDIUM | Content script injected on all pages | ⚠️ Broad access but minimal DOM interaction |
| Google Meet host permission | LOW | Required for meeting transcription | ✅ Primary use case |

### Content Security Policy
```json
"content_security_policy": {
  "extension_pages": "script-src 'self'; object-src 'self'"
}
```
✅ **Strong CSP**: No external script loading, no inline scripts, no eval().

## Vulnerability Analysis

### 1. Audio Capture and Data Transmission
**Severity**: LOW (Legitimate Feature)
**Files**: `src/background-script/background.js:10697`, `src/recordingTab/index.js:11691`

**Behavior**:
```javascript
// background.js:10697 - Tab audio capture
chrome.tabCapture.getMediaStreamId({
  consumerTabId: tabId
}, function(streamId) {
  // Processes audio for transcription
});

// recordingTab/index.js:11691 - Microphone access
await navigator.mediaDevices.getUserMedia({
  audio: {
    deviceId: microphoneId
  }
})
```

**Assessment**:
- Audio capture requires explicit user permission from Chrome
- Audio is transmitted to `api.aisense.com` for transcription (Otter's legitimate backend)
- No evidence of unauthorized recording or data leakage
- User must click "Start Recording" button to initiate capture

**Verdict**: ✅ **FALSE POSITIVE** - Core functionality, properly implemented

---

### 2. Cookie Access and Session Management
**Severity**: LOW
**Files**: `src/background-script/background.js:10194-10214`

**Behavior**:
```javascript
// background.js:10194 - Cookie reading
function ce(t, e) {
  return new Promise((n, r) => {
    chrome.cookies.get({
      url: t,
      name: e
    }, function(i) {
      i ? n(i.value) : r(chrome.runtime.lastError)
    })
  })
}

// Reads csrftoken and sessionid from otter.ai
const csrftoken = await ce("https://otter.ai", "csrftoken");
const sessionid = await ce("https://otter.ai", "sessionid");

// Copies cookies to api.aisense.com for API authentication
await xr("csrftoken", csrftoken, "https://api.aisense.com");
await xr("sessionid", sessionid, "https://api.aisense.com");
```

**Assessment**:
- Cookie access limited to own domains (otter.ai, api.aisense.com)
- Used for legitimate authentication and CSRF protection
- No third-party cookie harvesting
- Standard session management pattern

**Verdict**: ✅ **FALSE POSITIVE** - Legitimate authentication mechanism

---

### 3. declarativeNetRequest Header Modification
**Severity**: LOW
**Files**: `src/background-script/background.js:18031-18066`

**Behavior**:
```javascript
// background.js:18031 - Modifies Referer header for own API calls
Fe.runtime.onInstalled.addListener(async function(t) {
  const e = [{
    id: 1,
    action: {
      type: "modifyHeaders",
      requestHeaders: [{
        header: "Referer",
        operation: "set",
        value: "https://otter.ai"
      }]
    },
    condition: {
      domains: [chrome.runtime.id],
      urlFilter: "https://api.aisense.com",
      resourceTypes: ["xmlhttprequest"]
    }
  }, {
    id: 2,
    action: {
      type: "modifyHeaders",
      requestHeaders: [{
        header: "Referer",
        operation: "set",
        value: "https://otter.ai"
      }]
    },
    condition: {
      domains: [chrome.runtime.id],
      urlFilter: "https://otter.ai/forward/api",
      resourceTypes: ["xmlhttprequest"]
    }
  }];
  await Fe.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: e.map(n => n.id),
    addRules: e
  });
});
```

**Assessment**:
- Only modifies requests from the extension itself (domains: [chrome.runtime.id])
- Sets Referer to otter.ai for API calls to api.aisense.com
- Required for CORS/CSRF validation on Otter's backend
- Does NOT intercept or modify user page requests

**Verdict**: ✅ **FALSE POSITIVE** - Standard CORS workaround for extension-to-API communication

---

### 4. Analytics and Telemetry
**Severity**: LOW (Privacy Concern, but Disclosed)
**Files**: `src/content-script/contentscript.js:77800-77850`

**Behavior**:
```javascript
// contentscript.js:77800 - Analytics initialization
{
  rudderStack: {
    enabled: true,
    key: "2x3ixLCN9kOqC34N4CgTvYENV8Q",
    configUrl: "https://rudder-api.otter.ai",
    internalDataPlanUrl: "https://rudder-event.otter.ai/",
    pluginsSDKBaseURL: "https://rudder-cdn.otter.ai/v3/modern/plugins",
    destSDKBaseURL: "https://rudder-cdn.otter.ai/v3/modern/js-integrations"
  },
  statSig: {
    enabled: true,
    key: "client-AgfhdSMRmeNqZpTt4cg9ytp2Bch3DskbAomr4586nOD",
    proxy: "https://statsig.otter.ai/v1",
    environmentTier: "production"
  },
  ingestLogs: {
    url: "https://otter.ai/ingest"
  }
}
```

**Data Collected**:
- User actions (button clicks, feature usage)
- Error messages and diagnostics
- Product analytics (feature adoption, usage patterns)
- Session/page view telemetry
- Experiment assignments (A/B testing via Statsig)

**Assessment**:
- Uses RudderStack (Segment alternative) and Statsig (feature flags)
- OpenTelemetry for application performance monitoring
- All analytics routed through Otter's infrastructure
- Standard SaaS product analytics
- No evidence of sensitive data leakage (e.g., transcription content in analytics)

**Verdict**: ⚠️ **PRIVACY CONCERN** - Extensive telemetry but standard for SaaS products

---

### 5. AI Assistant Integration (Claude)
**Severity**: LOW
**Files**: `src/background-script/background.js:10293-10320`

**Behavior**:
```javascript
// background.js:10293 - LLM proxy for Greenhouse interview feedback
async function Rg(t) {
  const e = `${Nn}/get_llm_proxy_response`,
    n = await ce(Qt, "csrftoken");
  return await fetch(e, {
    method: "POST",
    credentials: "include",
    headers: {
      "x-csrftoken": n,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      llm_request: {
        chat_content: [{
          type: "text",
          text: t  // User prompt
        }],
        sys_content: [{
          type: "text",
          text: Tg  // System prompt for Greenhouse feedback
        }],
        option: {
          models: ["claude-sonnet-4-20250514"],
          temperature: .7,
          max_tokens: 2000
        }
      }
    })
  })
}
```

**Context**: Prototype feature for auto-filling Greenhouse interview feedback forms using Claude AI.

**Assessment**:
- AI calls proxied through Otter's backend (not direct to Anthropic)
- System prompt hardcoded for interview feedback generation (background.js:10249-10269)
- User must explicitly trigger AI generation
- Sends interview transcripts/notes to Otter's LLM proxy
- No evidence of conversation scraping across other sites

**Verdict**: ✅ **LEGITIMATE FEATURE** - Opt-in AI assistant, data stays within Otter ecosystem

---

### 6. Prototype Features (Greenhouse & Gmail)
**Severity**: LOW
**Files**:
- `src/prototypes/greenhouse/content-script.js` (8,000+ lines)
- `src/prototypes/gmail/content-script.js` (8,000+ lines)

**Greenhouse Prototype**:
- Content script injected on `greenhouse.io` (interview platforms)
- Scrapes interview form fields and candidate information
- Searches Otter transcripts for relevant interview notes
- Generates AI-powered feedback using Claude via Otter backend
- Requires user to click "Generate" button

**Gmail Prototype**:
- Content script injected on `mail.google.com`
- Fetches recent Otter conversations for email drafting context
- Generates AI-powered email responses
- Requires explicit user action

**Assessment**:
- Both are legitimate productivity features
- Manifest explicitly declares host permissions for greenhouse.io and gmail
- No stealth scraping - user-initiated actions
- React-based UI components (not keyloggers despite keydown listeners)

**Verdict**: ✅ **FALSE POSITIVE** - Legitimate productivity integrations

---

### 7. Content Script on `<all_urls>`
**Severity**: LOW
**Files**: `src/content-script/contentscript.js` (78,000 lines)

**Behavior**:
- Content script injected on all pages (except Zoom)
- Primary purpose: Inject Otter UI when user clicks extension icon
- Minimal page interaction - mostly waits for user action
- Check for Google Meet pages to enable meeting transcription

**Assessment**:
```javascript
// contentscript.js:34975 - Google Meet detection
Ze = () => window.location.href.includes("meet.google.com");
```

- Content script is mostly dormant until user activates
- No XHR/fetch hooking on arbitrary pages
- No form field scraping outside declared prototype sites
- Large file size due to React + UI components (bundled)

**Verdict**: ✅ **FALSE POSITIVE** - Broad injection necessary for user-initiated recording

---

### 8. OpenTelemetry Instrumentation
**Severity**: LOW (False Positive Pattern)
**Files**: `src/background-script/background.js:1039-1065`

**Behavior**:
```javascript
// background.js:1039 - OpenTelemetry registration
sn = Symbol.for("opentelemetry.js.api." + ul)

// Contains trace, metrics, logs providers
this._proxyTracerProvider = new Ua
this._proxyLoggerProvider = new Va
```

**Assessment**:
- Standard application performance monitoring (APM) library
- Used for debugging, error tracking, performance metrics
- NOT used for user data collection
- Common false positive pattern (see MEMORY.md)

**Verdict**: ✅ **FALSE POSITIVE** - Legitimate APM instrumentation

---

## False Positives Identified

| Pattern | Files | Explanation |
|---------|-------|-------------|
| React `innerHTML` with SVG | gmail/content-script.js:2298, greenhouse/content-script.js:2372 | SVG rendering in React components |
| Form `.value` property access | Multiple | React form handling, not keylogging |
| `addEventListener('keydown')` | Multiple | React event handling, focus management |
| `Proxy` objects | background.js:754, 801, 7567 | OpenTelemetry API pattern, Chrome API wrappers |
| `eval()` and `Function()` references | Multiple | React/bundler internals, not dynamic code execution |
| `localStorage`/`sessionStorage` access | Multiple | Standard web storage for extension state |
| `sendBeacon` API | background.js:3615-3627 | Analytics beacon for page unload (standard telemetry) |

## API Endpoints and Data Flows

### Primary Endpoints
| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| `api.aisense.com/api/v1/login_csrf` | Session validation | Cookies (csrftoken, sessionid) | LOW |
| `api.aisense.com/api/v1/speech` | Start transcription | Audio stream, metadata | LOW |
| `api.aisense.com/api/v1/subscription` | Check user quota | User ID | LOW |
| `otter.ai/forward/api/v1/available_speeches` | Fetch transcripts | User ID, search query | LOW |
| `otter.ai/forward/api/get_llm_proxy_response` | AI assistance | Interview context, user prompt | MEDIUM |
| `rudder-api.otter.ai` | Analytics events | User actions, page views | LOW |
| `statsig.otter.ai/v1` | Feature flags | User ID, environment | LOW |
| `otter.ai/ingest` | Error logging | Error messages, stack traces | LOW |

### Data Flow Summary
```
User Audio → chrome.tabCapture → Extension Processing → api.aisense.com (Otter Backend) → Transcription Service
User Actions → RudderStack SDK → rudder-api.otter.ai → Analytics Pipeline
Interview Data → LLM Proxy → otter.ai/forward/api/get_llm_proxy_response → Claude (via Otter) → Generated Feedback
```

**Assessment**:
- All data flows to Otter-controlled infrastructure
- No third-party data brokers or ad networks
- No residential proxy or data harvesting SDKs
- Claude AI accessed through Otter's proxy (not direct)

## Security Strengths

1. ✅ **Strong CSP**: No external scripts, no eval(), no inline code
2. ✅ **Manifest V3**: Uses modern, restricted extension APIs
3. ✅ **Scoped Permissions**: Cookie access limited to own domains
4. ✅ **No Extension Killing**: No chrome.management API usage
5. ✅ **No Arbitrary XHR Hooking**: No monkey-patching of XMLHttpRequest/fetch
6. ✅ **User-Initiated Actions**: Audio capture requires explicit permission
7. ✅ **Legitimate Business Model**: Paid transcription SaaS (no ad injection)
8. ✅ **Transparent Features**: Greenhouse/Gmail integrations declared in manifest

## Privacy Concerns (Non-Malicious)

1. ⚠️ **Extensive Telemetry**: RudderStack, Statsig, OpenTelemetry track user behavior
2. ⚠️ **AI Data Processing**: Interview transcripts sent to Otter backend for Claude analysis
3. ⚠️ **Broad Content Script**: Injected on all pages (though mostly dormant)
4. ⚠️ **Third-Party Integrations**: Greenhouse/Gmail scraping (but user-initiated)

**Note**: These are privacy considerations for a SaaS product, not security vulnerabilities.

## Comparison to Known Malicious Patterns

| Pattern | Otter.ai | Malicious Examples |
|---------|----------|-------------------|
| XHR/Fetch Hooking | ❌ None | ✅ StayFree, StayFocusd, Urban VPN |
| Extension Enumeration | ❌ None | ✅ VeePN, Troywell, YouBoost |
| AI Conversation Scraping | ❌ None (own transcripts only) | ✅ StayFree (ChatGPT/Claude/Gemini) |
| Market Intelligence SDK | ❌ None | ✅ Sensor Tower Pathmatics |
| Ad Injection | ❌ None | ✅ YouBoost, Urban VPN |
| Remote Kill Switch | ❌ None | ✅ Troywell "thanos" |
| Residential Proxy | ❌ None | ✅ Troywell, Urban VPN |
| Cookie Harvesting | ✅ Limited to own domains | ❌ Urban VPN (cross-site) |

## Recommendations

### For Users:
1. ✅ Extension is safe to use for its intended purpose
2. ⚠️ Be aware that audio/transcripts are sent to Otter's servers
3. ⚠️ Review Otter.ai's privacy policy for data retention/usage
4. ⚠️ Greenhouse/Gmail features scrape page content (with permission)

### For Developers:
1. Consider reducing content script scope (currently `<all_urls>`)
2. Add user-facing privacy controls for analytics opt-out
3. Document AI data processing in privacy policy
4. Consider on-device transcription for privacy-sensitive users

### For Security Researchers:
- Monitor future updates for feature creep or permission escalation
- Verify Otter.ai's data retention and sharing policies
- Check for changes to telemetry endpoints

## Overall Risk Assessment

**RISK LEVEL: LOW** ✅

**Verdict**: Otter.ai is a **CLEAN, LEGITIMATE** extension with appropriate permissions for its transcription and AI assistant features. While it implements extensive analytics and handles sensitive audio data, all functionality aligns with its advertised purpose. No evidence of malicious behavior, data exfiltration, or deceptive practices.

**Classification**: CLEAN

### Risk Breakdown
- **Data Exfiltration**: NONE
- **Privacy Impact**: MEDIUM (due to audio/analytics)
- **Permissions Abuse**: NONE
- **Malicious Code**: NONE
- **Deceptive Practices**: NONE

---

## Technical Details

### File Structure
```
deobfuscated/
├── manifest.json (108 lines)
├── src/
│   ├── background-script/background.js (18,144 lines)
│   ├── content-script/contentscript.js (78,656 lines - React + UI)
│   ├── offscreen.js (28 lines)
│   ├── recordingTab/index.js (large audio processing)
│   ├── prototypes/
│   │   ├── greenhouse/content-script.js (8K lines - interview assistant)
│   │   └── gmail/content-script.js (8K lines - email assistant)
│   └── shared/
│       ├── tab-audio-processor.js (audio worklet)
│       └── rolling-byte-buffer.js (audio buffering)
```

### Key Code Patterns
- **Framework**: React 18.3.1 (production build)
- **Analytics**: RudderStack 3.15.2
- **Feature Flags**: Statsig 3.18.2
- **Monitoring**: OpenTelemetry (traces, logs, metrics)
- **Build System**: Modern JavaScript bundler (Webpack/Rollup)

### No Obfuscation
- Code is beautified, readable JavaScript
- No string encryption or control flow obfuscation
- Standard minification/bundling patterns
- React symbols visible ($$typeof, __SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED)

---

**Analysis completed**: 2026-02-06
**Analyst**: Claude Code Agent (Sonnet 4.5)
**Confidence**: HIGH
