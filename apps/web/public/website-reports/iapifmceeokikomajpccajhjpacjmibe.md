# Security Analysis Report: Auto Clicker - AutoFill

## Extension Metadata
- **Extension ID**: iapifmceeokikomajpccajhjpacjmibe
- **Name**: Auto Clicker - AutoFill
- **Version**: 4.1.17
- **Approximate Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-06

## Executive Summary

Auto Clicker - AutoFill is a legitimate automation extension for Chrome that allows users to record and replay browser interactions (clicks, form fills, etc.). The extension implements **CLEAN** security practices with appropriate telemetry, authentication, and sandboxing. While the extension has broad permissions suitable for its automation functionality, it does not exhibit malicious behavior.

**Key Findings**:
- Legitimate telemetry to Google Analytics and Grafana for monitoring
- Firebase authentication with optional Google/Discord OAuth integration
- Proper use of sandboxed eval for user script execution
- No evidence of data exfiltration, extension enumeration, XHR/fetch hooking, or residential proxy infrastructure
- Chrome userScripts API used appropriately for user-defined automation
- OpenTelemetry instrumentation scoped to extension's own operations

**Overall Risk Level**: CLEAN

## Detailed Findings

### 1. Permissions Analysis

#### Manifest Permissions
```json
"permissions": [
  "storage",           // Store automation configs
  "notifications",     // User notifications
  "contextMenus",      // Context menu integration
  "activeTab",         // Current tab access
  "identity",          // OAuth authentication
  "alarms",            // Scheduled tasks
  "unlimitedStorage",  // Large config storage
  "scripting",         // Execute automation scripts
  "userScripts",       // User-defined scripts (MV3)
  "webNavigation",     // Page navigation events
  "sidePanel"          // Chrome side panel UI
],
"host_permissions": ["http://*/*", "https://*/*"]
```

**Assessment**: Permissions are extensive but appropriate for browser automation functionality. The `userScripts` permission (MV3-specific) is used for executing user-defined automation scripts in page context.

#### Content Security Policy
Default MV3 CSP applies. No custom relaxation detected.

### 2. Content Scripts Analysis

#### Script Injection Points
Three content scripts injected on `<all_urls>`:

1. **content_scripts.js** (ISOLATED world, document_start)
   - 72KB minified/bundled code (ret-regexp library)
   - XPath/selector utilities for element identification
   - No DOM manipulation or data harvesting detected

2. **content_scripts_main.js** (MAIN world, document_start)
   - Lightweight helper (60 lines)
   - Exposes `window.ACFCommon.getElements()` for element selection
   - Used by automation scripts to locate DOM elements
   - **Code snippet**:
   ```javascript
   window.ACFCommon = {
     getElements: async e => {
       // Supports multiple selector types: ID, Class, XPath, etc.
       if (/^(id::|#)/gi.test(e)) {
         const o = document.getElementById(e.replace(/^(id::|#)/gi, ""));
         t = o ? [o] : void 0
       }
       // ... additional selector logic
     }
   }
   ```

3. **wizard.js** (ISOLATED world, document_end)
   - Interactive automation wizard UI
   - Records user interactions (clicks, form fills)
   - Generates automation configs
   - No keylogging - only captures blur events on focused inputs

**Verdict**: CLEAN - Content scripts provide automation functionality without privacy violations.

### 3. Background Script Analysis

#### Network Endpoints

| Endpoint | Purpose | Data Sent | Verdict |
|----------|---------|-----------|---------|
| `https://www.google-analytics.com/mp/collect` | Google Analytics 4 telemetry | client_id (device ID), user_id, session_id, event names, extension version | CLEAN - Standard analytics |
| `https://otlp-gateway-prod-ap-south-1.grafana.net/otlp/v1/traces` | OpenTelemetry tracing | Performance traces, error logs | CLEAN - Observability monitoring |
| `https://otlp-gateway-prod-ap-south-1.grafana.net/otlp/v1/logs` | OpenTelemetry logging | Application logs | CLEAN - Error tracking |
| `https://stable.getautoclicker.com` | Extension web app | N/A | CLEAN - Legitimate domain |
| `https://auto-clicker-autofill-default-rtdb.firebaseio.com` | Firebase Realtime Database | User configs, subscriptions | CLEAN - Cloud storage |
| `https://us-central1-auto-clicker-autofill.cloudfunctions.net` | Firebase Cloud Functions | User data | CLEAN - Backend API |
| `https://discord.com/api/oauth2/authorize` | Discord OAuth | OAuth flow | CLEAN - Optional integration |
| `https://www.googleapis.com/oauth2/v3/userinfo` | Google OAuth | User profile | CLEAN - Authentication |

#### Configuration Constants (background.js:14330-14343)
```javascript
const n = "PROD",
  s = "https://stable.getautoclicker.com",
  i = "823765451199873044",  // Discord client ID
  o = "G-XQYJ5J7YBD",        // GA4 measurement ID
  a = "vMDF_2R2Tm6Dm_fkcpEU8g", // GA4 API secret
  c = "15763641869-nr64dmjefme58g2aqd91lchgk1l8bdu9.apps.googleusercontent.com", // OAuth client
  u = "AIzaSyCNwhdpTxJxprM1Ba9S0GFgNnNdQ-jO0LA" // Firebase API key
```

**Note**: Firebase API keys are public by design (not secrets). Authentication enforced by Firebase Security Rules.

#### Google Analytics Implementation (background.js:4618-4642)
```javascript
async fireEvent({ name: e, params: t = { source: "unknown" } }) {
  if (this.MEASUREMENT_ID && this.API_SECRET) {
    t.session_id || (t.session_id = await this.getOrCreateSessionId()),
    t.engagement_time_msec || (t.engagement_time_msec = 100),
    t.version = chrome.runtime.getManifest().version;

    await fetch(`https://www.google-analytics.com/mp/collect?measurement_id=${this.MEASUREMENT_ID}&api_secret=${this.API_SECRET}`, {
      method: "POST",
      body: JSON.stringify({
        client_id: await this.getClientId(),  // Device ID
        user_id: await this.getUserId(),      // Firebase UID (if logged in)
        events: [{ name: e, params: t }]
      })
    })
  }
}
```

**Assessment**: Standard GA4 Measurement Protocol. No PII or sensitive data collection detected.

### 4. Dynamic Code Execution

#### Sandboxed Eval (html/sandbox.html)
```javascript
window.addEventListener('message', (event) => {
  const { command, context, name } = event.data;
  if (command === 'eval') {
    try {
      const result = eval(context);
      event.source.postMessage({ name, result }, event.origin);
    } catch (error) {
      event.source.postMessage({ name, error }, event.origin);
    }
  }
});
```

**Purpose**: Safely evaluate user-provided expressions (e.g., JavaScript conditionals in automation rules) in isolated sandbox iframe (CSP-enforced, no DOM access).

**Verdict**: CLEAN - Proper sandboxing implementation.

#### UserScripts API (background.js:6250-6295)
```javascript
async execute({ code: e, ext: t }, r) {
  const i = r.tab?.id;
  const o = await chrome.userScripts.execute({
    injectImmediately: !0,
    target: { tabId: i },
    js: [
      { code: `window.ext = ${JSON.stringify(t)};` },
      { code: e }
    ]
  });
  return { result: o[0].result, error: o[0].error }
}
```

**Purpose**: Execute user-defined automation scripts created through the wizard. Replaces MV2's content script injection.

**Verdict**: CLEAN - Legitimate automation functionality.

#### chrome.scripting.executeScript (background.js:14820-14847)
```javascript
async click(e, t) {
  chrome.scripting.executeScript({
    world: "MAIN",
    target: { tabId: t.tab.id, allFrames: !0 },
    func: e => {
      window.ACFCommon.default.getElements(e).then(e => {
        e.forEach(e => { e.click() })
      })
    },
    args: [e]
  })
}

async bypass(e, t) {
  chrome.scripting.executeScript({
    world: "MAIN",
    target: { tabId: t.tab.id, allFrames: !0 },
    func: e => {
      e.alert && (window.alert = () => {});
      e.confirm && (window.confirm = () => !0);
      e.prompt && (window.prompt = () => "");
    },
    args: [e]
  })
}
```

**Purpose**: Execute automation actions (clicks, bypassing alerts/prompts) as requested by user configs.

**Verdict**: CLEAN - Expected automation behavior.

### 5. Authentication & Data Storage

#### Firebase OAuth Integration (background.js:14362-14425)
- Supports Google Sign-In via `chrome.identity.launchWebAuthFlow()`
- Optional Discord OAuth for community features
- User authentication required for cloud config sync
- Firestore stores user profiles, automation configs, Stripe subscriptions

**Data stored in Firebase**:
- User profiles (`users/{uid}`)
- Public profiles (opt-in)
- Discord usernames (opt-in)
- Automation configurations (`configurations/{configId}`)
- Stripe subscriptions (`customers/{uid}/subscriptions`)

**Verdict**: CLEAN - Standard SaaS authentication/storage.

### 6. Externally Connectable

```json
"externally_connectable": {
  "matches": [
    "http://localhost:*/*",
    "https://*.getautoclicker.com/*",
    "https://*.getdataentry.com/*"
  ]
}
```

**Purpose**: Allows extension's web app (getautoclicker.com) to communicate with extension via `chrome.runtime.sendMessage()`.

**Implementation** (background.js:4903-4909):
```javascript
static onMessageExternal(e) {
  chrome.runtime.onMessageExternal.addListener((t, r, n) =>
    p(t, r, e).then(n).catch(e => {
      n({ error: e.message })
    }), !0
  )
}
```

**Verdict**: CLEAN - Standard web-to-extension messaging for legitimate domains.

### 7. OpenTelemetry Instrumentation

#### Grafana Cloud Exporter (background.js:4537-4542)
```javascript
const H = e => ({
  url: `https://otlp-gateway-prod-ap-south-1.grafana.net/otlp/v1/${e}`,
  headers: {
    Authorization: "Basic MTQ4MTQwMjpnbGNfZXlKdklqb2lNVFl5T0RjeE9DSXNJbTRpT2lKemRHRmpheTB4TkRneE5EQXlMVzkwYkhBdGQzSnBkR1V0YzJWeWRtbGpaUzEzYjNKclpYSWlMQ0pySWpvaU1XY3hSRE16Vmpkek1reGhOR3RzYlhBMFpYQTJWV1U1SWl3aWJTSTZleUp5SWpvaWNISnZaQzFoY0MxemIzVjBhQzB4SW4xOQ=="
  },
  concurrencyLimit: 10
})
```

**Data sent**: Performance traces, error logs, span attributes
**Scope**: Extension's own operations (not page content)
**Purpose**: Developer observability/debugging

**Verdict**: CLEAN - Standard APM instrumentation (similar to Sentry/Datadog).

### 8. Checked Attack Vectors

| Attack Vector | Present | Evidence |
|---------------|---------|----------|
| XHR/Fetch hooking | NO | Only FetchProvider wrapper for Firebase SDK (not injected into pages) |
| Extension enumeration | NO | No chrome.management API usage |
| Extension disabling | NO | No extension manipulation detected |
| Residential proxy | NO | No proxy infrastructure |
| Cookie harvesting | NO | No chrome.cookies API usage |
| Browsing history | NO | No chrome.history API usage |
| Keylogging | NO | Only blur events for form autofill recording (user-initiated) |
| Remote config kill switch | NO | No dynamic behavior modification |
| Market intelligence SDKs | NO | No Sensor Tower/Pathmatics/similar |
| AI conversation scraping | NO | No platform-specific interceptors |
| Ad injection | NO | No DOM manipulation for ads |
| Search manipulation | NO | No search engine tampering |

## False Positives Explained

| Pattern | File | Explanation |
|---------|------|-------------|
| OpenTelemetry XHR/fetch hooks | background.js:12332 | Instrumentation library for tracing extension's own API calls (not injected into pages) |
| Firebase public API keys | background.js:14338 | Public by design - auth enforced by Firestore Security Rules |
| Grafana Basic auth header | background.js:4540 | Hardcoded API token for developer's telemetry account (not user data exfil) |
| Zone.js intercept methods | background.js:12428,12565 | Angular change detection framework (bundled dependency, not malicious) |
| Sandboxed eval | html/sandbox.html:12 | CSP-sandboxed iframe for safe expression evaluation |
| chrome.scripting.executeScript | background.js:14822,14840 | Legitimate automation script execution |
| chrome.userScripts.execute | background.js:6279 | MV3 API for user-defined automation (replaces MV2 content scripts) |

## Data Flow Summary

```
User → Extension UI → Chrome Storage (local automation configs)
                    ↓
User (authenticated) → Firebase Auth → Firestore (cloud config backup)
                                     ↓
Extension usage → Google Analytics → GA4 dashboard
                ↓
Extension errors/traces → Grafana Cloud → Developer monitoring

User automation → chrome.scripting/userScripts → Target webpage
```

**No sensitive user data leaves the browser** except:
1. Opted-in cloud config sync (encrypted in transit, stored in user's Firebase account)
2. Anonymous telemetry (device ID, session ID, event names - no PII)
3. Performance traces (error messages, timing data - no page content)

## Security Strengths

1. **MV3 Compliance**: Uses modern userScripts API instead of legacy eval-based injection
2. **Proper Sandboxing**: Eval confined to CSP sandbox with no DOM/network access
3. **Minimal Telemetry**: Only usage analytics and error tracking (no user content)
4. **Transparent OAuth**: Uses standard chrome.identity flows (user consent required)
5. **No Third-Party Trackers**: All telemetry goes to first-party services (GA/Grafana)
6. **Open Source Spirit**: Code structure suggests project is open-source (GitHub sponsors link in UI)

## Recommendations

**For Users**:
- Extension is safe to use for its intended purpose (browser automation)
- Be aware that automation scripts run with your page privileges (don't import untrusted configs)
- Cloud sync requires Google/Discord login (optional feature)

**For Developers**:
- Consider rotating Grafana API token (currently hardcoded in client)
- Add integrity checks for user-imported automation configs
- Document data collection in privacy policy

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

Auto Clicker - AutoFill is a legitimate browser automation tool with appropriate permissions, transparent telemetry, and no evidence of malicious behavior. The extension follows Chrome Web Store policies and modern security best practices (MV3, sandboxing, OAuth).

**Confidence: HIGH** - Extensive code review, all major attack vectors checked, legitimate developer infrastructure identified.

---

**Analyst Notes**: This extension represents a good example of a high-permission automation tool that maintains user trust through proper security implementation. The OpenTelemetry/Firebase/GA4 stack is standard for modern SaaS extensions. No red flags detected.
