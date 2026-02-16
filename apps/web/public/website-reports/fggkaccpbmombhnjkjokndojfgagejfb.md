# Security Analysis Report: Tactiq - AI note taker for Google Meet, Zoom and MS Teams

## Extension Metadata
- **Extension ID**: fggkaccpbmombhnjkjokndojfgagejfb
- **Name**: Tactiq - AI note taker for Google Meet, Zoom and MS Teams
- **Version**: 3.1.4849
- **Users**: ~1,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-06

---

## Executive Summary

Tactiq is a legitimate meeting transcription extension with **MEDIUM-HIGH** risk due to invasive WebRTC hooking, XHR/fetch interception on meeting platforms, and extensive analytics/telemetry collection. While designed for legitimate transcription purposes, the extension's aggressive instrumentation of web APIs and comprehensive user tracking present significant privacy concerns.

**Key Concerns:**
1. **RTCPeerConnection Override**: Patches native WebRTC APIs on Google Meet, Zoom, and MS Teams to intercept real-time captions/transcripts
2. **XHR/Fetch Hooking**: Intercepts network requests on Google Meet to extract session IDs and language settings
3. **Extensive Analytics**: Mixpanel, Datadog RUM, and custom telemetry tracking across all user interactions
4. **Optional Broad Permissions**: Requests `<all_urls>` as optional host permission for floating widget functionality
5. **Screenshot Capture**: Can capture tab screenshots via chrome.tabs API
6. **Firebase Authentication**: Full user authentication with persistent session tracking

**Mitigating Factors:**
- Legitimate business model (meeting transcription service)
- No evidence of malicious data exfiltration
- No extension enumeration/killing behavior
- No residential proxy infrastructure
- No third-party market intelligence SDKs (e.g., Sensor Tower)
- Strong CSP policy on extension pages

---

## Vulnerability Details

### 1. RTCPeerConnection Hooking (HIGH SEVERITY)

**Location**:
- `/deobfuscated/googlemeet.inline.js` (lines 8009-8128)
- `/deobfuscated/msteams.inline.js` (lines 5808-5851)
- `/deobfuscated/rtcinjector.js` (all platforms)

**Description**:
Tactiq overrides the native `window.RTCPeerConnection` API on Google Meet, Zoom, and MS Teams to intercept WebRTC data channels containing captions and transcripts.

**Code Evidence (Google Meet)**:
```javascript
// Line 8010-8032: RTCPeerConnection wrapper
let b = window.RTCPeerConnection,
  x = function(I, P) {
    let H = new b(I, P);
    return H.addEventListener("datachannel", function(ie) {
      ie.channel.label === "collections" && (window.tactiqRtc.RTCPeerConnection = H,
        ie.channel.addEventListener("message", Ae => {
          let Ft = i(Ae.data),
              is = s(Ft);
          // Intercepts caption data and dispatches to content script
          document.documentElement.dispatchEvent(new window.CustomEvent("tactiq-message", {
            detail: {
              type: "speech",
              messages: [rs]
            }
          }))
        }))
    }), H
  };

// Line 8124: Replace native API
window.RTCPeerConnection = x, window.RTCPeerConnection.prototype = b.prototype;
```

**Verdict**: **MEDIUM-HIGH RISK (Legitimate Use)**
- **Purpose**: Required for real-time caption extraction from meeting platforms
- **Scope**: Limited to meeting platforms (meet.google.com, zoom.us, teams.microsoft.com)
- **Privacy Impact**: Captures all spoken content in meetings (inherent to transcription functionality)
- **Mitigation**: Extension's core functionality; users should be aware they're consenting to real-time transcript capture

---

### 2. XHR/Fetch Interception on Google Meet (HIGH SEVERITY)

**Location**: `/deobfuscated/googlemeet.inline.js` (lines 8134-8229)

**Description**:
Tactiq hooks `XMLHttpRequest.prototype.open`, `XMLHttpRequest.prototype.send`, and `window.fetch` to intercept specific Google Meet API endpoints for session management and language settings.

**Code Evidence**:
```javascript
// Lines 8134-8164: XHR hooking
let p = window.XMLHttpRequest.prototype.open,
    g = window.XMLHttpRequest.prototype.send;
window.XMLHttpRequest.prototype.open = function(b, x) {
  x.toString().indexOf(Ee.modify) === 0 && (this.__tactiqRequestUrl = Ee.modify),
  x.toString().indexOf(Ee.queryCaptionLanguage) === 0 && (this.__tactiqRequestUrl = Ee.queryCaptionLanguage),
  p.apply(this, arguments)
};
window.XMLHttpRequest.prototype.send = function(b) {
  if (this.__tactiqRequestUrl) try {
    switch (this.__tactiqRequestUrl) {
      case Ee.modify: {
        let x = JSON.parse(b?.toString() || "[]"),
            [, , k, M] = x[3][0][17];
        // Extracts translation and transcript language IDs
        document.documentElement.dispatchEvent(new window.CustomEvent("tactiq-message", {
          detail: {
            type: "language-changed",
            payload: { translationLangId: k, transcriptLangId: M }
          }
        }));
        break
      }
      case Ee.queryCaptionLanguage: {
        xn = JSON.parse(b?.toString() || "[]")[1]; // Extracts media session ID
        break
      }
    }
  } catch (x) { }
  g.apply(this, arguments)
};

// Lines 8166-8229: Fetch hooking
window.fetch = function() {
  return new Promise((b, x) => {
    try {
      let [k, M] = arguments;
      // Intercepts createMeetingDevice, getMediaSession, updateMediaSession endpoints
      if (k === Ee.createMeetingDevice && M.body && M.headers) {
        let I = /\b[A-Za-z0-9_-]{28}\b/,
            H = new TextDecoder().decode(M.body).match(I);
        xn ??= H ? H[0] : null,
        os = Object.fromEntries(M.headers.entries()) // Stores auth headers
      }
    } catch (k) { console.debug(k) }
    C.apply(this, arguments).then(k => {
      // Intercepts responses from syncMeetingSpaceCollections, createMeetingMessage
      b(k)
    }).catch(k => { x(k) })
  })
};
```

**Targeted Endpoints**:
- `Ee.modify` - Language modification endpoint
- `Ee.queryCaptionLanguage` - Caption language query
- `Ee.createMeetingDevice` - Meeting device creation (extracts session ID)
- `Ee.getMediaSession` - Media session retrieval (extracts session ID)
- `Ee.updateMediaSession` - Language update endpoint
- `Ee.syncMeetingSpaceCollections` - Pre-meeting device sync
- `Ee.createMeetingMessage` - Real-time message creation

**Verdict**: **MEDIUM RISK (Legitimate Use)**
- **Purpose**: Required to manage Google Meet session state and language settings
- **Scope**: Only intercepts specific Google Meet API endpoints
- **Data Captured**: Session IDs, language preferences, auth headers (temporarily stored)
- **Privacy Impact**: Enables language switching and session management features

---

### 3. Extensive Analytics & Telemetry (MEDIUM-HIGH SEVERITY)

**Location**: `/deobfuscated/background.js` (multiple locations)

**Description**:
Tactiq implements comprehensive tracking via Mixpanel, Datadog RUM, and custom telemetry, collecting detailed user behavior, session recordings, and performance metrics.

**Analytics Platforms**:
1. **Mixpanel** (lines 12437-14024):
   - User identification: `Ro.identify(Un.uid)` (line 25493)
   - Event tracking: `mixpanel.track()`
   - People properties: Email, name, device ID, user ID
   - Session recording capabilities (rrweb integration)
   - Persistent storage in IndexedDB (`mixpanelRecordingEvents`, `mixpanelRecordingRegistry`)

2. **Datadog RUM** (lines 15000-18000):
   - Real User Monitoring with session replay
   - Error tracking and performance metrics
   - Telemetry sample rates configured (lines 16059-16061):
     - `telemetrySampleRate: 20%`
     - `telemetryConfigurationSampleRate: 5%`
     - `telemetryUsageSampleRate: 5%`

3. **Firebase Analytics** (lines 4270-4473):
   - Firebase project: `tactiq-prod-au` (line 25142)
   - Authentication tracking
   - Heartbeat database for session persistence

**Code Evidence**:
```javascript
// Line 25493-25501: User tracking initialization
Ro.identify(Un.uid), Ro.people.set({
  $email: Un.email,
  $name: Un.displayName
}), await nr.updateContext({
  userId: Un.uid,
  email: Un.email,
  domain: Un.email.split("@")[1] ?? "anonymous",
  anonymousId: ML
})

// Line 13041-13064: Session recording with rrweb
this._stopRecording = this._rrwebRecord({
  // Records DOM mutations, clicks, inputs, etc.
})
```

**Data Collected**:
- User ID (Firebase UID)
- Email address
- Display name
- Company domain (extracted from email)
- Installation ID (anonymous ID)
- Tab IDs and navigation events
- Meeting platform (Google Meet/Zoom/Teams)
- Language preferences
- Feature flag states
- DOM mutations and user interactions (via rrweb)
- Performance metrics and errors
- Screenshot capability (line 35195-35204)

**Verdict**: **MEDIUM-HIGH RISK**
- **Purpose**: Product analytics and debugging
- **Privacy Impact**: Extensive tracking of user behavior across all extension interactions
- **Data Retention**: Unclear retention policies for Mixpanel/Datadog
- **User Consent**: Not explicitly mentioned in manifest or prompts
- **Recommendation**: Users should review privacy policy; consider this level of telemetry when evaluating extension

---

### 4. Optional Broad Host Permissions (MEDIUM SEVERITY)

**Location**: `/deobfuscated/manifest.json` (lines 34-36)

**Description**:
Manifest requests optional permissions for `*://*/*` and `<all_urls>` to enable a "capture context widget" feature.

**Code Evidence**:
```json
"optional_host_permissions": [
  "*://*/*",
  "<all_urls>"
]
```

**Usage Context** (lines 35231-35288):
```javascript
case "tactiq.check-capture-widget-state": {
  let a = e.getState().user,
      o = !!a?.id,
      s = nr.isEnabled("extension-enable-floating-widget"),
      u = a?.settings?.captureContextWidget,
      c = u?.enabled ?? !0,
      l = u?.disabledSites || [];
  // ... returns widget state
}
```

**Verdict**: **MEDIUM RISK (Optional Feature)**
- **Purpose**: Floating widget for capturing context on any webpage
- **Scope**: User must explicitly grant permission
- **Mitigation**: Feature is behind a feature flag (`extension-enable-floating-widget`)
- **Privacy Impact**: If granted, extension can inject content scripts on all websites
- **Recommendation**: Users should deny optional permissions unless specifically needed

---

### 5. Screenshot Capture Capability (MEDIUM SEVERITY)

**Location**: `/deobfuscated/background.js` (lines 35195-35204, 25216-25221)

**Description**:
Extension can capture screenshots of the current active tab via `chrome.tabs.captureVisibleTab`.

**Code Evidence**:
```javascript
// Line 35195-35204: Screenshot capture handler
case "tactiq.get-current-tab-screenshot": {
  X0().then(a => i({
    success: !0,
    screenshot: a
  })).catch(a => {
    U.warn("Failed to get current tab screenshot", void 0, a), i({
      success: !1,
      error: String(a)
    })
  });
  break
}

// Line 25216-25221: Screenshot fetch wrapper
async function cL() {
  let e = await yr({
    type: "tactiq.get-current-tab-screenshot"
  });
  if (e.success && e.screenshot) return fetch(e.screenshot).then(t => t.blob())
}
```

**Verdict**: **LOW-MEDIUM RISK (Legitimate Use)**
- **Purpose**: Likely for attaching meeting screenshots to transcripts
- **Trigger**: Appears to be user-initiated or context-specific
- **Scope**: Only captures visible tab content (standard chrome.tabs permission)
- **Storage**: Screenshot data returned as blob, storage location unclear

---

### 6. Firebase Authentication & User Management (MEDIUM SEVERITY)

**Location**: `/deobfuscated/background.js` (lines 25139-25147, 4270-8072)

**Description**:
Full Firebase Authentication integration with persistent session management and user profile storage.

**Firebase Configuration**:
```javascript
// Line 25139-25147
var lJ = {
  apiKey: "AIzaSyBIibg6zIb1HLFzHjtBdyEj8fuitje9Wus",
  authDomain: "tactiq-prod-au.firebaseapp.com",
  databaseURL: "https://tactiq-prod-au.firebaseio.com",
  projectId: "tactiq-prod-au",
  storageBucket: "tactiq-prod-au.appspot.com",
  messagingSenderId: "399035273123",
  appId: "1:399035273123:web:0a0d0feae451bf70",
  measurementId: "G-K9TV4YH82E"
};
```

**Authentication Features**:
- Email/password authentication
- OAuth providers (Google, etc.)
- Custom token authentication (lines 35147-35157)
- ID token retrieval (lines 35159-35172)
- Persistent auth state in IndexedDB and localStorage
- Uninstall tracking URL with user ID (lines 25178-25185)

**Verdict**: **MEDIUM RISK (Standard Auth)**
- **Purpose**: User account management for premium features
- **Privacy Impact**: Full user profile linked to Firebase UID
- **Data Storage**: Auth tokens in IndexedDB/localStorage
- **Security**: Standard Firebase Auth (industry-standard)
- **Concern**: Uninstall tracking sends user ID to `api2.tactiq.io` endpoint

---

### 7. Dynamic Script Injection via chrome.scripting (LOW-MEDIUM SEVERITY)

**Location**: `/deobfuscated/background.js` (lines 35356-35386, 33995-34057)

**Description**:
Extension dynamically injects inline scripts into meeting pages at runtime, including Google Meet RTC override.

**Code Evidence**:
```javascript
// Lines 35367-35377: Google Meet RTC injection
await chrome.scripting.executeScript({
  target: {
    tabId: t
  },
  files: ["googlemeet.inline.js"],
  world: "MAIN",  // Injects into main world, not isolated content script
  injectImmediately: !0
}), U.debug("Injected RTCPeerConnection override into Google Meet tab", {
  tabId: t,
  url: n.url
})

// Lines 34022-34057: Dynamic content script registration
await chrome.scripting.registerContentScripts([{
  id: "chat-google",
  matches: ["*://chat.google.com/*"],
  js: ["chatgoogle.inline.js"],
  runAt: "document_start",
  world: "MAIN"
}])
```

**Injected Scripts**:
1. `googlemeet.inline.js` - RTCPeerConnection override on Google Meet
2. `zoom.inline.js` - Zoom meeting instrumentation
3. `msteams.inline.js` - MS Teams instrumentation
4. `chatgoogle.inline.js` - Google Chat integration

**Verdict**: **LOW-MEDIUM RISK (Required for Functionality)**
- **Purpose**: Inject platform-specific instrumentation for caption extraction
- **Scope**: Only on meeting platforms (meet.google.com, zoom.us, teams.microsoft.com, chat.google.com)
- **Risk**: Scripts run in "MAIN" world, can access page JavaScript context
- **Mitigation**: Required for WebRTC hooking functionality

---

### 8. Remote Configuration & Feature Flags (LOW-MEDIUM SEVERITY)

**Location**: `/deobfuscated/background.js` (lines 35391-35396, 25230-25243)

**Description**:
Extension uses a feature flag system that allows server-controlled functionality changes without extension updates.

**Code Evidence**:
```javascript
// Line 35391-35396: Feature flag initialization
await nr.updateContext({
  userId: e.getState().global.savedUserId || "anonymous",
  anonymousId: e.getState().global.installationId,
  domain: e.getState().user.email?.split("@")[1] ?? "anonymous"
}), await nr.start()

// Line 35234: Feature flag check
s = nr.isEnabled("extension-enable-floating-widget")

// Lines 35071-35078: Feature flags from storage
SCREENSHOTS: await Bt("SCREENSHOTS") ?? !1,
DOCUMENT: await Bt("DOCUMENT") ?? !0,
LANGUAGE_SWITCHER: await Bt("LANGUAGE_SWITCHER") ?? !1,
KEY_POINTS: await Bt("KEY_POINTS") ?? !1,
ASK_AI_TAB: await Bt("ASK_AI_TAB") ?? !0,
ASK_AI_QUICK_PROMPTS: await Bt("ASK_AI_QUICK_PROMPTS") ?? !1
```

**Feature Flags Observed**:
- `extension-enable-floating-widget` - Enables broad host permissions widget
- `extension-logs-enabled` - Debug logging toggle
- `SCREENSHOTS` - Screenshot capture feature
- `LANGUAGE_SWITCHER` - Language selection UI
- `KEY_POINTS` - AI key points extraction
- `ASK_AI_TAB` - AI assistant tab

**Verdict**: **LOW-MEDIUM RISK**
- **Purpose**: A/B testing and gradual feature rollout
- **Risk**: Server can remotely enable/disable features without user consent
- **Mitigation**: No evidence of kill switches or malicious remote control
- **Recommendation**: Monitor feature flag service for unexpected changes

---

### 9. Chrome Storage & Data Persistence (MEDIUM SEVERITY)

**Location**: `/deobfuscated/background.js` (lines 33655-33781, 35343-35350)

**Description**:
Extension stores meeting transcripts, user settings, and session state in chrome.storage.local with unlimitedStorage permission.

**Code Evidence**:
```javascript
// Line 33719-33727: Transcript storage
chrome.storage.local.set({
  [u]: {
    timestamp: a,
    data: JSON.stringify(d),
    metadata: f,
    blocks: JSON.stringify(p)
  }
})

// Line 35343-35350: Meeting state tracking
let n = (await chrome.storage.local.get(tI))[tI];
n ? (await chrome.storage.local.remove(tI), U.debug("Meeting state cleared successfully"))
```

**Stored Data Types**:
- Meeting transcripts (full text)
- Translation data
- User settings and preferences
- Meeting session state (meeting ID, tab ID, timestamps)
- Feature flag states
- Installation ID and user ID

**Verdict**: **MEDIUM RISK**
- **Purpose**: Offline transcript storage and state management
- **Privacy Impact**: Full meeting transcripts stored locally
- **Encryption**: No evidence of encryption at rest
- **Retention**: Unclear automatic cleanup policy
- **Recommendation**: Users should be aware transcripts persist in browser storage

---

## False Positive Analysis

| Pattern | Location | Explanation | Verdict |
|---------|----------|-------------|---------|
| Firebase API Keys | `background.js:25139` | Public Firebase config keys are safe to expose per Firebase docs | **FALSE POSITIVE** |
| `eval()` / `Function()` usage | Multiple bundled libraries | Standard library code (Redux, Apollo GraphQL, etc.) | **FALSE POSITIVE** |
| `setTimeout()` with callbacks | Throughout codebase | Legitimate async operations, not dynamic code execution | **FALSE POSITIVE** |
| Mixpanel session recording | `background.js:13041` | Standard Mixpanel rrweb integration, not malicious | **EXPECTED BEHAVIOR** |
| `document.cookie` access | Mixpanel/auth libraries | Standard cookie-based persistence, scoped to extension | **FALSE POSITIVE** |
| Datadog telemetry hooks | `background.js:17000+` | Standard Datadog RUM instrumentation | **EXPECTED BEHAVIOR** |
| `window.XMLHttpRequest` override | `googlemeet.inline.js:8134` | Required for Google Meet API interception | **EXPECTED BEHAVIOR** |
| `window.fetch` override | `googlemeet.inline.js:8166` | Required for Google Meet API interception | **EXPECTED BEHAVIOR** |
| `window.RTCPeerConnection` override | All `.inline.js` files | Core functionality for caption extraction | **EXPECTED BEHAVIOR** |
| `chrome.scripting.executeScript` | `background.js:35367` | Required for dynamic RTC injection | **EXPECTED BEHAVIOR** |

---

## API Endpoints & External Services

| Endpoint | Purpose | Data Sent | Risk Level |
|----------|---------|-----------|------------|
| `https://api2.tactiq.io/api/2/graphql` | GraphQL API for transcripts, user settings, AI features | User ID, transcripts, meeting metadata, settings | **MEDIUM** |
| `wss://api2.tactiq.io/api/2/graphql` | WebSocket for real-time updates | Subscription queries, live transcript updates | **MEDIUM** |
| `https://app.tactiq.io/*` | Web dashboard (externally connectable) | Auth tokens, user session data | **MEDIUM** |
| `https://api2.tactiq.io/api/2/u/uninstall/{installationId}/{userId}` | Uninstall tracking | Installation ID, User ID | **LOW-MEDIUM** |
| `https://tactiq-prod-au.firebaseapp.com` | Firebase Authentication | Email, password, OAuth tokens | **MEDIUM** |
| `https://tactiq-prod-au.firebaseio.com` | Firebase Database | User preferences, settings | **MEDIUM** |
| `https://api-js.mixpanel.com` | Mixpanel analytics | Events, user properties, session recordings | **MEDIUM-HIGH** |
| `https://mixpanel.com` | Mixpanel dashboard redirects | Replay session URLs | **LOW** |
| Datadog RUM (multiple domains) | Real User Monitoring | Performance metrics, errors, telemetry | **MEDIUM** |
| Google Meet API endpoints | Caption/transcript interception | Session IDs, language settings, auth headers (temporary) | **MEDIUM** |

---

## Data Flow Summary

### Meeting Transcript Flow:
1. **RTCPeerConnection hook** intercepts WebRTC data channels containing captions
2. **Inline scripts** extract caption messages and dispatch to content script
3. **Content script** aggregates messages into transcript blocks
4. **Background script** receives transcript via `chrome.runtime.sendMessage`
5. **Local storage** saves transcript to `chrome.storage.local` with `unlimitedStorage`
6. **GraphQL API** uploads transcript to `api2.tactiq.io` backend for cloud sync
7. **User dashboard** displays transcript at `app.tactiq.io`

### Analytics Data Flow:
1. **User actions** trigger event tracking in content/background scripts
2. **Mixpanel SDK** batches events with user ID, email, installation ID
3. **Mixpanel API** receives events at `api-js.mixpanel.com`
4. **Datadog RUM** collects performance metrics and error traces
5. **Firebase Analytics** tracks authentication events
6. **Session recordings** (rrweb) stored in IndexedDB, uploaded to Mixpanel

### Authentication Flow:
1. **User login** via Firebase Auth popup (Google OAuth or email/password)
2. **ID token** stored in IndexedDB (`firebaseLocalStorage`)
3. **Custom token** exchanged for session via GraphQL API
4. **Feature flags** fetched based on user ID, domain, installation ID
5. **User settings** synced from Firebase Database
6. **Uninstall URL** set with user ID for tracking

---

## Overall Risk Assessment: **MEDIUM-HIGH**

### Risk Breakdown:
- **Malware Indicators**: ❌ **NONE** - No evidence of malicious intent
- **Privacy Concerns**: ⚠️ **HIGH** - Extensive analytics, transcript capture, broad permissions
- **Security Posture**: ✅ **GOOD** - Strong CSP, manifest v3, no dynamic code eval
- **Transparency**: ⚠️ **MODERATE** - Legitimate service but aggressive tracking not clearly disclosed

### Verdict: **CLEAN** (with significant privacy caveats)

Tactiq is a **legitimate transcription service** with no malicious behavior. However, users should be aware of:

1. **All meeting audio is transcribed** and captured in real-time via RTCPeerConnection hooks
2. **Extensive analytics tracking** via Mixpanel and Datadog with unclear retention policies
3. **Session recordings** may capture DOM interactions and user behavior
4. **Optional broad permissions** allow injection on any website if user grants access
5. **Remote configuration** allows server-controlled feature changes
6. **Transcripts stored unencrypted** in local browser storage

### Recommendations:

**For Users:**
- ✅ **Safe to use** if you need meeting transcription and accept the privacy trade-offs
- ⚠️ Review Tactiq's privacy policy regarding data retention and third-party analytics
- ⚠️ Deny optional host permissions unless you need the floating widget feature
- ⚠️ Be aware all meeting conversations are captured and synced to cloud
- ⚠️ Consider if you're comfortable with Mixpanel/Datadog tracking across all extension usage

**For Security Researchers:**
- Monitor for changes in telemetry behavior or new tracking integrations
- Check if session recording (rrweb) captures sensitive user inputs
- Verify transcript data is encrypted in transit (HTTPS confirmed)
- Review future updates for changes to optional permissions scope

**Comparison to Known Malicious Patterns:**
- ❌ No extension enumeration/killing (unlike VeePN, Troywell)
- ❌ No residential proxy infrastructure (unlike Troywell)
- ❌ No market intelligence SDKs (unlike Sensor Tower/Pathmatics in StayFree)
- ❌ No ad injection or search manipulation (unlike YouBoost)
- ❌ No AI conversation scraping from third-party platforms (unlike Flash Copilot)
- ✅ Transparent business model (freemium transcription service)
- ⚠️ Similar analytics intensity to StayFree/StayFocusd (but for legitimate product metrics, not market intelligence)

---

## Technical Summary

**Core Functionality**: Meeting transcription via WebRTC data channel interception
**Permissions Used**: `activeTab`, `storage`, `unlimitedStorage`, `scripting`, `declarativeNetRequest`, `alarms`
**Optional Permissions**: `*://*/*`, `<all_urls>` (for floating widget)
**Host Permissions**: `meet.google.com/*-*-*` (required), `app.tactiq.io`, `testfirebaseauth-f5df6.firebaseapp.com` (externally connectable)
**CSP Policy**: ✅ Strong - `script-src 'self'; object-src 'self'` (no unsafe-eval, no unsafe-inline)
**Third-Party Services**: Mixpanel, Datadog, Firebase, GraphQL API (api2.tactiq.io)
**Storage**: chrome.storage.local (unlimited), IndexedDB (Firebase auth, Mixpanel events), localStorage (Mixpanel persistence)

**No Evidence Of:**
- Extension killing/disabling
- Residential proxy infrastructure
- Market intelligence data harvesting
- Ad injection or affiliate link manipulation
- Malicious remote code execution
- Credential theft or session hijacking
- Cross-site scripting vulnerabilities
- Third-party SDK injection beyond declared analytics

---

## Conclusion

Tactiq is a **legitimate, well-engineered extension** that delivers on its stated purpose (meeting transcription). The security concerns stem from the **inherently invasive nature of transcription services** and **aggressive analytics practices**, rather than malicious behavior.

Users should evaluate whether the convenience of automated transcription outweighs the privacy implications of real-time audio capture, extensive telemetry, and third-party analytics integrations.

**Final Rating: CLEAN (with MEDIUM-HIGH privacy impact)**
