# Vulnerability Report: Privacy Extension For WhatsApp Web - wabulk.net

## Extension Metadata
- **Extension ID**: mbcghjiodcjankhkllfohcgnckhdbkmi
- **Name**: Privacy Extension For WhatsApp Web - WABULK
- **Version**: 3.3.16
- **Users**: ~100,000
- **Manifest Version**: 3
- **Developer**: wabulk.net (privacy-wa-web.wabulk.net)

## Executive Summary

This extension provides legitimate privacy-enhancing features for WhatsApp Web (blur effects, screen lock, message hiding) but exhibits **MEDIUM** risk due to third-party API communication, remote configuration capabilities, potential monetization tracking, and WhatsApp Web internal API access. While no actively malicious behavior was detected, the extension's architecture includes concerning data collection and remote control mechanisms.

**Key Concerns**:
1. Communicates with third-party backend (ext.leadsext.com) for user tracking and remote configuration
2. Injects scripts that hook into WhatsApp Web's internal WPP (WhatsApp Web Protocol) APIs
3. Sends user actions and extension state to remote servers
4. Implements promotional banner/dialog system controlled by remote server
5. Password reset functionality sends WhatsApp messages to user's own account
6. Uses anonymous user tracking with persistent identifiers

## Vulnerability Details

### 1. Third-Party Backend Communication & User Tracking
**Severity**: MEDIUM
**Files**: `assets/chunk-45801e15.js` (lines 21-89)
**Code**:
```javascript
const r = await a("https://ext.leadsext.com/crx/in", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: {
    aid: "749905846386-8ntjrq2jnhhh8cjuq3qgro3d67i2sj1q.apps.googleusercontent.com",
    idStr: "wa-privacy",
    anonCode: o,
    unicode: t.generateUUID(),
    timestamp: (new Date).getTime(),
    aiid: "749905846386-8ntjrq2jnhhh8cjuq3qgro3d67i2sj1q.apps.googleusercontent.com",
    idUni: "wa-privacy",
    aCode: o
  }
});
```

**Verdict**: The extension registers with a third-party analytics/monetization backend (ext.leadsext.com) on installation, sending:
- Anonymous user code (persistent across sessions)
- Unique identifiers (UUID)
- Timestamps
- Google API client ID (suggests OAuth integration or analytics)

The backend returns a token (`crx_vcwgjg`) that's included in all subsequent API requests. This creates a persistent user tracking mechanism beyond Chrome Web Store analytics.

---

### 2. Remote Configuration & Kill Switch
**Severity**: MEDIUM
**Files**: `assets/chunk-45801e15.js` (lines 54-74)
**Code**:
```javascript
const c = async e => {
  const o = await a("https://ext.leadsext.com/crx/cjj2", {
    method: "GET",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: {
      aid: "749905846386-8ntjrq2jnhhh8cjuq3qgro3d67i2sj1q.apps.googleusercontent.com",
      v: "3.3.16",
      l: e,
      unicode: t.generateUUID(),
      timestamp: (new Date).getTime(),
      aidd: "749905846386-8ntjrq2jnhhh8cjuq3qgro3d67i2sj1q.apps.googleusercontent.com",
      idUni: "wa-privacy"
    }
  });
  if (200 === o.code) {
    let e = t.ungzip(o.result);
    return e ? JSON.parse(e) : e
  }
  throw new Error(o.message)
};
```

**Verdict**: The extension fetches gzip-compressed remote configuration (`dockingInfo`) that controls:
- Promotional banner/dialog display frequency and content
- "Tools" menu red dot notifications
- Feature flags (pricing page visibility, static/guide prompts)
- Custom DOM selectors for injection (`inStor`, `notLInStor`, etc.)

This provides remote kill-switch and feature toggle capabilities without requiring extension updates.

---

### 3. WhatsApp Web Internal API Hooking
**Severity**: MEDIUM
**Files**: `assets/du.js` (injected script, lines 1-243)
**Code**:
```javascript
class t {
  async findAndSetActiveInstance() {
    const t = this.discoverInstances(); // Searches window for WPP_* objects
    // ... validates structure and methods ...
    if (this.validateStructure(s.instance)) {
      const n = await this.checkActiveStatus(s.instance);
      // Hooks into conn.isMainReady(), chat.list(), contact.list()
    }
  }
}

// Message handlers
if ("GET_MY_PROFILE_PICTURE_URL" === t.command) {
  const n = t.conn.getMyUserId();
  if (n && n._serialized) {
    return await t.contact.getProfilePictureUrl(n._serialized)
  }
}

if ("RESET_LOCK_PASSWORD" === t.command) {
  const i = n.conn.getMyUserId();
  let a = "Your new WhatsApp Web password is:" + t.tempPassword;
  const { sendMsgResult: c } = await n.chat.sendTextMessage(i, a, {
    createChat: !0,
    detectMentioned: !0
  });
}
```

**Verdict**: The extension injects a script (`du.js`) that discovers and hooks into WhatsApp Web's internal WPP (WhatsApp Web Protocol) instances. This provides access to:
- User authentication state (`conn.isAuthenticated()`)
- Chat list and message data (`chat.list()`, `chat.sendTextMessage()`)
- Contact information (`contact.getProfilePictureUrl()`)
- User ID (`conn.getMyUserId()`)

While used for legitimate features (password reset, profile picture display), this deep integration creates significant security exposure if the extension is compromised or updates add malicious features.

---

### 4. Promotional System with Remote Content
**Severity**: LOW-MEDIUM
**Files**: `assets/chunk-ea21a509.js` (lines 52-269)
**Code**:
```javascript
const G = {
  createBanner: async (e, o, t = {}) => {
    const n = { title: "title", description: "description", buttonText: "Do it", actionUrl: "#", autoShow: !1, ...t };
    // Injects promotional banner into WhatsApp Web DOM
    (await p()).insertAdjacentHTML("afterend", d);
    // Clickable elements open actionUrl in new tab
    b.addEventListener("click", (() => {
      window.open(n.actionUrl, "_blank"), G.toggleBanner(a, !1)
    }))
  },
  showPromotions: async i => {
    // Fetches promotion config from dockingInfo
    // Displays based on IntervalDay and last display timestamp
    const g = b.IntervalDay && "number" == typeof b.IntervalDay ? b.IntervalDay : 1;
    if (a - d >= 24 * g * 60 * 60 * 1e3 && (h = !0), !h) return !1;
    // Shows banner or dialog with remote content
  }
};
```

**Verdict**: The extension displays promotional banners/dialogs controlled by remote configuration. While currently benign (likely used for feature announcements or premium upsells), this could be abused to:
- Display phishing links disguised as legitimate notifications
- Promote malicious external services
- Track user engagement with specific promotions

Display frequency is stored locally and respects user dismissals, suggesting non-aggressive monetization.

---

### 5. User Behavior Analytics
**Severity**: LOW
**Files**: `assets/chunk-45801e15.js` (lines 45-53), `assets/chunk-ae15f93d.js` (lines 28944-28964)
**Code**:
```javascript
const s = async () => {
  const e = await a("https://ext.leadsext.com/crx/uuinf", {
    method: "GET",
    headers: { "Content-Type": "application/json" }
  });
  if (200 === e.code) return e.result;
  throw new Error(e.message)
};

// Local state tracking
actions: {
  increment() { this.count++ },
  incrementRated() { this.ratedCount++ },
  incrementWork() { this.workCount++ },
  updateVerificationStatus(e, t, n) { /* ... */ }
}
```

**Verdict**: The extension tracks:
- General usage count (`count`)
- Chrome Web Store rating interactions (`ratedCount`)
- "Work" actions (privacy feature usage, `workCount`)
- User info fetched from backend (`crxUserInfo` with `anon`, `g`, `m` flags)

This data is synced to Chrome storage and potentially reported to the backend, though no explicit telemetry upload was observed in analyzed code.

---

### 6. Privacy Feature Implementation
**Severity**: CLEAN
**Files**: `assets/chunk-ae15f93d.js` (lines 28883-28913)
**Code**:
```javascript
privacy: {
  switchObj: {
    overall: !0,
    usersGroupNames: !0,
    profilePictures: !0,
    lastMessagesPreview: !1,
    allMessagesInChat: !1,
    mediaPreview: !1,
    mediaGallery: !1,
    textInput: !1,
    autoLockScreen: !1,
    lockScreen: !1
  },
  defaultPrivacyCss: {
    usersGroupNames: "._2au8k,._21S-L,._21nHd,.zzgSd,._3WYXy,._1ux8Y,._2PElp,.czcZD,.selectable-text ._3NUK1{filter:blur(5px) grayscale(1);transition-delay:0s;}",
    profilePictures: ".qq0sjtgm,.csshhazd {filter: blur(8px) grayscale(1);transition-delay: 0s;}",
    // ... other blur CSS rules ...
  }
}
```

**Verdict**: Core privacy features are implemented via CSS injection (blur filters on WhatsApp Web elements). This is a legitimate, non-invasive approach that doesn't modify page content or intercept messages. The lock screen feature stores passwords locally in Chrome storage (not sent to servers).

---

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| `innerHTML` usage | `chunk-ea15f93d.js` (line 28902) | CSS injection for privacy blur effects - no user content |
| `postMessage` | `chunk-ea21a509.js` (line 848) | Content script ↔ injected script communication for WPP API access |
| `localStorage` | `chunk-ea21a509.js` (line 733) | Promotional red dot status tracking - benign UX state |
| `window.open()` | `chunk-ea21a509.js` (line 89) | Opens promotional links in new tabs - user-initiated clicks |
| jQuery inclusion | `chunk-ae15f93d.js` (line 25) | DOM manipulation library (version 3.6.4) - standard practice |

---

## API Endpoints

| URL | Method | Purpose | Data Sent |
|-----|--------|---------|-----------|
| `https://ext.leadsext.com/crx/in` | POST | User registration/authentication | `anonCode`, `uuid`, `timestamp`, `aid` |
| `https://ext.leadsext.com/crx/uuinf` | GET | Fetch user info/entitlements | Auth token (`crx_vcwgjg`) |
| `https://ext.leadsext.com/crx/cjj2` | GET | Fetch remote config (gzipped) | `version`, `locale`, `uuid`, `timestamp` |
| `https://ext.leadsext.com/crx/lps` | GET | Unknown (pricing/licensing?) | `uuid`, `timestamp`, `aid` |

All requests include:
- Custom header `crx_vcwgjg` (session token from registration)
- Standard CORS mode and credentials
- JSON/form-urlencoded content types

---

## Data Flow Summary

```
Installation → ext.leadsext.com/crx/in (POST anonymous ID)
             ↓
          Receive session token (crx_vcwgjg)
             ↓
Background script fetches remote config (ext.leadsext.com/crx/cjj2)
             ↓
          Config controls promotional display & feature flags
             ↓
Content script injects du.js into WhatsApp Web
             ↓
du.js hooks WPP API (conn, chat, contact modules)
             ↓
User actions trigger privacy features (CSS blur injection)
             ↓
Password reset → WPP API call → sends WhatsApp message to self
             ↓
Promotional banners/dialogs display based on remote config
             ↓
Usage metrics stored locally (count, ratedCount, workCount)
```

**No evidence found of**:
- Message content exfiltration
- Cookie harvesting
- Keylogging
- Extension enumeration/killing
- Residential proxy infrastructure
- Market intelligence SDKs
- Ad/coupon injection
- Dynamic code execution (eval/Function)

---

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
1. **Third-party backend dependency**: Users rely on ext.leadsext.com for core functionality, creating single point of failure and potential data collection
2. **WhatsApp Web API access**: Deep integration with WPP internals (chat, contact, auth) creates attack surface if extension is compromised
3. **Remote configuration**: Promotional content and feature flags controlled externally without user transparency
4. **Anonymous tracking**: Persistent user IDs enable usage profiling across sessions

**Mitigating Factors**:
1. No evidence of malicious data exfiltration
2. Privacy features work as advertised (CSS-based blurring)
3. Passwords stored locally, not sent to backend
4. Minimal permissions (storage, tabs, unlimitedStorage, commands - no webRequest, cookies, history)
5. Open install page and uninstall feedback URLs (transparency signals)
6. Promotional system respects user dismissals and display frequency limits

**Recommendations**:
- Monitor network traffic to ext.leadsext.com for data leakage
- Audit future updates for changes to WPP API usage
- Consider alternatives without third-party backend dependencies
- Users concerned about privacy should note the irony of using a "privacy extension" that phones home to tracking servers
