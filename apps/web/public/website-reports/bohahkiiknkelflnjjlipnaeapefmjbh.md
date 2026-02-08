# Vulnerability Report: Note Anywhere

## Extension Metadata
- **Extension ID**: bohahkiiknkelflnjjlipnaeapefmjbh
- **Extension Name**: Note Anywhere
- **Version**: 1.1.5
- **Users**: ~100,000
- **Developer**: William (myatoms.io)
- **Manifest Version**: 3
- **Homepage**: https://myatoms.io

## Executive Summary

Note Anywhere is a sticky notes extension that allows users to create notes on any webpage. The extension implements a **cloud sync feature that collects and transmits user notes along with browsing metadata** to an external server (`beta.myatoms.io`). While the extension appears to function as advertised, it poses **privacy concerns** due to the automatic collection and synchronization of user-generated content and browsing metadata to a third-party service.

The extension collects note content, page URLs, page titles, and favicon URLs, transmitting this data to `https://beta.myatoms.io/api/integration/sync` every hour automatically. Users must explicitly opt-in to sync by logging into the My Atoms platform, but the data collection permissions are granted through broad host permissions.

**Overall Risk Level**: **MEDIUM**

## Vulnerability Details

### 1. Privacy Concern: User Content and Browsing Metadata Collection

**Severity**: MEDIUM
**Files**:
- `js/background.bundle.js` (lines 2496-2517, 3031-3049, 3064-3070)
- `manifest.json` (lines 22-24, 50-54)

**Description**:
The extension collects and syncs user notes along with comprehensive browsing metadata to an external server operated by the developer. The data collection includes:
- Note text content (HTML)
- Full page URLs where notes are created
- Page titles (`r.tab.title`)
- Page favicon URLs (`r.tab.favIconUrl`)
- Timestamps

**Code Evidence**:
```javascript
// Data creation with metadata (background.bundle.js:2496-2517)
return e.next = 50, n.notes.add(h(h({}, t.data), {}, {
  sourceTitle: r.tab.title,
  sourceImage: r.tab.favIconUrl,
  syncId: u()(),
  timestamp: +new Date
}));

// Data transformation for sync (background.bundle.js:3031-3049)
function V(e) {
  var t, r, n, o;
  return {
    syncId: null !== (t = e.syncId) && void 0 !== t ? t : u()(),
    type: "note",
    note: e.text,
    app: "Note Anywhere",
    appMeta: e,
    source: {
      type: "web",
      title: null !== (r = e.sourceTitle) && void 0 !== r ? r : e.url,
      url: e.url,
      image: null !== (n = e.sourceImage) && void 0 !== n ? n : null
    },
    control: {
      deleted: null !== (o = e.deleted) && void 0 !== o ? o : 0,
      timestamp: e.timestamp
    }
  }
}

// Sync endpoint (background.bundle.js:3064-3070)
fetch("".concat(p.a.base, "/api/integration/sync?token=").concat(n), {
  method: "POST",
  body: JSON.stringify(t),
  headers: {
    "Content-Type": "application/json"
  }
});
```

**Sync Configuration**:
```javascript
// Automatic sync every hour (background.bundle.js:3084-3089)
s.a.alarms.create("sync", {
  delayInMinutes: 1,
  periodInMinutes: 60
}), chrome.alarms.onAlarm.addListener((function(e) {
  "sync" === e.name && U()
}))
```

**Verdict**: While this is a legitimate feature for cloud synchronization, it poses privacy risks because:
1. User browsing patterns are exposed through URLs and page titles
2. Note content may contain sensitive information (passwords, personal notes, financial data)
3. Data is sent to a third-party server with unclear data retention/privacy policies
4. Automatic hourly sync continues once enabled

**Mitigation**: Users should be aware that enabling sync shares their notes and browsing metadata with My Atoms service.

---

### 2. Overly Broad Host Permissions

**Severity**: LOW
**Files**: `manifest.json` (lines 22-24)

**Description**:
The extension requests broad host permissions for all HTTP/HTTPS sites:

```json
"host_permissions": [
  "http://*/*",
  "https://*/*"
]
```

While these permissions are necessary for the content script to inject notes on any webpage, they grant the extension access to all web traffic and page content. This is a standard pattern for note-taking extensions but increases the potential attack surface if the extension is compromised.

**Verdict**: EXPECTED - Permissions align with stated functionality but represent significant access.

---

### 3. External Message Handler Accepts Credentials

**Severity**: MEDIUM
**Files**:
- `js/background.bundle.js` (lines 2884-2907)
- `manifest.json` (lines 50-54)

**Description**:
The extension implements `chrome.runtime.onMessageExternal` to receive authentication tokens from external websites. The manifest allows messages from:
- `https://*.myatoms.io/*`
- `http://localhost:9000/*` (development endpoint)

**Code Evidence**:
```javascript
s.a.runtime.onMessageExternal.addListener(function() {
  var e = x(a.a.mark((function e(t, r, n) {
    return a.a.wrap((function(e) {
      for (;;) switch (e.prev = e.next) {
        case 0:
          if (console.log("external", r, t), "login" !== t.type) {
            e.next = 6;
            break
          }
          return e.next = 4, Object(g.d)("token", t.token);
        case 4:
          return e.next = 6, Object(g.d)("user", t.user);
        case 6:
          return e.abrupt("return", Promise.resolve("got your message, thanks!"));
```

**Manifest Configuration**:
```json
"externally_connectable": {
  "matches": [
    "https://*.myatoms.io/*",
    "http://localhost:9000/*"
  ]
}
```

**Verdict**: ACCEPTABLE - This is a legitimate OAuth-style authentication flow, but the localhost development endpoint should be removed in production builds. The wildcard subdomain (`*.myatoms.io`) is acceptable for a legitimate multi-subdomain service.

---

### 4. Content Script innerHTML Usage (Custom Elements Polyfill)

**Severity**: FALSE POSITIVE
**Files**: `js/contentScript.bundle.js` (lines 1661-2088, 2515-2518)

**Description**:
The content script contains extensive innerHTML manipulation code, but upon analysis, this is part of the Custom Elements v1 polyfill library (https://github.com/webcomponents/polyfills). The code patches native DOM methods to support custom elements in older browsers.

**Code Context**:
```javascript
// Polyfill code wrapping native methods
d = Object.getOwnPropertyDescriptor(window.Element.prototype, "innerHTML"),
x = window.Element.prototype.insertAdjacentHTML,
// ... patching for custom element lifecycle callbacks

// Legitimate note element usage (lines 2515-2518)
get: function() {
  return this.contentElement.innerHTML
},
set: function(e) {
  this.contentElement.innerHTML = e
}
```

**Verdict**: FALSE POSITIVE - This is standard web component polyfill code and the extension's own shadow DOM implementation for sticky notes. No XSS risk.

---

## False Positive Analysis

| Pattern | Location | Reason | Verdict |
|---------|----------|--------|---------|
| `innerHTML` | contentScript.bundle.js:1661-2088 | Custom Elements v1 polyfill from webcomponents/polyfills | FALSE POSITIVE |
| `innerHTML` | contentScript.bundle.js:2515-2518 | Shadow DOM content setter for note element | FALSE POSITIVE |
| `insertAdjacentHTML` | contentScript.bundle.js:1669-2045 | Polyfill patch for custom elements | FALSE POSITIVE |
| `Function("r", "regeneratorRuntime = r")` | background.bundle.js:59 | Babel regenerator-runtime initialization | FALSE POSITIVE |
| Browser API polyfill | background.bundle.js:190-1650 | webextension-polyfill library | FALSE POSITIVE |

## API Endpoints

| Endpoint | Method | Purpose | Data Sent |
|----------|--------|---------|-----------|
| `https://beta.myatoms.io/api/integration/sync?token={token}` | POST | Sync notes to cloud | `{ streamId, data: [notes], lastSync }` |

**Note Data Structure**:
```json
{
  "syncId": "unique-id",
  "type": "note",
  "note": "HTML content",
  "app": "Note Anywhere",
  "appMeta": { /* full note object */ },
  "source": {
    "type": "web",
    "title": "Page Title",
    "url": "https://example.com/page",
    "image": "https://example.com/favicon.ico"
  },
  "control": {
    "deleted": 0,
    "timestamp": 1234567890
  }
}
```

## Data Flow Summary

1. **User Creates Note**: Content script captures note content, position, style, and page metadata
2. **Local Storage**: Note saved to IndexedDB with URL, title, favicon, timestamp
3. **Sync Trigger**: Automatic hourly alarm OR manual sync OR browser close event
4. **Data Collection**: Extension queries IndexedDB for notes modified since last sync (max 100 per batch)
5. **External Transmission**: Notes with full metadata sent to `beta.myatoms.io` via authenticated POST
6. **Bidirectional Sync**: Server can send updated/deleted notes back to extension
7. **No Analytics/Tracking SDKs**: No third-party analytics found (Sensor Tower, Mixpanel, etc.)

## Security Posture

**Positive Findings**:
- ✓ No malicious tracking SDKs
- ✓ No keylogger or form data interception
- ✓ No cookie harvesting
- ✓ No extension enumeration or competitive interference
- ✓ No dynamic code execution (eval, Function constructor misuse)
- ✓ No XHR/fetch hooking
- ✓ Proper CSP: `script-src 'self'; object-src 'self'`
- ✓ Manifest v3 compliance
- ✓ User must opt-in to sync feature
- ✓ Uses webextension-polyfill for cross-browser compatibility
- ✓ Local-first functionality (notes work without sync)

**Privacy Concerns**:
- ⚠ Collects browsing metadata (URLs, titles, favicons) alongside note content
- ⚠ Automatic hourly sync to third-party server
- ⚠ Broad host permissions (all sites)
- ⚠ No visible privacy policy regarding data retention

**Minor Issues**:
- ⚠ Development endpoint (`localhost:9000`) left in production manifest
- ⚠ Beta subdomain (`beta.myatoms.io`) suggests potential stability concerns

## Risk Assessment

### Overall Risk: **MEDIUM**

**Justification**:
The extension functions as advertised and contains no malicious code. However, the automatic collection and transmission of user notes with browsing metadata to a third-party service raises legitimate privacy concerns. Users who create notes containing sensitive information (passwords, financial data, personal thoughts) should be aware that this data may be transmitted to My Atoms servers if sync is enabled.

The extension is suitable for general use but requires user awareness about:
1. What data is collected when sync is enabled
2. Where data is stored (My Atoms servers)
3. How to disable sync if privacy is a concern

### Risk Breakdown:
- **Malware/Malicious Intent**: CLEAN
- **Privacy/Data Collection**: MEDIUM
- **Security Vulnerabilities**: LOW
- **Permission Appropriateness**: ACCEPTABLE

## Recommendations

**For Users**:
1. Only enable sync if you trust My Atoms service with your note content and browsing patterns
2. Avoid storing sensitive information in notes if sync is enabled
3. Review synced data at https://beta.myatoms.io/
4. Disable sync from extension options if not needed

**For Developer**:
1. Remove `http://localhost:9000/*` from `externally_connectable` in production builds
2. Add clear privacy policy explaining data collection, retention, and usage
3. Implement end-to-end encryption for synced notes
4. Make sync opt-in more explicit (currently requires external login)
5. Consider moving from `beta.myatoms.io` to stable production domain

## Conclusion

Note Anywhere is a **legitimate productivity extension** with cloud sync capabilities. It does not contain malware, tracking SDKs, or malicious code. The primary concern is privacy-related: the extension collects user notes and browsing metadata when sync is enabled. Users should make an informed decision about whether to enable the sync feature based on their privacy preferences.

The extension is appropriate for users who:
- Want cloud-synced sticky notes across devices
- Trust the My Atoms platform with their data
- Don't store highly sensitive information in notes

The extension may not be suitable for users who:
- Require maximum privacy
- Store sensitive/confidential information in notes
- Want strictly local-only note storage
