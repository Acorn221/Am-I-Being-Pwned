# Vulnerability Report: Sidebarr - Bookmarks, Apps and more

## Extension Metadata
- **Extension ID**: afdfpkhbdpioonfeknablodaejkklbdn
- **Name**: Sidebarr - Bookmarks, Apps and more
- **Version**: 2.1.4
- **User Count**: ~20,000 users
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

Sidebarr is a bookmark and app management extension with AI chat functionality. The extension demonstrates **concerning privacy and security patterns** including hardcoded API keys, usage tracking with unique user identifiers, remote configuration capabilities, and broad data access permissions. While no overtly malicious behavior was detected, the extension's telemetry practices and third-party data transmission raise significant privacy concerns.

**Overall Risk Level**: **MEDIUM**

The extension serves its intended purpose (bookmark management and AI chat) but implements extensive tracking infrastructure and remote control capabilities that are not transparently disclosed to users.

## Vulnerability Details

### 1. MEDIUM: Hardcoded OpenAI API Key in Extension Code
**Severity**: MEDIUM
**File**: `background.bundle.js:598`
**Code**:
```javascript
apiKey: "sk-[REDACTED]"
```

**Description**: The extension contains a hardcoded OpenAI API key in the background script initialization. This key appears to be stored in local storage during installation. The key has since expired/been revoked.

**Impact**:
- Hardcoded API keys should never be embedded in client-side code
- Users' AI chat requests may be tracked by extension developers
- This appears to be a shared key across all installations, creating accountability and rate-limiting issues

**Verdict**: SECURITY RISK - Poor credential management practice. The key is expired but demonstrates a pattern of embedding secrets in client-side code.

---

### 2. MEDIUM: User Tracking with Unique Persistent Identifiers
**Severity**: MEDIUM
**File**: `background.bundle.js:605-717`
**Code**:
```javascript
this.uid = ""
this.config.uid ? e.uid = e.config.uid : (e.uid = e.config.uid = e.generateUID(), e.saveConfig())

generateUID: function() {
  return "xxxxxxxx-xxxx-2xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (function(e) {
    var t = 16 * Math.random() | 0;
    return ("x" == e ? t : 3 & t | 8).toString(16)
  }))
}
```

**Description**: Extension generates and stores a persistent UUID for each user, then transmits this identifier along with extension ID, version, and timestamps to remote servers on multiple events.

**Impact**:
- Cross-session user tracking without explicit consent
- User behavior profiling across install/uninstall events
- Telemetry data transmitted to https://sidebarr.org

**Verdict**: PRIVACY CONCERN - Persistent tracking identifiers are privacy-invasive. Users are not transparently informed about this tracking in the extension's intended functionality.

---

### 3. MEDIUM: Remote Configuration with Dynamic Update Capability
**Severity**: MEDIUM
**File**: `background.bundle.js:677-709`
**Code**:
```javascript
updateConfig: function() {
  fetch(this.configUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "filters=" + encodeURIComponent(btoa(JSON.stringify({
      id: chrome.runtime.id,
      version: this.version,
      timestamp: Date.now(),
      uid: this.config.uid
    })))
  }).then((function(e) {
    return e.json()
  })).then((function(t) {
    if (t) {
      for (var r in t) e.config[r] = t[r];
      e.saveConfig(e.config)
    }
  })).finally((function() {
    if (e.config.configUpTime && e.config.configUpTime > 0) {
      chrome.alarms.create("updateTimer", {
        delayInMinutes: t(e.config.configUpTime),
        periodInMinutes: t(e.config.configUpTime)
      })
    }
  }))
}
```

**Description**: Extension fetches configuration from `https://sidebarr.org/api/config/` and dynamically updates stored config, including setting periodic alarm timers based on remote values.

**Impact**:
- Remote server can modify extension behavior post-installation
- Alarm intervals controlled by remote configuration
- Potential for remote kill switch or behavior modification

**Verdict**: REMOTE CONTROL - While not inherently malicious, dynamic remote configuration creates a channel for post-deployment behavior changes without user notification or additional permission grants.

---

### 4. LOW: Installation and Uninstall Event Tracking
**Severity**: LOW
**File**: `background.bundle.js:608-660`
**Code**:
```javascript
chrome.runtime.onInstalled.addListener((function(t) {
  e.queue.push({
    type: "action",
    action: t.reason  // "install", "update", etc.
  })
}))

processQueue: function() {
  var t = "p=" + encodeURIComponent(btoa(JSON.stringify({
    id: chrome.runtime.id,
    v: this.version,
    action: e.action,
    uid: this.uid,
    t: Date.now()
  })));
  fetch(this.actionUrl + "?" + t)
}

chrome.runtime.setUninstallURL(this.uninstallUrl + "?" + e)
```

**Description**: Extension tracks install/update/uninstall events and transmits them to https://sidebarr.org/api/action/ and https://sidebarr.org/uninstall/ with user UUID.

**Impact**:
- User installation lifecycle tracking
- Attribution tracking for uninstalls
- Limited privacy concern for usage analytics

**Verdict**: ACCEPTABLE WITH DISCLOSURE - Common practice for extensions, but should be disclosed in privacy policy.

---

### 5. LOW: AI Chat Service with User Identifier Transmission
**Severity**: LOW
**File**: `background.bundle.js:758-770`, `rules.json`
**Code**:
```javascript
fetch("https://chat.sidebarr.net/api/generate", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-Client-UUID": r.uuid || ""
  },
  body: JSON.stringify({
    model: r.model,
    prompt: r.prompt,
    stream: !0
  })
})
```

**Description**: Extension sends AI chat prompts to chat.sidebarr.net with user UUID header. The extension modifies CORS headers via declarativeNetRequest to enable this communication.

**Impact**:
- User chat history potentially logged server-side
- AI prompts transmitted with identifying information
- Third-party service processes user queries

**Verdict**: EXPECTED FUNCTIONALITY - This is core to the extension's advertised AI chat feature, though privacy implications should be clearly disclosed.

---

### 6. INFO: Broad Permissions Grant
**Severity**: INFO
**File**: `manifest.json`
**Permissions**:
```json
"permissions": [
  "storage",
  "bookmarks",
  "scripting",
  "unlimitedStorage",
  "favicon",
  "declarativeNetRequest",
  "tabs",
  "alarms"
],
"host_permissions": ["<all_urls>"],
"content_scripts": [{
  "matches": ["http://*/*","https://*/*","<all_urls>"],
  "js": ["contentScript.bundle.js"]
}]
```

**Description**: Extension requests access to all websites, bookmarks, tabs, and can inject scripts on all pages.

**Impact**:
- Can read/modify all browsing data
- Access to bookmark structure and URLs
- Content script injection on every webpage

**Verdict**: PERMISSIONS ALIGNED WITH FUNCTIONALITY - These permissions are necessary for bookmark sidebar functionality and search engine integration, but represent significant access.

## False Positives

| Finding | Reason for Exclusion |
|---------|---------------------|
| React framework hooks | Standard React DOM manipulation patterns |
| `.call()` and `.apply()` usage | Standard JavaScript prototype methods, not dynamic code execution |
| Regenerator runtime polyfill | Standard Babel/Webpack async/await transpilation |
| SVG namespace references | Standard SVG manipulation (http://www.w3.org/2000/svg) |
| MathML namespace references | Standard MathML support |

## API Endpoints and Data Transmission

| Endpoint | Method | Data Sent | Purpose |
|----------|--------|-----------|---------|
| `https://sidebarr.org/api/action/` | GET | extension_id, version, action_type, uid, timestamp | Installation event tracking |
| `https://sidebarr.org/api/config/` | POST | extension_id, version, uid, timestamp | Remote configuration retrieval |
| `https://sidebarr.org/uninstall/` | GET (on uninstall) | extension_id, version, uid, timestamp | Uninstall tracking |
| `https://chat.sidebarr.net/api/generate` | POST | model, prompt, stream flag, X-Client-UUID header | AI chat functionality |
| `https://api.dictionaryapi.dev/api/v2/entries/en/{word}` | GET | word lookup | Dictionary widget feature |

## Data Flow Summary

1. **On Installation**: Extension generates persistent UUID, stores it locally, syncs bookmarks to local storage, injects content scripts into all existing tabs, transmits install event to sidebarr.org
2. **Periodic Updates**: Extension polls sidebarr.org/api/config/ for configuration updates with configurable intervals
3. **User Actions**: Bookmark operations stored locally, AI chat prompts sent to chat.sidebarr.net with UUID
4. **On Uninstall**: Uninstall URL opened with tracking parameters

**Data Exposure**: User UUID, extension metadata, bookmarks (local only), AI chat prompts (sent to external service)

## Privacy Analysis

**Concerning Patterns**:
- Persistent cross-session tracking identifier without clear disclosure
- Hardcoded API credentials in client code
- Remote configuration capability for dynamic behavior modification
- AI chat prompts transmitted with user identifiers

**Mitigating Factors**:
- No evidence of data exfiltration beyond described telemetry
- Bookmarks remain local (only synced to chrome.storage.local, not transmitted)
- No credential harvesting or keylogging detected
- No ad injection or content manipulation beyond intended sidebar functionality

## Recommendations

### For Users:
1. Review extension's privacy policy regarding data collection and AI chat usage
2. Be aware that AI chat prompts are transmitted to third-party servers
3. Consider that usage patterns are tracked with persistent identifiers
4. Understand that remote configuration allows developer to modify extension behavior

### For Developers:
1. Remove hardcoded API key; implement secure server-side proxy
2. Add transparent user consent for UUID tracking
3. Implement privacy policy disclosure for data transmission
4. Document remote configuration capabilities
5. Consider making telemetry opt-in rather than automatic

## Overall Risk Assessment

**Risk Level**: **MEDIUM**

**Justification**:
The extension provides legitimate bookmark management and AI chat functionality but implements privacy-invasive tracking and remote control mechanisms that are not transparently disclosed. The hardcoded API key represents a security vulnerability. No overtly malicious behavior was detected, but the combination of broad permissions, persistent tracking, and remote configuration creates a concerning privacy posture.

**Recommendation**: Users should be aware of the extensive tracking and third-party data sharing before installation. The extension is not malware but demonstrates poor privacy practices that warrant user awareness.
