# Vulnerability Report: Any.do

## Metadata
- **Extension ID**: kdadialhpiikehpdeejjeiikopddkjem
- **Extension Name**: Any.do
- **Version**: 4.4.0
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Any.do is a legitimate task management browser extension that provides task organization, calendar integration, and productivity features. The extension integrates with Google Calendar and uses Firebase for configuration and authentication. While the static analyzer flagged some patterns, detailed code review reveals these are standard implementations for a productivity application of this type.

The extension uses proper OAuth flows for Google Calendar integration, implements message handlers for internal iframe communication (add-task overlay, auth flow), and collects minimal browser/OS metadata solely for contact form submissions to their support system. No evidence of unauthorized data collection or malicious behavior was found.

## Vulnerability Details

### 1. LOW: postMessage Handlers Without Origin Validation

**Severity**: LOW
**Files**: Root.js:8333, src/add-task/index.js:74, src/entrypoints/content-scripts/auth.js:893, persistence.js:45
**CWE**: CWE-346 (Origin Validation Error)
**Description**: Multiple postMessage event listeners do not explicitly validate the origin of incoming messages. However, these handlers implement application-level validation instead.

**Evidence**:
```javascript
// Root.js:8333 - Lexical editor message handler
window.addEventListener("message", n, !0)

// src/add-task/index.js:74-75 - Add task overlay handler
window.addEventListener("message", e => {
  if (e.data == null || typeof e.data != "object" || e.data.src !== window.location.href) return;
  const t = e.ports[0];
  // ... handles add-task overlay communication
});

// src/entrypoints/content-scripts/auth.js:893-896 - Auth callback handler
window.addEventListener("message", o => {
  o.source === window && o.data === v && (console.log("updated"), F.runtime.sendMessage(void 0, {
    msg: v
  }))
});
```

**Verdict**: While origin checks would be best practice, the handlers implement sufficient validation:
- Add-task handler validates `e.data.src !== window.location.href`
- Auth handler checks `o.source === window` and validates specific message constant
- These are internal communication channels between extension components (iframe overlays, content scripts)
- No sensitive operations are triggered without additional validation

This is a minor security hygiene issue but not exploitable in practice for this application.

### 2. FALSE POSITIVE: navigator.userAgent Collection

**Static Analyzer Finding**: "navigator.userAgent → fetch"
**Files**: CategoryPickerMenu.js:997-1002, 1055

**Analysis**: The userAgent collection is NOT exfiltration. Code review shows:

```javascript
// CategoryPickerMenu.js:997-1002 - Browser detection function
function Az() {
  const e = navigator.userAgent;
  // ... parses browser name/version
  return t + " " + n  // Returns browser name + version string
}

// CategoryPickerMenu.js:1055 - Contact form URL generator
function T_t(e, t, n) {
  const r = new URLSearchParams;
  r.set("platform", "web");
  r.set("fullname", e);
  r.set("email", t);
  r.set("browser", Az());  // Browser name for support context
  r.set("os", xz());       // OS name for support context
  r.set("version", XD());  // Extension version
  return `https://www.any.do/contact_form?${r.toString()}`
}
```

This is standard practice for help desk systems - collecting browser/OS info when users submit support tickets. Not tracking or exfiltration.

## False Positives Analysis

1. **Obfuscated code flag**: The extension uses standard webpack bundling with minification. This is NOT malicious obfuscation - it's normal production build output. The deobfuscated code is readable and shows standard React/Firebase patterns.

2. **querySelectorAll → fetch to www.w3.org**: This is likely the static analyzer misidentifying DOM manipulation in the new-tab page that happens to have W3C schema references (standard HTML/XML namespaces). No actual data exfiltration to W3.org was found in code review.

3. **Remote config**: The extension uses Firebase Remote Config (`firebaseremoteconfig.googleapis.com`) which is a standard Google service for managing app configuration flags. This is legitimate infrastructure, not malicious remote code loading.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.any.do | Main app backend | Task data, user auth | Low - Own service |
| *.any.do subdomains | Various services (sync, websocket, thumbnails, A/B testing) | Task metadata, sync data | Low - Own infrastructure |
| firebaseremoteconfig.googleapis.com | Firebase Remote Config | Installation ID, app config request | Low - Google service |
| firebaseinstallations.googleapis.com | Firebase installations | Installation metadata | Low - Google service |
| fcmregistrations.googleapis.com | Firebase Cloud Messaging | Push notification registration | Low - Google service |
| www.googleapis.com/calendar/v3/* | Google Calendar API | Calendar events, CRUD operations | Low - Disclosed OAuth integration |
| www.googleapis.com/oauth2/v3/userinfo | Google OAuth userinfo | OAuth token exchange | Low - Standard OAuth flow |

All network communication is to legitimate services:
- Any.do's own infrastructure for task management
- Google APIs for documented Calendar integration (requires OAuth permission: `https://www.googleapis.com/auth/calendar`)
- Firebase services for standard mobile/web app infrastructure

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
Any.do is a legitimate productivity application with no evidence of malicious behavior. The flagged patterns are either false positives (userAgent for contact form metadata, webpack bundling) or minor security hygiene issues (postMessage handlers that implement sufficient application-level validation).

The extension's permissions are appropriate for its stated functionality:
- `identity` - Google OAuth integration for Calendar
- `scripting`, `activeTab` - Injecting the "add task" overlay on web pages
- `contextMenus` - Right-click menu to add tasks
- `storage` - Local task data
- `sidePanel` - MV3 sidebar UI
- `cookies` - Session management for www.any.do

All data collection is disclosed and necessary for the task management functionality. The extension communicates only with its own backend and Google services for documented integrations.

**Recommendation**: Safe to use. This is a well-established productivity tool with proper security practices.
