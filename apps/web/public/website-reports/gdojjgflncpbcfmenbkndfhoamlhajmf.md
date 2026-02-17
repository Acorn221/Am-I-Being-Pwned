# Security Analysis: Annotate: Web Annotations with Screen Sharing
**Extension ID:** gdojjgflncpbcfmenbkndfhoamlhajmf
**User Count:** ~200,000
**Analysis Date:** 2026-02-06
**Risk Level:** CLEAN

---

## Executive Summary

Annotate is a legitimate educational tool for web annotation, PDF annotation, and screen sharing during Google Meet sessions. The extension integrates with the Annotate.net platform and provides collaborative annotation capabilities for teachers and students.

**No significant security vulnerabilities identified.** The extension operates as designed with appropriate permissions for its functionality. All observed behaviors are legitimate educational features.

---

## Manifest Analysis

### Permissions (Appropriate)
```json
"permissions": [
  "desktopCapture",     // Screen sharing in Google Meet
  "activeTab",          // Content injection for annotations
  "contextMenus",       // Right-click menu for highlighting
  "tabs",               // Tab management for PDF viewer
  "storage",            // User settings and annotation storage
  "alarms",             // Periodic tasks (state checks)
  "webNavigation",      // Frame detection for Google Slides/Docs
  "scripting"           // Content script injection
]
```

### Host Permissions
- `*://*/*` and `<all_urls>` — Required for web page annotation on any site
- **Justified:** Core functionality requires annotating arbitrary web pages

### OAuth Integration
- Google OAuth client ID: `759190914734-tci7fg5s2c2c7d3g1s2ad3806liupkhg.apps.googleusercontent.com`
- Scopes: `email`, `drive.readonly`, `drive.install`
- **Purpose:** PDF viewer integration with Google Drive

### Content Security Policy
- **Missing CSP header** in manifest — Not required for MV3, but absence noted
- No inline script execution detected in HTML files

---

## Network Communication Analysis

### Primary Domains
1. **annotate.net** (Primary backend)
   - `/zpadopenrequest.php` — Open user annotation requests
   - `/zpaduserrequest.php` — Authenticated user operations
   - `/zpadstudentrequest.php` — Student-specific requests
   - `/AnnotateDataRequest.php` — Annotation data retrieval
   - WebSocket: `wss://annotate.net:443/edgeconnection/ws` — Real-time collaboration

2. **googleapis.com** (Google Drive integration)
   - `/oauth2/v3/tokeninfo` — Token validation
   - `/drive/v3/files/` — PDF file access
   - `/v1/presentations/` (Google Slides API)

### WebSocket Connection
```javascript
// BackgroundMain.js:606
$a(b.g, "wss://" + b.h + ":" + b.port + b.l + "/ws?" + b.j);
// Parameters: userguid, ulogintype=1, PHPSESSID
```
- **Purpose:** Real-time collaboration for live annotation sessions
- **Reconnection logic:** Exponential backoff (5s → 30s max)
- **Loop detection:** Prevents infinite reconnect attempts (10 attempts in 10 minutes)

### CSRF Protection
```javascript
// BackgroundMain.js:1208-1229
D(["csrf_token"], e => {
  a.CSRFtoken = e.csrf_token;
  // All POST requests include CSRF token
});
// Error 21 triggers token regeneration
```

---

## Chrome API Usage

### Screen Capture (Legitimate)
```javascript
// BackgroundMain.js:3028
chrome.desktopCapture.chooseDesktopMedia(
  ["screen", "window"],
  b.tab,
  function(g) { /* stream ID returned to content script */ }
);
```
- **Purpose:** Screen sharing during Google Meet annotation sessions
- **User consent:** Requires explicit user selection of screen/window

### Tab Screenshot (Legitimate)
```javascript
// BackgroundMain.js:4030
chrome.tabs.captureVisibleTab(a.windowId, c, function(d) {
  // Creates annotation thumbnails
});
```
- **Frequency:** Only triggered by user annotation save actions
- **Storage:** Uploaded to annotate.net S3 bucket for thumbnail generation

### Context Menus
```javascript
// BackgroundMain.js:2870-2878
chrome.contextMenus.create({
  id: "annotate hightlight",
  title: "Highlight",
  contexts: ["selection"]
});
chrome.contextMenus.create({
  id: "annotate add image",
  title: "Add image to notebook",
  contexts: ["image"]
});
```

---

## Content Script Analysis

### Keyboard Event Listeners (Legitimate)
```javascript
// ContentMain.js — Multiple instances for annotation tool shortcuts
document.addEventListener("keydown", a, {capture: true, passive: false});
```
- **Purpose:** Annotation tool keyboard shortcuts (e.g., arrow keys for navigation)
- **Context:** Only active when annotation mode is enabled
- **No keylogging:** Events used for UI control, not transmitted

### PostMessage Communication
```javascript
// ContentMain.js:11036
window.top != window && (
  console.log("sent access token to base frame"),
  z.na({type: "AuthTokenForBaseFrame", accessToken: a.l}, null)
);
```
- **Purpose:** Cross-frame communication for Google Slides/Docs iframe integration
- **Scope:** Limited to internal frames within the extension's context

### DOM Manipulation
- **No suspicious innerHTML injection** detected
- Uses standard DOM APIs for annotation overlay rendering
- Canvas-based drawing tools for annotation markup

---

## Data Collection & Privacy

### User Data Transmitted
1. **Authentication:**
   - User GUID, user type (teacher/student), session token
   - Google OAuth access tokens (for Drive integration)

2. **Annotations:**
   - Annotation content (drawings, text, highlights)
   - Page URLs where annotations are created
   - Timestamps and version numbers

3. **Classroom Integration:**
   - Class IDs, assignment metadata
   - Student submission tracking (Google Classroom integration)

### Storage
```javascript
// BackgroundMain.js:2075-2088
chrome.storage.local.set(a).then(() => { /* success */ });
// Stores: loginResponse, csrf_token, annotation cache, user preferences
```
- **Local storage:** User session, annotation drafts
- **Server storage:** Final annotations on annotate.net backend

### No Third-Party Analytics
- **No Google Analytics** detected
- **No Sentry/error tracking SDKs**
- Console logging disabled: `console.log = function() {};`

---

## False Positive Patterns Detected

### 1. WebSocket Implementation (Legitimate)
```javascript
// ContentMain.js:41142
this.g = new WebSocket(a);
```
- **Not malicious:** Standard WebSocket for real-time collaboration
- Matches educational platform use case

### 2. setTimeout/setInterval (Legitimate)
```javascript
// BackgroundMain.js:720
a.l = setInterval(function() {
  a.T(a.I, a.type, a.g);  // Channel health check
}, 10000);
```
- **Purpose:** WebSocket keepalive, state management
- No dynamic code execution via strings

### 3. Base64 Encoding (Legitimate)
```javascript
// BackgroundMain.js:2248
e += "pdfData=" + btoa(JSON.stringify(f));
```
- **Purpose:** URL parameter encoding for PDF viewer state
- **Decoding:** `atob()` used to restore state from URL params
- No obfuscation intent detected

---

## Google Drive Integration Analysis

### PDF Import Flow
1. User authorizes Google Drive access via OAuth
2. Extension retrieves PDF file metadata from Drive API
3. File downloaded to blob, converted to base64 data URL
4. Sent to content script in chunks (10MB limit per message):
```javascript
// BackgroundMain.js:2285-2291
chrome.tabs.sendMessage(a.tab.id, {
  type: vd,  // "annotateImportPDFData"
  pdfUrl: k.substring(q, q + l),
  pdfName: a.filename,
  "final": p,
  start: t
}, {frameId: a.h ? a.h.frameId : 0});
```

### Google Slides/Docs Integration
- Detects iframe contexts: `window != window.top`
- Uses `chrome.webNavigation.getAllFrames()` to manage multi-frame annotation
- Reads Google Slides presentations via `/v1/presentations/` API

---

## Assessment Workflow Integration

### Google Classroom Features
```javascript
// BackgroundMain.js:4621-4636
H.bGoogleAssignmentAutosaved = I;
I && "courseWorkDetails" in a && (H.courseWorkDetails = a.courseWorkDetails);
```
- Tracks student submissions in Google Classroom
- Auto-saves annotations as assignment progress
- Teacher can review student annotations via platform

---

## Verified Security Controls

### 1. CSRF Token Validation
- All POST requests to annotate.net include `CSRFtoken`
- Regenerates token on error 21 response
- Prevents unauthorized state changes

### 2. Access Control
```javascript
// BackgroundMain.js:4622-4629
let F = 1;
a.bCoTeacher || A && A.ChromeClientLogin ? F = 2 :
A && A.uUserType == 3 ? F = 3 :  // Student
U(A) && (F = 4);                  // Open user
A == null && (F = 5);             // Guest
```
- Role-based access: Teacher (2), Student (3), Open User (4), Guest (5)
- Annotations locked based on ownership/permissions

### 3. Origin Validation
- WebSocket connections only to annotate.net domain
- No wildcard origins in postMessage handlers

---

## Potential Privacy Concerns (Informational)

### 1. Browsing History Visibility
- **What:** Extension monitors all tab updates via `chrome.tabs.onUpdated`
- **Why:** Detects when users navigate to Google Slides/Docs for annotation
- **Scope:** URLs checked against patterns (e.g., `docs.google.com/presentation`)
- **Mitigation:** No URL logging to backend detected, purely client-side filtering

### 2. Screenshot Capability
- **What:** `chrome.tabs.captureVisibleTab()` can capture current tab
- **When:** Only when user explicitly saves/exports annotations
- **Storage:** Uploaded to annotate.net for thumbnail generation
- **User Control:** Triggered by explicit save actions

### 3. Screen Sharing
- **What:** `chrome.desktopCapture` enables screen sharing
- **Consent:** Requires user to select screen/window in system dialog
- **Use Case:** Annotation during Google Meet presentations
- **No silent capture:** Cannot activate without user interaction

---

## Code Quality Observations

### Positive Indicators
1. **Error handling:** Try-catch blocks around JSON parsing, API calls
2. **Timeouts:** AbortController used for fetch requests (30s timeout)
3. **Reconnection logic:** Prevents infinite loops with exponential backoff
4. **Version tracking:** Annotation version numbers prevent data loss

### Minor Issues (Non-security)
1. **Console disabled globally:** `console.log = function() {};` — Hinders debugging
2. **Large content script:** 76,877 lines in ContentMain.js (includes libraries)
3. **No CSP in manifest:** Not exploitable in MV3, but best practice

---

## Comparison to Known Malicious Patterns

| Pattern | Found | Risk | Notes |
|---------|-------|------|-------|
| Extension enumeration | ❌ No | N/A | No chrome.management API usage |
| XHR/fetch hooking | ❌ No | N/A | Standard fetch() calls, no prototype pollution |
| Cookie harvesting | ❌ No | N/A | No document.cookie access |
| AI conversation scraping | ❌ No | N/A | No pattern matching for ChatGPT/Claude |
| Ad injection | ❌ No | N/A | No DOM manipulation for ads |
| Remote kill switches | ❌ No | N/A | No server-controlled feature flags |
| Proxy infrastructure | ❌ No | N/A | No residential proxy indicators |
| Obfuscation | ❌ No | N/A | Code is minified but not maliciously obfuscated |

---

## Conclusion

**Risk Level: CLEAN**

Annotate is a **legitimate educational tool** with no malicious behavior detected. All permissions and capabilities are justified by its core functionality:

1. **Screen sharing** for collaborative annotation during video calls
2. **Web annotation** across all sites (requires `<all_urls>`)
3. **Google Drive integration** for PDF annotation
4. **Real-time collaboration** via WebSocket

The extension follows standard security practices including CSRF protection, role-based access control, and user consent for sensitive operations.

### Recommendations for Users
- ✅ Safe to install for educational annotation purposes
- ⚠️ Be aware that annotate.net can see annotated content (expected for cloud sync)
- ⚠️ Screen sharing requires explicit user selection each time

### Developer Recommendations
1. Add explicit CSP header to manifest (defense-in-depth)
2. Consider scoping host_permissions to specific domains when possible
3. Re-enable console logging in development builds for debugging

---

## Evidence Summary

- **Lines analyzed:** 81,898 (BackgroundMain.js: 5,021 + ContentMain.js: 76,877)
- **Network domains:** 2 (annotate.net, googleapis.com)
- **External libraries:** jspdf, mathquill, hammer.js, sdp-transform (all legitimate)
- **No tracking SDKs detected**
- **No suspicious patterns found**
