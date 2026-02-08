# Security Analysis Report: Screenity - Screen Recorder & Annotation Tool

## Extension Metadata
- **Extension ID**: `kbbdabhdfibnancpjfhlkhafgdilcnji`
- **Extension Name**: Screenity - Screen Recorder & Annotation Tool
- **Version**: 4.2.5
- **Manifest Version**: 3
- **Estimated Users**: ~200,000
- **Analysis Date**: 2026-02-06

## Executive Summary

Screenity is a **CLEAN** screen recording and annotation tool with a legitimate cloud-based architecture. The extension integrates with a proprietary backend (`app.screenity.io`) for video editing, storage, and user account management. The extension uses extensive permissions for its core screen recording functionality, but all network communications and data handling patterns are transparent and aligned with the extension's stated purpose.

**Risk Level: CLEAN**

The extension exhibits no malicious behavior patterns. All concerning patterns identified (fetch hooks, extensive permissions, XHR usage) are legitimate implementations for screen recording, video processing, and cloud storage functionality. The extension uses standard OAuth2 for Google Drive integration and implements proper authentication with its own backend.

## Key Findings

### Legitimate Features
1. **Screen Recording Infrastructure**: Uses `tabCapture`, `desktopCapture`, and `MediaRecorder` APIs for recording
2. **Cloud Integration**: Authenticated backend API at `app.screenity.io/api` for video storage and editing
3. **Google Drive Integration**: OAuth2 implementation for optional Drive backup
4. **Video Processing**: FFmpeg WASM for local video encoding/transcoding
5. **AI Background Blur**: MediaPipe selfie segmentation WASM modules for camera effects
6. **Bunny CDN Upload**: TUS protocol implementation for chunked video uploads to Bunny CDN

### No Malicious Patterns Found
- ✅ No extension enumeration/killing
- ✅ No XHR/fetch hooking on user pages
- ✅ No residential proxy infrastructure
- ✅ No market intelligence SDKs (Sensor Tower, etc.)
- ✅ No AI conversation scraping
- ✅ No ad/coupon injection
- ✅ No social media data harvesting
- ✅ No credential exfiltration
- ✅ No obfuscated command & control

## Detailed Analysis

### 1. Permissions Analysis

| Permission | Justification | Risk Level |
|------------|---------------|------------|
| `<all_urls>` (host_permissions) | Required for content script injection to display recording UI overlay on any page | **LOW** - Standard for screen recorders |
| `<all_urls>` (content_scripts) | Injects recording controls and region selector UI | **LOW** - Necessary for functionality |
| `identity` | Google OAuth2 for Drive integration | **LOW** - Standard OAuth flow |
| `storage`, `unlimitedStorage` | Store recording settings, local backups, indexed DB for large videos | **LOW** - Core functionality |
| `tabs`, `activeTab` | Tab management for recording selection | **LOW** - Standard |
| `tabCapture` | Capture tab audio/video streams | **LOW** - Core functionality |
| `scripting` | Inject recording UI dynamically | **LOW** - Standard MV3 pattern |
| `system.display` | Query display info for screen recording | **LOW** - Core functionality |
| `offscreen` (optional) | Audio playback for UI sounds | **LOW** - User experience |
| `desktopCapture` (optional) | Full desktop recording | **LOW** - Core functionality |

**CSP Analysis:**
```
extension_pages: script-src 'self' 'wasm-unsafe-eval'
sandbox: sandbox allow-scripts allow-modals allow-popups; script-src 'self' 'unsafe-inline' 'unsafe-eval' blob:
```
- `wasm-unsafe-eval` required for FFmpeg and MediaPipe WASM modules
- Sandbox page (`editor.html`) uses `unsafe-eval` for video editor - this is sandboxed and isolated
- Cross-origin policies (COEP/COOP) properly configured for SharedArrayBuffer usage

### 2. Network Communication Analysis

#### API Endpoints Catalog

| Endpoint | Purpose | Authentication | Risk |
|----------|---------|----------------|------|
| `app.screenity.io/api/auth/verify` | Verify JWT token validity | Bearer token | CLEAN |
| `app.screenity.io/api/auth/refresh` | Refresh expired tokens | Cookie credentials | CLEAN |
| `app.screenity.io/api/videos` | Create/list user videos | Bearer token | CLEAN |
| `app.screenity.io/api/bunny/videos` | Create Bunny CDN video entry | Bearer token | CLEAN |
| `app.screenity.io/api/bunny/videos/tus-auth` | Get TUS upload credentials | User token | CLEAN |
| `app.screenity.io/api/bunny/upload` | Upload audio files | Bearer token | CLEAN |
| `app.screenity.io/api/transcription/queue` | Queue video transcription | Bearer token | CLEAN |
| `app.screenity.io/api/storage/quota` | Check cloud storage quota | Bearer token | CLEAN |
| `app.screenity.io/api/log/recorder-unload` | Diagnostic beacon (unload events) | User token | CLEAN |
| `video.bunnycdn.com/tusupload` | TUS resumable upload protocol | Signature auth | CLEAN |
| `www.googleapis.com/drive/v3/*` | Google Drive API | OAuth2 | CLEAN |
| `accounts.google.com/o/oauth2/v2/auth` | Google OAuth2 authorization | Standard OAuth | CLEAN |

**All endpoints are legitimate and scoped to extension functionality.**

#### Data Flow Summary

```
Recording Flow:
User initiates recording → MediaRecorder captures tab/screen →
Data stored in IndexedDB (local backup) →
Optional: Upload to Bunny CDN via TUS protocol →
Backend creates video metadata →
User can edit in cloud editor

Authentication Flow:
User logs in via app.screenity.io →
Extension receives JWT token →
Token stored in chrome.storage.local →
Token verified every 4 hours (cached) →
Token refreshed via /auth/refresh endpoint
```

**No data is sent without user consent. All uploads are user-initiated.**

### 3. Content Script Behavior

**File**: `contentScript.bundle.js` (47,647 lines)

**Legitimate Behaviors:**
- **Recording UI Injection**: Renders React-based recording controls overlay
- **Region Selection**: Allows users to select screen regions to record
- **Permission Prompts**: Displays permission request dialogs for camera/mic
- **Project Integration**: Shows active project banner when recording to cloud project
- **Keyboard Shortcuts**: Listens for recording hotkeys (Alt+Shift+G/X/M)
- **App.screenity.io Detection**: Disables "region" recording mode when on Screenity web app (prevents recursive recording)

**No Malicious Patterns:**
- No DOM scraping for user data
- No form field monitoring
- No credential harvesting
- No cookie access
- No localStorage snooping
- No AI conversation detection
- No XHR/fetch interception

**Code Sample (app.screenity.io check):**
```javascript
// Line 35826: Legitimate check to prevent recording app itself
var e, t = window.location.href.includes("https://app.screenity.io");
(l(t), t && "region" === r.recordingType) && (o(function(e) {
  return Yf(Yf({}, e), {}, { recordingType: "screen" })
}), chrome.storage.local.set({ recordingType: "screen" }),
// Show toast: "Tab recording disabled on Screenity app"
```

### 4. Background Script Behavior

**File**: `background.bundle.js` (12,477 lines)

**Legitimate Behaviors:**
- **Message Handling**: Responds to content script requests (start/stop recording, auth checks)
- **Authentication Management**: Verifies tokens, refreshes credentials
- **Google Drive Integration**: OAuth flow implementation
- **Tab Management**: Opens login tabs, closes recording tabs
- **Clipboard Helper**: Copies share URLs to clipboard (user-initiated)
- **Offscreen Document**: Manages audio playback offscreen document for UI sounds
- **Storage Quota**: Checks cloud storage limits

**Token Management:**
```javascript
// Line 5056-5060: Token verification
fetch("https://app.screenity.io/api/auth/verify", {
  headers: { Authorization: "Bearer " + token }
})
// Token cached for 4 hours (144e5 ms = 240 minutes)
// Line 5021: if (n && i - n < 144e5) { /* use cached */ }
```

**No Malicious Patterns:**
- No extension enumeration (`chrome.management` API not used)
- No malicious command & control
- No dynamic code loading from remote sources
- No beacon exfiltration of browsing data

### 5. Cloud Recording Infrastructure

**File**: `cloudrecorder.bundle.js` (14,222 lines)

**Bunny CDN TUS Upload Implementation:**
- Implements resumable uploads via TUS protocol
- Chunked uploads (524KB default chunks)
- Automatic retry with exponential backoff (5 retries max)
- Heartbeat mechanism to detect stalled uploads
- Signature-based auth from backend

**Diagnostic Beacon (Line 13300):**
```javascript
// Legitimate crash reporting - only fires on page unload during active recording
navigator.sendBeacon("https://app.screenity.io/api/log/recorder-unload",
  JSON.stringify({ /* recording state */ })
)
```
This is a standard diagnostic pattern to detect recorder crashes, not surveillance.

### 6. WASM Analysis

**3 WASM Modules Detected:**

| Module | Purpose | Size | Risk |
|--------|---------|------|------|
| `ffmpeg-core.wasm` | Video encoding/transcoding | 23.5 MB | **LOW** - Legitimate FFmpeg |
| `selfie_segmentation_solution_wasm_bin.wasm` | AI background blur (MediaPipe) | 5.6 MB | **LOW** - Google MediaPipe |
| `selfie_segmentation_solution_simd_wasm_bin.wasm` | AI background blur SIMD-optimized | 5.7 MB | **LOW** - Google MediaPipe |

**FFmpeg Strings**: Standard FFmpeg error messages, codec names, HTTP request handling
**MediaPipe Strings**: `drishti.aimatter.TensorViewRequestor` (Google's ML framework for selfie segmentation)

All WASM modules are loaded only for legitimate video processing and camera effects.

### 7. Third-Party Libraries

**Legitimate Dependencies:**
- **localForage** (v1.10.0): IndexedDB wrapper for local video storage
- **JSZip** (v3.10.1): Zip file handling for project exports
- **React** (v18+): UI framework
- **FFmpeg.js**: WASM-based video processing
- **MediaPipe**: Google's selfie segmentation for background blur
- **Bunny CDN TUS Client**: Resumable uploads

**No Market Intelligence SDKs detected:**
- ❌ No Sensor Tower / Pathmatics
- ❌ No analytics SDKs beyond standard usage

### 8. Externally Connectable

```json
"externally_connectable": {
  "matches": ["https://app.screenity.io/*"]
}
```

**Purpose**: Allows the Screenity web app to communicate with the extension for:
- Opening cloud editor with extension-recorded videos
- Checking authentication status
- Triggering "record to project" from web app

This is a **legitimate integration pattern** for hybrid web/extension apps.

## False Positive Analysis

| Pattern | Context | Verdict |
|---------|---------|---------|
| `fetch()` usage | Legitimate API calls to app.screenity.io and googleapis.com | **FP** - No hooking detected |
| `"function" == typeof fetch && -1 !== fetch.toString().indexOf("[native code")` | LocalForage library checking for native fetch support | **FP** - Feature detection |
| `btoa()` usage | Base64 encoding for TUS upload metadata, Drive API | **FP** - Standard encoding |
| `postMessage` | Web worker communication (FFmpeg, MediaPipe, GIF encoder) | **FP** - Worker IPC |
| `innerHTML` usage | React JSX rendering, SVG handling | **FP** - Framework usage |
| `addEventListener("keydown")` | Recording hotkeys (Alt+Shift+G/X/M), UI shortcuts | **FP** - User features |
| `sendBeacon` | Crash diagnostics on recorder page unload | **FP** - Error reporting |
| `Proxy` objects | Toast focus management, Plyr video player library | **FP** - UI libraries |

## Privacy Assessment

### Data Collection
- **User Account**: Email, token (standard auth)
- **Recording Metadata**: Title, timestamp, duration, project associations
- **Video Content**: Only uploaded if user explicitly saves to cloud
- **Storage Quota**: Cloud storage usage tracking
- **Crash Logs**: Recorder unload events for diagnostics

### Data Retention
- Local recordings stored in IndexedDB until user deletes
- Cloud recordings stored until user deletes (standard cloud storage model)

### Third-Party Sharing
- **Google Drive**: Optional user-controlled backup
- **Bunny CDN**: Video hosting infrastructure (standard CDN usage)
- No advertising partners, no analytics SDKs, no data brokers

## Security Recommendations

1. ✅ **CSP is properly configured** for WASM usage
2. ✅ **OAuth2 implementation** follows best practices
3. ✅ **Token refresh** mechanism prevents long-lived credentials
4. ⚠️ **Sandbox CSP**: `unsafe-eval` in sandbox is acceptable but requires trust in editor code
5. ✅ **No inline scripts** in main extension pages
6. ✅ **Proper cross-origin isolation** for SharedArrayBuffer

## Comparison to Known Malicious Extensions

### vs. Sensor Tower Extensions (StayFree/StayFocusd)
- ❌ Screenity has **NO** XHR/fetch hooking on user pages
- ❌ Screenity has **NO** AI conversation scraping
- ❌ Screenity has **NO** chatbot widget monitoring
- ❌ Screenity has **NO** market intelligence collection

### vs. VPN Extensions (Urban VPN/VeePN)
- ❌ Screenity has **NO** extension enumeration
- ❌ Screenity has **NO** extension killing mechanisms
- ❌ Screenity has **NO** proxy infrastructure
- ❌ Screenity has **NO** GA bypass techniques

### vs. Coupon Injectors (Troywell)
- ❌ Screenity has **NO** ad injection
- ❌ Screenity has **NO** affiliate link manipulation
- ❌ Screenity has **NO** server-controlled kill switches

## Conclusion

**Screenity is a legitimate, well-engineered screen recording tool with no malicious behavior.** The extension's extensive permissions and network activity are fully justified by its core functionality: recording screens, processing video locally with FFmpeg, and optionally uploading to a cloud editor. The integration with `app.screenity.io` is transparent, authenticated, and user-controlled.

The extension follows Chrome extension security best practices for Manifest V3, implements proper authentication, and uses industry-standard libraries (FFmpeg, MediaPipe) for video processing. There is no evidence of data harvesting, tracking, or malicious third-party integrations.

## Overall Risk Rating: **CLEAN**

---

**Analyst Notes:**
- Codebase is well-structured and readable (React + modern JS)
- No code obfuscation detected
- All network endpoints are documented and purposeful
- User consent is required for all data uploads
- Extension aligns with Chrome Web Store policy compliance
- Recommended for use without security concerns
