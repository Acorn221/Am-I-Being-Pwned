# Vulnerability Report: Vidline Screen Recorder

## Extension Metadata
- **Extension Name**: Vidline Screen Recorder
- **Extension ID**: peaiabjigdmcjiigljknblkdmllgmklp
- **Version**: 0.2.1
- **User Count**: ~40,000
- **Manifest Version**: 3
- **Default Locale**: zh_CN (Chinese)

## Executive Summary

Vidline Screen Recorder is a legitimate screen recording extension that allows users to capture screen, tab, and camera video with audio. The extension communicates with its backend services at `vidline.com` and `api.vidline.com` for video processing, storage, and user authentication.

While the extension requests extensive permissions appropriate for screen recording functionality, the analysis reveals **excessive host permissions** (`<all_urls>`) and **cross-domain confusion** between `vidline.com` and `haolu.com` domains. The extension appears to be a rebranded version originally developed for `haolu.com`, with hardcoded permissions for both domains. Despite these concerns, no active malicious behavior, data exfiltration, or critical vulnerabilities were detected.

**Risk Level: MEDIUM**

The extension serves its stated purpose without clear malicious intent but exhibits questionable permission requests and domain confusion that could pose privacy risks.

## Vulnerability Details

### 1. Excessive Host Permissions (MEDIUM Severity)

**Description**: The extension requests `<all_urls>` host permission, granting access to all websites.

**Location**: `manifest.json`
```json
"host_permissions": ["*://*.haolu.com/*", "<all_urls>"]
```

**Evidence**:
- Host permissions include both specific domain (`haolu.com`) and wildcard (`<all_urls>`)
- Content scripts inject into `<all_urls>` with `all_frames: true`

**Impact**: The extension can read and modify content on every website the user visits, creating potential privacy concerns.

**Verdict**: MEDIUM - While technically excessive, the content scripts appear to perform limited functionality (video player detection, meta tag injection on vidline.com). However, this level of access is broader than necessary for a screen recorder.

---

### 2. Cross-Domain Confusion and Branding Issues (MEDIUM Severity)

**Description**: The extension contains hardcoded references to both `vidline.com` and `haolu.com` domains, suggesting it may be a rebranded version with incomplete migration.

**Location**:
- `manifest.json` lines 54, 92
- `background.bundle.js` lines 1755-1756

**Evidence**:
```javascript
// manifest.json
"externally_connectable": {
    "matches": ["*://haolu.com/*", "https://*.haolu.com/*"]
}
"host_permissions": ["*://*.haolu.com/*", "<all_urls>"]

// background.bundle.js
o = "www.vidline.com",
r = "api.vidline.com",
```

**Impact**:
- Creates confusion about the extension's true operator
- `haolu.com` permissions serve no apparent purpose in current version
- Potential data routing to undisclosed domains

**Verdict**: MEDIUM - While not actively malicious, this indicates poor maintenance and potential for data leakage to unintended domains.

---

### 3. Sensitive Cookie Access (LOW Severity)

**Description**: The extension requests cookies permission and accesses authentication cookies for its backend.

**Location**: `manifest.json` line 82, `background.bundle.js` lines 2582, 2872

**Evidence**:
```javascript
// Retrieves token cookie from vidline.com
const e = yield(0, n.Ri)({
    url: o.WP.origin,  // vidline.com
    name: "token"
});
```

**Impact**: The extension reads authentication tokens for its own domain (vidline.com), which is legitimate for maintaining user sessions.

**Verdict**: LOW - This is standard practice for authenticated web services. No evidence of third-party cookie harvesting.

---

### 4. Content Script Injection on All Sites (LOW Severity)

**Description**: Content scripts inject into all websites to detect video players and meeting platforms.

**Location**: `frames.bundle.js` lines 10-52

**Evidence**:
```javascript
// Detects video players and video conferencing platforms
const e = document.querySelectorAll("video, bwp-video");
const meetingPlatforms = /^meet\.google\.com$/.test(e) ||
                        /^teams\.live\.com$/.test(e) ||
                        /\.zoom\.us$/.test(e);
```

**Impact**: While this enhances user experience by detecting recordable content, it runs on every page and could theoretically be modified to harvest data.

**Verdict**: LOW - Functionality appears legitimate for a screen recorder. No evidence of data collection beyond feature detection.

---

### 5. Third-Party Service Integration (INFO)

**Description**: The extension integrates Crisp chat support widget.

**Location**: `background.bundle.js` line 1769

**Evidence**:
```javascript
crispEmbed: "https://go.crisp.chat/chat/embed/?website_id=b10e0c42-a2ab-4ba0-b92b-909fadf8312b"
```

**Impact**: Standard customer support integration. Crisp is a legitimate service.

**Verdict**: INFO - No security concern, standard business practice.

## False Positives

| Pattern | Location | Reason | Verdict |
|---------|----------|--------|---------|
| `innerHTML` in content.bundle.js | Multiple SVG createElement calls | React SVG component rendering | False Positive |
| Token storage | background.bundle.js | Authentication for extension's own API | Expected Behavior |
| WebSocket connection | background.bundle.js line 1776 | Video upload via `wss://api.vidline.com` | Expected Behavior |
| localStorage usage | Multiple bundle files | Session state and user preferences | Expected Behavior |

## API Endpoints

| Domain | Endpoint | Purpose | Data Transmitted |
|--------|----------|---------|------------------|
| api.vidline.com | `/oauth/redirect` | OAuth authentication | User credentials |
| api.vidline.com | `/user/info` | Fetch user profile | Auth token |
| api.vidline.com | `/user/token/refresh` | Refresh auth token | Refresh token |
| api.vidline.com | `/v2/record/upload/init` | Initialize video upload | Video metadata |
| api.vidline.com | `/v2/record/upload/complete` | Finalize video upload | Upload confirmation |
| api.vidline.com | `wss://.../v2/record/connect_with_check` | WebSocket video streaming | Video chunks |
| api.vidline.com | `/video/share/create` | Generate share link | Video ID |
| api.vidline.com | `/video/detail` | Fetch video info | Video ID |
| api.vidline.com | `/record/buffer/first` | First slice report | Recording telemetry |
| api.vidline.com | `/record/user_click_stop` | Stop recording event | User action telemetry |
| www.vidline.com | `/my_videos` | User video library | Auth token |
| www.vidline.com | `/login` | User login page | - |
| go.crisp.chat | `/chat/embed/` | Customer support chat | Chat messages |

## Data Flow Summary

1. **Authentication Flow**:
   - User authenticates via `vidline.com/login`
   - OAuth redirect to `api.vidline.com/oauth/redirect`
   - Token stored in cookies and chrome.storage.local
   - Refresh token mechanism for session maintenance

2. **Recording Flow**:
   - User initiates recording (desktop/tab/camera)
   - Extension uses native Chrome APIs (desktopCapture, tabCapture, mediaRecorder)
   - Video processed locally with WASM (`mp4_muxer.wasm`)
   - Upload via WebSocket to `wss://api.vidline.com/v2/record/connect_with_check`
   - Video stored on vidline.com cloud infrastructure

3. **Data Collection**:
   - Screen/tab/camera video (user-initiated)
   - User authentication tokens
   - Recording telemetry (start/stop events, buffer status)
   - Browser/screen metadata (screen size, browser name)
   - No evidence of passive data harvesting

4. **Content Script Activity**:
   - Detects video elements on pages (for recording optimization)
   - Detects meeting platforms (Google Meet, Teams, Zoom)
   - Injects extension metadata on vidline.com pages only
   - No DOM manipulation or ad injection detected

## Overall Risk Assessment

**Risk Level: MEDIUM**

### Justification:

**Reasons for Concern**:
1. Excessive `<all_urls>` host permissions beyond necessary scope
2. Cross-domain confusion with abandoned `haolu.com` references
3. Content script injection on all websites (even if benign)
4. Broad permissions (cookies, tabs, scripting, storage, desktopCapture, tabCapture)

**Mitigating Factors**:
1. No evidence of malicious behavior or data exfiltration
2. All network requests go to documented vidline.com domains
3. No keylogging, credential harvesting, or ad injection
4. Permissions align with stated screen recording functionality
5. No analytics SDKs or market intelligence tools detected
6. No obfuscation or anti-analysis techniques (beyond standard webpack bundling)
7. Transparent communication with backend services

### Recommendation:

The extension is **functionally legitimate** but exhibits **poor security hygiene**:
- The `<all_urls>` permission should be removed or replaced with activeTab
- `haolu.com` references should be purged if truly deprecated
- Content scripts should be limited to specific domains or use declarative injection

**Verdict: MEDIUM** - Excessive permissions and cross-domain confusion warrant caution, but no active malicious behavior detected. Users concerned about privacy should avoid this extension until permissions are tightened. The extension serves its stated purpose without clear malicious intent.
