# Security Analysis: ScreenPal - Screen Recorder & Video Editor (eefedolmcildfckjamddopaplfiiankl)

## Extension Metadata
- **Name**: ScreenPal - Screen Recorder & Video Editor
- **Extension ID**: eefedolmcildfckjamddopaplfiiankl
- **Version**: 3.1.8
- **Manifest Version**: 3
- **Estimated Users**: ~300,000
- **Developer**: ScreenPal (formerly Screencast-O-Matic)
- **Analysis Date**: 2026-02-14

## Executive Summary
ScreenPal is a legitimate screen recording and video editing extension from a well-established company. The extension provides screen capture, webcam recording, and video editing functionality with upload to the ScreenPal cloud service. Analysis identified **one medium-severity vulnerability** related to unsafe postMessage handling that could enable XSS attacks, but no evidence of malicious intent was found. The extension's broad permissions and network activity are all justified by its core functionality as a cloud-based screen recorder.

**Overall Risk Assessment: MEDIUM**

## Vulnerability Assessment

### 1. Unsafe postMessage Handler Allowing XSS (MEDIUM)
**Severity**: MEDIUM
**Files**:
- `/app/js/SP-Main.js` (line 54)

**Analysis**:
The extension's content script includes a postMessage event listener that processes untrusted data without origin validation and assigns it directly to innerHTML, creating an XSS vulnerability.

**Code Evidence** (`SP-Main.js`, line 54):
```javascript
window.addEventListener("message", function(d) {
  // ... processing without origin check ...
  f = document.createElement("div");
  f.innerHTML = g;  // 'g' contains data from postMessage
  l.parentNode.replaceChild(f.firstChild, l)
});
```

**Attack Scenario**:
1. Malicious website embeds ScreenPal's web-accessible resources in an iframe
2. Sends crafted postMessage with XSS payload
3. Content script processes message without validating `event.origin`
4. Malicious HTML is injected into the page via innerHTML assignment

**Impact**:
- Cross-site scripting in context of the host page
- Potential data theft from pages where ScreenPal is active
- Session hijacking on vulnerable sites

**Mitigations Observed**:
- Content scripts run in isolated world (limited DOM access)
- CSP restrictions in Manifest V3 reduce attack surface
- No sensitive data handling in the vulnerable code path
- Attack requires user to be on a malicious page

**Recommendation**: Add origin validation to all postMessage handlers:
```javascript
window.addEventListener("message", function(event) {
  // Validate origin before processing
  if (event.origin !== chrome.runtime.getURL('').slice(0, -1)) return;
  // Process message safely
});
```

---

### 2. Multiple PostMessage Handlers Without Origin Validation (LOW)
**Severity**: LOW
**Files**:
- `/app/js/recorder.js` (line 2)
- `/app/js/player.js` (line 2)
- `/app/js/editor.js` (line 8)
- `/app/js/draw.js` (line 2)
- `/app/js/popup-menu-launcher.js` (line 2)

**Analysis**:
Five additional postMessage handlers exist without origin checks, but most only process internal commands without DOM manipulation.

**Code Evidence** (`recorder.js`):
```javascript
window.addEventListener("message", a => {
  a.data.recordFrameInit ?
    (/* handle recording setup */) :
    "stop" === a.data.effects &&
      document.getElementById("toggleEffects").click()
}, !1);
```

**Why Lower Severity**:
- Most handlers only trigger UI actions (clicks, toggles)
- No direct innerHTML or eval() calls in these handlers
- Data flows through internal state management
- Limited exploitation potential

**Recommendation**: Still add origin validation as defense-in-depth.

---

### 3. Broad Host Permissions (LOW - Expected)
**Severity**: LOW (Functional Requirement)
**Manifest**: `host_permissions: ["https://*/*", "http://*/*"]`

**Analysis**:
The extension requests access to all websites, which is necessary for its core functionality as a universal screen recorder that must inject UI controls on any page.

**Justification**:
- Screen recording requires content script injection on target pages
- In-page recorder controls need to overlay on any website
- Video preview/sharing features work across domains
- Template guide and link expansion features operate universally

**Mitigations**:
- Users can disable per-domain via extension settings (`DomainSettings.js`)
- Permissions are clearly described in Chrome Web Store listing
- No evidence of unauthorized data collection
- All network calls go to legitimate ScreenPal endpoints

**Verdict**: **NOT MALICIOUS** - Required for advertised functionality.

---

## Network Activity Analysis

### External Endpoints (All Legitimate)

| Domain | Purpose | Data Transmitted | Frequency |
|--------|---------|------------------|-----------|
| `screenpal.com/*` | Main service API | Session auth, video metadata, upload init | On recording |
| `share-preview.screenpal.com` | Preview thumbnails | Animated GIF previews | Per recording (if enabled) |
| `files2.screencast-o-matic.com` | CDN for effects | Effect video/audio files | On-demand |
| `*.amazonaws.com` | AWS S3 upload | Video chunks (via presigned URLs) | During recording |
| `somup.com/*` | Short link redirect | Link validation | Link expansion feature |

### Data Flow Summary

**Upload Process** (`Uploader.js`):
1. **Init**: POST to `/chromeapp/upload/create` with metadata (title, resolution, visibility)
2. **Upload**: Chunked video upload to AWS S3 (2MB parts via presigned URLs)
3. **Transcode**: Trigger server-side processing with metadata
4. **Preview**: Upload GIF/JPG previews for sharing

**Data Transmitted**:
- Video content (user-initiated recordings)
- Recording metadata (title, resolution, duration, effects used)
- Session cookies for authentication
- Analytics events (recording start/stop, errors, feature usage)

**Data NOT Transmitted**:
- Browsing history (beyond current tab for recording)
- Form data or user inputs from pages
- Credentials or sensitive page content
- Cross-site tracking identifiers

**Verdict**: **NOT MALICIOUS** - All network activity serves legitimate product features.

---

## Permission Analysis

| Permission | Justification | Risk Level |
|------------|---------------|------------|
| `tabs` | Query tab info for recording target | Low (standard) |
| `storage` | Save user preferences, session state | Low (local only) |
| `tabCapture` | Capture tab audio/video for recording | Low (user-initiated) |
| `webNavigation` | Track navigation for floating controls | Low (UI state) |
| `clipboardRead` | Paste video links (feature) | Medium (justified) |
| `clipboardWrite` | Copy share links after recording | Low (standard) |
| `contextMenus` | Right-click "Open Recorder" option | Low (UI only) |
| `unlimitedStorage` | Store large video files locally | Low (functional) |
| `offscreen` | Background video processing | Low (MV3 standard) |
| `scripting` | Inject recorder UI into pages | Medium (broad access) |

**Assessment**: All permissions are justified and used appropriately for screen recording functionality. The `scripting` + `host_permissions` combination is powerful but necessary for the product's core value proposition.

---

## Code Quality Observations

### Positive Indicators
1. **Legitimate company**: ScreenPal/Screencast-O-Matic has been in business since 2006
2. **No obfuscation malice**: Minification is standard build process, no anti-analysis techniques
3. **No dynamic code execution**: No eval(), Function(), or remote script loading
4. **No extension manipulation**: No chrome.management API usage to disable competitors
5. **Clean analytics**: Event tracking limited to product telemetry (feature usage, errors)
6. **Transparent uploads**: All video data goes to user's ScreenPal account
7. **User control**: Domain-level disable, in-page vs. popup recording options
8. **Error handling**: Comprehensive logging and error reporting to own service

### Obfuscation Level
**MEDIUM** - Code is minified with variable mangling (standard webpack/terser output), but logic is straightforward. AWS SDK and jQuery are included as expected dependencies. Flag is accurate.

---

## Security Best Practices Violations

| Issue | Severity | Impact |
|-------|----------|--------|
| postMessage without origin validation | Medium | XSS vulnerability |
| innerHTML with untrusted data | Medium | XSS vulnerability |
| Broad host permissions | Low | Large attack surface (necessary) |
| No Content Security Policy | Low | Manifest V3 provides defaults |

---

## Comparison to Known Malicious Patterns

| Malicious Pattern | Present? | Evidence |
|-------------------|----------|----------|
| Extension enumeration/killing | ✗ No | No chrome.management usage |
| XHR/fetch hooking | ✗ No | No prototype modifications |
| Residential proxy infrastructure | ✗ No | No proxy configuration |
| Remote code loading | ✗ No | All scripts bundled |
| Ad/coupon injection | ✗ No | No ad network calls |
| Cookie harvesting | ✗ No | Only session cookies for auth |
| Hidden data exfiltration | ✗ No | All uploads user-visible |
| Market intelligence SDKs | ✗ No | Only AWS SDK and jQuery |
| Credential phishing | ✗ No | Login via screenpal.com only |

---

## Overall Risk Assessment

### Risk Level: **MEDIUM**

**Justification**:
1. **One exploitable vulnerability** (postMessage XSS) in production code
2. **Legitimate product** from established company with no malicious intent
3. **Broad permissions** required for core functionality but create attack surface
4. **Large user base** (300K) means vulnerability impact is significant
5. **No active exploitation** or malicious behavior detected

### Vulnerability Breakdown
- **Critical**: 0
- **High**: 0
- **Medium**: 1 (postMessage XSS)
- **Low**: 2 (other postMessage handlers, broad permissions)

### Recommendations for Users
1. **Safe to use** for intended screen recording purposes
2. **Be cautious** when using on untrusted/malicious websites (XSS risk)
3. **Review domain settings** to disable on sensitive sites if desired
4. **Keep updated** to receive security patches

### Recommendations for Developer
1. **URGENT**: Add origin validation to all postMessage handlers
2. **URGENT**: Replace innerHTML with textContent or sanitize input
3. Consider Content Security Policy for web-accessible resources
4. Add subresource integrity checks for CDN resources
5. Implement permission warnings for clipboard access

---

## Technical Summary

**Lines of Code**: ~15,000 (excluding minified libraries)
**External Dependencies**: AWS SDK, jQuery, CreateJS, jszip, RxJS, UAParser
**Third-Party Libraries**: All from legitimate CDNs (no supply chain concerns)
**Remote Code Loading**: None
**Dynamic Code Execution**: None
**Web Accessible Resources**: 14 HTML pages (recorder UI, editor, player)

---

## User Privacy Impact

**MODERATE** - The extension:
- **Accesses**: Current tab URL (for recording context), webcam/mic (with permission)
- **Stores**: User preferences, recording metadata, session tokens
- **Transmits**: Video recordings (user-initiated), analytics events, crash reports
- **Does NOT**: Track browsing history, harvest credentials, or sell user data

Privacy policy at screenpal.com describes data handling practices. Video uploads are stored in user's private account by default (visibility level 3 = private).

---

## Conclusion

ScreenPal is a **legitimate screen recording extension with one medium-severity security vulnerability**. The postMessage XSS issue should be patched urgently, but there is no evidence of malicious intent or active exploitation. The extension's broad permissions and network activity are all justified by its core functionality as a cloud-based screen recorder and video editor.

The risk is elevated from CLEAN to MEDIUM solely due to the exploitable XSS vulnerability in production code serving 300,000 users. Once patched, this would be a CLEAN extension.

**Final Verdict: MEDIUM** - Legitimate product with security vulnerability requiring patch.
