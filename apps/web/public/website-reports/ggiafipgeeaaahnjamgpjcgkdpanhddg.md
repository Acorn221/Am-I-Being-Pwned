# Vulnerability Report: Sync Watch

## Metadata
- **Extension ID**: ggiafipgeeaaahnjamgpjcgkdpanhddg
- **Extension Name**: Sync Watch
- **Version**: 1.1.0
- **Users**: ~70,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Sync Watch is a video synchronization extension that allows users to watch videos together in real-time through Socket.IO connections to a remote server. The extension monitors video player events on all websites and synchronizes playback state (play/pause/seek/playback rate) across multiple users in the same "room."

The extension is functionally legitimate and appears to serve its stated purpose without malicious intent. However, it contains one low-severity security vulnerability: the Netflix-specific integration script uses `window.addEventListener("message")` without proper origin validation, which could potentially allow cross-site scripting attacks from malicious websites. The extension's use of `<all_urls>` host permissions is necessary for its core functionality but does create a broad attack surface.

## Vulnerability Details

### 1. LOW: Unsafe postMessage Handler in Netflix Integration

**Severity**: LOW
**Files**: js/players/netflix/netflix.js
**CWE**: CWE-345 (Insufficient Verification of Data Authenticity)

**Description**:
The Netflix integration script listens for `window.postMessage` events without validating the message origin. This allows any script running in the same window context to send messages that will be processed.

**Evidence**:
```javascript
// js/players/netflix/netflix.js:15
window.addEventListener('message', (event) => {
  const player = getPlayer();

  player.setPlaybackRate(event.data.playbackRate);

  switch (event.data.action) {
    case 'play': {
      player.play();
      break;
    }
    case 'pause': {
      player.pause();
      break;
    }
    case 'seek': {
      player.seek(event.data.time * 1000);
      break;
    }
  }
});
```

The event handler does not check `event.origin` or `event.source` before processing commands. While this script only runs on Netflix.com (limited by the manifest's content script matches), a malicious script injected into Netflix.com could potentially send spoofed control messages.

**Verdict**: Low severity. The risk is mitigated by several factors:
1. The script only executes on `https://www.netflix.com/*` (manifest restriction)
2. Actual exploitation requires another vulnerability or malicious extension to inject code into Netflix
3. The impact is limited to video player control, not data exfiltration or account compromise
4. The extension's own content script sends postMessages, creating a legitimate use case

**Recommendation**: Add origin validation:
```javascript
window.addEventListener('message', (event) => {
  if (event.source !== window) return;  // Only accept messages from same window
  // ... rest of handler
});
```

## False Positives Analysis

**Webpack/Build Artifacts**: The extension uses modern bundling (appears to be Vite or similar), which creates minified but not obfuscated code. The `obfuscated` flag from ext-analyzer is a false positive - the code is standard webpack bundled JavaScript, not intentionally obfuscated malware.

**<all_urls> Host Permission**: While this permission is powerful, it's necessary for the extension's core functionality - monitoring video elements on any website where users want to sync playback. This is disclosed in the extension's purpose ("Watch videos together at the same time!").

**Video Event Monitoring**: The extension listens to video element events (play, pause, seeked, ratechange, progress) on all pages. This is expected behavior for a video synchronization tool and does not constitute surveillance or data collection beyond the stated purpose.

**MutationObserver Usage**: The content script uses MutationObserver to detect dynamically added video elements. This is a legitimate technique for ensuring the extension works on single-page applications and is not malicious.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://server.syncwatch.space/ | WebSocket sync server | Username, room name, video state (currentTime, playbackRate, play/pause events), video metadata (URL, title) | Low - legitimate sync data for stated purpose |
| https://clients2.google.com/service/update2/crx | Chrome Web Store updates | N/A (automatic Chrome updates) | None |
| https://docs.google.com/forms/d/e/1FAIpQLSd8Z6m6lAFwLk88WK8arSgMfIcJxhVROR3r64RlCo-Lfs_0rA/viewform | Uninstall feedback form | User agent, extension version | None - standard feedback collection |

**Socket.IO Server Communication**: The extension connects to `server.syncwatch.space` via WebSocket and sends:
- User metadata: username, room name (user-provided)
- Video state: currentTime, playbackRate, element index, frame location
- Video metadata: URL, title (only when user clicks "share video")
- Tab metadata: Only for active tab when sharing

The data transmission is appropriate for the extension's synchronization functionality. No sensitive browsing data, credentials, or PII beyond user-provided names is collected.

**Configurable Server**: The extension allows users to configure a custom server URL (stored in `chrome.storage.sync`). This is a feature, not a vulnerability, allowing self-hosting or private deployments.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

This is a legitimate video synchronization extension with appropriate functionality for its stated purpose. The single identified vulnerability (unsafe postMessage handler) has low exploitability and limited impact. The extension:

✅ **Legitimate functionality**: Video sync across users via WebSocket is the stated purpose
✅ **Appropriate permissions**: `<all_urls>` is necessary for detecting videos on any site
✅ **No data exfiltration**: Only sends video playback state and user-provided metadata
✅ **No credential theft**: Does not access passwords, cookies, or authentication tokens
✅ **No hidden behavior**: All network communication is for documented sync features
✅ **Modern MV3**: Uses Manifest V3 with service worker architecture
✅ **User control**: Users must manually join rooms and share videos
✅ **Open security**: Allows custom server configuration for privacy-conscious users

⚠️ **Minor issue**: postMessage handler lacks origin validation (low severity)

The extension's broad host permissions and real-time video monitoring capabilities could be concerning in isolation, but the implementation shows these are used exclusively for legitimate video synchronization without privacy violations or malicious side effects.

**Recommended Actions**:
- Developer should add origin validation to the Netflix postMessage handler
- Users concerned about privacy can self-host the sync server using the configurable server option
- No immediate user action required - extension is safe to use as-is
