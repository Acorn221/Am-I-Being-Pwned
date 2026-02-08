# Vulnerability Report: Bulk Media Downloader

## Extension Metadata
- **Extension Name**: Bulk Media Downloader
- **Extension ID**: ehfdcgbfcboceiclmjaofdannmjdeaoi
- **Version**: 0.3.3
- **User Count**: ~100,000
- **Manifest Version**: 3
- **Developer**: InBasic
- **Homepage**: https://webextension.org/listing/bulk-media-downloader.html
- **GitHub**: https://github.com/inbasic/bulk-media-downloader/
- **License**: Mozilla Public License v2.0

## Executive Summary

Bulk Media Downloader is a legitimate open-source extension for monitoring network traffic and downloading media files (images, videos, audio). The codebase is clean, well-documented, and follows security best practices. No malicious behavior, tracking, or data exfiltration was detected. The extension uses standard Chrome APIs appropriately and includes proper Mozilla Public License headers.

**Overall Risk Level: CLEAN**

## Manifest Analysis

### Permissions Requested
- `storage` - Used to persist user preferences (window size, filter settings, external app configs)
- `webRequest` - Core functionality: monitors network traffic to detect media files
- `downloads` - Downloads selected media files to disk
- `notifications` - Shows download notifications to user
- `contextMenus` - Adds context menu items for related extensions

### Host Permissions
- `*://*/*` - Required for monitoring network traffic across all websites

### Content Security Policy
- No custom CSP defined (uses MV3 defaults)
- No `unsafe-eval` or `unsafe-inline`

### Background Service Worker
- **File**: `worker.js` (114 lines, minified)
- Handles extension icon clicks, message passing, context menu creation
- Creates FAQ/feedback tabs on install/update
- No remote code execution or dynamic script loading

## Vulnerability Assessment

### 1. Network Monitoring (webRequest API)
**Severity**: LOW
**Files**: `data/window/index.js` (lines 117-128)
**Code**:
```javascript
chrome.webRequest.onHeadersReceived.addListener(monitor.observe,
  {urls: ['*://*/*']},
  ['responseHeaders']
);
```

**Analysis**: The extension monitors HTTP response headers to detect media files (image, video, audio, application types). This is the core functionality and expected behavior for a media downloader. The monitoring is only active when the user opens the extension popup window.

**Data Handling**:
- Captures: URL, content-type, content-length, content-disposition, referrer URL
- Does NOT capture: request body, cookies, auth tokens, POST data
- All data stays local in the popup window (no remote transmission)
- YouTube video detection is explicitly blocked (line 76-77)

**Verdict**: EXPECTED BEHAVIOR - Standard media detection functionality

---

### 2. External Application Integration
**Severity**: MEDIUM
**Files**: `data/window/external.js` (lines 72-98)
**Code**:
```javascript
chrome.runtime.sendMessage(id[os], {
  app: {
    args: args.value,
    quotes: $.external.quotes.checked,
    path: path.value,
    filename,
    referrer
  },
  tab: {
    url
  },
  selectionText: 'Sent by Bulk Media Downloader'
}, resp => {
```

**Analysis**: The extension integrates with "External Application Button" extension to launch external download managers (IDM, FDM, wget). This requires cross-extension messaging.

**Security Concerns**:
- Sends download URLs and file paths to another extension
- User can configure custom executable paths (potential for abuse if user misconfigures)
- Hardcoded extension IDs for different browsers (lines 19-24)

**Mitigations**:
- User must explicitly click "Run" button
- Confirmation dialog for bulk operations (>10 items, line 114)
- Requires separate "External Application Button" extension (not bundled)
- User has full control over executable paths and arguments

**Verdict**: ACCEPTABLE RISK - Optional feature requiring user action and separate extension

---

### 3. Clipboard Access
**Severity**: LOW
**Files**: `data/window/index.js` (lines 350-362)
**Code**:
```javascript
document.oncopy = e => {
  e.clipboardData.setData('text/plain', links.join('\n'));
  e.preventDefault();
};
window.focus();
document.execCommand('Copy', false, null);
```

**Analysis**: The extension can copy download URLs to clipboard when user clicks "Copy Links" button.

**Verdict**: EXPECTED BEHAVIOR - User-initiated action only

---

### 4. Download Functionality
**Severity**: LOW
**Files**: `data/window/index.js` (lines 317-348)
**Code**:
```javascript
chrome.downloads.download(options, () => {
  if (chrome.runtime.lastError) {
    delete options.filename;
    chrome.downloads.download(options);
  }
});
```

**Analysis**: Downloads selected media files using Chrome's downloads API. Sanitizes filenames by removing special characters (line 336).

**Verdict**: EXPECTED BEHAVIOR - Core functionality with proper error handling

---

### 5. FAQ/Feedback Tabs (Potential Privacy Issue)
**Severity**: LOW
**Files**: `worker.js` (lines 88-113)
**Code**:
```javascript
tabs.create({
  url: page + '?version=' + version + (previousVersion ? '&p=' + previousVersion : '') + '&type=' + reason,
  active: reason === 'install',
  ...(tbs && tbs.length && {index: tbs[0].index + 1})
});
```

**Analysis**: Opens homepage with version parameters on install/update (limited to once per 45 days).

**Privacy Impact**:
- Sends: extension version, previous version, install/update reason
- Does NOT send: user ID, browsing data, unique identifiers
- Only opens if `navigator.webdriver !== true` (avoids automation/testing)
- User preference `faqs: true` can disable this

**Verdict**: ACCEPTABLE - Standard update notification, non-invasive

---

## False Positives

| Pattern | Location | Explanation |
|---------|----------|-------------|
| `navigator.userAgent` | `data/window/index.js:14`, `external.js:14` | Browser detection for UI adjustments and external app IDs |
| `document.execCommand` | `data/window/index.js:360` | Clipboard copy functionality (user-initiated) |
| YouTube URL filtering | `data/window/index.js:76-77` | Prevents detection due to Chrome Web Store policy |
| External extension messaging | `data/window/external.js:73` | Optional integration with download manager extension |

## API Endpoints & Network Activity

| Endpoint | Purpose | Data Sent | Triggered By |
|----------|---------|-----------|--------------|
| `https://webextension.org/listing/bulk-media-downloader.html` | Homepage/FAQ | version, previous version, install type | Install/update (45-day cooldown) |
| `https://webextension.org/listing/bulk-media-downloader.html?rd=feedback` | Uninstall feedback | extension name, version | Uninstall |
| N/A | No tracking/analytics | N/A | N/A |

**Note**: No third-party analytics, no tracking SDKs, no remote configurations detected.

## Data Flow Summary

```
1. User opens extension popup window
   ↓
2. Extension monitors webRequest.onHeadersReceived for media files
   ↓
3. Detected media URLs stored in local DOM table (no persistence)
   ↓
4. User selects files and clicks "Download" OR "Copy Links" OR "Run External"
   ↓
5a. Download: chrome.downloads.download() → Local filesystem
5b. Copy: Clipboard API → User's clipboard
5c. External: chrome.runtime.sendMessage() → External App Button extension
```

**Data Retention**: None. All detected URLs are stored temporarily in the popup window DOM and cleared when window closes.

**Data Transmission**: None (except optional external app integration, user-controlled).

## Security Best Practices Observed

1. ✅ **Open Source**: Full source code available on GitHub
2. ✅ **Proper Licensing**: Mozilla Public License v2.0
3. ✅ **No Obfuscation**: Code is clean and readable
4. ✅ **No eval()**: No dynamic code execution
5. ✅ **No Remote Scripts**: All code bundled in extension
6. ✅ **User Consent**: All actions require explicit user interaction
7. ✅ **Error Handling**: Proper try-catch and error callbacks
8. ✅ **Input Sanitization**: Filename sanitization before download
9. ✅ **Manifest V3**: Uses modern manifest version
10. ✅ **No Tracking**: No analytics or telemetry SDKs

## Potential Concerns (Non-Critical)

1. **Broad Host Permissions** (`*://*/*`): Required for media detection but grants access to all websites. This is inherent to the extension's purpose and cannot be narrowed.

2. **External App Integration**: Allows passing download URLs to external executables via another extension. While this could be misused if user installs a malicious "External Application Button" extension, the feature itself is legitimate and documented.

3. **Update Notifications**: Opens homepage on updates, which could be used to track install base size (though no unique identifiers are sent).

## Recommendations

### For Users
- Safe to use for media downloading
- Only install "External Application Button" from trusted sources if using external download manager integration
- Disable FAQ notifications via extension settings if desired

### For Developers
- Consider narrowing host permissions to specific domains (though impractical for general media downloader)
- Add option to disable update notifications in UI
- Consider using Chrome's declarativeNetRequest API (though webRequest is required for content-type inspection)

## Overall Risk Assessment

**CLEAN**

**Justification**:
- Legitimate open-source project with transparent codebase
- All functionality matches stated purpose (media downloading)
- No data exfiltration, tracking, or malicious behavior
- Follows Chrome extension security best practices
- Active development on GitHub with public issue tracker
- Proper licensing and copyright notices
- No obfuscation or code hiding attempts

**Confidence Level**: HIGH

This extension is a clean, well-maintained tool for media downloading with no security concerns for typical users.
