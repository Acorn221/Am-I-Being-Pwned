# Vulnerability Report: Cold Turkey Blocker

## Metadata
- **Extension ID**: pganeibhckoanndahmnfggfoeofncnii
- **Extension Name**: Cold Turkey Blocker
- **Version**: 4.9.1
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Cold Turkey Blocker is a legitimate productivity extension that blocks distracting websites by communicating with a native desktop application via Chrome's nativeMessaging API. The extension operates as a website blocking tool that requires user consent for data collection and communicates browsing activity (URLs, titles, time spent) to the local Cold Turkey desktop app. While the extension has one minor vulnerability (postMessage without origin validation), this does not pose a significant security risk in the extension's architecture. The extension's invasive permissions and data collection are fully disclosed to users through a consent screen, and all data remains local to the user's device - no external tracking or data exfiltration occurs beyond a single API call to validate break keys.

The extension's core functionality - blocking websites, monitoring browsing activity, and preventing circumvention - is clearly disclosed and expected for a website blocker. This is not malicious behavior but the stated purpose of the software.

## Vulnerability Details

### 1. MEDIUM: postMessage Without Origin Validation

**Severity**: MEDIUM
**Files**: ctFrame.js
**CWE**: CWE-346 (Origin Validation Error)
**Description**: The extension's frame handler (ctFrame.js) uses `window.addEventListener("message")` without validating the origin of incoming messages. This could allow malicious websites to send crafted messages to trigger extension functionality.

**Evidence**:
```javascript
// ctFrame.js:29
window.addEventListener("message", (event) => {
    if (typeof event.data.command != 'undefined') {
        if (event.data.command == "cold-turkey-blocker-get-reason") {
            document.getElementById("blocker-frame").contentWindow.postMessage({
                command: "cold-turkey-blocker-reason",
                reason: parsedReason
            }, "*");
        } else if (event.data.command == "cold-turkey-blocker-unblock-tab") {
            chrome.runtime.sendMessage({
                command: "unblockTab",
                blockId: parsedReason.blockId,
                lock: parsedReason.lock,
                duration: event.data.duration
            });
        }
        // ... additional commands
    }
});
```

**Verdict**: This vulnerability is mitigated by several factors:
1. The ctFrame.html page is only loaded when a site is blocked by Cold Turkey
2. The frame loads content from `https://getcoldturkey.com/blocked/` which is controlled by the extension developer
3. Commands require specific data structures from `parsedReason` which comes from the extension itself
4. The most sensitive operations (unblock, break) require data that would need to be obtained from the extension's internal state

While origin validation should be added (`if (event.origin === "https://getcoldturkey.com")`), the practical exploitability is limited because the frame context only exists on blocked pages and the extension validates block parameters server-side.

### 2. LOW: Broad Host Permissions Used for Legitimate Purpose

**Severity**: LOW
**Files**: manifest.json, ctContent.js
**CWE**: N/A (Overly Broad Permissions)
**Description**: The extension uses `<all_urls>` content script injection to block websites according to user-configured rules.

**Evidence**:
```json
"content_scripts": [{
    "run_at": "document_start",
    "all_frames": true,
    "js": ["ctContent.js"],
    "matches": ["<all_urls>"]
}]
```

**Verdict**: NOT A VULNERABILITY. This is the expected and necessary behavior for a website blocking extension. The extension must inject into all pages at document_start to prevent access to blocked content before the page loads. Users are explicitly consenting to this behavior when installing a website blocker.

## False Positives Analysis

The following patterns appear in the code but are NOT security issues:

1. **Service Worker Blocking** (ctContent.js:11-26): The extension deliberately blocks service worker registration to prevent websites from circumventing blocks. This is legitimate anti-circumvention functionality for a blocking tool.

2. **Native Messaging Data Collection** (ctBackground.js): The extension sends URLs, titles, and usage statistics to the local native app via `chrome.runtime.connectNative('com.coldturkey.coldturkey')`. This is:
   - Explicitly disclosed in the user consent screen (ctUserConsent.html)
   - Sent only to the local desktop application, NOT to remote servers
   - The core functionality of the extension (tracking blocked sites)
   - Covered by the privacy statement at getcoldturkey.com/privacy

3. **Tab Muting** (ctBackground.js:489-498): The extension mutes tabs when blocking pages. This is expected behavior to prevent audio from blocked content.

4. **Extension Enumeration** (ctBackground.js:107): The extension checks for chrome:// and chrome-extension:// URLs to handle browser internal pages. This is NOT malicious enumeration of other extensions.

5. **Break Key Validation** (ctBackground.js:820): One legitimate external API call to `getcoldturkey.com/activate/activate-break.php` validates one-time break keys. This is necessary to prevent users from reusing break codes.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| getcoldturkey.com/blocked/* | Display block page UI | URL parameters, block reason | **LOW** - Loads blocking page UI from vendor |
| getcoldturkey.com/activate/activate-break.php | Validate break keys | 10-digit numeric key | **LOW** - One-time validation to prevent key reuse |
| getcoldturkey.com/download/ | Link to download page | None (navigation only) | **NONE** - Simple link |
| getcoldturkey.com/support/extensions/chrome/ | Uninstall feedback | Reason parameter in URL | **LOW** - Optional uninstall survey |
| Native App (com.coldturkey.coldturkey) | Local app communication | URLs, titles, block stats | **LOW** - Local only, disclosed to user |

## Privacy & Data Collection

The extension explicitly requests user consent before collecting personal data:
- Website URLs
- Website titles
- Time spent on websites
- Number of times a website is blocked

**Critical Points**:
1. Users must click "Agree to transmit personal data" to enable the extension
2. The consent screen clearly states: "Your data is only read by the app and is never sent off your device"
3. All data is sent to the LOCAL desktop application via nativeMessaging, not to remote servers
4. The only external communication is break key validation (one-time use codes)

This is transparent, user-consented data collection for the extension's core functionality.

## Security Features

The extension includes several security-positive behaviors:

1. **Anti-Circumvention**: Blocks service workers, Picture-in-Picture, handles popstate events, removes unauthorized iframes
2. **User Consent**: Explicitly asks for permission before collecting browsing data
3. **Local Data**: All browsing data stays on the user's device via native messaging
4. **Uninstall Protection**: Clear warning that "This browser may be blocked if this extension is disabled or removed during a locked block"

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

Cold Turkey Blocker is a legitimate productivity tool with transparent data collection practices. The extension operates as expected for a website blocking application: it monitors browsing activity, blocks configured sites, and communicates with a local desktop application to synchronize blocks and track usage statistics.

The single vulnerability (postMessage without origin check) represents a theoretical attack surface but has limited practical exploitability due to the constrained context in which it operates (only on blocked pages loading content from the vendor's domain). The broad permissions (`<all_urls>`) are necessary and expected for a blocking tool.

All data collection is:
- Explicitly disclosed via consent screen
- Limited to the stated purpose (blocking and statistics)
- Kept local to the user's device (native messaging to desktop app)
- Covered by a privacy policy

**Recommended Remediation**:
1. Add origin validation to the postMessage handler in ctFrame.js:
   ```javascript
   window.addEventListener("message", (event) => {
       if (event.origin !== "https://getcoldturkey.com") return;
       // ... rest of handler
   });
   ```

This is a LOW risk extension that operates transparently and as advertised. The permissions are appropriate for its stated functionality as a website blocker.
