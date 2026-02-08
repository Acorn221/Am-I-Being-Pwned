# Vulnerability Report: LockDown Browser: AP Classroom Edition

## Metadata
| Field | Value |
|-------|-------|
| Extension Name | LockDown Browser: AP Classroom Edition |
| Extension ID | djpknfecbncogekjnjppojlaipeobkmo |
| Version | 0.4.00.04 |
| Manifest Version | 3 |
| Author | VERSIONTEST_CBPROD |
| Approximate Users | ~9,000,000 |
| Publisher | Respondus (LockDown Browser) |

## Executive Summary

LockDown Browser: AP Classroom Edition is a legitimate exam lockdown browser produced by Respondus, a well-known educational testing security company. The extension is designed exclusively for ChromeOS (it checks `chrome.runtime.getPlatformInfo` for `"cros"` and shows a "not a Chromebook" message otherwise). It enforces a locked-down exam environment by: controlling window focus and fullscreen state, blocking keyboard shortcuts, disabling other extensions during exams, preventing right-click and copy/paste, monitoring for screenshots, closing unauthorized tabs, and communicating with Respondus's server infrastructure for DRM checks and challenge-response authentication.

The extension requires extensive permissions (`<all_urls>`, `management`, `cookies`, `tabs`, `scripting`, `system.display`, `history`, `browsingData`, `contentSettings`, `webNavigation`, `webRequest`, `declarativeNetRequestWithHostAccess`), which are highly invasive. However, **every permission directly serves the extension's core exam-lockdown functionality**. There is no evidence of data exfiltration, tracking SDKs, advertising, residential proxy behavior, or any malicious activity.

## Vulnerability Details

### MEDIUM-1: Web-Accessible background.js Exposes Source Code
- **Severity**: MEDIUM
- **File**: `manifest.json` (line ~47-51, `web_accessible_resources`)
- **Code**: `"resources": ["background.js", "manifest.json", "toolbar.js", ...]`
- **Detail**: The background service worker source and multiple internal JS files are listed in `web_accessible_resources` with `"matches": ["<all_urls>"]`. This allows any website to read the extension's source code via `chrome.runtime.getURL()`, which could help attackers reverse-engineer the lockdown bypass logic.
- **Verdict**: Design concern for an exam security product. Not malicious, but weakens the extension's security posture against bypass attempts.

### LOW-1: innerHTML Usage with i18n Strings
- **Severity**: LOW
- **File**: `popup.js` (line ~261), `toolbar.js` (various), `protectPage` function
- **Code**: `r.innerHTML = t[i]` (popup.js), `t.innerHTML = e` (protectPage overlay)
- **Detail**: Several locations use innerHTML to insert localized strings. The strings are sourced from `chrome.i18n.getMessage()` or local `_locales/` JSON files, both of which are extension-controlled. No user-supplied or external data flows into innerHTML.
- **Verdict**: FALSE POSITIVE. All innerHTML inputs come from bundled i18n resources.

### LOW-2: Extension Disabling (Management API)
- **Severity**: LOW
- **File**: `background.js` (security module, `manageExtensions` function)
- **Code**: `yield chrome.management.setEnabled(r.id, !1)` and re-enables on exam end
- **Detail**: During an active exam, the extension disables all other extensions (except a hardcoded allowlist). Extensions are re-enabled when the exam concludes. This is standard LockDown Browser behavior to prevent cheating tools.
- **Verdict**: Expected behavior for exam lockdown. Extensions are properly restored after exam completion.

### LOW-3: Clipboard Monitoring and Overwriting
- **Severity**: LOW
- **File**: `background.js` (protectPage module)
- **Code**: `navigator.clipboard.readText().then(...)` with screenshot detection logic
- **Detail**: The extension periodically reads the clipboard to detect screenshots (clipboard becomes empty after ChromeOS screenshot). It also overwrites clipboard contents with spaces. This is a standard anti-cheating measure in exam lockdown software.
- **Verdict**: Expected behavior. Only active during exam sessions.

### LOW-4: History Deletion
- **Severity**: LOW
- **File**: `background.js` (utils module)
- **Code**: `chrome.history.deleteRange({startTime: n, endTime: Date.now()})` and `chrome.history.deleteUrl({url: n})`
- **Detail**: The extension clears browsing history created during the exam session and removes history entries related to the LockDown Browser server and its own extension URLs. This prevents exam URLs from appearing in browsing history.
- **Verdict**: Expected behavior for exam privacy. Scoped to exam session timeframe only.

### LOW-5: Browsing Data Cleanup
- **Severity**: LOW
- **File**: `background.js` (security module)
- **Code**: `chrome.browsingData.removeFormData({})`
- **Detail**: Form data is cleared when security is toggled on. This prevents autofill from leaking information during exams.
- **Verdict**: Expected behavior for exam security.

## False Positive Table

| Finding | Reason for FP Classification |
|---------|------------------------------|
| innerHTML usage in popup.js/toolbar.js | All sources are extension-bundled i18n JSON files |
| CryptoJS AES/Blowfish (modules 955, 3128) | Standard CryptoJS library for launch URL decryption |
| `new Function("return this")()` (module o.g) | Webpack runtime globalThis polyfill |
| Extension disabling via management API | Standard exam lockdown behavior, extensions re-enabled after exam |
| Clipboard read/write | Screenshot detection anti-cheat measure, exam-session-only |
| Cookie manipulation | Only sets/removes LockDown Browser-specific cookies (rldb* prefix) |
| `window.open` override | Blocks unauthorized window.open calls during exams |
| `beforeunload` event suppression | Prevents exam pages from blocking navigation during lockdown |
| `postMessage("*")` usage | Used between iframe toolbar and parent page within extension context |

## API Endpoints Table

| Endpoint | Purpose | Method |
|----------|---------|--------|
| `https://smc-service-cloud.respondus2.com/MONServer/drmcheck.shtml` | DRM verification check | GET (tab load) |
| `https://smc-service-cloud.respondus2.com/MONServer/chromebook/cbe_launch.do` | Exam launch/decryption handshake | GET (iframe src) |
| `https://smc-service-cloud.respondus2.com/MONServer/chromebook/cbe_handshake.do` | Challenge-response authentication | GET (iframe src) |
| `https://smc-service-cloud.respondus2.com/MONServer/chromebook/verify_oem_exit_pw.do` | Proctor password verification | POST |

## Data Flow Summary

1. **Launch**: Extension detects a URL containing `ldb1:jb` prefix, triggers exam launch sequence.
2. **Decryption**: Launch URL payload is sent to Respondus server via an iframe on `security.html` for decryption. Decrypted payload contains exam URL, allowed domains, and settings.
3. **Lockdown Activation**: Extension enters fullscreen, disables other extensions, injects page protection scripts (keyboard blocking, right-click blocking, clipboard control, screenshot detection), creates a toolbar overlay.
4. **Exam Session**: Extension monitors window focus, blocks unauthorized tabs/URLs, tracks focus-loss events via `rldbswipe` cookie counter. DRM check runs in a minimized tab.
5. **Cleanup**: On exam end, extensions are re-enabled, cookies are cleared, history is cleaned, fullscreen is exited, user is shown end-exam page.
6. **Communication**: Only communicates with `smc-service-cloud.respondus2.com` (Respondus infrastructure). No third-party analytics, telemetry, or tracking endpoints.

## Hardcoded Configuration
- **Allowed extension IDs**: `adkcpkpghahmbopkjchobieckeoaoeem`, `ghlpmldmjjhmdgmneoaibbegkjjbonbk`, `iheobagjkfklnlikgihanlhcddjoihkg`, `haldlgldplgnggkjaafhelgiaglafanh` (other LockDown Browser/Respondus extensions)
- **Index code**: `jb` (AP Classroom edition identifier)
- **Integrity hash**: `448e5fa2ccca1145bfd64b10b65f8024897254d4b4ec988c8492c4ca7c144098` (SHA-256 of web-accessible resources, self-integrity check)
- **Debug mode**: `false`
- **Server**: `https://smc-service-cloud.respondus2.com`

## Overall Risk Assessment

**CLEAN**

This extension is a legitimate exam lockdown browser from Respondus, a well-established educational technology company. While it requires highly invasive permissions and performs aggressive browser control actions (disabling extensions, forcing fullscreen, blocking keyboard shortcuts, monitoring clipboard, closing tabs), all behaviors directly serve the exam security/anti-cheating purpose. The extension:

- Only activates lockdown on ChromeOS when launched via a specific URL scheme
- Only communicates with Respondus's own server infrastructure
- Contains no tracking SDKs, analytics, advertising, or data exfiltration code
- Performs a self-integrity check on startup
- Properly restores browser state (re-enables extensions, clears lockdown cookies) when exams end
- Uses standard CryptoJS for legitimate cryptographic operations (launch URL decryption)
- Contains no obfuscated or suspicious code beyond standard webpack bundling/minification
