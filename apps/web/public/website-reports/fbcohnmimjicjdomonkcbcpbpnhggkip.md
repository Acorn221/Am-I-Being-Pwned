# Vulnerability Report: MyJDownloader Browser Extension

## Metadata
- **Extension ID**: fbcohnmimjicjdomonkcbcpbpnhggkip
- **Extension Name**: MyJDownloader Browser Extension
- **Version**: 3.3.20
- **Users**: ~500,000
- **Manifest Version**: 2
- **Publisher**: AppWork GmbH
- **Analysis Date**: 2026-02-15

## Executive Summary

MyJDownloader Browser Extension is a legitimate browser companion for the JDownloader download manager application. The extension facilitates communication between the user's browser and their JDownloader instance (either local or cloud-connected via MyJDownloader service). After thorough analysis of the codebase, including static analysis and manual code review, no security vulnerabilities or privacy concerns were identified. The extension operates transparently within its stated purpose and does not engage in any suspicious data collection or exfiltration activities.

The extension uses `<all_urls>` and webRequest permissions solely for intercepting ClickAndLoad (CNL) protocol requests, which is expected behavior for a download manager integration. All network communication occurs with the official JDownloader API (api.jdownloader.org) or the user's local JDownloader instance at 127.0.0.1:9666.

## Vulnerability Details

No vulnerabilities identified.

## False Positives Analysis

### 1. webRequest with `<all_urls>`
**Why it appears suspicious**: The extension requests `webRequest`, `webRequestBlocking`, and `<all_urls>` permissions, which could theoretically be used to intercept all network traffic.

**Why it's legitimate**: These permissions are used exclusively to intercept ClickAndLoad (CNL) protocol requests. The code in `BackgroundController.js` shows the extension only responds to specific patterns:
- `jdcheck.php` URLs (to identify JDownloader compatibility)
- `127.0.0.1:9666/flash/addcrypted2` (local JDownloader CNL endpoints)
- `localhost:9666/flash/addcrypted2` (local JDownloader CNL endpoints)

The intercepted requests are processed to extract download links and send them to JDownloader, which is the core functionality of this extension type.

### 2. Content Scripts on All URLs
**Why it appears suspicious**: Multiple content scripts inject into `<all_urls>` with `run_at: document_start` and `all_frames: true`.

**Why it's legitimate**: The content scripts serve specific, benign purposes:
- `rc2Contentscript.js`: Handles reCAPTCHA/hCaptcha solving for JDownloader (common feature as download sites often use captchas)
- `onCopyContentscript.js`: Monitors copy events to capture download links from clipboard
- `toolbarContentscript.js`: Provides UI toolbar for link collection
- `selectionContentscript.js`: Captures selected text/links for sending to JDownloader
- `webinterfaceEnhancer.js`: Only runs on `my.jdownloader.org/*` to enhance the official web interface

None of these scripts exfiltrate data to third parties - they only communicate with the extension background page and the official JDownloader API.

### 3. Clipboard Monitoring
**Why it appears suspicious**: The extension monitors clipboard/copy events via `onCopyContentscript.js`.

**Why it's legitimate**: This is a documented feature of download managers - users can copy download links and the extension automatically captures them to send to JDownloader. The clipboard observer can be toggled on/off in settings (`StorageService.SETTINGS_CLIPBOARD_OBSERVER`), giving users control. The captured data is only sent to JDownloader, not to external servers.

### 4. Google/hCaptcha Endpoints
**Why it appears suspicious**: The extension loads scripts from `www.google.com/recaptcha/` and `hcaptcha.com`.

**Why it's legitimate**: Many file hosting services protect downloads with captchas. The extension provides a "browser solver" feature where captchas are displayed to the user in a popup window (`rc2Contentscript.js`, lines 379-457). This is a convenience feature - users solve captchas in their browser instead of in the JDownloader application. The solved captcha tokens are sent back to the user's JDownloader instance to complete downloads.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.jdownloader.org | Official MyJDownloader cloud API | User credentials (hashed), session tokens, download links, device list requests | None - official API, encrypted communication (AES256 + SHA256 HMAC) |
| my.jdownloader.org | Official web interface | None (only content script injection for UI enhancement) | None - official domain |
| 127.0.0.1:9666 | Local JDownloader instance | Download links, CNL data, captcha solutions | None - localhost communication |
| www.google.com | reCAPTCHA service | User captcha interactions | None - standard captcha flow |
| hcaptcha.com | hCaptcha service | User captcha interactions | None - standard captcha flow |

## Code Quality & Security Observations

**Positive Security Practices:**
1. **Strong Cryptography**: Uses AES-256 encryption and SHA-256 HMAC for API communication (see `jdapi.js`)
2. **Password Handling**: Passwords are hashed client-side with email+salt before transmission (`hashPassword` function in `jdapi.js`)
3. **No Eval/Dynamic Code**: No use of `eval()`, `Function()`, or `executeScript` with dynamic strings
4. **Origin Checks**: CAPTCHA solver validates message origins with `window.parent.postMessage` patterns
5. **Standard Libraries**: Uses well-known libraries (Angular, jQuery, CryptoJS, RxJS) - no obfuscation beyond standard minification

**Architecture:**
- Angular-based single-page application with standard MVC pattern
- Background page (`index.html` with `BackgroundController.js`) manages API connections
- Content scripts are isolated and purpose-specific
- Local storage used only for user settings and session tokens

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:
This extension is a legitimate, well-architected browser companion for JDownloader. All functionality aligns with its stated purpose: intercepting download links, managing clipboard monitoring for downloads, and facilitating communication with the user's JDownloader instance. The cryptography implementation is robust, no data is exfiltrated to unauthorized endpoints, and all permissions are appropriately scoped to necessary functionality. The extension is published by AppWork GmbH, the company behind JDownloader, adding organizational legitimacy. No security vulnerabilities, privacy violations, or malicious behavior patterns were identified during analysis.
