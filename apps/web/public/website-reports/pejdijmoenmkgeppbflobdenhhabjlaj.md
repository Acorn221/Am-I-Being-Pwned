# Vulnerability Report: iCloud Passwords

## Metadata
| Field | Value |
|-------|-------|
| Extension Name | iCloud Passwords |
| Extension ID | pejdijmoenmkgeppbflobdenhhabjlaj |
| Version | 3.2.0 |
| Manifest Version | 3 |
| Users | ~6,000,000 |
| Publisher | Apple Inc. |

## Executive Summary

iCloud Passwords is Apple's official Chrome extension for integrating iCloud Keychain with Chrome/Edge browsers on Windows and macOS. The extension communicates exclusively with a local native application (`com.apple.passwordmanager`) via `chrome.runtime.connectNative()` -- there are **zero network requests** (no `fetch`, `XMLHttpRequest`, or `WebSocket` calls) from the extension itself. All credential data flows through a locally-authenticated, SRP-encrypted channel to the native iCloud for Windows/macOS Passwords application.

The extension requires broad permissions (`*://*/*` host permissions, `scripting`, `webNavigation`, `privacy`, `nativeMessaging`, `storage`, `contextMenus`, `declarativeContent`) and injects a content script on all pages. While invasive, every permission is justified by its password management functionality:

- **`*://*/*` + content scripts**: Required to detect login forms and fill credentials on all websites.
- **`privacy`**: Used to disable Chrome's built-in autofill to prevent double-filling.
- **`nativeMessaging`**: Core communication channel with the native iCloud Passwords app.
- **`scripting`**: Dynamic injection of content scripts into frames.
- **`webNavigation`**: Frame enumeration for multi-frame form filling.
- **`contextMenus`**: TOTP setup via right-click context menu.

No evidence of malicious behavior, data exfiltration, remote code execution, third-party SDKs, analytics, or obfuscation was found.

## Vulnerability Details

### LOW-1: Broad Host Permissions with All-Frame Content Script Injection
- **Severity**: LOW (Informational)
- **Files**: `manifest.json`
- **Code**: `"host_permissions": ["*://*/*"]`, `"all_frames": true`
- **Verdict**: Expected for a password manager. Content script must run on all pages and iframes to detect login forms. No data leaves the extension except through the authenticated native messaging channel.

### LOW-2: Privacy API Used to Override Browser Autofill Settings
- **Severity**: LOW (Informational)
- **Files**: `background.js` (ExtensionSettings class)
- **Code**: `chrome.privacy.services.passwordSavingEnabled.set({value: false})`
- **Verdict**: Disables Chrome's built-in password saving, credit card autofill, and address autofill to prevent conflicts. This is standard practice for password managers and is user-configurable via the extension's settings page.

### LOW-3: PIN-Based SRP Authentication (6-Digit PIN)
- **Severity**: LOW
- **Files**: `background.js` (SecretSession class), `page_popup.js`
- **Code**: SRP-3072 PAKE protocol using sjcl crypto library with a 6-digit PIN
- **Verdict**: The pairing uses SRP (Secure Remote Password) protocol over the native messaging channel. The 6-digit PIN is used only for initial device pairing with the local native app, not transmitted over the network. SRP-3072 with SHA-256 is cryptographically sound. The PIN's limited entropy is mitigated by the fact that it's a local pairing mechanism only.

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| `innerHTML` assignment | `completion_list.js` (strongPasswordSuggestionListItems) | Uses `innerHTML` with localized string templates (`g_localizer.getMessage()`), not user-supplied data. Limited to UI chrome within the completion list iframe. |
| `document.createElement` usage | `content_script.js`, `page_popup.js`, `completion_list.js` | Standard DOM manipulation for building autofill UI (completion list iframe, popup credential list). No user-controlled content injected. |
| Key event listeners (`keydown`, `keyup`, `keypress`) | `content_script.js` | Form field event monitoring for autofill heuristics and form submission detection. Does not exfiltrate keystrokes -- only tracks username/password field values for the local native app channel. |
| `postMessage` calls | `content_script.js` (CompletionListDriver) | Communication between the content script and the completion list iframe (web accessible resource). Messages are structured internal commands (resize, dismiss, etc.), not cross-origin data exchange. |
| Password/credential tracking | `content_script.js` (pageNavigationHandler) | Sends credentials to background script via `chrome.runtime.sendMessage` for saving to iCloud Keychain through the native app. This is the core intended functionality. |
| Base64/encryption code (sjcl) | `background.js` | Stanford JavaScript Crypto Library used for SRP-3072 PAKE authentication with the local native application. Standard cryptographic protocol implementation. |
| `chrome.scripting.executeScript` | `background.js` | Dynamically injects content scripts into frames. Used only to ensure the content script is present in all frames for form detection. |
| Discord URL check | `content_script.js:3550` | `"https://discord.com/channels/@me" !== window.location.href` -- Site-specific heuristic for form detection, not data collection. |

## API Endpoints

| Endpoint | Type | Purpose |
|----------|------|---------|
| `com.apple.passwordmanager` | Native Messaging | Sole communication channel. Connects to local iCloud for Windows/macOS native application. |
| `https://support.apple.com/kb/DL1455` | Static URL (download link) | Displayed to user for downloading iCloud for Windows. |
| `https://www.apple.com/macos` | Static URL (download link) | Displayed to macOS users for system update. |
| `https://clients2.google.com/service/update2/crx` | CWS Update URL | Standard Chrome Web Store auto-update endpoint (in manifest). |

## Data Flow Summary

```
[Web Page Form Fields]
        |
        | (content_script.js detects forms, monitors field changes)
        v
[Content Script] --chrome.runtime.sendMessage--> [Background Script (Service Worker)]
        ^                                                |
        |                                                | chrome.runtime.connectNative("com.apple.passwordmanager")
        |                                                v
        |                                     [Native iCloud Passwords App]
        |                                     (SRP-3072 encrypted channel)
        |                                                |
        |  <--chrome.tabs.sendMessage (fill commands)----+
        |
        v
[Autofill credentials into form fields]
```

**Key points:**
1. **Zero network requests** from the extension itself. All data flows through `chrome.runtime.connectNative()` to a local native application.
2. Credential data (usernames, passwords, TOTP codes) is encrypted via SRP-3072 PAKE before being sent over the native messaging channel.
3. Content script monitors form fields on all pages but only communicates with the background service worker (never directly to external servers).
4. The extension does not read cookies, localStorage, or sessionStorage.
5. No analytics, telemetry, or third-party SDKs are present.
6. QR code scanning (for TOTP setup) processes image data locally using jsQR library -- images are not transmitted.

## Overall Risk Assessment

| Risk Level | CLEAN |
|------------|-------|

**Justification**: This is Apple's official iCloud Passwords extension. Despite requiring broad permissions (`*://*/*`, `privacy`, `nativeMessaging`, `scripting`, `webNavigation`), every permission is directly justified by legitimate password manager functionality. The extension makes zero network requests -- all communication goes through an SRP-encrypted native messaging channel to the local iCloud Passwords application. No evidence of data exfiltration, remote code execution, third-party tracking, analytics SDKs, or any malicious behavior was found. The codebase is clean, well-structured, and consistent with Apple's published functionality.
