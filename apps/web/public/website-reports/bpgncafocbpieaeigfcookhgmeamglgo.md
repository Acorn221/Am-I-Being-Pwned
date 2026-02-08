# Vulnerability Report: Imprivata OneSign

## Metadata
| Field | Value |
|---|---|
| Extension Name | Imprivata OneSign |
| Extension ID | bpgncafocbpieaeigfcookhgmeamglgo |
| Version | 1.0.71.2904 |
| Manifest Version | 3 |
| User Count | ~19,000,000 |
| Analysis Date | 2026-02-08 |

## Executive Summary

Imprivata OneSign is a legitimate enterprise Single Sign-On (SSO) extension for Google Chrome and Microsoft Edge. It is developed by Imprivata, a well-known healthcare IT security company. The extension acts as a bridge between web browsers and a locally-installed Imprivata OneSign Windows Agent via Chrome's Native Messaging API. Its core purpose is to:

1. Gather form control information from web pages (login forms)
2. Capture user credentials entered into forms (encrypting them with libsodium)
3. Auto-fill (proxy) credentials into web application login pages on behalf of the authenticated user
4. Provide Identity Provider (IdP) authentication token services
5. Support Confirm ID (CID) biometric/secondary authentication flows
6. Support Application Profile Generator (APG) for SSO learning/configuration

The extension requires broad permissions because it must operate on all web pages to detect and interact with login forms across any enterprise web application. All credential data is encrypted using NaCl/libsodium public-key cryptography before transit. Communication is exclusively via Chrome's `nativeMessaging` API to a local agent -- there are **zero network calls** (no fetch, XMLHttpRequest, WebSocket, or any remote endpoints) in the entire codebase.

**Overall Risk: CLEAN**

## Vulnerability Details

### VULN-01: Broad Host Permissions on All URLs
| Field | Value |
|---|---|
| Severity | LOW (Informational) |
| Files | `manifest.json` |
| Verdict | Expected for SSO product -- FALSE POSITIVE |

The extension requests `http://*/*` and `https://*/*` host permissions and injects content scripts on all pages. This is necessary for an enterprise SSO solution that must detect login forms across arbitrary web applications. The extension does not exfiltrate any data to remote servers.

### VULN-02: Content Scripts Injected at document_start on All Pages
| Field | Value |
|---|---|
| Severity | LOW (Informational) |
| Files | `manifest.json`, `capture_page_info.js`, `content.js`, `confirmid_content.js` |
| Verdict | Expected for SSO -- FALSE POSITIVE |

Content scripts run at `document_start` on all URLs and enumerate all form controls (input, select, button, textarea, iframe). This is standard behavior for credential capture/proxy in enterprise SSO. The `all_frames: true` second content script set ensures iframed login forms are also handled.

### VULN-03: Cookie Set on Imprivata Domains
| Field | Value |
|---|---|
| Severity | LOW (Informational) |
| Files | `content.js` (line 976-978) |
| Code | `if (window.location.hostname.search(/.imprivata.com/) !== -1) { setCookie("imprivata_extension_installed", "1"); }` |
| Verdict | Benign -- FALSE POSITIVE |

The extension sets a single cookie `imprivata_extension_installed=1` only on `*.imprivata.com` domains. This is a simple presence detection cookie so the Imprivata web portal knows the extension is installed. No sensitive data is included. Note: the regex `/.imprivata.com/` technically matches any character before `imprivata.com` (not just `.`), but the impact is negligible since the cookie value is just "1".

### VULN-04: Native Messaging to Local Agent
| Field | Value |
|---|---|
| Severity | LOW (Informational) |
| Files | `background.js`, `transport.js` |
| Code | `chrome.runtime.connectNative("com.imprivata.isxnmhost")` and `chrome.runtime.connectNative("com.imprivata.isxnmtracehost")` |
| Verdict | Core functionality -- FALSE POSITIVE |

The extension connects to two native messaging hosts: the main Imprivata agent (`com.imprivata.isxnmhost`) and a trace/logging host (`com.imprivata.isxnmtracehost`). All browser-to-agent communication flows through these channels. This is the expected architecture for enterprise SSO -- credentials are passed to the local agent (encrypted) for authentication against enterprise identity stores.

### VULN-05: Web-Accessible Resources Exposed to All Origins
| Field | Value |
|---|---|
| Severity | LOW |
| Files | `manifest.json` |
| Verdict | Minor concern -- LOW risk |

The files `idp.js`, `confirmid.js`, `sso_ready.js`, and `apg.js` are web-accessible to all origins (`http://*/*`, `https://*/*`). These scripts are injected into page context to provide JavaScript APIs (`initiate_idp_login()`, `confirm_id_authenticate()`, `request_sso_ready()`, and APG SSO interface functions) that enterprise web applications call to integrate with Imprivata. The scripts only communicate via CustomEvent dispatching on the document -- they contain no sensitive logic themselves. A malicious page could theoretically detect the extension's presence by checking for these resources, but this is a minimal information leak.

### VULN-06: Credential Capture via Input/Change/KeyDown Listeners
| Field | Value |
|---|---|
| Severity | MEDIUM (by design) |
| Files | `content.js` (lines 42-66, 94-137, 193-263) |
| Verdict | Core SSO functionality -- EXPECTED BEHAVIOR |

The extension attaches `onChange`, `onInput`, and `onKeyDown` event listeners to form controls when the native agent requests credential capture. Values are immediately encrypted using libsodium `crypto_box_easy` with a fresh nonce before being stored. The encrypted credentials are sent back to the native agent (never to any remote server). The keyDown handler only triggers on Enter key (keyCode 13), not on arbitrary keystrokes -- this is NOT a keylogger.

### VULN-07: Credential Proxy (Auto-Fill) Sets Form Values Directly
| Field | Value |
|---|---|
| Severity | MEDIUM (by design) |
| Files | `capture_page_info.js` (lines 204-256, 1319-1355) |
| Verdict | Core SSO functionality -- EXPECTED BEHAVIOR |

The `ProxyCredentials` function and `HTMLElementInfo.setValue` method decrypt credentials received from the native agent and directly set `control.value` on form fields. This includes auto-submission (`AutoSubmit`) which clicks the submit button. This is standard enterprise SSO auto-fill behavior. Credentials are decrypted in the content script only at the moment of proxying.

## False Positive Table

| Pattern | Location | Reason |
|---|---|---|
| Broad host permissions (`<all_urls>`) | manifest.json | Required for enterprise SSO on arbitrary web apps |
| Content scripts on all pages | manifest.json | Must detect login forms on any enterprise web app |
| DOM enumeration of all form controls | capture_page_info.js | Page scraping for SSO form detection |
| Input/keydown event listeners | content.js | Credential capture for SSO (encrypted) |
| MutationObserver on document | content.js | Detect dynamic page changes for SPA login forms |
| Native messaging to local agent | transport.js, background.js | Core SSO architecture - local agent communication |
| Cookie write | content.js | Presence detection on imprivata.com only |
| Script injection into page context | content.js, trans_defs.js | IdP/CID/SSO Ready API injection for enterprise web app integration |
| `chrome.scripting.executeScript` | background.js, trans_defs.js | Fallback content script injection on install/update |
| `chrome.webRequest.onAuthRequired` | background.js | HTTP Basic Auth detection for SSO |
| Shadow DOM traversal | capture_page_info.js | Modern web component login form support |

## API Endpoints Table

| Endpoint | Type | Purpose |
|---|---|---|
| `com.imprivata.isxnmhost` | Native Messaging | Main communication channel to local Imprivata agent |
| `com.imprivata.isxnmtracehost` | Native Messaging | Trace/logging channel to local agent |
| None | HTTP/HTTPS | **No remote network calls exist in the codebase** |

## Data Flow Summary

```
[Web Page Login Form]
        |
        v (content scripts enumerate controls)
[capture_page_info.js] -- GatherPageInfo() --> control metadata
        |
        v (credential capture with encryption)
[content.js] -- onChange/onInput/onKeyDown --> encrypt(value) via libsodium
        |
        v (chrome.runtime.sendMessage)
[background.js] -- event routing
        |
        v (chrome.runtime.connectNative)
[transport.js] -- NM_Host.send_message() --> com.imprivata.isxnmhost
        |
        v (local IPC only)
[Imprivata OneSign Windows Agent] -- enterprise identity/auth
        |
        v (agent sends proxy command back)
[content.js] -- ProxyCredentials() --> decrypt + set control.value
        |
        v
[Web Page Login Form auto-filled and submitted]
```

Key security properties:
- All credential values are encrypted with NaCl `crypto_box_easy` (Curve25519/XSalsa20/Poly1305) before leaving the content script
- Key exchange happens per-session between content script and native agent
- No data is sent to any remote server -- all communication is local via native messaging
- The extension has no `fetch`, `XMLHttpRequest`, `WebSocket`, or any HTTP client code
- Generated by CoffeeScript 1.12.7 -- clean, readable, not obfuscated

## Overall Risk Assessment

**CLEAN**

Imprivata OneSign is a legitimate enterprise SSO browser extension from a major healthcare IT security vendor. While it has broad permissions and captures credentials from all web pages, this is its intended and documented purpose. All credential handling uses proper public-key encryption (libsodium). Communication is exclusively local via Chrome Native Messaging to the installed Imprivata agent -- there are zero remote network calls in the entire codebase. No signs of malicious behavior, data exfiltration, obfuscation, remote code execution, or any suspicious patterns. The code is cleanly generated from CoffeeScript and is fully readable.
