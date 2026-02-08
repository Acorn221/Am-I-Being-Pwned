# Vulnerability Report: Signer.Digital Digital Signature, PKI

## Metadata
| Field | Value |
|-------|-------|
| Extension Name | Signer.Digital Digital Signature, PKI |
| Extension ID | glghokcicpikglmflbbelbgeafpijkkf |
| Version | 5.1.2 |
| Manifest Version | 3 |
| Author | Chartered Information Systems Pvt. Ltd |
| Users | ~3,000,000 |
| Permissions | `nativeMessaging` |
| Content Scripts | `content.js` on `*://*/*` and `file:///*` (all_frames: true) |
| Web Accessible Resources | `sdscript.js`, `icon32.png`, `icon_trash.svg`, `SdHtmlPage.html`, `sdstyle.css` |

## Executive Summary

Signer.Digital is a digital signature / PKI extension that bridges web pages to a native host application (`signer.digital.chrome.host`) for cryptographic operations on smartcards and USB tokens. The extension injects a JavaScript API (`SignerDigital`) into every page, enabling websites to request digital signatures, encryption/decryption, certificate selection, and CSR generation via the native messaging host.

The extension has a minimal permission footprint (only `nativeMessaging`) and contains no obfuscation, no remote code loading, no telemetry/analytics SDKs, no ad injection, and no data exfiltration behavior. The code is straightforward and purpose-built for PKI operations. However, there are several medium-severity security concerns related to the architecture of injecting a privileged API into every web page.

## Vulnerability Details

### MEDIUM-1: Injected Page Script Exposes Signing API to All Origins

**Severity:** MEDIUM
**File:** `content.js` (lines 77-82), `sdscript.js`
**Code:**
```javascript
// content.js - injects sdscript.js into every page's DOM
var s = document.createElement('script');
s.src = chrome.runtime.getURL('sdscript.js');
(document.head || document.documentElement).appendChild(s);
```
**Analysis:** The `sdscript.js` file is injected into the main world of every page visited (including `file:///*`). This creates a global `SignerDigital` object accessible to any JavaScript running on the page. Any website can invoke `SignerDigital.signHash()`, `SignerDigital.getSelectedCertificate()`, `SignerDigital.encryptB64Data()`, etc. While host version 5+ includes a site licensing check (the user gets a "Deny / Always Allow" popup), the older host path has no such gating. Even with the license popup, once a user clicks "Always Allow" the site has permanent access.

**Verdict:** Design concern inherent to how browser-to-native-host PKI bridges work. The license/allow-deny popup in v5+ is a reasonable mitigation. Not malicious, but increases attack surface.

---

### MEDIUM-2: `window.postMessage` Used with Wildcard Origin

**Severity:** MEDIUM
**File:** `content.js` (line 47), `sdscript.js` (line 150)
**Code:**
```javascript
// content.js line 47
window.postMessage(respFromHost, '*');

// sdscript.js line 150
window.postMessage(msg, "*");
```
**Analysis:** Both the content script and the injected page script use `window.postMessage(data, "*")` with a wildcard target origin. This means any iframe on the page (including cross-origin iframes) could intercept these messages. The content script does check `event.source !== window` and `event.data.src === "user_page.js"` for incoming messages, which provides some filtering, but responses from the native host are broadcast to `*`. A malicious iframe could potentially intercept signing responses or certificate data.

**Verdict:** Common pattern in native messaging bridges but not ideal for security-sensitive PKI operations. Not exploitable without an attacker-controlled iframe on the same page.

---

### LOW-1: innerHTML Used for Certificate List Population

**Severity:** LOW
**File:** `sdscript.js` (lines 594-604)
**Code:**
```javascript
SDCertListContainer.innerHTML = lstCert
    .map((cert) => {
        return `<div class="SignerDigitalExtCertItem" data-thumbprint="${cert.CertThumbprint}">
            <strong style="color: blue;">${cert.CertName}</strong>
            ...
        </div>`;
    }).join("");
```
**Analysis:** Certificate data from the native host is inserted into the DOM via `innerHTML` without sanitization. If the native host returned malicious certificate metadata (e.g., a crafted CertName containing script tags), this could lead to XSS in the page context. However, the native host is a locally installed trusted application, so this is a theoretical rather than practical concern.

**Verdict:** Low risk. The data source (native host) is locally controlled.

---

### LOW-2: Content Script Injected on All Frames Including file:// URLs

**Severity:** LOW
**File:** `manifest.json` (lines 13-17)
**Code:**
```json
"content_scripts": [{
    "all_frames": true,
    "js": ["content.js"],
    "matches": ["*://*/*", "file:///*"]
}]
```
**Analysis:** The content script and its injected API run on every frame of every page, including local file:// URLs. This is a broad injection surface. However, the extension needs this to function on government and enterprise PKI sites. The actual operations are gated through the native messaging host.

**Verdict:** Broad but necessary for the extension's purpose.

## False Positive Table

| Pattern | Location | Reason |
|---------|----------|--------|
| `innerHTML` assignment in cert list | `sdscript.js:594` | Data sourced from trusted local native host, not remote/untrusted input |
| `insertAdjacentHTML` for CSS/HTML injection | `content.js:56,64` | Loading extension's own bundled HTML/CSS resources, not remote content |
| `document.createElement('script')` injection | `content.js:77` | Injecting extension's own `sdscript.js` from `chrome.runtime.getURL` |
| `window.postMessage` calls | `content.js:47`, `sdscript.js:150` | Standard pattern for content-script-to-page communication bridge |

## API Endpoints Table

| Endpoint / Domain | Purpose | Context |
|-------------------|---------|---------|
| `signer.digital.chrome.host` (native messaging) | All cryptographic operations | Native messaging host connection |
| `https://downloads.signer.digital/` | Host installer download link | Shown in popup.html |
| `https://web.signer.digital` | Demo/developer reference links | Shown in popup.html |
| `https://signer.digital/signerdigitalbrowserextensions/` | About page link | Shown in popup.html |
| `https://clients2.google.com/service/update2/crx` | Chrome auto-update | Standard CWS update URL |

No runtime network requests are made by the extension itself. All cryptographic operations are delegated to the native host via `chrome.runtime.connectNative`.

## Data Flow Summary

1. **Web page** calls `SignerDigital.signHash()` (or other API method) which is exposed globally via injected `sdscript.js`
2. `sdscript.js` creates a message with action, nonce, and origin, posts it via `window.postMessage`
3. **Content script** (`content.js`) receives the postMessage, filters by `src === "user_page.js"`, forwards to background via `chrome.runtime.sendMessage`
4. **Background script** (`background.js`) relays the message to the native host via `port.postMessage`
5. **Native host** (`signer.digital.chrome.host`) performs the cryptographic operation and responds
6. **Background script** receives the response and sends it to the active tab's content script via `chrome.tabs.sendMessage`
7. **Content script** posts the response back to the page via `window.postMessage(respFromHost, '*')`
8. `sdscript.js` resolves the stored promise by matching the nonce

No data is sent to any remote server by the extension. All sensitive operations (signing, encryption, certificate access) are handled by the locally installed native host application.

## Overall Risk: **CLEAN**

This extension is a legitimate PKI/digital signature bridge with ~3M users, primarily used for Indian government e-filing (GST, IT returns, IceGate customs) and enterprise PKI workflows. It has:

- **Minimal permissions**: Only `nativeMessaging` (no cookies, storage, webRequest, tabs, etc.)
- **No remote code loading**: All JS is bundled; no eval, no dynamic script fetching from remote servers
- **No telemetry or analytics**: No tracking SDKs, no data collection
- **No obfuscation**: Code is clean and readable
- **No network requests**: Extension makes zero HTTP/fetch requests; all work delegated to native host
- **Tight CSP**: `default-src 'none'; script-src-elem 'self'`
- **Site licensing gating**: Host v5+ requires user consent per-site before allowing cryptographic operations

The broad content script injection and `postMessage` wildcard patterns are inherent to the native messaging bridge architecture and represent acceptable design tradeoffs for this type of extension, not malicious intent.
