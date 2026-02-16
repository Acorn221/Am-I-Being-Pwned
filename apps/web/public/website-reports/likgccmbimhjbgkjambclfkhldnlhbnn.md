# Vulnerability Report: Yomitan Popup Dictionary

## Metadata
- **Extension ID**: likgccmbimhjbgkjambclfkhldnlhbnn
- **Extension Name**: Yomitan Popup Dictionary
- **Version**: 26.1.19.0
- **Users**: Unknown (not provided)
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Yomitan is an open-source Japanese language learning extension that provides popup dictionary functionality. The extension has 81,604 lines of code and is a fork of the well-known Yomichan project. Static analysis identified multiple postMessage event listeners without origin validation, which could theoretically allow cross-frame attacks. However, manual code review reveals these handlers are part of an internal iframe-based template rendering system and cross-frame API that validates message sources against known iframe windows. The extension communicates with legitimate third-party dictionary services (Jisho.org, LanguagePod101) and local Anki installations for flashcard integration. The WASM binary (resvg.wasm) is a Rust-based SVG rendering library used for image processing. Overall, this is a legitimate, well-maintained language learning tool with no evidence of malicious behavior.

## Vulnerability Details

### 1. LOW: PostMessage Handlers Without Explicit Origin Validation

**Severity**: LOW
**Files**: js/templates/template-renderer-proxy.js, js/templates/template-renderer-frame-api.js, js/display/display.js, js/comm/frame-ancestry-handler.js, js/pages/settings/popup-preview-frame.js, js/dictionary/dictionary-worker-handler.js, js/dictionary/dictionary-database-worker-handler.js
**CWE**: CWE-346 (Origin Validation Error)
**Description**: The extension uses window.addEventListener("message") handlers without checking event.origin in the listener function signature. The static analyzer flagged 8 instances of this pattern.

**Evidence**:
```javascript
// js/templates/template-renderer-frame-api.js:41
window.addEventListener('message', this._onWindowMessage.bind(this), false);

_onWindowMessage(e) {
    const {source, data: {action, params, id}} = e;
    invokeApiMapHandler(this._windowMessageHandlers, action, params, [], (response) => {
        this._postMessage(/** @type {Window} */ (source), 'response', response, id);
    });
}
```

**Verdict**: While the handlers don't explicitly check `event.origin` as a string, they implement alternative validation:

1. **Source validation**: The code validates `e.source` matches expected iframe windows (e.g., `frame.contentWindow`)
2. **Structured messages**: Uses typed action/params structure that limits what can be triggered
3. **Internal communication**: These are internal cross-frame APIs between extension pages, not exposed to external websites
4. **Sandboxed contexts**: Some handlers run in sandboxed iframes with limited capabilities

Example of source validation from template-renderer-proxy.js:
```javascript
const onWindowMessage = (e) => {
    if ((state & 0x5) !== 0x1) { return; }
    const frameWindow = frame.contentWindow;
    if (frameWindow === null || frameWindow !== e.source) { return; }
    // Process message only if source matches iframe
}
```

This is a low-severity architectural concern rather than an exploitable vulnerability, as external websites cannot send postMessage to extension pages.

## False Positives Analysis

1. **WASM flagged as obfuscated**: The extension uses `lib/resvg.wasm` (2.4MB Rust binary) for SVG rendering. This is a legitimate, compiled Rust library, not obfuscated code. The CSP includes `'wasm-unsafe-eval'` specifically to allow WASM execution.

2. **unsafe-eval in CSP**: The sandbox CSP includes `'unsafe-eval'` which is required for Handlebars.js template rendering in the sandboxed iframe. This is isolated from the main extension context.

3. **Network access to various domains**: The extension legitimately connects to:
   - Dictionary services (jisho.org, languagepod101.com, wiktionary.org, lingua-libre.org)
   - Local Anki installation (127.0.0.1:8765)
   - Optional MeCab parser (127.0.0.1:19633)

   All external connections are user-initiated (clicking audio pronunciation buttons or looking up words).

4. **`<all_urls>` permission**: Required for the dictionary to work on any webpage the user is reading.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| assets.languagepod101.com/dictionary/japanese/audiomp3.php | Audio pronunciation | Word (kanji/kana) | Low - legitimate dictionary service |
| jisho.org | Word definitions | Search terms | Low - legitimate dictionary service |
| commons.wikimedia.org | Audio files via Lingua Libre | Word pronunciations | Low - Wikimedia CDN |
| en.wiktionary.org | Dictionary data | Search terms | Low - Wikimedia service |
| 127.0.0.1:8765 | AnkiConnect API | Flashcard data (user-configured) | Low - local application |
| 127.0.0.1:19633 | MeCab morphological parser | Japanese text | Low - optional local parser |

All external endpoints are well-known language learning services. No user browsing data or sensitive information is transmitted beyond search terms the user explicitly looks up.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**: Yomitan is a legitimate, open-source language learning extension with an active development community (GPL-3.0 licensed, fork of Yomichan). The postMessage handlers without explicit origin checks represent a theoretical architectural weakness but are mitigated by source validation and the fact that external pages cannot message extension contexts. The extension's permissions (`<all_urls>`, scripting, declarativeNetRequest) are appropriate for a dictionary that needs to inject lookup functionality on any webpage. Network connections are limited to legitimate dictionary APIs and local applications, all triggered by explicit user actions. The WASM binary is a standard SVG rendering library. No evidence of data exfiltration, credential theft, or other malicious behavior was found.

**Recommendation**: The extension is safe for general use. Users concerned about network requests can disable audio downloads in settings, though this would remove pronunciation features.
