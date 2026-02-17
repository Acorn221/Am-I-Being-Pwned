# Vulnerability Report: FlashPlayer - SWF to HTML

## Metadata
- **Extension ID**: nodnmpgjlnclahkmgjiinfjklgbbgecg
- **Extension Name**: FlashPlayer - SWF to HTML
- **Version**: 0.3.2
- **Users**: ~60,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

FlashPlayer - SWF to HTML is a browser extension that enables users to run Adobe Flash (SWF) files using JavaScript-based emulators (Ruffle and SWF2JS). The extension detects SWF content on web pages and provides an interface to load it in a sandboxed player environment.

The extension contains one medium-severity vulnerability related to improper origin validation in postMessage handlers. However, the security impact is significantly mitigated by the use of sandbox CSP for the player iframe, which prevents JavaScript execution in the main context. The extension's core functionality is legitimate and necessary for its stated purpose. Overall risk is assessed as LOW due to the sandboxing architecture and the limited exploitability of the identified issue.

## Vulnerability Details

### 1. MEDIUM: Improper Origin Validation in postMessage Handlers

**Severity**: MEDIUM
**Files**: data/player/index.js:91, data/player/player.js:95
**CWE**: CWE-346 (Origin Validation Error)

**Description**:
The extension uses `window.addEventListener('message', ...)` and `window.onmessage` handlers without verifying the origin of incoming messages using the wildcard `'*'` when posting messages. This pattern appears in multiple locations:

1. In `data/player/index.js` (line 91): The handler receives messages without checking `event.origin`
2. In `data/player/player.js` (line 95): Similar pattern with no origin validation
3. Messages are posted with `postMessage(..., '*')` in multiple locations

**Evidence**:

```javascript
// data/player/index.js:91
window.addEventListener('message', e => {
  const request = e.data;
  if (request.method === 'fetch') {
    fetch(request.href).then(async r => {
      const content = await r.arrayBuffer();
      iframe.contentWindow.postMessage({
        content,
        type: r.headers.get('Content-Type')
      }, '*');
    })
  }
});
```

```javascript
// data/player/player.js:95
window.onmessage = e => {
  const request = e.data;
  if (!request) {
    return;
  }
  // Processes message without validating e.origin
  // Later sends with wildcard: top.postMessage({...}, '*')
};
```

**Verdict**:
While this is a classic postMessage vulnerability pattern, the security impact is significantly limited by the extension's architecture:

1. **Sandboxed Context**: The player runs in a sandboxed iframe (manifest.json line 34-36) with `sandbox.pages = ["/data/player/player.html"]`, which applies strict CSP preventing inline scripts and eval
2. **Limited Attack Surface**: The message handlers primarily facilitate fetch proxying for loading SWF files and don't expose sensitive data
3. **Message Structure**: The handlers check for specific properties (e.g., `request.method === 'fetch'`) providing some protection against arbitrary message injection
4. **No Sensitive Data Exposure**: The messages primarily contain SWF content and rendering parameters

However, this remains a vulnerability because:
- A malicious webpage could potentially send crafted messages to trigger unintended behavior
- The fetch proxy functionality could potentially be abused to make requests on behalf of the extension
- Best practice is always to validate message origins

## False Positives Analysis

The ext-analyzer flagged the extension as "obfuscated," but this is a false positive. The code includes:
1. **Webpack bundling**: The ruffle.js file (3,672 lines) is a webpack-bundled library, which is standard for JavaScript module bundling, not obfuscation
2. **Ruffle emulator**: The WASM files are legitimate Rust-compiled Flash emulators from the open-source Ruffle project, as evidenced by the cargo registry paths in the WASM analysis
3. **Standard minification**: The bundled code uses standard webpack patterns and is not intentionally obfuscated to hide malicious behavior

The WASM binaries are legitimate components:
- Size: ~12MB each (typical for a Flash runtime emulator)
- Contains Ruffle-specific strings and cargo build paths
- Used for legitimate Flash emulation functionality

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| webextension.org | Homepage/FAQ link | Version info, install/update reason | Low - informational only |
| webbrowsertools.com | Test Flash page link | None (user navigation) | Low - testing tool |
| SWF URLs (user-provided) | Fetch SWF content via proxy | SWF file requests with referer | Low - legitimate functionality |

The extension makes network requests to:
1. **User-specified SWF URLs**: Fetched through the extension's proxy mechanism to load Flash content
2. **Homepage (webextension.org)**: Opened on install/update for changelog (lines 298-323 in worker.js)
3. **Test page**: Opens webbrowsertools.com/test-flash-player when user clicks "Open Test Flash Page" menu

All network activity is user-initiated or for legitimate extension maintenance (FAQ/changelog).

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
While the extension has a postMessage origin validation vulnerability (MEDIUM severity), the overall risk is LOW because:

1. **Strong Sandboxing**: The player runs in a sandboxed iframe with strict CSP, preventing JavaScript code execution that could exploit the postMessage issue
2. **Legitimate Functionality**: The extension serves a genuine purpose (running legacy Flash content) and uses appropriate technology (Ruffle WASM emulator)
3. **No Data Exfiltration**: No evidence of collecting or transmitting user data beyond the stated functionality
4. **Limited Permissions**: While it has `<all_urls>` host permissions, these are necessary to detect and extract SWF content from web pages
5. **Open Source Components**: Uses the well-known open-source Ruffle Flash emulator
6. **User Control**: All Flash rendering is user-initiated (click to play)
7. **Minimal Background Activity**: The service worker only handles context menu creation and SWF detection coordination

**Recommendations**:
1. Add origin validation to all postMessage handlers by checking `event.origin`
2. Use a whitelist of allowed origins or validate that messages come from extension pages
3. Consider using a nonce-based message authentication scheme for critical operations

The extension is safe for users who need Flash emulation capabilities, but the developer should address the postMessage origin validation issue in a future update.
