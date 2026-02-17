# Vulnerability Report: Convert HEIC to JPG

## Metadata
- **Extension ID**: giendkofjkgpomkagbpkeimknkmfadgh
- **Extension Name**: Convert HEIC to JPG
- **Version**: 1.5.3
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

"Convert HEIC to JPG" is an image format converter that transforms HEIC images to various formats (JPG, PNG, GIF, TIFF, BMP, ICO, WEBP). The extension uses ImageMagick WASM (14MB) for local image processing and integrates with a commercial paywall service (onlineapp.pro). While the extension's core functionality appears legitimate, it contains medium-severity security issues related to postMessage handling without proper origin validation and a broad externally_connectable configuration.

The extension collects user analytics (country, user ID, install/update events) and communicates with external paywall infrastructure. All image processing occurs locally via WASM, which aligns with the privacy-first claims in the extension description.

## Vulnerability Details

### 1. MEDIUM: Unsafe postMessage Event Handlers

**Severity**: MEDIUM
**Files**: wall.2.1.1.js:13, assets/worker-0NUZNp8D.js:45
**CWE**: CWE-346 (Origin Validation Error)

**Description**: The extension implements multiple `window.addEventListener("message")` handlers without validating the origin of incoming messages. This creates a potential attack surface where malicious websites could send crafted messages to manipulate the extension's behavior.

**Evidence**:
```javascript
// wall.2.1.1.js:13
_globalEventHandler: function (e) {
  if (!this._iframeCreated) return;
  let a = this._paywallDocumentRoot.getElementById('paywall-'.concat(this._paywallId));
  if (e.source === (null == a ? void 0 : a.contentWindow)) for (let [,n] of (
    'change-styles' === e.data.type ? Object.assign(a.style, {...e.data.style, ...this._overrideStyles || {}})
    : 'redirect' === e.data.type ? window.open(e.data.redirectUrl)
    : 'remove' === e.data.type && a.remove(), this._eventHandlers))n(e);
}
```

The handler only checks if the source matches the iframe's contentWindow, but does not validate `e.origin`. While the iframe is loaded from `onlineapp.pro`, a malicious site could potentially exploit timing issues or race conditions.

**Verdict**: The paywall implementation does check the sender URL in later handlers (lines 34, 40), but the initial message listeners lack origin validation. This is a medium-risk issue as exploitation would require specific timing and conditions.

### 2. MEDIUM: Broad externally_connectable Configuration

**Severity**: MEDIUM
**Files**: manifest.json
**CWE**: CWE-923 (Improper Restriction of Communication Channel to Intended Endpoints)

**Description**: The extension allows external connections from three domains via `externally_connectable`:
- `https://onlineapp.pro/*`
- `https://onlineapp.stream/*`
- `https://onlineapp.live/*`

**Evidence**:
```json
"externally_connectable": {
  "matches": [
    "https://onlineapp.pro/*",
    "https://onlineapp.stream/*",
    "https://onlineapp.live/*"
  ]
}
```

The background script implements handlers for external connections:
```javascript
// background.js:13822-13838
vt.runtime.onConnectExternal.addListener(r => {
  r.sender?.url && (
    r.sender.url.includes("onlineapp.pro") ||
    r.sender.url.includes("onlineapp.live") ||
    r.sender.url.includes("onlineapp.stream")
  ) ? (f.add(r), r.onDisconnect.addListener(() => {
    f.delete(r)
  })) : (console.warn("Connection attempt from unauthorized domain:", r.sender?.url), r.disconnect())
})
```

The external message handler provides storage access to these domains:
```javascript
// background.js:13845-13869
case "getItem":
  const { key: s } = r.data;
  return vt.storage.sync.get(s, c => {
    if (vt.runtime.lastError) {
      console.error("Storage error:", l);
      n({ status: "error", message: l })
    } else n({ status: "success", value: c[s] || null })
  }), !0
```

**Verdict**: While the extension validates sender URLs, the broad wildcard paths (`/*`) on three domains expands the attack surface. If any of these domains are compromised or host user-generated content, they could interact with the extension. The storage access is limited to sync storage for authentication purposes (Supabase auth adapter), which mitigates some risk.

### 3. LOW: Content Security Policy with wasm-unsafe-eval

**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-1021 (Improper Restriction of Rendered UI Layers or Frames)

**Description**: The extension's CSP includes `'wasm-unsafe-eval'` which is required for WASM execution but slightly weakens the security boundary.

**Evidence**:
```json
"content_security_policy": {
  "extension_pages": "script-src 'self' 'wasm-unsafe-eval' http://localhost; object-src 'self';"
}
```

**Verdict**: This is acceptable given the legitimate use of a 14MB ImageMagick WASM module for image processing. The extension also includes `http://localhost` which suggests development/debugging capabilities but poses minimal risk in production. The use of WASM for client-side image processing aligns with the privacy-focused approach.

## False Positives Analysis

**WASM Usage**: The ext-analyzer flagged WASM as "high risk" due to it being an "unknown WASM in service worker". However, analysis of the binary strings confirms this is the legitimate ImageMagick library (references to "ImageMagick Version", image codecs, BMP headers, TIFF processing, etc.). This is NOT malicious.

**Network Requests**: The extension makes network requests to:
1. `getcountry.cloudsearch.workers.dev` - Fetches user country code (falls back to "RU" on failure)
2. `onlineapp.pro/api/track-event` - Analytics tracking (install, update events with user ID and extension ID)

These are disclosed functionality for localization and analytics, not hidden data exfiltration.

**Paywall Integration**: The integration with onlineapp.pro is a legitimate commercial paywall service for monetization. The extension acts as a client to this service and does not implement any deceptive practices.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| getcountry.cloudsearch.workers.dev | Geolocation | None (returns country code) | LOW |
| onlineapp.pro/api/track-event | Analytics | event name, wallId, extensionId, userId | LOW |
| onlineapp.pro/api/v1/paywall/{id}/user | Get user info | Authentication credentials via iframe | MEDIUM |
| onlineapp.pro/api/signout | Sign out | Authentication credentials | LOW |
| onlineapp.live/* | Paywall service | User authentication state | MEDIUM |
| onlineapp.stream/* | Paywall service | User authentication state | MEDIUM |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

The extension provides legitimate HEIC image conversion functionality using client-side WASM processing (ImageMagick), which aligns with its privacy claims. However, it contains two medium-severity vulnerabilities:

1. **Unsafe postMessage handling** - Message listeners lack proper origin validation, creating potential attack surface
2. **Broad externally_connectable configuration** - Three domains with wildcard paths can interact with the extension, with storage access granted to Supabase authentication adapter

The extension integrates with a commercial paywall service (onlineapp.pro) for monetization, which introduces additional trust dependencies. Analytics collection (country, user ID, events) is standard for commercial software but should be disclosed to users.

**Recommendations**:
- Add explicit origin validation to all postMessage handlers
- Restrict externally_connectable paths to specific endpoints rather than wildcards
- Document the data collection and third-party service dependencies in the privacy policy
- Consider removing `http://localhost` from CSP in production builds

The core image processing functionality is sound and privacy-preserving. The security issues are fixable and do not indicate malicious intent, but they do represent legitimate attack surface that should be addressed.
