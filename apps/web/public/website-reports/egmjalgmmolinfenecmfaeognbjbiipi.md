# Vulnerability Report: Convert WebP to PNG / JPG

## Metadata
- **Extension ID**: egmjalgmmolinfenecmfaeognbjbiipi
- **Extension Name**: Convert WebP to PNG / JPG
- **Version**: 3.0.17
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Convert WebP to PNG / JPG is an image conversion extension that allows users to convert WebP images to other formats (PNG, JPG, GIF, TIFF, ICO) using a context menu and drag-and-drop interface. The extension uses WebAssembly (ImageMagick) for local image processing, which is a legitimate privacy-preserving approach. However, the extension includes a paywall system hosted on external domains (onlineapp.pro) that restricts features based on user geography and usage count. The extension contains medium-severity security vulnerabilities including postMessage handlers without origin validation and automatic geolocation tracking without explicit user consent.

The extension's core functionality appears legitimate - converting images locally using WASM. However, the implementation includes concerning patterns around monetization and feature restriction based on geographic location.

## Vulnerability Details

### 1. MEDIUM: postMessage Handler Without Origin Validation

**Severity**: MEDIUM
**Files**: assets/worker-DrZl3vXI.js:61, assets/paywall-Bxti8igg.js:1
**CWE**: CWE-346 (Origin Validation Error)
**Description**: The extension registers window message event listeners without proper origin validation before processing messages. While the paywall code does check origins in some cases, the initial message handlers in worker-DrZl3vXI.js do not validate the message source.

**Evidence**:
```javascript
// In paywall-Bxti8igg.js, line 13:
window.addEventListener("message", this._globalEventHandler.bind(this), !1)

// In _globalEventHandler (lines 27-34):
_globalEventHandler: function(a) {
  let t = this._paywallDocumentRoot.getElementById("paywall-".concat(this.paywallId));
  if (a.source === t?.contentWindow)
    for (let [n, i] of(a.data.type === "change-styles" ? Object.assign(t.style, {
        ...a.data.style,
        ...this._overrideStyles || {}
      }) : a.data.type === "redirect" ? window.open(a.data.redirectUrl) :
      a.data.type === "remove" && t.remove(), this._eventHandlers)) i(a)
}
```

The origin check happens only after the source comparison, and the static analyzer flagged handlers in worker-DrZl3vXI.js without origin validation.

**Verdict**: While some origin checks exist, the incomplete validation pattern could allow malicious frames to inject messages. The risk is reduced by the fact that messages are processed based on iframe source comparison, but this is not as secure as explicit origin whitelisting before any message processing.

### 2. MEDIUM: Undisclosed Geolocation Tracking

**Severity**: MEDIUM
**Files**: assets/index.ts-CKVDYBtc.js:4355-4377
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension automatically fetches the user's country code from a remote endpoint (getcountry.cloudsearch.workers.dev) without explicit user consent or disclosure in the extension's privacy policy. This data is used to determine feature restrictions based on a hardcoded list of countries.

**Evidence**:
```javascript
async function qe() {
  if (!await tr()) try {
    const t = await fetch("https://getcountry.cloudsearch.workers.dev/", {
      signal: AbortSignal.timeout(1e4)
    });
    if (!t.ok) throw new Error(`HTTP error! status: ${t.status}`);
    const e = await t.text();
    if (!e.length || e.length > 5 || !/^[A-Za-z]+$/.test(e))
      throw new Error(`Invalid country code received: ${e}`);
    await chrome.storage.local.set({
      userCountry: e.toUpperCase()
    })
  } catch (t) {
    console.log("Failed to fetch user country:", t),
    await chrome.storage.local.set({
      userCountry: "RU"
    })
  }
}

// Usage in context menu handler (lines 4441-4444):
const { convertedCount: i, userCountry: r } = await Ht(), { state: a } = await ds(["state"]);
Qe.includes(r) && i >= $e && !a?.purchase_status && a?.purchase_status !== "paid" ? ps() : sr(s)
```

The extension checks if the user's country is in a specific list (Xs = ["AU", "AT", "BE", "CA", "CZ", "DK", "FI", "FR", "DE", "IS", "IE", "IT", "LU", "NL", "NZ", "NO", "PL", "PT", "SI", "ES", "SE", "CH", "GB", "US"]) and restricts features after 10 conversions (qs = 10) for users in those countries.

**Verdict**: This is a privacy concern. While the geolocation is inferred server-side and only the country code is returned, this automatic tracking without user consent or clear disclosure is problematic. Users in certain countries are subjected to artificial usage limits and paywall prompts.

### 3. LOW: CSP Allows wasm-unsafe-eval

**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-1188 (Insecure Default Initialization of Resource)
**Description**: The Content Security Policy includes 'wasm-unsafe-eval' which is required for WASM execution but reduces security boundaries.

**Evidence**:
```json
"content_security_policy": {
  "extension_pages": "script-src 'self' 'wasm-unsafe-eval' http://localhost; object-src 'self';"
}
```

**Verdict**: This is a necessary CSP directive for WASM functionality (ImageMagick), but it does weaken security. Given the extension's legitimate use case (image conversion via WASM), this is acceptable but worth noting. The inclusion of `http://localhost` in development suggests this may have been overlooked for production.

## False Positives Analysis

### Static Analyzer Flags

1. **WASM Flag**: The extension uses a 15MB WASM file (magick-B_KU7dU3.wasm) which is the ImageMagick library for image conversion. This is legitimate for the extension's stated purpose and processing happens locally, which is actually privacy-preserving.

2. **Obfuscated Flag**: The code appears to be bundled/minified by a build tool (likely Vite based on the asset naming pattern), not intentionally obfuscated for malicious purposes.

3. **Attack Surface - Message Handlers**: While the static analyzer correctly flagged postMessage handlers, the actual security impact is MEDIUM not HIGH because there is some source validation (though incomplete).

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| getcountry.cloudsearch.workers.dev | Fetch user country code | IP address (implicit in HTTP request) | MEDIUM - Tracking without consent |
| onlineapp.pro/paywall/* | Paywall iframe and authentication | User state, purchase status | MEDIUM - Third-party tracking via iframe |
| onlineapp.live | Alternative paywall domain | Same as above | MEDIUM - Multiple domains for same service |
| onlineapp.stream | Alternative paywall domain | Same as above | MEDIUM - Multiple domains for same service |
| chrome-extensions.tilda.ws/webp-to-png | Extension homepage | None (redirect only) | LOW - Information disclosure |
| docs.google.com/forms | Feedback form | User-initiated feedback | LOW - Legitimate use |
| chromewebstore.google.com | Extension reviews page | None (redirect only) | LOW - Legitimate use |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

The extension's core functionality (local image conversion using WebAssembly/ImageMagick) is legitimate and privacy-preserving. However, the implementation includes problematic patterns:

1. **Geographic Discrimination**: The extension implements region-based feature restrictions by automatically fetching the user's country without consent. Users in wealthy countries (US, EU, etc.) are limited to 10 free conversions before being prompted with a paywall, while users in other regions get unlimited access. This is disclosed nowhere in the extension description.

2. **Incomplete Origin Validation**: postMessage handlers exist without complete origin validation, creating potential for message injection attacks, though the risk is somewhat mitigated by source checks.

3. **Third-Party Paywall Integration**: The extension loads iframes from multiple external domains (onlineapp.pro/live/stream) for monetization, which enables cross-site tracking and data collection by a third party.

4. **Excessive Host Permissions**: The extension requests `<all_urls>` permission but only needs to access image URLs that users explicitly right-click. This is overly broad for the stated functionality.

The extension is not malicious, but it employs deceptive practices around feature restrictions and lacks transparency about geolocation tracking. The security vulnerabilities are real but not critical. Users should be aware that their usage is tracked and restricted based on geographic location, and that a third-party paywall service is integrated into the extension.

**Recommendation**: The extension should disclose geolocation tracking in its privacy policy, implement proper origin validation for all message handlers, and explain the geographic-based usage restrictions in its store description.
