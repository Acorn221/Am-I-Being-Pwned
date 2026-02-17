# Vulnerability Report: OCR - Image Reader

## Metadata
- **Extension ID**: bhbhjjkcoghibhibegcmbomkbakkpdbo
- **Extension Name**: OCR - Image Reader
- **Version**: 0.5.0
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

"OCR - Image Reader" is a legitimate optical character recognition extension that allows users to capture portions of web pages and extract text using Tesseract.js. The extension uses WASM for OCR processing and downloads language training data from tessdata.projectnaptha.com. While the core functionality is benign, the extension has a minor security issue related to postMessage communication without origin validation. Additionally, it includes an optional feature allowing users to POST OCR results to arbitrary endpoints, which is user-configured rather than a privacy concern.

The extension follows standard patterns for OCR tools, injects content scripts only when activated, and operates primarily through user interaction. The CSP includes 'wasm-unsafe-eval' which is necessary for WebAssembly execution.

## Vulnerability Details

### 1. LOW: postMessage Without Origin Validation

**Severity**: LOW
**Files**: worker.js (lines 42-47, 64-68), sandbox.js (line 74-77)
**CWE**: CWE-345 (Insufficient Verification of Data Authenticity)

**Description**:
The extension uses postMessage with wildcard origin ('*') in multiple locations. In worker.js, when injecting the OCR iframe, the background script posts messages to the iframe without origin verification:

```javascript
e.contentWindow.postMessage({
  method: 'proceed',
  href,
  request
}, '*');
```

Similarly, in sandbox.js, the message listener accepts messages without validating the origin:

```javascript
onmessage = e => {
  if (e.data && e.data.method === 'proceed') {
    service.run(e.data);
  }
};
```

**Evidence**:
From worker.js (lines 42-47):
```javascript
f.contentWindow.postMessage({
  method: 'proceed',
  href,
  request
}, '*');
```

From worker.js (lines 64-68):
```javascript
e.contentWindow.postMessage({
  method: 'proceed',
  href,
  request
}, '*');
```

**Verdict**:
While this is a security weakness, the impact is limited because:
1. The iframe is created by the extension itself (chrome-extension:// URL)
2. The messages contain screenshot data and coordinates, not sensitive user data
3. The iframe is injected into the page DOM with a unique class name
4. The communication is between extension pages, not with external origins

However, a malicious script on the host page could potentially intercept or send forged messages. The risk is low given the limited sensitive data being transmitted.

## False Positives Analysis

**User-Configured POST Endpoint**: The extension allows users to configure a POST/GET/PUT endpoint to send OCR results (via elements.js, lines 574-647). This is an optional feature requiring explicit user configuration through a prompt dialog. This is NOT data exfiltration but a legitimate integration feature. The default value is empty, and users must manually enter server details. The extension even uses 'no-cors' mode for these requests, limiting potential abuse.

**Obfuscated Flag**: The static analyzer flagged this extension as "obfuscated," but this is a false positive. The extension uses bundled Tesseract.js and ONNX transformer libraries, which are legitimately minified third-party dependencies, not intentionally obfuscated malware code. The main extension code (worker.js, inject.js, etc.) is clean and readable.

**WASM Usage**: The CSP includes 'wasm-unsafe-eval' which ext-analyzer flags. This is necessary and appropriate for Tesseract OCR processing using WebAssembly.

**Web Accessible Resources**: The extension exposes two HTML pages (data/engine/index.html, data/inject/sandbox.html) to <all_urls>. This is required for the OCR UI iframe injection functionality and is not a vulnerability in this context.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://tessdata.projectnaptha.com/ | Download OCR language training data files (.traineddata.gz) | None (GET requests only) | None - Legitimate CDN for Tesseract language models |
| https://github.com/naptha/tessdata/ | Fallback source for language training data | None (GET requests only) | None - Official Tesseract repository fallback |
| https://webextension.org/listing/ocr.html | Homepage/FAQ page | Extension version, install/update type | Low - Standard telemetry on install/update |
| User-configured endpoint (optional) | POST OCR results if user enables | OCR text, page URL (only if user configures) | Low - Explicit user configuration, disabled by default |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
This is a legitimate OCR extension with appropriate permissions for its functionality. The only security concern is the use of postMessage without origin validation, which poses minimal risk in this context given the internal nature of the communication. The extension does not collect user data, has no hardcoded analytics endpoints beyond the standard install/update homepage redirect, and operates entirely on-demand through user interaction. The user-configurable POST feature is transparent and requires explicit setup.

The extension's permissions are justified:
- `activeTab`, `scripting` - Required to inject OCR capture UI and screenshot pages
- `storage`, `unlimitedStorage` - Used for caching language training data and user preferences
- `notifications` - For error messages
- `clipboardWrite` (optional) - For copying OCR results

The host permissions are limited to downloading OCR language models from legitimate sources. The extension follows manifest v3 best practices and uses a service worker architecture.

**Recommendation**: The extension is safe for use. The postMessage origin validation should be improved in future versions, but the current risk is minimal.
