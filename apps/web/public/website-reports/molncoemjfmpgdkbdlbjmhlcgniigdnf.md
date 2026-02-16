# Vulnerability Report: Project Naptha

## Metadata
- **Extension ID**: molncoemjfmpgdkbdlbjmhlcgniigdnf
- **Extension Name**: Project Naptha
- **Version**: 0.9.7
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Project Naptha is an OCR (Optical Character Recognition) extension that allows users to highlight, copy, edit, and translate text from images on the web. The extension uses WASM-based OCR engines (Tesseract and OCRAD) to perform client-side text recognition. The extension has been migrated to Manifest V3 with appropriate service worker architecture.

The code analysis reveals a legitimate productivity tool with no evidence of malicious intent. While the static analyzer flagged WASM usage and eval() calls, these are part of the emscripten-compiled OCRAD library and represent standard practice for porting C/C++ libraries to JavaScript. The extension does communicate with backend services for lookup functionality, but does not exfiltrate sensitive user data.

## Vulnerability Details

### 1. LOW: CSP Allows wasm-unsafe-eval

**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-1095 (Loop Condition Value Update within the Loop)
**Description**: The Content Security Policy for extension pages includes `'wasm-unsafe-eval'` which is required for WebAssembly execution but slightly reduces defense-in-depth protections.

**Evidence**:
```json
"content_security_policy": {
  "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'"
}
```

**Verdict**: This is a necessary and appropriate use of `wasm-unsafe-eval` for WASM-based OCR libraries. Not a security issue for this extension type.

### 2. BENIGN: eval() in Emscripten-compiled Code

**Severity**: INFORMATIONAL
**Files**: ocrad-worker.js
**CWE**: N/A
**Description**: The OCRAD worker contains eval() calls that are part of the emscripten runtime for executing asm.js/WebAssembly code.

**Evidence**:
```javascript
// ocrad-worker.js line 88
eval("if (typeof gc === 'function' && gc.toString().indexOf('[native code]') > 0) var gc = undefined");

// ocrad-worker.js line 396
return Runtime.asmConstCache[code] = eval('(function(' + args.join(',') + '){ ' + Pointer_stringify(code) + ' })');
```

**Verdict**: These are standard emscripten runtime patterns for compiling C++ OCR libraries to JavaScript. This is not a vulnerability in the context of this extension.

## False Positives Analysis

1. **WASM Flag**: The static analyzer correctly identifies WASM usage, but this is the intended and documented functionality of the extension (OCR processing).

2. **Obfuscated Flag**: While the analyzer flagged the code as obfuscated, this is actually emscripten-compiled code from the OCRAD library, which naturally produces complex JavaScript. The deobfuscated source is well-structured and readable.

3. **eval() Usage**: All eval() calls are contained within the emscripten runtime for the OCRAD library. The extension's own code does not use eval() dynamically.

4. **clipboard_read/clipboard_write**: These are legitimate clipboard operations required for the extension's core OCR functionality (copying recognized text from images).

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://sky-lighter.appspot.com/api/ | OCR API root | OCR metadata/lookup | LOW |
| https://ssl.projectnaptha.com/lookup | Pre-lookup service | Region identifiers | LOW |
| http://projectnaptha.com/process/ | Documentation link | None (reference only) | NONE |

The endpoints appear to be for auxiliary OCR services (likely for cloud-assisted recognition or model lookups). The extension generates a random user_id stored in chrome.storage.sync but this appears to be for settings synchronization rather than tracking.

**Key Observations**:
- User ID generation is random (not tied to browsing data)
- No browsing history, cookies, or sensitive data sent to endpoints
- OCR processing happens client-side using WASM workers
- Clipboard operations are user-initiated (when copying recognized text)

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

Project Naptha is a legitimate OCR productivity extension with no evidence of malicious behavior. The flagged concerns (WASM, eval, CSP) are all legitimate requirements for client-side OCR processing using compiled C++ libraries.

The extension:
- Does not collect or exfiltrate sensitive user data
- Processes images locally using WASM-based OCR
- Uses standard Chrome APIs appropriately (clipboard, storage, TTS)
- Has been properly migrated to Manifest V3
- Communicates with backend services only for OCR lookup/API functions

The minor LOW rating is due to the broad `<all_urls>` permission and backend communication, but given the extension's stated purpose (recognizing text in any image on any page), these permissions are justified and disclosed.

**Recommendation**: CLEAN for users who need OCR functionality, with the understanding that the extension injects content scripts on all pages to detect and process images.
