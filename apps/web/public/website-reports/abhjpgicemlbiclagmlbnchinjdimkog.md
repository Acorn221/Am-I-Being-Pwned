# Vulnerability Report: Text to Speech TTS AI | Readvox

## Metadata
- **Extension ID**: abhjpgicemlbiclagmlbnchinjdimkog
- **Extension Name**: Text to Speech TTS AI | Readvox
- **Version**: 3.22.7
- **Users**: ~50,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Readvox is a text-to-speech extension that reads web content aloud using natural, lifelike voices. The extension uses WebAssembly modules for speech synthesis (phonemizer and synthesizer) and includes OCR capabilities. It integrates with Supabase for backend services and implements Google Analytics 4 for usage tracking.

The extension exhibits standard behavior for a TTS application with minimal security concerns. While it has broad permissions and uses WASM modules, the static analysis and code review reveal legitimate functionality aligned with the extension's stated purpose. Two medium-severity issues were identified: postMessage handlers without origin validation in offscreen workers, and CSP allowing 'wasm-unsafe-eval'. However, these are acceptable design choices for this application architecture.

## Vulnerability Details

### 1. MEDIUM: PostMessage Handlers Without Origin Validation

**Severity**: MEDIUM
**Files**: src/offscreen/index.js, src/offscreen/workers/phonemizer/index.js, src/offscreen/workers/synthesizer/index.js
**CWE**: CWE-346 (Origin Validation Error)

**Description**: The extension uses offscreen workers for WASM-based speech processing. These workers implement postMessage handlers without explicit origin validation:

**Evidence**:
```javascript
// src/offscreen/index.js:2941
self.addEventListener("message", r), o

// src/offscreen/workers/phonemizer/index.js:96
self.addEventListener("message", t)

// src/offscreen/workers/synthesizer/index.js:96
self.addEventListener("message", r)
```

The static analyzer flagged these as high-risk findings:
```
[HIGH] window.addEventListener("message") without origin check    src/offscreen/index.js:2
[HIGH] window.addEventListener("message") without origin check    src/offscreen/workers/synthesizer/index.js:1
[HIGH] window.addEventListener("message") without origin check    src/offscreen/workers/phonemizer/index.js:1
```

**Verdict**: **Acceptable for this architecture**. The postMessage handlers are used for internal communication between the service worker and offscreen document workers (required for WASM execution in MV3). The offscreen API is isolated from web contexts and cannot be accessed by external origins. This is a standard pattern for MV3 extensions using WASM in offscreen documents. The messages are structured with type-checking and are not exposed to untrusted web content.

### 2. MEDIUM: Content Security Policy Allows 'wasm-unsafe-eval'

**Severity**: MEDIUM
**Files**: manifest.json
**CWE**: CWE-1188 (Insecure Default Initialization of Resource)

**Description**: The extension's CSP includes 'wasm-unsafe-eval' for extension pages:

**Evidence**:
```json
"content_security_policy": {
  "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self';"
}
```

The extension includes two large WASM modules:
- `src/offscreen/workers/phonemizer/lib/phonemize.wasm` (635 KB) - espeak-ng for phonemization
- `src/offscreen/workers/synthesizer/lib/ort-wasm-simd-threaded.wasm` (11 MB) - ONNX Runtime for TTS synthesis

**Verdict**: **Required for legitimate functionality**. The 'wasm-unsafe-eval' directive is necessary for instantiating WebAssembly modules. The extension uses WASM for:
1. Phonemization (converting text to phonemes using espeak-ng)
2. Neural TTS synthesis (ONNX Runtime with ML models)

The WASM modules are bundled with the extension and loaded from local sources only. This is a legitimate use case for text-to-speech processing that requires performance beyond what JavaScript can provide.

## False Positives Analysis

### WASM Obfuscation Flag
The static analyzer marked the extension as "obfuscated" due to the presence of WASM binaries. However, this is not malicious obfuscation but rather standard compilation of C/C++ libraries (espeak-ng and ONNX Runtime) to WebAssembly for performance-critical TTS operations.

### Network Activity
The extension makes network requests to several domains:
- `readvox.com` - installation tracking, notifications API, uninstall survey
- `speech-breaks.readvox.com` - fetching speech break audio samples (background music)
- `google-analytics.com` - standard GA4 analytics
- `pyglisjcmjonzikufyux.supabase.co` - Supabase backend for storage and authentication

All network activity is transparent and aligned with the extension's functionality. The analytics implementation is standard Google Analytics 4 with client_id, session_id, and event tracking. No sensitive user data is exfiltrated.

### React and Webpack
The extension uses React (visible in deobfuscated code) and is bundled with Webpack. The "bundled" appearance is not obfuscation but standard modern web development practices.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| readvox.com/installed | Post-install redirect | Extension version | Low - Standard onboarding |
| readvox.com/api/notifications | Feature announcements | None (GET request) | Low - Read-only notifications |
| speech-breaks.readvox.com/v1 | Background audio | None (GET random MP3) | Low - Public audio assets |
| google-analytics.com/mp/collect | Usage analytics | client_id, session_id, event names | Low - Standard analytics |
| pyglisjcmjonzikufyux.supabase.co | Backend services | User auth, storage (for premium features) | Low - Standard SaaS backend |

## Data Collection

The extension implements Google Analytics 4 tracking with the following structure:
```javascript
{
  client_id: e,
  events: [{
    name: r.name,
    params: {
      ...r.params,
      session_id: s,
      engagement_time_msec: 100,
    }
  }]
}
```

The GA4 measurement ID is `G-CVNXW8BGMH`. Event tracking is standard for understanding feature usage and does not capture sensitive page content or user input. The extension uses `chrome.storage.local` to persist GA client IDs and session IDs locally.

## Permissions Analysis

- **activeTab**: Required to inject content scripts and read page content for TTS
- **scripting**: Required for dynamic script injection in content contexts
- **storage**: Stores user preferences, voice settings, and analytics IDs
- **offscreen**: Required for WASM execution in MV3 (WASM cannot run in service workers)
- **unlimitedStorage**: Likely for caching TTS audio and ML models
- **system.cpu, system.memory**: Potentially used to optimize WASM performance based on system capabilities
- **contextMenus**: Adds right-click menu option to read selected text
- **<all_urls>**: Required to provide TTS functionality on any website

All permissions are justified for a text-to-speech extension that needs to read and process content from any webpage.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**: This is a legitimate text-to-speech extension with standard functionality and no evidence of malicious behavior. The two medium-severity findings are acceptable design choices for the extension's architecture:

1. **PostMessage without origin checks**: Standard pattern for offscreen worker communication in MV3 extensions, isolated from web contexts
2. **CSP 'wasm-unsafe-eval'**: Required for WASM-based speech synthesis, modules are bundled and loaded locally

The extension's network activity is transparent, analytics are standard industry practice, and permissions are appropriate for its stated functionality. The large WASM modules are legitimate libraries (espeak-ng and ONNX Runtime) used for high-quality text-to-speech synthesis. No data exfiltration, credential theft, or malicious code execution patterns were detected.

The extension serves its stated purpose (text-to-speech for web content) without engaging in deceptive or harmful practices.
