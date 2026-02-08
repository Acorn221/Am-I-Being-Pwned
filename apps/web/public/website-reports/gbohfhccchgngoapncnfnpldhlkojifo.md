# Security Analysis Report: Beautiful Epub Reader

## Extension Metadata
- **Extension Name**: Beautiful Epub Reader
- **Extension ID**: gbohfhccchgngoapncnfnpldhlkojifo
- **Version**: 1.8.2
- **User Count**: ~60,000
- **Manifest Version**: 3
- **Author**: kska32@gmail.com

---

## Executive Summary

Beautiful Epub Reader is a legitimate ePub file reader extension with a licensing system that communicates with a remote API. The extension uses modern cryptographic libraries (jose/JWE) for license validation and includes Sentry error tracking SDK. While the extension contains several legitimate third-party libraries, the **license validation mechanism is currently non-functional** (returns null), and the extension appears to be clean of malicious behavior.

**Overall Risk: CLEAN**

The extension demonstrates good security practices including:
- Proper manifest v3 implementation
- Encrypted license communication using ECDH-ES and A256GCM
- No content scripts (no page interaction)
- Limited, appropriate permissions for an ePub reader
- No evidence of data exfiltration, tracking beyond error reporting, or malicious behavior

---

## Vulnerability Analysis

### 1. Disabled License Validation System
**Severity**: LOW (Informational)
**Files**: `background/index.js` (lines 10443-10445)
**Code**:
```javascript
async function Ro(e = null, t = "atlas") {
  return null
}
```

**Description**: The device info retrieval function `Ro()` always returns `null`, effectively disabling the entire license validation system. This means the license activation and refresh endpoints are never actually called in practice.

**Verdict**: NOT A VULNERABILITY - This appears to be intentional, possibly indicating the extension operates in a free/trial mode or the licensing system was disabled. No security risk.

---

### 2. Remote API Communication
**Severity**: LOW
**Files**: `background/index.js` (lines 10494, 10531)
**API Endpoints**:
```javascript
// License activation endpoint
"https://dev.beautifulepubreader.online/api/license/activate"

// License refresh endpoint
"https://dev.beautifulepubreader.online/api/license/refresh"
```

**Description**: The extension includes code to communicate with a license server for activation and refresh. However, due to the disabled `Ro()` function, these endpoints are never reached. The communication would be encrypted using ECDH-ES key agreement with A256GCM content encryption.

**Public Keys Used**:
```
Activation: MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIGnVTU8ZoTl3lssjyRqeUuWsxzYGGXKJLTdj3X0NocrOH17ZSBNBtv2CGEXhvwtxifQ1VpVFieWUfKng0D2LhA==

Verification: MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEX6Ad2S80xMl3QLh96Ha0YwYbduNkkXKmL2z/IfluEwv1nCuCnv7xsFSSSHviqDyOpc1+5K/g7HCC6OW5Ma9NPg==
```

**Verdict**: CLEAN - Proper encryption, never actually executed, no sensitive data transmitted.

---

### 3. Sentry Error Tracking
**Severity**: LOW (Informational)
**Files**: `home/index.js` (lines 29939+, 32323+)
**Code**:
```javascript
const pi = "__sentry_xhr_v3__";
// Sentry XHR instrumentation detected
t.__SENTRY__ = t.__SENTRY__ || {};
```

**Description**: The extension includes Sentry SDK for error tracking. XHR requests are instrumented to detect Sentry's own traffic (`"POST" === o && a.match(/sentry_key/)`). No DSN configuration found in deobfuscated code, suggesting either it's compiled into a different bundle or error reporting may be disabled.

**Verdict**: FALSE POSITIVE - Standard error tracking SDK, known FP per analysis guidelines.

---

### 4. declarativeNetRequest for File Redirection
**Severity**: LOW
**Files**: `background/index.js` (lines 10577-10594)
**Code**:
```javascript
chrome?.declarativeNetRequest?.updateDynamicRules({
  addRules: [{
    id: 198964,
    priority: 1,
    action: {
      type: "redirect",
      redirect: {
        regexSubstitution: `chrome-extension://${chrome.runtime.id}/home/index.html?url=\\0`
      }
    },
    condition: {
      regexFilter: "^file:.*\\.epub$",
      isUrlFilterCaseSensitive: !1,
      resourceTypes: ["main_frame"]
    }
  }],
  removeRuleIds: [198964]
})
```

**Description**: The extension uses declarativeNetRequest to redirect file:// URLs ending in .epub to its reader interface. This is the core functionality enabling the extension to open local ePub files.

**Verdict**: CLEAN - Legitimate use case for an ePub reader, requires `file://*` host permission which is declared.

---

## Permissions Analysis

### Declared Permissions
```json
"permissions": [
  "tts",              // Text-to-speech for reading aloud
  "storage",          // Local storage for settings and license data
  "fontSettings",     // Custom fonts for reading
  "declarativeNetRequest"  // File redirection for .epub files
],
"host_permissions": [
  "file://*"         // Access to local .epub files
]
```

**Assessment**: All permissions are appropriate for an ePub reader:
- `tts`: Read-aloud functionality
- `storage`: Storing user preferences and (unused) license data
- `fontSettings`: Customizing reading fonts
- `declarativeNetRequest`: Intercepting .epub file opens
- `file://*`: Required to read local ePub files

**Verdict**: CLEAN - Minimal, justified permissions.

---

## False Positives Table

| Pattern | Location | Reason |
|---------|----------|--------- |
| `Function()` constructor | background/index.js:4170, 4728 | Polyfill detection for generators, not dynamic code eval |
| `innerHTML` | home/index.js | React/rendering framework, safe usage |
| `XMLHttpRequest` instrumentation | home/index.js:32326+ | Sentry SDK hooks (known FP) |
| `__sentry_xhr_v3__` | home/index.js:32323 | Sentry error tracking SDK |
| `setTimeout/setInterval` | background/index.js:2685+, 10571 | Legitimate async operations (tab status polling) |
| Cryptographic functions | background/index.js:6-29 | PBKDF2, AES encryption libraries (CryptoJS) |
| ECDH-ES encryption | background/index.js:10400, 10489 | Jose library for JWE license encryption |

---

## API Endpoints Table

| Endpoint | Method | Purpose | Status |
|----------|--------|---------|--------|
| `https://dev.beautifulepubreader.online/api/license/activate` | POST | License activation | Unreachable (disabled) |
| `https://dev.beautifulepubreader.online/api/license/refresh` | POST | License refresh | Unreachable (disabled) |

**Note**: Both endpoints are never actually called due to `Ro()` returning null.

---

## Data Flow Summary

### Inbound Data
- Local .epub files via `file://*` permission
- User settings stored in chrome.storage.local
- (Hypothetical) License data from API - **NEVER EXECUTED**

### Outbound Data
- **None observed** - License API calls are disabled
- Potential Sentry error reports (no DSN found, likely disabled)

### Storage
- `chrome.storage.local`:
  - "refresh": License refresh attempt counter (max 3)
  - User preferences (fonts, themes, reading position - inferred from typical reader functionality)

### No Evidence Of
- ❌ Cookie harvesting
- ❌ Form data interception
- ❌ DOM manipulation on web pages (no content scripts)
- ❌ XHR/fetch hooking for malicious purposes
- ❌ Extension enumeration/killing
- ❌ Ad injection
- ❌ Tracker SDKs (Sensor Tower, Pathmatics, etc.)
- ❌ Residential proxy infrastructure
- ❌ AI conversation scraping
- ❌ Keylogging
- ❌ Clipboard access

---

## Code Quality Observations

### Positive Indicators
1. **Modern MV3**: Uses service worker background, declarativeNetRequest
2. **Strong Cryptography**: ECDH-ES + A256GCM for license data (jose library)
3. **No Content Scripts**: Cannot interact with web pages
4. **Scoped Functionality**: Only handles .epub files
5. **Error Handling**: Includes try-catch blocks around crypto operations

### Libraries Detected
- **CryptoJS**: PBKDF2, AES, HMAC implementations
- **jose**: JWE/JWT library for encrypted tokens
- **Sentry SDK**: Error tracking (likely disabled)
- **Dexie.js**: IndexedDB wrapper (for storing ePub data)
- **React**: UI framework for reader interface
- **Moment.js**: Date/time formatting with multiple locales

---

## Risk Assessment

### Overall Risk: **CLEAN**

**Justification**:
1. **No Active Network Connections**: License system is disabled, no actual API calls
2. **No Content Script Injection**: Cannot interact with web pages
3. **Appropriate Permissions**: All permissions justified for core functionality
4. **No Malicious Patterns**: No data exfiltration, tracking, or abuse detected
5. **Transparent Functionality**: Reads local ePub files and displays them
6. **Good Cryptography**: Uses industry-standard encryption (when enabled)

### Recommendation
- **Action**: No action required
- **User Impact**: Safe for general use
- **Monitoring**: None needed

---

## Conclusion

Beautiful Epub Reader is a legitimate Chrome extension for reading ePub files. The extension demonstrates good security practices including manifest v3 compliance, appropriate permission usage, and strong cryptography for its (currently disabled) license system. No malicious behavior, data exfiltration, or privacy concerns were identified during analysis. The extension is **CLEAN** and safe for users.

---

**Analysis Date**: 2026-02-07
**Analyst**: Claude Sonnet 4.5 (Automated Security Analysis)
**Report Version**: 1.0
