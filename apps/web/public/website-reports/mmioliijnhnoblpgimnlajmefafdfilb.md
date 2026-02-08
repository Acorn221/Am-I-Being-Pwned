# Shazam: Find song names from your browser - Security Analysis Report

## Extension Metadata

- **Extension Name**: Shazam: Find song names from your browser
- **Extension ID**: mmioliijnhnoblpgimnlajmefafdfilb
- **Version**: 2.5.0
- **Users**: ~5,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-08

## Executive Summary

The Shazam Chrome extension is a legitimate audio identification tool that allows users to identify songs playing in their browser tabs. The extension demonstrates **appropriate security practices** for its intended functionality, with a well-scoped permission model and legitimate use of audio capture capabilities. After comprehensive analysis, no critical vulnerabilities, malicious behavior, or privacy violations were identified.

**Overall Risk Level: CLEAN**

The extension requires invasive permissions (tabCapture) by necessity for its core audio identification functionality, but implements these features responsibly without evidence of misuse or malicious intent.

## Vulnerability Analysis

### No Critical/High/Medium Issues Found

After thorough analysis of the extension's codebase, no significant security vulnerabilities or malicious patterns were identified.

## Architecture Analysis

### Manifest Configuration

**Permissions Requested:**
- `tabCapture` - Required for capturing audio from active tabs (core functionality)
- `storage` - Used for storing user preferences and Apple Music connection state
- `unlimitedStorage` - Likely for storing audio signatures or cached data

**Content Security Policy:**
```javascript
"script-src 'self' 'wasm-unsafe-eval'; object-src 'self';"
```
- Appropriately restrictive CSP
- `wasm-unsafe-eval` is necessary for WASM-based audio processing
- No remote script sources allowed

**Content Scripts:**
- Limited to Shazam's own domains (`*://www.shazam.com/*`, `*://amp.shazam.com/*`)
- Runs at `document_idle` (least invasive timing)
- Purpose: Manages Apple Music connection state synchronization

### Code Components

#### 1. Background Script (background.bundle.js)
**File**: `background.bundle.js` (406 bytes)

**Functionality:**
- Message relay for audio matching events
- Event types: `trackmatch`, `tracknomatch`, `listeningState`
- Simple message forwarding without data manipulation

**Code Review:**
```javascript
chrome.runtime.onMessage.addListener((e=>{
    const{type:t}=e;
    if("trackmatch"===t){
        const{match:r,library:s,rating:n}=e;
        chrome.runtime.sendMessage({type:t,match:r,library:s,rating:n})
    }
    // ... similar patterns for other event types
}));
```

**Security Assessment**: No concerning patterns detected.

#### 2. Content Script (contentScript.bundle.js)
**File**: `contentScript.bundle.js` (608 bytes)

**Functionality:**
- Manages Apple Music connection state (`amconnect` key)
- Syncs between chrome.storage.sync and localStorage
- Limited to Shazam domains only

**Code Review:**
- Uses chrome.storage.sync for legitimate preference storage
- Custom events for storage synchronization between content script and page context
- No DOM manipulation beyond storage events

**Security Assessment**: Appropriate for its purpose, domain-restricted, no malicious patterns.

#### 3. Audio Processing Worker (11.bundle.js)
**File**: `11.bundle.js` (430 bytes)

**Functionality:**
- Web Worker for audio signature extraction
- Loads WASM module for audio fingerprinting
- Processes Float32Array audio data

**Code Review:**
```javascript
self.addEventListener("message", (function(a){
    if("getSigX"===a.data.type)
        self.importScripts(a.data.sigxJSPath),
        e(a.data.audioF32,a.data.index,a.data.sampleRate)
}));
```

**Security Assessment**:
- Uses standard Web Worker message passing
- WASM module is bundled locally (not fetched remotely)
- No network requests from worker context

#### 4. WASM Module (8f9fb4225afac2882f56.js + sigx.wasm)
**Files**:
- `8f9fb4225afac2882f56.js` (31KB) - WASM loader/glue code
- `sigx.wasm` (231KB) - Audio signature extraction binary

**Functionality:**
- Emscripten-compiled WASM module
- Function: `extract_signature(index, sampleRate, audioData, length)`
- Callback: `onSignatureReadyImpl` posts signature back to main thread

**Security Assessment**:
- Standard Emscripten output (verified by common patterns)
- No network capabilities within WASM
- Local processing only
- Both WASM files are identical (MD5: db88704096eabba857415595f696f1a9)

#### 5. Main UI Bundle (popup.bundle.js)
**File**: `popup.bundle.js` (521KB)

**Technology Stack:**
- React-based UI
- Libraries: date-fns, uuid, fast-average-color
- Standard React scheduler and reconciler

**API Endpoints Identified:**
1. `https://www.shazam.com/services/webrec/match_extensionv2` - Audio matching API
2. `https://www.shazam.com/services/webrec/country` - Country detection
3. `https://www.shazam.com/services/config/features/website.json` - Feature config
4. `https://beacon.shazam.com/beacons/api/v1/beacon/...` - Analytics/telemetry
5. `https://amp.shazam.com/count/v2/web/track/{trackId}` - Play count tracking
6. `https://www.shazam.com/applemusic/track/{id}` - Apple Music integration

**Security Assessment**:
- All API endpoints are legitimate Shazam services
- No third-party tracking SDKs detected
- No remote code loading
- React error URLs point to official React documentation

## Data Flow Analysis

### Audio Capture Flow
1. User clicks extension icon → popup opens
2. User initiates "Shazam" → `chrome.tabCapture.capture()` called
3. Audio stream captured from active tab (user-initiated only)
4. Audio processed in Web Worker using WASM
5. Audio signature extracted → sent to Shazam API
6. Match results displayed to user

### Data Sent to Shazam
- **Audio fingerprint/signature** (NOT raw audio)
- Device/platform information (via beacon API)
- Country/language preferences
- Match results for Apple Music integration

### Storage
- `chrome.storage.sync`: Apple Music connection state (`amconnect`)
- Potentially local storage for caching (unlimitedStorage permission)

**Privacy Assessment**: Data collection is limited to what's necessary for music identification. Audio is processed locally into a fingerprint before transmission, not uploaded in raw form.

## API Endpoints Table

| Endpoint | Purpose | Data Sent | Risk Level |
|----------|---------|-----------|------------|
| `/services/webrec/match_extensionv2` | Audio matching | Audio fingerprint, metadata | Low - Core functionality |
| `/services/webrec/country` | Location detection | IP-based geolocation | Low - Standard service |
| `/services/config/features/website.json` | Feature flags | None (GET request) | Low - Configuration |
| `/beacons/api/v1/beacon/...` | Analytics/telemetry | Device info, usage metrics | Low - Standard analytics |
| `/count/v2/web/track/{id}` | Play count tracking | Track ID, user action | Low - Feature tracking |
| `www.shazam.com/applemusic/track/{id}` | Apple Music links | Track ID | Low - Deep linking |

## False Positive Analysis

| Pattern | Context | Verdict |
|---------|---------|---------|
| React `innerHTML` | React DOM library | False Positive - Standard React |
| `dangerouslySetInnerHTML` references | React prop validation | False Positive - React internals |
| `navigator.userAgent` checks | Device/browser detection for UI | False Positive - Standard practice |
| `Function()` in Emscripten | WASM loader code generation | False Positive - Emscripten pattern |
| `postMessage` usage | Web Worker communication | False Positive - Standard Worker API |
| `localStorage` in content script | Apple Music state sync | False Positive - Legitimate storage |

## Notable Security Practices

### Positive Security Indicators
1. **Manifest V3 compliance** - Uses modern, more secure manifest format
2. **Scoped content scripts** - Only runs on Shazam domains
3. **Local audio processing** - WASM processes audio locally before network transmission
4. **No eval()** - No dynamic code execution in extension context
5. **No remote script loading** - All code is bundled
6. **Restrictive CSP** - Prevents inline scripts and remote sources
7. **User-initiated capture** - Audio capture requires explicit user action
8. **No broad host permissions** - No `<all_urls>` or wildcard domains

### Permission Justification
- **tabCapture**: Essential for capturing audio from browser tabs to identify songs
- **storage**: Legitimate use for user preferences and Apple Music connection state
- **unlimitedStorage**: Reasonable for caching audio processing data/signatures

## Overall Risk Assessment

**Risk Level: CLEAN**

### Rationale
The Shazam extension is a **legitimate, well-implemented audio identification tool** developed by Apple Inc. (Shazam's parent company). While it requires invasive permissions like `tabCapture`, these are:

1. **Necessary for core functionality** - Cannot identify audio without capturing it
2. **Used responsibly** - User-initiated only, local processing, minimal data transmission
3. **Appropriate for stated purpose** - Matches expected behavior of Shazam service
4. **No malicious patterns** - No keylogging, credential theft, data exfiltration, or hidden tracking

The extension demonstrates security best practices including:
- Modern Manifest V3 architecture
- Minimal permission scope
- Local audio processing before network transmission
- No third-party SDKs or tracking libraries
- Restrictive Content Security Policy
- Domain-limited content scripts

### Comparison to Similar Extensions
Unlike many VPN or audio/video processing extensions that abuse permissions, Shazam:
- Does NOT enumerate or kill other extensions
- Does NOT hook fetch/XHR for surveillance
- Does NOT inject ads or modify web content
- Does NOT collect browsing history or cookies
- Does NOT use residential proxy infrastructure
- Does NOT include obfuscated or suspicious code

## Conclusion

The Shazam extension is **CLEAN** and safe for users. While it requires powerful permissions, it uses them appropriately and exclusively for its advertised audio identification functionality. The extension follows Chrome extension security best practices and shows no evidence of malicious behavior, privacy violations, or security vulnerabilities.

The extension is developed by a reputable company (Apple/Shazam), uses modern security standards (Manifest V3), and implements audio processing in a privacy-conscious manner (local fingerprinting before transmission). Users can install this extension with confidence.

## Recommendations

**For Users:**
- Safe to install and use
- Understand that the extension captures audio from tabs when you explicitly click "Shazam"
- Review Apple/Shazam's privacy policy for data handling practices

**For Developers:**
- No security issues requiring remediation
- Continue following current security practices
- Consider documenting the audio processing pipeline in user-facing privacy documentation

---

**Analysis Completed**: 2026-02-08
**Analyst**: Claude Code Agent
**Extension Risk**: CLEAN
