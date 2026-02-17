# Security Analysis: Ruffle - Flash Emulator (donbcfbmhbcapadipfkeojnmajbakjdc)

## Extension Metadata
- **Name**: Ruffle - Flash Emulator
- **Extension ID**: donbcfbmhbcapadipfkeojnmajbakjdc
- **Version**: 0.2.0.26039 (nightly 2026.2.8)
- **Manifest Version**: 3
- **Estimated Users**: ~1,000,000
- **Developer**: Ruffle (ruffle.rs)
- **Homepage**: https://ruffle.rs/
- **GitHub**: https://github.com/ruffle-rs/ruffle
- **Analysis Date**: 2026-02-14

## Executive Summary
Ruffle is the **LEGITIMATE** open-source Flash emulator project. This extension automatically replaces Flash content on websites with the Ruffle WebAssembly-based Flash player. Analysis confirms this is the authentic Ruffle extension distributed by the official Ruffle project, with expected permissions, architecture, and code patterns for a Flash emulator. The flags raised by automated analysis (WASM, unsafe-eval CSP, obfuscation) are **all expected and required** for Flash emulation functionality.

**Overall Risk Assessment: CLEAN**

## Verification of Authenticity

### 1. Official Project Confirmation
**Evidence**:
- Homepage URL in manifest: `https://ruffle.rs/` (official project website)
- README.md in `/dist/` references official Chrome Web Store and Firefox Add-ons listings
- License files: Apache 2.0 and MIT dual license (standard for Ruffle)
- GitHub references throughout code: `https://github.com/ruffle-rs/ruffle`
- Official WASM filenames: `ruffle_web_bg.wasm` (13 MB) and `ruffle_web-wasm_mvp_bg.wasm` (14 MB)

**Verified Contents**:
- Extension is signed by Chrome Web Store with verified publisher signatures
- Code structure matches open-source Ruffle architecture (Rust → WASM + TypeScript/JavaScript wrapper)

**Conclusion**: This is the **authentic** Ruffle extension, not a trojan or impersonator.

---

## Analysis of Flagged Items (All Expected)

### 1. WASM (WebAssembly) - EXPECTED
**Severity**: N/A (Required Feature)
**Files**:
- `/dist/assets/ruffle_web_bg.wasm` (13 MB)
- `/dist/assets/ruffle_web-wasm_mvp_bg.wasm` (14 MB)

**Analysis**:
Ruffle is a Flash Player emulator written in Rust and compiled to WebAssembly. WASM is the **core technology** that makes Ruffle work - it contains the entire Flash runtime implementation.

**Why WASM is Required**:
- Flash emulation requires complex runtime logic (ActionScript VM, rendering engine, etc.)
- Rust provides memory safety and performance needed for emulation
- WASM allows running Rust code in the browser at near-native speed
- The large file size (13-14 MB) is expected for a full Flash runtime implementation

**Code Evidence**:
```javascript
// From dist/482.js and dist/655.js - WASM loader code
module_or_path = fetch(module_or_path);
// WASM binding functions
__wbg_fetch_e6e8e0a221783759: function(arg0, arg1) {
    const ret = getObject(arg0).fetch(getObject(arg1));
}
```

**Verdict**: **NOT MALICIOUS** - WASM is fundamental to Ruffle's functionality.

---

### 2. CSP unsafe-eval (wasm-unsafe-eval) - EXPECTED
**Severity**: N/A (Required for WASM)
**Manifest CSP**:
```json
"content_security_policy": {
  "extension_pages": "default-src 'self'; script-src 'wasm-unsafe-eval' 'self'; style-src 'unsafe-inline'; connect-src *; media-src *; img-src data:;"
}
```

**Analysis**:
The `wasm-unsafe-eval` directive is **required** in Manifest V3 to load and execute WebAssembly modules. This is not the dangerous `'unsafe-eval'` that allows arbitrary JavaScript eval(), but a specific permission for WASM.

**Why This is Safe**:
- `wasm-unsafe-eval` only allows WASM instantiation, not JavaScript `eval()`
- This is the standard CSP for any legitimate WebAssembly-based extension
- Required by Chrome's security policy for WASM extensions
- Does not enable code injection or dynamic script execution

**Additional CSP Settings**:
- `connect-src *` - Required to load SWF files from any website being visited
- `media-src *` - Required for Flash content that includes audio/video
- `img-src data:` - Required for Flash graphics rendering
- `style-src 'unsafe-inline'` - Required for Ruffle's UI rendering

**Verdict**: **NOT MALICIOUS** - Standard and necessary CSP for WASM-based extensions.

---

### 3. Obfuscation - EXPECTED
**Analysis**:
The "obfuscation" flag is triggered by webpack bundling and WASM bindings. Examination of the code shows:

**Code Characteristics**:
- Clean, well-commented TypeScript enums and configuration objects
- Standard webpack bundle format with readable function names
- WASM binding functions (from wasm-bindgen) with auto-generated names like `__wbg_fetch_e6e8e0a221783759`
- Configuration objects like `AutoPlay`, `RenderBackend`, `WindowMode` with full documentation

**Example of Clean Code** (from dist/background.js):
```javascript
/**
 * Represents the various types of auto-play behaviours that are supported.
 */
var AutoPlay;
(function (AutoPlay) {
    AutoPlay["On"] = "on";
    AutoPlay["Off"] = "off";
    AutoPlay["Auto"] = "auto";
})(AutoPlay || (AutoPlay = {}));
```

**Verdict**: **NOT MALICIOUS** - Build artifacts from Rust→WASM compilation and webpack bundling, not deliberate obfuscation.

---

## Attack Surface Analysis (From ext-analyzer)

### CSP - extension_pages: 'unsafe-inline' (MEDIUM)
**Analysis**:
The `style-src 'unsafe-inline'` directive allows inline styles in extension pages (popup, options, player).

**Risk Assessment**:
- **Context**: Only applies to extension's own pages, not content scripts
- **Justification**: Required for Ruffle's dynamic UI rendering and player controls
- **Mitigation**: Extension pages are not injectable by third parties
- **Impact**: Low risk - no external content can exploit this

**Verdict**: **ACCEPTABLE** - Standard for extensions with dynamic UIs.

---

## Permissions Analysis

### Host Permissions: <all_urls>
**Justification**: Ruffle must run on all websites to detect and replace Flash content wherever it appears.

**Usage**:
- Content script injected at `document_start` to detect `<embed>` and `<object>` tags
- Replaces Flash player instances with Ruffle player before page renders
- Excludes known problematic domains (Twitch, TikTok, banking sites, etc.)

**Exclude Matches** (Good Security Practice):
```json
"exclude_matches": [
  "https://sso.godaddy.com/*",
  "https://authentication.td.com/*",
  "https://*.twitch.tv/*",
  "https://*.duosecurity.com/*",
  "https://*.tiktok.com/*"
]
```

**Verdict**: **JUSTIFIED** - Cannot function without broad host access.

### Permissions: scripting, storage, declarativeNetRequestWithHostAccess
**Analysis**:
- **scripting**: Required to inject Ruffle player into pages dynamically
- **storage**: Stores user preferences (autoplay settings, backend selection)
- **declarativeNetRequestWithHostAccess**: Modifies CORS headers for 4399.com (Chinese Flash game site)

**CORS Rule** (dist/4399_rules.json):
```json
{
  "condition": {
    "initiatorDomains": ["4399.com"],
    "urlFilter": "|*.swf",
    "resourceTypes": ["xmlhttprequest"]
  },
  "action": {
    "type": "modifyHeaders",
    "responseHeaders": [{
      "header": "Access-Control-Allow-Origin",
      "operation": "set",
      "value": "https://www.4399.com"
    }]
  }
}
```

**Purpose**: 4399.com is a major Chinese Flash games portal that requires CORS modification for cross-origin SWF loading.

**Verdict**: **JUSTIFIED** - All permissions have clear, legitimate uses.

---

## Web Accessible Resources
**Configuration**:
```json
"web_accessible_resources": [{
  "resources": ["*"],
  "matches": ["<all_urls>"]
}]
```

**Analysis**:
Makes all extension resources accessible to web pages. Required because:
- Ruffle WASM files must be loaded by injected player on web pages
- Player UI assets (CSS, SVG icons) must be accessible to embedded player
- Standard pattern for player/emulator extensions

**Risk**: Could allow fingerprinting of extension installation, but this is acceptable tradeoff for functionality.

**Verdict**: **JUSTIFIED** - Required for Ruffle player to load assets.

---

## Network Activity Analysis

### Endpoints Contacted
1. **ruffle.rs** (official website)
   - Hardware acceleration help link
   - Project documentation
   - No data transmission

2. **github.com/ruffle-rs** (source repository)
   - Issue reporting links
   - Wiki documentation
   - No automatic connections

**Data Exfiltration Check**: **NONE**
- No analytics, tracking, or telemetry
- No automatic network requests
- No data collection or transmission
- All network activity is user-initiated (clicking help links)

**Verdict**: **CLEAN** - No privacy concerns.

---

## Code Quality and Safety

### Background Script (dist/background.js)
**Functions**:
- Content script registration management
- Options storage management
- Onboarding page display
- Response header support detection

**Safety Indicators**:
- No eval(), Function(), or code generation
- No obfuscated strings or encoded payloads
- Clear error handling and permissions checks
- Uses standard Chrome extension APIs

### Content Script (dist/content.js)
**Functions**:
- Detects Flash content on pages
- Injects Ruffle player
- Negotiates with website-installed Ruffle instances (version selection)

**Safety Indicators**:
- Runs at `document_start` to catch Flash elements early
- Only modifies Flash-related DOM elements
- No page content scraping or data extraction

### Player Implementation (dist/ruffle.js, dist/player.js)
**Features**:
- Flash content rendering (via WASM runtime)
- User controls (play/pause, volume, fullscreen)
- Save state management (local storage only)
- Context menu with Ruffle branding

**Safety**:
- All Flash execution sandboxed in WASM
- LocalStorage used for save states (no external sync)
- No external script loading

---

## Vulnerability Assessment

### No Vulnerabilities Detected

**Critical**: 0
**High**: 0
**Medium**: 0
**Low**: 0

**Analysis Summary**:
- No hardcoded credentials
- No injection vulnerabilities
- No insecure data handling
- No unvalidated external input
- No dangerous postMessage usage
- No extension enumeration
- No malicious code patterns

---

## Comparison with Known Malicious Patterns

**Trojan Check**: PASSED
- No fake version of legitimate software
- Official publisher signatures verified
- Code matches open-source repository structure
- No hidden malicious payloads

**Data Exfiltration Check**: PASSED
- No unauthorized data collection
- No tracking beacons
- No analytics services
- No C2 (command and control) infrastructure

**Permission Abuse Check**: PASSED
- All permissions have justified uses
- No excessive or unexplained permissions
- Follows principle of least privilege where possible

---

## Conclusion

**Risk Level: CLEAN**

Ruffle - Flash Emulator is a **legitimate, safe, and well-architected** browser extension. All potentially concerning flags (WASM, unsafe-eval CSP, broad permissions) are **expected and required** for Flash emulation functionality. The extension represents a significant open-source effort to preserve Flash content after Adobe Flash Player's end-of-life.

**Recommendation**: SAFE FOR USE

**Key Points**:
- Official Ruffle project extension
- Open-source with transparent development
- No malicious code or behaviors
- Privacy-respecting (no tracking or data collection)
- Technically necessary permissions and CSP directives
- High-quality codebase with proper error handling

**Note for Security Teams**: When analyzing emulator/player extensions, WASM usage and relaxed CSP policies are **expected** and should not automatically trigger alarms. Context matters - in this case, all potentially risky features are legitimate technical requirements for Flash emulation.

---

## Additional Information

### Flash Emulation Technology Stack
- **Core Runtime**: Rust (compiled to WASM)
- **Rendering**: WebGL/WebGPU/Canvas (selectable backends)
- **UI Framework**: Preact (React-like library)
- **Build System**: Webpack
- **Bundler**: wasm-pack (Rust→WASM)

### Version Information
- Extension version: 0.2.0.26039
- Version name: 0.2.0-nightly.2026.2.8
- Nightly build from February 8, 2026
- Matches official Ruffle release cadence

### User Trust Indicators
- 1,000,000+ users
- Available on official Chrome Web Store
- Also available on Firefox Add-ons
- Active development and maintenance
- Community-driven open-source project
- Sponsored by Internet Archive and others

---

**Analyst Notes**: This extension demonstrates that not all "concerning" patterns are malicious. Proper security analysis must consider:
1. **Context**: What is the extension supposed to do?
2. **Necessity**: Are risky features actually required?
3. **Transparency**: Is the code open-source and auditable?
4. **Reputation**: Is the developer trustworthy?

Ruffle passes all these checks with flying colors.
