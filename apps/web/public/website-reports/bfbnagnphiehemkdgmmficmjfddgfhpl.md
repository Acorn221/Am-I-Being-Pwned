# Vulnerability Report: UltraWideo

## Metadata
- **Extension ID**: bfbnagnphiehemkdgmmficmjfddgfhpl
- **Extension Name**: UltraWideo
- **Version**: 3.5.5
- **Users**: ~60,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

UltraWideo is a cross-browser extension that manipulates video aspect ratios to fit the entire screen. The extension provides three modes (Normal, Upscale, Stretch) with customizable scaling controls and additional features like ambient light effects. The extension includes a premium "Pro" tier with license management functionality hosted on uw.wtf.

Security analysis reveals the extension is largely benign with standard functionality expected for a video manipulation tool. The main security concern is a postMessage event listener without proper origin validation in the license management content script. The extension communicates only with its own website (uw.wtf) for license activation/deactivation purposes. Static analysis flagged one exfiltration flow involving document.querySelectorAll → fetch, which upon manual review is benign code for preloading module dependencies (Vue.js/Vite framework code), not actual data exfiltration.

## Vulnerability Details

### 1. LOW: postMessage Event Listener Without Origin Check

**Severity**: LOW
**Files**: content-scripts/license.js
**CWE**: CWE-346 (Origin Validation Error)

**Description**:
The license.js content script registers a postMessage event listener without validating the message origin before processing data. While the receive() function does check `t.origin !== o` (where `o` is "https://uw.wtf"), this pattern could be vulnerable if the origin check is bypassed or if there are edge cases in the validation logic.

**Evidence**:
```javascript
// content-scripts/license.js:626-629
receive(e) {
  window.addEventListener("message", t => {
    t.origin !== o || t.data.from !== "uw:web" || e(t.data)
  })
}
```

The code does include origin validation (`t.origin !== o` where `o = "https://uw.wtf"`), and also checks for a specific `from` property in the message data. However, the ext-analyzer flagged this as missing origin check, likely because the check format doesn't match standard patterns.

**Verdict**:
This is a LOW severity issue because:
1. The origin check IS present (validates against "https://uw.wtf")
2. The content script only runs on "https://uw.wtf/*" pages (see manifest matches)
3. The data exchanged is limited to license keys and review consent flags
4. No sensitive user data from other sites is involved
5. The message protocol uses a namespace ("uw:ext" and "uw:web") for additional validation

The static analyzer appears to have generated a false positive by not recognizing the validation pattern.

## False Positives Analysis

### Exfiltration Flow (document.querySelectorAll → fetch)
The static analyzer flagged an exfiltration flow in chunks/popup-C97Br_YZ.js. Manual code review reveals this is standard Vite/Vue.js framework code for module preloading:

```javascript
// chunks/popup-C97Br_YZ.js:5
for (const s of document.querySelectorAll('link[rel="modulepreload"]')) r(s);

// chunks/popup-C97Br_YZ.js:24
function r(s) {
  if (s.ep) return;
  s.ep = !0;
  const i = n(s);
  fetch(s.href, i)  // Fetching the module file itself
}
```

This code finds link elements with `rel="modulepreload"` and fetches them to preload JavaScript modules. The fetch target is `s.href` (the link's href attribute), not user data. This is legitimate framework functionality for performance optimization, not data exfiltration.

### Obfuscation Flag
The static analyzer flagged the extension as "obfuscated". Upon review, the code is webpack/Vite bundled with Vue.js framework code, which involves minification and module bundling. This is standard build tooling, not intentional obfuscation to hide malicious behavior. Variable names like `Vf`, `Hf`, `Ki` are artifacts of the minification process.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| uw.wtf | License management (activation/deactivation/validation) | License key, review consent preference | Low - legitimate premium feature backend |
| chromewebstore.google.com | Review/rating link generation | Extension ID (hardcoded) | None - read-only link generation |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

UltraWideo is a legitimate video aspect ratio manipulation extension with no significant security or privacy concerns. The extension's core functionality (modifying video element CSS) operates entirely client-side and does not exfiltrate browsing data or user information.

The only identified vulnerability is a postMessage handler that, while technically including origin validation, could be implemented more defensively. However, given the limited scope (only processes messages from uw.wtf, only handles license keys), the actual risk is minimal.

The extension's permissions are appropriate for its stated functionality:
- `storage`, `alarms`: Store user preferences and settings
- `tabs`: Detect fullscreen events and manage extension state
- `https://*/*`, `http://*/*`: Inject content scripts to manipulate video players on all sites

The license management system is transparent (hosted on the developer's website uw.wtf) and only handles license activation/deactivation flows, which is standard for premium extensions.

**Recommendation**: CLEAN with minor advisory note about postMessage validation pattern. The extension is safe for end users.
