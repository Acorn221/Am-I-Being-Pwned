# Security Analysis Report: Group Speed Dial

## Metadata

- **Extension Name:** Group Speed Dial
- **Extension ID:** imfeikbeimbfpmgfkkmjekabdehiiajc
- **User Count:** ~50,000
- **Analysis Date:** 2026-02-07
- **Manifest Version:** 3

## Executive Summary

Group Speed Dial is a legitimate new tab replacement extension developed by Juraj Mäsiar (a recognized "Friend of Add-ons" by Mozilla). The extension provides speed dial functionality with cloud synchronization, end-to-end encryption, and premium features. After comprehensive analysis, **no malicious behavior or critical security vulnerabilities were identified**. The extension follows security best practices, implements proper encryption for user data, and only uses its extensive permissions for legitimate functionality.

## Vulnerability Details

### CLEAN - No Critical or High Severity Issues Found

The extension demonstrates good security practices:

1. **Encryption Implementation**: Uses Web Crypto API for end-to-end encryption with proper key derivation (PBKDF2)
2. **Content Script Isolation**: Only injects content scripts on the developer's own domain (`group-speed-dial.fastaddons.com`) for legitimate web integration
3. **Permission Usage**: Extensive permissions (`<all_urls>`, `webRequest`, `scripting`) are used exclusively for legitimate speed dial features (thumbnail generation, tab management, screenshot capture)
4. **No Remote Code Execution**: No dynamic code evaluation or remote script loading detected
5. **No Data Exfiltration**: Network requests are limited to the developer's infrastructure and documented APIs
6. **Open Source**: Project is open source on GitHub (fastaddons/GroupSpeedDial) with transparent privacy policy

## False Positive Analysis

| Pattern | Location | Verdict | Reason |
|---------|----------|---------|--------|
| `Function("return this")()` | 432.js:2083, 2367 | FALSE POSITIVE | Standard polyfill pattern to detect global object in different environments (window/self/global) |
| `document.evaluate` XPath | edit_single_dial.js:278, background_gsd.worker.js:2952 | FALSE POSITIVE | User-configurable XPath selectors for custom thumbnail capture feature |
| `chrome.scripting.executeScript` | Multiple files | FALSE POSITIVE | Legitimate use for thumbnail generation, screenshot capture, and web page automation features |
| `postMessage` communication | content_scripts/content_script.js, dial.js | FALSE POSITIVE | Secure communication between content script and web page for cloud sync feature (origin-verified to `group-speed-dial.fastaddons.com`) |
| Proxy objects | background.loader.js:1 | FALSE POSITIVE | Service worker polyfill to handle `document`/`window` access in worker context |
| `eval` reference | browser-polyfill.min.js:221 | FALSE POSITIVE | Mozilla's webextension-polyfill library defining eval-related properties |

## API Endpoints & Network Traffic

| Endpoint | Purpose | Security Notes |
|----------|---------|----------------|
| `https://group-speed-dial.fastaddons.com/*` | Cloud sync, shared groups, authentication | Developer-owned domain, content script only injected here |
| `https://img.fastaddons.com/fav/?d=` | Favicon fetching service | CDN for website icons |
| `https://www.google.com/s2/favicons?sz=64&domain=` | Google favicon API | Public fallback for favicons |
| `https://picsum.photos/*` | Random background images | Public service for placeholder backgrounds |

All network requests are to documented, legitimate services. No suspicious third-party tracking or analytics SDKs detected.

## Data Flow Summary

1. **Local Storage**: User data (speed dials, groups, settings) stored in browser's IndexedDB
2. **Optional Cloud Sync**: End-to-end encrypted sync to `group-speed-dial.fastaddons.com` using Web Crypto API
3. **Encryption Flow**:
   - User password → PBKDF2 derivation → AES-GCM encryption
   - Encrypted data stored both locally and (optionally) on cloud
   - Master password never transmitted; only encrypted payloads sent to server
4. **Content Script**: Limited to developer's domain for web-based settings interface integration

## Permission Justification

| Permission | Usage |
|------------|-------|
| `<all_urls>` | Screenshot/thumbnail capture for any website added to speed dial |
| `webRequest` | Monitor navigation for productivity mode (block distracting sites) |
| `declarativeNetRequestWithHostAccess` | Productivity mode blocking rules |
| `scripting` | Inject scripts for thumbnail generation and screenshot capture |
| `tabs` | Tab management (open, close, switch) for speed dial functionality |
| `storage` | Store user data locally |
| `bookmarks`, `topSites` (optional) | Import existing browser data |

All permissions are necessary and properly utilized for documented features.

## Overall Risk Assessment

**Risk Level: CLEAN**

**Justification:**
- Legitimate, open-source extension with transparent development
- Proper implementation of security features (encryption, CSP)
- No evidence of malicious behavior, tracking, or data harvesting
- Permissions used appropriately for advertised functionality
- Developer is a recognized contributor in the browser extension community
- Active maintenance and bug fixes on public GitHub repository

**Recommendations:**
- Extension is safe for use
- Users concerned about privacy can verify encryption implementation in the public source code
- Optional cloud sync can be disabled for fully local-only operation

## Conclusion

Group Speed Dial is a well-designed, security-conscious extension that poses no threat to users. The extensive permissions are justified by the feature set, and the implementation demonstrates security best practices including proper encryption, permission scoping, and transparent data handling.
