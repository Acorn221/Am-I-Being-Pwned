# Vulnerability Report: Violentmonkey

## Metadata
- **Extension ID**: jinjaccalgkegednnccohejagnlnfdag
- **Extension Name**: Violentmonkey
- **Version**: 2.33.0
- **Users**: ~700,000
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

Violentmonkey is a legitimate and well-known userscript manager extension that allows users to install and run custom JavaScript code on web pages. While the extension itself is not malicious, its core functionality inherently creates significant security risks. The extension requests extremely powerful permissions including `<all_urls>` host access, `webRequest`/`webRequestBlocking`, and `cookies`, which it uses to inject arbitrary user-provided scripts into all websites. The extension provides a complete API (GM_* functions) that enables userscripts to perform XMLHttpRequests, access cookies, manipulate clipboard, and execute dynamic code with eval/Function constructors.

The primary security concern is not with Violentmonkey's code itself, but with the attack surface it creates: if a user installs a malicious userscript (deliberately or inadvertently), that script gains the ability to exfiltrate sensitive data, hijack sessions, perform credential theft, or conduct other attacks on any website the user visits. The extension's webpack-bundled code includes dynamic code execution patterns that are necessary for its legitimate operation as a userscript manager.

## Vulnerability Details

### 1. MEDIUM: Arbitrary Code Execution on All Websites
**Severity**: MEDIUM
**Files**: background/index.js, injected.js, injected-web.js
**CWE**: CWE-94 (Improper Control of Generation of Code)
**Description**: Violentmonkey's core functionality is to inject and execute arbitrary user-provided JavaScript code on all websites (`<all_urls>`). The extension implements comprehensive code injection infrastructure including:
- Content scripts that run at `document_start` on all frames
- Background script message handlers that coordinate script execution
- Dynamic eval/Function usage to execute userscript code
- Cross-context communication between page and content script contexts

**Evidence**:
```javascript
// injected.js - minified but shows eval/Function patterns
function(e,t,n){const o={__proto__:null},r=this,{window:l}=r
// Dynamic code execution infrastructure throughout

// manifest.json - broad permissions
"content_scripts": [{
  "js": ["injected-web.js", "injected.js"],
  "matches": ["<all_urls>"],
  "run_at": "document_start",
  "all_frames": true
}]
```

**Verdict**: This is EXPECTED and LEGITIMATE behavior for a userscript manager. However, it creates medium risk because malicious userscripts installed by users can exploit this infrastructure to conduct attacks. The extension itself appears to be properly implementing userscript manager functionality without hidden malicious behavior.

### 2. MEDIUM: Comprehensive Data Access Capabilities
**Severity**: MEDIUM
**Files**: background/index.js, manifest.json
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension requests broad permissions that enable userscripts to access sensitive browser data:
- `cookies` permission allows reading/writing cookies on all domains
- `webRequest` + `webRequestBlocking` enables request interception
- `clipboardWrite` for clipboard manipulation
- `tabs` for tab enumeration and control
- `storage` + `unlimitedStorage` for persistent data storage

**Evidence**:
```json
"permissions": [
  "tabs",
  "<all_urls>",
  "webRequest",
  "webRequestBlocking",
  "notifications",
  "storage",
  "unlimitedStorage",
  "clipboardWrite",
  "contextMenus",
  "cookies"
]
```

**Verdict**: These permissions are necessary for userscript manager functionality (e.g., GM_xmlhttpRequest, GM_cookie APIs, GM_setClipboard). However, they enable powerful capabilities that malicious userscripts can abuse. The risk is MEDIUM because the extension legitimately requires these permissions, but users must trust both Violentmonkey and every userscript they install.

### 3. LOW: Webpack Bundled Code Obfuscation
**Severity**: LOW
**Files**: All main JavaScript files
**CWE**: CWE-656 (Reliance on Security Through Obscurity)
**Description**: The extension's JavaScript files are webpack-bundled and minified, making manual code review difficult. The static analyzer flagged the code as "obfuscated," though this appears to be standard webpack bundling rather than intentional malicious obfuscation.

**Evidence**:
Static analyzer output shows: `Flags: obfuscated`

Files like `injected.js` and `background/index.js` are single-line minified bundles with short variable names.

**Verdict**: This is LOW risk and EXPECTED for modern JavaScript projects using build tools. The extension is open source (https://violentmonkey.github.io/), allowing independent verification of the source code. The bundling/minification is for performance and size optimization, not malicious obfuscation.

## False Positives Analysis

The static analyzer reported "obfuscated" code, which is accurate in terms of readability but not indicative of malicious intent. Modern JavaScript extensions commonly use webpack/rollup bundling with minification for:
- Reduced file size and faster loading
- Module bundling from source code
- Tree shaking and optimization

The dynamic code execution patterns (eval, Function, executeScript) detected are NOT false positives - they are genuinely present in the code. However, for a userscript manager, these patterns are EXPECTED and NECESSARY functionality, not vulnerabilities in Violentmonkey itself.

Cookie access, webRequest interception, and other powerful capabilities are also expected features that userscript managers must provide to support the GM_* API specification.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://violentmonkey.github.io/ | Official homepage/documentation | None from extension | LOW - Informational only |
| https://clients2.google.com/service/update2/crx | Chrome Web Store update mechanism | Extension version info | LOW - Standard CWS updates |
| User-configured endpoints | Userscript update URLs, GM_xmlhttpRequest targets | Controlled by installed userscripts | MEDIUM-HIGH - Depends on userscripts |

The extension itself does not hardcode any data exfiltration endpoints. Network activity is driven by:
1. User-installed userscripts making GM_xmlhttpRequest calls
2. Automatic userscript update checks (to URLs specified in userscript metadata)
3. Standard Chrome Web Store update checks

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

Violentmonkey is a **legitimate userscript manager** with no evidence of malicious behavior in its own code. The MEDIUM risk classification reflects the inherent security implications of its purpose:

**Why MEDIUM, not HIGH:**
- The extension is a well-known, open-source project with 700,000 users
- No hidden data exfiltration, credential theft, or backdoors detected
- All powerful capabilities are disclosed and necessary for userscript management
- Users install the extension specifically to run custom scripts

**Why MEDIUM, not LOW/CLEAN:**
- Creates significant attack surface through arbitrary code execution on all URLs
- Malicious userscripts can leverage full browser API access
- Permissions enable cookie theft, request interception, session hijacking
- Users may not fully understand risks when installing untrusted userscripts
- No built-in sandboxing or security review of installed userscripts

**Security Recommendations for Users:**
1. Only install userscripts from trusted sources
2. Review userscript code before installation when possible
3. Be aware that userscripts have full access to website data
4. Keep Violentmonkey updated to receive security patches
5. Understand that userscripts can perform actions with your credentials
6. Consider using separate browser profiles for sensitive activities

**Conclusion**: Violentmonkey is a tool, and like any powerful tool, it can be used safely or dangerously. The extension itself appears properly designed and implemented, but users bear responsibility for the security of the userscripts they choose to install.
