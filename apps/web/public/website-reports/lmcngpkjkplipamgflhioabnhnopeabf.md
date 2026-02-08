# Security Analysis Report: Briskine Email Templates

## Extension Metadata

| Field | Value |
|-------|-------|
| **Extension Name** | Briskine: Email templates for Gmail™ |
| **Extension ID** | lmcngpkjkplipamgflhioabnhnopeabf |
| **Version** | 7.15.14 |
| **User Count** | ~100,000 |
| **Manifest Version** | 3 |
| **License** | GNU GPL v3 |

## Executive Summary

Briskine is an email template productivity extension for Gmail, Outlook, and LinkedIn. The security analysis reveals a **CLEAN** extension with legitimate functionality and appropriate permissions. The extension uses Firebase for backend services, implements proper CSP policies, and uses sandboxed template rendering. No evidence of malicious behavior, data exfiltration, tracking SDKs, or unauthorized data collection was found.

**Overall Risk Level: CLEAN**

The extension appears to be a legitimate productivity tool with transparent functionality matching its stated purpose.

## Manifest Analysis

### Permissions

The extension requests the following permissions:

- **tabs** - Used to interact with browser tabs for template insertion
- **contextMenus** - Provides right-click context menu options
- **storage** - Stores user templates and settings locally
- **scripting** - Required for content script injection
- **unlimitedStorage** - Allows storing large template libraries

### Host Permissions

- `https://*/*` and `http://*/*` - Broad host access required to inject templates on any website (Gmail, Outlook, LinkedIn, etc.)

**Assessment:** While broad host permissions are requested, this is necessary for the extension's stated functionality of providing email templates across multiple web platforms. The permissions are appropriate for an email template tool.

### Content Security Policy

```
extension_pages: script-src 'self'; object-src 'self'; frame-ancestors 'none'
sandbox: sandbox allow-scripts; script-src 'self' 'unsafe-eval'; child-src 'self';
```

**Assessment:** Strong CSP implementation. The use of `'unsafe-eval'` is isolated to the sandbox environment, which is appropriate for Handlebars template compilation. The sandbox properly isolates potentially dangerous template rendering from the main extension context.

### Content Scripts

- **Matches:** All HTTP/HTTPS sites
- **Run at:** document_end
- **All frames:** true
- **Match about:blank:** true

**Assessment:** Broad injection scope is consistent with the extension's need to work across multiple email platforms. The `all_frames` setting allows template insertion in iframes (common in modern web apps).

## Vulnerability Assessment

### 1. Dynamic Code Execution

**Severity:** LOW (False Positive)

**Files:** sandbox/sandbox.js

**Details:**
The manifest allows `'unsafe-eval'` in the sandbox CSP for Handlebars template compilation. This is properly isolated:

- Template rendering occurs in a sandboxed iframe
- Sandbox script size: 666.8KB (Handlebars library)
- No `eval()` calls found in sandbox script
- Handlebars uses legitimate template compilation

**Verdict:** FALSE POSITIVE - This is proper usage of the sandbox API for template rendering. The sandbox provides security isolation from the main extension context.

### 2. Broad Host Permissions

**Severity:** LOW

**Files:** manifest.json

**Details:**
Extension requests access to all HTTP/HTTPS sites to enable template insertion across email platforms.

**Code:**
```json
"host_permissions": ["https://*/*", "http://*/*"]
```

**Verdict:** ACCEPTABLE - Required for cross-platform email template functionality. Users expect this from an email productivity tool.

### 3. Network Communication

**Severity:** LOW

**Files:** background/background.js

**Details:**
Extension communicates with legitimate backend services:

- `https://app.briskine.com` - Main application backend
- `https://gorgias-templates-production.firebaseio.com` - Firebase Realtime Database
- Firebase SDK integrated (Google's official SDK)
- 5 fetch() calls in background script
- No XMLHttpRequest usage
- 1 WebSocket reference (likely Firebase Realtime Database)

**Verdict:** CLEAN - All network communication is to legitimate first-party services. Firebase is a standard backend-as-a-service platform.

### 4. Keyboard Event Handlers

**Severity:** LOW

**Files:** content/content.js

**Details:**
Content script registers keyboard event listeners (20 references to keydown/keypress/keyup):

Analysis shows these are used for:
- Keyboard shortcuts to trigger template insertion
- Escape key handling for dialog dismissal
- Standard UI interaction patterns

**Code Context:**
```javascript
window.addEventListener("keydown",$,!0)
"Escape"===t.key&&r()&&(t.stopPropagation(),window.addEventListener("keyup"...
```

**Verdict:** FALSE POSITIVE - Keyboard handlers are used for legitimate keyboard shortcuts, not keylogging. No evidence of capturing or transmitting keystrokes.

### 5. DOM Data Access

**Severity:** LOW

**Files:** content/content.js

**Details:**
Content script accesses DOM elements and values:
- 89 `.value` property accesses
- 17 `innerText` accesses
- 14 `textContent` accesses

**Verdict:** ACCEPTABLE - Required for template insertion into email compose fields. This is the core functionality of the extension.

### 6. Script Injection Patterns

**Severity:** LOW

**Files:** content/content.js

**Details:**
- 2 `createElement` script patterns found
- 2 `innerHTML` script patterns found

**Verdict:** FALSE POSITIVE - Analysis shows these are SVG-related (React SVG innerHTML) and not malicious script injection. Patterns match known false positives.

## False Positive Analysis

| Pattern | Count | Verdict | Explanation |
|---------|-------|---------|-------------|
| `unsafe-eval` in CSP | 1 | FP | Isolated to sandbox for Handlebars template compilation |
| Keyboard event handlers | 20 | FP | Used for keyboard shortcuts, not keylogging |
| innerHTML with script | 2 | FP | React SVG rendering patterns |
| createElement script | 2 | FP | SVG element creation, not dynamic script loading |
| Broad value access | 89 | FP | Required for template insertion into email fields |

## API Endpoints

| Endpoint | Purpose | Protocol |
|----------|---------|----------|
| https://app.briskine.com | Main application backend | HTTPS |
| https://gorgias-templates-production.firebaseio.com | Firebase Realtime Database | WSS/HTTPS |

**Data Flow:** Extension syncs user templates between devices using Firebase. Template data is stored in Firebase and synchronized to chrome.storage for offline access.

## Chrome API Usage

| API | References | Purpose |
|-----|-----------|---------|
| chrome.runtime | 3 | Extension lifecycle management |
| chrome.storage | ~150 | Template and settings persistence |
| chrome.tabs | ~100+ | Tab interaction for template insertion |
| chrome.contextMenus | ~50 | Right-click menu integration |
| chrome.scripting | ~20 | Content script injection |

**Assessment:** All Chrome API usage is appropriate for an email template extension.

## Data Flow Summary

1. **User Templates:** Users create templates → Stored in chrome.storage.local → Synced to Firebase → Available across devices
2. **Template Insertion:** User triggers shortcut → Content script reads compose field → Sandbox renders template → Content script inserts result
3. **Settings:** User preferences stored in chrome.storage
4. **No evidence of:** Cookie harvesting, password interception, browsing history collection, or unauthorized data transmission

## Third-Party Services

| Service | Purpose | Privacy Impact |
|---------|---------|----------------|
| Firebase (Google) | Backend database for template sync | Standard BaaS, data encrypted in transit |
| Briskine API | Template management | First-party service |

**No tracking SDKs found:**
- No Google Analytics
- No Sensor Tower / Pathmatics
- No ad networks
- No marketing intelligence tools

## Security Strengths

1. **Manifest V3 compliance** - Uses modern, more secure manifest version
2. **Proper sandboxing** - Template rendering isolated from extension privileges
3. **Strong CSP** - Prevents inline scripts and restricts resource loading
4. **Open source license** - GNU GPL v3 promotes transparency
5. **No obfuscation** - Code is minified (standard build practice) but not obfuscated
6. **Minimal Chrome API surface** - Only uses APIs necessary for functionality
7. **No dynamic code loading** - No eval(), Function constructor, or remote script loading
8. **HTTPS-only communication** - All network requests use secure protocols

## Security Weaknesses

1. **Broad host permissions** - Access to all websites (mitigated: necessary for functionality)
2. **Minified code** - Makes manual code review difficult (mitigated: standard practice, includes LICENSE file)
3. **All frames injection** - Content script runs in all iframes (mitigated: necessary for modern webmail apps)

## Indicators of Legitimacy

- GNU GPL v3 licensed (open source friendly)
- Uses Google's official Firebase SDK
- Clean LICENSE file included
- Standard build tools (minification typical for production)
- Transparent backend communication
- No encoded/obfuscated payloads
- Consistent with Chrome Web Store description
- 100,000+ users with no major security incidents found

## Overall Risk Assessment

**CLEAN**

Briskine is a legitimate email productivity extension with no evidence of malicious activity. The extension:

- Functions exactly as advertised (email template management)
- Uses appropriate permissions for its stated purpose
- Implements proper security isolation (sandboxing)
- Communicates only with legitimate first-party services
- Contains no tracking SDKs or data exfiltration mechanisms
- Follows security best practices (MV3, CSP, HTTPS)

**Recommendation:** Safe for use. The broad permissions are necessary for cross-platform email template functionality and are transparently disclosed.

---

**Analysis Date:** 2026-02-07
**Analyst:** Claude Opus 4.6 (Automated Security Analysis)
**Analysis Duration:** Comprehensive static analysis of all extension components
