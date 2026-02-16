# Security Analysis Report: OneTab

## Extension Metadata

- **Extension Name**: OneTab
- **Extension ID**: chphlpgkkbolifaimnlloiipkdnihall
- **Version**: 2.4
- **Manifest Version**: 3
- **User Count**: ~2,000,000
- **Rating**: 4.5/5
- **Publisher**: OneTab Ltd.
- **Analysis Date**: 2026-02-14

## Executive Summary

OneTab is a **legitimate tab management extension** that helps users consolidate open tabs into a single list to reduce memory usage and organize browsing sessions. The extension stores tab data locally and offers an optional feature to share tab lists via www.one-tab.com.

**Overall Risk Level: CLEAN**

The static analyzer flagged 97 exfiltration flows and marked the code as "obfuscated," which initially suggested high risk. However, deep analysis reveals:

1. All 97 flows are **legitimate tab-sharing features** where users explicitly opt-in
2. The "obfuscation" is actually **code concatenation/minification**, not malicious obfuscation
3. The extension only communicates with www.one-tab.com (its own domain), and only when the user grants optional permissions
4. No analytics, tracking, credential harvesting, or third-party data sharing detected
5. Strong Content Security Policy prevents code injection attacks

The extension is well-established with 2 million users and serves its stated purpose without privacy violations.

## Vulnerability Details

### False Positives Analysis

#### 1. "97 Exfiltration Flows" - All Legitimate

**Severity**: None (False Positive)
**Files**: All 8 concatenated source files
**CWE**: N/A

**Evidence**:
The static analyzer detected 97 flows of `chrome.tabs.query/get → fetch/img.src(www.one-tab.com)`. Analysis shows:

```javascript
// From ext-onetab-concatenated-sources-background.js
const Ie = "https://www.one-tab.com"  // Constant for OneTab domain

// Optional permission - requires explicit user grant
"optional_host_permissions": [
  "https://www.one-tab.com/*"
]

// API endpoint for sharing
async My(e, a=!1) {
  try {
    return await St(Ie+"/api/updatePage", e), {success:!0}
  } catch(i) {
    console.error(i)
    // Queue failed requests for retry
    a && await y.Oe(["shareUpdate"], "readwrite", async(n,[s])=>{
      await y.put(e,s)
    })
    return {success:!1}
  }
}
```

**Analysis**:
- Tab sharing is an **advertised feature** of OneTab
- Users must explicitly grant `https://www.one-tab.com/*` permission (optional_host_permissions)
- Only tab URLs and titles are collected: `chrome.tabs.query({}).map(s=>[s.url,s.title])`
- No sensitive data (cookies, passwords, form data) is accessed
- The 97 flows are duplicates across 8 concatenated files (shared-page-permission, popup, placeholder, options, onetab, localisation, import, background)

**Verdict**: **BENIGN** - Core functionality working as designed. Users explicitly opt-in to sharing.

---

#### 2. "Obfuscated Code" - Concatenation/Minification, Not Malicious

**Severity**: None (False Positive)
**Files**: All `ext-onetab-concatenated-sources-*.js` files
**CWE**: N/A

**Evidence**:
```javascript
// Copyright 2025 OneTab Ltd.  All rights reserved.
const cn="2.4",dn=!1,un=!1,fn=!1,wn=!1,hn=!1,pn=!1,yn=!0,Ia="chrome://",
mn="chrome://newtab/",Ie="https://www.one-tab.com",In=!1,bn=!1,Tn=!0...
```

All JS files are 2-18 lines with extremely long lines (minified format).

**Analysis**:
- Code is minified/concatenated for performance (common practice)
- All files include copyright notice: "Copyright 2025 OneTab Ltd. All rights reserved."
- Variable names are shortened but readable (e.g., `Ie` for one-tab.com, `Re` for runtime URL)
- No string encoding, base64 obfuscation, or anti-debugging techniques
- No eval() or Function() constructor usage
- Deobfuscation via jsbeautifier successfully produces readable code

**Verdict**: **BENIGN** - Standard build optimization, not malicious obfuscation.

---

## API Endpoints Analysis

### Legitimate Endpoints

1. **www.one-tab.com/api/updatePage**
   - **Purpose**: Share/update/delete shared tab lists
   - **Data sent**:
     - `shareId`: Unique identifier for shared list
     - `key`: Share authentication key
     - `action`: "create", "update", or "delete"
     - Tab URLs and titles (only when sharing)
   - **Trigger**: User explicitly shares a tab group AND grants optional permission
   - **Privacy**: User-controlled, opt-in feature

2. **t2.gstatic.com** (favicon service)
   - **Purpose**: Display favicon images in tab list
   - **Data sent**: None (read-only image requests)
   - **Allowed by CSP**: `img-src 'self' data: https://t2.gstatic.com;`
   - **Privacy**: Google's public favicon service, no tracking

3. **clients2.google.com/service/update2/crx**
   - **Purpose**: Chrome Web Store auto-update mechanism
   - **Data sent**: Extension ID, version (standard Chrome behavior)
   - **Privacy**: Required for all Chrome extensions

### No Third-Party Tracking

- ✅ No Google Analytics
- ✅ No advertising networks
- ✅ No telemetry services
- ✅ No CDN-hosted scripts
- ✅ No remote code loading

---

## Data Flow Summary

### What Data is Collected

**Local Storage (Always)**:
- Tab URLs and titles
- User-created tab groups
- Settings/preferences
- Access dates and metadata

**Network Transmission (Optional - User Must Grant Permission)**:
- Tab URLs and titles (only when user shares a tab group)
- Share ID and encryption key
- Actions: create/update/delete shared lists

**NOT Collected**:
- ❌ Passwords or credentials
- ❌ Cookies or session tokens
- ❌ Browser history beyond saved tabs
- ❌ Form data or autofill information
- ❌ Browsing behavior or analytics
- ❌ User identity or email

### Permission Usage Analysis

| Permission | Justification | Risk Level |
|------------|---------------|------------|
| `tabs` | **Required** - Core functionality to save/restore tabs | ✅ Appropriate |
| `storage` | **Required** - Store tab lists locally | ✅ Appropriate |
| `unlimitedStorage` | **Required** - Users may save thousands of tabs | ✅ Appropriate |
| `favicon` | **Required** - Display tab favicons in UI | ✅ Appropriate |
| `activeTab` | **Required** - Identify current tab for actions | ✅ Appropriate |
| `scripting` | **Required** - Inject content scripts for features | ✅ Appropriate |
| `contextMenus` | **Required** - Right-click menu integration | ✅ Appropriate |

**Optional Permissions** (User must approve):
- `https://www.one-tab.com/*` - Sharing feature
- `readingList` - Import from reading list
- `tabGroups` - Enhanced tab group support
- `bookmarks` - Import/export bookmarks

All permissions are justified and appropriate for a tab management extension.

---

## Manifest Analysis

### Content Security Policy

```json
{
  "extension_pages": "script-src 'self'; object-src 'self'; img-src 'self' data: https://t2.gstatic.com;"
}
```

**Security Evaluation**: ✅ **Excellent**
- `script-src 'self'` - Only local scripts, no remote code execution
- `object-src 'self'` - No embedded plugins
- `img-src` allows only self, data URIs, and Google favicon service
- No `unsafe-inline` or `unsafe-eval` directives

### Background Script

```json
{
  "background": {
    "service_worker": "ext-onetab-concatenated-sources-background.js"
  }
}
```

**Security Evaluation**: ✅ **Good**
- Uses Manifest V3 service worker (modern, secure architecture)
- Single background script (no dynamic loading)

### Web Accessible Resources

```json
"web_accessible_resources": null
```

**Security Evaluation**: ✅ **Excellent**
- No files exposed to web pages
- Prevents fingerprinting via extension detection
- No attack surface for malicious websites

### Content Scripts

**Declared in manifest**: None

**Dynamically registered**:
```javascript
// Only registers on www.one-tab.com and only when user grants permission
await chrome.scripting.registerContentScripts([{
  id: "oneTabWebBridge",
  matches: ["https://www.one-tab.com/*"],
  js: ["ext-onetab-concatenated-sources-one-tab.com-contentscript.js"],
  runAt: "document_idle"
}])
```

**Content Script Purpose**: Bridge between www.one-tab.com web page and extension
```javascript
// ext-onetab-concatenated-sources-one-tab.com-contentscript.js
window.addEventListener("message", async o => {
  if (o.source !== window || o.origin !== window.location.origin ||
      o.data?.direction !== "page-to-extension") return;

  const {id:e, request:r} = o.data;
  try {
    const i = await chrome.runtime.sendMessage({
      type: "contentscript-to-extension",
      request: r
    });
    o.source.postMessage({
      direction: "extension-to-page",
      id: e,
      response: i
    }, o.origin);
  } catch(i) {
    console.error(i);
  }
});
```

**Security Evaluation**: ✅ **Secure**
- Only injected into www.one-tab.com (extension's own domain)
- Validates origin before processing messages
- No access to sensitive web pages
- Only runs when user explicitly uses sharing feature

---

## Code Quality and Security Practices

### Positive Security Indicators

1. ✅ **No eval() or Function() usage** - Prevents code injection
2. ✅ **No XMLHttpRequest interception** - Not hooking browser APIs
3. ✅ **Copyright notices** - Legitimate developer identity
4. ✅ **Strict CSP** - Prevents inline scripts and remote code
5. ✅ **Optional permissions** - User consent for network access
6. ✅ **Error handling** - Graceful failure with console.error()
7. ✅ **Manifest V3** - Modern, secure extension architecture
8. ✅ **No obfuscation** - Minified but not maliciously hidden
9. ✅ **Offline-first** - Works without network connection
10. ✅ **Transparent data flow** - Clear separation between local/remote

### Architecture Summary

OneTab uses a **privacy-preserving architecture**:

1. **Local-first storage**: All tab data stored in chrome.storage (local)
2. **Explicit opt-in**: Network access requires optional permission grant
3. **Minimal data transmission**: Only URLs and titles sent when sharing
4. **User control**: Share/unshare actions controlled by user
5. **No tracking**: No analytics, telemetry, or user identification

---

## Overall Risk Assessment

### Risk Level: CLEAN

**Reasoning**:
1. **Legitimate functionality** - Tab management is the stated and actual purpose
2. **Transparent data practices** - Only collects tab URLs/titles for sharing (opt-in)
3. **No malicious indicators** - No tracking, credential theft, or code injection
4. **Strong security** - CSP, MV3, no WARs, permission-gated network access
5. **User control** - Sharing is optional and clearly presented
6. **Established reputation** - 2M users, 4.5 rating, consistent updates

### Static Analyzer Score Context

The ext-analyzer assigned a risk score of 70 with 97 exfiltration flows, which would normally indicate HIGH risk. However, this analysis demonstrates that:

1. **All 97 flows are duplicates** - Same code patterns repeated across 8 concatenated source files
2. **All flows are legitimate** - Tab sharing to www.one-tab.com with user consent
3. **Obfuscation flag is false** - Code is minified, not maliciously obfuscated
4. **No unexpected behavior** - Extension does exactly what it advertises

The high flow count is an artifact of code concatenation (build process includes same source in multiple bundles), not malicious data exfiltration.

### Recommendations

**For Users**:
- ✅ **Safe to use** for tab management
- ⚠️ Only grant www.one-tab.com permission if you want to use the sharing feature
- ⚠️ Be aware shared tab lists may contain sensitive URLs (bank logins, private documents)
- ✅ Review shared lists before publishing to ensure no private information

**For Developers**:
- Consider adding privacy controls (e.g., filter sensitive domains before sharing)
- Document data practices in extension description
- Consider end-to-end encryption for shared lists

### Comparison to Similar Extensions

OneTab is **less privacy-invasive** than many tab management extensions because:
- No analytics or tracking (many competitors include Google Analytics)
- No required network permissions (operates fully offline unless sharing)
- No web accessible resources (prevents fingerprinting)
- No content scripts on arbitrary pages (some competitors inject everywhere)

---

## Conclusion

**OneTab is a legitimate, well-designed tab management extension with minimal privacy risk.**

The static analyzer's HIGH risk score (70) was triggered by:
1. High exfiltration flow count (97) - which are all legitimate sharing features
2. Obfuscation flag - which is minification, not malicious obfuscation

Deep code analysis confirms:
- All network activity is user-initiated and transparent
- Data collection is limited to tab URLs/titles for opt-in sharing
- No tracking, analytics, or third-party data transmission
- Strong security posture with CSP, MV3, and permission gating

**Final Verdict**: CLEAN. Safe for general use.

---

## Technical Appendix

### Key Functions Analyzed

1. **My()** - Share API endpoint handler
   - Sends share data to www.one-tab.com/api/updatePage
   - Includes retry logic with local queue
   - Requires optional permission grant

2. **chrome.tabs.query()** - Tab enumeration
   - Collects `[url, title]` for saved tabs
   - Used for both local storage and optional sharing
   - No access to tab content, cookies, or credentials

3. **Sm()** - Content script registration
   - Dynamically registers bridge script for www.one-tab.com
   - Only runs if user granted optional permission
   - Validates permission before registration

### Message Flow (Sharing Feature)

```
User clicks "Share" button
  ↓
Extension checks optional_host_permissions
  ↓
If not granted → Shows permission request dialog
  ↓
User approves permission
  ↓
Extension registers content script for www.one-tab.com
  ↓
Extension sends tab data: {shareId, key, action, tabs: [[url, title], ...]}
  ↓
POST https://www.one-tab.com/api/updatePage
  ↓
Server returns share URL
  ↓
User can view/edit shared list on www.one-tab.com
```

### Data Retention

- **Local**: Unlimited (stored in chrome.storage)
- **Remote**: Controlled by www.one-tab.com (user can delete shares)
- **No telemetry**: Extension does not collect usage statistics

---

**Report Generated**: 2026-02-14
**Analyst**: Claude Sonnet 4.5
**Analysis Method**: Manual source code review + static analysis correlation
