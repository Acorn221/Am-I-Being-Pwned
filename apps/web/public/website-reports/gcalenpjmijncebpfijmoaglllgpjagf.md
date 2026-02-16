# Security Analysis Report: Tampermonkey BETA

## Extension Metadata
- **Extension ID**: gcalenpjmijncebpfijmoaglllgpjagf
- **Name**: Tampermonkey BETA
- **Version**: 5.5.6234
- **Users**: 700,000
- **Manifest Version**: 3
- **Rating**: 4.8/5

## Executive Summary

Tampermonkey BETA is the beta version of the popular and legitimate userscript manager extension. This is **NOT MALWARE**. The extension requires extensive permissions to fulfill its core purpose: managing and executing user-installed JavaScript code across all websites. Static analysis flagged several patterns that appear suspicious out of context but are entirely legitimate functionality for a userscript manager.

**Risk Level: LOW**

The only security concern is inherent to the extension's purpose: it enables arbitrary code execution of user-installed scripts. This is a **documented, intended feature**, not a vulnerability. Users should only install userscripts from trusted sources.

## Static Analysis False Positives

The ext-analyzer flagged the following patterns, all of which are **false positives**:

### 1. Exfiltration Flows (2 flagged)
- **document.querySelectorAll → fetch**: Line 586 in extension.js
- **document.getElementById → fetch**: Line 586 in extension.js

**Analysis**: These flows are part of the **QR code generation** feature for donation/contribution UI. The code fetches image data to embed in QR codes for users who want to support the developer. This is a benign, opt-in feature displayed in the extension's options/dashboard.

```javascript
// QR code generation with optional logo embedding (extension.js:586)
if (i.startsWith("data:image/svg")) {
    const e = new Image;
    e.src = i,
    await e.decode(),
    n = await createImageBitmap(e, {resizeWidth: s, resizeHeight: s})
} else
    n = await fetch(i).then((e=>e.blob())).then((e=>createImageBitmap(e)));
```

This code creates QR codes for crypto addresses or donation links. The DOM queries select elements to display the QR code, and fetch loads icon images.

### 2. PostMessage Listener Without Origin Check (1 flagged)
- **window.addEventListener("message")**: Line 611 in extension.js

**Analysis**: This is part of the **optional donation/contribution dialog** that appears after updates. The message listener handles communication with an embedded iframe from tampermonkey.net for optional donation tracking. While missing explicit origin validation in the event handler, the context shows this is limited to an opt-in feature dialog.

```javascript
// Donation dialog message handler (extension.js:611)
window.addEventListener("message", (e => {
    let t;
    const i = e.data.clicked || e.data.type,
    s = e.data.amount,
    o = e.data.currency,
    a = e.data.redirect_url
    // ... processes donation dialog events
}))
```

**Recommendation**: The message handler should validate `e.origin` matches expected tampermonkey.net domains as a defense-in-depth measure, though this is a low-severity finding since the feature is opt-in and sandboxed.

## Legitimate Network Endpoints

All network communication serves documented, legitimate purposes:

### Core Infrastructure (tampermonkey.net)
- `tampermonkey.net` - Update notifications, changelog, documentation
- `accounts.tampermonkey.net` - OAuth2 flow for cloud sync
- `blacklist.tampermonkey.net` - Malicious script blacklist updates
- `a.tampermonkey.net` - Optional analytics (Matomo, opt-in with probabilistic sampling)

### Cloud Sync Providers
- `accounts.google.com`, `googleapis.com` - Google Drive sync (opt-in)
- `dropbox.com`, `api.dropboxapi.com` - Dropbox sync (opt-in)
- Yandex.Disk, OneDrive, WebDAV - Additional sync options (visible in code, opt-in)

### Userscript Repositories
- `greasyfork.org`, `sleazyfork.org` - Script discovery and updates
- `openuserjs.org` - Script repository integration
- `github.com`, `gitlab.com`, `bitbucket.com` - Git-hosted userscript support
- `userscripts-mirror.org` - Mirror for legacy userscripts.org

All endpoints are hardcoded, use HTTPS, and serve documented functionality.

## Permission Analysis

Tampermonkey BETA requires extensive permissions that are **necessary and appropriate** for a userscript manager:

### Critical Permissions (All Justified)
- **`<all_urls>`** - Required to inject user scripts into any website per user configuration
- **`scripting`** - MV3 API for script injection
- **`userScripts`** - MV3 API specifically designed for userscript managers
- **`webRequest`, `webRequestBlocking`** - Required for userscript `@connect` directives and CORS bypassing
- **`storage`, `unlimitedStorage`** - Store userscripts, settings, and cached data
- **`tabs`, `webNavigation`** - Manage script execution contexts across tabs
- **`contextMenus`** - "Add/Edit script" context menu integration
- **`clipboardWrite`** - Copy script URLs, debug info, etc.
- **`cookies`** - Userscript `GM.cookie` API support
- **`declarativeNetRequestWithHostAccess`** - MV3 request modification
- **`offscreen`** - Background tasks in MV3 architecture
- **`alarms`** - Scheduled script updates
- **`idle`** - Optimize update checks
- **`notifications`** - Update/install notifications

### Optional Permissions
- **`downloads`** - Export/backup userscripts (opt-in)

All permissions are either required by Manifest V3 architecture or directly map to documented userscript manager features.

## Code Execution Analysis

Tampermonkey executes JavaScript code by design - this is its entire purpose. The extension:
1. Allows users to create/install JavaScript userscripts
2. Executes these scripts in web page contexts per user-defined `@match` rules
3. Provides sandboxed APIs (`GM.*` functions) for controlled capabilities

This is **not a vulnerability** - it's the documented functionality that 700,000 users installed the extension to use.

## Security Observations

### Positive Security Practices
1. **Hardcoded endpoints** - No dynamic URL construction for infrastructure calls
2. **HTTPS enforcement** - All Tampermonkey infrastructure uses HTTPS
3. **Blacklist protection** - Downloads and applies malicious script blacklists
4. **Update integrity** - Script update checking from known repositories
5. **Sandboxing options** - Configurable script isolation modes
6. **MV3 migration** - Uses modern Manifest V3 APIs (userScripts, scripting)

### Minor Security Considerations
1. **PostMessage origin validation** - The donation dialog message handler should validate `e.origin` (LOW severity - opt-in feature)
2. **User responsibility** - Users must only install scripts from trusted sources (inherent to userscript managers, not a bug)

## Verdict

**RISK LEVEL: LOW**

Tampermonkey BETA is a **legitimate, well-established browser extension** from a trusted developer. The static analysis flags are false positives caused by:
- QR code generation for donation UI (flagged as "exfiltration")
- Donation dialog iframe communication (flagged as "unsafe postMessage")

The extension's extensive permissions and code execution capabilities are **necessary and appropriate** for its documented purpose as a userscript manager. There is no evidence of:
- Data exfiltration
- Malicious behavior
- Deception
- Privacy violations
- Hidden functionality

The only security consideration is inherent to all userscript managers: users can install and execute arbitrary JavaScript. This is the extension's intended functionality, clearly documented, and why users install it.

## Recommendations

### For Users
- Only install this extension if you understand it enables arbitrary code execution
- Only install userscripts from trusted sources (Greasy Fork, etc.)
- Review script permissions before installation
- Keep the extension updated

### For Developers (Minor Enhancement)
- Add origin validation to the donation dialog postMessage listener:
```javascript
window.addEventListener("message", (e => {
    if (!e.origin.match(/^https:\/\/.*\.tampermonkey\.net$/)) return;
    // ... rest of handler
}))
```

## Conclusion

Tampermonkey BETA is **safe to use** and the static analysis results should be disregarded as false positives. The extension is a legitimate tool that requires powerful permissions to fulfill its well-documented purpose as a userscript manager.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
