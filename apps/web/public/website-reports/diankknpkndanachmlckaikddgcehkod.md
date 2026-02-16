# Vulnerability Report: TickTick - Todo & Task List

## Metadata
- **Extension ID**: diankknpkndanachmlckaikddgcehkod
- **Extension Name**: TickTick - Todo & Task List
- **Version**: 1.2.1.1
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

TickTick is a legitimate task management browser extension developed by the popular productivity service TickTick (dida365.com/ticktick.com). The extension allows users to quickly save web content as tasks, manage their to-do lists via a side panel, and sync with their TickTick account.

While the extension requests broad permissions (cookies + host_permissions for all URLs), analysis of the code reveals these permissions are not actively exploited. All actual functionality is scoped to the TickTick/Dida365 domains through content scripts with specific match patterns. The extension does not collect browsing data, exfiltrate information, or perform any malicious activities. The overly broad permissions represent a minor security concern due to potential for future abuse if the extension were compromised, but current behavior is benign.

## Vulnerability Details

### 1. LOW: Overprivileged Permissions

**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-250 (Execution with Unnecessary Privileges)

**Description**: The extension requests both the `cookies` permission and `host_permissions: ["*://*/*"]`, which together could theoretically allow the extension to steal cookies from any website. However, analysis of the actual code shows no usage of `chrome.cookies` API and no data exfiltration mechanisms.

**Evidence**:
```json
"permissions": [
  "scripting",
  "tabs",
  "storage",
  "contextMenus",
  "cookies",
  "sidePanel"
],
"host_permissions": [
  "*://*/*"
]
```

Static analysis output flagged:
- "critical: cookies"
- "critical: cookies + broad host access (can steal cookies from any site)"

However, code inspection reveals:
- No calls to `chrome.cookies.get()` or `chrome.cookies.getAll()`
- No network requests to external domains besides core-js/React licensing comments
- All content scripts operate only on TickTick/Dida365 domains
- The general content script (`contentscript.js` on `<all_urls>`) only provides right-click context menu integration

**Verdict**: This is a case of defensive permission requests where the developer may have anticipated future features or requested permissions proactively. The permissions are not currently exploited for malicious purposes. Modern Manifest V3 architecture limits the damage potential compared to MV2.

## False Positives Analysis

### Static Analyzer Findings

The ext-analyzer tool reported:
```
EXFILTRATION (1 flow):
  [HIGH] chrome.tabs.query → fetch(github.com)    scripts/background.js
```

**Analysis**: This is a false positive. The "github.com" references found in the code are:
1. Licensing comments for core-js library: `https://github.com/zloirock/core-js`
2. Webpack bundle license headers
3. React error decoder URL patterns

There are no actual `fetch()` calls to github.com or any exfiltration mechanisms in the extension.

### Webpack Bundling

The extension uses webpack-bundled React code, which the deobfuscator correctly preserved but results in extremely long single-line files. This is standard for modern web development, not obfuscation intended to hide malicious behavior.

### Content Scripts on All URLs

The extension has a content script matching `http://*/*` and `https://*/*`, but this script's sole purpose is to:
- Inject a context menu option for "Add to TickTick"
- Allow users to right-click selected text/images and save them as tasks

This is legitimate functionality for a task management tool and does not involve data collection.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| dida365.com | TickTick web app (Chinese domain) | User tasks, settings, authentication | None - first-party service |
| ticktick.com | TickTick web app (International domain) | User tasks, settings, authentication | None - first-party service |
| 365dida.com | TickTick development/testing domains | Development data only | None - first-party service |

All endpoints are owned and operated by the TickTick team. The extension communicates exclusively with first-party services for legitimate task synchronization.

### Communication Mechanism

The extension uses:
- `chrome.storage.sync` for syncing user preferences across devices (Chrome sync, not custom servers)
- `externally_connectable` to allow the TickTick web apps to communicate with the extension
- Side panel integration showing the TickTick web app in an iframe: `https://{domain}/webapp#?sidepanel=true`

No third-party analytics, tracking, or advertising services detected.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

This is a legitimate, well-maintained extension from a reputable productivity software company with 200,000+ users. The code quality is professional, using modern development practices (React, webpack, Manifest V3).

The LOW rating (rather than CLEAN) is due solely to the overprivileged permissions request. While the extension doesn't currently abuse these permissions, the combination of `cookies` permission + `host_permissions: *://*/*` creates unnecessary risk:

1. **Supply chain risk**: If the developer's account were compromised, a malicious update could leverage these permissions to steal cookies from any website
2. **Future feature creep**: The developer could silently add cookie-harvesting functionality in a future update without needing to request additional permissions
3. **Principle of least privilege**: Best practice dictates requesting only the minimum necessary permissions

**Recommendations for users**:
- The extension is safe to use in its current form
- Monitor for updates that might introduce new behaviors
- Consider uninstalling if not actively using TickTick service

**Recommendations for developer**:
- Remove the `cookies` permission if not actively used
- Narrow `host_permissions` to only the domains where content scripts are injected
- Consider using `activeTab` permission instead of broad host permissions for context menu functionality

**No malicious behavior detected.**
