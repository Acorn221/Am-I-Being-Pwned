# Vulnerability Report: Easy Clean

## Metadata
- **Extension ID**: bjpclojdgakmcjmfdgiodjgfncaejaki
- **Extension Name**: Easy Clean
- **Version**: 1.0.1
- **Users**: ~60,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Easy Clean is a browser cleaning utility that allows users to clear browsing data (history, cache, cookies, downloads, passwords, form data, and various storage types) either manually or automatically when the browser closes. The extension provides a basic UI for managing which data types to delete and maintaining a whitelist of cookies to preserve (e.g., social media sites).

While the core functionality is legitimate for a cleaning utility, the extension exhibits overly broad permissions and a potentially aggressive default configuration that raises medium-level privacy and usability concerns. The extension requests `*://*/*` host permissions which are unnecessary for its stated purpose, and enables automatic cleaning by default, which could lead to unexpected data loss for users who don't fully understand the implications.

## Vulnerability Details

### 1. MEDIUM: Overly Broad Host Permissions

**Severity**: MEDIUM
**Files**: manifest.json
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension requests `host_permissions: ["*://*/*"]` which grants access to all websites. For a browser cleaning utility that only uses Chrome's native `browsingData` API and manages cookies, this broad permission is unnecessary and violates the principle of least privilege.

**Evidence**:
```json
"host_permissions": ["*://*/*"]
```

**Verdict**: The `browsingData` permission combined with `cookies` permission is sufficient for the extension's functionality. The `*://*/*` host permission is not required to clear browsing data or manage cookies via the Chrome API. This represents an excessive permission request that could be exploited if the extension were compromised or if the developer added malicious functionality in a future update.

### 2. MEDIUM: Aggressive Default Auto-Clean Configuration

**Severity**: MEDIUM
**Files**: background.js
**CWE**: CWE-1188 (Insecure Default Initialization of Resource)
**Description**: The extension is configured to automatically delete nearly all browsing data (history, cache, downloads, cookies, passwords, form data, file systems, app cache, IndexedDB, localStorage, WebSQL, service workers) when the browser closes, with auto-clean enabled by default. This behavior is not clearly communicated during installation and could lead to significant data loss.

**Evidence**:
```javascript
// From background.js lines 26-59
async function cleanCache () {
  const settingsList = ['deleteHistory', 'deleteCache', 'deleteDownloads',
    'deleteCookies', 'deletePasswords', 'deleteFormData', 'deleteFileSystems',
    'deleteAppCache', 'deleteIndexedDB', 'deleteLocalStorage', 'deleteWebSQL',
    'deleteServiceWorkers', 'autoClean']
  const getSettings = await new Promise(resolve =>
    chrome.storage.local.get(settingsList, data => resolve(data)))
  // All options default to enabled if undefined
  if (getSettings.deleteHistory || getSettings.deleteHistory === undefined)
    removeOptions.history = true
  // ... similar for all other options
}

// Triggered on browser close
chrome.windows.onRemoved.addListener(() => {
  chrome.windows.getAll({}, async windows => {
    const windowCount = windows.length
    if (windowCount < 1) cleanCache()
  })
})

// Also triggered on browser startup
chrome.runtime.onStartup.addListener(cleanCache)
```

**Verdict**: While auto-cleaning is a legitimate feature for privacy-conscious users, defaulting to enabled with all data types selected creates a high risk of unintended data loss. Users who install this extension without carefully reviewing the settings may lose saved passwords, form data, and browsing history unexpectedly. The extension would be safer if auto-clean defaulted to disabled, requiring explicit opt-in.

### 3. LOW: Tab Closing Functionality Scope Creep

**Severity**: LOW
**Files**: popup.js
**CWE**: CWE-749 (Exposed Dangerous Method or Function)
**Description**: The extension includes functionality to close browser tabs (all tabs, all except current, or close and create new tab). This is feature creep beyond the core "cleaning" purpose and could be confusing or disruptive if accidentally triggered.

**Evidence**:
```javascript
// popup.js lines 79-103
closeTab.addEventListener('click', async () => {
  const tabSetting = await new Promise(resolve =>
    chrome.storage.local.get('tabSetting', data => resolve(data.tabSetting))) || 'newTab'
  function closeTabs (tabID) {
    chrome.tabs.query({}, tabs => {
      tabs.forEach(tab => {
        if (tab.id !== tabID) chrome.tabs.remove(tab.id)
      })
    })
  }
  switch (tabSetting) {
    case 'newTab':
      closeTabs('all')
      chrome.tabs.create({})
      break
    case 'currentTab':
      chrome.tabs.query({ active: true, currentWindow: true },
        thisTab => closeTabs(thisTab[0].id))
      break
    case 'allTabs':
      closeTabs('all')
      break
  }
})
```

**Verdict**: While not inherently malicious, the ability to close all browser tabs is beyond the scope of a "cleaning" extension and could be accidentally triggered. The default "newTab" option that closes all tabs and opens a blank one is particularly disruptive. This functionality requires the `windows` permission which contributes to the extension being overprivileged.

## False Positives Analysis

### Static Analyzer: No Suspicious Findings
The ext-analyzer reported "No suspicious findings," which is accurate. The extension does not exhibit:
- Data exfiltration to external servers (beyond the one-time install redirect to dev-coco.github.io)
- Dynamic code execution (eval, Function constructor)
- Cookie harvesting or credential theft
- Hidden API access or obfuscated code
- Message-based attack vectors

### Cookie Management is Legitimate
The extension's access to `chrome.cookies.getAll()` and management of cookie domains is entirely appropriate for its stated purpose of selective cookie deletion with a whitelist feature. This is not cookie harvesting.

### browsingData Permission is Appropriate
The `browsingData` permission and all associated data deletion operations are core to the extension's functionality as a browser cleaner.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| dev-coco.github.io | Post-install welcome page | None (navigation only) | LOW - Legitimate documentation site, only accessed once on install |

The endpoint is a GitHub Pages site (https://dev-coco.github.io/post/Easy-Clean or Easy-Clean-EN) that appears to be the developer's blog/documentation. The extension opens this page once on installation to provide usage instructions. The URL is constructed dynamically based on browser language (`navigator.language.substring(0, 2) === 'zh'`) to serve Chinese or English content. No data is sent to this endpoint; it's a simple tab navigation.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

Easy Clean is a functionally legitimate browser cleaning utility that does what it claims, with no evidence of malicious behavior, data exfiltration, or code execution vulnerabilities. The extension uses standard Chrome APIs appropriately for its core purpose.

However, it demonstrates poor security and UX practices that warrant a MEDIUM risk rating:

1. **Unnecessary Privilege Escalation**: The `*://*/*` host permission is not required for any of the extension's functionality and represents a significant over-privilege that violates the principle of least privilege.

2. **Aggressive Defaults**: Auto-clean enabled by default with all data types selected (including passwords and form data) creates a high risk of unexpected data loss, particularly for less technical users.

3. **Scope Creep**: Tab management functionality goes beyond "cleaning" and adds complexity that requires additional permissions.

The extension would be appropriate for CLEAN or LOW if it:
- Removed the `*://*/*` host permission (unnecessary)
- Defaulted auto-clean to disabled (opt-in rather than opt-out)
- Provided clearer warnings about the implications of password and form data deletion

For the current implementation, MEDIUM is appropriate: the extension is not malicious, but its excessive permissions and aggressive defaults create legitimate privacy and usability concerns that users should be aware of before installation.
