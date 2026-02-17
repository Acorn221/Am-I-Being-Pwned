# Vulnerability Report: LockDown Browser for ALEKS

## Metadata
- **Extension ID**: dgnifmckdjjdhbpkmboncnacknekaheh
- **Extension Name**: LockDown Browser for ALEKS
- **Version**: 0.1.00.113
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

LockDown Browser for ALEKS is a legitimate exam proctoring and lockdown extension developed by Respondus for the ALEKS learning platform. The extension enforces exam security by controlling the browser environment, preventing cheating behaviors (screenshots, tab switching, developer tools), and monitoring exam sessions. While the extension serves its intended purpose and is not malicious, it employs highly invasive monitoring capabilities and collects extensive telemetry including browsing history, cookies, clipboard data, and user activity logs which are transmitted to Respondus servers.

The extension has several security issues including window.postMessage handlers without proper origin validation and obfuscated code patterns. Given that this is an enterprise exam proctoring tool with disclosed functionality, the privacy-invasive behavior is expected and disclosed. However, the lack of origin checks on message handlers and the broad data collection warrant a MEDIUM risk rating.

## Vulnerability Details

### 1. HIGH: Insecure postMessage Handlers Without Origin Validation

**Severity**: HIGH
**Files**: pages/webcamstart/webcamstart.js, pages/security_a/security_a.js, pages/security_b/security_b.js, pages/security_c/security_c.js
**CWE**: CWE-346 (Origin Validation Error)

**Description**: Multiple pages in the extension contain `window.addEventListener("message")` event handlers that do not validate the origin of incoming messages. This creates a potential attack surface where malicious web pages could send crafted messages to these extension pages.

**Evidence**:
```javascript
// Static analyzer detected 4 instances:
// pages/webcamstart/webcamstart.js:1
// pages/security_c/security_c.js:1
// pages/security_a/security_a.js:1
// pages/security_b/security_b.js:1
window.addEventListener("message") without origin check
```

**Verdict**: While this is a legitimate security concern, the risk is mitigated because these pages are web_accessible_resources that are loaded in controlled contexts during exam sessions. However, proper origin validation should be implemented as defense-in-depth.

### 2. MEDIUM: Privacy-Invasive Data Collection and Exfiltration

**Severity**: MEDIUM
**Files**: background.js
**CWE**: CWE-359 (Exposure of Private Personal Information)

**Description**: The extension collects and uploads extensive telemetry to Respondus servers including:
- Complete browsing history via `chrome.history` API
- Cookie data via `chrome.cookies.getAll()`
- User activity logs (focus events, screenshot attempts, clipboard events)
- Extension list via `chrome.management.getAll()`
- System information (display config, OS details)

**Evidence**:
```javascript
// Line 542: Fetches remote configuration
fetch(url).then(response => response.json()).then(json => {
  GLOBAL_examTabTitle = json.name, GLOBAL_index = json.ic
})

// Line 568-577: Uploads user cookie data on early exit
chrome.storage.local.get(["ldb_user_cookie"], function(result) {
  var result = JSON.parse(result.ldb_user_cookie),
      fullname = result.name,
      // ... extracts user info ...
  fetch(sessionbase + "?" + (result + "&reason=" + reasonIn + "&timestamp=" + exitstamp))
})

// Line 596-602: Uploads logs and extension metadata
fetch(sessionbase, {
  method: "POST",
  body: new URLSearchParams(timestamp)
})
timestamp += "|||Extension Id=" + chrome_runtime_id
```

**Verdict**: Expected behavior for exam proctoring software. The extension's purpose is to monitor exam sessions and report violations. However, users should be aware of the extensive data collection. This is disclosed in the extension description as "locks down the exam environment."

### 3. LOW: Obfuscated Code Patterns

**Severity**: LOW
**Files**: background.js, multiple content scripts
**CWE**: CWE-506 (Embedded Malicious Code)

**Description**: The static analyzer flagged the code as "obfuscated." While much of the code appears to be minified/uglified rather than intentionally obfuscated, some patterns suggest deliberate obfuscation (aliasing of all Chrome API calls, complex control flow).

**Evidence**:
```javascript
// Lines 25-80: All Chrome APIs are aliased
let chrome_action_onClicked = chrome.action.onClicked,
  chrome_tabs_create = chrome.tabs.create,
  chrome_tabs_update = chrome.tabs.update,
  // ... 50+ more aliases
```

**Verdict**: The aliasing pattern is likely for code size optimization or to make reverse engineering slightly harder, but the deobfuscated code is readable. Not a security issue per se, but reduces transparency.

### 4. HIGH: Invasive Permission Set

**Severity**: HIGH
**Files**: manifest.json
**CWE**: CWE-250 (Execution with Unnecessary Privileges)

**Description**: The extension requests an extremely broad set of permissions including:
- `system.display` - Monitor display configuration
- `history` - Access browsing history
- `clipboardRead`, `clipboardWrite` - Monitor clipboard
- `management` - Control other extensions
- `contentSettings` - Modify browser settings
- `browsingData` - Clear browsing data
- `<all_urls>` - Access all websites

**Verdict**: All permissions are necessary for the extension's exam lockdown functionality (preventing cheating, enforcing single-display mode, blocking screenshots via clipboard monitoring, disabling conflicting extensions). Expected for enterprise proctoring software but highly invasive for typical users.

## False Positives Analysis

1. **Extension Management**: The extension uses `chrome.management` APIs to enumerate and potentially disable other extensions. This could be flagged as "extension_enumeration" but is legitimate behavior for exam lockdown software that needs to prevent VPN/proxy extensions from being used during exams.

2. **Browsing Data Clearing**: Uses `chrome.browsingData.removeFormData()` which is legitimate exam cleanup behavior to remove sensitive data after exam completion.

3. **Cookie Harvesting**: Accesses cookies extensively via `chrome.cookies.getAll()`, but this is for session management with the LMS (ALEKS) and authentication with Respondus proctoring servers.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| smc-service-cloud.respondus2.com | Block page during exam | Exam session info | LOW |
| smc-service-cloud-sdk1.respondus2.com | Main proctoring server | User info, tokens, exam events, logs, activity telemetry | MEDIUM |
| /MONServer/chromebook/non_monitor_exit2.do | Log non-monitored exam exit | token, courseId, examId, userName, firstName, lastName, exit reason, timestamp | MEDIUM |
| /MONServer/chromebook/monitor_exit2.do | Log monitored exam exit | sequenceSid, exit reason, timestamp | MEDIUM |
| /MONServer/chromebook/upload_log.do | Upload activity logs | token, hct, timestamp, logString content | HIGH |
| /MONServer/chromebook/upload_info.do | Upload system info | Extension version, author, extension ID, issue strings | LOW |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

LockDown Browser for ALEKS is a legitimate enterprise exam proctoring extension by Respondus, a well-known educational technology company. The extension functions exactly as advertised - it locks down the browser environment during exams, prevents cheating behaviors, and monitors exam sessions.

**Why MEDIUM rather than HIGH or CRITICAL:**
- The extension is legitimately published by Respondus (ALEKSPROD) for exam proctoring purposes
- The privacy-invasive behavior is expected and necessary for its stated purpose
- Users voluntarily install this to take proctored exams (institutional requirement)
- All data collection is disclosed in the extension description

**Why MEDIUM rather than LOW or CLEAN:**
- Extremely invasive permission set (system.display, history, clipboardRead/Write, management, browsingData)
- Collects and uploads extensive telemetry including browsing history, cookies, and activity logs
- Four postMessage handlers without origin validation (security best practice issue)
- Obfuscated code reduces transparency
- Potential for abuse if Respondus servers were compromised

**Recommendation**: This extension should only be installed when required by an educational institution for taking proctored exams. Users should uninstall immediately after completing the exam due to the invasive monitoring capabilities. The extension is not malware, but represents a privacy tradeoff for exam integrity.
