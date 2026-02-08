# Security Analysis Report: Salesforce Logins by Synebo

## Extension Metadata
- **Extension ID**: mhpbcjokcjoldhjcapkcmfkkkgepapgm
- **Name**: Salesforce Logins by Synebo
- **Version**: 3.0.1
- **User Count**: ~50,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

---

## Executive Summary

**Overall Risk Level: CLEAN**

Salesforce Logins by Synebo is a legitimate credential management extension designed specifically for Salesforce users. The extension provides secure storage and automated login functionality for multiple Salesforce environments (Production, Sandbox, Developer Edition, PreRelease, Community, Custom domains).

The extension uses standard Chrome Extension APIs appropriately for its intended functionality. It stores credentials locally using `chrome.storage.sync`, performs SOAP-based authentication with Salesforce servers, and automates login forms. No malicious behavior, data exfiltration, or suspicious network activity was detected.

**Key Findings:**
- ✅ Legitimate Salesforce credential management tool
- ✅ Uses official Salesforce SOAP API for authentication
- ✅ No unauthorized data collection or exfiltration
- ✅ No connection to third-party analytics or tracking services
- ✅ No code obfuscation beyond standard webpack bundling
- ✅ Appropriate permission usage for stated functionality
- ✅ No runtime code generation or eval() usage

---

## Vulnerability Analysis

### 1. Credential Storage in Sync Storage
**Severity: MEDIUM (Security Consideration)**
**Files**: `background.bundle.js` (lines 1093-1154)
**Code**:
```javascript
chrome.storage.sync.get((t => {
  // Retrieves credentials
}))

chrome.storage.sync.set({
  [credentialId]: credentialData
}, callback)
```

**Description**:
The extension stores Salesforce credentials (usernames, passwords, security tokens) in `chrome.storage.sync`. While this is encrypted by Chrome, it syncs across user devices and could be accessed by other extensions with storage permissions.

**Verdict**: ACCEPTABLE - This is standard practice for credential manager extensions. Chrome's storage API provides encryption at rest. Users explicitly grant storage permissions and understand they're storing credentials.

---

### 2. Password Transmission via SOAP API
**Severity: LOW (Expected Behavior)**
**Files**: `background.bundle.js` (lines 1544-1548, 1670-1703, 1705-1736)
**Code**:
```javascript
function Me(e) {
  var t = e.Password + (e.Token ? e.Token : "");
  t = t.replace(/&/g, "&amp;").replace(/</g, "&lt;")...
  return '<?xml version="1.0" encoding="utf-8"?> ' +
    '<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema"...' +
    '<n1:username>' + e.SfName + '</n1:username>' +
    '<n1:_password>' + t + '</n1:_password>'...
}

// XMLHttpRequest to Salesforce SOAP endpoint
a.open("POST", o, true);
a.setRequestHeader("Content-Type", "text/xml");
a.setRequestHeader("SOAPAction", "login");
a.send(xmlPayload);
```

**Description**:
The extension sends credentials to official Salesforce SOAP API endpoints (`services/Soap/c/39.0/`) using HTTPS. Passwords are XML-escaped and sent in SOAP envelope format. This is the official Salesforce authentication mechanism.

**Verdict**: CLEAN - Uses official Salesforce Enterprise API for authentication. All connections are HTTPS. No credentials sent to third parties.

---

### 3. Script Injection for Auto-Login
**Severity: LOW (Expected Behavior)**
**Files**: `background.bundle.js` (lines 1559-1581, 1590-1619)
**Code**:
```javascript
chrome.scripting.executeScript({
  target: { tabId: o },
  func: Ve,
  args: [url, username, password]
})

function Ve(e, t, r) {
  const n = document.createElement("form");
  n.setAttribute("method", "POST");
  n.setAttribute("action", e);
  // Creates hidden form fields with credentials
  n.submit()
}

function $e(e, t) {
  // Waits for login form elements to appear
  const n = document.querySelector("#sfdc_username_container input");
  const o = document.querySelector("#sfdc_password_container input");
  n.value = e;
  o.value = t;
  a.click(); // Clicks login button
}
```

**Description**:
The extension injects scripts into Salesforce login pages to auto-fill credentials and submit login forms. This is the core functionality of the credential manager.

**Verdict**: CLEAN - Targeted script injection only on Salesforce domains (`*.force.com`, `*.salesforce.com`). No data harvesting or exfiltration.

---

### 4. Cookie Access for Session Management
**Severity: LOW (Expected Behavior)**
**Files**: `background.bundle.js` (lines 2159-2198)
**Code**:
```javascript
chrome.cookies.get({
  url: t,
  name: "sid"
}, (async t => {
  if (!t) return;
  var r = t.value.split("!")[0]; // Extract org ID from session
  // Updates tab title and favicon with org alias/color
}))
```

**Description**:
The extension reads Salesforce session cookies (`sid`) to extract organization IDs and update tab titles/favicons with custom aliases and colors for easier identification of multiple Salesforce orgs.

**Verdict**: CLEAN - Reads cookies only from Salesforce domains. Uses data for UI customization, not exfiltration.

---

### 5. Omnibox Integration
**Severity: CLEAN**
**Files**: `background.bundle.js` (lines 2132-2155)
**Code**:
```javascript
chrome.omnibox.onInputStarted.addListener(...)
chrome.omnibox.onInputChanged.addListener(...)
chrome.omnibox.onInputEntered.addListener(...)
```

**Description**:
Provides omnibox (address bar) search functionality to quickly find and login to stored Salesforce credentials by typing 's <query>'.

**Verdict**: CLEAN - Standard Chrome omnibox API usage for productivity feature.

---

### 6. Offscreen Document for XML Parsing
**Severity: CLEAN**
**Files**: `background.bundle.js` (lines 1709-1719), `offscreen.bundle.js` (lines 1-37)
**Code**:
```javascript
chrome.offscreen.createDocument({
  url: "/offscreen.html",
  reasons: ["DOM_PARSER"],
  justification: "reason for needing the document"
})

// offscreen.bundle.js parses SOAP XML responses
chrome.runtime.onMessage.addListener((function(e, t, r) {
  const a = (new DOMParser).parseFromString(e.data, "text/xml");
  // Extracts sessionId, serverUrl, organizationName
}))
```

**Description**:
Uses offscreen document (MV3 pattern) to parse XML SOAP responses using DOMParser, which requires a document context.

**Verdict**: CLEAN - Standard MV3 pattern for DOM operations in service workers.

---

## False Positives

| Pattern | Location | Reason | Verdict |
|---------|----------|--------|---------|
| Password in code | background.bundle.js:1546-1548 | SOAP XML construction for Salesforce API | FALSE POSITIVE - Legitimate API usage |
| Script injection | background.bundle.js:1559-1619 | Auto-login functionality | FALSE POSITIVE - Core feature |
| Cookie reading | background.bundle.js:2159-2198 | Session management for UI customization | FALSE POSITIVE - Legitimate use |
| XMLHttpRequest | background.bundle.js:1675-1701 | Salesforce SOAP authentication | FALSE POSITIVE - Official API |

---

## API Endpoints

| Endpoint | Purpose | Protocol | Risk |
|----------|---------|----------|------|
| `https://login.salesforce.com/` | Production login | HTTPS | CLEAN |
| `https://test.salesforce.com/` | Sandbox login | HTTPS | CLEAN |
| `https://prerellogin.pre.salesforce.com/` | PreRelease login | HTTPS | CLEAN |
| `*/services/Soap/c/39.0/` | Salesforce SOAP API v39.0 | HTTPS | CLEAN |
| `*/secur/frontdoor.jsp?sid=*` | Salesforce session redirect | HTTPS | CLEAN |

**All endpoints are official Salesforce infrastructure. No third-party services detected.**

---

## Data Flow Summary

```
User Input (Credentials)
  → chrome.storage.sync (encrypted local storage)
  → SOAP XML envelope construction
  → HTTPS POST to Salesforce SOAP API (login.salesforce.com/services/Soap/c/39.0/)
  → Salesforce session response (sessionId, orgId, orgName)
  → Automated form submission or frontdoor.jsp redirect
  → Tab/window opens with authenticated Salesforce session
  → Cookie reading for UI customization (tab title/favicon)
```

**No data leaves Chrome or goes to non-Salesforce servers.**

---

## Permissions Analysis

| Permission | Usage | Justification |
|------------|-------|---------------|
| `storage` | Credential storage | Required for saving Salesforce logins |
| `cookies` | Read Salesforce cookies | Used to extract org ID for UI customization |
| `tabs` | Tab management | Required to open/update tabs with logins |
| `activeTab` | Current tab access | Required for login automation |
| `scripting` | Content script injection | Required to auto-fill login forms |
| `alarms` | Timer functionality | Used for session timeout warnings |
| `offscreen` | XML parsing | MV3 pattern for DOMParser in service worker |
| `background` | Service worker | Required for persistent functionality |

**Host Permissions:**
- `https://*.force.com/` - Salesforce domains
- `https://*.salesforce.com/` - Salesforce domains
- `https://*.my.site.com/` - Salesforce Community domains
- `https://*/*` (optional) - For custom Salesforce domains

**All permissions are appropriately scoped and necessary for stated functionality.**

---

## Security Best Practices Observed

✅ Uses HTTPS for all network requests
✅ XML-escapes user input before SOAP transmission
✅ No eval() or Function() code generation
✅ No connection to analytics/tracking services
✅ Minimal permission scope (no webRequest, no history, no downloads)
✅ Uses official Salesforce APIs
✅ MV3 compliant (service worker, offscreen documents)
✅ Externally connectable only to specific extension ID (kcfbknlaoagjpohbkpcpiceakdcnjchn)

---

## Recommendations

1. **For Users**: This extension is safe to use for managing Salesforce credentials. Understand that credentials are stored in Chrome sync storage and will sync across your devices.

2. **For Developers**: Consider adding:
   - Master password option for additional encryption layer
   - Auto-lock after timeout
   - Browser fingerprinting protection
   - CSP headers in manifest (currently absent)

---

## Overall Risk Assessment

**CLEAN**

This extension is a legitimate productivity tool for Salesforce users. It uses standard Chrome Extension APIs appropriately, connects only to official Salesforce infrastructure, and performs no malicious activities. The code is straightforward with no obfuscation beyond standard webpack bundling.

**Risk Breakdown:**
- **Data Exfiltration**: None detected
- **Malicious Code**: None detected
- **Suspicious Network Activity**: None detected
- **Permission Abuse**: None detected
- **Code Injection Risks**: Low (limited to Salesforce domains)
- **Credential Security**: Medium (relies on Chrome's sync storage encryption)

**Recommended Action**: APPROVE for continued use.

---

*Report generated by automated security analysis*
*Analysis performed on deobfuscated source code*
