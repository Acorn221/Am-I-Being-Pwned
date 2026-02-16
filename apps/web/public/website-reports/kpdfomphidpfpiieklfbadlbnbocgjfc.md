# Vulnerability Report: Group Address Book 3 - Sateraito Office

## Metadata
- **Extension ID**: kpdfomphidpfpiieklfbadlbnbocgjfc
- **Extension Name**: Group Address Book 3 - Sateraito Office
- **Version**: 3.2.9
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Group Address Book 3 - Sateraito Office is a legitimate Google Workspace productivity extension designed to add group address book functionality to Gmail, Google Calendar, Google Drive, Google Sites, and Google Chat. The extension integrates with multiple Google Workspace services to facilitate email address selection from shared contact lists hosted on remote servers.

While the extension serves a legitimate business purpose, it exhibits several security concerns related to message handling and remote configuration fetching. The primary issue is a postMessage handler without origin validation that could allow malicious websites to inject data into Google Workspace pages. Additionally, the extension fetches DOM selector configurations from remote servers dynamically, creating potential attack vectors if these servers were compromised.

## Vulnerability Details

### 1. MEDIUM: postMessage Handler Without Origin Validation

**Severity**: MEDIUM
**Files**: addr_cs.js:25
**CWE**: CWE-346 (Origin Validation Error)

**Description**: The content script implements a postMessage event listener that validates the message origin against a stored value but does not perform this check correctly. The origin check `if (a.origin === g)` on line 306 of the deobfuscated addr_cs.js only validates against a variable `g` (the server origin) which is set dynamically via chrome.storage. If this value is manipulated or if the check fails to initialize properly, unauthorized origins could send messages.

**Evidence**:
```javascript
function va(a) {
  if (a.origin === g) {
    var b = na();
    if ("mail" === b) {
      var d = ua(a.data);
      // ... processes message data and injects into Gmail forms
    }
    // ... handles other Google Workspace contexts
    a.source.close()
  }
}
window.addEventListener("message", va, !1)
```

The ext-analyzer flagged this pattern:
```
ATTACK SURFACE:
  [HIGH] window.addEventListener("message") without origin check    addr_cs.js:25
  message data → fetch    from: options.js ⇒ addr_bs.js
```

**Verdict**: While there is an origin check present, the dynamic nature of the origin validation (relying on `g` being correctly set from storage) and the lack of a fallback/default creates a window where messages might be processed without proper validation during initialization or if storage is tampered with.

### 2. MEDIUM: Remote Configuration Fetching

**Severity**: MEDIUM
**Files**: addr_bs.js (lines 437-574, deobfuscated 529-574)
**CWE**: CWE-494 (Download of Code Without Integrity Check)

**Description**: The extension fetches DOM selector configurations from remote servers without integrity verification. The background script downloads a JSON configuration file from multiple hardcoded AppSpot domains that specify CSS selectors used to identify email input fields in Google Workspace pages.

**Evidence**:
```javascript
M = {
  s: "email_selector selector_chat_user_select_area ...".split(" "),
  v: function(a) {
    return a + "/static/json/domselectoremail.json?rk=" + (new Date).getTime()
  },
  u: function(a) {
    var b = JSON.parse(a);
    var e = {};
    M.s.forEach(function(k) {
      e[k] = b[k] || ""
    });
    chrome.storage.local.set(e);
    // Sets selectors that control where the extension injects data
  }
}
```

The configuration is fetched from:
- https://kddi-address.appspot.com
- https://sateraito-apps-address.appspot.com
- https://sateraito-apps-address-misawa.appspot.com
- https://akindo-sushiro-address.appspot.com

**Verdict**: If any of these servers were compromised, an attacker could modify the DOM selectors to target different form fields, potentially causing the extension to inject address book data into sensitive fields (passwords, credit cards, etc.) rather than email recipient fields. However, the servers appear to be controlled by the extension developer (Sateraito), and all connections use HTTPS.

### 3. LOW: Clipboard Manipulation

**Severity**: LOW
**Files**: addr_cs.js (deobfuscated lines 28-35)
**CWE**: CWE-250 (Execution with Unnecessary Privileges)

**Description**: The extension requests both `clipboardRead` and `clipboardWrite` permissions and creates hidden textarea elements to manipulate the clipboard for copying email addresses.

**Evidence**:
```javascript
function ha(a) {
  var b = document.getElementById("idSatAdrInputElement");
  b || (b = document.createElement("textarea"),
       b.id = "idSatAdrInputElement",
       b.style.cssText = "position:absolute; top:0; left:-500px; z-index:-1;",
       document.body.appendChild(b));
  b.value = a;
  b.select();
  document.execCommand("copy", !1, null);
  window.getSelection().removeAllRanges()
}
```

**Verdict**: This is a standard pattern for clipboard operations in extensions and is necessary for the extension's core functionality (copying email addresses from the address book). The clipboard permissions are declared in the manifest and visible to users. This is expected behavior for this type of extension.

## False Positives Analysis

### Exfiltration Flows (False Positive)

The ext-analyzer reported two HIGH severity exfiltration flows:
```
[HIGH] chrome.storage.local.get → fetch    addr_bs.js
[HIGH] chrome.storage.local.get → fetch    addr_cs.js ⇒ addr_bs.js
```

**Analysis**: These flows are legitimate functionality. The extension reads the user's selected server preference from storage and then fetches the address book data or DOM selector configuration from that server. This is the core purpose of the extension - to connect Google Workspace apps to a remote group address book service. The data flow is:
1. User configures which address book server to use (via options page)
2. Extension stores this preference in chrome.storage.local
3. Extension reads the preference and fetches address book data from the configured server
4. Extension displays the addresses to the user within Google Workspace pages

This is not data exfiltration; it's fetching external data for display within Google's pages.

### Obfuscation Flag

The ext-analyzer flagged the code as `obfuscated: true`. This is due to Google Closure Compiler minification, which is standard for production JavaScript. The deobfuscated code shows typical Google Workspace integration patterns with no signs of malicious obfuscation.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://kddi-address.appspot.com | Address book server option | Domain name (via /checkdomain?domain=) | LOW - Legitimate server discovery |
| https://sateraito-apps-address.appspot.com | Primary address book server | Domain name, server origin preference | LOW - Core functionality |
| https://sateraito-apps-address-misawa.appspot.com | Custom address book server | Domain name | LOW - Custom deployment |
| https://akindo-sushiro-address.appspot.com | Custom address book server | Domain name | LOW - Custom deployment |
| [server]/static/json/domselectoremail.json | DOM selector config | None (GET request with cache-busting timestamp) | MEDIUM - If compromised, could alter injection targets |
| [server]/checkdomain | Server auto-discovery | Google Workspace domain name | LOW - Used to determine which server handles the domain |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

This extension serves a legitimate business purpose for Google Workspace users who need shared group address books across their organization. The core functionality - fetching contact lists from remote servers and injecting them into Google Workspace email/calendar/chat forms - is transparent and expected.

The MEDIUM risk rating is based on two concerns:

1. **postMessage Origin Validation**: The origin validation relies on a dynamically-loaded value from chrome.storage, which could fail to initialize properly or be manipulated. While an actual exploit would require specific timing or storage manipulation, the lack of a hardcoded whitelist or fallback validation creates unnecessary risk.

2. **Remote DOM Selector Configuration**: Fetching DOM selectors from remote servers means that if any of the AppSpot servers were compromised, an attacker could alter where the extension injects email addresses. This could potentially cause addresses to be inserted into password fields or other sensitive inputs rather than email recipient fields.

However, several factors limit the risk:

- The extension only runs on Google Workspace domains (mail.google.com, drive.google.com, etc.), not arbitrary websites
- All remote servers are on AppSpot (Google Cloud) and use HTTPS
- The servers appear to be controlled by the legitimate developer (Sateraito)
- The extension has 100,000+ users with no apparent security incidents
- The functionality is transparent - users can see the address book UI and what data is being inserted

**Recommendations**:
1. Hardcode a whitelist of allowed postMessage origins rather than relying solely on dynamic storage
2. Implement integrity checks (e.g., content hashes) for the remote DOM selector configuration
3. Add CSP headers to the remote configuration endpoints to prevent potential XSS if servers are compromised
4. Consider bundling DOM selectors in the extension package rather than fetching them remotely

This is a legitimate enterprise tool with some security weaknesses that should be addressed, but not evidence of malicious intent.
