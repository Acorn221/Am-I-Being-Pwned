# Security Analysis Report: Open in Firefox™ Browser

## Extension Metadata
- **Extension Name**: Open in Firefox™ Browser
- **Extension ID**: lmeddoobegbaiopohmpmmobpnpjifpii
- **Version**: 0.5.0
- **User Count**: ~50,000
- **Manifest Version**: 3
- **Homepage**: https://webextension.org/listing/open-in.html?from=firefox

## Executive Summary

The "Open in Firefox™ Browser" extension is a legitimate utility that enables users to open links and tabs from Chrome/Chromium browsers in Firefox. The extension requires a native messaging host to execute Firefox from the system. After comprehensive analysis, **no malicious code was detected**. However, the extension has a **MEDIUM** security risk profile due to its powerful native messaging capabilities, custom code execution feature, and potential for misuse if the native client is compromised.

**Key Findings:**
- Native messaging with system command execution (com.add0n.node or org.webextension.bun)
- User-configurable custom validation scripts executed in page context (MAIN world)
- Broad content script injection on all URLs
- No external network communication detected
- No credential harvesting or tracking functionality
- Legitimate use case with transparent functionality

## Vulnerability Details

### 1. Native Messaging Command Execution - MEDIUM

**Severity**: MEDIUM
**Files**: `worker.js`, `builder.js`
**Lines**: worker.js:69-84, builder.js:7-64

**Description**:
The extension uses native messaging to execute system commands to launch Firefox. This is the core functionality but presents security risks if the native client is compromised or misconfigured.

**Code Evidence**:
```javascript
// worker.js
function exec(command, args, c, properties = {}) {
  if (command) {
    chrome.storage.local.get({
      'native': 'com.add0n.node'
    }, prefs => chrome.runtime.sendNativeMessage(prefs.native, {
      arguments: args,
      command,
      cmd: 'exec',
      properties
    }, res => (c || response)(res, chrome.runtime.lastError)));
  }
}

// builder.js - Windows command construction
const cmd = sarg ? `firefox ${sarg}` : `firefox &Separated-URLs;`;
return {
  command: 'cmd',
  args: ['/s/c', 'start', cmd],
  options: {
    windowsVerbatimArguments: true,
    shell: false
  }
};
```

**Attack Vector**:
- If the native messaging host (com.add0n.node or org.webextension.bun) is compromised, arbitrary system commands could be executed
- User-provided arguments are passed to the command parser, potentially allowing injection if not properly sanitized by the native host
- The extension trusts the native client to safely execute commands

**Verdict**: **MEDIUM RISK** - This is necessary functionality for the extension's purpose. The risk is mitigated by requiring separate installation of the native client, but users must trust both the extension and the native messaging host.

---

### 2. Custom Validation Script Execution - MEDIUM

**Severity**: MEDIUM
**Files**: `data/inject/main.js`, `data/inject/isolated.js`
**Lines**: main.js:13-29, isolated.js:43-48

**Description**:
The extension allows users to configure custom JavaScript that executes in the MAIN world (page context) when validating click events. This provides powerful customization but introduces XSS-style risks.

**Code Evidence**:
```javascript
// main.js (MAIN world - page context)
const block = e => {
  // run user-script
  const script = document.createElement('script');
  script.textContent = port.dataset.script;  // User-provided code
  script.evt = e;
  document.documentElement.append(script);
  script.remove();
  // get data
  if (script.dataset.block === 'true') {
    port.dispatchEvent(new CustomEvent('open', {
      detail: {
        url: script.dataset.url,
        close: script.dataset.close === 'true'
      }
    }));
  }
};

// isolated.js
chrome.storage.onChanged.addListener(e => {
  Object.keys(e).forEach(n => config[n] = e[n].newValue);
  if (e['custom-validation']) {
    port.dataset.script = e['custom-validation'].newValue;
    port.dispatchEvent(new Event('update'));
  }
});
```

**Attack Vector**:
- Malicious actor with access to the user's Chrome profile could inject malicious code via storage
- User error in custom validation script could expose page DOM to unintended access
- The script runs in MAIN world with full page access (though limited communication back to extension)

**Verdict**: **MEDIUM RISK** - This is a power-user feature. The risk is limited to users who explicitly configure custom validation scripts. The extension properly isolates communication between worlds using CustomEvents, preventing direct code injection from web pages.

---

### 3. Broad Content Script Injection - LOW

**Severity**: LOW
**Files**: `manifest.json`, `data/inject/isolated.js`, `data/inject/main.js`
**Lines**: manifest.json:37-51

**Description**:
Content scripts are injected on `<all_urls>` at `document_start` in both ISOLATED and MAIN worlds.

**Code Evidence**:
```json
"content_scripts": [{
  "matches": ["<all_urls>"],
  "js": ["/data/inject/main.js"],
  "run_at": "document_start",
  "all_frames": true,
  "match_about_blank": true,
  "world": "MAIN"
}, {
  "matches": ["<all_urls>"],
  "js": ["/data/inject/isolated.js"],
  "run_at": "document_start",
  "all_frames": true,
  "match_about_blank": true,
  "world": "ISOLATED"
}]
```

**Attack Vector**:
- Performance impact from running on every page
- Potential for web pages to detect the extension presence
- Minor privacy concern (extension enumeration)

**Verdict**: **LOW RISK** - Necessary for the extension's link interception functionality. The content scripts are minimal and perform no data exfiltration.

---

### 4. Powerful Permissions - LOW

**Severity**: LOW
**Files**: `manifest.json`
**Lines**: manifest.json:11-24

**Description**:
The extension requests several powerful permissions, though all are justified for its functionality.

**Permissions Analysis**:
- `activeTab` - Legitimate, for current tab URL access
- `storage` - Legitimate, for user settings
- `contextMenus` - Legitimate, for right-click menu
- `nativeMessaging` - **High privilege**, necessary for Firefox launch
- `declarativeNetRequestWithHostAccess` - For URL filter redirects
- `tabs` (optional) - For opening multiple tabs
- `downloads` (optional) - For native client installation

**Verdict**: **LOW RISK** - All permissions have legitimate justification. The most powerful permission (nativeMessaging) is core to the extension's purpose.

---

## False Positives

| Pattern | File | Reason for False Positive |
|---------|------|---------------------------|
| None detected | - | Clean codebase, no common false positive patterns found |

---

## API Endpoints & External Communication

| Endpoint | Purpose | Risk Level |
|----------|---------|------------|
| https://api.github.com/repos/andy-portmen/native-client/releases/latest | Native client download (helper page only) | LOW |
| https://api.github.com/repos/andy-portmen/native-client-bunjs/releases/latest | BunJS native client download | LOW |
| https://webextension.org/listing/open-in.html | FAQs/feedback page | LOW |
| https://www.youtube.com/watch?v=* | Tutorial videos | LOW |

**Analysis**:
- No analytics or tracking endpoints detected
- No third-party SDK integration
- All network requests are user-initiated or transparent (FAQ page on install/update)
- GitHub API access is only for downloading the native client installer

---

## Data Flow Summary

### Data Collection
- **User Settings**: Stored locally (browser path, custom scripts, automation rules)
- **Tab URLs**: Accessed only when user clicks to open in Firefox
- **No external transmission**: All data remains local

### Data Transmission
- **None to third parties**: No user data is sent to external servers
- **Native messaging only**: URLs are sent to local native client for Firefox launch

### Data Storage
- `chrome.storage.local`: User preferences, custom validation scripts, URL filters
- `chrome.storage.managed`: Optional enterprise policy configuration
- No `chrome.storage.sync`: Settings are not synchronized across devices

### Privacy Analysis
The extension has an excellent privacy profile:
- No telemetry or analytics
- No user tracking
- No credential access
- No cookie harvesting
- URLs only processed locally for Firefox launching

---

## Overall Risk Assessment

**Risk Level**: **MEDIUM**

### Risk Factors:
1. **Native Messaging** (Medium): Requires trusting external native client for command execution
2. **Custom Script Execution** (Medium): Power-user feature that could be misused
3. **Broad Injection** (Low): Content scripts on all URLs
4. **Powerful Permissions** (Low): nativeMessaging is high-privilege

### Mitigating Factors:
1. **No Network Communication**: Extension operates entirely locally
2. **Transparent Functionality**: Code matches stated purpose
3. **Open Source**: Code is readable and auditable
4. **No Obfuscation**: Clean, well-structured code
5. **No Data Exfiltration**: No evidence of tracking or data harvesting
6. **Established Developer**: webextension.org with multiple legitimate extensions

### Recommendations:
1. **Users should verify** the native client source (andy-portmen GitHub repos)
2. **Avoid using** custom validation scripts unless you understand JavaScript security
3. **Enterprise deployments** should use managed storage to pre-configure safe settings
4. **Regular updates** to ensure native client security patches

### Conclusion:
This extension is **LEGITIMATE** and performs as advertised. The MEDIUM risk rating is due to the inherent power of native messaging and custom code execution features, not malicious intent. For users who need to open links in Firefox from Chrome, this extension is a reasonable choice with acceptable security tradeoffs, provided the native client is obtained from official sources.

---

## Report Metadata
- **Analysis Date**: 2026-02-07
- **Analyst**: Claude Sonnet 4.5
- **Code Quality**: High - Clean, well-structured, no obfuscation
- **Documentation**: Excellent - Clear inline comments, comprehensive options UI
- **Confidence Level**: Very High - Complete code review with no suspicious patterns
