# Vulnerability Report: Open in PDF Reader

## Metadata
- **Extension Name**: Open in PDF Reader
- **Extension ID**: cehiomcamjpnfmemkmpjadaclohoibgo
- **Version**: 0.3.7
- **User Count**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

Open in PDF Reader is a legitimate extension that enables users to open PDF files in external native PDF readers instead of the browser's built-in viewer. The extension requires a companion native messaging host (`com.add0n.node`) that executes system commands to launch external applications.

**Overall Risk Level: MEDIUM**

While the extension appears to be legitimate and open-source, it presents a **MEDIUM** risk profile due to:
1. **Native Messaging with Code Execution**: The extension uses native messaging to execute arbitrary system commands via Node.js `child_process`, which could be exploited if the native host is compromised
2. **Broad Permissions**: Requests sensitive permissions including `<all_urls>` content script injection, downloads, and native messaging
3. **Remote Code Dependency**: Downloads and installs a native client from GitHub releases, creating supply chain risk

No active malicious behavior was detected, but the architectural design presents inherent security risks that users should understand.

## Vulnerability Details

### 1. Native Messaging with Code Execution Capability
**Severity**: MEDIUM
**Files**: `worker.js` (lines 147-213), `data/options/index.js` (lines 82-175)
**Type**: Architectural Security Risk

**Description**:
The extension communicates with a native messaging host (`com.add0n.node`) that executes arbitrary Node.js scripts with access to `child_process`, `os`, `fs`, and `path` modules. The background worker constructs shell commands dynamically and passes them to the native host for execution.

**Code Evidence**:
```javascript
// worker.js:147-186
const script = `
  const os = require('os').platform();
  const cmds = [];

  if (args[1]) {
    cmds.push(args[1] + ' "' + args[0] + '"');
    if (args[1].includes('%ProgramFiles(x86)%')) {
      cmds.push(args[1].replace('%ProgramFiles(x86)%', '%ProgramFiles%') + ' "' + args[0] + '"');
    }
    // ... more command construction
  }

  const run = () => {
    const cmd = cmds.shift();
    require('child_process').exec(cmd, (error, stdout, stderr) => {
      if (error && cmds.length) {
        run();
      }
      // ...
    });
  };
  run();`;

const resp = await chrome.runtime.sendNativeMessage(NATIVE, {
  permissions: ['child_process', 'os'],
  args: [d.filename, prefs.path],
  script
});
```

**Risk Assessment**:
- **Legitimate Use**: Opens PDF files in user-configured external applications
- **Potential Abuse**: If the native host binary is replaced by malware, arbitrary commands could be executed with user privileges
- **Mitigation**: The native host code is open-source and must be manually installed by users

**Verdict**: Legitimate functionality but inherently risky architecture. Users trust the native host integrity.

---

### 2. Download and Execute External Binary
**Severity**: MEDIUM
**Files**: `data/helper/index.js` (lines 50-91)
**Type**: Supply Chain Risk

**Description**:
The extension facilitates downloading the native messaging host from GitHub releases and instructs users to install it, which involves executing installer scripts.

**Code Evidence**:
```javascript
// data/helper/index.js:52-74
const req = new window.XMLHttpRequest();
req.open('GET', 'https://api.github.com/repos/andy-portmen/native-client/releases/latest');
req.responseType = 'json';
req.onload = () => {
  chrome.downloads.download({
    filename: os + '.zip',
    url: req.response.assets.filter(a => a.name === os + '.zip')[0].browser_download_url
  }, () => {
    notify.show('success', 'Download is started. Extract and install when it is done');
  });
};
```

**Risk Assessment**:
- **Supply Chain Attack Vector**: If the GitHub account or repository is compromised, malicious binaries could be distributed
- **HTTPS Protection**: Uses HTTPS for both API and download, preventing MITM attacks
- **User Interaction Required**: Users must manually extract and run installers
- **No Integrity Checking**: No checksum or signature verification of downloaded files

**Verdict**: Standard software distribution model but lacks cryptographic verification. Risk mitigated by GitHub's infrastructure security.

---

### 3. Broad Content Script Injection
**Severity**: LOW
**Files**: `manifest.json` (lines 39-45), `data/inject.js`
**Type**: Permission Escalation Surface

**Description**:
Content script injected into all URLs at document start to intercept PDF link clicks.

**Code Evidence**:
```json
// manifest.json:39-45
"content_scripts": [{
  "match_about_blank": true,
  "matches": ["<all_urls>"],
  "js": ["data/inject.js"],
  "run_at": "document_start",
  "all_frames": true
}]
```

```javascript
// data/inject.js:3-24
function observe(e) {
  const a = e.target.closest('a');
  if (a) {
    let href = (a.href || '').toLowerCase();
    // Google URL redirect handling
    if (/google\.[^./]+\/url?/.test(href)) {
      const tmp = /url=([^&]+)/.exec(href);
      if (tmp && tmp.length) {
        href = decodeURIComponent(tmp[1]);
      }
    }
    if (href.endsWith('.pdf') || href.includes('.pdf?')) {
      e.preventDefault();
      chrome.runtime.sendMessage({method: 'open-in', href: a.href});
    }
  }
}
```

**Risk Assessment**:
- **Minimal Code Footprint**: Only intercepts clicks on PDF links when enabled
- **No Data Collection**: Does not read page content, cookies, or credentials
- **User-Controlled**: Feature disabled by default (`link: false` in storage)
- **Privacy Consideration**: Processes Google redirect URLs, but only for PDF links

**Verdict**: Minimal risk. Functionality is opt-in and narrowly scoped.

---

### 4. Download Monitoring and Session Storage
**Severity**: LOW
**Files**: `worker.js` (lines 65-138)
**Type**: Privacy/State Management

**Description**:
Tracks download IDs in session storage to automatically open PDFs after download completion.

**Code Evidence**:
```javascript
// worker.js:70-86
chrome.downloads.onChanged.addListener(async d => {
  if (d.state && (d.state.current === 'complete' || d.state.current === 'interrupted')) {
    const ps = await chrome.storage.session.get({ids: []});
    const prefs = await storage({delay: 0});
    if (ps.ids.includes(d.id)) {
      if (d.state.current === 'complete') {
        chrome.alarms.create('open:' + d.id, {
          when: Date.now() + prefs.delay * 1000
        });
      }
    }
  }
});
```

**Risk Assessment**:
- **Session-Only**: Download IDs stored only in session storage (cleared on browser restart)
- **No File Content Access**: Only tracks download IDs, not file contents
- **Legitimate Purpose**: Required to trigger external viewer after download

**Verdict**: Standard download management pattern with no privacy concerns.

---

## False Positives

| Pattern | Location | Context | Reason for FP |
|---------|----------|---------|---------------|
| `child_process.exec()` | worker.js:176 | Native host script | Legitimate external app launcher |
| XMLHttpRequest | data/helper/index.js:53 | GitHub API fetch | Legitimate update check for native client |
| `<all_urls>` permission | manifest.json:41 | Content script | Required for PDF link interception (opt-in feature) |
| Google URL parsing | data/inject.js:7-11 | Redirect handler | Legitimate URL extraction from Google search results |

## API Endpoints and Network Calls

| Endpoint | Purpose | Method | Data Sent | Sensitive |
|----------|---------|--------|-----------|-----------|
| `https://api.github.com/repos/andy-portmen/native-client/releases/latest` | Fetch native client latest version | GET | None | No |
| `https://github.com/andy-portmen/native-client/releases` (fallback) | Manual download page | Browser navigation | None | No |
| `https://webextension.org/listing/open-in-pdf-reader.html` | Homepage/FAQ redirect | Browser navigation | Version params in URL | No |
| `https://www.youtube.com/watch?v=HVyk0EWA5F8` | Tutorial video | Browser navigation | None | No |

**Network Summary**: All network calls are HTTPS-only to trusted domains (GitHub, official homepage, YouTube). No user data is transmitted to third parties.

## Data Flow Summary

### Input Sources
1. **User Configuration**: PDF reader path, preferences stored in `chrome.storage.local`
2. **PDF Links**: URLs from clicked links or downloads
3. **Download Events**: Chrome download API events

### Processing
1. **Content Script → Background**: Sends PDF URLs when user clicks links
2. **Background → Native Host**: Constructs shell commands to open PDFs
3. **Native Host → OS**: Executes system commands via Node.js child_process
4. **Session Storage**: Tracks active download IDs temporarily

### Output/Storage
- **Local Storage**: User preferences (reader path, notification settings)
- **Session Storage**: Download IDs (ephemeral)
- **Native Host Communication**: File paths and commands
- **No External Transmission**: No data sent to remote servers beyond version checks

### Sensitive Data Handling
- **File Paths**: Local PDF file paths passed to native host (never transmitted externally)
- **Environment Variables**: Windows ProgramFiles paths accessed via native host (stays local)
- **No Credential Access**: Does not interact with cookies, passwords, or authentication

## Permissions Analysis

| Permission | Justification | Risk Level |
|------------|---------------|------------|
| `storage` | Save user preferences (PDF reader path) | LOW |
| `contextMenus` | Add "Open in PDF Reader" context menu | LOW |
| `notifications` | Display download/error notifications | LOW |
| `nativeMessaging` | Communicate with native PDF launcher | **MEDIUM** |
| `downloads` | Download PDFs and monitor completion | LOW |
| `activeTab` | Get current tab URL for toolbar button | LOW |
| `alarms` | Delayed PDF opening, notification auto-close | LOW |
| Content Script `<all_urls>` | Intercept PDF link clicks | **MEDIUM** |

**High-Risk Permissions**: `nativeMessaging` (enables code execution), `<all_urls>` (broad access, though minimal code)

## Overall Risk Assessment

### Risk Level: MEDIUM

**Reasoning**:
1. **Legitimate Open-Source Extension**: Code is available on GitHub (https://github.com/andy-portmen/open-in-pdf-reader)
2. **Necessary Elevated Privileges**: Native messaging and `<all_urls>` are required for core functionality
3. **No Malicious Indicators**: No obfuscation, no data exfiltration, no credential theft
4. **Architectural Risks**:
   - Native host compromise could enable arbitrary code execution
   - Supply chain risk from GitHub dependency
   - Broad content script scope (though minimal code)

**Threat Model**:
- **Primary Risk**: Compromise of the native messaging host binary
- **Secondary Risk**: Compromise of GitHub repository serving malicious updates
- **User Mitigation**: Manual installation of native host provides visibility and control

### Recommendations for Users
1. **Verify Native Host Source**: Only install native client from official GitHub releases
2. **Review Installer Scripts**: Check install.sh/install.bat before execution
3. **Monitor Permissions**: Be aware extension can execute system commands via native host
4. **Alternative**: Use browser's built-in PDF viewer if native app integration isn't required

### Recommendations for Developers
1. **Implement Checksum Verification**: Verify downloaded native host integrity with SHA-256 hashes
2. **Code Signing**: Sign native host binaries to prevent tampering
3. **Scope Content Script**: Use specific URL patterns instead of `<all_urls>` where possible
4. **CSP Header**: Add Content Security Policy to manifest (currently missing)

## Conclusion

Open in PDF Reader is a **legitimate utility extension** with no detected malicious behavior. The MEDIUM risk rating reflects the inherent security considerations of any extension that:
- Executes native code with system command access
- Injects content scripts broadly across all websites
- Downloads and installs external binaries

Users should understand these architectural risks and verify the integrity of the native messaging host before installation. The extension is appropriate for users who need native PDF application integration and trust the open-source codebase.
