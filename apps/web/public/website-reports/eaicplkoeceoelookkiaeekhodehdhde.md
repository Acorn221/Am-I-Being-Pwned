# Vulnerability Report: Easy Video Downloader

## Metadata
- **Extension ID**: eaicplkoeceoelookkiaeekhodehdhde
- **Extension Name**: Easy Video Downloader
- **Version**: 0.2.1
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Easy Video Downloader is a video downloading extension that monitors media resources loaded on web pages and provides options to download them using either Chrome's built-in download manager or external download managers (Internet Download Manager, GNU Wget, etc.). While the core functionality is legitimate, the extension contains significant security vulnerabilities related to its native messaging implementation that could allow arbitrary command execution on the host system.

The extension uses optional native messaging permissions to communicate with a native client (`com.add0n.node`) for spawning external download manager processes. The implementation allows user-controlled input to be passed directly to `child_process.spawn()` with minimal sanitization, creating a command injection vulnerability. Additionally, the extension downloads and auto-installs the native client from GitHub without proper integrity verification.

## Vulnerability Details

### 1. HIGH: Arbitrary Command Execution via Native Messaging

**Severity**: HIGH
**Files**: data/dialog/downloader/idm.js, data/dialog/downloader/wget.js, data/dialog/downloader/common.js
**CWE**: CWE-78 (OS Command Injection)

**Description**: The extension's external download manager integration allows arbitrary command execution on the host system through native messaging. When users select external download managers (IDM, Wget), the extension sends commands to a native host that executes them using Node.js `child_process.spawn()`. While there is some parsing via a terminal parser, user-controlled URLs and filenames are directly substituted into command templates.

**Evidence**:

From `data/dialog/downloader/idm.js`:
```javascript
chrome.runtime.sendNativeMessage(downloads.id, {
  permissions: ['child_process'],
  args: [executable, ...argv],
  script: String.raw`
    const command = args[0].replace(/%([^%]+)%/g, (_, n) => env[n]);
    function execute() {
      const exe = require('child_process').spawn(command, args.slice(1), {
        detached: true,
        windowsVerbatimArguments: true
      });
```

From `data/dialog/downloader/wget.js`:
```javascript
chrome.runtime.sendNativeMessage(downloads.id, {
  permissions: ['child_process', 'path', 'os', 'crypto', 'fs'],
  args: [cookies, executable, ...argv],
  script: String.raw`
    const exe = require('child_process').spawn(command, args.slice(2), {
      detached: true,
      windowsVerbatimArguments: true
    });
```

From `data/dialog/downloader/common.js`:
```javascript
downloads.parse = (str, {url, filename}, quotes = false) => {
  filename = filename || ' ';
  url = new URL(url);
  const termref = {
    lineBuffer: str.replace(/\[HREF\]/g, url.href)
      .replace(/\[HOSTNAME\]/g, url.hostname)
      .replace(/\[PATHNAME\]/g, url.pathname)
      .replace(/\[HASH\]/g, url.hash)
      .replace(/\[PROTOCOL\]/g, url.protocol)
      .replace(/\[FILENAME\]/g, filename)
      .replace(/\[REFERRER\]/g, args.get('referrer'))
      .replace(/\[USERAGENT\]/g, navigator.userAgent)
      .replace(/\[PROMPT\]/g, () => window.prompt('User input'))
```

**Verdict**: While the extension uses a terminal parser (`termlib_parser.js`) for some sanitization, the native host directly executes commands with user-controlled URLs and filenames. A malicious website could craft URLs or filenames containing shell metacharacters that could escape parsing and execute arbitrary commands. The `windowsVerbatimArguments: true` option on Windows is intended to prevent command injection, but the overall design creates unnecessary attack surface.

### 2. HIGH: Insecure Native Client Distribution

**Severity**: HIGH
**Files**: data/helper/index.js
**CWE**: CWE-494 (Download of Code Without Integrity Check)

**Description**: The extension downloads the native client directly from GitHub without verifying signatures or checksums, opening the door for supply chain attacks or man-in-the-middle attacks.

**Evidence**:

From `data/helper/index.js`:
```javascript
const req = new window.XMLHttpRequest();
req.open('GET', 'https://api.github.com/repos/andy-portmen/native-client/releases/latest');
req.responseType = 'json';
req.onload = () => {
  chrome.downloads.download({
    filename: os + '.zip',
    url: req.response.assets.filter(a => a.name === os + '.zip')[0].browser_download_url
  }, () => {
    toast.notify('Download is started. Extract and install when it is done', 'success', 3000);
```

The extension fetches the latest release metadata from GitHub's API over HTTPS, but there is no integrity verification (no SHA256 hash check, no signature verification) before instructing the user to install the downloaded native client. A compromised GitHub account or successful MITM attack could deliver malicious native code.

**Verdict**: This creates a significant supply chain vulnerability. Native messaging hosts have full system access, so delivering a malicious native client would give attackers complete control over the user's system. The extension should verify cryptographic signatures or at least checksums before recommending installation.

### 3. MEDIUM: Overly Broad Host Permissions

**Severity**: MEDIUM
**Files**: manifest.json, observe.js
**CWE**: CWE-250 (Execution with Unnecessary Privileges)

**Description**: The extension requests `*://*/*` host permissions to monitor all HTTP requests for media resources. While this is technically necessary for its stated functionality (detecting video/audio/image resources on any website), it grants the extension the ability to read and modify all web traffic.

**Evidence**:

From `manifest.json`:
```json
"host_permissions": [
  "*://*/*"
]
```

From `observe.js`:
```javascript
chrome.webRequest.onHeadersReceived.addListener(onHeadersReceived, {
  urls: ['*://*/*'],
  types
}, ['responseHeaders']);
```

The extension monitors all HTTP responses on all websites to detect media files based on content-type headers and file extensions. It injects tracking data into web pages using `chrome.scripting.executeScript()` to maintain lists of detected media resources.

**Verdict**: While overly broad, this permission usage is expected for a video downloader extension that needs to work on any website. However, it creates significant attack surface if the extension were compromised or if malicious code were injected. The extension does not appear to abuse these permissions for data exfiltration or other malicious purposes in its current implementation.

## False Positives Analysis

1. **webRequest monitoring**: The extension's use of `webRequest.onHeadersReceived` to detect media files is legitimate for its stated functionality as a video downloader.

2. **executeScript usage**: The injection of JavaScript to maintain media tracking lists in page context is a reasonable implementation choice for persisting detected resources across the extension's lifecycle.

3. **GitHub API access**: Fetching release information from `api.github.com` is legitimate for checking native client versions, though the implementation lacks integrity verification.

4. **Broad permissions**: While `*://*/*` is very broad, it's necessary for a video downloader that needs to work on any website.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.github.com | Fetch latest native client release info | GET request (no user data) | LOW - HTTPS, but no integrity verification on downloaded binaries |
| webextension.org | Homepage/documentation links | None (just links) | LOW - Informational only |

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**:

While Easy Video Downloader provides legitimate video downloading functionality, it contains two significant security vulnerabilities that elevate its risk level to HIGH:

1. **Command Execution Risk**: The native messaging implementation allows execution of external download manager commands with user-controlled input (URLs, filenames). While there is some parsing, the attack surface is significant, especially when combined with the ability for malicious websites to craft specific URLs or filenames. An attacker could potentially achieve command injection if they can bypass the terminal parser.

2. **Supply Chain Risk**: The extension downloads and recommends installing a native messaging host (which has full system access) without any integrity verification. This creates a critical supply chain vulnerability where a compromised GitHub account or MITM attack could deliver malicious native code with system-level privileges.

3. **Excessive Privileges**: The `*://*/*` host permissions, while necessary for functionality, grant very broad access that could be abused if the extension were compromised.

The extension's core functionality is legitimate, and there is no evidence of malicious intent in the current implementation. However, the security architecture creates significant vulnerabilities that could be exploited by sophisticated attackers. The extension would benefit from:
- Implementing signature verification for native client downloads
- Adding additional input sanitization for command construction
- Considering sandboxing or capability restrictions for the native host
- Implementing Content Security Policy restrictions

**Recommendation**: HIGH risk due to arbitrary command execution potential and insecure native client distribution. The extension should not be installed by security-conscious users without significant security improvements.
