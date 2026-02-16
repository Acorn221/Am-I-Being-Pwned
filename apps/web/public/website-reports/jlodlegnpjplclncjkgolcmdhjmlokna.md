# Vulnerability Report: Download with Free Download Manager (FDM)

## Metadata
- **Extension ID**: jlodlegnpjplclncjkgolcmdhjmlokna
- **Extension Name**: Download with Free Download Manager (FDM)
- **Version**: 0.3.5
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This extension provides integration with the Free Download Manager (FDM) desktop application. When downloads are initiated in Chrome, the extension intercepts them and redirects them to FDM via native messaging. The extension's behavior is consistent with its stated purpose and does not engage in undisclosed data collection or malicious activities.

The extension uses the `nativeMessaging` permission to communicate with a native host application (`com.add0n.native_client`), which spawns the FDM desktop application with download URLs as command-line arguments. All network requests are limited to checking for native client updates on GitHub and accessing the extension's homepage. The extension has minimal security concerns, with only a minor issue related to the potential for command injection if user-controlled data were to influence the spawned process arguments.

## Vulnerability Details

### 1. LOW: Potential Command Injection via Native Messaging

**Severity**: LOW
**Files**: worker.js, data/native.js
**CWE**: CWE-78 (OS Command Injection)
**Description**: The extension passes download URLs and other metadata to a native messaging host, which then spawns the FDM executable with these parameters as command-line arguments. While the extension attempts to sanitize inputs by replacing backslashes and using a parser for argument handling, there is theoretical risk if URLs or filenames contain malicious content.

**Evidence**:
```javascript
// worker.js lines 50-120
const execute = async d => {
  const prefs = await chrome.storage.local.get(config.command.guess);
  // ... argument construction ...
  const termref = {
    lineBuffer: prefs.args
      .replace(/\[URL\]/g, url)
      .replace(/\[REFERRER\]/g, d.referrer)
      .replace(/\[FILENAME\]/g, name)
      .replace(/\[DISK\]/g, (d.filename || ''))
      .replace(/\[USERAGENT\]/g, navigator.userAgent)
      .replace(/\\/g, '\\\\')
  };
  p.parseLine(termref);

  const res = await chrome.runtime.sendNativeMessage('com.add0n.native_client', {
    permissions: ['path', 'child_process'],
    args: [prefs.executable, ...termref.argv],
    script
  });
}

// data/native.js lines 10-14
const {spawn} = require('child_process');
const fdm = spawn(command, args.map(s => s.replace(/\[COOKIES\]/g, '.')).slice(1), {
  detached: true,
  windowsVerbatimArguments: false
});
```

**Verdict**: LOW severity because:
1. The native messaging host is a separate application that the user must explicitly install
2. Command construction uses a parser (termlib_parser.js) designed for shell argument handling
3. The extension only processes download URLs from Chrome's download API, which are somewhat sanitized
4. The native host application controls the actual command execution, not the extension directly
5. This is standard behavior for download manager integration extensions

## False Positives Analysis

**Native Messaging Data Flow**: The ext-analyzer flagged a flow from `chrome.storage.local.get` to `chrome.runtime.sendNativeMessage` as potential exfiltration. This is a false positive - the extension legitimately sends user configuration (executable path, command arguments) to the native client to configure how FDM should be launched. This is the documented and expected behavior for native messaging-based download manager integrations.

**Obfuscation Flag**: The ext-analyzer marked the extension as obfuscated. Upon manual review, the code appears to be minimized/bundled (particularly the materialize.js library) but not intentionally obfuscated. The main extension logic in worker.js, context.js, and other files is readable and follows standard extension patterns.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://api.github.com/repos/belaviyo/native-client/releases/latest | Check for native client updates | None (GET request) | NONE - Public GitHub API |
| https://github.com/belaviyo/native-client/releases | Native client download page | None (navigation only) | NONE - Public GitHub page |
| https://webbrowsertools.com/test-download-with/ | Test/demo page | None (navigation only) | NONE - Test functionality page |
| https://webextension.org/listing/download-with.html | Extension homepage | Referrer, version info via URL params | NONE - Standard analytics |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

The extension performs its stated function of integrating Chrome's download manager with the Free Download Manager desktop application. The use of native messaging is appropriate and disclosed through the required permission. The extension does not:

- Collect or exfiltrate user data beyond its stated purpose
- Make undisclosed network requests
- Inject ads or modify web content
- Access sensitive APIs without justification
- Exhibit malicious behavior patterns

The only security concern is the theoretical command injection risk when passing download metadata to the native host, but this is mitigated by:
1. The use of a command-line parser
2. The requirement for users to install and configure the native messaging host
3. Chrome's download API providing some input sanitization
4. Standard escaping of backslashes in arguments

The extension is operating as expected for a download manager integration tool and poses minimal risk to users who understand and intentionally install both the extension and the native FDM application.
