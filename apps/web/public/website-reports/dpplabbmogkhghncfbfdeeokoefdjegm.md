# Vulnerability Report: Proxy SwitchySharp

## Metadata
- **Extension ID**: dpplabbmogkhghncfbfdeeokoefdjegm
- **Extension Name**: Proxy SwitchySharp
- **Version**: 1.10.7
- **Users**: ~200,000
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

Proxy SwitchySharp is a legacy proxy management extension that allows users to manage and switch between multiple proxy configurations. The extension is based on the open-source "Proxy Switchy!" and "SwitchyPlus" projects and is licensed under GPL v3. While this is a legitimate tool for its intended purpose, the security analysis revealed several coding weaknesses that could potentially be exploited in certain attack scenarios.

The primary security concerns include unsafe postMessage event handling without origin validation, use of eval() for dynamic code execution in a sandboxed iframe, and acceptance of external connections from a specific extension ID (SwitchyOmega). These issues are rated MEDIUM severity because they represent design flaws that could be exploited in combination with other vulnerabilities, though they do not constitute active malicious behavior.

## Vulnerability Details

### 1. MEDIUM: Unsafe postMessage Handling Without Origin Validation

**Severity**: MEDIUM
**Files**: assets/scripts/ruleManager.js (line 573), assets/scripts/sandbox.js (line 57)
**CWE**: CWE-346 (Origin Validation Error)

**Description**: The extension implements a postMessage-based communication system between the background page and a sandboxed iframe for evaluating proxy auto-config rules. The message event listener in ruleManager.js (line 573) accepts messages without validating the origin:

**Evidence**:
```javascript
// ruleManager.js:573
window.addEventListener("message", function (e) {
  var callback = RuleManager._waitingReply[e.data.reqid];
  delete RuleManager._waitingReply[e.data.reqid];
  callback(e.data.profileId);
}, false);
```

And in sandbox.js:
```javascript
// sandbox.js:57-68
window.addEventListener("message", function (e) {
  if (typeof e.data.u2p !== "undefined") {
    try {
      window.u2p = eval(e.data.u2p);  // Dynamic eval of received code
    } catch (e) {
      console.log(e);
    }
  } else if (typeof e.data.match !== "undefined") {
    var profileId = u2p(e.data.match.url, e.data.match.host);
    e.source.postMessage({"reqid": e.data.reqid, "profileId": profileId}, "*");
  }
}, false);
```

**Verdict**: This is a design flaw where any webpage could potentially send crafted postMessage events to interfere with the extension's proxy rule evaluation system. While the sandboxed nature of the iframe provides some isolation, the lack of origin validation is a security weakness. An attacker controlling a webpage could potentially send malicious messages to manipulate the proxy configuration logic.

### 2. MEDIUM: Dynamic Code Execution via eval()

**Severity**: MEDIUM
**Files**: assets/scripts/sandbox.js (line 60)
**CWE**: CWE-95 (Improper Neutralization of Directives in Dynamically Evaluated Code)

**Description**: The sandboxed iframe evaluates code received via postMessage using eval(). While this is contained within a sandboxed iframe (limiting the damage), it represents a dangerous coding pattern.

**Evidence**:
```javascript
// sandbox.js:58-63
if (typeof e.data.u2p !== "undefined") {
  try {
    window.u2p = eval(e.data.u2p);
  } catch (e) {
    console.log(e);
  }
}
```

The code is sent from ruleManager.js which generates PAC-style proxy auto-config scripts:
```javascript
// ruleManager.js:580-582
RuleManager.sandboxFrame.postMessage(
    {"u2p": u2p},
    "*");
```

**Verdict**: This is an intentional design to support dynamic proxy auto-config scripts, similar to how PAC files work. However, using eval() is inherently risky. The sandbox provides isolation, but combined with the lack of origin validation in the postMessage handler, this could potentially be exploited to execute arbitrary JavaScript in the sandbox context.

### 3. LOW: Unrestricted External Messaging Connection

**Severity**: LOW
**Files**: assets/scripts/main.js (lines 265-266)
**CWE**: CWE-862 (Missing Authorization)

**Description**: The extension accepts external connections via chrome.runtime.onConnectExternal but only validates that the sender is from a specific extension ID ('padekgcemlokbadohgkifijomclgjgif' - SwitchyOmega).

**Evidence**:
```javascript
// main.js:265-313
chrome.runtime.onConnectExternal.addListener(function (port) {
  if (port.sender.id != 'padekgcemlokbadohgkifijomclgjgif') return;
  // ... handles disable/enable/getOptions commands
  // ... exposes all localStorage contents via getOptions
});
```

**Verdict**: This is an intentional migration path to allow SwitchyOmega (the successor extension) to disable SwitchySharp and import its settings. The hardcoded extension ID check provides some security, but this exposes all localStorage contents (including proxy configurations and rules) to the external extension. This is likely acceptable for the intended migration use case, but represents a privacy concern if the specific extension ID were compromised.

## False Positives Analysis

1. **Obfuscated Code Flag**: The static analyzer flagged this extension as "obfuscated". However, review of the deobfuscated code shows this is minified jQuery and jQuery UI libraries, not malicious obfuscation. The main extension code is well-commented GPL-licensed code.

2. **Proxy Permission with &lt;all_urls&gt;**: This is expected and necessary functionality for a proxy management extension. The extension needs the proxy permission to configure proxy settings and &lt;all_urls&gt; to apply proxy rules based on the visited URL patterns.

3. **Remote Configuration**: While the extension supports downloading proxy rule lists from remote URLs, this is an opt-in feature for users who want to subscribe to pre-configured proxy rules (such as for bypassing regional restrictions). This is disclosed functionality, not hidden malicious behavior.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| User-configured proxy servers | Forward web traffic | All web traffic when proxy is active | LOW - User configured |
| User-configured rule list URLs | Import proxy rules | None (download only) | LOW - User controlled |

The extension does not make any hardcoded network requests to third-party servers. All network endpoints are user-configured through the options interface.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

Proxy SwitchySharp is a legitimate open-source proxy management tool with a specific security architecture weakness rather than malicious intent. The MEDIUM risk rating is based on:

1. **Unsafe postMessage handling**: Lack of origin validation on critical message handlers creates potential attack surface for malicious websites.

2. **Dynamic eval usage**: While sandboxed, the use of eval() for executing received code is a dangerous pattern that could be exploited in combination with other vulnerabilities.

3. **Legacy codebase**: This is an old extension (last updated with v1.10.7) that has been superseded by SwitchyOmega. The migration code exists to help users transition to the newer extension.

4. **Limited actual exploit risk**: The vulnerabilities require specific attack scenarios and are mitigated by sandboxing and the extension's architecture. No evidence of active exploitation or malicious behavior.

**Recommendations**:
- Users should migrate to SwitchyOmega (the officially recommended successor) which has a modernized codebase
- If continuing to use SwitchySharp, users should be aware it is no longer actively maintained
- The extension itself is not malicious, but its age and coding patterns make it less secure than modern alternatives
