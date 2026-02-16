# Vulnerability Report: 秀米插件

## Metadata
- **Extension ID**: fifkoliiibjdpcdfcknjjcpnahhnihid
- **Extension Name**: 秀米插件 (Xiumi Plugin)
- **Version**: 0.0.6
- **Users**: ~60,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This extension provides cross-application content transfer functionality between the Xiumi.us rich text editor and WeChat Official Account (mp.weixin.qq.com) article editor. It enables users to copy formatted content from Xiumi to WeChat MP articles via browser extension messaging. The extension implements a legitimate use case for content transfer but has a medium-severity vulnerability in its postMessage handler that lacks proper origin validation, potentially allowing unauthorized webpages to trigger its messaging functionality.

The extension's scope is limited to the two specific domains (xiumi.us and mp.weixin.qq.com) and does not collect or exfiltrate user data. The vulnerability exists in the message handling logic but requires specific conditions to exploit and is mitigated by the extension's narrow functionality scope.

## Vulnerability Details

### 1. MEDIUM: postMessage Handler Without Origin Validation

**Severity**: MEDIUM
**Files**: scripts/crossoverSource.js
**CWE**: CWE-346 (Origin Validation Error)

**Description**:
The content script injected into xiumi.us pages implements a `window.addEventListener("message")` handler that processes messages with the callee identifier `tn.xover.trigger` without validating the origin of the message sender. While the handler does verify that `source === window` (line 53), it does not check the `origin` parameter of the message event to ensure the message originated from a trusted domain.

**Evidence**:
```javascript
// crossoverSource.js line 73-80
window.addEventListener("message", function(e) {
  var {
    data: t
  } = e;
  "tn.xover.trigger" === t.__tn_callee__ && execMethod(e).then(() => {}).catch(e => {
    console.error("[xover] exec method error: %o", e)
  })
}, !1);

// execMethod function (line 45-72) - no origin validation
async function execMethod(e) {
  const {
    source: t,
    origin: r,
    data: n
  } = e;
  let o = null;
  try {
    if (t !== window) throw new Error("The 'source' is mismatching.");
    // Origin 'r' is extracted but never validated
    if ("tn.xover.trigger" !== n.__tn_callee__) throw new Error("The 'callee' is mismatching.");
    // ... continues to process message
```

**Verdict**:
This is a genuine vulnerability but with LIMITED exploitability. An attacker would need to:
1. Have the user visit a malicious page while also having a xiumi.us page open
2. Know the internal message format (`__tn_callee__`, `__tn_callee_token__`)
3. The exploit impact is limited to triggering content transfer operations to WeChat MP tabs

The vulnerability is rated MEDIUM rather than HIGH because:
- The functionality is narrow (content transfer only, no data exfiltration)
- Requires specific user context (both xiumi.us and mp.weixin.qq.com tabs open)
- No sensitive data is exposed through this pathway
- The extension does not have broad host permissions

**Recommendation**: Add origin validation in the message event handler:
```javascript
if (e.origin !== 'https://xiumi.us' && !e.origin.endsWith('.xiumi.us')) {
  return;
}
```

## False Positives Analysis

### Static Analyzer Flag: externally_connectable
The extension declares `externally_connectable` for `https://xiumi.us/*` and subdomains. This is NOT a vulnerability but the intended functionality—the extension is designed to allow the xiumi.us website to communicate with the extension via chrome.runtime.sendMessage. This is the correct implementation pattern for webpage-to-extension communication.

### Version Check Mechanism
The service worker fetches version information from `https://xiumi.us/api/sys_info/settings` every 60 seconds to check for updates. This is legitimate update notification behavior, not remote configuration for malicious purposes. The extension only displays a badge indicator ("↑") when an update is available.

### Content Injection Pattern
The extension uses `chrome.scripting.executeScript` to inject HTML content into WeChat MP article editor fields (serviceWorker.js line 172-179). This is the core legitimate functionality—transferring user-created content from Xiumi to WeChat. The injected content comes from the user's own Xiumi session, not from external sources.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| xiumi.us/api/sys_info/settings | Version check for update notification | None (GET request) | Low - legitimate update check |
| mp.weixin.qq.com | Content injection target | User-authored HTML content, title, description | None - this is the stated purpose of the extension |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
The extension implements a legitimate and useful content transfer feature for the Chinese market (Xiumi editor → WeChat Official Accounts). The postMessage handler vulnerability represents a real security issue that should be fixed, but the exploitability is limited by:

1. **Narrow attack surface**: Only affects users with both xiumi.us and mp.weixin.qq.com tabs open
2. **Limited impact**: Attackers could only trigger content transfer operations, not steal data or execute arbitrary code
3. **No data exfiltration**: The extension does not send user data to external servers
4. **Scoped permissions**: Host permissions restricted to mp.weixin.qq.com only
5. **Transparent functionality**: The extension's behavior aligns with its stated purpose

The vulnerability should be remediated by adding origin validation to the postMessage handler, which would reduce the risk to LOW/CLEAN. The current implementation poses a moderate risk primarily in scenarios where users might have malicious pages open alongside their legitimate xiumi.us workflow.

**Recommended Actions**:
- Add origin validation to the postMessage event handler
- Consider implementing Content Security Policy headers for additional defense-in-depth
- The extension does not require removal or blocking, but users should be aware of the postMessage vulnerability until patched
