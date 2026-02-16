# Vulnerability Report: NopeCHA: CAPTCHA Solver

## Metadata
- **Extension ID**: dknlfmjaanfblgfdfebhijalfmhmjjjo
- **Extension Name**: NopeCHA: CAPTCHA Solver
- **Version**: 0.5.5
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

NopeCHA is a CAPTCHA-solving extension that uses AI to automatically solve various CAPTCHA challenges (reCAPTCHA, hCAPTCHA, FunCaptcha, Turnstile, etc.). The extension intercepts CAPTCHA challenges on web pages, sends them to the NopeCHA API service (api.nopecha.com) for solving, and automatically fills in the solutions. While the extension is legitimate and operates as disclosed, it uses highly privileged APIs (debugger, scripting, <all_urls>) and sends tab data and CAPTCHA images to external servers for processing.

The extension's security posture is appropriate for its stated purpose as a paid CAPTCHA-solving service. Users should understand that CAPTCHA images and some page context are transmitted to NopeCHA's servers.

## Vulnerability Details

### 1. MEDIUM: Tab Data Sent to Remote API
**Severity**: MEDIUM
**Files**: background.js (lines 209-217, 453-530)
**CWE**: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
**Description**: The extension collects current tab information and sends it to api.nopecha.com as part of the CAPTCHA-solving workflow. The `chrome.tabs.query` API retrieves active tab data which is then packaged and sent in API requests.

**Evidence**:
```javascript
// background.js lines 209-217
async function Ee() {
  let e = await new Promise(t => {
    S.tabs.query({
      active: !0,
      currentWindow: !0
    }, ([n]) => {
      t(n)
    })
  });
  return O.has(e.id) ? [...O.get(e.id)] : []
}

// lines 453-530 - API recognition function
async function je(e) {
  let t = new Headers;
  t.append("accept", "application/json"), t.append("content-type", "application/json");
  let n = typeof e.v == "string" ? de(e.v.split("").map(l => l.charCodeAt(0))) : -1;
  e.key && e.key !== "undefined" && t.append("authorization", `Basic ${e.key}`);
  let r = e.type;
  if (!r) return {
    error: -2,
    message: "Unknown error occured"
  };
  let s = `${(await z()).base_api||j.api.base}${j.api.recognition}/${r}`,
    i;
  for (let l = 30; l > 0 && n === 2385114787; l--) {
    let p = me(s, {
        method: "POST",
        headers: t,
        body: e
      }),
      g = await fetch(s, {
        method: "POST",
        headers: t,
        body: JSON.stringify(e)
      });
```

**Verdict**: This is MEDIUM severity because while the extension does send tab context and CAPTCHA data to external servers, this is the core disclosed functionality of a CAPTCHA-solving service. Users who install the extension expect it to send CAPTCHA challenges to a remote AI service. The data sent is necessary for the service to function. However, users should be aware that page context associated with CAPTCHAs is transmitted externally.

### 2. MEDIUM: Chrome Debugger API for Automation
**Severity**: MEDIUM
**Files**: background.js (lines 729-1320)
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension requests and uses the `debugger` permission to automate mouse movements, clicks, and page interactions for CAPTCHA solving. While this is a highly privileged API typically reserved for developer tools, it's used legitimately here for browser automation.

**Evidence**:
```javascript
// background.js lines 729-745
function k() {
  return chrome.debugger !== void 0
}
async function C() {
  try {
    let e = await chrome.tabs.query({
      active: !0,
      currentWindow: !0
    });
    return e.length === 0 ? null : e[0].id
  } catch {
    return null
  }
}
var m = new ae;
async function Ye(e) {
  return !k() || (e = e ?? await C(), e === null) ? !1 : m.abort(e)
}

// lines 794-809 - Debugger attach/detach
async function ue(e) {
  if (!k() || (e = e ?? await C(), e === null)) return !1;
  try {
    return await chrome.debugger.attach({
      tabId: e
    }, "1.3"), V.add(e), I.has(e) || I.set(e, new Map), !0
  } catch (t) {
    return t.message.includes("already attached") ? (V.add(e), !0) : !1
  }
}
```

**Verdict**: MEDIUM severity. The debugger permission is extremely powerful and allows the extension to control page behavior, inject code, and monitor network activity. However, for a CAPTCHA-solving extension, this level of access is necessary to simulate human interactions convincingly enough to solve modern CAPTCHAs. The extension appears to use it appropriately for mouse movement simulation and element interaction rather than for surveillance or data theft.

## False Positives Analysis

**Obfuscation Flag**: The ext-analyzer flagged the code as "obfuscated". However, examining the code reveals this is webpack/bundler minification, not intentional obfuscation. Variable names are shortened (e, t, n, r) consistent with minification, but the code structure is straightforward and readable. The extension uses standard IIFE patterns and the code matches typical bundled JavaScript.

**Exfiltration Flow**: The ext-analyzer detected a "chrome.tabs.query → fetch" flow as potential exfiltration. While technically accurate, this is the core disclosed functionality of the extension - it must send CAPTCHA data to the NopeCHA API service to get solutions. This is not hidden exfiltration but rather the advertised service model.

**Debugger API Usage**: While the debugger permission is unusual for most extensions, it's appropriate here. CAPTCHA-solving requires sophisticated browser automation that mimics human behavior, which necessitates low-level control over the browser. The extension uses it to simulate mouse movements, clicks, and scrolling to solve CAPTCHAs convincingly.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.nopecha.com | CAPTCHA recognition API | CAPTCHA images, challenge data, user API key, tab context | MEDIUM - Necessary for service, but sends page data externally |
| api.nopecha.com/v1/status | API status and credit check | Extension version, user API key | LOW - Account management |
| www.nopecha.com | Extension website/updates | None (referenced URLs) | LOW - Informational |
| developers.nopecha.com | Documentation links | None (referenced URLs) | LOW - Informational |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

NopeCHA is a legitimate CAPTCHA-solving service that operates as disclosed. The extension's use of high-privilege APIs (debugger, scripting, <all_urls>) is appropriate for its stated purpose of automating CAPTCHA solutions through AI. The data sent to api.nopecha.com (CAPTCHA challenges, images, and page context) is necessary for the service to function.

The MEDIUM rating reflects:

1. **Disclosed Functionality**: The extension clearly states it solves CAPTCHAs using AI, which inherently requires sending CAPTCHA data to external servers.

2. **Appropriate API Usage**: While the debugger and scripting permissions are powerful, they're used legitimately for browser automation needed to interact with complex CAPTCHA challenges.

3. **Privacy Considerations**: Users should understand that CAPTCHA images and some surrounding page context are transmitted to NopeCHA's servers. This is disclosed in the extension's purpose but represents a privacy tradeoff.

4. **Legitimate Service Model**: This is a paid service (requires API key) with clear documentation and transparent operation. The code shows no evidence of hidden data collection or malicious behavior beyond the stated functionality.

5. **No Credential Theft**: The extension does not harvest credentials, inject ads, or perform hidden tracking. Its data collection is limited to what's necessary for CAPTCHA solving.

The extension is not malicious, but users should be aware they're trading CAPTCHA image/context privacy for automated solving convenience. The risk is inherent to the service model rather than malicious implementation.

**Recommendation**: SAFE for users who understand and accept that CAPTCHA data will be sent to external servers for AI processing. Users requiring strict privacy should not use automated CAPTCHA-solving services in general.
