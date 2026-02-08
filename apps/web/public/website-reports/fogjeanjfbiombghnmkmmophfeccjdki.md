# Vulnerability Report: LockDown Browser

## Metadata
- **Extension Name:** LockDown Browser
- **Extension ID:** fogjeanjfbiombghnmkmmophfeccjdki
- **Version:** 0.4.59
- **Author:** VERSIONPROD (Respondus)
- **Users:** ~6,000,000
- **Manifest Version:** 3
- **Analysis Date:** 2026-02-08

## Executive Summary

LockDown Browser is a well-known commercial exam proctoring extension by Respondus, widely used in educational institutions to lock down browser environments during online exams. The extension is extremely invasive by design -- it disables other extensions, blocks screenshots, prevents copy/paste, forces fullscreen, monitors window focus, hooks XHR requests, clears browsing history, manipulates cookies, and detects virtual machines. However, **all of these behaviors are consistent with its stated purpose** as an exam lockdown/proctoring tool.

The extension communicates exclusively with Respondus-owned infrastructure (smc-service-cloud.respondus2.com, web.respondus.com, and several CloudFront distributions). It does not exhibit malicious behavior such as data exfiltration beyond exam session data, ad/coupon injection, residential proxy infrastructure, or market intelligence SDK activity. There is no evidence of remote code execution, remote config kill switches, or obfuscated malicious payloads.

## Permissions Analysis

| Permission | Justification | Concern |
|---|---|---|
| `system.display` | Detect secondary displays during exam | Legitimate |
| `history` | Clear browsing history after exam | Legitimate |
| `cookies` | Manage LDB challenge/session cookies | Legitimate |
| `storage` | Store exam state | Legitimate |
| `webNavigation` | Inject security scripts on page load | Legitimate |
| `webRequest` | Monitor/intercept navigation during exam | Legitimate |
| `tabs` | Manage exam tabs, close illegal tabs | Legitimate |
| `activeTab` | Inject scripts into active tab | Legitimate |
| `scripting` | Inject page protections, toolbar, milestones | Legitimate |
| `management` | Disable/re-enable other extensions during exam | Legitimate |
| `contentSettings` | Control camera/microphone/popup permissions | Legitimate |
| `browsingData` | Clear form data during exam | Legitimate |
| `declarativeNetRequestWithHostAccess` | Block URLs, redirect, modify User-Agent | Legitimate |
| `clipboardRead` / `clipboardWrite` | Screenshot detection, clipboard clearing | Legitimate |
| `wallpaper` | Set blank wallpaper on ChromeOS during exam | Legitimate |
| `host_permissions: <all_urls>` | Inject security scripts on any LMS page | Legitimate |

**Assessment:** Every permission serves the exam lockdown functionality. The permission set is extremely broad but necessary for the stated purpose.

## Vulnerability Details

### VULN-01: XHR Hooking via eval() (LOW)

- **Severity:** LOW
- **Files:** `background.js` (postPatchListener function)
- **Code:**
  ```javascript
  postPatchListener=eval(postPatchListenerString);
  postPatchListener(patchHandler)
  ```
- **Description:** The extension uses `eval()` to create an XHR interceptor that monitors POST/PATCH requests on exam pages. This hooks `window.XMLHttpRequest` to capture form submission data for milestone tracking (tracking which exam questions have been answered). The eval'd code is a static string from the extension bundle itself, not remotely fetched.
- **Verdict:** The XHR hooking is used for exam question milestone tracking on Blackboard and Canvas LMS platforms. The intercepted data is sent to Respondus servers as question progress milestones. While `eval()` is generally a red flag, the string being eval'd is hardcoded in the bundle. **Not malicious -- standard exam proctoring behavior.**

### VULN-02: Clipboard Monitoring and Clearing (LOW)

- **Severity:** LOW
- **Files:** `background.js` (protectPage function)
- **Code:**
  ```javascript
  setInterval(h, 3e3)  // checks clipboard every 3 seconds
  // h() reads clipboard, detects screenshots (image/png), clears to whitespace
  await navigator.clipboard.writeText(" ".repeat(e))
  ```
- **Description:** During exams, the extension polls the clipboard every 3 seconds. If it detects a PNG image (screenshot), it clears the clipboard and warns the user. After 2 screenshots, the exam is forcibly ended.
- **Verdict:** Anti-cheating measure. The clipboard data is not exfiltrated -- only checked for image content type and cleared. **Legitimate proctoring behavior.**

### VULN-03: Extension Enumeration and Disabling (LOW)

- **Severity:** LOW
- **Files:** `background.js` (manageExtensions function)
- **Code:**
  ```javascript
  const e = await chrome.management.getAll();
  const n = filterExtensions(e, [...a, ...t.allowList], r, [...o, ...t.blockList]);
  for (const e of n) await chrome.management.setEnabled(e.id, false);
  ```
- **Description:** The extension enumerates all installed extensions and disables those not on an allow list during exams. Extensions are re-enabled when the exam ends. A listener prevents re-enabling during the exam.
- **Verdict:** Standard exam lockdown behavior to prevent cheating extensions. Extensions are restored after the exam. **Legitimate.**

### VULN-04: History Deletion (LOW)

- **Severity:** LOW
- **Files:** `background.js`
- **Code:**
  ```javascript
  chrome.history.deleteRange({startTime: e, endTime: Date.now()})
  chrome.history.deleteUrl({url: e})
  ```
- **Description:** Browsing history generated during the exam session is deleted after the exam ends. Only history from the exam timeframe is deleted.
- **Verdict:** Privacy measure to clean up exam-related browsing. Time-scoped, not blanket deletion. **Legitimate.**

### VULN-05: User-Agent Modification (INFO)

- **Severity:** INFO
- **Files:** `background.js`
- **Code:**
  ```javascript
  {header: "User-Agent", operation: "set", value: `${navigator.userAgent} CBEV3 SLVP-CBE-2`}
  ```
- **Description:** Appends "CBEV3 SLVP-CBE-2" to the User-Agent string so LMS servers can detect LockDown Browser is active.
- **Verdict:** Standard behavior for LMS integration. **Legitimate.**

### VULN-06: Integrity Self-Check with Hash Verification (INFO)

- **Severity:** INFO
- **Files:** `background.js` (checkHash function)
- **Code:**
  ```javascript
  t.checkHash = async (e, a) => {
      const r = await fetch(e), o = await r.json();
      return await (0, t.createHash)(o) === a
  };
  ```
- **Description:** On startup, the extension verifies its own manifest.json against a hardcoded hash. If the hash doesn't match (and it's not a dev environment), the extension does not launch. This is a tamper-detection mechanism.
- **Verdict:** Anti-tampering security measure. **Legitimate.**

## False Positive Table

| Pattern | Location | Reason |
|---|---|---|
| `eval()` usage | background.js (postPatchListener) | Evaluates a hardcoded string from the bundle for XHR milestone tracking, not remote code |
| `new Function("return this")` | background.js (webpack runtime) | Standard webpack polyfill for globalThis |
| Clipboard read/write | background.js (protectPage) | Screenshot detection for anti-cheating, not data exfiltration |
| XHR hooking | background.js (postPatchListener) | Exam question milestone tracking, not credential/data theft |
| Extension enumeration | background.js (manageExtensions) | Exam lockdown, extensions re-enabled after exam |
| History deletion | background.js (cleanHistory) | Post-exam cleanup, time-scoped |
| VM detection | background.js (isVirtualMachine) | Anti-cheating measure checking WebGL renderer |
| Cookie manipulation | background.js | LDB session/challenge cookies only |

## API Endpoints Table

| Endpoint | Method | Purpose |
|---|---|---|
| `https://smc-service-cloud.respondus2.com/MONServer/chromebook/exam_start_v3.do` | POST | Notify server exam started |
| `https://smc-service-cloud.respondus2.com/MONServer/chromebook/lab_exam_end.do` | POST | Notify server exam ended |
| `https://smc-service-cloud.respondus2.com/MONServer/chromebook/upload_log_body.do` | POST | Upload exam session logs |
| `https://smc-service-cloud.respondus2.com/MONServer/chromebook/question_timings.do` | POST | Send question milestone timings |
| `https://smc-service-cloud.respondus2.com/MONServer/chromebook/verify_exit_pw.do` | POST | Verify proctor exit password |
| `https://smc-service-cloud.respondus2.com/MONServer/chromebook/verify_test_pw.do` | POST | Verify test password |
| `https://smc-service-cloud.respondus2.com/MONServer/chromebook/decode_bb_user.do` | GET | Decode Blackboard user info |
| `https://smc-service-cloud.respondus2.com/MONServer/chromebook/cbe_handshake.do` | GET | CBE handshake |
| `https://web.respondus.com/` | GET | Connectivity check |
| `https://d1hvyp8wapcgir.cloudfront.net` | GET | CDN connectivity check |
| `https://d9unvfzorf0bo.cloudfront.net` | GET | CDN connectivity check |
| `https://d1hu9sl7n8ouk3.cloudfront.net` | GET | CDN connectivity check |
| `https://d1yb8axa7jtm4t.cloudfront.net` | GET | CDN connectivity check |
| `https://d3gmpnnqf0pogw.cloudfront.net` | GET | CDN connectivity check |
| `https://autolaunch.respondus2.com/` | GET | Auto-launch page |
| `https://studymate.com/psm2/sm.do` | GET | StudyMate connectivity check |

## Data Flow Summary

1. **Launch Phase:** Extension receives launch URL from LMS (Canvas, Blackboard, Moodle, D2L, Schoology, Infinite Campus). Validates hash integrity. Sets up exam session state in chrome.storage.local.
2. **Lockdown Phase:** Disables other extensions, forces fullscreen, blocks context menu, monitors clipboard for screenshots, blocks keyboard shortcuts (Ctrl+P, etc.), detects secondary displays and VMs, clears form data, modifies User-Agent.
3. **Exam Phase:** Monitors tab/window focus. Injects milestone tracking (XHR hooks) to track question progress. Sends question milestones and logs to Respondus servers. Manages exam navigation within allowed domains.
4. **Post-Exam Phase:** Re-enables disabled extensions, clears LDB cookies, clears exam-period browsing history, resets system state, uploads final logs to Respondus servers.

**Data sent to Respondus servers:**
- Exam session events (start, end, early exit reasons)
- Question progress milestones (which questions answered, timing)
- Diagnostic logs (extension version, user agent, installed extensions list, display info)
- Screenshot detection events
- Error logs

**Data NOT collected:** Browsing history content, passwords, personal files, non-exam cookies, keystrokes (beyond blocking), page content beyond LMS exam pages.

## Overall Risk Assessment

**CLEAN**

LockDown Browser is an extremely invasive extension, but its invasiveness is entirely consistent with its intended purpose as an exam proctoring lockdown tool. All network communication goes to Respondus-owned infrastructure. The extension uses no third-party SDKs, no analytics/tracking libraries, no ad injection, and no remote code loading. The `eval()` usage is limited to evaluating hardcoded bundle strings for XHR milestone tracking. The extension includes self-integrity verification and is purpose-built for educational institution exam security. All 6,000,000 users install this at the direction of their educational institutions.
