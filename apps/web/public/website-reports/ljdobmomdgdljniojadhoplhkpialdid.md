# Katalon Recorder (Selenium tests generator) - Vulnerability Report

**Extension ID:** ljdobmomdgdljniojadhoplhkpialdid
**Version:** 7.1.0
**Manifest Version:** 3
**Publisher:** Katalon LLC
**Category:** Developer Tools (Selenium test recorder/player)
**Analysis Date:** 2026-02-06

---

## Executive Summary

Katalon Recorder is a legitimate Selenium IDE alternative for recording and playing back browser automation test scripts. The extension is **open-source** (Apache 2.0 licensed, forked from SideeX) and its functionality aligns with its stated purpose. The vast majority of the 25 T1 flags are **false positives** caused by the Selenium WebDriver runtime, Google Closure Library (atoms.js), and jQuery -- all of which legitimately require eval() and dynamic script injection to execute user-authored test scripts in the page context.

However, the extension has several **genuine security and privacy concerns** that merit attention:

1. **FingerprintJS Pro v3.9.3** is bundled and used to generate a persistent browser fingerprint ID sent to Katalon's Segment analytics backend -- even before user consent is explicitly confirmed.
2. **Persistent cross-domain tracking cookies** are set on a fictitious domain (`katalon-persistent-domain.com`) to survive storage clears.
3. **Overly broad permissions** (`<all_urls>`, `debugger`, `cookies`, MAIN world content scripts) combined with `externally_connectable: { ids: ["*"] }` creates an attack surface where any installed extension can register capabilities.
4. The **Trusted Types bypass** (`trustedPolicy`) wraps eval/script injection calls with a permissive policy that simply passes through all input, defeating the purpose of Trusted Types.
5. **User-uploaded extension scripts** are eval'd in the MAIN world content script context on every page -- a stored XSS vector if local storage is compromised.

**Overall Risk Assessment: MEDIUM**

This is not malware. It is a legitimate developer tool with aggressive analytics tracking, questionable fingerprinting practices, and architectural security weaknesses that could be exploited by other malicious extensions or a compromised Katalon backend.

---

## Vulnerability Analysis

### VULN-01: FingerprintJS Pro Browser Fingerprinting for Analytics

**Severity:** MEDIUM
**CVSS 3.1:** 4.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N)
**Files:**
- `common/browser-fingerprint2.js:1` (FingerprintJS Pro v3.9.3 -- 262KB bundle)
- `common/get-browser-fingerprint-background.js:7-10`
- `common/get-browser-fingerprint.js:4` (calls `FingerprintJS.load({ region: "ap" })`)
- `common/offscreen.js:14` (offscreen document runs fingerprinting)

**Description:**
The extension bundles FingerprintJS Pro (a commercial browser fingerprinting service) and generates a `visitorId` with a confidence score. This fingerprint is:
- Cached persistently via `getPersistentValue("visitor", ...)` (local storage, sync storage, AND cookies)
- Sent as `browser_id_2` and `browser_id_2_confidence` with every Segment tracking event to `https://backend.katalon.com/api/segment-kr/tracking`
- Included in the uninstall URL parameters

FingerprintJS Pro uses canvas fingerprinting, WebGL fingerprinting, audio fingerprinting, and dozens of other signals to create a cross-session, cross-context unique identifier. This goes well beyond what is needed for basic product analytics and constitutes aggressive user tracking.

**PoC Scenario:**
1. User installs Katalon Recorder
2. Extension immediately generates FingerprintJS Pro `visitorId` via offscreen document
3. Every subsequent tracking event (record, play, export, etc.) sends `browser_id_2` to Katalon's backend
4. Even after clearing browser data, the fingerprint persists via cookie on `katalon-persistent-domain.com`

---

### VULN-02: Persistent Cross-Domain Tracking Cookie on Fictitious Domain

**Severity:** MEDIUM
**CVSS 3.1:** 4.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N)
**File:** `common/persistent-store.js:3,42-54`

**Description:**
The `setPersistentValue()` function stores tracking identifiers (anonymous ID, fingerprint visitor data) in THREE locations simultaneously:
1. `browser.storage.local`
2. `browser.storage.sync` (syncs across Chrome profiles!)
3. A cookie on `http://katalon-persistent-domain.com/` domain `.katalon-persistent-domain.com`

```javascript
const PERSISTENT_STORE_URL = "http://katalon-persistent-domain.com/";
const PERSISTENT_STORE_DOMAIN = ".katalon-persistent-domain.com";
// ...
browser.cookies.set({
    url: PERSISTENT_STORE_URL,
    domain: PERSISTENT_STORE_DOMAIN,
    name: getPersistentCookieName(key),
    value: encodeURIComponent(JSON.stringify(value)),
    expirationDate: new Date("9999-12-31").getTime() / 1000,  // Never expires
});
```

This creates a supercookie on a domain that exists solely for persistent tracking. The expiration is set to year 9999. The triple-store design ensures the ID survives even if users clear one storage type. The `storage.sync` usage means the tracking ID follows the user across devices logged into the same Google account.

**PoC Scenario:**
1. User installs extension, anonymous ID + fingerprint stored in 3 locations
2. User clears localStorage -- ID restored from cookie or sync storage
3. User clears cookies -- ID restored from localStorage or sync storage
4. Only uninstalling the extension fully removes the tracking

---

### VULN-03: Externally Connectable to All Extensions (ids: ["*"])

**Severity:** MEDIUM
**CVSS 3.1:** 5.0 (AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N)
**Files:**
- `manifest.json:41-49` (`externally_connectable.ids: ["*"]`)
- `background/kar.js:267-308` (`onMessageExternal` handler)

**Description:**
The manifest declares `externally_connectable.ids: ["*"]`, meaning ANY other Chrome extension can send messages to Katalon Recorder. The `onMessageExternal` listener at `background/kar.js:267` accepts `katalon_recorder_register` messages that register "capabilities" (export plugins). While the current handler only stores metadata, this creates a trust boundary violation:

```javascript
browser.runtime.onMessageExternal.addListener(function(message, sender) {
    if (message.type === 'katalon_recorder_register') {
        var capabilities = payload.capabilities;
        externalCapabilities[capabilityGlobalId] = {
            extensionId: extensionId,
            capabilityId: capabilityId,
            summary: capability.summary,
            type: capability.type,
            lastPing: now
        };
    }
});
```

A malicious extension could register itself as an export plugin, potentially receiving test data when the user exports. The `matches` array also includes `https://katalon.com/*` and `https://developer.mozilla.org/*`, allowing those origins to send messages to the extension.

---

### VULN-04: User Extension Scripts Eval'd in MAIN World Content Script

**Severity:** MEDIUM-HIGH
**CVSS 3.1:** 6.1 (AV:L/AC:L/PR:L/UI:R/S:C/C:L/I:H/A:N)
**Files:**
- `content/command-receiver.js:31-39`
- `bundles/content.1.bundle.js:31411`

**Description:**
Katalon Recorder allows users to upload "extension scripts" (custom Selenium commands). These scripts are stored in `browser.storage.local['extensions']` and are loaded and eval'd in the **MAIN world** content script on every page:

```javascript
browser.storage.local.get('extensions', function(result) {
    extensions = result.extensions;
    if (extensions) {
        var extensionScripts = Object.values(extensions);
        for (var i = 0; i < extensionScripts.length; i++) {
            var extensionScript = extensionScripts[i];
            eval(trustedPolicy.createScript(`{ ${extensionScript.content} }`));
        }
    }
});
```

The MAIN world execution means these scripts run with the **page's full privileges** on every URL. If an attacker can write to `browser.storage.local` (via another vulnerability, a compromised extension with `storage` access, or physical access), they achieve persistent arbitrary JS execution on every page the user visits.

**PoC Scenario:**
1. A malicious extension with `storage` permission writes to Katalon's `extensions` storage key
2. Every page load, the injected script executes in MAIN world
3. The script can steal cookies, tokens, intercept form submissions, etc.

---

### VULN-05: Trusted Types Policy Bypass (Permissive Pass-Through)

**Severity:** LOW
**CVSS 3.1:** 3.1 (AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N)
**File:** `content/trustedPolicy.js:1-9`

**Description:**
The Trusted Types policy is a complete pass-through that defeats the purpose of the security mechanism:

```javascript
var trustedPolicy = {
  createScriptURL: (url) => url,
  createHTML: (string, sink) => string,
  createScript: string => string,
}
if (window.trustedTypes && window.trustedTypes.createPolicy) {
  trustedPolicy = window.trustedTypes.createPolicy('default2', trustedPolicy);
}
```

Every `eval(trustedPolicy.createScript(...))` call throughout the codebase passes the string directly through without any sanitization. This is used as a wrapper around ~20+ eval calls in the Selenium runtime, selenium-api.js, selenium-browserbot.js, and command-receiver.js.

---

### VULN-06: Password Field Recording

**Severity:** LOW-MEDIUM
**CVSS 3.1:** 3.7 (AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N)
**Files:**
- `content/recorder-handlers.js:48` (`Recorder.inputTypes` includes "password")
- `katalon/ku-recorder-event-handlers.js:21` (same)

**Description:**
The recorder explicitly includes `"password"` in the list of input types it captures:

```javascript
Recorder.inputTypes = ["text", "password", "file", "datetime", "datetime-local",
    "date", "month", "time", "week", "number", "range", "email", "url", "search", "tel", "color"];
```

When recording is active and the user types in a password field, the `change` event handler records the password value as a test step via `this.record("type", this.locatorBuilders.buildAll(eventTarget), eventTarget.value)`. This value is stored in `browser.storage.local` as part of the test case and can be exported. While this is expected behavior for a test recorder (recording login flows), passwords are stored in **plaintext** in local storage with no encryption and no warning to the user.

**Mitigating factor:** Recording only happens when the user has explicitly activated the recorder by clicking the Record button. It is not passive.

---

### VULN-07: WebSocket Connection to localhost (Katalon Studio Integration)

**Severity:** LOW
**CVSS 3.1:** 2.4 (AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)
**File:** `katalon/background.js:210-240`

**Description:**
On startup and install, the extension attempts to connect to a WebSocket at `ws://localhost:{port}/` (default port 50000) to integrate with Katalon Studio desktop application. The connection handler processes commands including `START_INSPECT`, `START_RECORD`, and `HIGHLIGHT_OBJECT`.

While this is a legitimate integration feature, any local process listening on that port could send commands to the extension, potentially triggering recording or object inspection without user awareness.

---

## False Positive Analysis

| Flag Category | Count | Verdict | Explanation |
|---|---|---|---|
| `dynamic_eval` | 17 active + ~10 commented | **FALSE POSITIVE** (architectural) | Selenium WebDriver runtime requires eval() to execute user test scripts (`runScript`, `storeEval`, `assertEval`, etc.), access window properties dynamically, and run Google Closure Library module loading. This is core Selenium IDE functionality. The sandboxed evaluator (`panel/sandbox.js`) properly isolates panel-side eval in an iframe. |
| `document_write_script` | 2 | **FALSE POSITIVE** | Both instances are in Google Closure Library (`goog.global.document.write`) at `content/atoms.js:403` and `bundles/content.1.bundle.js:1358`. This is Closure's legacy module loader, only used as a fallback and never triggered in the extension context. |
| `csp_unsafe_eval` | 1 | **TRUE POSITIVE** (but non-functional) | The manifest CSP `"script-src 'self'; object-src 'self'; unsafe-eval; unsafe-inline;"` is malformed -- `unsafe-eval` and `unsafe-inline` are outside the `script-src` directive and are **ignored** by Chrome MV3. Chrome's MV3 CSP enforcement overrides this. The extension likely copied this from its MV2 manifest. |
| `csp_unsafe_inline` | 1 | **TRUE POSITIVE** (but non-functional) | Same as above -- malformed CSP, ignored by Chrome MV3. |
| `script_injection` | ~15 | **FALSE POSITIVE** | Script injection via `createElement("script")` is used for: (1) injecting `page/prompt.js` to intercept alert/confirm/prompt dialogs during recording (`content/prompt-injecter.js:21`), (2) injecting `page/runScript.js` for the Selenium `runScript` command (`content/runScript-injecter.js:21`), (3) jQuery internal script evaluation, (4) drag-and-drop simulation in selenium-browserbot.js, (5) Closure Library module loading. All are standard Selenium IDE operations. |
| `createElement("iframe")` | ~5 | **FALSE POSITIVE** | Used for: (1) SandboxEvaluator creating sandbox iframe for safe expression evaluation (`panel/js/UI/services/helper-service/SandboxEvaluator.js:24`), (2) FingerprintJS internal iframe for font detection, (3) Socket.IO transport fallback, (4) jQuery utility. |
| `postMessage("*")` | 3 | **MIXED** | `page/runScript.js:21` uses `postMessage({...}, "*")` to communicate results back from page context -- acceptable for this architecture. The SandboxEvaluator also uses `postMessage(script, "*")` to sandbox iframe, which is safe since the iframe is same-origin extension page. |
| `browser.cookies` | ~5 | **TRUE POSITIVE** | Cookies permission used for persistent tracking store on fictitious domain (VULN-02) and reading `kr_campaign_source` cookie for install attribution. |
| `debugger` permission | 1 | **FALSE POSITIVE** | Chrome DevTools Protocol used solely for `DOM.setFileInputFiles` (file upload testing) and `Input.dispatchKeyEvent` (special key simulation) at `background/kar.js:60-157`. Legitimate test automation need. |
| `externally_connectable` | 1 | **TRUE POSITIVE** | `ids: ["*"]` is overly permissive (VULN-03). Should be restricted to known Katalon plugin extension IDs. |

---

## Network Endpoints

| Endpoint | Purpose | Data Sent |
|---|---|---|
| `https://backend.katalon.com/api/segment-kr/tracking` | Segment analytics | anonymousId, email, browser fingerprint, event name, UI actions |
| `https://web-api.katalon.com/wp-json/restful_api/v1/auth/kr/me` | Check logged-in user | Cookies (session) |
| `https://web-api.katalon.com/wp-json/restful_api/v1/hubspot/update-contact` | HubSpot CRM tracking | email, product registration status |
| `ws://localhost:{port}/` | Katalon Studio desktop integration | Test objects, recording commands (local only) |
| `http://katalon-persistent-domain.com/` | Cookie storage domain (never actually fetched) | Persistent tracking IDs via cookie |
| FingerprintJS Pro API (region: "ap") | Browser fingerprinting | Canvas, WebGL, audio, fonts, and ~30 other signals |

**Key observation:** All analytics endpoints are gated by `settingData.setting.tracking` -- the user can disable tracking in settings. However, the `kru_install_application` event bypasses this check and always fires on install (`segment-tracking-services.js:16-17`).

---

## Permissions Analysis

| Permission | Justification | Risk |
|---|---|---|
| `tabs` | Navigate, query tabs for test playback | LOW -- standard for automation |
| `activeTab` | Interact with current tab | LOW |
| `contextMenus` | Right-click record commands (verifyText, etc.) | LOW |
| `downloads` | Export test reports/scripts | LOW |
| `webNavigation` | Track page loads during playback | LOW |
| `notifications` | Update notifications | LOW |
| `cookies` | Persistent tracking store + session check | **MEDIUM** -- used for supercookie |
| `storage` + `unlimitedStorage` | Store test cases, extensions, settings | LOW |
| `debugger` | CDP for file upload + special keys | LOW -- scoped to active test tab |
| `scripting` | Inject content scripts dynamically | LOW -- for test recording |
| `offscreen` | Run fingerprinting in offscreen document | **MEDIUM** -- fingerprinting |
| `host_permissions: <all_urls>` | Record/play tests on any site | EXPECTED for test tool, but HIGH surface area |

---

## Data Flow Summary

### Test Recording (user-initiated)
1. User clicks Record in Katalon panel
2. Content script (`recorder-handlers.js`) attaches DOM event listeners
3. Clicks, types, selects recorded as Selenium commands (including password values)
4. Commands sent via `browser.runtime.sendMessage` to panel
5. Stored in `browser.storage.local` as test case JSON
6. **Data stays local** unless user explicitly exports or uploads to Katalon TestOps

### Analytics Tracking (automatic)
1. On every significant UI action, `trackingSegment()` fires
2. Collects: anonymousId, email (if logged in), browser fingerprint, event type
3. POSTs to `https://backend.katalon.com/api/segment-kr/tracking`
4. Gated by `setting.tracking` flag (except install event)

### No evidence of:
- Test data exfiltration (recorded tests stay in local storage)
- Remote command & control behavior
- Extension enumeration or disabling
- Cryptomining or ad injection
- Page content scraping for non-test purposes

---

## Overall Risk Assessment

**Rating: MEDIUM**

Katalon Recorder is a **legitimate open-source developer tool** that functions as described. The triage flagged it as SUSPECT primarily due to the Selenium WebDriver runtime's inherent need for eval() and dynamic script injection, which are **architectural false positives** for this class of tool.

The genuine concerns are:

1. **Aggressive analytics tracking** with FingerprintJS Pro (commercial-grade browser fingerprinting) and triple-persistence storage, which goes beyond what is standard for an open-source developer tool
2. **Overly permissive `externally_connectable`** allowing any extension to register as a plugin
3. **No encryption of recorded passwords** in local storage
4. **User extension scripts eval'd in MAIN world** creating a stored-XSS-like vector

None of these rise to the level of intentional malicious behavior. The extension does not exfiltrate test data, does not operate as a proxy, does not inject ads, and does not enumerate/disable other extensions. The fingerprinting and tracking are for product analytics (Segment + HubSpot), which while aggressive, is disclosed in their privacy policy and gatable by the user.

**Recommendation:** DOWNGRADE from SUSPECT to REVIEW. Flag the FingerprintJS Pro bundling and persistent cookie tracking for the privacy report.
