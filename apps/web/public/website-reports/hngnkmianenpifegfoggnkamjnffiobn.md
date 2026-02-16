# Writer Chrome Extension (hngnkmianenpifegfoggnkamjnffiobn) - Vulnerability Report

**Extension:** Writer - "Generative AI in all the places you work"
**Version:** 2.14.7
**Manifest Version:** 3
**Developer:** Writer Inc. (formerly Qordoba)
**Analysis Date:** 2026-02-06

---

## Executive Summary

Writer is a legitimate enterprise AI writing assistant extension. The triage system flagged it as SUSPECT with 20 T1, 8 T2, 18 V1, 10 V2 flags across 16 categories. After deep static analysis of all flagged categories, **the vast majority of flags are FALSE POSITIVES** caused by bundled third-party libraries (Sentry SDK, rrweb session replay, MobX, DOMPurify, Firebase Auth, LaunchDarkly, React/ReactDOM, pdf.js).

No residential proxy infrastructure, no malicious data exfiltration, no extension enumeration, and no C2 behavior was found. The extension does have a broad permission surface and sends user-authored text content to Writer's servers for analysis, which is its core function.

**Overall Risk Assessment: LOW**

The extension operates within normal bounds for an enterprise AI writing assistant. The privacy considerations around text content transmission are clearly part of the product's stated purpose and are sent only to first-party Writer servers (`app.writer.com`).

---

## Permission Analysis

| Permission | Justification | Risk |
|---|---|---|
| `tabs` | Track active tab for writing context | LOW - standard for content-aware extensions |
| `cookies` | Store auth tokens (`qToken`) on `writer.com` domain | LOW - first-party auth only |
| `storage` | Persist settings, feature flags, org config | LOW |
| `scripting` | Inject content scripts dynamically (writerApp.js on writer.com) | LOW - only injects on own domain |
| `sidePanel` | Chrome Side Panel API for writing assistant UI | LOW |
| `http://*/`, `https://*/` | Content scripts need to run on all pages for writing assistance | MEDIUM - broad but typical for writing tools |

---

## Triage Flag Analysis

### 1. residential_proxy_vendor (2 flags) -- FALSE POSITIVE

**Verdict: FALSE POSITIVE**

The "proxy" matches are entirely from:

1. **MobX observable proxy** (JavaScript `Proxy` API): Used for reactive state management throughout the extension. Examples at `background.js:7487-7491`, `background.js:9307`, `background.js:9513-9514`. MobX uses `new Proxy()` to create observable objects, arrays, and maps. The pattern `e.proxy_` / `this.proxy_` appears hundreds of times -- all MobX internal state.

2. **rrweb session replay** CSSStyleSheet proxying at `background.js:20697-20755`: Part of Sentry's rrweb integration that wraps `CSSStyleSheet.prototype.insertRule`, `deleteRule`, `replace`, and `replaceSync` with `new Proxy()` to track CSS mutations for session replay.

3. **`[object Proxy]`** toString representation checks at `background.js:5926`, `content.js:6884`.

**There is ZERO evidence of:**
- Bright Data / Luminati / Hola SDK
- SOCKS5 proxy setup
- Peer-to-peer traffic routing
- Residential proxy node enrollment
- Traffic tunneling through user machines

### 2. beacon_exfil (5 flags) -- FALSE POSITIVE

**Verdict: FALSE POSITIVE**

All `navigator.sendBeacon` calls are from the **Google Closure Library channel termination** code, duplicated across multiple bundles:

- `background.js:45529-45530` - Session termination beacon
- `sidePanelButton.js:57339-57340` - Same code
- `onboardingPage.js:57341-57342` - Same code
- `content.js:64544-64545` - Same code
- `sidePanel.js:75807-75808` - Same code

The code at `background.js:45529`:
```javascript
if (Nt(n, "SID", e.K), Nt(n, "RID", t), Nt(n, "TYPE", "terminate"), Am(e, n),
    t = new Sm(e, e.l, t), t.L = 2, t.v = M0(la(n)), n = !1,
    Le.navigator && Le.navigator.sendBeacon) try {
  n = Le.navigator.sendBeacon(t.v.toString(), "")
}
```

This sends a `TYPE=terminate` session cleanup signal with an empty body (`""`). This is standard Google channel library behavior for gracefully closing server-sent event connections. The `SID` and `RID` are session/request IDs for the channel protocol.

The remaining "beacon" references (`data-beacon-article-modal`) are HTML data attributes for help center article modals -- pure UI metadata.

### 3. cookie_access (3 flags) -- LEGITIMATE USE

**Verdict: FALSE POSITIVE (no malicious cookie access)**

Cookie access is used for **first-party authentication only**:

- `background.js:31752-31849`: The `yU()` function creates a cookie storage abstraction with exactly two cookies:
  - `userLoginDetected` (boolean) - set on `writer.com` domain with `secure: true`, 90-day expiry
  - `qToken` (string) - the Writer authentication token

- `background.js:31780-31806`: Standard CRUD operations (`getItem`, `setItem`, `removeItem`) scoped to the Writer API host URL.

- `background.js:55708-55709`: The domain filter `D6()` only matches `writer.com` (production) or `qordoba(test|dev).com` (dev/test environments).

- `background.js:30885`: `cookiesOnChanged` listener monitors for auth cookie changes to keep the extension's auth state synchronized.

No third-party cookie harvesting, no reading cookies from arbitrary domains, no session hijacking patterns.

### 4. script_injection (5 flags) -- LEGITIMATE USE

**Verdict: FALSE POSITIVE**

Script injection is limited to the extension's own functionality:

1. **`chrome.scripting.executeScript`** at `background.js:30892`: Generic wrapper that takes an options parameter -- used for injecting the extension's own content scripts into tabs.

2. **`chrome.scripting.insertCSS`** at `background.js:30923`: Injects the extension's own CSS styles.

3. **`chrome.scripting.registerContentScripts`** at `background.js:31461` and `background.js:58926-58931`: Registers `writerApp.js` to run on `https://${Cn.hostname}/*` (i.e., the Writer app domain only).

4. **`buzzFeedInjectScript.js`**: A tiny 1-line script that listens for `SET_DISABLE_ACTIONS` messages from content scripts to temporarily disable actions on BuzzFeed CMS (a content editor integration). No malicious behavior.

5. **`tinymceInjectScript.js`**: A tiny 1-line script that listens for `SET_TINYMCE_CONTENT` messages to insert content into TinyMCE editors. This is a standard writing tool integration pattern.

6. **Google Docs scripts** (`gdocsInit.js`, `gdocsPreInject.js`, `gdocsPreInjectImpl.js`, `gdocsPreInjectFast.js`): Google Docs integration for the writing assistant using operational transformation (OT) diff algorithms. These are the core of how Writer provides writing suggestions in Google Docs.

### 5. dynamic_function (11 flags) -- FALSE POSITIVE

**Verdict: FALSE POSITIVE**

1. **`Function("return this")`** at `background.js:5345`, `5952`, `32381`: Standard globalThis polyfill pattern. Used by bundled libraries (Lodash-like utilities) to get the global object in environments where `globalThis` is not available.

2. **`new Function("debugger; ...")`** at `background.js:8745`: **MobX trace debugging** -- creates a function with a `debugger` statement for developer trace breakpoints. Only executes when `isTracing_ === Ti.BREAK`, which is a development debugging feature.

3. **`importScripts`** reference at `background.js:53658`: Feature detection check (`typeof qq().importScripts == "function"`) in Firebase SDK to detect Worker environment. Not actually calling importScripts.

### 6. Web Accessible Resources (11 JS files) -- LEGITIMATE BUT NOTABLE

The manifest exposes these resources to `<all_urls>`:

| Resource | Purpose | Risk |
|---|---|---|
| `js/pdfWorker.js` | PDF.js web worker for PDF parsing | LOW |
| `static/content.js` | Main content script | LOW |
| `static/gdocsInit.js` | Google Docs initialization | LOW |
| `static/gdocsPreInjectImpl.js` | Google Docs OT implementation | LOW |
| `static/gdocsPreInjectFast.js` | Google Docs fast-path | LOW |
| `static/gdocsAnnotatedCanvas.js` | Google Docs canvas annotations | LOW |
| `static/buzzFeedInjectScript.js` | BuzzFeed CMS integration | LOW |
| `static/tinymceInjectScript.js` | TinyMCE editor integration | LOW |
| `static/iframeInit.js` | iframe content detection | LOW |
| `static/sidePanel.js` | Side panel UI | LOW |
| `static/codemirror5Script.js` | CodeMirror 5 editor integration | LOW |

These are all integration scripts for different writing surfaces. While web-accessible resources can theoretically be probed for extension detection, this is a well-known extension with millions of users and detection provides minimal attacker advantage.

---

## Data Flow Analysis

### What data is sent to Writer servers

1. **User-authored text content**: Sent to `/api/content/organization/{orgId}/workspace/{wsId}/persona/{pId}/document/{docId}/content` and `/delta/fragmented` endpoints for grammar/style checking. This is the core product function.

2. **Analytics events**: Sent to `/api/analytics/track`, `/api/analytics/identify`, `/api/analytics/anonymous/track`, `/api/analytics/organization/{orgId}/track`. Standard product analytics with event names and properties.

3. **Autocorrect requests**: Sent to `/api/autocorrect/v2/{organizationId}/correction`.

4. **AI generation requests**: Sent to `/api/generation/organization/{orgId}/team/{teamId}/autowrite/stream` and `/command/generate/stream` for AI writing assistance.

5. **Domain status checks**: Sent to `/api/organization/v2/extension/domain/status` with the current domain hostname -- used for enterprise domain allow/block configuration.

### What third-party services receive data

1. **Sentry** (`o1026471.ingest.sentry.io/6549427`): Error/crash reports with 25% sample rate. Standard error monitoring.

2. **LaunchDarkly** (`app.launchdarkly.com`, `clientstream.launchdarkly.com`, `events.launchdarkly.com`): Feature flag evaluation. Context includes `organizationId`, `userId`, `teamId`, `isFree`, `isEnterprise`, `email`, `version`.

3. **Firebase** (`qordoba-prod.firebaseapp.com`): Authentication (Firebase Auth) and possibly Firestore for real-time data sync.

---

## Hardcoded Credentials Assessment

| Credential | Location | Risk |
|---|---|---|
| Sentry DSN `bbac32b2ac1946828893bc55e23696e8` | `background.js:30777` | LOW - Client-side DSN, by design public |
| LaunchDarkly Client ID `6697ab4a8d3d1d108b7cf904` | `background.js:30779` | LOW - Client-side SDK key, by design public |
| Firebase API Key `AIzaSyDUAfLpIJa9zTLFsFLDMYq0FiLa98Hu6Wc` | `background.js:30781` | LOW - Client-side key, by design public |

All of these are client-side keys designed to be embedded in client code. They are not server secrets.

---

## Sentry Session Replay (rrweb) Analysis

**File:** `background.js:19042-24417`

The extension bundles Sentry Session Replay (based on rrweb). This records DOM mutations, CSS changes, mouse movements, and input interactions for error debugging.

**Privacy safeguards observed:**
- `background.js:24214`: Password fields are explicitly blocked (`password: !0` in blockSelector config)
- `background.js:19059`: Elements with `data-rr-is-password` attribute are treated as password fields
- `background.js:19212`: Autocomplete attributes like `current-password`, `new-password`, `cc-number`, `cc-exp`, etc. are detected and masked
- `background.js:22742`: Replay data is only sent when errors occur (error sample rate), not continuously

**Assessment:** While session replay is privacy-sensitive, the implementation follows Sentry's standard SDK with appropriate masking of sensitive fields. This is an industry-standard debugging tool used by thousands of applications.

---

## False Positive Analysis Summary

| Triage Category | Flag Count | Verdict | Root Cause |
|---|---|---|---|
| residential_proxy_vendor | 2 | FALSE POSITIVE | MobX `Proxy` API, rrweb CSS `Proxy` wrapping |
| beacon_exfil | 5 | FALSE POSITIVE | Google Closure Library channel termination, UI data attributes |
| cookie_access | 3 | FALSE POSITIVE | First-party auth tokens on writer.com only |
| script_injection | 5 | FALSE POSITIVE | Own content script injection, editor integrations (TinyMCE, BuzzFeed, CodeMirror, Google Docs) |
| dynamic_function | 11 | FALSE POSITIVE | `Function("return this")` globalThis polyfill (x3), MobX debugger trace (x1), Firebase Worker detection (x1), plus duplicates across bundles |

---

## Genuine Privacy Observations (Not Vulnerabilities)

### 1. Broad Text Content Transmission
- **Severity:** Informational (CVSS N/A)
- **Description:** The extension sends text content from any web page where the user is editing to Writer's servers for grammar/style/AI analysis. This is the core product function and is disclosed in the product description ("Generative AI in all the places you work").
- **Scope:** Only text in active editing areas (INPUT, TEXTAREA, contentEditable elements) -- NOT arbitrary page scraping.
- **Mitigation:** Enterprise customers can configure domain allow/deny lists via `/api/organization/v2/extension/domain/status`. The extension supports per-page opt-in mode (`optInPerPage`).

### 2. Domain Hostname Sent to Server
- **Severity:** Informational (CVSS N/A)
- **File:** `background.js:57310-57321`
- **Description:** The extension sends the current page's domain (e.g., `example.com`) to Writer's API to check if the extension should be active on that domain. This reveals browsing activity to Writer's servers.
- **Context:** This is an enterprise feature allowing IT admins to control which sites the extension operates on.

### 3. Sentry Session Replay
- **Severity:** Informational (CVSS N/A)
- **File:** `background.js:19042-24417`
- **Description:** When errors occur, rrweb session replay data (DOM snapshots) may be sent to Sentry. This could include page content visible at the time of the error.
- **Mitigation:** Password/credit card fields are masked. Only triggered on errors, not continuous recording.

### 4. LaunchDarkly User Context
- **Severity:** Informational (CVSS N/A)
- **File:** `background.js:58612-58617`
- **Description:** Feature flag evaluation sends user context (userId, email, orgId, subscription type) to LaunchDarkly.
- **Context:** Standard feature flag practice. LaunchDarkly is a reputable vendor with SOC2 compliance.

---

## Overall Risk Assessment

**Rating: LOW**

**Rationale:**
- All triage flags (residential_proxy_vendor, beacon_exfil, cookie_access, script_injection, dynamic_function) are **FALSE POSITIVES** caused by bundled libraries.
- The extension communicates exclusively with first-party Writer infrastructure (`app.writer.com`) and well-known, reputable third-party services (Sentry, LaunchDarkly, Firebase).
- No evidence of data harvesting, extension enumeration, proxy node behavior, C2 communication, remote code loading, or any pattern seen in malicious extensions (VeePN, Troywell, Urban VPN, YouBoost).
- Cookie access is strictly limited to Writer's own authentication domain.
- Script injection is limited to the extension's own integration scripts for known editor platforms.
- The broad `host_permissions` are justified by the product's purpose as an all-site writing assistant.

**Recommendation:** This extension should be reclassified from SUSPECT to CLEAN. The high triage flag count is an artifact of the extension's large codebase (1.5M lines across bundles) which includes many third-party libraries that trigger pattern-based detection rules.

---

## Appendix: Triage Improvement Recommendations

Based on this analysis, the following patterns should be added to the false positive filter list:

1. **MobX `Proxy` usage** -- `e.proxy_`, `this.proxy_`, `new Proxy(i.values_,` with MobX observable context should not trigger `residential_proxy_vendor`.
2. **Google Closure Library `sendBeacon`** -- `TYPE", "terminate"` + `sendBeacon` for channel cleanup is not data exfiltration.
3. **rrweb CSSStyleSheet.prototype proxy wrapping** -- `new Proxy(i, { apply:` wrapping CSS methods is session replay instrumentation, not monkey-patching for interception.
4. **`Function("return this")`** globalThis polyfill -- This is the most common false positive pattern for `dynamic_function` across the entire web ecosystem.
5. **`chrome.scripting.executeScript` / `insertCSS` / `registerContentScripts`** -- When used to inject the extension's own bundled scripts (referenced in manifest), these should not trigger `script_injection`.
