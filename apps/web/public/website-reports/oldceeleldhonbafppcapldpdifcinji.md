# LanguageTool Extension - Security & Privacy Vulnerability Report

**Extension ID:** `oldceeleldhonbafppcapldpdifcinji`
**Version:** 10.0.12
**Author:** LanguageTooler GmbH
**Users:** ~3M
**Manifest Version:** 3
**Date:** 2026-02-06

## Executive Summary

LanguageTool is a legitimate grammar/spell-checking extension that sends all user-typed text to LanguageTool's servers for analysis. The triage flags (11 T1, 10 V1, 6 V2) are overwhelmingly **false positives** caused by duplicated bundler code across 9+ entry points, a standard Giphy API key, and legitimate postMessage usage via MessageChannels. However, there are real **privacy concerns** and a small number of genuine **low-to-medium severity vulnerabilities** worth noting.

**Overall Risk Rating: LOW** (not malicious, but has notable privacy implications for 3M users)

---

## 1. Triage Flag Analysis

### 1.1 dynamic_eval (9 files) -- FALSE POSITIVE

**Files:** background.js, content.js, popup.js, options.js, toolbox.js, validator.js, trial.js, changelog.js, feedbackForm.js

**Verdict: FALSE POSITIVE -- Safari cross-browser compatibility code duplicated across all bundles**

All 9 instances are identical code from the same shared module duplicated into each entry point bundle:

```javascript
// background.js:4830-4834
if ("eval" in e && Ft(e.eval)) {
    if ("safari" in e) try {
        e.eval("window.safari = window.safari || window.parent.safari;")
    } catch {}
    e.eval(r)
}
```

This is `loadContentScripts()` -- a method that fetches the extension's own content script files via `chrome.runtime.getURL()`, joins them, and evals them into iframe windows. The `eval` is only called on the **extension's own bundled JS files**, not arbitrary remote code. The Safari polyfill line sets `window.safari` for cross-browser API compatibility.

The code:
1. Gets the manifest's content_scripts list
2. Fetches each JS file from the extension's own bundle via `chrome.runtime.getURL()`
3. Joins them and calls `e.eval(r)` where `e` is a window/frame reference

This is a standard pattern for injecting extension scripts into iframes that can't be reached by the content_scripts manifest declaration. Not exploitable.

### 1.2 hardcoded_secret (4 files) -- FALSE POSITIVE

**Files:** options.js, toolbox.js, content.js, popup.js

**Verdict: FALSE POSITIVE -- Public Giphy API key for GIF picker feature**

All 4 instances contain the same Giphy API key:
```javascript
apiKey: "sXGNsG8jHYVfhNuNZ0L5oUqUKTPpqgHd"
```

This is a **public-tier Giphy SDK API key** used for the "Toolbox" GIF picker feature. Giphy API keys at this tier are designed to be embedded in client-side applications and have rate limits applied per-key. This is not a credential leak -- it is the intended usage model for Giphy's SDK. The key appears in 4 files because the Toolbox UI component is bundled into each entry point.

No other secrets (AWS keys, OAuth client secrets, database credentials, etc.) were found.

### 1.3 postmessage_no_origin (7+ files) -- FALSE POSITIVE (with one exception)

**Verdict: FALSE POSITIVE -- Mostly MessageChannel port communication (origin-irrelevant); one legitimate window.postMessage with origin**

The vast majority of postMessage calls fall into two categories:

**Category A: MessageChannel.port.postMessage() (SAFE)**
```javascript
this.messageChannel.port1.postMessage(e)
```
MessageChannel port communication is inherently point-to-point and does not require origin validation. Found in: content.js, popup.js, validator.js, toolbox.js, options.js.

**Category B: BroadcastChannel (SAFE)**
```javascript
Dt.postMessage("close_others")  // changelog.js, trial.js
```
BroadcastChannel messages only propagate within the same origin.

**Category C: Scheduler polyfill (SAFE)**
```javascript
I.postMessage(null)  // options.js:151, popup.js:151, etc.
```
This is a standard `MessageChannel`-based `setImmediate` polyfill. The message port is created locally and not exposed.

**One exception worth noting (LOW RISK):**
```javascript
// welcome/managedLoginRedirectUri.js:905
self.opener.postMessage(n, `https://${e}`)
```
This sends login credentials (email + token) to `self.opener` but properly specifies the target origin from a hardcoded allowlist: `languagetoolplus.com`, `languagetool.com`, `languagetool.org` (and www variants). This is correctly implemented.

### 1.4 script_injection -- FALSE POSITIVE

**Verdict: FALSE POSITIVE -- Extension injecting its own bundled scripts**

All `createElement("script")` instances inject the extension's own files:

1. **executor.js injection** (most files): Loads `/content/executor.js` via `chrome.runtime.getURL()`:
   ```javascript
   n.src = fr().runtime.getURL("/content/executor.js")
   ```

2. **Google Docs/Slides injectors**: Loads editor-specific content scripts:
   ```javascript
   e.src = t.runtime.getURL("/content/editors/google/gdocs-content.js")
   ```

3. **Outlook injector**: Loads Outlook-specific content script:
   ```javascript
   e.src = o.runtime.getURL("/content/outlook/content.js")
   ```

4. **Validator/loadValidator.js**: Uses `document.write()` to load its own scripts:
   ```javascript
   s.src = r.getURL(e), document.write(s.outerHTML)
   ```

All scripts are loaded from the extension's own bundle. No remote script loading.

### 1.5 innerHTML_dynamic -- FALSE POSITIVE

**Verdict: FALSE POSITIVE -- i18n string interpolation and DOM templating**

The innerHTML usages are for inserting localized strings from `chrome.i18n.getMessage()`:
```javascript
t.isHTML ? e.innerHTML = ce.getMessage(t.key, t.interpolations) : ...
```

This is a standard i18n pattern where some translations contain HTML formatting (bold, links, etc.). The data source is the extension's own `_locales/` message bundles, not user input. Other innerHTML usage is for the Markdown renderer (marked.js) in the Toolbox UI, rendering extension-controlled content.

### 1.6 document_write (2 files) -- FALSE POSITIVE

**Verdict: FALSE POSITIVE -- Validator loader writing own script tags**

Found in `validator/loadValidator.js` and CSS comments:
```javascript
s.src = r.getURL(e), document.write(s.outerHTML)
g.src = "./validator.js", document.write(g.outerHTML)
```

The `document.write()` calls are in `loadValidator.js`, which is a bootstrap loader for the standalone validator page (`validator.html`). It writes `<script>` tags pointing to the extension's own files. The CSS file "document.write" references are just in comments about a Chrome bug workaround.

---

## 2. Real Vulnerabilities & Privacy Concerns

### 2.1 PRIVACY: All Typed Text Sent to Remote Servers (MEDIUM)

**Severity: MEDIUM (Privacy)**
**Impact: 3M users' text content transmitted to LanguageTool servers**

Every text field the user types in is sent to LanguageTool's API for grammar checking:

```
Primary:   https://api.languagetool.org/v2/check
Premium:   https://api.languagetoolplus.com/v2/check
Fallback:  https://api-fallback.languagetool.org/v2/check
Alt:       https://languagetoolplus.com/api/v2/check
```

The request payload (from `_getRequestData`) includes:
- **Full text content** of the editable field
- User's **preferred languages**
- User's **mother tongue**
- **Email recipient name and address** (when composing emails)
- A/B test group assignments
- User agent identifier
- Instance/session ID

```javascript
// background.js:5699-5707
static _getRequestData(e, t, r) {
    const n = new URLSearchParams, s = { text: e };
    r.recipientInfo && (r.recipientInfo.address || r.recipientInfo.fullName) && (s.metaData = {
        EmailToAddress: r.recipientInfo.address,
        FullName: r.recipientInfo.fullName
    }), n.append("data", JSON.stringify(s));
```

**The email recipient metadata is particularly concerning** -- when checking emails in Outlook or other email clients, the extension sends the recipient's name and email address alongside the text content.

**Consent mechanism:** The extension does have an `allowRemoteCheck` privacy setting that defaults to `false`:
```javascript
DEFAULT_PRIVACY_SETTINGS = {
    allowRemoteCheck: !1,  // false by default
    ...
}
```

On first install, a privacy confirmation dialog is shown. Text checking does not begin until the user consents. **However**, enterprise admins can bypass this via managed settings:
```javascript
static _applyManagedSettings() {
    const { disablePrivacyConfirmation: e } = this._storageController.getManagedSettings();
    !0 === e && this._storageController.updatePrivacySettings({
        allowRemoteCheck: !0,
        acceptedTermsOfServiceVersion: dt
    })
}
```

### 2.2 PRIVACY: Third-Party AI Data Sharing (Opt-In Defaults to TRUE) (MEDIUM)

**Severity: MEDIUM (Privacy)**

The extension has two privacy flags that **default to true** for new users:

```javascript
DEFAULT_PRIVACY_SETTINGS = {
    hasOptedIntoThirdPartyAiGrammarChecking: !0,  // true by default!
    hasOptedIntoThirdPartyAiParaphrasing: !0       // true by default!
}
```

These settings control whether user text can be shared with third-party AI services for grammar checking and paraphrasing. The flags are synced from the server during `_onSyncUserData`:

```javascript
hasOptedIntoThirdPartyAiGrammarChecking: "boolean" == typeof i.opt_in_3rd_party_ai_grammar_checker && i.opt_in_3rd_party_ai_grammar_checker,
hasOptedIntoThirdPartyAiParaphrasing: "boolean" == typeof i.opt_in_3rd_party_ai_paraphraser && i.opt_in_3rd_party_ai_paraphraser
```

For users without a LanguageTool account (userId is null), a migration (`_setPreliminary3rdPartyAiOption`) explicitly sets `hasOptedIntoThirdPartyAiParaphrasing: true`. This is an opt-out model for third-party AI sharing, which is a privacy concern.

### 2.3 PRIVACY: Matomo/Piwik Analytics Tracking (LOW)

**Severity: LOW**

The extension sends analytics to a self-hosted Matomo instance:
```
https://analytics.languagetoolplus.com/matomo/piwik.php
```

Tracked data includes:
- Unique user ID (persistent across sessions)
- Screen resolution
- Extension version
- Subscription status (paid/free)
- Login status
- Preferred languages
- Picky mode status
- Trial status
- Session count / first visit timestamp
- Error events with stack traces
- Feature usage events (applied suggestions, synonyms, etc.)

The tracking respects `hasStatisticsCollectionEnabled` (defaults to `true`) and is disabled when using a custom server or custom login. It is **not** disabled for standard users by default.

**Dictionary words are tracked too** -- when a user adds a word to their dictionary, the actual word is sent as an analytics event:
```javascript
trackDictionaryEvent(e, t, r) {
    // ...
    i.searchParams.append("e_a", `${e}:add_word`),
    i.searchParams.append("e_n", t)  // 't' is the actual word
```

### 2.4 VULN: lt-execute-code Custom Event Code Injection (LOW)

**Severity: LOW**
**Exploitability: LOW** (requires page-level code execution as prerequisite)

The `content/executor.js` script listens for custom DOM events and executes code:

```javascript
document.addEventListener("lt-execute-code", t)
// where t():
function t(t) {
    t && t.detail && t.detail.code && (t.stopImmediatePropagation(), function(t) {
        const n = document.createElement("script"),
            c = document.querySelector("link[nonce], style[nonce], script[nonce]");
        c && c.nonce && n.setAttribute("nonce", c.nonce),
        n.textContent = e ? e.createScript(t) : t,
        (document.head || document.documentElement).append(n), n.remove()
    }(t.detail.code))
}
```

This creates a `<script>` element with arbitrary code from the event's `detail.code` property. It also **steals the page's CSP nonce** from existing script/link/style elements, which allows bypassing Content Security Policy.

**Risk factors:**
- Any script on the page can dispatch `lt-execute-code` with arbitrary JavaScript
- The CSP nonce theft means the injected code runs with the page's full CSP privileges
- This is in the MAIN world (runs in page context), so any XSS on the page could leverage this

**Mitigating factors:**
- Exploiting this requires the attacker already has script execution on the page (via XSS)
- If the attacker already has XSS, they can already execute code -- but the CSP nonce bypass is an escalation
- The executor is only loaded when LanguageTool activates on a page

### 2.5 VULN: Cerberus Browser Fingerprinting (LOW)

**Severity: LOW (Privacy)**

The extension includes a "Cerberus" module for bot/abuse detection that performs canvas fingerprinting:

```javascript
m = "https://cerberus.languagetool.org/"
// Uses OffscreenCanvas or regular Canvas to inspect a PNG:
const r = await this.canvas.inspect(t);
return await this.fetchJwt(r)
```

The flow:
1. Fetches a PNG image from `cerberus.languagetool.org/verify`
2. Renders it on an OffscreenCanvas
3. Reads pixel data via `getImageData()`
4. Sends the result back to get a JWT token

This is used for trial/premium verification (not grammar checking). The canvas rendering behavior varies by GPU/driver, making this a form of device fingerprinting.

### 2.6 PRIVACY: User Activity Statistics Sent to Server (LOW)

**Severity: LOW**

Aggregate writing statistics are sent to `https://api.languagetoolplus.com/statistics/api/store` for logged-in users:

```javascript
const r = {
    source: t.source,
    data: {
        rewritings: t.rewritings,
        ...t.statistics,    // words, sentences, texts, hiddenMatches, premiumMatches, pickyErrors
        ...t.suggestions,   // spelling, grammar, style, punctuation, typography counts
        ...t.meta           // language, writingGoalId, checkLevel
    }
};
```

This is **aggregate count data** (word counts, suggestion counts), not actual text content. Sent with HTTP Basic auth using the user's email and token. Only applies to logged-in users.

### 2.7 PRIVACY: Remote Configuration Fetch (LOW)

**Severity: LOW**

The extension fetches remote configuration from:
```
https://languagetool.org/webextension_config.json
```

The response controls:
- `disabledSites` -- domains where the extension should not run
- `isTrialSupported` -- whether trial is available in user's country
- `geoIpCountry` -- user's country (from server-side GeoIP)

This is a standard pattern but means LanguageTool knows which countries users are in via GeoIP. The configuration fetch includes the extension version and user agent string.

---

## 3. Permissions Analysis

```json
"permissions": ["activeTab", "storage", "contextMenus", "scripting", "alarms"]
```

| Permission | Justification | Risk |
|-----------|---------------|------|
| `activeTab` | Needed to access active tab content for grammar checking | Appropriate |
| `storage` | Settings, dictionary, user preferences | Appropriate |
| `contextMenus` | Right-click "Check text" menu | Appropriate |
| `scripting` | Inject content scripts dynamically | Appropriate |
| `alarms` | Periodic tasks (icon updates, trial checks, syncs) | Appropriate |

**Content scripts run on `<all_urls>`** with `all_frames: true` and `match_about_blank: true`, which is very broad but necessary for a grammar checker that needs to work on every page.

**Notably absent:** No `webRequest`, `tabs`, `history`, `bookmarks`, or `management` permissions. No host permissions beyond what `activeTab` provides.

---

## 4. Network Endpoints Summary

| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `api.languagetool.org/v2/check` | Grammar checking (free) | Full text, language, email recipient info |
| `api.languagetoolplus.com/v2/check` | Grammar checking (premium) | Full text, language, email recipient info |
| `api-fallback.languagetool.org/v2/check` | Failover grammar checking | Same as above |
| `rewriting.languagetoolplus.com` | AI paraphrasing | Selected text |
| `prod-translator.languagetool.org/translator` | Translation feature | Selected text |
| `analytics.languagetoolplus.com/matomo/piwik.php` | Analytics tracking | User ID, events, screen res, version |
| `api.languagetoolplus.com/statistics/api/store` | Usage statistics | Aggregate counts (logged-in users only) |
| `languagetool.org/webextension_config.json` | Remote configuration | Version, user agent |
| `languagetool.org/webextension/user` | User data sync | Email, token |
| `languagetool.org/users/privacy-policy/` | ToS acceptance | Email, token |
| `cerberus.languagetool.org/verify` | Bot detection / trial verification | Canvas fingerprint |
| `languagetool.org/send-feedback/` | Bug reports | User-submitted feedback |
| `qb-grammar-en.languagetool.org` | Phrasal paraphraser (SSE) | Selected text |
| `api.giphy.com/v1/gifs/` | GIF picker (Toolbox feature) | Search queries |

---

## 5. Verdict

### Is this malware? **No.**

LanguageTool is a legitimate grammar checking service that is transparent about its data collection (privacy dialog on install, configurable settings). The extension does not:
- Enumerate or disable other extensions
- Inject ads or modify search results
- Exfiltrate data to third parties (beyond the declared Giphy integration)
- Execute remote code from untrusted sources
- Perform credential theft or session hijacking

### Should 3M users be concerned?

**Moderately.** Users should understand that:

1. **All text typed in any editable field** is sent to LanguageTool servers when the extension is active on a page. This includes passwords typed in plaintext fields, private messages, confidential documents, and financial information.

2. **Email recipient names and addresses** are sent alongside email content when composing in Outlook and similar email clients.

3. **Third-party AI data sharing** is opt-out by default (enabled unless the user explicitly disables it). Users may not realize their text could be processed by third-party AI providers.

4. **The lt-execute-code mechanism** provides a small CSP nonce bypass that could be leveraged by XSS attacks on pages where LanguageTool is active, though this requires pre-existing XSS.

### Triage Summary

| Flag | Count | Verdict |
|------|-------|---------|
| dynamic_eval | 9 files | **FALSE POSITIVE** -- Safari polyfill in shared module across all bundles |
| hardcoded_secret | 4 files | **FALSE POSITIVE** -- Public Giphy API key (intended client-side use) |
| postmessage_no_origin | 7 files | **FALSE POSITIVE** -- MessageChannel ports (origin-irrelevant) |
| script_injection | multiple | **FALSE POSITIVE** -- Extension injects its own scripts via chrome.runtime.getURL() |
| innerHTML_dynamic | multiple | **FALSE POSITIVE** -- i18n message rendering from extension's own locale files |
| document_write | 2 files | **FALSE POSITIVE** -- Validator bootstrap loader writing own script tags |

### Real Issues Found

| Issue | Severity | Type |
|-------|----------|------|
| All typed text sent to LT servers | MEDIUM | Privacy |
| Third-party AI sharing opt-out default | MEDIUM | Privacy |
| Email recipient metadata in API calls | MEDIUM | Privacy |
| lt-execute-code CSP nonce bypass | LOW | Vulnerability |
| Matomo analytics (dictionary words tracked) | LOW | Privacy |
| Cerberus canvas fingerprinting | LOW | Privacy |
| User activity statistics collection | LOW | Privacy |
| Remote configuration (GeoIP disclosure) | LOW | Privacy |

### Recommendation

**Downgrade from SUSPECT to REVIEW.** All T1 triage flags are false positives from duplicated bundler code. The extension is a legitimate product with a clear business model. The privacy concerns are real but are typical for a grammar checking SaaS product. The CSP nonce bypass via lt-execute-code is the only actual vulnerability, and it is low severity (requires pre-existing XSS to exploit).
