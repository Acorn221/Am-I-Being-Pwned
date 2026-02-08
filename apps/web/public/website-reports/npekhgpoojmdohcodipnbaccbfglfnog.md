# Vulnerability Report: Jibble Time Tracker (npekhgpoojmdohcodipnbaccbfglfnog)

**Extension:** Jibble Time Tracker v1.5.1
**Manifest Version:** 3
**Triage Flags:** V1=4, V2=1 -- innerhtml_dynamic, postmessage_no_origin, dynamic_window_open
**Analysis Date:** 2026-02-06
**Analyst:** Automated Security Review

---

## Executive Summary

**No verified vulnerabilities found.** All triage flags are false positives attributable to well-known third-party library patterns. The extension is a legitimate time-tracking tool that integrates with 21 productivity services (Jira, Google Docs, Notion, Asana, etc.) via content scripts.

---

## Triage Flag Analysis

### Flag 1: `innerhtml_dynamic` (V1 count: 4)

#### Source 1: Vue 3 Runtime (`js/app.686efeb5.js`)

- **Lines 162, 200, 495-496, 577**: Vue 3's `insertStaticContent` and `Gd` DOM patching functions use `innerHTML` with a Trusted Types wrapper (`Bg`).
- **Assessment: FALSE POSITIVE** -- This is the standard Vue 3 runtime template rendering engine. The `Bg` function at line 162 is `Ru.createHTML(e)` (a Trusted Types passthrough: `createHTML: e => e`). These code paths are only invoked by Vue's virtual DOM reconciler with compiler-generated render functions, not with user-controlled strings.

#### Source 2: Quasar Framework Notification System (`js/app.686efeb5.js:10031`)

- **Code:** `if (t.html === !0) l.innerHTML = t.caption ? \`<div>${t.message}</div>...\` : t.message`
- **Assessment: FALSE POSITIVE** -- This is the Quasar (Vue component library) QNotification component. The `html: true` flag is opt-in and only used by developer-authored notification calls. In this extension, notification messages come from the i18n translation function (`$t()`), which returns static locale strings. No user-controlled data flows to these notifications.

#### Source 3: CommonDialog Component (`js/app.686efeb5.js:30927, 30944`)

- **Code:** `innerHTML: e.options.title` and `innerHTML: e.options.message`
- **Assessment: FALSE POSITIVE** -- The `CommonDialog` (class `xk`) receives its `title` and `message` via `Ha.confirm()` / `Ha.open()`. The only call site (line 19107) passes values from `We()` (i18n translation function) parameterized by server-returned organization/user names. These are not attacker-controlled web content.

#### Source 4: Content Script Button Creation (`js/content.js:13`)

- **Code:** `l.innerHTML = a` where `a` is composed from hardcoded SVG icons and static text ("Jibble in"/"Jibble out").
- **Assessment: FALSE POSITIVE** -- All data flowing into `innerHTML` is static: SVG markup from the `d()` function (4 hardcoded SVG templates), CSS class names from string literals, and boolean state from `chrome.storage.local`. No external/user-controlled input reaches this path.

#### Source 5: Integration Scripts (google-docs.js, jira.js, bitbucket.js, etc.)

- **Code pattern:** `jibbleButton.innerHTML = res.innerHTML` where `res` comes from `window.createButton()`.
- **Assessment: FALSE POSITIVE** -- `createButton()` (defined in content.js) only produces hardcoded SVG + static label HTML. The integration scripts merely refresh the button appearance on clock-in/out events.

#### Source 6: TFAVerification Component (`assets/TFAVerification.adc060b9.js:584`)

- **Code:** `innerHTML: u.$t("authorization.messages.loginProtected")`
- **Assessment: FALSE POSITIVE** -- `$t()` is the Vue i18n translation function returning static locale strings.

---

### Flag 2: `postmessage_no_origin` (V2 count: 1)

#### Source 1: Axios Microtask Polyfill (`assets/create-api.4a170ef1.js:9075-9082`)

- **Code:** `Cr.postMessage(r, "*")` with listener checking `n === Cr && i === r`
- **Assessment: FALSE POSITIVE** -- This is the standard Axios `asap` microtask scheduling polyfill. It posts a message to itself (`Cr` = `window`) with a random token (`axios@${Math.random()}`). The listener verifies both `source === window` (self) and `data === randomToken`. This is a well-documented pattern that cannot be exploited cross-origin because:
  1. The token is generated randomly at module load time.
  2. The source check ensures only self-posted messages are processed.
  3. Even if a message matched, the callback only runs queued microtasks (no data extraction).

#### Source 2: Microsoft Teams JS SDK (`js/app.686efeb5.js:25688-25705`)

- **Code:** `Be.parentOrigin = "*"` during initialization, immediately followed by `finally { Be.parentOrigin = null }`.
- **Assessment: FALSE POSITIVE** -- This is the standard `@microsoft/teams-js` SDK initialization flow. The wildcard origin is used transiently for the initial handshake message to the parent Teams host frame, and is immediately cleared. Incoming messages are validated by `ad()` (line 25855), which checks against a hardcoded allowlist of Microsoft domains (teams.microsoft.com, outlook.office.com, etc.) stored at line 24167.

#### Source 3: OIDC Client Session Check (`assets/create-api.4a170ef1.js:11325-11342`)

- **Code:** `window.addEventListener("message", this._message, !1)` with handler checking `a.origin === this._frame_origin && a.source === this._frame.contentWindow`.
- **Assessment: FALSE POSITIVE** -- This is the `oidc-client-ts` library's `CheckSessionIFrame` class implementing the OpenID Connect Session Management spec. Origin is properly validated against the IdP's origin (`this._frame_origin`), and source is verified against the iframe's `contentWindow`.

#### Source 4: OIDC Popup Window Handler (`assets/create-api.4a170ef1.js:12326-12338`)

- **Code:** Message listener with `o.origin !== u` check where `u = e.scriptOrigin ?? window.location.origin`.
- **Assessment: FALSE POSITIVE** -- Origin is validated. Source is also checked (`o.source !== this._window`). Standard `oidc-client-ts` popup authentication flow.

---

### Flag 3: `dynamic_window_open`

#### Source: OIDC Popup Window (`assets/create-api.4a170ef1.js:12461`)

- **Code:** `this._window = window.open(void 0, e, Sc.serialize(r))`
- **Assessment: FALSE POSITIVE** -- This is the `oidc-client-ts` `PopupWindow` class used for OIDC authentication flows. The URL is set later via `location.replace(e.url)` where `e.url` is the authorization endpoint URL from the OIDC configuration. This is standard authentication library behavior.

---

## Permissions Review

| Permission | Justification |
|---|---|
| `contextMenus` | Right-click "Jibble" / "Jibble in with note" menu items |
| `storage` | Stores clock-in state, user preferences, integration settings |
| `scripting` | Injects integration scripts into 21 supported productivity sites |
| `tabs` | Queries tabs to send clock-in/out notifications to content scripts |
| `https://*/*` (host_permissions) | Required for `chrome.scripting.executeScript` on integration sites; used to inject Jibble buttons |

The permissions are proportionate to the extension's stated functionality.

---

## Third-Party Libraries Identified

| Library | Version | Location |
|---|---|---|
| Vue 3 | -- | `js/app.686efeb5.js` (lines 1-800+) |
| Quasar Framework | -- | `js/app.686efeb5.js` (lines 6000-10000+) |
| `@microsoft/teams-js` | 2.x | `js/app.686efeb5.js` (lines 24100-26600+) |
| Axios | -- | `assets/create-api.4a170ef1.js` |
| `oidc-client-ts` | -- | `assets/create-api.4a170ef1.js` (lines 11000-12500+) |

---

## Conclusion

All 6 triage flags (4 V1 + 1 V2 + 1 V3) are **false positives** caused by standard third-party library patterns:

- **Vue 3 runtime** innerHTML for template rendering (known FP)
- **Quasar Framework** notification HTML rendering with developer-controlled content
- **Axios** self-messaging microtask polyfill (known FP)
- **@microsoft/teams-js** SDK initialization with proper origin validation
- **oidc-client-ts** authentication flows with proper origin validation

**Verdict: CLEAN** -- No real vulnerabilities identified. Recommend classifying as CLEAN.
