# Vulnerability Report: Japanese IO (dccefjeoofjkdjodbkkbncjcipagdnad)

**Extension:** Japanese IO v0.14.1
**Manifest Version:** 3
**Triage Flags:** V1=4, V2=3 (postmessage_no_origin, dynamic_tab_url, dynamic_window_open)
**Date:** 2026-02-06

---

## Executive Summary

Analysis of the Japanese IO Chrome extension identified **1 verified vulnerability** and **1 informational finding**. Multiple triage flags (postmessage_no_origin, dynamic_tab_url, dynamic_window_open) were investigated and determined to be false positives originating from bundled third-party libraries (core-js setImmediate polyfill, Mixpanel SDK, React Router history).

The verified vulnerability involves the `onExternalMessageReceived` handler accepting unauthenticated commands from externally connectable pages, including `http://localhost:5000`, which allows any local process to force user logout and clear authentication state.

---

## Vulnerability 1: Unauthenticated External Message Handler Permits Forced Logout via localhost

**CVSS 3.1:** 4.3 (Medium)
**Vector:** `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L`

**File:** `serviceWorker.bundle.js` (lines 5532-5535)

### Description

The service worker registers a `chrome.runtime.onMessageExternal` listener that processes four commands (`version`, `options`, `update user`, `logout`) without any additional sender validation beyond Chrome's built-in `externally_connectable` filtering.

The `externally_connectable.matches` in `manifest.json` includes:

```json
"externally_connectable": {
  "matches": [
    "http://localhost:5000/*",
    "https://staging.japanese.io/*",
    "https://www.japanese.io/*"
  ]
}
```

The vulnerable handler:

```javascript
t.onExternalMessageReceived = function(e, t, n) {
    return "version" === (null == e ? void 0 : e.message) && n({
        version: chrome.runtime.getManifest().version
    }),
    "options" === (null == e ? void 0 : e.message) && chrome.runtime.openOptionsPage(),
    "update user" === (null == e ? void 0 : e.message) && (0, c.getUserDataWithoutPermissionCheck)(!0),
    "logout" === (null == e ? void 0 : e.message) && S(),
    !0
}
```

The `logout` command (calling `S()` at line 5622-5644) clears the user's stored authentication data by setting `userData: void 0` in extension storage. The `update user` command forces a re-fetch of user data from the server, which could fail or be disrupted.

### Attack Vector

The inclusion of `http://localhost:5000/*` in `externally_connectable` means that **any process on the local machine** that opens a web server on port 5000 and loads a page with JavaScript can send messages to this extension. This is significant because:

1. Port 5000 is a common development port (Flask, various dev servers)
2. No authentication or secret is required -- just the correct message format
3. The attacker does not need to know the extension ID (Chrome resolves it from `externally_connectable`)

Additionally, any XSS on `www.japanese.io` or `staging.japanese.io` would grant the same access.

### PoC Exploit Scenario

**Scenario:** A malicious or compromised local application (or any dev server running on port 5000) serves a page containing:

```html
<!-- Served from http://localhost:5000/ -->
<script>
  // Force logout -- clears user's stored auth data
  chrome.runtime.sendMessage(
    "dccefjeoofjkdjodbkkbncjcipagdnad",
    { message: "logout" }
  );

  // Or enumerate extension version
  chrome.runtime.sendMessage(
    "dccefjeoofjkdjodbkkbncjcipagdnad",
    { message: "version" },
    function(response) {
      console.log("Extension version:", response.version);
      // Exfiltrate version for targeted attacks
    }
  );
</script>
```

**Attack chain:**
1. Attacker runs any process that binds to port 5000 (trivial on shared/compromised machines)
2. User navigates to (or is redirected to) `http://localhost:5000/anything`
3. Page JavaScript sends `{message: "logout"}` to the extension
4. User's auth session is silently cleared
5. Extension stops functioning for authenticated features (word tracking, decoration, etc.)
6. Repeated invocation creates a persistent denial-of-service on the extension

### Impact

- **Integrity:** User's authenticated session is silently destroyed (forced logout)
- **Availability:** Extension's authenticated features become non-functional until user manually re-authenticates
- **Confidentiality:** Extension version number is disclosed, enabling targeted exploitation of version-specific bugs

---

## Informational: Extension Fingerprinting via web_accessible_resources

**Severity:** Informational (not scored)

**File:** `manifest.json` (lines 54-68)

### Description

The manifest declares `web_accessible_resources` with `matches: ["<all_urls>"]`, exposing several image resources and an audio endpoint pattern (`/api/vocabulary/*/audio`) to all websites:

```json
"web_accessible_resources": [{
  "resources": [
    "/images/icons/triangle.svg",
    "/images/powerUp/powerhead-white-green.png",
    "/images/powerUp/powerhead-dark-green.png",
    "/images/icons/close.svg",
    "/images/logos/japanese-io-logo.svg",
    "/images/icons/star.svg",
    "/images/icons/star-grey.svg",
    "/images/icons/speaker.svg",
    "/images/icons/speaker-grey.svg",
    "/api/vocabulary/*/audio"
  ],
  "matches": [ "<all_urls>" ]
}]
```

Any website can attempt to load these resources to determine whether the Japanese IO extension is installed. This enables user profiling and targeted attacks.

### PoC

```javascript
// Any website can detect this extension
const img = new Image();
img.onload = () => console.log("Japanese IO extension is installed");
img.onerror = () => console.log("Extension not installed");
img.src = "chrome-extension://dccefjeoofjkdjodbkkbncjcipagdnad/images/logos/japanese-io-logo.svg";
```

---

## False Positives Investigated

### postmessage_no_origin (FALSE POSITIVE)

All `addEventListener("message", ...)` handlers found across the codebase are instances of the **core-js `setImmediate` polyfill** (task scheduling mechanism), not application-level postMessage listeners. These use MessageChannel ports or numeric task IDs for internal scheduling and do not process external data.

**Locations:**
- `InPageMainScript.bundle.js:24823` -- core-js setImmediate polyfill
- `InPageSelectionButtonScript.bundle.js:3867` -- core-js setImmediate polyfill
- `serviceWorker.bundle.js:8321` -- core-js setImmediate polyfill
- `OptionsPageScript.bundle.js:4469` -- core-js setImmediate polyfill
- `InPageJapaneseIoMessageScript.bundle.js:6888` -- React scheduler MessageChannel port

### dynamic_tab_url (FALSE POSITIVE)

All `chrome.tabs.create({url: ...})` calls construct URLs from `SERVER_URLS`, a hardcoded constant with only 4 entries:

```javascript
t.SERVER_URLS = {
  official: "https://www.japanese.io",
  local: "http://localhost:5000",
  staging: "https://staging.japanese.io",
  dev: "https://dev.japanese.io"
}
```

The `server` setting is read from `chrome.storage.sync` and is only settable via the options page (not externally). URL construction is restricted to `SERVER_URLS[serverKey]`, preventing arbitrary URL injection.

**Locations:**
- `serviceWorker.bundle.js:4983` -- Login URL construction
- `serviceWorker.bundle.js:5446` -- Go-to-app tab creation

### dynamic_window_open (FALSE POSITIVE)

The `window.open(e.dest_url)` at `InPageMainScript.bundle.js:38751` is within the **Mixpanel SDK's** in-app notification handler. The `dest_url` comes from Mixpanel's notification configuration API, not from external postMessage or user input. This is standard Mixpanel SDK behavior.

The `window.location.href = n` patterns at `InPageMainScript.bundle.js:47451-47483` are within the **React Router `history` library**, handling programmatic navigation. These are standard library operations.

---

## Recommendations

1. **Remove `http://localhost:5000/*` from `externally_connectable`** in production builds. Development-only origins should not be included in published extensions. This is the primary remediation for the forced logout vulnerability.
2. **Restrict `web_accessible_resources`** to only the domains that need them (e.g., `*://*.japanese.io/*`) rather than `<all_urls>` to prevent extension fingerprinting.
3. **Add sender validation** in `onExternalMessageReceived` to verify `sender.url` or `sender.origin` matches expected patterns, as defense-in-depth beyond `externally_connectable`.
