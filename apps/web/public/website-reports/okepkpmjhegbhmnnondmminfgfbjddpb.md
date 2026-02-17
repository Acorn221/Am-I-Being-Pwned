# Vulnerability Report: Video Ad Block Youtube

## Metadata
- **Extension ID**: okepkpmjhegbhmnnondmminfgfbjddpb
- **Extension Name**: Video Ad Block Youtube
- **Version**: 3.3
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

"Video Ad Block Youtube" is a YouTube ad blocking extension that blocks ads using declarativeNetRequest rules and content script manipulation. While the ad blocking functionality appears legitimate, the extension engages in undisclosed user tracking by transmitting detailed browsing data to a third-party server (ytadskip.com).

The extension collects the user's complete URL for every page visit, a generated user identifier (UID), and referrer information, then sends this data to an external endpoint (`https://ytadskip.com/dynamic/rules/get`). The privacy policy mentions data collection but does not adequately specify what data is collected or how it's used beyond "optimizing functionality." This represents a privacy concern given the breadth of data collection (all URLs visited with `<all_urls>` permission) and the lack of clear user benefit from this server communication.

## Vulnerability Details

### 1. MEDIUM: Undisclosed User Browsing Data Exfiltration

**Severity**: MEDIUM
**Files**: background.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**:
The extension tracks every URL the user visits across all domains and transmits this information to `ytadskip.com` along with a persistent user identifier and referrer data. This occurs via the `chrome.tabs.onUpdated` listener that fires on every tab completion.

**Evidence**:
```javascript
// From deobfuscated/background.js
const BURL = "https://ytadskip.com";

chrome.tabs.onUpdated.addListener((async (e, t, a) => {
  const {status: s} = t, {url: r} = a;
  if ("complete" === s) {
    let t = await getFromStorage("uid");
    const a = await tabInfo(e);
    let s = a?.url;
    if (isValidPage(r) && r !== s) {
      let a = {
        uri: r,        // Current page URL
        uid: t,        // User identifier
        dr: s          // Referrer URL
      };
      await postData(`${BURL}/dynamic/rules/get`, a);
      // Update tracking state...
    }
  }
}))
```

The extension generates a persistent user ID on install:
```javascript
chrome.runtime.onInstalled.addListener((function(e) {
  "install" == e.reason ? chrome.storage.sync.set({
    installDate: Date.now(),
    uid: genrateId(),  // Generates UUID
    showsharebtn: !0
  })
```

**Verdict**:
This is a privacy violation. The extension has `<all_urls>` permission and tracks every HTTP/HTTPS page the user visits, not just YouTube. While the privacy policy mentions "bare minimum data collection," it does not explicitly disclose URL tracking or the purpose of communicating with ytadskip.com. The server response could potentially contain dynamic ad-blocking rules, but this remote configuration mechanism is not disclosed to users and creates a privacy/security risk.

### 2. MEDIUM: Remote Configuration via External Server

**Severity**: MEDIUM
**Files**: background.js
**CWE**: CWE-494 (Download of Code Without Integrity Check)

**Description**:
The extension fetches data from `ytadskip.com/dynamic/rules/get` on every page load, potentially to receive updated ad-blocking rules or configuration. This creates a remote kill-switch/behavior modification mechanism.

**Evidence**:
```javascript
await postData(`${BURL}/dynamic/rules/get`, a);
```

The endpoint name suggests it returns rules, but there's no code visible that processes the response. The `postData` function returns JSON but the result is not captured or used:

```javascript
const postData = async (e, t = {}) => {
  try {
    const a = await fetch(e, {
      method: "POST",
      credentials: "include",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(t)
    });
    return await a.json()
  } catch (e) {}
};
```

**Verdict**:
While remote configuration is not inherently malicious (many ad blockers use filter list updates), the lack of transparency and the fact that browsing data is sent in exchange for these updates is concerning. The extension should use standard public filter lists or clearly disclose the purpose of this server communication.

### 3. LOW: Excessive Host Permissions

**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-250 (Execution with Unnecessary Privileges)

**Description**:
The extension requests `<all_urls>` host permission but only needs access to YouTube and potentially a few video streaming sites (Hotstar, JioCinema as mentioned in the description).

**Evidence**:
```json
"host_permissions": ["<all_urls>"],
"content_scripts": [{
  "matches": ["<all_urls>"],
  "js": ["content.js"],
  "all_frames": true
}]
```

The content script only performs useful work on YouTube (via dynamically registered scripts for `*://*.youtube.com/*`), but the background script tracks all URLs.

**Verdict**:
While technically used (for tracking), this is excessive for the stated purpose of ad blocking. The extension should limit permissions to specific video streaming domains.

## False Positives Analysis

1. **Ad Blocking Functionality**: The extension's core ad-blocking mechanism using declarativeNetRequest rules and content script DOM manipulation is legitimate and expected for this category of extension.

2. **Content Script Code Obfuscation**: The content scripts use helper functions like `JPFR`, `RXRC`, `DC` which appear to be custom scriptlet helpers for JSON manipulation and regex replacement. While these look unusual, they're part of uBlock Origin-style ad-blocking scriptlets and are not inherently malicious.

3. **Storage Usage**: The extension uses `chrome.storage.sync` to persist user preferences (consent, install date, show share button) - this is standard behavior.

4. **Rate Button Injection**: The content.js injects a "Rate Us" button into YouTube pages, which is promotional but not malicious.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| ytadskip.com/dynamic/rules/get | Potentially fetches updated ad-blocking rules | `uri` (current URL), `uid` (user ID), `dr` (referrer) | **MEDIUM** - Sends complete browsing history to third party; unclear purpose; no user disclosure |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
The extension provides legitimate ad-blocking functionality but engages in undisclosed tracking of user browsing behavior. While not actively malicious (no credential theft, no clear monetization of data, no code injection beyond ad blocking), the collection and transmission of complete browsing history to a third-party server without adequate disclosure violates user privacy expectations.

The privacy policy is generic and does not specifically explain what data is collected or why the extension needs to communicate with ytadskip.com. Users installing an "ad blocker" would not reasonably expect their complete browsing history to be transmitted to an external server.

**Recommendation**: The extension should either:
1. Remove the server communication and use local/public filter lists only
2. Clearly disclose the tracking in the privacy policy and store listing with explicit opt-in consent
3. Limit tracking to only YouTube URLs if server-side rules are necessary for ad blocking

**Risk downgrade rationale**: This is not rated HIGH because:
- The privacy policy does mention data collection (albeit vaguely)
- The data is allegedly used for "optimizing functionality" not clearly monetization
- There's no evidence of credential theft or active malware behavior
- The user consents to the privacy policy on first use (though informed consent is questionable)
