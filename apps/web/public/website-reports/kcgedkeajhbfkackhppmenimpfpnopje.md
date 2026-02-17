# Vulnerability Report: 600% Sound Volume Booster

## Metadata
- **Extension ID**: kcgedkeajhbfkackhppmenimpfpnopje
- **Extension Name**: 600% Sound Volume Booster
- **Version**: 3.1.6
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

600% Sound Volume Booster is a Manifest V3 extension that provides audio volume enhancement functionality by capturing tab audio and applying gain. While its primary functionality is legitimate, the extension implements undisclosed tracking and data collection through remote configuration and third-party iframes loaded from `config.extaddon.site`. The extension injects hidden iframes into an offscreen document for "tagging" purposes and loads external configurations without user disclosure. Additionally, the offscreen document contains a postMessage listener without proper origin validation, creating an attack surface for message injection.

## Vulnerability Details

### 1. MEDIUM: Undisclosed Third-Party Tracking via Hidden Iframes

**Severity**: MEDIUM
**Files**: assets/offscreen-d8fadabd.js, assets/chunk-69d9e57c.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension implements a "tagging" system that loads hidden iframes from `config.extaddon.site` for tracking purposes. When users visit pages matching domains in the remote configuration, the extension injects a hidden iframe to tag the user.

**Evidence**:
```javascript
// offscreen-d8fadabd.js line 27
a.src = `https://config.extaddon.site/tag/?v=${m}&id=` + e.data.id + "&rnd=" + Math.random()
a.id = "tagFrame"
document.body.appendChild(a)
```

```javascript
// chunk-69d9e57c.js line 80-82
if (window.location.href.indexOf("." + n.uid) > -1 ||
    window.location.href.indexOf("//" + n.uid) > -1) {
  u() || (f(s.offscreenTag, n, o => {}),
  localStorage.setItem("tagged", new Date().toISOString()));
}
```

**Verdict**: This constitutes undisclosed third-party tracking. The extension privacy policy and description do not mention external tracking or data sharing with `extaddon.site`. Users visiting certain domains trigger tracking beacons without their knowledge or consent.

### 2. MEDIUM: Remote Configuration with Unrestricted Domain Matching

**Severity**: MEDIUM
**Files**: assets/chunk-69d9e57c.js, assets/chunk-b58cf4dc.js
**CWE**: CWE-494 (Download of Code Without Integrity Check)
**Description**: The extension downloads configuration from `https://config.extaddon.site/` and uses it to determine which domains to track. This remote configuration is loaded without integrity verification and controls extension behavior.

**Evidence**:
```javascript
// chunk-69d9e57c.js line 56-60
async function r() {
  f(s.loadExtConfig, {
    url: "https://config.extaddon.site/?rnd=" + Math.random()
  }, null)
}
```

```javascript
// offscreen-d8fadabd.js line 34-45
a.src = e.data.url
a.id = "configFrame"
document.body.appendChild(a)
const t = await new Promise(s => {
  const d = window;
  d.messageListener = r => {
    s({
      action: n.loadExtConfigSuccess,
      config: r.data
    })
  }
  window.addEventListener("message", d.messageListener, !1)
})
await chrome.runtime.sendMessage(t)
```

**Verdict**: While remote configuration itself is not inherently malicious for legitimate extensions, the lack of disclosure and the use of this configuration for undisclosed tracking elevates the risk. The configuration controls which domains trigger tracking, allowing the developer to arbitrarily expand surveillance.

### 3. LOW: postMessage Listener Without Origin Validation

**Severity**: LOW
**Files**: assets/offscreen-d8fadabd.js
**CWE**: CWE-346 (Origin Validation Error)
**Description**: The offscreen document registers a postMessage listener to receive configuration data from the loaded iframe but does not validate the message origin before processing.

**Evidence**:
```javascript
// offscreen-d8fadabd.js line 38-43
d.messageListener = r => {
  s({
    action: n.loadExtConfigSuccess,
    config: r.data
  }), window.removeEventListener("message", d.messageListener), a.remove()
}, window.addEventListener("message", d.messageListener, !1)
```

**Verdict**: While this listener is in an offscreen document (not a content script with page access), the lack of origin validation is a security weakness. If the config iframe were compromised or redirected, arbitrary configuration could be injected. However, the impact is limited since the iframe is loaded from a controlled domain and the offscreen document has limited privileges.

## False Positives Analysis

The static analyzer flagged a data flow from `chrome.tabs.query` to `*.src(www.w3.org)` as potential exfiltration. This is a false positive - the extension is likely setting an audio element source to a W3C test resource or similar, not exfiltrating tab data to w3.org.

The extension's core volume boosting functionality using `chrome.tabCapture`, `AudioContext`, and gain nodes is legitimate and necessary for the stated purpose. The fullscreen window management is also expected behavior for a media enhancement tool.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| config.extaddon.site | Remote configuration retrieval | Extension version, random nonce | MEDIUM - Controls tracking behavior |
| config.extaddon.site/tag/ | User tracking beacon | Extension version, user ID, domain identifier, random nonce | HIGH - Undisclosed tracking |
| extaddon.site/600-sound-volume/chrome/ | Post-install landing page | None (tab opened on install) | LOW - Standard onboarding |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: The extension's core volume boosting functionality is legitimate and works as advertised. However, the undisclosed tracking implementation via hidden iframes and remote configuration elevates the risk to MEDIUM. The extension collects information about user browsing activity (which domains are visited that match the remote configuration) and sends this to a third-party server (`config.extaddon.site`) without disclosure in the privacy policy or user consent. While not actively malicious or stealing credentials, this constitutes a clear privacy violation and violates Chrome Web Store policies regarding disclosure of data collection practices.

The extension should disclose its tracking practices, obtain user consent, and provide an opt-out mechanism to be compliant with privacy standards.
