# Vulnerability Report: Medium Unlock

## Metadata
- **Extension ID**: babnnfmbjokkeieobamoifmeapbbfhje
- **Extension Name**: Medium Unlock
- **Version**: 1.1.8
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Medium Unlock is a browser extension that claims to provide unlimited access to Medium articles by redirecting users to third-party proxy services. The extension exhibits undisclosed promotional behavior by fetching remote configurations to inject advertisements for other extensions on proxy websites. While the core functionality appears to match the stated purpose, the extension engages in undisclosed promotional activities that could be considered deceptive to users. The extension also opens tabs automatically on install/update with promotional URLs, and sets uninstall URLs to track user removal.

## Vulnerability Details

### 1. MEDIUM: Undisclosed Remote Configuration for Extension Promotion

**Severity**: MEDIUM
**Files**: background.js, content-scripts/freedium.js
**CWE**: CWE-506 (Embedded Malicious Code)
**Description**: The extension fetches a remote JSON configuration file from `news.musko.top/medium-unlock.json` that contains promotional data for other extensions. This configuration is then used to inject extension advertisements into the Freedium proxy pages without user consent or disclosure in the extension's description.

**Evidence**:
```javascript
// background.js:166
async getPromoteProducts() {
  try {
    const o = await fetch("https://news.musko.top/medium-unlock.json");
    return o.ok ? await o.json() : null
  } catch {
    return null
  }
}

// freedium.js:68-112
async createExtensionLists() {
  const r = "medium-unlock-body",
    a = await E.getStorage("promoteProducts");
  if (!a || a.listData.length === 0) return;
  const m = a.listData;
  // Creates injected promotional UI with extension icons, descriptions, and "Add To Chrome" links
  v.innerHTML = `
    <div class="medium-unlock-container" id="extensionContainer">
      <div class="medium-unlock-header">
        <h1 class="medium-unlock-title">Support Our Development</h1>
        ...
      </div>
      ${f()??""}
    </div>
  `;
}
```

**Verdict**: This behavior constitutes undisclosed promotional activity. While not strictly malicious, users are not informed that the extension will inject advertisements for other extensions. This violates user expectations and could be considered deceptive.

### 2. MEDIUM: Automatic Tab Opening with Tracking Parameters

**Severity**: MEDIUM
**Files**: background.js
**CWE**: CWE-201 (Information Exposure Through Sent Data)
**Description**: On installation and updates, the extension automatically opens tabs to promotional URLs with tracking parameters. It also sets an uninstall URL to track when users remove the extension.

**Evidence**:
```javascript
// background.js:147-162
chrome.runtime.onInstalled.addListener(async r => {
  r.reason === "install" && (o(), await this.openURL("install")),
  r.reason === "update" && (o(), n(), await this.openURL("update"))
})

async openURL(o) {
  const n = await this.getPromoteProducts();
  n && (
    o === "install" && n.install.autoOpen && await chrome.tabs.create({
      url: `${n.install.url}?mode=install&name=Medium Unlock`,
      active: !1
    }),
    o === "update" && n.upgrade.autoOpen && await chrome.tabs.create({
      url: `${n.upgrade.url}?mode=upgrade&name=Medium Unlock`,
      active: !1
    }),
    o === "update" && await chrome.tabs.create({
      url: "https://hellohelloworld.notion.site/Medium-Unlock-Changelog-1188c9d5e496805cb9cac0b1d8f33965",
      active: !0
    }),
    n.uninstall.autoOpen ?
      chrome.runtime.setUninstallURL(`${n.uninstall.url}?mode=uninstall&name=Medium Unlock`) :
      chrome.runtime.setUninstallURL("")
  )
}
```

**Verdict**: The extension opens promotional tabs without explicit user consent during install/update events. The uninstall URL allows tracking user removal behavior. While this is common in some free extensions, it should be disclosed to users.

## False Positives Analysis

The static analyzer flagged an exfiltration flow from `document.querySelectorAll → fetch` in the options page. This is a false positive - the code is actually fetching a preload link's href attribute to load module preloads, not exfiltrating user data:

```javascript
// chunks/options-Uy0utADp.js:40
for (const s of document.querySelectorAll('link[rel="modulepreload"]')) l(s);
function l(s) {
  if (s.ep) return;
  s.ep = !0;
  const u = i(s);
  fetch(s.href, u)  // Fetching the module, not exfiltrating data
}
```

The extension's core functionality (redirecting Medium articles to proxy services) is legitimate and matches the stated purpose. The proxy list includes well-known services: Freedium, ReadMedium, 12ft.io, and Archive.is.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| news.musko.top/medium-unlock.json | Fetch remote configuration for extension promotions | None (GET request) | Medium - Enables undisclosed promotional behavior |
| freedium-mirror.cfd | Proxy service for Medium articles | User redirected with article URL | Low - Expected functionality |
| freedium.cfd | Proxy service for Medium articles | User redirected with article URL | Low - Expected functionality |
| readmedium.com | Proxy service for Medium articles | User redirected with article URL | Low - Expected functionality |
| 12ft.io | Paywall bypass service | User redirected with article URL | Low - Expected functionality |
| archive.is | Archive service | User redirected with article URL | Low - Expected functionality |
| hellohelloworld.notion.site | Changelog page | Tracking parameters on update | Low - Informational page |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

Medium Unlock's core functionality is legitimate - it provides access to Medium articles through well-known proxy services. However, the extension engages in two undisclosed practices that elevate it to MEDIUM risk:

1. **Remote Configuration for Promotions**: The extension fetches remote configuration to inject advertisements for other extensions on Freedium pages. This behavior is not disclosed in the extension's description and could be considered deceptive.

2. **Automatic Tab Opening**: The extension automatically opens promotional tabs on install/update with tracking parameters, and sets uninstall tracking URLs.

While these behaviors are not overtly malicious, they represent undisclosed data collection and promotional activities that users are not informed about. The extension does not appear to exfiltrate sensitive user data or perform credential theft, preventing it from being classified as HIGH or CRITICAL risk.

For CLEAN rating, the extension would need to either remove these promotional features or clearly disclose them in the Chrome Web Store listing.
