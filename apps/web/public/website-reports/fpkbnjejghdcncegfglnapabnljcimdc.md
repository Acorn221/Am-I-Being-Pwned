# Vulnerability Report: Ad Block Wonder - stop ads & Popups

## Metadata
- **Extension ID**: fpkbnjejghdcncegfglnapabnljcimdc
- **Extension Name**: Ad Block Wonder - stop ads & Popups
- **Version**: 3.7
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Ad Block Wonder is a legitimate ad-blocking extension that uses declarativeNetRequest to block ads and trackers. However, it exhibits privacy concerns by collecting user browsing data and sending it to a remote server (wonderadblock.com). On first install, the extension gathers all open tab domains and UTM parameters from Chrome Web Store tabs, then transmits this data along with subsequent browsing history to the backend server. The extension also has a postMessage handler without proper origin validation, creating an attack surface for malicious websites.

While the core ad-blocking functionality appears legitimate and uses standard techniques (DNR rules, cosmetic CSS, scriptlets), the undisclosed data collection and remote configuration mechanism raise privacy concerns that users may not be aware of when installing.

## Vulnerability Details

### 1. MEDIUM: Browsing Data Collection and Exfiltration

**Severity**: MEDIUM
**Files**: src/helper/utils.js, src/broker.js, src/config.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension collects user browsing data and transmits it to a remote server without clear disclosure.

**Evidence**:

1. **First Install Data Collection** (utils.js:200-241):
```javascript
async installDataGathering() {
  const allTabs = await tabs.getAllTabs(1);
  const domains = new Set();
  const utms = {};

  for (const tab of allTabs) {
    if (tab.url) {
      const dom = getHostName(tab.url);
      if (dom) domains.add(dom);

      if (tabs && tabs.isStoreTab(tab)) {
        if (tab.url.includes("an")) {
          try {
            Object.assign(
              utms,
              Object.fromEntries(new URL(tab.url).searchParams.entries())
            );
          } catch {}
        }
      }
    }
  }

  await storage.setItem("installDoms", Array.from(domains), "sync");
  for (const [k, v] of Object.entries(utms)) {
    await storage.setItem(k, v, "sync");
  }
}
```

2. **Ongoing Navigation Tracking** (broker.js:42-100):
```javascript
async function trackTopFrameNavDomain() {
  const NAV_DOMS_KEY = "navDoms";
  const isTop = (() => {
    try {
      return window.top === window;
    } catch {
      return true;
    }
  })();
  if (!isTop) return;

  const domain = domainTrim(location.hostname);
  if (!domain) return;

  try {
    const result = await chrome.storage.sync.get([NAV_DOMS_KEY]);
    let data = result?.[NAV_DOMS_KEY];
    if (!data || typeof data !== "object" || Array.isArray(data)) data = {};

    if (Object.prototype.hasOwnProperty.call(data, domain)) {
      const cur = Number(data[domain]) || 0;
      data[domain] = cur + 1;
    } else {
      data[domain] = 1;
      // Keep the list bounded (max 50 domains)
    }

    await chrome.storage.sync.set({ [NAV_DOMS_KEY]: data });

    setTimeout(async () => {
      try {
        await chrome.runtime.sendMessage({
          eventName: "CHECK_AND_FETCH_DATA",
          params: { domain },
        });
      } catch (e) {}
    }, 5000);
  } catch {}
}
```

3. **Data Transmission to Remote Server** (utils.js:74-179):
```javascript
async fetchData(toFetch = false) {
  let wonderinformation = await storage.getItems("sync");

  const PERSIST_WHITELIST_KEY = "wb_whitelist_domains";
  const allowedDomains =
    (await storage.getItem(PERSIST_WHITELIST_KEY, "local")) || [];
  const extid = ch.runtime.id;

  wonderinformation.allowedDomains = allowedDomains;
  wonderinformation.extid = extid;

  // POST to GET_RESOURCE (wonderadblock.com/wonder-3_7.php)
  const response = await httpClient.post(config.URLS.GET_RESOURCE, {
    body: wonderinformation,
  });

  // Server response updates local storage with blocking rules
  const data = response.data;
  if (data && typeof data === "object") {
    for (const [k, v] of Object.entries(data)) {
      let n = k.startsWith("wonder") ? "sync" : "local";
      await storage.setItem(k, v, n);
    }
  }
}
```

**Verdict**: The extension collects all domains from open tabs at install time, tracks navigation to top-level domains during browsing, and periodically sends this data to wonderadblock.com along with UTM parameters and extension ID. While this may be used for legitimate remote configuration and rule updates, the collection of browsing history is not clearly disclosed in the extension's description ("Block ads and pop-ups on your favorite websites"). The data is stored in chrome.storage.sync, which is synced across devices.

### 2. MEDIUM: Insecure postMessage Handler

**Severity**: MEDIUM
**Files**: src/broker.js
**CWE**: CWE-345 (Insufficient Verification of Data Authenticity)
**Description**: The content script listens for window.postMessage events without properly validating the message origin, allowing malicious websites to send messages to the extension.

**Evidence** (broker.js:1307-1322):
```javascript
window.addEventListener("message", (message) => {
  if (
    !runtime?.id ||
    message.data?.sender !== "wonder-blocker" ||
    !message.data?.eventName
  )
    return;
  runtime.sendMessage({
    eventName: message.data.eventName,
    params: message.data.params,
  });
});

runtime.onMessage.addListener((message) => {
  window.postMessage({ sender: "wonder-blocker", message }, "*");
});
```

**Verdict**: The postMessage listener only checks that `message.data.sender === "wonder-blocker"` but does not validate `message.source` or `message.origin`. Any malicious website can craft a postMessage with the correct structure and trigger extension messages. While the extension's message handlers appear to primarily handle internal events (CHECK_AND_FETCH_DATA, WB_IS_PAUSED_FOR_TAB, etc.), this creates an unnecessary attack surface. The static analyzer correctly flagged this as a HIGH attack surface issue.

## False Positives Analysis

The static analyzer flagged the extension as "obfuscated," but after reviewing the deobfuscated code, this appears to be webpack bundling rather than intentional obfuscation. The code structure is readable and follows standard patterns for Chrome extensions.

The XHR/fetch hooking code found in scriptlet files (prevent-tools.min.js, prune-tools.min.js, trusted-tools.min.js) is **legitimate ad-blocking functionality**, not malicious. These scriptlets are injected into pages to prevent ads from bypassing the blocker by:
- Intercepting XHR/fetch requests to ad servers
- Modifying responses to remove ads from JSON payloads
- Blocking specific request patterns

The special scripts for facebook.js, x.js, reddit.js, pinterest.js, and twitch.js contain site-specific ad-blocking logic (e.g., removing sponsored posts from Facebook's feed), which is expected behavior for an ad blocker.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| wonderadblock.com/wonder-3_7.php | Remote configuration & rule updates | Extension ID, sync storage (installDoms, navDoms, UTM params, extension version, allowed domains) | MEDIUM - Collects browsing history |
| wonderadblock.com/goodbye.php | Uninstall tracking | (Not analyzed - triggered on uninstall) | LOW - Standard analytics |
| wonderadblock.com | Thank you page | None (navigation only) | LOW - Just a landing page |

The extension periodically checks if its configuration data has expired (based on `wondercycle` timestamp) and fetches updated blocking rules from the server. The server responds with:
- `wonderinformation` - User ID
- `wondercycle` - Update interval
- `rules` - Dynamic DNR rules
- `whitelistedDomains` - Backend-controlled allowlist
- `allowedDomains` - Additional bypass list

This remote configuration mechanism allows the publisher to update blocking rules and allowlists without pushing a new extension version, which is a common pattern for ad blockers but also creates a centralized control point.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

Ad Block Wonder is a functional ad-blocking extension with legitimate blocking capabilities using Chrome's declarativeNetRequest API and cosmetic filtering. However, it exhibits **medium-severity privacy concerns**:

1. **Undisclosed data collection**: Collects all open tab domains at install time and tracks top-level navigation domains, sending this browsing history to the publisher's server. This is not clearly disclosed in the extension description.

2. **Remote configuration dependency**: The extension relies on a remote server for configuration updates, allowing the publisher to change blocking behavior or add tracking without user knowledge. While this enables rapid updates, it creates a trust dependency.

3. **Attack surface**: The insecure postMessage handler could potentially be exploited by malicious websites, though the actual impact appears limited based on the message handlers observed.

**Mitigating factors**:
- No credential theft or session hijacking
- Ad-blocking functionality appears legitimate
- Uses standard MV3 APIs (declarativeNetRequest, scripting)
- No evidence of affiliate injection or ad replacement
- 200,000 users with 4.4/5 rating suggests stable behavior

**Risk upgrade reasoning**: While the core functionality is legitimate, the undisclosed collection and transmission of browsing data (all tab domains, navigation history) to a remote server elevates this from LOW to MEDIUM risk. Users installing an "ad blocker" typically do not expect their browsing history to be sent to the developer's server. The privacy policy and data collection practices should be clearly disclosed.
