# Vulnerability Report: Ad Blocker Elite

## Metadata
- **Extension ID**: bfelalhndlhoohbhiddkmkjhcaipclcn
- **Extension Name**: Ad Blocker Elite
- **Version**: 1.1.1.1
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Ad Blocker Elite is a declarative ad blocking extension that uses Chrome's declarativeNetRequest API to block ads with 152,947 blocking rules. The extension implements dynamic content script injection with ad blocking scriptlets similar to uBlock Origin. While the core ad blocking functionality appears legitimate, the extension sends chrome.storage.local data and a unique installation UUID to adznomore.com for remote rule updates. This constitutes undisclosed telemetry that goes beyond the stated "Remove ads and distractions from your web pages" functionality and violates user privacy expectations.

The extension does not appear to be malicious, but the lack of transparency about data collection to a remote server warrants a MEDIUM risk rating.

## Vulnerability Details

### 1. MEDIUM: Undisclosed Telemetry and Remote Configuration

**Severity**: MEDIUM
**Files**: anm_background.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension sends local storage data including a unique installation UUID to adznomore.com without disclosure in the privacy policy or extension description.

**Evidence**:

```javascript
// anm_background.js lines 107-145
async function u() {
  let a = await async function() {
    let a = await chrome.storage.local.get(["__iId"]),
      n = await chrome.storage.local.get({
        __lu: 0
      }),
      t = a.__iId,
      e = n.__lu;
    return {
      __iId: t,
      __lu: e
    }
  }(), {
    __iId: n,
    __lu: t
  } = a;
  if (!(t && Date.now() - t < e.__updatePeriod)) try {
    let a = await async function(a) {
      let n = await i(e.__updateEndpoint + "?uuid=" + a),  // Sends UUID to adznomore.com/rules
        t = await chrome.storage.local.get(n.map((function(a) {
          return a.id
        })));
      return await async function(a, n) {
        for (var t = {}, e = 0; e < a.length; e++) {
          let r = a[e];
          r.data_version !== n[r.id] && await m(r);
          var i = r.id,
            s = r.version;
          t[i] = s
        }
        return t
      }(n, t)
    }(n);
    await chrome.storage.local.set(a)
  } finally {
    await chrome.storage.local.set({
      __lu: Date.now()
    })
  }
}
```

```javascript
// anm_background.js lines 196-210 - UUID generation on install
async function p(a) {
  if (a.reason === chrome.runtime.OnInstalledReason.INSTALL) try {
    var n = await async function(a) {
      return await i(a)  // Fetches from adznomore.com/uuid
    }(e.__installEndpoint), t = {};
    t.__iId = n.uuid, await chrome.storage.local.set(t)
  } catch (a) {
    var s = {
      __iId: "default"
    };
    await chrome.storage.local.set(s)
  } finally {
    await async function() {
      return await _()
    }()
  }
}
```

**Exfiltration Flow (from ext-analyzer)**:
```
[HIGH] chrome.storage.local.get → fetch(adznomore.com)    anm_background.js
```

**Verdict**: This is undisclosed telemetry. The extension description states only "Remove ads and distractions from your web pages" with no mention of remote data collection, UUID tracking, or communication with external servers. While the data sent appears limited to rule version information and a UUID, this behavior should be disclosed to users. The remote configuration mechanism itself is legitimate for ad blocker updates, but the lack of transparency is a privacy concern.

## False Positives Analysis

The following patterns appear suspicious but are legitimate for an ad blocking extension:

1. **Dynamic Content Script Injection**: The extension registers content scripts dynamically in both MAIN and ISOLATED worlds with scriptlets for ad blocking (e.g., `anm_stop-current-script.js`, `anm_block-fetch.js`, `anm_addEventListener-interceptor.js`). This is standard for advanced ad blocking similar to uBlock Origin.

2. **Large declarativeNetRequest Ruleset**: The 152,947 blocking rules in `declarative_net_request.json` is typical for comprehensive ad blocking and uses Chrome's native API.

3. **chrome.storage.local Usage**: Storing rule versions and configuration locally is expected behavior for an ad blocker that updates its blocking lists.

4. **<all_urls> Permission**: Required for ad blocking across all websites, which is the core stated functionality.

5. **Periodic Alarms**: The extension uses chrome.alarms to check for rule updates every 60 minutes (lines 169-174), which is reasonable for keeping blocking rules current.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| adznomore.com/uuid | Installation UUID generation | None (GET request) | Low - generates tracking UUID |
| adznomore.com/rules | Fetch updated blocking rules | uuid parameter, rule version data from chrome.storage.local | Medium - undisclosed telemetry |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

Ad Blocker Elite is a functional ad blocking extension using legitimate techniques (declarativeNetRequest API, dynamic scriptlets in MAIN/ISOLATED worlds). However, it sends chrome.storage.local data and a unique installation UUID to adznomore.com for rule updates without any disclosure in the extension description or visible privacy policy. This constitutes undisclosed telemetry that violates user privacy expectations.

The extension is rated MEDIUM rather than HIGH because:
- The data exfiltrated appears limited to rule version metadata and a UUID
- The core ad blocking functionality is legitimate
- There's no evidence of sensitive user data collection (browsing history, credentials, etc.)
- The remote configuration mechanism serves a legitimate purpose (updating blocking rules)

However, the lack of transparency about remote data collection is a clear privacy violation. Users install an "ad blocker" expecting local-only functionality, not communication with external servers and UUID tracking. The extension should disclose this behavior in its description and provide an opt-out mechanism.

**Recommendation**: Users concerned about privacy should uninstall this extension and use alternatives with transparent data handling policies (e.g., uBlock Origin). The developer should add clear disclosure about remote configuration and UUID tracking.
