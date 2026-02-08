# Vulnerability Report: 360 Internet Protection

## Metadata
| Field | Value |
|-------|-------|
| Extension Name | 360 Internet Protection |
| Extension ID | glcimepnljoholdmjchkloafkggfoijh |
| Version | 2.1.60 |
| Manifest Version | 3 |
| Users | ~18,000,000 |
| Developer | Qihoo 360 (360.cn) |

## Executive Summary

360 Internet Protection is a companion browser extension for the 360 Total Security / 360 Safe desktop antivirus products (Chinese security company Qihoo 360). The extension acts as a browser-side interface to a **Windows native messaging host** (`com.google.chrome.wdwedpro`) that performs URL safety checking, shopping protection, and anti-tracking fingerprint randomization. The extension itself does not make any direct network requests (no `fetch`, `XMLHttpRequest`, or `ajax` calls). All URL analysis is delegated to the native host process running on the user's machine.

The extension requires broad permissions (`<all_urls>`, `webRequest`, `scripting`, `tabs`, `webNavigation`, `nativeMessaging`) but these are consistent with its stated purpose as a web protection/safe browsing tool. The `nativeMessaging` permission is the core of its architecture -- the extension is essentially non-functional without the companion desktop product installed on Windows.

**No malicious behavior, data exfiltration, keylogging, remote code execution, or suspicious SDK injection was found.** The codebase is straightforward, well-commented (with Chinese developer comments), and uses standard Google Analytics for telemetry with privacy policy opt-out support.

## Vulnerability Details

### MEDIUM-001: User Agent Modification Injected into MAIN World
- **Severity**: MEDIUM
- **Files**: `background.js` (lines 602-674, 1822-1828)
- **Code**:
```javascript
chrome.scripting.executeScript({
    target: { tabId : sender.tab.id, allFrames: true },
    world: 'MAIN',
    func: overrideUserAgent,
    args: [JSON.stringify(e)],
});
```
- **Verdict**: The anti-tracking feature uses `chrome.scripting.executeScript` with `world: 'MAIN'` to override `navigator.userAgent` and `navigator.plugins` in the page's main world via `Object.defineProperty`. This is a legitimate anti-fingerprinting technique but running code in the MAIN world is always a concern. The injected function only modifies navigator properties with randomized values -- no data exfiltration. The feature is opt-in and controlled by the native host.

### MEDIUM-002: wdHelper Function Injection into MAIN World
- **Severity**: MEDIUM
- **Files**: `background.js` (lines 676-679, 1857-1863)
- **Code**:
```javascript
chrome.scripting.executeScript({
    target: { tabId : sender.tab.id, allFrames: true },
    world: 'MAIN',
    func: inject360Func,
});
```
- **Verdict**: Injects a `wdHelper` function into the page's MAIN world that allows web pages (whitelisted by the native host via `wdHelper.web_list`) to call native host functions via `postMessage`. The whitelisted websites are controlled by the native host process, not hardcoded. This is a bridge between whitelisted websites and the 360 desktop product. The attack surface is limited because: (a) only URLs matching the native-provided whitelist trigger injection, and (b) the native host controls what functions are available. However, if the whitelist were compromised, this could be abused.

### LOW-001: toast.innerHTML with User-Controlled Content
- **Severity**: LOW
- **Files**: `toast/toast.js` (line 91)
- **Code**:
```javascript
toast.innerHTML = this.text;
```
- **Verdict**: The toast notification uses `innerHTML` to set its content. The text comes from `chrome.i18n.getMessage()` (localization strings) prepended with hardcoded SVG icons. The content is not user-controlled in any meaningful way -- it originates from the background script's i18n messages and native host messages. XSS risk is theoretical and extremely low.

### LOW-002: Undefined Function Reference
- **Severity**: LOW
- **Files**: `background.js` (line 1075)
- **Code**:
```javascript
sendAntiTrackChangedMessage(jsonObject)
```
- **Verdict**: This function is called but never defined anywhere in the codebase. Would cause a runtime error if the `antitrack_status_changed` event fires. Bug, not a security issue.

### INFO-001: Google Analytics Telemetry
- **Severity**: INFO
- **Files**: `utils/ga.js`, `utils/stat.js`, `utils/stat_bg.js`
- **Code**: Standard Google Analytics `_gaq.push()` calls with UA-102283103-* tracking IDs
- **Verdict**: Standard DAU (daily active user) tracking and event analytics (popup views, shopping protection on/off). Respects the privacy policy opt-out toggle (`privacyPolicyChecked`). This is a standard analytics implementation, not data exfiltration.

## False Positive Table

| Pattern | Location | Reason |
|---------|----------|--------|
| `innerHTML` | `toast/toast.js:91` | Only sets hardcoded SVG + i18n strings, not user input |
| `Object.defineProperty(navigator, ...)` | `background.js:661-673` | Anti-fingerprinting feature, modifies UA with random strings |
| `postMessage('*')` | `wdsupport/wd_extension.js:24`, `background.js:677` | Inter-component messaging for native host bridge, not data exfiltration |
| `<all_urls>` host permission | `manifest.json:39` | Required for web protection (URL safety checking on all sites) |
| `webRequest` permission | `manifest.json:47` | Required for anti-tracking header modification |
| `scripting` permission | `manifest.json:42` | Required for anti-fingerprint injection and wdHelper bridge |
| `chrome.tabs.create({ url: visturl })` | `background.js:1024-1025` | Opens 360 product pages on install/unsupported platform, not adware |
| Google Analytics (ga.js) | `utils/ga.js` | Standard GA library, respects privacy opt-out |

## API Endpoints Table

| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `https://info.url.cloud.360safe.com/` | Install/unsupported platform redirect pages | UI language, request type (rq param) |
| `https://www.360totalsecurity.com/` | Product links, upgrade links, privacy policy | None (user clicks only) |
| `http://www.360.com/` | 360 Safe product link | None (user clicks only) |
| `http://www.360.cn/privacy/v2/xuyan.html` | Privacy policy (Chinese) | None |
| `http://fuwu.360.cn/shensu/putong` | False positive reporting | None (user clicks only) |
| Google Analytics (UA-102283103-*) | DAU tracking, event analytics | Standard GA pageview/event data |
| Native Host (`com.google.chrome.wdwedpro`) | URL checking, security status | Tab IDs, URLs, window IDs, transition types |

## Data Flow Summary

1. **URL Checking**: On tab create/update/navigate, the extension sends `{tabid, url, event}` to the native host via `chrome.runtime.connectNative`. The native host responds with safety status (safe/risk/shopping/payment) which updates the toolbar icon and popup.

2. **Anti-Tracking**: When enabled by the native host, the extension: (a) appends a random string to the User-Agent header on all outbound requests via `onBeforeSendHeaders`, (b) injects `overrideUserAgent` into page MAIN world to override `navigator.userAgent` and `navigator.plugins` with randomized values. An exclude list is maintained by the native host.

3. **wdHelper Bridge**: For websites whitelisted by the native host, a `wdHelper` function is injected into the page's MAIN world. This allows those specific sites to call native host functions via postMessage relay through the content script and background script.

4. **Analytics**: Standard Google Analytics DAU tracking, gated behind a privacy policy opt-in/opt-out toggle.

5. **No Direct Network Requests**: The extension makes zero `fetch`, `XMLHttpRequest`, or `ajax` calls. All network communication goes through the native messaging host or Google Analytics.

## Overall Risk Assessment

**CLEAN**

This extension is a legitimate companion to the 360 Total Security / 360 Safe desktop antivirus product from Qihoo 360. While it requests broad permissions (`<all_urls>`, `webRequest`, `scripting`, `tabs`, `webNavigation`, `nativeMessaging`), all permissions are justified by its core functionality as a web protection tool. The extension:

- Makes no direct network requests (all URL analysis delegated to native host)
- Contains no obfuscated code (all code is readable, with Chinese developer comments)
- Has no remote config/kill switches (all configuration comes from the native host)
- Has no ad/coupon injection, no keylogging, no clipboard monitoring
- Has no SDK injection (Sensor Tower, Pathmatics, etc.)
- Has no extension enumeration or killing behavior
- Respects user privacy preferences with an opt-out toggle for analytics
- Uses standard, unmodified Google Analytics
- Only functions on Windows (explicitly checks platform and disables on non-Windows)
- Is non-functional without the companion 360 desktop product installed

The MAIN world code injection (anti-tracking and wdHelper) represents the highest-risk surface area, but both serve clear, legitimate purposes consistent with a security product.
