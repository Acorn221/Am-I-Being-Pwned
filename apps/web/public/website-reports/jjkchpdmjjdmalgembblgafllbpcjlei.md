# Vulnerability Report: Trellix Endpoint Security Web Control

## Metadata
- **Extension Name:** Trellix Endpoint Security Web Control
- **Extension ID:** jjkchpdmjjdmalgembblgafllbpcjlei
- **Version:** 10.7.0.5779
- **Manifest Version:** 3
- **User Count:** ~6,000,000
- **Publisher:** Trellix (formerly McAfee Enterprise)
- **Type:** Enterprise endpoint security / web filtering

## Executive Summary

Trellix Endpoint Security Web Control is a legitimate enterprise security product (formerly McAfee SiteAdvisor / Web Control) that provides URL reputation checking, phishing protection, search result annotation, download scanning, and web content blocking. It uses `nativeMessaging` to communicate with a locally installed C++ host application (`siteadvisor.mcafee.chrome.extension`) which performs the actual GTI (Global Threat Intelligence) reputation lookups.

The extension requests broad permissions (all URLs, cookies, webRequest, tabs, downloads, nativeMessaging, storage) which are invasive but justified by its intended enterprise web security function. It runs content scripts on all pages to annotate search results and enforce web access policies.

Several noteworthy behaviors were identified, though none constitute clear malicious activity or exploitable vulnerabilities given the enterprise security context.

## Vulnerability Details

### MEDIUM: Cookie Sync (CSync) - DoubleClick/Zeotap Cookie Harvesting

- **Severity:** MEDIUM
- **File:** `mcafee_wa_bkground.js` (lines 1144-1189)
- **Code:**
```javascript
mcafee_wa_csynchandler.prototype.cSyncHandler = function (cData) {
    var gData = "";
    var zData = "";
    for (var i = 0; i < cData.length; i++) {
        if (cData[i]["domain"] == ".doubleclick.net") {
            gData += cData[i]['name'] + '=' + cData[i]['value'] + '; ';
        }
        if (cData[i]["domain"] == ".zeotap.com") {
            zData += cData[i]['name'] + '=' + cData[i]['value'] + '; ';
        }
    }
    mcafee_wa_bkglobals.messageDispatcher.onCSync(gData, zData);
};
// Runs every 6 hours + 1 minute after startup
mcafee_wa_csynchandler.prototype.init = function () {
    setTimeout(function () {
        chrome.cookies.getAll({}, function (cData) { ... });
    }, 60 * 1000);
    setInterval(function () {
        chrome.cookies.getAll({}, function (cData) { ... });
    }, 6 * 60 * 60 * 1000);
};
```
- **Analysis:** The extension reads ALL browser cookies via `chrome.cookies.getAll({})`, filters for `.doubleclick.net` and `.zeotap.com` domains, and sends these cookie values to the native host application via native messaging. This runs 1 minute after browser startup and then every 6 hours. Zeotap is an advertising data platform. This appears to be a cookie sync mechanism for McAfee/Trellix telemetry or advertising partnerships.
- **Mitigating factor:** This feature is only initialized when `browserType == Firefox` (line 3030-3033), so it does NOT run in the Chrome enterprise build variant (this extension is enterprise=true, Chrome). The CSync listener is gated behind the Firefox browser type check. Additionally, data is sent to the local native host, not to a remote server directly from the extension.
- **Verdict:** Not active in this Chrome enterprise build variant, but the code is present and concerning for Firefox variants.

### LOW: URL Telemetry - Every Navigation Sent to Native Host

- **Severity:** LOW
- **File:** `mcafee_wa_bkground.js` (lines 2036-2050)
- **Code:**
```javascript
chrome.tabs.onUpdated.addListener(function (tabId, changeInfo, tab) {
    if (changeInfo.status == "complete" && typeof (tab.url) != "undefined") {
        var lastURL = mcafee_wa_bkglobals.lastUrl;
        if (lastURL == null || lastURL != tab.url) {
            mcafee_wa_bkglobals.lastUrl = tab.url;
            var name = "BrowserNavigate_" + browserstr;
            mcafee_wa_bkglobals.messageDispatcher.reportStat({Name: name, Value: tab.url});
        }
    }
});
```
- **Analysis:** Every unique URL navigated to is reported to the native host via `reportStat`. The native host (McAfee/Trellix endpoint agent) processes this for GTI reputation checking and telemetry. This is fundamental to the product's web protection function.
- **Verdict:** Expected behavior for an enterprise web control product. The data goes to the local native host, not directly to a remote endpoint from the extension.

### LOW: Password Protection - Password Values Sent to Native Host

- **Severity:** LOW
- **File:** `mcafee_wa_contentplg.js` (lines 1891-1931)
- **Code:**
```javascript
_wa.passwordProtect = {
    addSubmitEventListener: function (document) {
        var inputs = doc.querySelectorAll("[type=password]"),
            hostName = doc.location.hostname;
        var onSubmitEvent = function () {
            var passwords = this.querySelectorAll("[type=password]");
            for (var j = 0; j < passwords.length; ++j) {
                var password = passwords[j],
                    passwordValue = password.value;
                if (self.isValid(password) && isLogin) {
                    var params = hostName + " " + passwordValue,
                        COMMANDID_CHECK_PASSWORD = 2;
                    mcafee_wa_backgroundipc.executeCommand(COMMANDID_CHECK_PASSWORD, params);
                }
            }
        };
    }
};
```
- **Analysis:** On form submission, password values from login pages are extracted and sent to the background script, which forwards them to the native host. This is used for McAfee/Trellix Password Protection (checking if users are reusing corporate passwords on non-corporate sites). This feature is disabled in enterprise mode (`isPProtectFeatureDisabled = true` at line 2678).
- **Verdict:** Feature is disabled in enterprise builds. Even when active, it is an intended security feature of the product (password reuse detection). The data goes to the local native agent only.

### INFO: Content Script Injection on All Pages

- **Severity:** INFO
- **File:** `manifest.json` (lines 22-46)
- **Analysis:** Four content scripts (`sizzle.js`, `punycode.js`, `mcafee_wa_coreengine.js`, `mcafee_wa_contentplg.js`) are injected into all HTTP/HTTPS pages at `document_start` in `all_frames`. This is the maximum injection surface. `sizzle.js` is the standard jQuery CSS selector engine, `punycode.js` is a standard punycode library. The core engine handles search result annotation and the content plugin handles page blocking/warning.
- **Verdict:** Expected for a web protection product that needs to annotate search results, block pages, and enforce web policies.

### INFO: Native Messaging to Local Host

- **Severity:** INFO
- **File:** `mcafee_wa_bkground.js` (line 2648)
- **Code:**
```javascript
this._port = chrome.runtime.connectNative("siteadvisor.mcafee.chrome.extension");
```
- **Analysis:** All reputation queries, telemetry, download scanning events, and navigation events are sent to the local native messaging host `siteadvisor.mcafee.chrome.extension` (McAfee/Trellix endpoint agent). This is the standard architecture for enterprise endpoint security products.
- **Verdict:** Expected architectural pattern.

### INFO: Script Injection into Page Context

- **Severity:** INFO
- **File:** `mcafee_wa_coreengine.js` (lines 398-413)
- **Code:**
```javascript
var mcafee_wa_scriptinjector = function () {
    var injectscript = function (document, script) {
        var customscript = document.createElement("script");
        customscript.setAttribute("type", "text/javascript");
        customscript.innerHTML = script;
        document.getElementsByTagName("head")[0].appendChild(customscript);
    };
    return { injectscript: injectscript };
}();
```
- **Analysis:** Injects small event handler scripts into the page context for balloon show/hide and warning banner interactions. The injected scripts are hardcoded string constants (`mcafee_wa_scripts`), not dynamic or remote content.
- **Verdict:** Not a vulnerability -- injected scripts are static and used for UI event handling.

## False Positive Table

| Pattern | Location | Reason |
|---------|----------|--------|
| `innerHTML` assignments | `mcafee_wa_coreengine.js`, `mcafee_wa_contentplg.js` | Used for balloon UI rendering, warning banners, and search annotations. Content comes from extension's own bundled HTML/resources, not user input. |
| `chrome.cookies.getAll({})` | `mcafee_wa_bkground.js:1178` | CSync handler -- gated behind Firefox browser type check, not active in Chrome enterprise variant. |
| `chrome.management.getAll` | `mcafee_wa_bkground.js:1235` | Used to check if buddy McAfee extensions are installed, not for extension enumeration/killing. |
| `querySelector("[type=password]")` | `mcafee_wa_contentplg.js:1895` | Password Protection feature -- disabled in enterprise builds. |
| `postMessage` usage | Multiple files | Used for internal extension IPC between injected page scripts and content scripts. Origin-checked (`event.source != window`). |

## API Endpoints Table

| Endpoint | Purpose | File |
|----------|---------|------|
| `siteadvisor.mcafee.chrome.extension` (native) | All reputation queries, telemetry, download scanning | `mcafee_wa_bkground.js:2648` |
| `https://www.siteadvisor.com/restricted.html` | Block page redirect | `mcafee_wa_bkground.js:23` |
| `https://www.siteadvisor.com/phishing.html` | Phishing page redirect | `mcafee_wa_bkground.js:24` |
| `https://trustedsource.org/en/feedback/url?action=checksingle&url=` | Site report viewer | `mcafee_wa_bkground.js:22` |
| `https://www.trellix.com/SAE/BlockPageGC.html` | Enterprise block page | `mcafee_wa_bkground.js:54` |
| `https://www.trellix.com/SAE/WarnPromptPageGC.html` | Enterprise warn page | `mcafee_wa_bkground.js:55-56` |
| `https://www.trellix.com/SAE/subframeblockpage.html` | Enterprise iframe block | `mcafee_wa_bkground.js:57-58` |
| `https://home.trellix.com/root/landingpage.aspx` | Uninstall landing page | `mcafee_wa_bkground.js:19` |
| `https://www.trellix.com/threat-intelligence/site/default.aspx` | Site report (popup) | `mcafee_wa_popup.js:17` |

## Data Flow Summary

1. **Navigation events:** Every URL navigated to is captured via `chrome.webRequest.onCompleted` and `chrome.webRequest.onHeadersReceived`, sent to native host for GTI reputation check.
2. **Reputation data flow:** Background script sends DSS (Data Security Service) requests containing page URLs and search result links to native host. Native host queries Trellix GTI servers. Results are returned to annotate search results with safety ratings (green/yellow/red/unknown).
3. **Download scanning:** Completed downloads are reported to native host (URL, filename, referrer) for malware scanning by the local endpoint agent.
4. **Telemetry:** Browser navigation events and internal statistics are sent to native host as `reportStat` calls.
5. **Block/Warn pages:** When GTI rates a URL as dangerous, the native host instructs the extension to navigate to a block or warning page (either local file or Trellix-hosted).
6. **Cookie sync (Firefox only):** DoubleClick and Zeotap cookies are read and sent to native host every 6 hours -- NOT active in Chrome enterprise builds.
7. **Password protection (disabled):** Login page password values would be sent to native host for corporate password reuse detection -- disabled in enterprise variant.

## Overall Risk: **CLEAN**

This is a legitimate enterprise endpoint security product from Trellix (formerly McAfee Enterprise). The broad permissions (all URLs, cookies, webRequest, tabs, downloads, nativeMessaging) are justified by the product's intended function: enterprise web filtering, URL reputation checking, phishing protection, download scanning, and web access policy enforcement.

Key points supporting CLEAN rating:
- All data flows go to the local native messaging host (`siteadvisor.mcafee.chrome.extension`), not directly to remote servers from the extension code.
- No obfuscation -- code is well-commented McAfee proprietary code with clear function names.
- No remote code execution, no dynamic script loading from external servers.
- No ad injection, no search result modification beyond safety annotations.
- No residential proxy infrastructure.
- No market intelligence SDK.
- Cookie sync (CSync) code is present but gated behind Firefox browser type and not active in this Chrome enterprise build.
- Password protection is present but explicitly disabled in enterprise mode.
- The CSP is restrictive: `default-src 'self'`.
- Content scripts inject into all pages, which is necessary for the web protection functionality.
- This is a 6-million-user enterprise product from a well-known security vendor.
