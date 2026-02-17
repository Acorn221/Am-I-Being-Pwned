# Vulnerability Report: XDown

## Metadata
- **Extension ID**: kebpgmmmoiggnchlpamiefihdjiaikaf
- **Extension Name**: XDown
- **Version**: 2.0.1
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

XDown is a Chrome extension that integrates with a native download manager application (XDown) to handle file downloads. The extension intercepts browser downloads and forwards them to the native application via Chrome's nativeMessaging API. While this functionality is legitimate for a download manager integration, the extension collects cookies from all websites using the `<all_urls>` host permission and the `cookies` permission, then transmits these cookies along with download URLs to a native application outside the browser sandbox. This creates a privacy concern as user session data is exposed to an external application.

The extension's stated purpose is to enable downloads through the XDown download manager, and cookie collection appears necessary for authenticated downloads. However, the broad host permissions grant access to cookies from all websites, not just those related to download operations.

## Vulnerability Details

### 1. MEDIUM: Cookie Collection and External Transmission

**Severity**: MEDIUM
**Files**: xdown_worker.js, cookie_manager.js, native_host_manager.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: The extension collects cookies from all websites and transmits them to a native application via nativeMessaging. When a download is detected, the extension retrieves all cookies for the download URL and packages them with the download request to send to the XDown native host.

**Evidence**:

In `cookie_manager.js`, the extension retrieves cookies for URLs:
```javascript
CookieManager.prototype.getCookiesForUrl = function(url, callback) 
{
    this.getCookiesForUrls([url], function (result) {
        callback(result[0]);
    });
}

CookieManager.prototype.getCookiesForUrls = function(urls, callback)
{
    var remained = urls.length;
    var result = [];
    for (var i = 0; i < urls.length; ++i) {
        chrome.cookies.getAll(
            { 'url': urls[i] },
            function (resultIndex, cookies) {
                var cookiesString = "";
                if (cookies) {
                    cookiesString = cookies.map(function (cookie) {
                        return cookie.name + "=" + cookie.value + ";";
                    }).join(' ');
                }
                result[resultIndex] = cookiesString;
                // ...
            }
        );
    }
}
```

In `xdown_worker.js`, cookies are included in download tasks sent to the native application:
```javascript
var cManager = new CookieManager;
cManager.getCookiesForUrl(
    url,
    function (cookies) {
        var downItem = {
          'httpReferer': d.referrer,
          'url': url,
          'originalUrl': url,
          'userAgent': navigator.userAgent,
          'httpCookies': cookies || '',
          'httpContentType': d.mime || '',
          'httpContentLength': cur_length.toString(),
          'httpFileName': file_name || '',
        };
        downList.push(downItem);
        // ...
        xdownExt.postMessage(downTask, res => {
          // sent to native host via nativeMessaging
        });
    }
);
```

In `native_host_manager.js`, messages are sent to the native host `org.xdown.xmsg`:
```javascript
XDownNativeHostManager.prototype.initialize = function()
{
    this.port = chrome.runtime.connectNative('org.xdown.xmsg');
    this.port.onMessage.addListener(
        this.onPortMessage.bind(this));
    // ...
}
```

**Verdict**: This is a legitimate use case for a download manager that needs to handle authenticated downloads. However, it presents a privacy concern because user cookies (which may contain session tokens and authentication data) are transmitted to a native application outside the browser's security sandbox. The extension does not appear to collect cookies for malicious purposes, but users should be aware that their authentication data is being shared with the XDown application. The risk level is MEDIUM because while the functionality is disclosed in the extension description ("enables you to download a desired item with an Internet Download Manager (xdown) application"), the broad scope of cookie access across all URLs is a legitimate privacy concern.

## False Positives Analysis

The following patterns are legitimate for this extension type:

1. **Cookie Collection**: While cookie harvesting is typically malicious, download managers often need cookies to handle authenticated downloads (e.g., downloading files from sites requiring login). This is expected behavior for download manager integrations.

2. **Native Messaging**: Communication with a native application via `chrome.runtime.connectNative` is the standard and documented way for extensions to integrate with desktop applications.

3. **Download Interception**: The extension intercepts Chrome downloads using `chrome.downloads.onDeterminingFilename` to redirect them to the external download manager. This is the intended functionality.

4. **Host Permission `<all_urls>`**: While broad, this is necessary for the extension to access cookies for any download URL the user might encounter.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| xdown.org | Homepage/about link | None (user navigation) | Low |
| org.xdown.xmsg (native host) | Download manager communication | Download URLs, cookies, referrers, user agent | Medium |

The extension does not communicate with external web servers. All functionality is local (browser) and communication with the native XDown application via nativeMessaging.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: XDown is a legitimate download manager integration extension that performs its stated function of redirecting downloads to the XDown native application. The privacy concern stems from the collection of cookies across all websites and transmission to an external application. While this is necessary for authenticated downloads, it does create a potential privacy risk if the native application is compromised or malicious. The extension does not appear to have malicious intent, and the functionality is disclosed in the description. Users should be aware that installing this extension grants cookie access to the XDown application for any website they download files from.

**Recommendations**:
- Users should only install this extension if they trust the XDown application
- Users should review the XDown application's privacy policy to understand how cookies and download data are handled
- The extension could be improved by implementing cookie filtering to only send cookies necessary for the specific download, rather than all cookies for the domain
