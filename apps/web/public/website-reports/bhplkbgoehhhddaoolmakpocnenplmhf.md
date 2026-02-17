# Vulnerability Report: Alternate Player for Twitch.tv

## Metadata
- **Extension ID**: bhplkbgoehhhddaoolmakpocnenplmhf
- **Extension Name**: Alternate Player for Twitch.tv
- **Version**: 2025.6.16
- **Users**: ~80,000
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

Alternate Player for Twitch.tv is a legitimate browser extension that provides an alternative video player interface for Twitch streaming. The extension implements fetch hooking to extract authentication tokens from Twitch's GraphQL API, modifies HTTP headers to bypass CORS restrictions, and includes optional crash reporting to the developer's server. While these behaviors could appear suspicious in isolation, they serve the extension's stated purpose of providing an enhanced Twitch viewing experience.

The extension uses WASM for video processing, hooks into the fetch API to capture GQL integrity tokens, and modifies webRequest headers to impersonate twitch.tv origin. The optional crash reporting functionality sends user-approved diagnostic data to r90354g8.beget.tech. Third-party CDN integration with BetterTTV and FrankerFaceZ is implemented for enhanced chat features.

## Vulnerability Details

### 1. LOW: Optional Crash Reporting to Developer Server
**Severity**: LOW
**Files**: player.js (lines 379-382)
**CWE**: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
**Description**: The extension implements optional crash reporting that sends diagnostic data to http://r90354g8.beget.tech/tw5/report3.php. The code includes comments indicating that users can view and refuse to send the report data.

**Evidence**:
```javascript
//! This request sends a crash report or user feedback to the extension developer. The user can
//! view the contents of оОтчет and refuse to send it. See https://coolcmd.github.io/privacy.html
оЗапрос.open('POST', 'http://r90354g8.beget.tech/tw5/report3.php');
оЗапрос.send(оДанные);
```

The form at `отладка-ошибка` (debug-error) allows users to review the contents of `оОтчет` before submitting. The report includes extension version, browser info, system memory/CPU details, and optionally video stream segments for debugging.

**Verdict**: This is consensual diagnostic data collection with user transparency. The extension shows the report contents before sending and requires explicit user action (form submission). However, the endpoint uses HTTP instead of HTTPS, which is suboptimal for privacy.

## False Positives Analysis

### Fetch Hooking (gqltoken.js)
The extension hooks `window.fetch` to intercept responses from `https://gql.twitch.tv/integrity`:

```javascript
const оригинальнаяФункция = window.fetch;
window.fetch = function(адрес, параметры) {
    const обещание = оригинальнаяФункция(адрес, параметры);
    if (адрес === 'https://gql.twitch.tv/integrity' && параметры && параметры.method && параметры.method.toUpperCase() === 'POST' && параметры.headers && параметры.headers.Authorization) {
        обещание.then(ответ => {
            if (ответ.ok && ответ.status === 200) {
                return ответ.clone().json().then(({token: сТокен, expiration: чПротухнетПосле}) => {
                    // Stores token in cookie for player use
                    document.cookie = `tw5~gqltoken=...`;
                });
            }
        }).catch(причина => {});
    }
    return обещание;
};
```

**Analysis**: This hooks fetch to extract authentication tokens needed for the alternative player to function. The token is stored in a cookie scoped to `/tw5~storage/` and is necessary for the player to authenticate with Twitch's API on behalf of the user. This is **not malicious** for a Twitch player replacement extension.

### WebRequest Header Modification (background.js)
The extension modifies Origin and Referer headers:

```javascript
chrome.webRequest.onBeforeSendHeaders.addListener(request => {
    const requestHeaders = request.requestHeaders.filter(({name}) => !remove.includes(name.toLowerCase()));
    requestHeaders.push({
        name: 'Origin',
        value: 'https://www.twitch.tv'
    }, {
        name: 'Referer',
        value: 'https://www.twitch.tv/'
    });
    return {
        requestHeaders
    };
}, {
    urls: chrome.runtime.getManifest().permissions.filter(permission => permission.includes(':')),
    types: [ 'xmlhttprequest' ]
}, beforeSendHeadersOptions);
```

**Analysis**: This is required to bypass CORS restrictions when the alternative player makes requests to Twitch APIs from the extension's context. Without this, the requests would be blocked. This is **standard practice** for extensions that replace web application interfaces.

### X-Frame-Options Removal (background.js)
The extension removes `X-Frame-Options` and `frame-ancestors` CSP directives:

```javascript
chrome.webRequest.onHeadersReceived.addListener(response => {
    return {
        responseHeaders: response.responseHeaders.filter(({name, value}) => {
            const headerName = name.toLowerCase();
            return headerName !== 'x-frame-options' && (headerName !== 'content-security-policy' || !value.toLowerCase().includes('frame-ancestors'));
        })
    };
}, {
    urls: [ 'https://www.twitch.tv/popout/*/chat', 'https://www.twitch.tv/embed/*/chat', 'https://www.twitch.tv/*/chat?*', 'https://www.twitch.tv/popout/' ],
    types: [ 'sub_frame' ]
}, headersReceivedOptions);
```

**Analysis**: This allows embedding Twitch chat in iframes within the alternative player. The URLs are specifically scoped to Twitch chat endpoints. This is **necessary functionality** for the extension's purpose.

### Auto-claim Bonus Points (autoclaim.js)
```javascript
setInterval(
    () => {
        const e = document.getElementsByClassName('claimable-bonus__icon');
        if (e.length !== 0) {
            e[0].click();
        }
    },
    5000
);
```

**Analysis**: Automatically clicks Twitch channel point bonus claims every 5 seconds. This is a **quality-of-life feature** for viewers and is commonly found in Twitch enhancement extensions.

### Third-Party CDN Loading (content.js)
The extension loads BetterTTV and FrankerFaceZ scripts from their official CDNs when those extensions are detected as installed:

```javascript
script.src = 'https://cdn.betterttv.net/betterttv.js';
// and
script.src = 'https://cdn.frankerfacez.com/script/script.min.js';
```

**Analysis**: This provides compatibility with popular Twitch enhancement extensions. The CDN domains are official and the code includes comments referencing the legitimate extensions. This is **expected behavior** for a Twitch player enhancement.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| gql.twitch.tv | Twitch GraphQL API | Stream metadata queries, authentication | Low - legitimate Twitch API |
| cdn.betterttv.net | BetterTTV script loading | None (GET request) | Low - official BetterTTV CDN |
| cdn.frankerfacez.com | FrankerFaceZ script loading | None (GET request) | Low - official FrankerFaceZ CDN |
| r90354g8.beget.tech | Crash reports / user feedback | Extension version, browser info, system specs, optionally video segments | Low - user-approved diagnostic data, but uses HTTP not HTTPS |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**: This extension implements behaviors that could appear suspicious (fetch hooking, header modification, third-party script loading, remote reporting) but all serve the extension's legitimate purpose as an alternative Twitch player. The fetch hooking captures only Twitch authentication tokens needed for player functionality, header modifications bypass CORS for legitimate API access, and crash reporting is transparent and user-approved.

The main security concern is the use of HTTP (not HTTPS) for the crash reporting endpoint, which could expose diagnostic data in transit. However, the user has full visibility into what data is sent and must explicitly approve it.

The extension's permissions are appropriately scoped to Twitch-related domains, and the code quality suggests a legitimate developer (proper error handling, internationalization support, detailed comments). The Russian variable names (е.g., `г_оЗапрос`, `оригинальнаяФункция`) indicate a Russian-speaking developer, which aligns with the .ru developer site mentioned in comments.

**Recommendation**: The extension appears safe for users who want an alternative Twitch viewing experience. Users should be aware that optional crash reports are sent over HTTP to a third-party server, though this requires explicit consent.
