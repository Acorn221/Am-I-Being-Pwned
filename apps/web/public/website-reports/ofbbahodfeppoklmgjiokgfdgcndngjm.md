# Vulnerability Report: TTV LOL

## Metadata
- **Extension ID**: ofbbahodfeppoklmgjiokgfdgcndngjm
- **Extension Name**: TTV LOL
- **Version**: 0.0.0.3
- **Users**: ~80,000
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

TTV LOL is a legitimate Twitch ad-blocking extension that intercepts video playlist requests and redirects them through the ttv.lol API service to provide ad-free streaming. The extension uses webRequest blocking APIs to intercept requests to Twitch's streaming servers (usher.ttvnw.net) and redirects them to api.ttv.lol, which serves modified playlists without ad segments. The extension is transparent about its purpose and operates within expected parameters for this category of tool. No security vulnerabilities or privacy concerns were identified.

## Vulnerability Details

No vulnerabilities identified. This section documents the extension's expected behavior.

### Architecture Analysis

**Files**: js/background.js
**Description**: The extension implements a straightforward request interception mechanism:

1. Intercepts requests to `https://usher.ttvnw.net/api/channel/hls/*` and `https://usher.ttvnw.net/vod/*`
2. Extracts the playlist/VOD identifier from the URL
3. Pings `https://api.ttv.lol/ping` to check service availability
4. If the service is online, redirects to `https://api.ttv.lol/playlist/{id}` or `https://api.ttv.lol/vod/{id}`
5. If the service is offline, returns the original Twitch URL (graceful degradation)
6. Adds a promotional header `X-Donate-To: https://ttv.lol/donate` to outgoing requests to the ttv.lol API

**Evidence**:
```javascript
function onPlaylistBeforeRequest(details) {
  const match = /(hls|vod)\/(.+?)$/gim.exec(details.url);

  if (match !== null && match.length > 1) {
    var playlistType = match[1] == "vod" ? "vod" : "playlist";

    var req = new XMLHttpRequest();
    req.open("GET", `https://api.ttv.lol/ping`, false);
    req.send();

    // validate that our API is online, if not fallback to standard stream with ads
    if (req.status != 200) {
      return {
        redirectUrl: details.url
      };
    } else {
      return {
        redirectUrl: `https://api.ttv.lol/${playlistType}/${encodeURIComponent(match[2])}`,
      };
    }
  }
}
```

**Verdict**: This is expected and legitimate behavior for an ad-blocking extension. The extension is transparent about its purpose and the code matches its stated functionality.

## False Positives Analysis

**webRequest Blocking Permission**: The extension requires webRequest and webRequestBlocking permissions to intercept and redirect playlist requests. This is a necessary privilege for the extension's core functionality and is not excessive.

**External API Communication**: The extension communicates with api.ttv.lol to fetch modified playlists. This is disclosed in the extension's permissions (https://api.ttv.lol/*) and is the core mechanism by which the ad-blocking works.

**Synchronous XHR**: The code uses a synchronous XMLHttpRequest to ping the API, which is generally discouraged but is acceptable in a service worker context for quick availability checks.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.ttv.lol/ping | Service availability check | None | None - simple health check |
| api.ttv.lol/playlist/{id} | Retrieve ad-free playlist | Twitch playlist identifier | None - identifier is needed for service functionality |
| api.ttv.lol/vod/{id} | Retrieve ad-free VOD | Twitch VOD identifier | None - identifier is needed for service functionality |

The extension does not send any user data, browsing history, cookies, or personal information to external servers. Only the Twitch playlist/VOD identifiers that are already part of the URL being accessed are forwarded to the ttv.lol API.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**: TTV LOL is a well-designed, purpose-built ad-blocking extension for Twitch streaming. The code is minimal, transparent, and performs exactly the functionality described. There are no signs of data exfiltration, tracking, credential harvesting, or other malicious behavior. The extension appropriately scopes its permissions to only Twitch domains and the ttv.lol API. The popup provides links to donate and join Discord, which are standard promotional elements for open-source/community projects. The extension gracefully degrades if the API service is unavailable, falling back to the original Twitch URLs. This is a legitimate tool that poses no security or privacy risks to users.
