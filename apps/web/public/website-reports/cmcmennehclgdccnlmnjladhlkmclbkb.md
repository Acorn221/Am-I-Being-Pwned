# Vulnerability Report: uberAgent MV2

## Metadata
- **Extension ID**: cmcmennehclgdccnlmnjladhlkmclbkb
- **Extension Name**: uberAgent MV2
- **Version**: 3.1.1
- **Users**: ~100,000
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

uberAgent MV2 is an enterprise monitoring extension designed to collect web application usage and performance data from Chrome browsers. The extension monitors all browsing activity including tab URLs, page load performance metrics, XHR/WebSocket requests, and foreground tab tracking. All collected data is transmitted to a native application via the nativeMessaging API (com.vastlimits.uainsessionhelper). While the extension's description discloses its monitoring purpose, the comprehensive surveillance capabilities and privileged access to all browsing data present significant privacy implications for users who may not fully understand the extent of data collection.

The extension is a legitimate enterprise monitoring tool and functions as described. However, it implements extensive data collection across all websites with broad permissions, qualifying it as a MEDIUM risk due to the disclosed but highly invasive monitoring capabilities.

## Vulnerability Details

### 1. MEDIUM: Comprehensive Browsing Activity Monitoring

**Severity**: MEDIUM
**Files**: background.js, content.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: The extension collects extensive browsing data including all visited URLs, page load timings, network request details, and foreground tab activity. Data is transmitted to a native messaging host that can persist and forward this information to enterprise monitoring systems.

**Evidence**:

Background script monitors all web requests:
```javascript
var callbackFilter = {types: ["main_frame", "sub_frame", "xmlhttprequest", "websocket"], urls: ["<all_urls>"]};

uABrowserObject.webRequest.onBeforeRequest.addListener (onBeforeRequestCallback, callbackFilter, ["blocking"]);
```

Collected data includes tab URLs, request URLs, timing information:
```javascript
var message = {
   type : WebRequestEventTypes.Start,
   requestId : details.requestId,
   relativeTimeMs : details.timeStamp,
   timestampMs : Date.now (),
   tabId : details.tabId,
   frameId : details.frameId,
   requestUrl : requestUrl,
   requestUriScheme : uriSchemeToEnum (requestUrl.protocol)
};
```

Content script collects page load performance metrics:
```javascript
message.pageLoadTotalMs = timingInfo.loadEventEnd - timingInfo.navigationStart;
message.pageLoadNetworkMs = timingInfo.responseEnd - networkStartMs;
message.pageLoadRenderMs = timingInfo.loadEventEnd - timingInfo.responseEnd;
```

Foreground tab tracking monitors active browsing:
```javascript
function doActionFgUrl (formatVersion)
{
   getForegroundTabUrl().then((foregroundTabUrl) =>
   {
      let foregroundTabUrlStringOutput = "";
      if (foregroundTabUrl)
      {
         foregroundTabUrlStringOutput = getUrlDetailLevel (foregroundTabUrl, foregroundTabUrl, tabUrlSpecs);
      }
      port.postMessage (output);
   });
}
```

Data exfiltration to native messaging host:
```javascript
port = uABrowserObject.runtime.connectNative ('com.vastlimits.uainsessionhelper');
port.onMessage.addListener (nativeMessagingOnMessage);

// Data is sent via port.postMessage
port.postMessage (output);
```

**Verdict**: This is a disclosed enterprise monitoring tool functioning as described. The extension clearly states in its description: "Enables uberAgent to collect web app usage and performance data (e.g., foreground tab, page load duration) from Chrome." While the monitoring is extensive, it is transparent about its purpose. The MEDIUM risk rating reflects that this is disclosed monitoring with a legitimate enterprise use case, but with highly invasive data collection capabilities.

## False Positives Analysis

1. **Native Messaging Communication**: The use of nativeMessaging API to communicate with 'com.vastlimits.uainsessionhelper' is the intended architecture for this enterprise monitoring solution. This is not malicious but rather the designed mechanism for sending telemetry to the uberAgent analytics platform.

2. **webRequest API with <all_urls>**: While extremely broad, this permission set is necessary for the extension's stated purpose of monitoring web application usage across all sites. Enterprise monitoring tools require this level of access.

3. **Data Collection Controls**: The extension implements data collection controls including:
   - User consent checking via `isDataCollectionEnabledByUser()`
   - Centrally managed policy settings via `browser.storage.managed`
   - Denylist/allowlist filtering for excluding specific URLs
   - Firefox-specific consent dialog support

4. **Content Script Injection**: The extension injects content.js to gather page load timing data using the Performance API, which is standard practice for performance monitoring tools.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| Native Messaging Host | com.vastlimits.uainsessionhelper | Browsing activity, URLs, timing metrics, foreground tab info | Medium - disclosed enterprise monitoring |

**Note**: The extension does not make any direct HTTP/HTTPS network requests. All data is transmitted to a local native messaging host application, which is responsible for any subsequent data transmission to uberAgent servers.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

uberAgent MV2 is a legitimate enterprise monitoring extension that functions exactly as described. The extension's disclosure in its Chrome Web Store description clearly states it collects "web app usage and performance data" including "foreground tab" and "page load duration" information. The implementation aligns with this disclosed purpose.

The MEDIUM risk rating is assigned because:

1. **Disclosed Purpose**: The extension transparently describes its monitoring capabilities in the CWS listing
2. **Enterprise Context**: This is an enterprise IT tool, not consumer software, designed for workplace monitoring scenarios
3. **Consent Mechanisms**: Implements user consent checks and centrally-managed policy controls for enterprise deployments
4. **No Hidden Behavior**: All data collection serves the stated monitoring purpose
5. **Legitimate Vendor**: uberAgent (vastlimits) is a known enterprise endpoint monitoring solution

However, it remains MEDIUM risk rather than LOW due to:

1. **Extensive Data Collection**: Monitors all browsing activity across all websites
2. **Privacy Impact**: Comprehensive surveillance of user behavior
3. **Sensitive Data**: Collects URLs which may contain personal information, authentication tokens, or sensitive business data
4. **Broad Permissions**: Full access to all web requests and tab information

This extension is appropriate for managed enterprise environments where employee monitoring is disclosed and authorized, but would be inappropriate for personal use or installations without user awareness and consent.
