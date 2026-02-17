# Vulnerability Report: uberAgent

## Metadata
- **Extension ID**: jghgedlkcoafeakcaepncnlanjkbinpb
- **Extension Name**: uberAgent
- **Version**: 4.0.0
- **Users**: ~1,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

uberAgent is an enterprise endpoint monitoring extension designed to collect web application usage and performance data from Chrome browsers in corporate environments. The extension monitors all web browsing activity across all URLs, collecting detailed metrics including foreground tab URLs, page load durations, network timing, rendering performance, and web request metadata. All collected data is transmitted via native messaging to a local host application (com.vastlimits.uainsessionhelper) for centralized monitoring and analytics.

While this is a legitimate enterprise monitoring tool from vastLimits (a known endpoint monitoring vendor), it represents a medium privacy risk due to the comprehensive nature of browsing data collection. The extension operates transparently as an enterprise monitoring solution, but end users should be aware that all their web browsing activity is being tracked and logged when this extension is installed by their IT department.

## Vulnerability Details

### 1. MEDIUM: Comprehensive Browsing Activity Monitoring and Data Collection

**Severity**: MEDIUM
**Files**: service-worker.js, uberAgent-content.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: The extension collects extensive browsing telemetry across all websites, including tab URLs, request URLs, timing data, HTTP status codes, frame hierarchies, and web request patterns. This data is transmitted to a native host application via chrome.runtime.connectNative.

**Evidence**:

Content script collects page performance timing:
```javascript
const r={
  status:"success",
  pageLoadTotalMs:e.duration,
  pageLoadNetworkMs:e.responseEnd-o,
  pageLoadRenderMs:e.loadEventEnd-e.responseEnd
};
chrome.runtime.sendMessage(r)
```

Service worker monitors all web requests:
```javascript
const t={types:["main_frame","sub_frame","xmlhttprequest","websocket"],urls:["<all_urls>"]};
u.webRequest.onBeforeRequest.addListener(P,t,[]),
u.webRequest.onCompleted.addListener(K,t),
```

Tracks foreground tab URLs:
```javascript
async function O(){
  const t=(await u.windows.getAll({populate:!0})).filter(n=>n.focused)[0];
  const r=t.tabs.filter(n=>n.active)[0];
  if(r?.url!=null)return new URL(r.url);
}
```

Comprehensive data package sent via native messaging:
```javascript
t+=C.WebRequestAndPageLoad+",",
t+=(i.tabUrlStringOutput??"")+",",
t+=(i.tabUriScheme??"")+",",
t+=(i.requestUrlStringOutput??"")+",",
t+=i.requestUriScheme+",",
t+=(i.frameId>0?"1":"0")+",",
t+=Math.round(i.durationMs)+",",
t+=i.requestType+",",
t+=(i.httpStatusCode??"")+",",
t+=(i.pageLoadTotalMs??"")+",",
t+=(i.pageLoadNetworkMs??"")+",",
t+=i.pageLoadRenderMs??""
```

Native messaging connection:
```javascript
p=chrome.runtime.connectNative("com.vastlimits.uainsessionhelper"),
p.onMessage.addListener(Z),
```

**Verdict**: This is a MEDIUM severity finding because while the data collection is comprehensive and privacy-invasive, this is an intentional enterprise monitoring tool. The extension description clearly states it "collects web app usage and performance data" and it's designed for corporate IT deployment. However, end users should be aware of the extent of monitoring occurring.

## False Positives Analysis

The following patterns are expected for this extension type and are not security concerns:

1. **<all_urls> permissions**: Required for comprehensive endpoint monitoring across all enterprise web applications
2. **webRequest API usage**: Necessary to track web request performance and patterns
3. **tabs permission**: Required to identify foreground tabs and collect tab-level metrics
4. **Native messaging**: Standard pattern for enterprise extensions to communicate with local endpoint agents
5. **Data transmission**: The extension's explicit purpose is to collect and transmit usage telemetry

These behaviors align with the extension's stated purpose as an enterprise endpoint monitoring solution.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| com.vastlimits.uainsessionhelper (native host) | Receive browsing telemetry | Tab URLs, request URLs, timing data, HTTP status codes, frame info, URI schemes | MEDIUM - Comprehensive browsing activity |

No external HTTP endpoints are contacted. All data flows to a local native messaging host, which then handles transmission to enterprise monitoring infrastructure outside the extension's scope.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

uberAgent is a legitimate enterprise endpoint monitoring extension from vastLimits GmbH that collects comprehensive web browsing telemetry for corporate IT purposes. The extension operates as designed and disclosed, monitoring web application usage and performance metrics across all sites.

The MEDIUM risk rating reflects:

**Privacy Concerns**:
- Monitors ALL web browsing activity across all URLs
- Collects detailed request-level metadata and timing information
- Tracks foreground tab activity
- No apparent user controls to limit monitoring scope
- Data collection includes URL components (host, path, query parameters) with configurable detail levels

**Mitigating Factors**:
- Legitimate vendor (vastLimits) with established enterprise monitoring product
- Extension description clearly states data collection purpose
- Intended for IT-managed enterprise deployments, not consumer use
- Uses native messaging (local) rather than direct external transmission
- Implements allow/deny list configuration for excluding certain URLs
- No evidence of credential theft, malicious behavior, or unauthorized data collection beyond stated purpose

**Recommendation**: This extension should only be installed in enterprise environments where employee monitoring is authorized and disclosed. IT administrators should ensure proper privacy policies are in place and employees are informed about the extent of monitoring. For personal/consumer use, this level of monitoring would be inappropriate and privacy-invasive.
