# Vulnerability Report: Dynatrace Real User Monitoring

## Metadata
- **Extension ID**: fklgmciohehgadlafhljjhgdojfjihhk
- **Extension Name**: Dynatrace Real User Monitoring
- **Version**: 1.6.2
- **Users**: ~300,000
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

Dynatrace Real User Monitoring is a legitimate enterprise application performance monitoring (APM) extension designed for monitoring SaaS applications where traditional Dynatrace OneAgent installation is not possible. The extension injects Dynatrace monitoring scripts into web pages based on enterprise-configured URL patterns and sends performance telemetry to Dynatrace servers.

While the extension has powerful capabilities including script injection on all URLs, CSP modification, and webRequest interception, these are all necessary for its stated monitoring purpose and are managed through enterprise-controlled configuration (Chrome's managed storage). The extension is designed for deployment via enterprise policy and includes proper permission-based session replay proxying. There are no security vulnerabilities or privacy concerns beyond the extension's disclosed monitoring functionality.

## Vulnerability Details

### 1. FALSE POSITIVE: Script Injection and CSP Modification
**Severity**: N/A (Expected Behavior)
**Files**: content_scripts/injection.js, background/csp.js
**Description**: The extension injects Dynatrace monitoring scripts into pages and modifies Content Security Policy headers to allow those scripts.

**Evidence**:
```javascript
// injection.js - Injects monitoring script based on configuration
var script = document.createElement('script');
script.setAttribute("crossorigin" , "anonymous");
script.src = tempScript.src + '?' + encodeURIComponent(document.URL);
injectScriptElementIntoDOM(head, script);

// csp.js - Modifies CSP to allow Dynatrace domains
chrome.webRequest.onHeadersReceived.addListener(
    function(details) {
        var csp = details.responseHeaders[i].value;
        details.responseHeaders[i].value = addCSPValues(csp);
    }
);
```

**Verdict**: This is the core legitimate functionality of an APM tool. The injected scripts are configured via enterprise managed storage (`globalconfig_schema.json`) and load from Dynatrace's official CDN domains (js-cdn.dynatracelabs.com). This is not malicious script injection but expected monitoring behavior.

### 2. FALSE POSITIVE: Remote Configuration Fetching
**Severity**: N/A (Expected Behavior)
**Files**: background/globalconfig.js, options/options.js
**Description**: The extension fetches monitoring configuration from remote Dynatrace servers.

**Evidence**:
```javascript
function fetchAppConfig() {
    var fetchUrl = localStorage.getItem("fetchUrl");
    fetch(fetchUrl).then(function (response) {
        return response.json().then(function (item) {
            if (item.revision <= revision) {
                return;
            }
            saveFetchedApps(item);
        });
    });
}
```

**Verdict**: This is standard enterprise configuration management. The `fetchUrl` is controlled via Chrome's managed storage API, which requires enterprise policy deployment. The configuration determines which URLs to monitor and which Dynatrace monitoring script to inject. This is necessary for centralized APM management in enterprise environments.

### 3. FALSE POSITIVE: Session Replay Proxy
**Severity**: N/A (Expected Behavior with Consent)
**Files**: background/session-replay/proxy.js, content_scripts/proxy.js
**Description**: The extension can proxy network requests for session replay functionality, but only with explicit user permission.

**Evidence**:
```javascript
// Proxy only works if permission granted
case SR_PROXY_MT:
    getProxyPermissionData(new URL(sender.tab.url).hostname).then(function (result) {
        if (result && result[PROXY_PERMISSION_STATE_KEY] === true) {
            startResourceFetching(request.url, request.grabHeaders, sendResponse);
        } else {
            sendResponse(null);
        }
    });
```

**Verdict**: The session replay proxy functionality requires explicit user permission via Chrome notifications. It's used to capture resources for session replay in the Dynatrace APM platform. The permission checks are properly implemented and tied to notification permissions, ensuring users must opt-in.

## False Positives Analysis

The ext-analyzer flagged one exfiltration flow (`document.getElementById → fetch` in options/options.js). This is a false positive - the fetch call retrieves monitoring configuration from a Dynatrace-controlled URL specified by enterprise administrators via managed storage. The admin can enter a URL in the options page to fetch application configuration, which is a standard configuration management pattern for enterprise software.

Key patterns that appear suspicious but are legitimate for this extension type:

1. **`<all_urls>` content script**: Required to inject monitoring scripts on any page that matches enterprise-configured URL patterns
2. **webRequest/webRequestBlocking**: Required to modify CSP headers to allow Dynatrace script injection
3. **Script injection**: Core functionality of APM tools to collect performance metrics
4. **Remote configuration**: Standard enterprise deployment pattern using Chrome managed storage
5. **Unique visitor ID**: Used for user session tracking in the Dynatrace platform (stored in chrome.storage.sync)

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| js-cdn.dynatracelabs.com | Load Dynatrace monitoring agent scripts | Page URL (as query parameter) | Low - Standard APM CDN |
| Admin-configured fetchUrl | Retrieve monitoring configuration | None (GET request with optional API token) | Low - Enterprise-controlled endpoint |
| Dynatrace monitoring endpoints | Performance telemetry | User behavior metrics, performance data | Low - Disclosed monitoring functionality |

The extension uses the official Dynatrace CDN (js-cdn.dynatracelabs.com) which is explicitly allowed in the extension's CSP (`script-src 'self' https://js-cdn.dynatracelabs.com`).

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:

This is a legitimate enterprise APM extension from Dynatrace, a well-known application performance monitoring vendor. All of the extension's capabilities align with its disclosed purpose of monitoring web applications. Key security considerations:

1. **Enterprise Deployment Model**: The extension is designed for deployment via Chrome enterprise policies using managed storage, not for individual consumer installation
2. **Disclosed Functionality**: Script injection and performance monitoring are clearly described in the extension description
3. **Permission-Based Features**: Session replay proxy requires explicit user opt-in via notifications
4. **Proper CSP**: The extension has a secure CSP limiting script sources to self and official Dynatrace CDN
5. **Configuration Controls**: Sensitive configuration (fetchUrl, applications to monitor) is managed via Chrome managed storage API, which requires enterprise policy
6. **No Hidden Behavior**: All network requests and data collection align with APM monitoring functionality

The extension has 300,000 users and a 5.0 rating, consistent with enterprise deployment. While it has powerful capabilities (script injection, CSP modification, network interception), these are all necessary for application performance monitoring and are controlled through enterprise policy rather than being exploitable by arbitrary websites or actors.

There are no security vulnerabilities or privacy concerns beyond the extension's disclosed and expected monitoring functionality.
