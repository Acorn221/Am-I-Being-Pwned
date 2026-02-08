# Security Analysis: Screen & Webcam recorder - Flonnect

## Extension Metadata
- **Extension ID**: lkeokcighogdliiajgbbdjibidaaeang
- **Extension Name**: Screen & Webcam recorder - Flonnect
- **Approximate Users**: 100,000
- **Analysis Date**: 2026-02-07

## Executive Summary

Screen & Webcam recorder - Flonnect is a screen/webcam recording extension with integrated bug reporting features. The extension implements **extensive surveillance capabilities** that capture detailed user activity including network traffic, console logs, browser navigation history, and device information. While marketed as a bug reporting tool, the breadth and depth of data collection raises significant privacy concerns. The extension requires optional permissions for `webRequest` and `webNavigation` APIs, which when granted, enable comprehensive monitoring of all user web activity.

**Overall Risk Assessment**: MEDIUM

## Vulnerability Details

### 1. Excessive Network Traffic Surveillance

**Severity**: HIGH
**Files**: `background.js` (lines 1975-2253)
**Type**: Privacy/Data Collection

The extension implements comprehensive network traffic interception when optional `webRequest` and `webNavigation` permissions are granted:

```javascript
chrome.webRequest.onBeforeRequest.addListener(
  function (details) {
    if (details.method === "POST" && details.requestBody) {
      const raw = details.requestBody.raw?.[0]?.bytes;
      if (raw) {
        const postData = new TextDecoder().decode(new Uint8Array(raw));
        requestBodyMap[details.requestId] = postData;
      }
    }
    return {};
  },
  { urls: ["<all_urls>"] },
  ["requestBody"]
);

chrome.webRequest.onBeforeSendHeaders.addListener(
  function (details) {
    requestHeadersMap[details.requestId] = details.requestHeaders;
    return { requestHeaders: details.requestHeaders };
  },
  { urls: ["<all_urls>"] },
  ["requestHeaders", "extraHeaders"]
);
```

**Evidence of Data Collection**:
- Captures all HTTP/HTTPS request headers and POST body data
- Records response headers and bodies for all network requests
- Stores intercepted data in IndexedDB (`TabDataDatabase`)
- Tracks request timing and caching information
- Monitors requests across ALL domains (`<all_urls>`)

**Verdict**: The network monitoring is gated behind optional permissions and appears intended for bug reporting. However, when enabled, it provides complete visibility into user web traffic including potentially sensitive POST data, authentication headers, and API responses. This level of surveillance exceeds typical screen recording functionality.

---

### 2. Console Log and Browser Event Harvesting

**Severity**: MEDIUM
**Files**: `background.js` (lines 2255-2292, 1826-1872)
**Type**: Privacy/Data Collection

The extension captures browser navigation events and console output:

```javascript
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId === 0) {
    let navigationType = getNavigationType(
      details.transitionType,
      details.transitionQualifiers
    );
    chrome.storage.local.get(
      ["eventData", "hasRequiredPermissions"],
      function (result) {
        let eventObj = {
          event: "Navigated",
          url: details.url,
          method: navigationType,
        };
        let storedEvents = result.eventData || [];
        storedEvents.push(eventObj);
        chrome.storage.local.set({ eventData: storedEvents });
      }
    );
  }
});
```

**Evidence of Tracking**:
- Records every page navigation with URL and navigation type
- Stores console logs (`consoleLogs` field in data payloads)
- Tracks tab switching behavior (`switchedArr`)
- Maintains device/system information (`systemInfo`)
- Correlates network requests with specific tabs and URLs

**Verdict**: Navigation and console tracking provide detailed browser usage patterns. When combined with network monitoring, this creates a comprehensive activity log. The data is collected for bug reporting purposes but represents significant surveillance capability.

---

### 3. XMLHttpRequest/Fetch Response Interception

**Severity**: MEDIUM
**Files**: `interceptor.js` (all 60 lines)
**Type**: Privacy/Data Exfiltration Risk

The extension injects a content script that intercepts XMLHttpRequest responses:

```javascript
var origOpen = XMLHttpRequest.prototype.open;
var origSend = XMLHttpRequest.prototype.send;

async function onLoadHandler() {
    if (this.status >= 200 && this.status < 300) {
        let apiResponse;
        const apiUrl = this.responseURL;

        const contentType = this.getResponseHeader("content-type");
        if (contentType && contentType.includes("application/json")) {
            apiResponse = JSON.parse(this.responseText);
        } else {
            apiResponse = this.responseText;
        }

        const apiData = { apiUrl, apiResponse, type: "xmlhttprequest" };

        const event = new CustomEvent("apiData", {
            detail: apiData,
        });
        document?.dispatchEvent(event);
    }
}

XMLHttpRequest.prototype.send = function() {
    this.addEventListener("load", function(event) {
        onLoadHandler.call(this, event);
    });
    origSend?.apply(this, arguments);
};
```

**Evidence of Hooking**:
- Overrides native `XMLHttpRequest.prototype.send`
- Intercepts response bodies from all AJAX requests
- Parses JSON responses automatically
- Dispatches captured data via `CustomEvent` to page context
- Listed in `web_accessible_resources` for injection into pages

**Verdict**: This XHR hooking mechanism captures API response data from websites the user visits. While the `interceptor.js` file is listed as web-accessible and appears designed for debugging, it provides direct access to sensitive API responses including authentication tokens, user data, and private information returned by web services.

---

### 4. Comprehensive Data Transmission to Backend

**Severity**: MEDIUM
**Files**: `background.js` (lines 13-16, 1661-1753)
**Type**: Data Exfiltration

All collected surveillance data is transmitted to backend servers:

```javascript
const captureHost = "https://backend.flonnect.com";
const websiteUrl = "https://app.flonnect.com";
const host = "https://backend.flonnect.com";
const authUrl = "https://backend.flonnect.com";

async function addBugCapture(data) {
  const url = `${host}/flonnect/api/bugreports/add-bug-capture`;
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(data),
    });
    const result = await response.json();
    return result;
  } catch (error) {
    console.error("Error adding bug capture:", error);
    throw error;
  }
}
```

**Data Payload Structure** (line 1168-1177):
```javascript
let payLoad = {
  bugId,
  bugUrl: bugScreenShotFinalUrl,
  captureType: "SCREENSHOT",
  deviceInfo: data?.deviceInfo ? data?.deviceInfo : {},
  consoleLogs: data?.consoleLogs ? data?.consoleLogs : [],
  networkLogs: data?.networkLogs ? data?.networkLogs : [],
  title: tab?.title ? tab?.title : "",
  overlays: message.data,
};
```

**Endpoints Used**:
- `/flonnect/api/bugreports/add-bug-capture` - Screenshot bug reports
- `/flonnect/api/bugreports/add-bug-report` - Video bug reports
- `/flonnect/api/bugreports/add-video-network-requests` - Network logs
- `/auth/api/getcurrentuser` - User authentication
- `/flonnect/api/video/getfourvideos` - Video retrieval

**Verdict**: The extension transmits comprehensive surveillance data including network logs, console output, navigation history, and device information to Flonnect's backend. While this supports the bug reporting functionality, users may not expect such detailed activity logs to be uploaded. The data transmission uses HTTPS but there's no evidence of additional encryption.

---

### 5. Intrusive Permissions Model

**Severity**: LOW
**Files**: `manifest.json` (lines 36-58), `background.js` (lines 18-21, 1384-1404)
**Type**: Permission Escalation

The extension uses an optional permissions model that requests powerful APIs after installation:

```javascript
const REQUIRED_PERMISSIONS = {
  permissions: ["webRequest", "webNavigation", "desktopCapture"],
  origins: ["<all_urls>"],
};

async function requestPermissions() {
  try {
    const granted = await chrome.permissions.request(REQUIRED_PERMISSIONS);
    if (granted) {
      hasRequiredPermissions = true;
      initializeMonitoring();
      return true;
    }
    return false;
  } catch (error) {
    console.error("Error requesting permissions:", error);
    return false;
  }
}
```

**Manifest Permissions**:
- Required: `tabs`, `contentSettings`, `storage`, `downloads`, `scripting`, `contextMenus`
- Optional: `desktopCapture`, `webNavigation`, `webRequest`
- Host Permissions: `<all_urls>`

**Verdict**: While using optional permissions is better than requiring them upfront, the extension actively prompts users to grant `webRequest` and `webNavigation` which unlock the surveillance capabilities. Users may not understand the privacy implications when granting these permissions for "bug reporting" functionality.

## False Positives

| Finding | Reason | Verdict |
|---------|--------|---------|
| React SVG `innerHTML` usage | Standard React rendering in popup/content UI (content.js) | **FALSE POSITIVE** |
| jQuery usage | Legitimate library inclusion for UI components | **FALSE POSITIVE** |
| `chrome.scripting.executeScript` | Required for injecting content scripts into tabs for bug reporting UI | **FALSE POSITIVE** |
| IndexedDB usage for video chunks | Legitimate crash recovery for screen recordings stored locally | **FALSE POSITIVE** |
| Camera/microphone permissions | Required for webcam recording feature advertised in extension name | **FALSE POSITIVE** |
| Excalidraw library | Legitimate drawing/annotation library for bug reporting annotations | **FALSE POSITIVE** |

## API Endpoints

| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `backend.flonnect.com/auth/api/getcurrentuser` | User authentication check | Cookies (credentials: include) |
| `backend.flonnect.com/flonnect/api/video/getfourvideos` | Retrieve user's recent recordings | Cookies (credentials: include) |
| `backend.flonnect.com/flonnect/api/bugreports/add-bug-capture` | Submit screenshot bug report | deviceInfo, consoleLogs, networkLogs, bugUrl, title, overlays |
| `backend.flonnect.com/flonnect/api/bugreports/add-bug-report` | Submit video bug report | title, deviceInfo, consoleLogs, networkLogs, tabNetworkRequests |
| `backend.flonnect.com/flonnect/api/bugreports/add-video-network-requests` | Upload network logs for video bug | bugCaptureId, tabNetworkRequests[] |
| `backend.flonnect.com/api/capture/aws/getpresignedurl` | Get AWS S3 upload URL | documentId, fileName |

## Data Flow Summary

1. **User Activity Capture**:
   - User installs extension and grants optional permissions
   - Background script initializes `webRequest`/`webNavigation` listeners (if permissions granted)
   - All HTTP traffic intercepted: headers, bodies, responses, timing
   - XHR/fetch responses captured via `interceptor.js` hook
   - Navigation events logged with URLs and transition types
   - Console logs and device info collected

2. **Data Storage**:
   - Network logs stored in IndexedDB (`TabDataDatabase`)
   - Navigation/console logs stored in `chrome.storage.local` (`eventData`, `apiDataArray`)
   - Video chunks stored in IndexedDB (`flonnect_chunks`)
   - Device/system info stored in `chrome.storage.local` (`systemInfo`)

3. **Data Transmission**:
   - User creates bug report (screenshot or video recording)
   - Extension aggregates: networkLogs, consoleLogs, deviceInfo, navigationHistory
   - Payload sent to `backend.flonnect.com` via POST requests
   - Screenshots/videos uploaded to AWS S3 via presigned URLs
   - Tab-specific network requests correlated and transmitted

4. **Backend Processing**:
   - Bug reports stored with associated metadata
   - Network logs, console output, and navigation history persisted
   - Screenshots/videos accessible via bug report interface

## Privacy Concerns

1. **Scope Creep**: A "screen recorder" extension collects far more than screen pixels - it captures complete network traffic, browsing history, and API responses
2. **Surveillance Without Clear Disclosure**: Optional permissions dialog may not adequately convey the depth of monitoring
3. **Third-party Data Leakage**: Network logs may contain data from other websites/services the user interacts with
4. **Persistent Tracking**: Navigation history and network patterns create detailed user profiles
5. **No Local-Only Mode**: Bug reporting requires cloud upload; no option to keep sensitive debug data local

## Recommendations

1. **For Users**:
   - Only grant optional `webRequest`/`webNavigation` permissions if actively debugging issues
   - Review data collection in extension's privacy policy before use
   - Revoke optional permissions when not needed via chrome://extensions
   - Avoid using extension on pages with sensitive information (banking, healthcare, etc.)

2. **For Developers**:
   - Implement local-only bug reporting mode without network log upload
   - Add granular controls for what data types to collect
   - Provide clear UI indicators when surveillance is active
   - Consider end-to-end encryption for uploaded bug reports
   - Add option to review/redact data before transmission
   - Implement automatic data retention limits

## Overall Risk Assessment

**Risk Level**: MEDIUM

**Justification**:
- Extension's surveillance capabilities are extensive but gated behind optional permissions
- Data collection appears intentional for bug reporting, not clearly malicious
- Network monitoring captures highly sensitive data including authentication credentials
- XHR interception could expose tokens, session IDs, and private API responses
- Lacks transparency about full extent of data collection
- No evidence of malicious behavior, but privacy implications are significant
- Legitimate use case (bug reporting) doesn't justify depth of monitoring for average users

**Threat Model**:
- **Insider Threat**: Flonnect has access to detailed user activity logs
- **Data Breach**: Compromise of Flonnect's backend would expose sensitive user data
- **Feature Creep**: Monitoring infrastructure could be repurposed for analytics/tracking
- **Accidental Exposure**: Network logs may inadvertently capture credentials or PII from third-party sites

The extension provides legitimate functionality but implements surveillance capabilities that significantly exceed what's necessary for screen recording. Users should carefully evaluate whether the bug reporting features justify granting such invasive permissions.
