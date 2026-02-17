# Vulnerability Report: Onelog

## Metadata
- **Extension ID**: onjjmhhddjeopkhboiehpmhihjmoecpi
- **Extension Name**: Onelog
- **Version**: 2.10.2511.5
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Onelog is an enterprise-grade time tracking and session monitoring extension deployed in corporate environments. The extension operates by collecting comprehensive user activity data including visited URLs, window titles, form inputs, and page analytics, transmitting this data to a locally-installed service (localhost:12345) which acts as a relay to cloud infrastructure at cloud.onelog.com.

While the extension appears to be a legitimate enterprise monitoring tool with consent-based deployment, it exhibits significant privacy implications due to its extensive data collection capabilities across all websites, execution of remote JavaScript for page analysis, and storage of personal details/passwords. The extension is clearly designed for workforce monitoring in corporate settings where users are presumably notified of surveillance, but the broad permissions and data access present HIGH privacy risks if deployed without explicit user consent or if the backend service/cloud infrastructure is compromised.

## Vulnerability Details

### 1. HIGH: Comprehensive User Activity Surveillance
**Severity**: HIGH
**Files**: serviceWorker.js, extensionMessaging.js, modAnalysis.js, extensionApiService.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: The extension continuously monitors and collects detailed user browsing activity across all websites including:
- All visited URLs via webNavigation events
- Window/document titles
- Form field values and submissions
- Page-specific analytics data extracted via configurable rules
- Tab information and session tracking
- Personal details and passwords (SetPersonalDetailsRequest, GetSharedPasswordsRequest)

**Evidence**:
```javascript
// extensionApiService.js - Sends browsing data to backend
BeforeNavigateRequestSend: function (requestContent, processRequestSuccess) {
    var ajaxData_ = {
        BeforeNavigateRequest: {
            URL: requestContent.TabMember.PageInfo.RequestUrl,
            WindowId: requestContent.TabMember.WindowId,
            SessionSetId: 1,
            WindowHandle: requestContent.TabMember.WindowHandle,
            BrowserType: (browserName_ == olWrap.browser.name.edg ? 'chrome' : browserName_),
            NewEdgeCompatibility: (browserName_ == olWrap.browser.name.edg)
        }
    };
    if (olExtension._internal.UsernameResolved) {
        ajaxData_.BeforeNavigateRequest.Username = olExtension._internal.Username
    }
    olExtension.Service._internal.SendRequest(sendRequestParams_);
}

// Collects form submissions
FormSubmitRequestSend: function (requestContent, processRequestSuccess) {
    var ajaxData_ = {
        FormSubmitRequest: {
            ApplicationSessionId: requestContent.TabMember.ApplicationsSessionId
        }
    };
}

// Collects personal details including passwords
SetPersonalDetailsRequestSend: function (requestContent, processRequestSuccess) {
    var ajaxData_ = {
        SetPersonalDetailsRequest: {
            ApplicationSessionId: requestContent.TabMember.ApplicationsSessionId,
            Variable: requestContent.Parameters.Variable
        }
    };
}
```

**Verdict**: This is HIGH severity because while this appears to be a legitimate enterprise monitoring tool (similar to ActivTrak, Teramind, etc.), the sheer breadth of data collection without visible user consent mechanisms in the extension code represents significant privacy exposure. In enterprise deployments with informed consent, this would be expected behavior; however, the extension's presence on 100K+ users raises questions about deployment transparency.

### 2. HIGH: Remote Code Execution for Page Analysis
**Severity**: HIGH
**Files**: modAnalysis.js, extensionApiService.js
**CWE**: CWE-94 (Improper Control of Generation of Code)
**Description**: The extension receives base64-encoded JavaScript from the remote server and executes it in page context for "fingerprinting" and analytics purposes. This creates a code execution pathway controlled by the backend service.

**Evidence**:
```javascript
// modAnalysis.js - Executes remote JS in page context
ProcessAnalysis: function (applicationType, jscodeArray) {
    try {
        switch (applicationType) {
            case 'FP':
                window.OnelogClientResponse = Analysis.OneLogClientResponse;
                var currentJsCode_ = '';
                for (var i = 0; i < jscodeArray.length; i++) {
                    currentJsCode_ = currentJsCode_ + atob(jscodeArray[i].jsCode);
                }
                var atobCode_ = '"olInternalJS";window.OnelogClientResponse = Analysis.OneLogClientResponse;try{' + currentJsCode_ + '}catch(e){console.log("AnalysisCode ERROR!!!!!!!!!!!!!!!!!");console.log(e)};';
                olfWrap.browser.execScript(atobCode_)
                break;
```

The executed code can send data back via `window.OnelogClientResponse.OLSendData()` which relays to the extension:
```javascript
OneLogClientResponse: {
    OLSendData: function (messageContent) {
        Analysis.dispatchMessage('olSetAnalysisRequest', messageContent);
    }
}
```

**Verdict**: HIGH severity. While the execution is intended for page analysis/fingerprinting as part of the monitoring service, this creates a dynamic remote code execution channel. If the backend server (localhost:12345 or cloud.onelog.com) is compromised, arbitrary JavaScript could be injected into all visited pages. The execution scope is limited to page context (not extension privileges) which somewhat mitigates risk.

### 3. MEDIUM: Localhost Service Dependency with Cloud Fallback
**Severity**: MEDIUM
**Files**: extension.js, modOptions.js, extensionApiService.js
**CWE**: CWE-319 (Cleartext Transmission of Sensitive Information)
**Description**: The extension communicates with a locally-installed service at http://localhost:12345 (cleartext HTTP) to relay all monitoring data. Fallback endpoints include cloud.onelog.com over HTTPS.

**Evidence**:
```javascript
// extension.js - Cloud endpoints
ResourcesUrlPrefix: 'https://cloud.onelog.com/extensions/olResources/',
LogoutUrl: 'https://cloud.onelog.com/extensions/olResources/logout.html',
LogoutInfoUrl: 'https://cloud.onelog.com/extensions/olResources/logoutInfo.html',
RuntimeDataUrl: 'https://cloud.onelog.com/extensions/olResources/olRuntimeData.json',

// modOptions.js - Localhost service (HTTP)
ServerUrl: 'http://localhost:12345/index/',

// extensionApiService.js - Fetch request to server
_SendRequestFetch: async function (sendRequestParameters) {
    const response = await fetch(olOptions.General.Extension.ServerUrl(), {
        method: sendRequestParameters.AjaxParam.Type,
        cache: 'no-cache',
        timeout: sendRequestParameters.AjaxParam.Timeout,
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(sendRequestParameters.AjaxParam.Data)
    });
    return response.json();
}
```

**Verdict**: MEDIUM severity. The localhost service uses cleartext HTTP which could expose monitoring data to local network attackers or malicious software on the same machine. However, this is typical for localhost IPC mechanisms and the cloud endpoints do use HTTPS. The architecture suggests a local relay service that handles the actual cloud transmission.

### 4. LOW: Overly Permissive Web Accessible Resources
**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-668 (Exposure of Resource to Wrong Sphere)
**Description**: The extension exposes all resources via wildcard patterns, allowing any webpage to probe for the extension's presence and potentially access extension resources.

**Evidence**:
```json
"web_accessible_resources": [
  {
    "resources": [
      "assets/*",
      "icons/*",
      "fonts/*",
      "*"
    ],
    "matches": [
      "http://*/*",
      "https://*/*"
    ]
  }
]
```

**Verdict**: LOW severity. While the wildcard `"*"` pattern is overly broad, the actual risk depends on what sensitive resources exist. This mainly enables extension fingerprinting and potential information disclosure, but given this is an enterprise monitoring tool where detection isn't a primary concern, the impact is minimal.

## False Positives Analysis

1. **Legitimate Enterprise Tool**: The extension appears to be a legitimate workforce analytics/time tracking solution similar to ActivTrak, Time Doctor, or Teramind. The data collection is extensive but expected for this category of software.

2. **Local Service Architecture**: The localhost:12345 endpoint is not malicious obfuscation but rather a standard architecture for enterprise browser extensions that need to communicate with locally-installed management software.

3. **Password Management Features**: The `SetPersonalDetailsRequest` and `GetSharedPasswordsRequest` functions appear to be for legitimate password autofill/management features within monitored corporate applications, not credential theft.

4. **Remote Config**: The extension fetches configuration from `RuntimeDataUrl` which is standard practice for enterprise deployments requiring centralized policy management.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| http://localhost:12345/index/ | Primary relay service | All monitoring data (URLs, titles, form data, analytics, personal details, session info) | MEDIUM - Cleartext HTTP on localhost |
| https://cloud.onelog.com/extensions/olResources/ | Cloud backend resources | Configuration, logout handling, runtime data | LOW - HTTPS encrypted |
| https://devtest.onelog.com/mobview/olResources/ | Development/test endpoints (commented out) | Same as production | LOW - Dev endpoints |

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**:

Onelog is a legitimate enterprise monitoring and time tracking solution, but receives a HIGH risk rating due to:

1. **Comprehensive Privacy Exposure**: The extension has unfettered access to all user browsing activity, form inputs, and potentially sensitive personal/credential data across all websites (`<all_urls>`). While this is the intended functionality, it represents significant privacy exposure if deployed without explicit user consent or knowledge.

2. **Remote Code Execution**: The ability to execute server-supplied JavaScript in page contexts creates a potential attack surface if the backend infrastructure (localhost service or cloud.onelog.com) is compromised.

3. **Enterprise Context Required**: This extension should ONLY be deployed in enterprise environments where:
   - Users are explicitly informed of monitoring
   - IT administrators control deployment via policy
   - Legal/compliance frameworks support workplace monitoring
   - The Onelog service infrastructure is properly secured

4. **100K User Base**: With ~100,000 users, the scale of data collection and potential impact of any security incident is substantial.

**Recommended Actions**:
- For Enterprise IT: Ensure deployment is policy-based with user notification, not voluntary installation
- For Individual Users: Remove this extension unless you are knowingly participating in corporate monitoring programs
- For Onelog Vendor: Implement extension-level consent verification and upgrade localhost service to use encrypted transport (HTTPS or secure IPC)
- Security Monitoring: The localhost service at port 12345 should be monitored for compromise as it is a high-value target

This is not malware in the traditional sense, but rather enterprise surveillance software with legitimate use cases that becomes HIGH risk when privacy expectations and deployment context are not properly managed.
