# Vulnerability Report: Calabrio Analytics Plugin

## Metadata
- **Extension ID**: hecgknieibccghjmmhhckdfeobjoffdf
- **Extension Name**: Calabrio Analytics Plugin
- **Version**: 0.2.0.7
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Calabrio Analytics Plugin is an enterprise contact center analytics tool that monitors agent activity by capturing comprehensive user interaction data across all websites. The extension intercepts and logs form field focus/blur events, XMLHttpRequest responses, and navigation activity, transmitting this data to a local native application ("chromeplugin.exe") via Chrome's nativeMessaging API. While this functionality is legitimate for its intended purpose as an enterprise workforce management and quality monitoring solution, it represents significant privacy exposure. The extension runs content scripts on all URLs (`*://*/*`) and captures sensitive data that could include user credentials, PII, and confidential business information entered into web forms. The data collection occurs indiscriminately across all websites without user-visible consent mechanisms.

This extension is classified as MEDIUM risk because it is a disclosed enterprise monitoring tool with a legitimate business use case, but it implements extensive surveillance capabilities including form field monitoring and XHR interception that could capture sensitive data if deployed outside its intended enterprise context.

## Vulnerability Details

### 1. MEDIUM: Comprehensive Form Field Data Collection
**Severity**: MEDIUM
**Files**: script.js, inject.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: The extension monitors all form field interactions on every website by hooking focus and blur events on all input elements. It captures field attributes, values, and metadata, then transmits this data to a native application. This occurs via injection of `script.js` into the page context, which registers handlers that fire every second via `setInterval(registerFieldHandlers, 1000)`.

**Evidence**:
```javascript
// script.js lines 174-194
function registerFieldHandlers() {
    var i;
    var inputs= document.getElementsByTagName("input");
    for (i=0; i < inputs.length; i++) {
        var myform = inputs[i];
        if(myform.chainedCalabrioEvent != 1) {
            myform.chainedCalabrioEvent = 1;
            myform.addEventListener('focus', calabrioOnFocusHandler);
            myform.addEventListener('blur', calabrioOnBlurHandler);
            if(myform.autofocus) {
                calabrioFieldHandler(myform,'onfocus');
            }
        }
    }
}

// script.js lines 65-117
function createJsonEvent(element,eventType) {
    // ... captures all element attributes and values
    jsonEvent["fieldValue"] = element.value;
    // sends to native app via background.js
}
```

The captured data includes the full field value (`element.value`) which could contain passwords, credit card numbers, SSNs, or other PII.

**Verdict**: This is a legitimate enterprise monitoring feature for contact center quality assurance and compliance purposes. However, if deployed on personal devices or outside the intended enterprise context, it represents a significant privacy risk. The extension description "Field Detection" does not clearly communicate the extent of monitoring to end users.

### 2. MEDIUM: XMLHttpRequest Response Interception
**Severity**: MEDIUM
**Files**: script.js
**CWE**: CWE-319 (Cleartext Transmission of Sensitive Information)
**Description**: The extension hooks the native `XMLHttpRequest.prototype.send` method to intercept all XHR responses on every website. When XHR requests complete (readyState == 4), it attempts to parse the response as JSON and sends both the response data and URL to the native application.

**Evidence**:
```javascript
// script.js lines 206-249
(function(send) {
    XMLHttpRequest.prototype.send = function(data) {
        var readyStateChange = this.onreadystatechange;
        if (readyStateChange) {
            this.onreadystatechange = function() {
                if(this.readyState == 4) {
                    var JSONobj = {};
                    var payload = {};
                    payload["type"] = "xhr";
                    try {
                        var o = JSON.parse(this.response);
                        if (o && typeof o === "object" && o !== null) {
                            payload["data"] = o;
                        }
                    } catch (e) {
                        payload["data"] = "";
                    }
                    payload["url"] = this.responseURL;
                    JSONobj["payload"] = JSON.stringify(payload);
                    document.dispatchEvent(new CustomEvent('CaFieldEvent', {detail: JSONobj}));
                }
                return readyStateChange.apply(this, arguments);
            };
        }
        return send.apply(this, arguments);
    };
})(XMLHttpRequest.prototype.send);
```

This could capture API responses containing authentication tokens, user profile data, or sensitive business information from web applications.

**Verdict**: This is a standard feature for enterprise session recording and analytics tools used in contact centers. The captured XHR data allows supervisors to understand the full context of customer interactions. However, the lack of filtering means it captures data from all websites, not just the contact center application.

## False Positives Analysis

Several patterns that might appear suspicious are actually legitimate for this extension type:

1. **Native Messaging to "chromeplugin.exe"**: This is the expected architecture for enterprise monitoring tools. The extension is a lightweight data collector that forwards events to a native application (Calabrio's Screen and Desktop Capture service) which handles storage, analytics, and compliance features.

2. **Content Script on `*://*/*`**: While broad, this is necessary because contact center agents may interact with multiple web applications during customer support sessions (CRM systems, knowledge bases, ticket systems, etc.). The extension needs to monitor activity across all of these.

3. **webNavigation Permission**: Used to track which URLs the agent visits during their work session. This is a core feature for quality monitoring and compliance in regulated industries.

4. **CCaaS Integration**: The code includes handlers for Contact Center as a Service (CCaaS) events (login, call start/end, logout). This integrates with cloud contact center platforms to correlate captured data with specific customer calls.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| None | N/A | All data sent to local native application "chromeplugin.exe" via `chrome.runtime.connectNative()` | LOW - Data stays local, not transmitted to remote servers by this extension |

The extension does not make any network requests directly. All captured data is transmitted to a local Windows executable via Chrome's nativeMessaging API. The native application would handle any subsequent network transmission to Calabrio's backend systems, which is outside the scope of this extension analysis.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

This is a legitimate enterprise workforce monitoring tool with appropriate use in contact center environments where employers have legal obligations to record customer interactions for compliance, quality assurance, and training purposes. The extension's functionality aligns with its stated purpose as an analytics plugin for Calabrio's contact center platform.

However, it receives a MEDIUM risk rating rather than LOW due to:

1. **Scope of Data Collection**: The extension indiscriminately monitors ALL websites visited, not just the contact center application. This captures data from personal browsing, banking sites, healthcare portals, etc. if the agent uses the same browser for non-work activities.

2. **Sensitive Data Exposure**: Form field values and XHR responses may contain passwords, authentication tokens, PII, PHI, financial data, or other sensitive information that extends beyond what's necessary for contact center quality monitoring.

3. **Lack of User Transparency**: The extension description "Field Detection" significantly understates the extent of monitoring. Users (agents) may not fully understand that every keystroke, form field, and API response is being captured.

4. **No Privacy Controls**: There are no visible mechanisms for pausing monitoring, excluding certain websites, or filtering sensitive data types. The only control appears to be the CCAAS_CONNECTED flag which gates some functionality but not all data collection.

This extension is appropriate for enterprise-managed devices where employees have been notified of monitoring practices and have signed acceptable use policies. It would be HIGH risk if deployed on personal devices or without explicit user consent. Organizations using this tool should implement browser profile separation to ensure agents use dedicated work profiles that don't contain personal browsing activity.
