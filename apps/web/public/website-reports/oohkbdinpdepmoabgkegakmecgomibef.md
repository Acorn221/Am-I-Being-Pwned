# Vulnerability Report: RapidIdentity

## Metadata
- **Extension ID**: oohkbdinpdepmoabgkegakmecgomibef
- **Extension Name**: RapidIdentity
- **Version**: 2024.10.0.1
- **Users**: ~2,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

RapidIdentity is an enterprise Single Sign-On (SSO) extension developed by Identity Automation, LP, designed to provide form-fill SSO capabilities when used with their RapidIdentity product. The extension has legitimate enterprise functionality but exhibits security concerns that warrant a MEDIUM risk rating.

The extension operates on all websites (`<all_urls>`) with both content scripts and host permissions, monitoring form submissions and providing automatic credential filling based on templates received from a backend system. While this is expected behavior for an SSO solution, the implementation has security weaknesses including postMessage communication without origin validation and broad interception of user interactions across all web pages.

## Vulnerability Details

### 1. MEDIUM: Unsafe postMessage Communication Without Origin Validation

**Severity**: MEDIUM
**Files**: content.js (lines 25-32, 72-80)
**CWE**: CWE-345 (Insufficient Verification of Data Authenticity)

**Description**: The content script uses custom events and postMessage-like patterns to communicate between the page context and extension context without validating the origin or source of messages. The `SendTwoFASSOMessage` function dispatches custom events that can be triggered by any script running in the page context.

**Evidence**:
```javascript
function SendTwoFASSOMessage(sMessage, sType, pDetails, fFirefox)
{
    trace("content -> SendTwoFASSOMessage(" + sMessage + ") fFirefox=" + (fFirefox == true ? "true" : "false"));
    var pData = { type: sType, detail: pDetails };
    var evt = document.createEvent("CustomEvent");
    evt.initCustomEvent(sMessage, true, true, fFirefox ? cloneInto(pData, document) : pData);
    document.dispatchEvent(evt);
}

function OnTwoFASSOEvent(msg)
{
    if(msg.type == "TwoFASSOEnableDebug")
    {
        LogEnabledTime = msg.detail;
        trace("content -> TwoFASSOEnableDebug: " + msg.detail);
    }
    SendBrowserMessage(msg.type, msg.detail, function(response) { SendTwoFASSOResult(msg.type, response); });
}

window.addEventListener("TwoFASSOConnect", OnTwoFASSOEvent);
window.addEventListener("TwoFASSOSetTemplates", OnTwoFASSOEvent);
```

The event listeners on lines 584-587 accept custom events without validating that they originated from a trusted source. A malicious website could dispatch these events to manipulate the extension's behavior, potentially enabling debug mode or injecting malicious templates.

**Verdict**: This represents a genuine security concern for an extension with 2 million users handling sensitive credential data. While exploitation requires specific conditions, the lack of origin validation creates an attack surface for malicious websites.

### 2. LOW: Credential Storage and Transmission Mechanism Unclear

**Severity**: LOW
**Files**: content.js (lines 431-456, 524-525), background.js (lines 56-97)
**CWE**: CWE-311 (Missing Encryption of Sensitive Data)

**Description**: The extension collects form data including usernames and passwords and sends them to the background script via `TwoFASSOSaveForm` messages. The exact storage mechanism and whether credentials are encrypted in transit to the RapidIdentity backend is not visible in the client-side code.

**Evidence**:
```javascript
function GetFormData(pFormElement, sURL, sTitle)
{
    var sFormPath = GetNodeTreeXPath(pFormElement);
    var sFormName = IsStrEmpty(pFormElement.name) ? sFormPath : pFormElement.name;
    var pFormFields = new Array();
    var pFormCreds = new Array();
    // ...
    for(var iElement = 0; iElement < pFormElement.elements.length; iElement++)
    {
        var pElement = pFormElement.elements[iElement];
        if(SSOFieldTypes.indexOf(pElement.type) != -1)
        {
            pFormFields.push(iElement + "\r" + GetNodeTreeXPath(pElement) + "\r" + pElement.name);
            pFormCreds.push(escape(pElement.value));
        }
    }
    // ...
}

// Later sent to background
SendBrowserMessage("TwoFASSOSaveForm", pFormData, function(response) { });
```

The credentials are only escaped using the deprecated `escape()` function (not encryption), and it's unclear how they are stored or transmitted to the RapidIdentity backend. For an enterprise SSO solution handling 2 million users' credentials, this warrants closer examination.

**Verdict**: This is marked as LOW severity because this is an enterprise product that likely has proper security implementations on the backend that aren't visible in the extension code. However, the client-side code review alone cannot verify the security of credential handling.

## False Positives Analysis

### HTTP Basic Auth Credential Handling
The extension intercepts `webRequest.onAuthRequired` events to automatically fill HTTP Basic Authentication dialogs (background.js, lines 56-97). This might appear as credential theft, but it's a legitimate feature for enterprise SSO systems that need to handle legacy Basic Auth prompts. The credentials are pre-configured via templates sent from the RapidIdentity backend.

### Global Form Interception
The content script monitors all form submissions across all websites (lines 508-529, 531-541). While this could be flagged as suspicious keylogging or form hijacking, it's the expected behavior for an SSO extension that needs to:
1. Detect login forms to auto-fill credentials
2. Offer to save new credentials when users manually log in

The extension does show user confirmation dialogs (line 601: `confirm("RapidIdentitySSO: Do you want to apply saved form?")`), providing transparency about its actions.

### Click and Submit Event Listeners
The extension attaches click and submit listeners to all pages (lines 543-577). This is necessary for the SSO functionality to detect when users are attempting to log in, not malicious event interception.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| None observed | N/A | N/A | N/A |

**Note**: The extension does not make direct HTTP requests visible in the analyzed code. All credential handling appears to go through the RapidIdentity backend infrastructure, which is managed separately from the extension code. The extension receives SSO templates from the backend via message passing but doesn't show the network layer implementation.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

RapidIdentity is a legitimate enterprise SSO solution from Identity Automation, LP, with 2 million users. The core functionality of form-filling, credential storage, and HTTP Basic Auth handling is expected for this class of extension. However, the implementation has security weaknesses that elevate it to MEDIUM risk:

1. **postMessage/CustomEvent without origin validation** - The most significant concern. The extension accepts commands via custom DOM events without validating the source, potentially allowing malicious websites to manipulate extension behavior or inject templates.

2. **Broad permissions scope** - The extension operates on `<all_urls>` with full host permissions, meaning any vulnerability can be exploited on any website the user visits.

3. **Unclear credential security** - While likely secure in practice given this is an enterprise product, the client-side code doesn't demonstrate encryption or secure transmission of credentials, relying on backend systems not visible in the extension.

4. **Low user ratings (1.8/5)** - This unusually low rating for an enterprise product may indicate user concerns or functionality issues that could relate to security or privacy problems.

**Recommendation**: For an enterprise security product handling credentials for 2 million users, the postMessage vulnerability should be addressed by validating the origin of custom events. The extension is not malicious but has implementation weaknesses that could be exploited by sophisticated attackers on malicious websites.
