# Vulnerability Report: HelloID Extension

## Metadata
- **Extension ID**: mffifeinkgjdnhnamgabdknfkdnmkgmj
- **Extension Name**: HelloID Extension
- **Version**: 5.0.0.6
- **Users**: ~300,000
- **Manifest Version**: 3
- **Publisher**: Tools4ever
- **Analysis Date**: 2026-02-15

## Executive Summary

HelloID Extension is an enterprise Single Sign-On (SSO) and password management solution developed by Tools4ever. The extension operates by intercepting HTTP authentication requests and automatically filling web forms with credentials retrieved from a configured HelloID portal server. While designed for legitimate enterprise identity management, the extension exhibits concerning security practices that pose medium-level risks.

The extension runs content scripts on all websites (http://*/*, https://*/*, file:///*/*) and intercepts authentication flows globally. It dynamically injects application-specific scripts from a library of hundreds of application packages, uses prototype modification to hook form submissions, and communicates credentials across all domains. While these capabilities are expected for an SSO solution, the implementation lacks proper origin validation and uses insecure practices like dynamic code injection.

## Vulnerability Details

### 1. MEDIUM: Dynamic Script Injection from Application Packages

**Severity**: MEDIUM
**Files**: service-worker.js (lines 323-335), Framework/js/sso.min.js (lines 697-714)
**CWE**: CWE-94 (Improper Control of Generation of Code - Code Injection)

**Description**: The extension dynamically injects application-specific JavaScript files from a library of application packages based on application GUIDs. These scripts are loaded at runtime using chrome.scripting.executeScript() and can execute arbitrary code in the context of the page.

**Evidence**:
```javascript
// service-worker.js lines 323-335
const injectLegacyScript = (app, tabId) => {
    console.info("Loading legacy script: " + app.applicationGUID);

    chrome.scripting
        .executeScript({
            target: { tabId: tabId },
            files: ["./Assets/application_packages/" + app.applicationGUID + ".js"]
        }).catch((error) => {
            console.log(error);
            console.log("Could not load application (" + app.applicationGUID + ") script")
        });
}
```

```javascript
// Framework/js/sso.min.js lines 697-714
executeScript(currentForm, currentField, scriptType) {
    if (!window.helloIDSSO) {
        return;
    }
    var key = currentField.key;
    if (!key || key.length === 0) {
        key = currentField.query;
    }
    if (currentForm.changepw) {
        window.helloIDSSO.changePasswordScript[key][scriptType](currentField);
    } else {
        window.helloIDSSO.loginScript[key][scriptType](currentField);
    }
}
```

These application packages (408 total .js files) define custom login and password change scripts that are executed in the page context. Example from 01d51ce7-502d-4376-8c96-1181915b6670.js:
```javascript
var helloIDSSO = {
    loginScript : {
        "submitBtn" : {
            postjs : function(currentField) {
                document.getElementById('helloid_closebanner_btn').click()
            }
        }
    },
    changePasswordScript : {}
};
```

**Verdict**: While the scripts appear to be bundled with the extension and not fetched remotely, the dynamic injection pattern and execution of arbitrary code from these packages represents a code injection risk. If any of these 408 application package files were compromised in the build process or contained malicious code, it would be executed in user contexts across all websites. This is a characteristic of enterprise SSO tools but represents an elevated attack surface.

### 2. MEDIUM: Prototype Modification and Form Submission Hooking

**Severity**: MEDIUM
**Files**: Content/SubmitHelloIDEvent.js (lines 11-19), Framework/js/sso.min.js (line 257)
**CWE**: CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)

**Description**: The extension modifies the HTMLFormElement prototype to intercept all form submissions across all websites. This is done by replacing the native submit() method with a wrapped version that dispatches additional events.

**Evidence**:
```javascript
// Content/SubmitHelloIDEvent.js lines 11-19
HTMLFormElement.prototype._nativeSubmit = HTMLFormElement.prototype.submit;
HTMLFormElement.prototype.submit = function () {
    var submitEvent = document.createEvent("HTMLEvents");
    submitEvent.initEvent("submit", true, false);
    if (this.dispatchEvent(submitEvent)) {
        this._nativeSubmit.apply(this, arguments);
    }
};
```

The same code is also injected inline via script injection:
```javascript
// Framework/js/sso.min.js line 257
scriptEl.innerHTML = 'HTMLFormElement.prototype._nativeSubmit = HTMLFormElement.prototype.submit;HTMLFormElement.prototype.submit = function () {var submitEvent = document.createEvent("HTMLEvents");submitEvent.initEvent("submit", true, false);if (this.dispatchEvent(submitEvent)) {this._nativeSubmit.apply(this, arguments);}};';
```

**Verdict**: Modifying built-in prototypes globally is a dangerous practice that can break website functionality and creates conflicts with other extensions or website code that may rely on the native behavior. While the modification appears benign (just ensuring submit events are properly dispatched), this technique is indicative of invasive code practices. This is a standard pattern for SSO extensions but increases the risk surface.

### 3. LOW: Broad Cookie and Storage Access Without Origin Validation

**Severity**: LOW
**Files**: service-worker.js (lines 233-258), manifest.json (lines 28-39)
**CWE**: CWE-346 (Origin Validation Error)

**Description**: The extension requests broad permissions (webRequest, cookies, storage, scripting) on all HTTP/HTTPS URLs and accesses cookies without strict origin validation in message handlers.

**Evidence**:
```javascript
// service-worker.js lines 233-258
chrome.cookies.get({ "url": background.portalUrl, "name": "_helloidentiy" }, async function (cookie) {
    if (cookie !== null) {
        var response;
        try {
            await SSO.Ajax.send(background.portalUrl + 'plugin/GetApplications')
                .then((r) => r.json())
                .then((data) => response = data);
        }
        catch (e) {
            response = undefined;
            console.log("exception in getApps");
        }
        if (response && response.result) {
            background.updateTime = Date.UTC();
            background.apps = response.result;
            chrome.storage.local.set({ appData: background.apps });
        }
    } else {
        console.log("Not signed on (no cookie available)");
    }
    if (callback)
        callback();
});
```

The extension operates on all URLs but relies on the presence of a specific cookie (_helloidentiy) to gate functionality. However, the message handlers in service-worker.js (lines 90-206) do not validate message origins.

**Verdict**: While the extension does check for a specific session cookie before retrieving credentials, there is no explicit origin validation in the chrome.runtime.onMessage.addListener handler. For an enterprise SSO tool operating on <all_urls>, this represents a minor security concern as malicious pages could potentially send crafted messages to trigger certain extension behaviors. The risk is mitigated by the fact that credentials are only provided for configured applications from the HelloID portal.

## False Positives Analysis

1. **HTTP Authentication Interception**: The webRequest.onAuthRequired listener (service-worker.js lines 44-87) intercepts HTTP Basic/Digest authentication prompts on all URLs. While this appears invasive, it is the core functionality of an SSO extension - automatically providing credentials for configured applications. This is NOT malicious but is expected behavior for enterprise SSO solutions.

2. **All URLs Permission**: The extension requests host_permissions for "https://*/*" and "http://*/*" which is extremely broad. However, this is necessary for an SSO solution that needs to work across any enterprise application. The extension only activates when it detects a configured application from the HelloID portal.

3. **Credential Storage and Transmission**: The extension stores application data in chrome.storage.local and retrieves credentials from the HelloID portal server. This is standard for SSO solutions - credentials are stored centrally on the portal, not in the extension itself.

4. **Content Scripts on All Frames**: The manifest specifies "all_frames": true for content scripts. This is necessary because login forms can appear in iframes (e.g., embedded SSO portals).

5. **Script Injection**: The chrome.scripting.executeScript calls are used to inject application-specific automation scripts. While this is a code injection pattern, it's using bundled scripts, not remotely fetched code.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| fonts.googleapis.com | Google Fonts CSS | None (CSP resource in popup.html) | None |
| {portalUrl}/plugin/GetApplications | Retrieve list of configured SSO apps | Portal cookie for auth | Low - requires valid session |
| {portalUrl}/plugin/GetCredentialData | Retrieve credentials for an app | applicationGuid parameter | Low - requires valid session |
| {portalUrl}/plugin/UpdateCredential | Update stored credentials | Credential set JSON | Low - requires valid session |
| {portalUrl}/RelayService/Redirect/{guid} | Launch SSO app | None (navigation) | None |

The portal URL is configured by the user in extension settings (options.js) and stored in chrome.storage.sync. All API calls require a valid session cookie (_helloidentiy) which indicates the user is authenticated to the HelloID portal.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

HelloID Extension is a legitimate enterprise SSO solution from Tools4ever, a recognized identity management vendor. The extension's core functionality - intercepting authentication requests, auto-filling credentials, and managing SSO workflows - is working as designed for its intended enterprise use case.

However, several implementation choices elevate the risk level:

1. **Dynamic Code Injection**: The pattern of injecting 408 different application-specific JavaScript files at runtime creates an elevated attack surface. If the extension's build process were compromised, malicious code could be injected into these packages and would execute across all user websites.

2. **Prototype Modification**: Globally modifying HTMLFormElement.prototype is an invasive practice that can cause conflicts and represents poor coding practices, even if the current implementation appears benign.

3. **Broad Permissions**: While necessary for SSO functionality, the combination of <all_urls> permissions, webRequest, cookies, and scripting creates a very powerful extension. If compromised, this extension would have extensive capabilities.

4. **Lack of Origin Validation**: Message handlers don't explicitly validate origins, though the risk is mitigated by the session cookie check.

The extension is rated MEDIUM rather than HIGH because:
- It is a legitimate enterprise tool from an established vendor
- The invasive permissions are necessary for SSO functionality
- Credentials are fetched from a user-configured portal with session authentication, not exfiltrated to unknown third parties
- The dynamic scripts are bundled with the extension, not fetched remotely
- There is no evidence of malicious behavior or undisclosed data collection

For enterprise deployments, this extension should be:
- Deployed only via enterprise policy with IT oversight
- Configured to connect only to trusted HelloID portal instances
- Monitored for unexpected network activity
- Kept updated to ensure application packages are current and secure
- Used with awareness that it has extensive access to all web pages and authentication flows
