# Vulnerability Report: Right Click Enable

## Metadata
- **Extension ID**: aegpaehcnpbhdmnghlnbnngogbfelnno
- **Extension Name**: Right Click Enable
- **Version**: 0.7.7
- **Users**: Unknown (not listed in CWS metadata)
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Right Click Enable is a browser extension that allows users to enable right-click context menus and copy-paste functionality on websites that restrict these capabilities. The extension implements a 7-day trial period after which users are required to pay via a third-party paywall service (onlineapp.pro). The extension collects user feedback including visited URLs and issue descriptions, which are sent to clevermathgames.com. While the extension appears to function as advertised for its core purpose, it lacks transparency about its paywall model and privacy practices around feedback collection.

The extension requests broad host permissions (`http://*/*`, `https://*/*`) which are necessary for its functionality but create significant attack surface. Analysis reveals medium-risk privacy concerns around undisclosed URL collection and a postMessage handler without origin validation. No evidence of malicious data exfiltration or credential theft was found.

## Vulnerability Details

### 1. MEDIUM: Undisclosed Feedback Collection with URL Exfiltration

**Severity**: MEDIUM
**Files**: feedback-popup.js, worker.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**: The extension displays a feedback popup asking users if the extension works on the current page. When users report issues, the extension collects the current URL along with the issue description and sends this data to clevermathgames.com without explicit user consent beyond a generic confirmation dialog.

**Evidence**:
```javascript
// feedback-popup.js
function submitFeedback(issueType,issueDescription){
    const currentUrl=currentLocation.href;
    const dataToSend=`Extension: ${extensionName} v${extensionVersion}\nURL: ${currentUrl}\nProblem: ${issueDescription}`;
    const userConfirmed=window.confirm(`This feedback will be sent to developers:\n\n${dataToSend}\n\n`+"Ensure no sensitive data is included.\n\n"+"Continue sending?");
    if(userConfirmed){
        const data={name:extensionName,URL:currentUrl,version:extensionVersion,issueType:issueType,issueDescription:issueDescription};
        fetch('https://clevermathgames.com/wp-json/custom/v1/feedback',{
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify(data)
        })
    }
}
```

The extension reads from `chrome.storage.local` to determine whether to show the feedback popup, and the static analyzer correctly identified this as an exfiltration flow: `chrome.storage.local.get → fetch(clevermathgames.com)`.

**Verdict**: While users are prompted with a confirmation dialog showing the data being sent, this feedback collection mechanism is not disclosed in the Chrome Web Store description. Users visiting sensitive URLs (banking, healthcare, private intranets) may inadvertently share these URLs when reporting issues. The dialog does warn "Ensure no sensitive data is included" which provides some protection, but the default behavior of including full URLs is a privacy concern.

### 2. MEDIUM: Undisclosed Paywall/Trial Model

**Severity**: MEDIUM
**Files**: worker.js, wall.js, check-payment.js
**CWE**: CWE-506 (Embedded Malicious Code)

**Description**: The extension implements a 7-day trial period (hardcoded as `TRIAL_IN_MS = 7 * 24 * 60 * 60 * 1000`) after which it requires payment through a third-party service at onlineapp.pro. This paywall is not mentioned in the Chrome Web Store description, which presents the extension as a free utility.

**Evidence**:
```javascript
// worker.js
const trialOver = await new Promise((resolve) => {
    const TRIAL_IN_MS = 7 * 24 * 60 * 60 * 1000;
    chrome.storage.local.get(['installDate', 'newUser'], (data) => {
        const {installDate, newUser} = data;
        if (!newUser) {
            resolve(false);
            return;
        }
        if (installDate) {
            const currentDate = new Date().getTime();
            const trialPeriodOver = ((currentDate - installDate) > TRIAL_IN_MS);
            resolve(trialPeriodOver);
        }
    });
});
if (trialOver && !isPaywallGetUserRunning) {
    // Inject paywall
    await chrome.scripting.executeScript({
        target: {tabId, ...properties, allFrames: false},
        injectImmediately: true,
        files: ['wall.js', '/data/inject/check-payment.js']
    });
}
```

The paywall system communicates with `onlineapp.pro` to check payment status and uses postMessage for cross-origin iframe communication.

**Verdict**: The undisclosed trial/paywall model constitutes deceptive behavior. Users install what appears to be a free extension only to discover after 7 days that payment is required. This violates user expectations and Chrome Web Store policies around transparency. While not technically malicious, this behavior pattern is commonly associated with unwanted software.

### 3. LOW: postMessage Handler Without Origin Validation

**Severity**: LOW
**Files**: wall.js
**CWE**: CWE-346 (Origin Validation Error)

**Description**: The paywall implementation uses `window.addEventListener("message")` to handle cross-origin communication with the onlineapp.pro payment iframe. While the handler does check that the message source matches the iframe's contentWindow, the static analyzer flagged this as a potential vulnerability.

**Evidence**:
```javascript
// wall.js
_globalEventHandler: function(e) {
    let a = this._paywallDocumentRoot.getElementById("paywall-".concat(this.paywallId));
    if (e.source === (null == a ? void 0 : a.contentWindow))
        for (let [t, n] of ("change-styles" === e.data.type ?
            Object.assign(a.style, {...e.data.style, ...this._overrideStyles || {}}) :
            "redirect" === e.data.type ? window.open(e.data.redirectUrl) :
            "remove" === e.data.type && a.remove(), this._eventHandlers)) n(e)
}
```

The handler validates that messages come from the expected iframe but does not explicitly check the origin against a whitelist. However, the code does validate origins in other locations:
```javascript
if ((null === (i = n.data) || void 0 === i ? void 0 : i.type) === "state" &&
    ["https://onlineapp.pro", "https://onlineapp.live", "https://onlineapp.stream"].includes(n.origin))
```

**Verdict**: The risk is mitigated by the source validation and origin checks present in the authentication flows. However, the `"redirect"` message type could potentially be exploited if an attacker could inject messages, as it calls `window.open(e.data.redirectUrl)` without validating the redirect destination. This is a low-severity issue as exploitation requires compromising the payment iframe first.

## False Positives Analysis

The static analyzer flagged the extension as "obfuscated" - this appears to be related to the minified paywall library (wall.js) which uses shortened variable names and compact formatting typical of production JavaScript bundles. The core extension logic in worker.js and the content scripts are readable and appear to be legitimate code. The use of webpack or similar bundling does not constitute malicious obfuscation.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| clevermathgames.com/wp-json/custom/v1/feedback | Feedback submission | Extension name, version, current URL, issue type, issue description | MEDIUM - Collects URLs without clear disclosure |
| clevermathgames.com/right-click-enable-uninstall/ | Uninstall tracking | None (URL visit only) | LOW - Standard analytics |
| multiplication-flash-cards.tilda.ws/right-click-enable | Welcome page | None (URL visit only) | LOW - Opened on first install |
| onlineapp.pro/paywall/237 | Payment iframe | None directly (iframe communication) | MEDIUM - Third-party payment service |
| onlineapp.pro/api/v1/paywall/237/user | User authentication | Cookies (via fetch with credentials) | MEDIUM - Authentication endpoint |
| onlineapp.pro/api/signout | Sign out | Cookies | LOW - Standard auth flow |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

The extension performs its advertised functionality (enabling right-click and copy-paste on restricted websites) without evidence of malicious code execution, credential theft, or hidden data exfiltration. However, it exhibits concerning privacy and transparency issues:

1. **Undisclosed Paywall**: The 7-day trial leading to a paid subscription via onlineapp.pro is not mentioned in the store listing, constituting deceptive behavior.

2. **URL Collection**: The feedback mechanism collects and transmits user URLs to a third-party domain (clevermathgames.com) with only a generic consent dialog. Users visiting sensitive sites may inadvertently leak private URLs.

3. **Broad Permissions**: The extension requests `http://*/*` and `https://*/*` which are necessary for its functionality but create significant attack surface if the extension were to be compromised or sold to a malicious actor.

4. **Third-Party Payment Integration**: The paywall integration with onlineapp.pro involves cross-origin iframe communication and could potentially be exploited, though no active vulnerabilities were identified.

The extension does not exhibit characteristics of malware (no keylogging, no hidden crypto mining, no botnet C2, no credential theft). The primary concerns are around user privacy and transparency rather than active malicious behavior. The MEDIUM risk rating reflects the need for improved disclosure and privacy practices while acknowledging the extension's legitimate core functionality.

**Recommendations**:
- Disclose the trial/payment model clearly in the Chrome Web Store description
- Make feedback URL collection opt-in rather than default behavior
- Implement explicit origin validation for all postMessage handlers
- Consider using a privacy-preserving feedback mechanism that doesn't collect full URLs
