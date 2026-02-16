# Vulnerability Report: ProctorExam Activity Sharing

## Metadata
- **Extension ID**: digojkgonhgmnohbapdfjllpnmjmdhpg
- **Extension Name**: ProctorExam Activity Sharing
- **Version**: 1.8.1
- **Users**: ~800,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

ProctorExam Activity Sharing is a proctoring extension used during online exams on proctorexam.com. The extension monitors browser tabs and shares browsing activity with the ProctorExam platform during exam sessions. While the extension's functionality is aligned with its stated purpose of exam proctoring, it contains a moderate security vulnerability: the content script uses `window.addEventListener("message")` without proper origin validation (line 17), creating an attack surface that could allow malicious websites to interact with the extension's privileged APIs if a student navigates to an attacker-controlled page during an exam.

The extension collects sensitive browsing data (tab URLs, tab creation/closure events) and forwards this information to the ProctorExam website. This data collection is disclosed and expected for an exam proctoring tool, making it legitimate within the context of its purpose.

## Vulnerability Details

### 1. MEDIUM: PostMessage Handler Without Origin Validation

**Severity**: MEDIUM
**Files**: content-script.js
**CWE**: CWE-942 (Permissive Cross-domain Policy with Untrusted Domains)
**Description**: The content script implements a message handler on line 17 that listens to all postMessage events from any origin. While the handler does implement some validation (checking event.source, data structure, and a "from" field), it does not validate the origin of the message sender against a whitelist of trusted domains.

**Evidence**:
```javascript
// content-script.js:17
window.addEventListener('message', messageHandler);

// content-script.js:56-68
function onMessageHandler(port) {
  return function onMessage(event) {
    if(event.source != window) {
      return;
    }

    if(!(event.data != null && typeof event.data === 'object' && event.data[prefix]
      && event.data.payload != null && typeof event.data.payload === 'object')) {
      return;
    }

    if(event.data.from !== 'jsapi') {
      return;
    }
    // ... handles messages without checking event.origin
  }
}
```

The validation checks that `event.source == window` (same-window messages only) and `event.data.from === 'jsapi'`, but an attacker-controlled script injected into the same page could craft messages meeting these criteria.

**Verdict**: MEDIUM severity. The extension only runs on `https://*.proctorexam.com/*` domains (per manifest), which significantly limits the attack surface. An attacker would need to either compromise the ProctorExam website or exploit an XSS vulnerability on that domain to inject malicious scripts. The impact is limited to tab manipulation APIs (open/close/refresh tabs, query tab information) rather than direct data exfiltration, though an attacker could potentially open tabs to malicious sites or interfere with the exam session.

### 2. LOW: Broad Tab Monitoring Capabilities

**Severity**: LOW
**Files**: background-script.js
**CWE**: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
**Description**: The background script monitors all tab events (creation, updates, removal) and queries tab information including URLs. This is forwarded to the ProctorExam website via the content script bridge.

**Evidence**:
```javascript
// background-script.js:28-29
chrome.tabs.onRemoved.addListener(handleOnRemoved);
chrome.tabs.onUpdated.addListener(handleOnUpdated);

// background-script.js:45-48
function handleOnUpdated(tabId, changeInfo, tab) {
  if(changeInfo.status == 'complete') {
    port.postMessage({method: 'updatedTab', payload: {tabId: tabId, tab: tab, tabUrl: changeInfo.url}});
  }
}

// background-script.js:61-64
function getTabs() {
  chrome.tabs.query({}, function(tabs) {
    port.postMessage({method: 'tabs', payload: {tabs: tabs}});
  });
}
```

**Verdict**: LOW severity. This behavior is expected and disclosed for an exam proctoring extension. Students installing this extension should reasonably expect their browsing activity to be monitored during exams. The permissions are appropriate for the stated purpose (activeTab, tabs, scripting).

## False Positives Analysis

1. **Tab monitoring/data collection**: While the extension collects browsing data (tab URLs, events), this is the core functionality of a proctoring tool and is disclosed in the extension description ("share your browsing activity when taking an online exam"). This is NOT data exfiltration in the malicious sense.

2. **Dynamic tab operations**: The extension can open, close, and refresh tabs based on messages from the webpage. This is a legitimate feature for exam platforms that may need to control the student's browser environment during testing.

3. **Extension enumeration check**: The `isExtensionInstalled` method is a standard handshake pattern to verify the extension is present before starting an exam session, not malicious fingerprinting.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://*.proctorexam.com/* | Exam proctoring platform | Tab URLs, tab count, tab creation/update/removal events, extension version | LOW - Disclosed functionality for exam monitoring |

The extension only communicates with the ProctorExam domain through the content script bridge. No external third-party endpoints are contacted.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
The extension performs its stated purpose (exam proctoring and browser activity monitoring) without deceptive behavior. However, the postMessage handler vulnerability creates a moderate security risk: if an attacker can inject JavaScript into a proctorexam.com page (via XSS or website compromise), they could send crafted messages to manipulate tabs, potentially disrupting exam sessions or opening malicious tabs.

The risk is mitigated by:
- The content script only runs on proctorexam.com domains (limited attack surface)
- The validation checks prevent many trivial attacks (requires crafting specific message format)
- The impact is limited to tab manipulation rather than direct credential theft or data exfiltration

The extension would benefit from strict origin validation in the message handler (checking `event.origin` against a whitelist) to prevent potential abuse even in the event of a proctorexam.com compromise.

Given the large user base (800,000 users) and the moderate vulnerability, a MEDIUM risk rating is appropriate.
