# Vulnerability Report: TestCase Studio - Selenium IDE

## Metadata
- **Extension ID**: loopjjegnlccnhgfehekecpanpmielcj
- **Extension Name**: TestCase Studio - Selenium IDE
- **Version**: 1.8.9
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

TestCase Studio is a legitimate Selenium IDE alternative that records user actions on web applications and converts them to English sentences for test automation. The extension integrates with TestRigor (a third-party testing platform) and uses analytics services operated by the same developer (SelectorHub). Despite ext-analyzer flagging data flows to app.testrigor.com, this is an intentional and disclosed feature - the extension explicitly offers an "Execute on TestRigor" button that sends recorded test steps to TestRigor's external test execution service.

The extension operates transparently as a test recording tool with proper disclosure of its TestRigor integration via the homepage URL (selectorshub.com/testcase-studio/) and UI elements. No undisclosed data collection, credential theft, or malicious behavior was identified.

## Vulnerability Details

### False Positive Analysis

The static analyzer flagged two EXFILTRATION flows involving `document.querySelectorAll → fetch(app.testrigor.com)`. However, detailed code review reveals this is the extension's core legitimate functionality:

**Evidence from captureEvents.js (lines 1178-1189)**:
```javascript
document.getElementById("execute_btn").addEventListener("click", function() {
  trackEvent("execute test on testrigor");
  if (steps && steps.length) {
    var a = document.querySelector(".testRigorLink"),
      b = steps[1].step;
    // ... builds URL with test steps ...
    for (var c = "https://app.testrigor.com/external-test?url=" +
         encodeURIComponent(steps[0].dataText) + "&steps=" + b,
         f = 2; f < steps.length; f++) {
      // Concatenates user's recorded test steps
      c = c + "%0A" + b;
    }
    a.setAttribute("href", c + "&reference=selectorshub&utm_source=selectorshub&utm_medium=tcs&eid=LYFcml")
  }
})
```

**Verdict**: The "data exfiltration" is user-initiated via an explicit "Execute on TestRigor" button that sends the user's recorded test case to TestRigor's cloud testing service. This is:
1. Disclosed in the extension's description and homepage
2. Triggered by explicit user action (clicking execute button)
3. Functionally necessary for the advertised TestRigor integration
4. Not collecting browsing data beyond the test case the user explicitly recorded

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| shubads.testcasehub.net | Analytics tracking | Usage events, country info | Low - standard analytics |
| selectorshub.info | Extension API | Extension data | Low - first-party service |
| app.testrigor.com | Test execution service | User-recorded test steps (user-initiated) | None - disclosed integration |
| selectorshub.com | Cookie domain | Authentication cookie | None - first-party auth |

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:
TestCase Studio is a legitimate test automation tool that operates as advertised. The extension records user interactions for test case generation and optionally integrates with TestRigor's cloud testing platform. All data flows are either:
- First-party analytics to the developer's own infrastructure
- User-initiated exports to TestRigor (a disclosed third-party testing service)
- Local storage of recorded test cases

The extension does not engage in:
- Hidden data exfiltration
- Credential theft
- Browsing history collection beyond explicitly recorded test steps
- Ad injection or affiliate manipulation
- Any form of deceptive behavior

The static analyzer's EXFILTRATION flags are false positives related to the extension's core disclosed functionality of sending user-created test cases to an external testing platform when the user clicks "Execute on TestRigor".
