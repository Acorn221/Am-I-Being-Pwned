# Vulnerability Report: Accessibility Insights for Web

## Metadata
- **Extension ID**: pbjjkligggfmakdaogkfomddhfmpjeni
- **Extension Name**: Accessibility Insights for Web
- **Version**: 2.46.0
- **Users**: ~100,000
- **Manifest Version**: 3
- **Author**: Microsoft Corporation
- **Analysis Date**: 2026-02-15

## Executive Summary

Accessibility Insights for Web is a legitimate developer tool created by Microsoft Corporation to help developers identify and fix accessibility issues in web applications. The extension performs accessibility testing using the axe-core accessibility engine and provides detailed reports through a DevTools panel and popup interface.

The extension implements telemetry collection using Azure Application Insights, but critically, telemetry is **disabled by default** and only enabled after explicit user consent through a permission dialog. The implementation follows privacy-respecting patterns with the telemetry configuration controlled through user settings stored locally. All network endpoints contacted are legitimate Microsoft services for telemetry data collection and CDN resources.

## Vulnerability Details

### 1. LOW: Optional Telemetry to Microsoft Azure Application Insights

**Severity**: LOW
**Files**: bundle/serviceWorker.bundle.js, insights.config.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**:

The extension collects usage telemetry and sends it to Microsoft's Azure Application Insights service using instrumentation key `5217efad-9690-44fc-9646-04b25a95e63b`. However, this is implemented with proper user consent mechanisms.

**Evidence**:

Configuration file (insights.config.js):
```javascript
globalThis.insights = {
    "options": {
        "fullName": "Accessibility Insights for Web",
        "telemetryBuildName": "Production",
        "appInsightsInstrumentationKey": "5217efad-9690-44fc-9646-04b25a95e63b"
    }
}
```

Telemetry initialization with disabled-by-default configuration (serviceWorker.bundle.js:77961-77970):
```javascript
if (oP.getOption("appInsightsInstrumentationKey") != null) {
  let a = new gX({
    config: {
      instrumentationKey: oP.getOption("appInsightsInstrumentationKey"),
      disableTelemetry: !0,  // DISABLED BY DEFAULT
      disableAjaxTracking: !0,
      disableFetchTracking: !0
    }
  });
  r.push(new FR(e, a))
}
```

User consent check (serviceWorker.bundle.js:78024):
```javascript
this.userConfigStore.getState().enableTelemetry ?
  this.telemetryEventHandler.enableTelemetry() :
  this.telemetryEventHandler.disableTelemetry()
```

Default state (serviceWorker.bundle.js:65167):
```javascript
enableTelemetry: !1,  // FALSE by default
```

**Verdict**:

This is a **privacy-respecting implementation**. The extension:
1. Disables telemetry by default (`disableTelemetry: !0`)
2. Requires explicit user consent through a permission dialog
3. Stores the user's telemetry preference in local storage
4. Only enables telemetry after the user opts in
5. Clearly discloses the telemetry collection in the UI

The telemetry data is sent to legitimate Microsoft Azure endpoints:
- `dc.services.visualstudio.com` (production telemetry)
- `breeze.aimon.applicationinsights.io` (Application Insights)
- `dc-int.services.visualstudio.com` (internal/testing)

This is standard practice for enterprise developer tools and aligns with Microsoft's privacy policies.

## False Positives Analysis

1. **Webpack Bundling**: The static analyzer flagged the code as "obfuscated", but this is standard webpack bundling/minification, not malicious obfuscation. The code structure clearly shows React components, Application Insights SDK, and accessibility testing logic.

2. **Application Insights SDK**: The presence of extensive telemetry infrastructure might appear concerning, but this is the standard Microsoft Application Insights JavaScript SDK, not custom tracking code. The SDK is integrated but remains dormant unless explicitly enabled by user consent.

3. **Optional `<all_urls>` Permission**: The extension requests optional host permissions for all URLs, which is necessary for its stated purpose of analyzing any webpage for accessibility issues. This is not automatically granted and requires user approval.

4. **postMessage Usage**: The extension uses postMessage for internal communication between extension components (DevTools panel, content scripts, injected scripts), which is the standard pattern for Chrome extensions with DevTools integration.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| dc.services.visualstudio.com | Azure Application Insights telemetry ingestion | Usage events, exceptions, metrics (only if opted-in) | Low - Legitimate Microsoft service with user consent |
| breeze.aimon.applicationinsights.io | Alternative Application Insights endpoint | Same as above | Low - Legitimate Microsoft service |
| dc-int.services.visualstudio.com | Internal/testing telemetry endpoint | Same as above | Low - Microsoft internal service |
| go.microsoft.com | Microsoft URL shortener for documentation links | None (outbound links only) | None - Documentation links |
| res-1.cdn.office.net | Microsoft Office Fabric UI assets | None (resource loading only) | None - Static UI resources |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

Accessibility Insights for Web is a legitimate, well-designed developer tool from Microsoft Corporation with no significant security or privacy concerns. The extension:

1. **Serves its stated purpose**: Provides comprehensive accessibility testing using the industry-standard axe-core engine
2. **Implements privacy by design**: Telemetry is disabled by default and requires explicit opt-in
3. **Uses appropriate permissions**: The optional `<all_urls>` permission is necessary for its accessibility testing functionality
4. **Contacts only legitimate endpoints**: All network communication is with verified Microsoft services
5. **Follows extension best practices**: Uses Manifest V3, proper message passing, and secure coding patterns

The only privacy consideration is the optional telemetry to Azure Application Insights, which is:
- Clearly disclosed to users
- Disabled by default
- Only enabled after explicit consent
- Sent to legitimate Microsoft services
- Standard practice for enterprise developer tools

This extension is safe to use and represents a best-in-class example of privacy-respecting telemetry implementation in browser extensions.
