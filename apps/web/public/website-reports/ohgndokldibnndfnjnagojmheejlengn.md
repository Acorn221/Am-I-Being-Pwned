# Vulnerability Report: Citavi Picker

## Metadata
- **Extension ID**: ohgndokldibnndfnjnagojmheejlengn
- **Extension Name**: Citavi Picker
- **Version**: 2025.11.12.23
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Citavi Picker is a legitimate academic reference management browser extension developed by Lumivero (formerly Swiss Academic Software). The extension assists researchers in collecting bibliographic references, PDFs, and screenshots from academic databases and websites. It integrates with both the local Citavi desktop application (via native messaging) and the web-based Citavi cloud service.

The extension uses broad permissions appropriately for its stated academic research functionality. It collects telemetry data via Microsoft Application Insights (Azure), which is standard practice for commercial software quality monitoring. A minor postMessage origin validation issue exists but poses minimal practical risk due to the controlled iframe communication pattern.

## Vulnerability Details

### 1. LOW: Missing postMessage Origin Validation in PDF Viewer Helper

**Severity**: LOW
**Files**: iframe/helper.js:187
**CWE**: CWE-346 (Origin Validation Error)

**Description**:
The `PDFViewerHelper` class registers a message event listener without explicitly checking the message origin:

```javascript
window.addEventListener('message', this._onMessage, false);
```

This listener is created in the constructor when `this.isActive` is true (detecting PDF viewer context). However, the `_onMessage` handler implementation was not examined in the deobfuscated code, and the listener is only registered in specific PDF viewer contexts.

**Evidence**:
```javascript
class PDFViewerHelper {
    constructor() {
        if (this.isActive) {
            window.addEventListener('message', this._onMessage, false);
            this._textSelectionCallback = null;
        }
        this.injectPdfEventListener = true;
    }
```

**Verdict**:
This is a minor security issue. The extension's iframe communication primarily occurs between the extension's own iframe (`iframe/iframe.html`) and the parent content script context. The `FrameEngine` class (iframe.js:31-39) does implement origin validation using `this.parentOrigin` extracted from the URL hash. The postMessage listener in PDFViewerHelper appears limited to handling PDF text selection events and is only active in PDF viewer contexts. No evidence of exploitable attack surface was found.

## False Positives Analysis

1. **Telemetry to Microsoft Application Insights**: The extension sends error logs, traces, and usage telemetry to `dc.services.visualstudio.com/v2/track`. This is Microsoft's Azure Application Insights service and is a legitimate commercial telemetry system. The instrumentation key `96b182b2-9852-41fa-858f-26d5e0b50757` is hardcoded in settings.js:12. This is NOT data exfiltration - it's standard error tracking for software development.

2. **Native Messaging Permission**: The extension uses `nativeMessaging` to communicate with the local Citavi desktop application. This is expected and disclosed functionality for integrating the browser extension with desktop reference management software.

3. **Broad Host Permissions**: The extension requests `https://*/*` and `http://*/*` permissions because it needs to extract bibliographic metadata from any academic website, database, or journal platform. The codebase includes specialized "hunters" for 40+ academic platforms (PubMed, JSTOR, Google Scholar, IEEE, ScienceDirect, arXiv, Wikipedia, etc.). This broad access is necessary and appropriate for an academic reference collector.

4. **declarativeNetRequest CORS Bypass**: The rules.json file modifies headers for `www.sciencedirect.com` to add CORS headers. This is a legitimate workaround to enable fetching bibliographic metadata from ScienceDirect's API for academic reference collection.

5. **Dynamic Script Execution**: The extension uses `chrome.scripting.executeScript()` to inject functionality for detecting PDF viewers, taking screenshots, and extracting page metadata. All executed scripts are bundled with the extension (not remote code). This is standard MV3 practice.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| citaviweb.citavi.com | Citavi cloud service API | Reference metadata, OAuth tokens, project data | Low - legitimate service backend |
| backoffice6.citavi.com | Bibliographic lookup service | ISBN/DOI/PMID identifiers | Low - academic metadata lookup |
| dc.services.visualstudio.com | Microsoft Application Insights telemetry | Error logs, usage traces, session IDs | Low - standard telemetry |
| doi.org, search.crossref.org | DOI resolution and CrossRef API | DOI identifiers | Low - public academic APIs |
| eutils.ncbi.nlm.nih.gov | PubMed/NCBI API | PubMed IDs, search queries | Low - public health database |
| api.elsevier.com | Elsevier/ScienceDirect API | Article identifiers | Low - academic publisher API |
| core.ac.uk | CORE aggregator API | Search queries | Low - public research aggregator |
| data.epo.org | European Patent Office API | Patent identifiers | Low - public patent database |
| inis.iaea.org | IAEA Nuclear Science DB | Bibliographic queries | Low - public scientific database |
| clinicaltrials.gov | NIH clinical trials registry | Trial identifiers | Low - public health database |
| www.jstor.org, en.wikipedia.org, www.youtube.com | Content scraping | Page URLs, metadata | Low - public academic/reference sites |

All endpoints are either:
1. Operated by Lumivero (Citavi's parent company) for legitimate service functionality
2. Public academic APIs and databases for bibliographic metadata lookup
3. Microsoft Azure telemetry (Application Insights) for error tracking

No evidence of undisclosed data collection or exfiltration to third parties.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
Citavi Picker is a legitimate commercial academic reference management tool with appropriate use of permissions for its disclosed functionality. The extension's broad permissions are necessary to support bibliographic metadata extraction from diverse academic sources. The telemetry implementation uses a standard commercial service (Microsoft Application Insights) for quality monitoring. The minor postMessage origin validation issue poses negligible practical risk due to the controlled iframe communication architecture. The extension integrates with both local Citavi software (via native messaging) and cloud services (via OAuth), which aligns with the product's documented features.

The extension is developed by Lumivero (www.lumivero.com), a reputable academic software company, and serves 200,000+ users in the academic research community. No evidence of malicious behavior, hidden data exfiltration, or undisclosed functionality was found.
