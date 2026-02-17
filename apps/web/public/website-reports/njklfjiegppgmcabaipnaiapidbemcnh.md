# Vulnerability Report: SkyGuard Endpoint Browser Helper

## Metadata
- **Extension ID**: njklfjiegppgmcabaipnaiapidbemcnh
- **Extension Name**: SkyGuard Endpoint Browser Helper
- **Version**: 3.9.7
- **Users**: Unknown (enterprise deployment)
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

SkyGuard Endpoint Browser Helper is an enterprise Data Loss Prevention (DLP) and endpoint monitoring solution. The extension captures comprehensive webpage content including HTML source, form inputs, textarea content, and iframe content from all visited pages. This data is transmitted to a local management server running on localhost (127.0.0.1) for monitoring and compliance purposes. The extension also implements dynamic watermarking capabilities for document protection and tracks file downloads.

While this extension performs extensive data collection that would be considered highly invasive in a consumer context, it appears to be a legitimate enterprise security tool designed for corporate environments where employee monitoring is disclosed and authorized. The data stays within the local network (localhost endpoints only) and requires a native messaging component to function properly, indicating enterprise deployment infrastructure.

## Vulnerability Details

### 1. MEDIUM: Comprehensive Content Capture and Exfiltration to Local Server

**Severity**: MEDIUM
**Files**: background.js, content_script.js
**CWE**: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
**Description**: The extension captures extensive webpage content and transmits it to a local management server. The content script extracts:
- Complete HTML source code (`document.documentElement.outerHTML`)
- All textarea values (by ID and name)
- All input field values
- Iframe content (with cross-origin error handling)

This data is sent to the background script upon request, which then forwards it to either:
1. Native messaging host (`com.skyguard.browser.helper`)
2. WebSocket server (`ws://127.0.0.1:8859/skyguard/endpoint/browser`)
3. HTTP REST API (`http://127.0.0.1:8852/sgep/v1/clientAgent/cloudApp/`)

**Evidence**:

Content script data capture (content_script.js lines 217-230):
```javascript
chrome.runtime.onMessage.addListener(function (request, sender, sendMessage) {
    if (request.act == "sourceCode") {
        var textareaContent = " ";
        textareaContent += getTextareaContent("id");
        textareaContent += " ";
        textareaContent += getTextareaContent("name");

        var iframeContent = " ";
        iframeContent += getIframeContent();

        var inputContent = " ";
        inputContent += getInputContent();

        var html = document.documentElement.outerHTML;
        sendMessage(html + iframeContent + textareaContent + inputContent);
    }
```

Background script forwarding to native host (background.js lines 314-319):
```javascript
chrome.tabs.sendMessage(activeId, {act: "sourceCode"}, function(response) {
    curPrintData = response;
    console.log("get activeTab id source: " + activeId);
    var printData = {"data": curPrintData!=null?curPrintData:"none", "url": curTabUrl!=null?curTabUrl:"none"};
    sendNativeMessage(printData);
});
```

**Verdict**: This is classified as MEDIUM rather than HIGH because:
1. All endpoints are localhost-only (no remote exfiltration)
2. This is clearly an enterprise monitoring tool with disclosed purpose
3. Requires native messaging component (enterprise deployment infrastructure)
4. Data stays within the local corporate network
5. The extension name and description clearly indicate its monitoring purpose

In a consumer context, this would be CRITICAL. However, for an enterprise DLP tool where monitoring is disclosed and authorized, this is expected behavior.

## False Positives Analysis

Several patterns that could appear suspicious are actually legitimate for this extension type:

1. **Input Field Harvesting**: The extension captures all input values, which could appear as credential theft. However, this is the core functionality of a DLP tool monitoring data entry.

2. **Content Exfiltration**: Sending webpage content to external endpoints is the primary purpose of this monitoring solution.

3. **Broad Host Permissions**: The `<all_urls>` permission pattern is necessary for comprehensive DLP monitoring across all corporate web activity.

4. **Native Messaging**: Connection to native host is standard for enterprise extensions that integrate with endpoint security agents.

5. **WebSocket Communication**: The WebSocket connection to localhost:8859 is part of the real-time monitoring architecture, not command-and-control infrastructure.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| http://127.0.0.1:8852/sgep/v1/clientAgent/cloudApp/login | Authenticate extension with local agent | Browser type, version | Low - localhost only |
| http://127.0.0.1:8852/sgep/v1/clientAgent/cloudApp/heartbeat | Periodic check-in | Current tab URL | Low - localhost only |
| http://127.0.0.1:8852/sgep/v1/clientAgent/cloudApp/currentTab | Report active tab changes | URL of active tab | Low - localhost only |
| http://127.0.0.1:8852/sgep/v1/clientAgent/cloudApp/downloadList | Report file downloads | Download URL, local path | Low - localhost only |
| ws://127.0.0.1:8859/skyguard/endpoint/browser | Real-time bidirectional communication | Webpage content, watermark requests | Medium - extensive data |
| http://127.0.0.1:9005/ | Network filtering service | Unknown (configurable endpoint) | Low - localhost only |

Authentication mechanism uses SHA256-based HMAC with session tokens:
- Base auth: `SHA256(timestamp + 'skyguard')`
- Session auth: `SHA256(timestamp + session_token + session_id)`

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

SkyGuard Endpoint Browser Helper is a legitimate enterprise DLP and monitoring solution that captures comprehensive webpage content including user inputs and transmits this data to localhost-based management infrastructure.

**Risk Elevation Factors:**
- Captures all form inputs, potentially including credentials and sensitive data
- Monitors all browsing activity across HTTP, HTTPS, FTP, and file:// protocols
- Sends complete webpage source code to monitoring server
- Watermarking system modifies page DOM and can track document viewing

**Risk Mitigation Factors:**
- All communication endpoints are localhost-only (no remote exfiltration)
- Requires native messaging component (controlled enterprise deployment)
- Clear enterprise security tool identity in name and description
- Data stays within local corporate network infrastructure
- Standard architecture for DLP solutions
- Uses session-based authentication with HMAC

**Conclusion**: This extension represents expected behavior for an enterprise DLP tool. The MEDIUM rating reflects that while the data collection is extensive and would be unacceptable in a consumer context, this is a disclosed enterprise monitoring solution where such capabilities are authorized and necessary for its stated purpose. Organizations deploying this extension should ensure employees are aware of the monitoring and that appropriate data handling policies are in place.

The extension does not exhibit signs of malicious behavior, obfuscation, or unauthorized data exfiltration beyond its legitimate enterprise monitoring purpose.
