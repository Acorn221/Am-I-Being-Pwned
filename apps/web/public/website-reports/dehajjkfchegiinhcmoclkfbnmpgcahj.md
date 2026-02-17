# Vulnerability Report: InsertLearning

## Metadata
- **Extension ID**: dehajjkfchegiinhcmoclkfbnmpgcahj
- **Extension Name**: InsertLearning
- **Version**: 2.2.0
- **Users**: ~800,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

InsertLearning is an educational Chrome extension designed to help teachers insert instructional content (sticky notes, questions, discussions, highlights) on any web page. The extension requests broad permissions (`<all_urls>`) which are legitimately required for its core functionality of annotating arbitrary websites. The extension communicates with its backend services at insertlearning.com and integrates with Google OAuth for authentication.

While the extension is fundamentally legitimate in its purpose and implementation, it contains one minor security issue: a postMessage listener that does not validate the origin of incoming messages, which could potentially be exploited by malicious websites. The extension also makes use of dynamic script injection via `chrome.scripting.executeScript`, but this is appropriate for its stated functionality.

## Vulnerability Details

### 1. LOW: Insufficient postMessage Origin Validation

**Severity**: LOW
**Files**: lib/iframe/iframe.js
**CWE**: CWE-346 (Origin Validation Error)
**Description**: The extension includes an iframe bridge component that relays postMessage events without proper origin validation.

**Evidence**:
```javascript
// lib/iframe/iframe.js
window.addEventListener('message', function(event) {
    if (event.origin == 'https://insertlearning.com') {
        event.source.postMessage(event.data, event.origin);
    }
});
```

While this code does check the origin is `https://insertlearning.com`, the broader issue is the message handler in `lib/js/docent.js` that processes messages from the iframe. If a malicious page could manipulate the message flow or if the iframe bridge logic were compromised, it could potentially relay unauthorized messages.

**Verdict**: This is a minor security concern. The extension does validate the origin against `insertlearning.com` in the iframe bridge, and the main message handler in `docent.js` also checks `event.origin === iframeOrigin`. However, the relay pattern could be strengthened with additional validation of message content and structure.

## False Positives Analysis

Several patterns that might initially appear suspicious are actually legitimate for this extension type:

1. **<all_urls> permission**: Required for the extension's core functionality of annotating any web page a teacher might want to use for instruction.

2. **Dynamic script injection**: The extension uses `chrome.scripting.executeScript` extensively to inject the annotation UI onto pages. This is the standard MV3 approach for content script injection and is necessary for the extension's functionality.

3. **CloudFront endpoint**: The extension fetches data from `dnmkr7tf85gze.cloudfront.net` (specifically `/data/p/{uuid}`), which appears to be for ReadWorks article integration - a legitimate educational content provider.

4. **Google OAuth integration**: The extension uses the Chrome Identity API with Google OAuth scopes for user authentication and Google Classroom integration, which is appropriate for an educational tool.

5. **Storage usage**: The extension uses `chrome.storage.local` and browser localStorage/sessionStorage to persist lesson data and user authentication state, which is normal for this type of application.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| insertlearning.com | Primary backend service | Lesson content, annotations, user actions | Low - HTTPS, legitimate service |
| docentedu.com | Legacy domain (old brand name) | Extension version, lesson data | Low - Same service as insertlearning.com |
| okeebo.com | Alternative domain | Extension version | Low - Related service |
| accounts.google.com | OAuth authentication | OAuth tokens (via Chrome Identity API) | Low - Standard Google OAuth flow |
| dnmkr7tf85gze.cloudfront.net | ReadWorks content CDN | UUID for article requests | Low - Educational content delivery |

## Permission Analysis

**Requested Permissions**:
- `activeTab`: Used to interact with the currently active tab when extension is activated
- `scripting`: Required for MV3 dynamic content script injection
- `storage`: Stores user preferences and lesson data
- `webNavigation`: Monitors page navigation to maintain annotation state
- `<all_urls>`: Broad host permission enabling annotation on any website
- `identity` (optional): Google OAuth for user authentication

**Justification**: All permissions are appropriate for an educational annotation tool. The `<all_urls>` permission is necessary because teachers need to annotate arbitrary web content for their lessons.

## Data Flow Analysis

The extension's data flow follows this pattern:
1. Teacher activates the extension on a webpage
2. Extension injects annotation UI via `chrome.scripting.executeScript`
3. User creates annotations (highlights, notes, questions)
4. Annotations are sent to iframe bridge via postMessage
5. Iframe bridge communicates with insertlearning.com backend
6. Student users can view and interact with the annotated content

No evidence of data exfiltration beyond what is necessary for the service to function was found.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
InsertLearning is a legitimate educational tool with a clear purpose and appropriate permission usage. The single identified vulnerability (postMessage origin validation) is minor and has limited exploitability given the existing origin checks in place. The extension does not engage in any hidden data collection, credential theft, or malicious behavior. Its broad permissions are justified by its functionality, and it follows standard patterns for MV3 educational extensions.

The extension is used by approximately 800,000 users (primarily educators and students) and appears to be well-maintained. The security concern identified should be addressed but does not pose an immediate threat to users.

**Recommendations**:
1. Add more robust validation of message content structure in the postMessage handlers
2. Consider implementing Content Security Policy restrictions for the iframe bridge
3. Add integrity checks for dynamically loaded content from CloudFront
