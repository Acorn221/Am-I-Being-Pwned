# QuillBot: AI Writing and Grammar Checker Tool - Security Analysis Report

## Extension Metadata
- **Extension Name**: QuillBot: AI Writing and Grammar Checker Tool
- **Extension ID**: iidnbdjijdkbmajdffnidomddglmieko
- **Version**: 4.60.0
- **User Count**: ~5,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-08

## Executive Summary

QuillBot is a legitimate AI-powered writing assistant extension with **5 million users**. The extension provides paraphrasing, grammar checking, and AI writing tools across various web platforms including Google Docs, Gmail, ChatGPT, and other text editors.

**Overall Assessment**: The extension has extensive permissions and collects analytics data, but operates within its stated purpose. There are **no critical security vulnerabilities or malicious behavior** detected. The extension uses appropriate APIs for its functionality and implements standard telemetry practices.

**Risk Level**: **CLEAN**

The extension requires extensive permissions (host_permissions for all URLs, cookies, scripting, storage) which are invasive, but these are necessary for its core functionality of providing AI writing assistance across all websites. All data collection appears to be for legitimate analytics and product functionality purposes, sent to first-party QuillBot domains.

## Detailed Analysis

### 1. Manifest Permissions & CSP

**Permissions Declared**:
- `alarms` - For periodic tasks
- `cookies` - For authentication with quillbot.com
- `storage` - For user preferences and data
- `activeTab` - For accessing current tab content
- `contextMenus` - For right-click menu integration
- `notifications` - For user notifications
- `scripting` - For dynamic content script injection
- `sidePanel` - For side panel UI

**Host Permissions**:
- `*://*/*` - All URLs (required for universal text editor integration)
- `https://quillbot.com/` and `https://quillbot.com/*` - First-party API access

**Content Security Policy**:
```json
"script-src 'self' 'wasm-unsafe-eval'; object-src 'self';"
```
The CSP is appropriately restrictive, allowing only extension scripts and WASM execution. No remote script loading or eval allowed.

**Verdict**: Permissions are extensive but justified for a universal writing assistant. CSP follows best practices.

### 2. Content Scripts Analysis

The extension injects multiple content scripts across different contexts:

**Google Docs Integration** (`content-gdocs.js`, `content-gdocs-pre.js`, `main-world-injection.js`):
- Runs on `https://docs.google.com/document/*` and `https://docs.google.com/presentation/*`
- Hooks into Canvas rendering to suppress Google's grammar suggestions and display QuillBot's own
- Manipulates DOM to integrate QuillBot toolbar into Google Docs interface
- Uses `postMessage` for communication between MAIN world script and extension context

**ChatGPT/Gemini Integration** (`content-gpt-humanizer.js`):
- Runs on `https://chatgpt.com/*` and `https://gemini.google.com/*`
- Provides AI text humanization features for AI-generated content

**Universal Editor Detection** (`detect-editors.js`):
- Runs on `*://*/*` (all URLs)
- Detects editable elements (contenteditable, textareas) on web pages
- Proactively renders QuillBot toolbar for detected editors

**AI Chat** (`ai-chat.js`):
- Runs on `*://*/*`
- Provides QuillBot's AI chat functionality

**Verdict**: Content scripts are extensive and run on all pages, but functionality is limited to detecting/enhancing text editors. No keylogging, form hijacking, or credential harvesting detected.

### 3. Background Service Worker Analysis

**File**: `quillbot-sw.js` (2.6MB minified)

**Chrome API Usage**:
- `chrome.runtime` - Message passing, extension management
- `chrome.tabs` - Tab querying and management
- `chrome.scripting.executeScript` - Dynamic script injection for toolbar rendering
- `chrome.storage` - User preferences and settings
- `chrome.cookies` - Authentication cookie management for quillbot.com domain
- `chrome.sidePanel` - Side panel management
- `chrome.alarms` - Periodic tasks

**Network Endpoints**:
All network requests are sent to legitimate QuillBot infrastructure:
- `https://quillbot.com` - Main website and API
- `https://quillbot.dev` - Development/QA environment
- `https://collector.quillbot.com` - Analytics/telemetry endpoint
- `https://stream.quillbot.com` - Streaming API for AI features
- `https://api.languagetool.org` and `https://api.languagetoolplus.com` - Grammar checking API (third-party integration)
- `https://api2.amplitude.com` - Analytics platform (third-party)

**Verdict**: Service worker uses appropriate APIs for extension functionality. No suspicious network behavior, proxy infrastructure, or remote code execution detected.

### 4. Data Collection & Privacy

**Analytics Integration**:
- **Amplitude Analytics**: Standard product analytics SDK for tracking user interactions, page views, and feature usage
- **Sentry Error Tracking**: Error monitoring and crash reporting to `browser.sentry-cdn.com`

**Data Sent to `collector.quillbot.com`**:
All scripts reference the collector endpoint, indicating comprehensive product telemetry. Based on Amplitude integration patterns found in code:
- User interactions with QuillBot features
- Page domains and URLs where extension is used
- Feature usage patterns
- Performance metrics

**Cookie Access**:
The extension requests cookies permission and accesses cookies for `quillbot.com` domain, which is appropriate for maintaining user authentication state.

**Verdict**: Data collection is standard for a SaaS product. All telemetry goes to first-party QuillBot domains or legitimate third-party analytics providers. No evidence of credential theft, browsing history exfiltration, or unauthorized data harvesting.

### 5. Injection & DOM Manipulation

**Canvas Hooking** (`injection.js`):
The extension hooks into `CanvasRenderingContext2D` methods to intercept Google Docs grammar underlines:
```javascript
CanvasRenderingContext2D.prototype.stroke = function() {
  if (arguments[0]) {
    var t = this.strokeStyle.toString();
    if ([n,i].includes(t.toLowerCase()) && l()) return
  }
  return b.apply(this, arguments)
}
```
This suppresses Google's native grammar suggestions to avoid conflicts with QuillBot's own suggestions.

**Dynamic Script Injection**:
The service worker uses `chrome.scripting.executeScript` to inject toolbar components on-demand when text editors are detected.

**Verdict**: DOM manipulation is aggressive but serves legitimate product functionality. No malicious code injection or XSS exploitation detected.

### 6. Remote Configuration & Kill Switches

**No Remote Kill Switches Detected**: The extension does not fetch remote configuration that could disable or alter core functionality. Configuration is bundled with the extension.

**Verdict**: Extension behavior is deterministic and not remotely controllable beyond normal API responses.

### 7. Third-Party Integrations

The extension integrates with several third-party services:
- **LanguageTool API** - Grammar checking services
- **Amplitude** - Product analytics
- **Sentry** - Error tracking

All integrations are with legitimate, well-known services appropriate for a writing assistant product.

**Verdict**: Third-party integrations are transparent and serve legitimate purposes.

## False Positives

| Pattern | File(s) | Reason |
|---------|---------|--------|
| Sentry SDK hooks | All scripts | Standard error tracking SDK, known FP |
| Amplitude analytics | All scripts | Legitimate product analytics platform |
| React dev tools hooks | content-gpt-humanizer.js, ai-chat.js | React framework detection |
| Canvas API manipulation | injection.js | Legitimate feature to suppress Google Docs grammar |
| Chrome API wrapping | detect-editors.js | webextension-polyfill library for Firefox compatibility |

## API Endpoints Table

| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `https://quillbot.com/api/*` | Main API | User text for processing, authentication |
| `https://collector.quillbot.com` | Analytics | Usage telemetry, feature interactions |
| `https://stream.quillbot.com` | Streaming API | Real-time AI text processing |
| `https://api.languagetool.org` | Grammar API | Text for grammar checking |
| `https://api2.amplitude.com/*` | Analytics | Product usage events |
| `https://browser.sentry-cdn.com` | Error tracking | Error reports, stack traces |

## Data Flow Summary

1. **User Input**: User types in text editor on any website
2. **Content Script**: Detects editable elements, injects QuillBot toolbar
3. **Text Processing**: User selects text and triggers QuillBot feature
4. **API Request**: Text sent to `quillbot.com` API for paraphrasing/grammar checking
5. **Response**: Processed text returned and displayed to user
6. **Telemetry**: Usage event sent to `collector.quillbot.com` and Amplitude
7. **Storage**: User preferences saved in `chrome.storage`

All data flows are appropriate for the extension's stated functionality as an AI writing assistant.

## Vulnerabilities & Security Issues

### No Critical or High Severity Issues Found

**Medium Severity**: None

**Low Severity**:
- **Broad Permissions**: The extension requests `*://*/*` host permissions and runs content scripts on all pages. While necessary for functionality, this creates a large attack surface if the extension were compromised.
  - **Mitigation**: This is inherent to universal writing assistants. QuillBot appears to be a legitimate, well-maintained extension from a reputable company.

**Informational**:
- **Extensive Analytics**: The extension collects comprehensive product usage data. Users concerned about privacy should review QuillBot's privacy policy.
- **Third-Party Services**: Extension relies on external APIs (LanguageTool, Amplitude, Sentry) which could be points of failure or data leakage if those services are compromised.

## Overall Risk Assessment

**CLEAN** - QuillBot is a legitimate AI writing assistant that operates transparently within its stated purpose. While it has extensive permissions and collects analytics data, there is no evidence of:
- Malicious behavior
- Credential theft
- Unauthorized data exfiltration
- Ad injection
- Proxy/residential IP infrastructure
- Extension enumeration/killing
- Market intelligence SDKs
- Keylogging
- Cookie harvesting beyond authentication
- Remote code execution
- Obfuscated malware

The extension serves its intended purpose as an AI-powered writing assistant and grammar checker. The broad permissions are necessary for its universal text editor integration, and data collection appears limited to legitimate product analytics and functionality.

Users should be aware that the extension:
- Has access to all website content (necessary for text editing features)
- Sends text to QuillBot servers for processing
- Collects usage analytics via Amplitude
- Integrates with third-party grammar checking services

All of these behaviors are expected and disclosed for a cloud-based AI writing assistant.

## Recommendations

**For Users**:
- Extension is safe to use for its intended purpose
- Be aware that text sent to QuillBot is processed on their servers
- Review QuillBot's privacy policy regarding data retention and usage

**For Developers**:
- Consider implementing Content Security Policy for content scripts
- Document data collection practices more transparently in extension description
- Consider offering privacy-focused modes with reduced analytics

## Conclusion

QuillBot is a **CLEAN** extension with no security vulnerabilities or malicious behavior detected. It serves a legitimate business purpose with ~5 million active users. The extensive permissions are justified by its functionality as a universal writing assistant, and all observed behavior aligns with its stated purpose.
