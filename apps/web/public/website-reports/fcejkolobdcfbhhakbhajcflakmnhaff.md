# Vulnerability Assessment Report: Knowee AI (formerly StudyGPT)

## Extension Metadata
- **Extension ID**: fcejkolobdcfbhhakbhajcflakmnhaff
- **Name**: Knowee AI (formerly StudyGPT) - Your Homework & Essay Helper
- **Version**: 4.2.0
- **Users**: ~40,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-08

## Executive Summary

Knowee AI is a legitimate homework assistance extension that provides AI-powered help for students working on documents, PDFs, YouTube videos, and web content. The extension implements extensive permissions to provide its core functionality across multiple platforms (Google Docs, YouTube, PDF viewers, general web pages). While the extension has broad access capabilities, the analysis reveals **no evidence of malicious behavior, hidden data exfiltration, or security vulnerabilities**. The extension's invasive permissions are justified by its intended purpose as a comprehensive AI learning assistant.

**Overall Risk Level**: **CLEAN**

The extension:
- Legitimately uses cookies for authentication with knowee.ai backend
- Communicates only with known, legitimate API endpoints (core.knowee.ai)
- Does not contain obfuscated malicious code
- Does not implement keyloggers, clipboard hijacking, or credential theft
- Uses permissions appropriately for stated functionality
- Has no Content Security Policy violations

## Detailed Analysis

### 1. Manifest Permissions Assessment

#### Declared Permissions
```json
"permissions": [
    "tabs",
    "storage",
    "cookies",
    "activeTab",
    "scripting",
    "<all_urls>",
    "file://*"
]
```

**Analysis**:
- **tabs**: Used for managing PDF viewer tabs and extension UI integration - LEGITIMATE
- **storage**: Stores user settings and preferences locally - LEGITIMATE
- **cookies**: Accesses knowee.ai cookies for authentication (_sg_auth_token, channel, promotionCode, device_id) - LEGITIMATE
- **activeTab**: Captures screenshots for AI analysis feature - LEGITIMATE
- **scripting**: Injects UI components for sidebar and floating tools - LEGITIMATE
- **<all_urls>**: Required for universal content script deployment - INVASIVE BUT JUSTIFIED
- **file://***: Enables local PDF file processing - LEGITIMATE

**Verdict**: All permissions serve the extension's stated purpose as a comprehensive AI assistant for students.

### 2. Content Security Policy

**Finding**: No CSP defined in manifest
**Risk**: Low - MV3 has default CSP protections
**Verdict**: Acceptable for MV3 extension

### 3. Background Script Analysis

**File**: `background.js` (34KB minified)

**Key Functions Identified**:
- Cookie management for authentication (getCookie, setCookie, removeCookie)
- Tab management for PDF viewer redirection
- User authentication flow via knowee.ai popup windows
- Screenshot capture via `chrome.tabs.captureVisibleTab()`
- Extension icon click handler for toggling sidebar
- Installation/update event tracking

**Network Endpoints**:
```
https://core.knowee.ai/api/users/me (GET - fetch user profile)
https://core.knowee.ai/api/eventlogs (POST - analytics)
https://knowee.ai/login (authentication page)
https://knowee.ai/pricing (subscription page)
https://knowee.ai/uninstall (uninstall feedback)
https://knowee.ai/onboarding (welcome page)
```

**Data Collected**:
- Authorization token (from cookies)
- Promotion/channel codes
- Device ID
- Extension version
- Platform info (OS: mac/windows/linux)
- Current page URL (location header)
- User profile from API

**Verdict**: All network communication is with legitimate knowee.ai infrastructure. No third-party trackers or suspicious endpoints detected.

### 4. Content Scripts Analysis

The extension deploys multiple content scripts across different contexts:

#### 4.1 Universal Content Scripts (`content.js` - 4MB, `selection.js` - 3.4MB)
- **Purpose**: Main UI components (floating assistant, text selection helper)
- **Size**: Large due to bundled Vue.js framework and UI libraries
- **DOM Access**: Creates overlay UI, responds to text selection events
- **Communication**: Message passing with background script for API calls
- **Risk**: None - standard UI framework usage

#### 4.2 Google Docs Integration (`googleDocs.js` - 4.1MB, `googleDocsInject.js` - 16KB, `googleDocsGuide.js` - 590KB)
- **Purpose**: Writing assistant within Google Docs
- **Access**: Reads document content for AI suggestions
- **Functionality**: Insert/accept/cite/replace operations in document
- **Data Handling**: Document content sent to knowee.ai API for processing
- **Risk**: Low - standard document assistant functionality, similar to Grammarly

**Privacy Consideration**: Users should be aware that document content is transmitted to knowee.ai servers for AI processing. This is explicit in the extension's purpose.

#### 4.3 YouTube Integration (`youtube.js` - 869KB)
- **Purpose**: Video transcript analysis and Q&A
- **Access**: Reads video metadata and transcript
- **Risk**: None - read-only access to public video data

#### 4.4 PDF Viewer (`localPdfTips.js` - 678KB, PDF.js library)
- **Purpose**: Built-in PDF viewer with AI assistant
- **Implementation**: Uses Mozilla's PDF.js library
- **File Access**: Requires `file://*` permission for local PDFs
- **Risk**: None - standard PDF rendering library

#### 4.5 Google Scholar (`googleScholar.js` - 15KB)
- **Purpose**: Minimal integration, mostly placeholder
- **Risk**: None

### 5. Vulnerability Assessment

#### 5.1 Dynamic Code Execution
**Search**: `eval()`, `Function()`, `setTimeout/setInterval` with string arguments
**Result**: No instances found
**Verdict**: CLEAN

#### 5.2 XSS/Injection Risks
**Finding**: No innerHTML manipulation with untrusted data
**Verdict**: Uses Vue.js framework with built-in XSS protection
**Risk**: Low

#### 5.3 Credential Harvesting
**Search**: Password field monitoring, credential theft patterns
**Result**: None detected
**Verdict**: CLEAN

#### 5.4 Clipboard Hijacking
**Search**: Clipboard API abuse
**Result**: None detected
**Verdict**: CLEAN

#### 5.5 Extension Enumeration/Killing
**Search**: chrome.management API abuse
**Result**: None detected
**Verdict**: CLEAN

#### 5.6 XHR/Fetch Hooking
**Search**: Prototype pollution of fetch/XMLHttpRequest
**Result**: None detected
**Verdict**: CLEAN

#### 5.7 Remote Code Injection
**Search**: Remote script loading, WebSocket command execution
**Result**: None detected - all code bundled in extension
**Verdict**: CLEAN

### 6. Privacy & Data Flow Analysis

**Data Collected**:
1. **Authentication Data**: Cookies for knowee.ai session management
2. **User Content**: Text selections, document content, PDF text, video transcripts
3. **Usage Analytics**: Feature interaction events (Google Docs insertions, sidebar opens)
4. **Browser Metadata**: Tab URLs, platform info, extension version

**Data Transmission**:
- All data sent to `core.knowee.ai` API via HTTPS
- No third-party analytics SDKs detected
- No data sent to unknown endpoints

**Data Usage**:
- User content processed by AI models for homework assistance
- Analytics used for feature usage tracking

**Privacy Verdict**: The extension is transparent about its data usage. All data collection is necessary for the AI assistance functionality. No excessive or hidden data harvesting detected.

### 7. False Positives Identified

| Pattern | Context | Explanation |
|---------|---------|-------------|
| Large minified files | Vue.js framework bundles | Standard for modern web frameworks |
| Cookie access | Authentication flow | Legitimate session management |
| <all_urls> permission | Universal assistant | Required for cross-site functionality |
| Document content access | Google Docs integration | Core feature for writing assistance |
| Screenshot capture | Visual Q&A feature | User-initiated for homework help |

### 8. API Endpoints Summary

| Endpoint | Method | Purpose | Data Sent |
|----------|--------|---------|-----------|
| https://core.knowee.ai/api/users/me | GET | Fetch user profile | Auth token |
| https://core.knowee.ai/api/eventlogs | POST | Analytics events | Event ID, description |
| https://knowee.ai/login | N/A | Authentication page | N/A (browser navigation) |
| https://knowee.ai/pricing | N/A | Subscription page | N/A (browser navigation) |
| https://knowee.ai/onboarding | N/A | Welcome flow | N/A (browser navigation) |

**Verdict**: All endpoints are legitimate first-party services. No third-party data sharing detected.

## Security Strengths

1. **Manifest V3**: Uses latest extension platform with enhanced security
2. **HTTPS-Only**: All API communication encrypted
3. **No Dynamic Code**: No eval() or remote code execution
4. **Framework Security**: Uses Vue.js with built-in XSS protections
5. **Scoped Permissions**: Only accesses knowee.ai cookies, not arbitrary domains
6. **Standard Libraries**: Uses Mozilla PDF.js for file rendering

## Privacy Considerations (Not Vulnerabilities)

While not security issues, users should be aware:

1. **Content Transmission**: Text selections, documents, and PDFs are sent to knowee.ai servers for AI processing
2. **Broad Permissions**: Extension has access to all websites for universal assistant functionality
3. **Usage Tracking**: Analytics events track feature usage (insertions, clicks, etc.)
4. **File Access**: Can read local PDF files when granted permission

These are inherent to the extension's functionality as an AI learning assistant and are comparable to other popular tools like Grammarly, QuillBot, or ChatGPT extensions.

## Compliance Assessment

- ✅ No hidden functionality
- ✅ Permissions match stated purpose
- ✅ No credential theft
- ✅ No cryptocurrency mining
- ✅ No malware distribution
- ✅ No ad injection beyond intended functionality
- ✅ No user tracking for surveillance
- ✅ Secure communication (HTTPS)

## Recommendations

For the Extension Developer (knowee.ai):
1. Consider adding explicit privacy disclosure about data transmission to AI servers
2. Implement Content Security Policy in manifest for defense-in-depth
3. Add permission justification in Chrome Web Store listing

For Users:
1. Be aware that content you interact with is sent to knowee.ai for AI processing
2. Do not use on sensitive/confidential documents if concerned about data privacy
3. Extension is safe for general academic use

## Conclusion

Knowee AI is a **legitimate educational tool** with no malicious functionality. The extension requires extensive permissions to provide comprehensive AI assistance across multiple platforms (Google Docs, PDFs, YouTube, general web pages), but all permissions are appropriately used for stated features. There is no evidence of:

- Malware or malicious code
- Hidden data exfiltration
- Credential theft
- Ad injection beyond intended functionality
- Surveillance or tracking for non-functional purposes
- Remote code execution vulnerabilities
- Third-party data sharing

The extension operates transparently as an AI homework assistant, comparable to other legitimate productivity tools. The invasive permissions are justified by the breadth of functionality offered.

**Final Risk Level**: **CLEAN**

---

**Analyst Note**: This extension serves its intended purpose without security concerns. The broad permissions are necessary for universal AI assistant functionality and are appropriately utilized.
