# Security Analysis Report: Send from Gmail (by Google)

## Extension Metadata
- **Extension ID**: pgphcomnlaojlmmcjmiddhdapjpbgeoc
- **Name**: Send from Gmail (by Google)
- **Version**: 1.17
- **User Count**: ~800,000
- **Publisher**: Google Inc.
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-08

## Executive Summary

Send from Gmail is an official Google extension that enables users to set Gmail as their default email application and provides functionality to quickly share links via Gmail. The extension rewrites mailto: links on web pages to open Gmail compose windows and adds a browser action button to share the current page.

**Overall Risk Assessment: CLEAN**

This extension exhibits no malicious behavior, security vulnerabilities, or privacy concerns. The code is clean, well-documented, and follows secure development practices. All functionality aligns with the stated purpose. While the extension requests broad host permissions (`http://*/*`, `https://*/*`), these are necessary for its core functionality of rewriting mailto links on all pages and are used appropriately without data exfiltration or abuse.

## Permissions Analysis

### Declared Permissions
- `tabs` - Used to query active tab information (title, URL) for composing emails
- `storage` - Used to store user preferences (domain name, subject prefix)
- `scripting` - Used to inject content script to capture selected text

### Host Permissions
- `http://*/*` - Required for mailto link rewriting on all HTTP pages
- `https://*/*` - Required for mailto link rewriting on all HTTPS pages
- `http://*.google.com/` - For Google Apps domain integration

### Content Security Policy
No custom CSP defined - uses default Manifest V3 CSP (secure).

### Permission Usage Assessment
All permissions are used appropriately for stated functionality:
- Host permissions enable content script injection on all pages to rewrite mailto links
- `tabs` permission only accesses title and URL of current tab when user clicks extension icon
- `storage` only stores user-configured preferences (domain, subject prefix)
- No sensitive data access or exfiltration

## Vulnerability Analysis

### No Critical or High Severity Issues Found

After comprehensive analysis of all JavaScript files, no security vulnerabilities were identified.

### Medium Severity Issues: NONE

### Low Severity Issues: NONE

## Code Analysis Details

### Background Script (background.js)
**Functionality:**
- Handles message passing between content scripts and creates Gmail compose windows
- Manages user preferences (Google Apps domain, subject prefix) in chrome.storage.local
- Executes content script (infopasser.js) when user clicks extension icon
- Performs localStorage to chrome.storage migration for Manifest V3 compliance

**Security Observations:**
- No external network requests
- No dynamic code execution
- Proper use of async/await and modern Chrome APIs
- URL encoding applied to subject and body parameters
- No sensitive data collection beyond page title/URL when user explicitly clicks icon

### Content Script (mailto.js)
**Functionality:**
- Rewrites mailto: links on web pages to Gmail compose links
- Uses XPath to find all mailto links: `//a[contains(@href, "mailto:")]`
- Transforms mailto parameters (subject, cc, bcc, body) to Gmail URL format
- Connects to background script to get configured Gmail URL

**Security Observations:**
- No DOM manipulation beyond rewriting href attributes
- No data exfiltration - only transforms existing mailto links
- No postMessage usage or cross-origin communication
- Sets `target="_blank"` to open links in new tabs (expected behavior)

### Content Script (infopasser.js)
**Functionality:**
- Captures selected text from page when user clicks extension icon
- Sends selected text to background script via chrome.runtime.sendMessage

**Security Observations:**
- Only captures `window.getSelection().toString()` - no keylogging
- Data only sent when user explicitly triggers extension action
- No persistent selection monitoring
- Minimal code surface area (19 lines)

### Options Page (options.js, options.html)
**Functionality:**
- Allows users to configure Google Apps domain and subject prefix
- Migrates localStorage data to chrome.storage.local for MV3 compliance
- Basic domain validation (checks for presence of '.')

**Security Observations:**
- No external requests
- Simple form handling with proper event listeners
- Data stored locally only in chrome.storage.local
- Auto-closes tab after migration (clever UX for upgrade path)

## False Positives

| Pattern | Location | Explanation | Verdict |
|---------|----------|-------------|---------|
| N/A | N/A | No suspicious patterns detected | CLEAN |

## API Endpoints & External Communication

| Domain/URL | Purpose | Data Sent | Assessment |
|------------|---------|-----------|------------|
| https://mail.google.com/ | Opens Gmail compose window | Page title, URL, selected text (user-initiated) | LEGITIMATE - Core functionality |
| https://clients2.google.com/service/update2/crx | Chrome Web Store update endpoint | N/A (update_url) | LEGITIMATE - Standard update mechanism |

**Note**: The extension does not make any network requests itself. It only constructs URLs that open Gmail in new windows when the user explicitly triggers the extension.

## Data Flow Summary

### Data Collection
- **Page Title**: Collected only when user clicks extension icon
- **Page URL**: Collected only when user clicks extension icon
- **Selected Text**: Collected only when user clicks extension icon
- **User Preferences**: Domain name and subject prefix stored in chrome.storage.local

### Data Transmission
- No data is transmitted to external servers by the extension
- All collected data is used to construct Gmail compose URLs that open in user's browser
- User controls what information is ultimately sent via Gmail (standard email composition)

### Data Storage
- `chrome.storage.local.domainName`: Optional Google Apps domain
- `chrome.storage.local.subjectPrefix`: Optional email subject prefix
- `chrome.storage.local.hasMigrated`: Migration flag (boolean)

## Privacy Assessment

**Data Minimization**: Excellent - only collects data necessary for stated functionality
**User Consent**: Explicit - data only collected when user clicks extension icon
**Transparency**: High - extension description accurately describes functionality
**Third-Party Sharing**: None - no data sent to third parties
**Retention**: Minimal - only preferences stored locally, no telemetry

## Code Quality & Security Practices

**Positive Indicators:**
- Clean, well-documented code with copyright headers
- Modern ES6+ syntax (async/await, const/let, template literals)
- Proper error handling and input validation
- Manifest V3 compliant (modern security model)
- No obfuscation or minification
- URL encoding for user inputs
- Secure message passing patterns

**No Red Flags:**
- No dynamic code execution (eval, Function, setTimeout with strings)
- No DOM-based XSS vectors
- No cookie harvesting
- No keylogging
- No extension fingerprinting or killing
- No ad injection or affiliate fraud
- No fetch/XHR hooking
- No WebAssembly
- No remote configuration or kill switches

## Comparison to Stated Functionality

**Extension Description**: "Makes Gmail your default email application and provides a button to compose a Gmail message to quickly share a link via email"

**Actual Behavior**:
1. Rewrites mailto: links on pages to open Gmail compose
2. Provides browser action button to share current page/selection via Gmail
3. Supports Google Apps for Work/Education domain configuration
4. Allows custom subject prefix configuration

**Verdict**: Extension behavior precisely matches stated functionality with no hidden features or malicious capabilities.

## Overall Risk Assessment

### Risk Level: CLEAN

### Justification
This is a legitimate, well-engineered extension by Google that performs exactly as advertised. While it requests broad host permissions (`http://*/*`, `https://*/*`), these are essential for its core mailto-rewriting functionality and are not abused. The extension:

1. **Serves its intended purpose** - mailto link rewriting and quick email sharing
2. **No malicious behavior** - no data exfiltration, tracking, or hidden functionality
3. **No security vulnerabilities** - clean code with proper input handling
4. **Respects user privacy** - only collects data when user explicitly triggers actions
5. **Transparent operation** - all functionality aligns with extension description
6. **Official Google product** - code quality and security practices reflect internal standards

The broad permissions are invasive by nature but are legitimately required for the advertised functionality. There is no evidence of data collection beyond what's necessary, and no communication with external servers for analytics or tracking purposes.

### Recommendations
- **For Users**: Safe to install and use. Extension is trustworthy and performs as described.
- **For Security Teams**: No action required. Extension poses no security or privacy risk.
- **For Developers**: Exemplary code quality - serves as good reference for secure Chrome extension development.

## Conclusion

Send from Gmail (by Google) is a clean, secure extension with no vulnerabilities or malicious behavior. It represents a legitimate use case for broad host permissions in service of its core mailto-rewriting functionality. The extension is recommended as safe for general use.

---

**Analyst Notes**: This is one of the cleanest extensions analyzed to date. Google's internal development standards are evident in the code quality, security practices, and minimal attack surface. The extension serves as a good benchmark for what legitimate, non-malicious extensions should look like.
