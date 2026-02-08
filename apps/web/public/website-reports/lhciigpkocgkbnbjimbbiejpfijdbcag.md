# Action Model Extension Security Analysis

## Metadata
- **Extension Name**: Action Model
- **Extension ID**: lhciigpkocgkbnbjimbbiejpfijdbcag
- **Version**: 0.23.0
- **User Count**: ~40,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-08

## Executive Summary

Action Model is a browser automation and training extension built with the Plasmo framework. The extension allows users to record, train, and automate browser interactions. While the extension has broad permissions and significant access to user data, the functionality appears aligned with its stated purpose of browser automation. The extension communicates with legitimate Action Model infrastructure and uses PostHog for analytics tracking.

**Overall Risk Level**: **MEDIUM**

The extension has invasive permissions and broad access patterns typical of browser automation tools, but the data collection and external communication appear to serve the extension's intended functionality rather than malicious purposes.

## Manifest Analysis

### Permissions
```json
"permissions": [
  "storage",
  "alarms",
  "cookies",
  "tabs",
  "activeTab",
  "scripting",
  "notifications"
]
```

### Host Permissions
- `<all_urls>` - Required for browser automation across all websites

### Content Scripts
- **Injection**: All URLs (`<all_urls>`)
- **Timing**: `document_start`
- **All Frames**: Yes
- **Script**: `contents.27786a0d.js` (331KB minified)

### Externally Connectable
```json
"externally_connectable": {
  "matches": [
    "*://localhost/*",
    "https://*/*"
  ]
}
```

**Security Concern**: This allows ANY HTTPS website to communicate with the extension via `chrome.runtime.sendMessage()`. This is an extremely broad attack surface.

### Content Security Policy
- **No CSP defined** - Uses default Manifest V3 CSP

## Code Analysis

### Architecture
- **Framework**: Plasmo (React-based extension framework)
- **Bundler**: Parcel
- **Code Size**:
  - Background script: 2.3MB (heavily bundled)
  - Content script: 331KB
  - Popup: 1.9MB
  - Main ESM bundle: 1.9MB

### Network Communication

#### Action Model Infrastructure
```
https://api.actionmodel.com
https://train.actionmodel.com
https://actionmodel.com
```

The extension communicates with legitimate Action Model backend services for:
- User authentication (appears to use Clerk.dev authentication service)
- Training session data
- Browser automation workflows
- User settings and preferences

#### Analytics
```
https://eu.i.posthog.com
```

Uses PostHog analytics for telemetry and user behavior tracking.

### Chrome API Usage

**Content Script APIs**:
- `chrome.runtime.sendMessage` - Communication with background
- `chrome.runtime.getURL` - Resource loading
- `chrome.storage.local` - Local data storage
- `chrome.storage.onChanged` - Storage event listeners
- `chrome.notifications.create/clear/getAll` - User notifications

**Popup/Background APIs**:
- `chrome.tabs.query/create/sendMessage` - Tab management
- `chrome.runtime.getManifest` - Extension metadata
- `chrome.notifications.*` - Notifications

**Notable**: No evidence of:
- `chrome.cookies.get/getAll` usage (despite having permission)
- `chrome.webRequest` hooking
- `chrome.debugger` API usage
- Extension enumeration patterns

### DOM Access Patterns

The content script has typical DOM access for browser automation:
```
document.cookie (READ access for automation)
document.querySelector/querySelectorAll
document.createElement
document.addEventListener
window.addEventListener
window.getComputedStyle
```

## Vulnerability Assessment

### 1. Overly Broad External Connectivity (HIGH)

**Severity**: HIGH
**Files**: manifest.json
**Code**:
```json
"externally_connectable": {
  "matches": [
    "*://localhost/*",
    "https://*/*"
  ]
}
```

**Description**: The `externally_connectable` configuration allows ANY HTTPS website to send messages to the extension. This creates a massive attack surface where malicious websites could potentially trigger extension functionality or probe for vulnerabilities.

**Impact**:
- Any HTTPS site can interact with the extension
- Potential for cross-site scripting attacks via extension APIs
- Third-party websites could abuse automation features
- Social engineering attacks (malicious sites could trigger automated actions)

**Recommendation**: Restrict to specific Action Model domains:
```json
"externally_connectable": {
  "matches": [
    "https://actionmodel.com/*",
    "https://train.actionmodel.com/*",
    "https://api.actionmodel.com/*",
    "*://localhost/*"
  ]
}
```

**Verdict**: VULNERABLE

### 2. Broad Host Permissions (MEDIUM)

**Severity**: MEDIUM
**Files**: manifest.json
**Code**:
```json
"host_permissions": ["<all_urls>"]
```

**Description**: The extension requests access to all websites. While this is required for browser automation functionality, it provides significant data access.

**Impact**:
- Can access content on all websites
- Can read/modify DOM on any page
- Can intercept form submissions and user interactions
- Cookies permission allows reading cookies from any domain

**Mitigation**: This is largely justified by the extension's purpose (browser automation), but users should be aware of the broad access.

**Verdict**: JUSTIFIED (for intended functionality, but high risk if compromised)

### 3. Third-Party Analytics Tracking (LOW)

**Severity**: LOW
**Files**: popup.0cac8ff0.js
**Code**: PostHog analytics integration

**Description**: The extension uses PostHog (https://eu.i.posthog.com) for analytics and telemetry.

**Impact**:
- User behavior and interactions are tracked
- Extension usage patterns sent to third-party service
- Potential privacy concerns for sensitive workflows

**Data Collected**: Likely includes:
- Feature usage
- User interactions with popup
- Extension events and errors
- Session information

**Verdict**: DISCLOSED (standard analytics, but privacy implications)

### 4. Content Script Injection at document_start (LOW)

**Severity**: LOW
**Files**: manifest.json, contents.27786a0d.js
**Code**:
```json
"run_at": "document_start",
"all_frames": true
```

**Description**: Content script runs before page load in all frames on all websites.

**Impact**:
- Performance impact on all web pages
- Access to page before security controls load
- Can intercept early page state

**Verdict**: JUSTIFIED (required for reliable browser automation)

## False Positives

| Pattern | Location | Explanation |
|---------|----------|-------------|
| React SVG innerHTML | esm.f1f6d97f.js | Standard React rendering patterns |
| Clerk.dev authentication | esm.f1f6d97f.js, popup.0cac8ff0.js | Legitimate third-party auth service |
| Bearer token headers | popup.0cac8ff0.js | Standard API authentication (19 occurrences) |
| document.cookie access | contents.27786a0d.js | Required for browser automation recording |
| Parcel bundler runtime | All .js files | Standard build tool artifacts |

## API Endpoints

| Endpoint | Purpose | Authentication |
|----------|---------|----------------|
| https://api.actionmodel.com | Main API server | Bearer token |
| https://train.actionmodel.com | Training interface | Session-based |
| https://actionmodel.com | Main website | Public |
| https://eu.i.posthog.com | Analytics telemetry | API key |

## Data Flow Summary

### Data Collection
1. **User Interactions**: Browser automation workflows, clicks, form inputs
2. **Page Context**: DOM structure, selectors, element states
3. **Session Data**: Training sessions, automation history
4. **Analytics**: Feature usage, errors, performance metrics

### Data Transmission
- **Action Model Backend**: User automation data, training workflows
- **PostHog**: Analytics and telemetry data
- **Clerk.dev**: Authentication credentials

### Local Storage
- `chrome.storage.local`: User settings, cached workflows, session tokens

## Privacy Concerns

1. **Broad Data Access**: Extension can access all web page content including sensitive data
2. **Cookie Access**: Has permission to read cookies from all sites (though not actively used)
3. **Third-Party Analytics**: Usage data sent to PostHog
4. **External Message Reception**: Any HTTPS site can communicate with extension

## Recommendations

### Critical
1. **Restrict externally_connectable** to only Action Model domains
2. **Implement message origin validation** in runtime.onMessageExternal handlers
3. **Add rate limiting** for external message handling

### High Priority
1. Document what data is collected and transmitted to PostHog
2. Implement user consent for analytics tracking
3. Add CSP to manifest for additional security hardening

### Medium Priority
1. Minimize bundle sizes (2.3MB background script is excessive)
2. Consider lazy-loading analytics modules
3. Add code signing/integrity checks for external communications

## Overall Risk Assessment

**Risk Level**: MEDIUM

**Justification**:
- The extension's broad permissions are justified by its browser automation functionality
- Network communication appears limited to legitimate Action Model infrastructure
- No evidence of data exfiltration, malicious scripts, or crypto mining
- No obfuscated malicious code patterns detected
- The main security concern is the overly permissive `externally_connectable` configuration

**Key Concerns**:
1. Any HTTPS website can send messages to the extension (HIGH risk)
2. Broad access to all websites and cookies (justified, but high impact if exploited)
3. Third-party analytics tracking (privacy concern, but standard practice)

**Verdict**: The extension serves its stated purpose without clear malicious intent. However, the `externally_connectable` configuration creates unnecessary security risks that should be addressed. Users should understand that this extension has extensive access to their browsing data as required for browser automation functionality.

## Conclusion

Action Model is a legitimate browser automation tool with permissions appropriate to its functionality. The extension does not exhibit malicious behavior patterns, but the overly broad external connectivity configuration creates unnecessary security risks. The extension should restrict which websites can communicate with it to prevent potential abuse.

For users concerned about privacy, be aware that:
- The extension can access all web page content
- Usage data is sent to PostHog analytics
- Training workflows are synced to Action Model servers
- Any HTTPS website can potentially interact with the extension

**Recommended for**: Users who understand and accept the privacy/security trade-offs of browser automation tools
**Not recommended for**: Users handling highly sensitive data or requiring strict data isolation
