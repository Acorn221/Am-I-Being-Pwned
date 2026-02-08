# Security Analysis Report: superagent - Automatic cookie consent

## Extension Metadata
- **Extension ID**: neooppigbkahgfdhbpbhcccgpimeaafi
- **Name**: superagent - Automatic cookie consent
- **Version**: 3.46
- **User Count**: ~30,000
- **Analysis Date**: 2026-02-08

## Executive Summary

superagent is a legitimate cookie consent automation extension that automatically fills out cookie consent forms based on user preferences. The extension uses AWS Cognito for authentication, AWS API Gateway for backend services, and implements client-side encryption for consent logs. While the extension requests broad permissions and communicates with remote servers, all functionality aligns with its stated purpose of automating cookie consent decisions. No malicious behavior, data exfiltration, or privacy violations were detected.

**Overall Risk Level**: CLEAN

## Manifest Analysis

### Permissions
```json
"permissions": [
    "storage",
    "tabs",
    "cookies",
    "activeTab"
]
```

- **storage**: Used for caching user preferences, authentication tokens, and consent logs
- **tabs**: Required to interact with active tabs and inject consent handling logic
- **cookies**: Used to read cookie consent settings and delete cookies per user preference (lines 62302-62317 in background.js)
- **activeTab**: Standard permission for content script interaction

### Host Permissions
```json
"host_permissions": [
    "http://*/*",
    "https://*/*"
]
```
Broad host permissions are necessary for the extension to detect and interact with cookie consent forms on any website.

### Content Security Policy
No custom CSP defined - uses default Manifest V3 restrictions.

## Vulnerability Analysis

### 1. Authentication & AWS Integration
**Severity**: LOW
**Files**: `static/js/background.js` (lines 3-43)

**Finding**:
Extension uses AWS Cognito for user authentication with hardcoded configuration:
```javascript
Auth: {
  Cognito: {
    userPoolId: "eu-west-1_GRKlTYjgb",
    userPoolClientId: "5vjrqisbqg6edpfff4t1hlk3nr",
    identityPoolId: "eu-west-1:041b1b3c-c6a0-4c56-8d4d-002a45c5a57b"
  }
}
```

**Verdict**: FALSE POSITIVE - These are public AWS Cognito identifiers required for client-side authentication. Not credentials.

### 2. Backend API Endpoints
**Severity**: LOW
**Files**: `static/js/background.js` (lines 10-36)

**Finding**:
Extension communicates with multiple AWS API Gateway endpoints:
- `logger`: https://sb36xcrwx4.execute-api.eu-west-1.amazonaws.com/prod
- `keys`: https://58nocgldz5.execute-api.eu-west-1.amazonaws.com/prod
- `reporter`: https://udpnn9eiw0.execute-api.eu-west-1.amazonaws.com/prod
- `auth`: https://4ji95obasf.execute-api.eu-west-1.amazonaws.com/prod
- GraphQL: https://yz5sfocrcff47nuopemljg2tdu.appsync-api.eu-west-1.amazonaws.com/graphql

**Verdict**: CLEAN - All endpoints are part of legitimate backend infrastructure for user authentication, encrypted log storage, and metrics collection. Uses AWS Amplify library for secure API communication.

### 3. Data Collection & Logging
**Severity**: LOW
**Files**: `static/js/background.js` (lines 51730-51950)

**Finding**:
Extension logs consent actions with the following data:
```javascript
{
  hostname: <site>,
  outcome: "PREFERENCES_APPLIED|ACCEPTED_DEFAULT|REJECTED_ALL",
  totalClicks: <number>,
  cookieItems: <number>,
  time: <timestamp>
}
```

Logs are:
1. Encrypted client-side using Data Encryption Key (DEK) from key manager (line 51918)
2. Sent to logger API endpoint
3. Limited to one log per hostname per day (lines 51752-51769)
4. Only collected if user has logging enabled in preferences

**Verdict**: CLEAN - Transparent logging of consent automation with user control and client-side encryption. Serves legitimate purpose of tracking extension usage.

### 4. Cookie Access
**Severity**: LOW
**Files**: `static/js/background.js` (lines 62295-62318)

**Finding**:
Extension implements cookie deletion functionality:
```javascript
chrome.cookies.getAll({ url: e })
chrome.cookies.remove({ url: i, name: r.name })
```

**Verdict**: CLEAN - Cookie access is used solely for the stated purpose: reading cookie consent preferences and deleting cookies based on user settings. No evidence of cookie theft or unauthorized access.

### 5. Content Script Injection
**Severity**: LOW
**Files**: `static/js/content.js` (lines 34465-34510)

**Finding**:
Extension injects authentication helper script on specific domains:
- account.super-agent.com
- dev.super-agent.com
- rules.super-agent.com (for rule testing)

Uses custom events to communicate credentials from page context to extension:
```javascript
document.addEventListener("superAgent_sdte", a => {
  e(a.detail.message)
});
```

**Verdict**: CLEAN - Script injection is limited to the extension's own domains for legitimate authentication purposes. Not injecting on third-party sites.

### 6. Usage Metrics Collection
**Severity**: LOW
**Files**: `static/js/background.js` (lines 51959-52036)

**Finding**:
Extension tracks basic usage metrics:
```javascript
{
  ws: 1,           // websites processed
  cc: totalClicks, // consent clicks
  ms: timeSaved    // time saved calculation
}
```

**Verdict**: CLEAN - Minimal metrics collection for product analytics. No PII collected. Metrics are aggregated and sent to authenticated backend.

## False Positives

| Pattern | Location | Explanation |
|---------|----------|-------------|
| AWS Cognito IDs | background.js:4-8 | Public client identifiers, not secrets |
| innerHTML usage | Likely in vendors.js | Standard React/framework usage for DOM manipulation |
| API endpoints | background.js:10-42 | Legitimate backend infrastructure URLs |
| chrome.cookies | background.js:62302-62317 | Core functionality - managing cookie consent |
| postMessage | content.js:34401,34423 | Limited to extension's own domains for auth |

## API Endpoints Summary

| Endpoint | Purpose | Authentication | Data Sent |
|----------|---------|----------------|-----------|
| logger/logs | Store encrypted consent logs | AWS Cognito | Encrypted log entries |
| logger/metrics | Usage statistics | AWS Cognito | Aggregated metrics (ws, cc, ms) |
| keys/* | Encryption key management | AWS Cognito | Key requests |
| reporter/* | Error/bug reporting | AWS Cognito | User-submitted reports |
| auth/* | User authentication | Public | Auth credentials |
| GraphQL | User data queries | AWS Cognito | User preferences/settings |

## Data Flow Summary

1. **User Authentication**: Credentials → AWS Cognito → Session tokens stored in chrome.storage.local
2. **Consent Automation**: Page load → Detect consent form → Apply user preferences → Click buttons → Log outcome
3. **Encrypted Logging**: Consent action → Encrypt with DEK → Send to logger API → Store in AWS
4. **Metrics**: Daily aggregated metrics (websites, clicks, time saved) → logger/metrics endpoint
5. **Cookie Management**: Read cookie consent status → Delete cookies per user preferences

All data transmission uses HTTPS. User logs are encrypted client-side before transmission. Extension operates only when user is on a webpage with cookie consent forms.

## Security Strengths

1. Uses AWS Amplify library for secure API communication
2. Client-side encryption of consent logs before transmission
3. Implements proper session management with expiration
4. Limited to legitimate domains for script injection
5. No evidence of obfuscation or code hiding
6. Uses Manifest V3 (modern extension format)
7. Respects user preferences for logging/metrics

## Overall Risk Assessment

**Risk Level: CLEAN**

**Rationale:**
superagent is a legitimate privacy-focused extension that serves its stated purpose of automating cookie consent decisions. While it requests broad permissions (cookies, all hosts) and communicates with remote servers, all functionality is directly related to consent automation and optional cloud sync features. The extension:

- Does NOT inject ads or affiliate tracking
- Does NOT exfiltrate browsing history or sensitive data
- Does NOT implement residential proxy infrastructure
- Does NOT hook into fetch/XHR globally
- Does NOT enumerate or kill competing extensions
- Does NOT scrape AI conversations or inject market intelligence SDKs
- Implements proper encryption for user data
- Provides user control over logging and metrics

The invasive permissions are necessary for the core functionality and are used appropriately. Users who want automated cookie consent handling must accept that the extension needs to access cookies and interact with all websites. The backend infrastructure (AWS Cognito, encrypted logging) follows security best practices.

**Recommendation**: Safe for general use. Users should understand that consent logs are stored in the cloud (encrypted) if they use the account features.
