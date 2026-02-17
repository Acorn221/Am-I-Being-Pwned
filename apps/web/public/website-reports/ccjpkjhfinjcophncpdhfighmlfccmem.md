# Security Analysis: LearnPlatform for Educators

## Extension Metadata

- **Extension ID**: ccjpkjhfinjcophncpdhfighmlfccmem
- **Name**: LearnPlatform for Educators
- **Version**: 1.25
- **Manifest Version**: 3
- **User Count**: 700,000
- **Rating**: 3.0/5
- **Publisher**: LearnPlatform
- **Category**: Educational Technology / Analytics

## Executive Summary

LearnPlatform for Educators is an educational analytics extension designed to track educator browsing behavior and time spent on educational websites. While the extension serves a legitimate educational purpose (providing product evaluations for educational websites), it implements extensive surveillance capabilities that raise significant privacy concerns.

**Risk Level: MEDIUM**

The extension collects granular browsing data including:
- Complete URLs of all visited websites (with query parameters)
- User email addresses via Chrome identity API
- Time-on-task metrics (tracking active time spent on specific websites)
- Tab metadata and window focus states
- Page load performance metrics

This data is transmitted to LearnPlatform's servers every minute, creating a comprehensive profile of educator browsing behavior. While the functionality appears aligned with its stated educational analytics purpose, the breadth of data collection and real-time transmission creates privacy risks, particularly if the data is stored long-term or shared with third parties.

### Key Findings

- **Medium Severity**: Comprehensive browsing surveillance with minute-by-minute reporting
- **Medium Severity**: User identity collection (email address) linked to browsing behavior
- **Low Severity**: Unexpected external dependency on reactjs.org CDN

## Detailed Vulnerability Analysis

### MEDIUM: Invasive Browsing Behavior Tracking

**Category**: Privacy / User Tracking

The extension implements comprehensive browsing surveillance by monitoring all tab activity and transmitting detailed usage data to remote servers.

**Technical Details**:

The background service worker monitors all tab changes and window focus events:

```javascript
chrome.tabs.onUpdated.addListener(((e,t,n)=>{"complete"===t.status&&n.active&&Ce(n)}))
chrome.tabs.onActivated.addListener((async({tabId:e})=>{const t=await chrome.tabs.get(e);Ce(t)}))
chrome.windows.onFocusChanged.addListener((async t=>{...}))
```

When a user visits any website, the extension:

1. **Matches visited URLs against a domain list** fetched from `app.learnplatform.com/api/chrome_extension/domains`
2. **Records the complete URL** including path and query parameters
3. **Tracks time-on-task** by monitoring active window focus and measuring duration in seconds
4. **Stores usage events** in local storage, including:
   - `usage_type: "load"` - URL loads with full URL path
   - `usage_type: "minute_on_system"` - Time spent on each matched website
   - `usage_type: "download_metrics"` - Performance timing data

**Data Transmission**:

Every minute, the extension sends aggregated data to `ep.learnplatform.com/api/aggregations`:

```javascript
// Aggregation payload structure
{
  email: userEmail,
  user_type: "educator",
  user_id: userId,
  sessions: [{
    period: "minute",
    period_length: 1,
    time: timestamp,
    events: [
      {usage_type: "load", url: fullUrl, tool_id: toolId},
      {usage_type: "minute_on_system", tool_id: toolId, seconds: timeInSeconds}
    ]
  }]
}
```

**Privacy Impact**:

- URLs may contain sensitive query parameters (search terms, session IDs, personal identifiers)
- Time-tracking creates detailed behavioral profiles showing which educational tools educators use most
- Continuous 1-minute reporting intervals enable near-real-time surveillance
- Data is linked to personally identifiable information (email address)

**Evidence from Static Analysis**:

ext-analyzer identified three exfiltration flows:
- `chrome.storage.local.get → fetch(app.learnplatform.com)` - Storage data sent to analytics
- `chrome.tabs.get → fetch(app.learnplatform.com)` - Tab metadata sent to analytics
- `chrome.storage.local.get → fetch(reactjs.org)` - Unexpected third-party data flow

### MEDIUM: User Identity Collection and Linkage

**Category**: Privacy / PII Collection

The extension collects user email addresses via the Chrome Identity API and links this personally identifiable information to all browsing activity.

**Technical Details**:

On startup and sign-in events, the extension retrieves the user's Google account email:

```javascript
chrome.identity.getProfileUserInfo({accountStatus:"ANY"},(({email:t})=>e(t)))
```

It then fetches a user ID from LearnPlatform's servers:

```javascript
// Fetch user ID from data.learnplatform.com
const userId = await Pe(email, userType);
// Endpoint: https://data.learnplatform.com/public/api/v1/processor/people/{email}
```

If the user is not found, it creates a new user record via POST to the `/fetch` endpoint.

**Privacy Impact**:

- **PII Linkage**: Every browsing event is explicitly linked to the user's email address
- **Persistent Tracking**: User ID enables cross-session tracking and long-term profile building
- **Third-party Integration**: User data is shared with `data.learnplatform.com` (separate subdomain)
- **No Anonymization**: No evidence of data anonymization or hashing before transmission

**Headers Sent**:

All API requests include identifying headers:
```javascript
{
  "LearnPlatform-ContainsUserId": "true",
  "LearnPlatform-Version": "1.25",
  "LearnPlatform-UserType": "educator"
}
```

### LOW: Unexpected Third-Party Dependency (reactjs.org)

**Category**: Code Integrity / Supply Chain

The static analyzer detected data flows to `reactjs.org`, which is not declared in host_permissions and represents an unexpected third-party dependency.

**Technical Details**:

ext-analyzer reported:
- `chrome.storage.local.get → fetch(reactjs.org)` flow from `background.js ⇒ popup.js`
- `message data → fetch(reactjs.org)` attack surface from `options.js ⇒ popup.js`

This suggests the popup or options page may be loading React libraries from a CDN rather than bundling them locally.

**Potential Risks**:

- **Supply Chain Attack**: If reactjs.org is compromised, malicious code could be injected
- **Privacy Leak**: Requests to reactjs.org expose user browsing patterns (though not extension-specific data)
- **Availability**: Extension functionality depends on external CDN availability

**Note**: This is likely a false positive from the static analyzer detecting React component references rather than actual network requests. Manual code review found no explicit fetch calls to reactjs.org in the background script. However, the popup and options pages are heavily minified React bundles and may contain embedded CDN URLs.

## Attack Surface Analysis

### Message Passing Vulnerabilities

ext-analyzer identified potential injection risks in cross-component communication:

```
message data → *.innerHTML(reactjs.org)    from: popup.js, options.js ⇒ options.js
message data → fetch(app.learnplatform.com)    from: popup.js, options.js ⇒ background.js
```

The background worker accepts messages from popup/options pages:

```javascript
chrome.runtime.onMessage.addListener(((e,t,n)=>{
  ce&&"WRITE_TO_STATE"===e.type?se(e.data):"READ_STATE"===e.type&&n(...)
}))
```

The `WRITE_TO_STATE` message allows popup/options to modify the extension's state directly. While this appears to be legitimate inter-component communication, if popup.js or options.js were compromised (e.g., via XSS), an attacker could manipulate the extension's state.

**Mitigation**: The extension uses Content Security Policy `"script-src": "'self'"`, which prevents inline scripts and external script loading, reducing XSS risk.

### Code Obfuscation

ext-analyzer flagged the extension as obfuscated. All JavaScript files (background.js, popup.js, options.js) are heavily minified webpack bundles with variable name mangling, making code review difficult. While this is common for production React applications, it reduces transparency.

## Network Analysis

### Endpoints Contacted

| Domain | Purpose | Data Sent |
|--------|---------|-----------|
| app.learnplatform.com | Domain list retrieval | None (GET request) |
| ep.learnplatform.com | Event aggregation | Email, userId, URLs, time-on-task |
| data.learnplatform.com | User ID lookup/creation | Email, user_type |
| reactjs.org | React CDN (suspected) | Unknown |

### Data Exfiltration Patterns

1. **Initialization**: Fetch domain list from `app.learnplatform.com/api/chrome_extension/domains`
2. **User Identification**: Retrieve email via chrome.identity, fetch userId from data.learnplatform.com
3. **Continuous Monitoring**: Track tab changes, URL loads, and active time
4. **Minute-by-Minute Reporting**: POST aggregated events to `ep.learnplatform.com/api/aggregations` every 60 seconds
5. **Performance Metrics**: Send download timing data to `ep.learnplatform.com/api/load_metric`

### Retry and Caching Logic

The extension implements sophisticated retry logic with exponential backoff:

```javascript
async function _e(e,t=500,n=2,r=3e5,a=fetch){
  // Retries failed requests with exponential backoff
  // Caches failed responses in Cache API with custom headers
  // Max backoff: 300 seconds (5 minutes)
}
```

This ensures persistent data transmission even if the server is temporarily unavailable.

## Permission Analysis

### Requested Permissions

| Permission | Justification | Risk Level |
|------------|--------------|------------|
| `tabs` | Read active tab URLs | HIGH - Full browsing history access |
| `identity` + `identity.email` | User identification | HIGH - PII collection |
| `storage` | Cache state and events | MEDIUM - Local data persistence |
| `alarms` | Minute/hour timers | LOW - Background execution |
| `idle` | Detect device lock/unlock | MEDIUM - User presence tracking |
| Host: `app.learnplatform.com/*` | API access | LOW - Legitimate backend |
| Host: `ep.learnplatform.com/*` | Event reporting | LOW - Legitimate backend |

### Over-Privileged Permissions

**`tabs` permission**: The extension only needs to read the active tab URL, but the `tabs` permission grants access to all tabs, including those in other windows. The extension uses:
- `chrome.tabs.get(tabId)` - Read specific tab
- `chrome.tabs.query({active:true, windowId:windowId})` - Find active tab
- `chrome.tabs.onUpdated` - Monitor all tab updates
- `chrome.tabs.onActivated` - Monitor tab switches

While the extension only processes the active tab, the permission grants broader access than strictly necessary. Manifest V3's `activeTab` permission would be more appropriate but would require user interaction.

**`idle` permission**: Used to detect device lock state and pause tracking. While this serves a legitimate purpose (don't count time when device is locked), it also enables presence detection, which could be privacy-invasive if misused.

## Code Quality and Security Practices

### Positive Security Practices

1. **Content Security Policy**: Strict CSP prevents inline scripts and external code execution
2. **Manifest V3**: Uses modern service worker architecture
3. **Error Handling**: Comprehensive try/catch blocks and promise error handlers
4. **Retry Logic**: Exponential backoff prevents aggressive server requests

### Security Concerns

1. **Heavy Minification**: All code is webpack-minified, making auditing difficult
2. **Immer.js Library**: Uses Immer for state management (bundled, version unclear)
3. **No Data Encryption**: While HTTPS is used, no evidence of additional encryption for sensitive data
4. **No User Consent**: Extension begins tracking immediately upon installation (education context may justify this)

## Recommendations

### For Users

1. **Review Privacy Policy**: Understand how LearnPlatform stores and shares your browsing data
2. **Check Institutional Agreement**: Verify your school/district has a data processing agreement with LearnPlatform
3. **Limit Use to Work Contexts**: Only enable when using educational tools, not for personal browsing
4. **Request Data Deletion**: If you leave the institution, request deletion of your tracked data

### For Developers

1. **Data Minimization**: Only collect URLs for whitelisted educational domains, not all URLs
2. **Anonymization**: Hash or pseudonymize user identifiers before transmission
3. **User Controls**: Provide granular controls to pause tracking or exclude specific websites
4. **Transparency**: Include in-extension privacy dashboard showing collected data
5. **Local Processing**: Aggregate data locally before transmission rather than sending every URL load
6. **reactjs.org Dependency**: Bundle React locally or clarify why reactjs.org appears in dataflow analysis

### For Administrators

1. **Data Retention Policy**: Establish clear data retention limits with LearnPlatform
2. **Third-Party Sharing**: Verify LearnPlatform does not share data with third parties
3. **Student Privacy**: Ensure compliance with FERPA, COPPA, and state student privacy laws
4. **Informed Consent**: Inform educators about the scope of tracking before deployment

## Conclusion

LearnPlatform for Educators is a **medium-risk** extension that implements extensive browsing surveillance for educational analytics purposes. While the functionality appears legitimate for its intended use case (tracking educator engagement with educational technology), the breadth of data collection and granular reporting intervals create significant privacy concerns.

The extension collects personally identifiable information (email addresses) linked to detailed browsing behavior and transmits this data to third-party servers every minute. This creates a comprehensive surveillance apparatus that, while potentially valuable for educational research, represents a substantial invasion of user privacy.

**Risk Rating: MEDIUM**

The extension is appropriate for institutional deployment with proper data governance policies, but individual users should carefully consider the privacy trade-offs before installation. The extension would benefit from data minimization practices, user controls for pausing tracking, and greater transparency about data handling practices.

---

**Analysis Date**: 2026-02-15
**Analyzer**: ext-analyzer v1.25 + Manual Code Review
**Risk Score**: 58/100
