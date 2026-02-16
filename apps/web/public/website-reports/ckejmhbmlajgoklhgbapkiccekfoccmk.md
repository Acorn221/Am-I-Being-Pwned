# Security Analysis: Mobile simulator - responsive testing tool (ckejmhbmlajgoklhgbapkiccekfoccmk)

## Extension Metadata
- **Name**: Mobile simulator - responsive testing tool
- **Extension ID**: ckejmhbmlajgoklhgbapkiccekfoccmk
- **Version**: 4.14.8
- **Manifest Version**: 3
- **Estimated Users**: ~1,000,000
- **Developer**: François Duprat
- **Analysis Date**: 2026-02-14

## Executive Summary
Mobile simulator is a legitimate mobile device simulator extension for responsive web testing. The extension provides device emulation, screenshot capture, and screen recording features. Analysis revealed **MULTIPLE SECURITY VULNERABILITIES** including missing postMessage origin validation, hardcoded API keys, and potential innerHTML injection vectors. While the extension appears to serve its stated purpose without malicious intent, the security issues present real attack surface for exploitation by malicious websites.

**Overall Risk Assessment: LOW**

The extension's functionality is legitimate, but implementation flaws create security risks that should be addressed by the developer.

## Vulnerability Assessment

### 1. Missing postMessage Origin Validation (MEDIUM)
**Severity**: MEDIUM
**Files**:
- `/js/simulator.js` (line 13)
- `/js/message.js` (line 1)

**Analysis**:
The extension registers multiple `window.addEventListener("message")` handlers without validating the `event.origin` property. This allows ANY website to send messages to the extension's simulator page, potentially triggering unintended actions.

**ext-analyzer findings**:
```
[HIGH] window.addEventListener("message") without origin check    js/simulator.js:13
[HIGH] window.addEventListener("message") without origin check    js/simulator.js:13
[HIGH] window.addEventListener("message") without origin check    js/message.js:1
```

**Attack Scenarios**:
1. **Message Injection**: Malicious websites could send crafted postMessage events to manipulate simulator state
2. **Data Exfiltration via Cross-Component Flow**: The analyzer detected flows where message data reaches innerHTML and fetch calls:
   - `message data → *.innerHTML(www.w3.org)` from workers/screencast_worker.js → js/simulator.js
   - `message data → fetch(github.com)` from workers/screencast_worker.js → js/simulator.js

**Impact**:
- Medium severity: While exploitation requires specific conditions, the missing origin validation violates security best practices
- The extension uses `externally_connectable` to allow connections from `https://www.webmobilefirst.com/*`, but the postMessage handlers don't enforce this restriction

**Remediation**:
Add origin validation to all message handlers:
```javascript
window.addEventListener("message", (event) => {
  if (event.origin !== "chrome-extension://" + chrome.runtime.id &&
      !event.origin.startsWith("https://www.webmobilefirst.com")) {
    return; // Ignore messages from untrusted origins
  }
  // Process message...
});
```

**Verdict**: **MEDIUM RISK** - Missing security controls that could be exploited

---

### 2. Hardcoded API Keys (LOW)
**Severity**: LOW
**Files**: `/js/background.js` (embedded in minified code)

**Analysis**:
The extension contains a hardcoded PostHog analytics API key embedded directly in the code.

**Code Evidence**:
```javascript
api_key:"phc_yObZ9Y7kcPWkhvNtSflXm0gdkDuRBvOFsps03KXgxRH"
```

**Endpoint**:
- `https://us.i.posthog.com/capture` (analytics endpoint)

**Data Transmitted**:
Based on PostHog SDK patterns and code analysis, the extension sends analytics events including:
- User actions (device changes, zoom changes, etc.)
- Browser/OS information (`$browser`, `$os` properties detected)
- Extension version and configuration
- User activity tracking (throttled - events blocked on Tuesdays: `2!==(new Date).getDay()`)

**Privacy Considerations**:
The extension's locale files disclose analytics usage to users:
> "I help the developer of this extension improve their product with Posthog. All data is anonymized." (settings_change_analytics message)

Users can disable analytics through extension settings.

**Security Impact**:
- **LOW**: Hardcoded API key is for analytics service, not sensitive infrastructure
- Key could be abused to send fake analytics data to developer's PostHog account
- No evidence of PII collection beyond standard browser fingerprinting

**Verdict**: **LOW RISK** - Hardcoded key is for analytics only, usage disclosed to users

---

### 3. innerHTML Injection Risk (MEDIUM)
**Severity**: MEDIUM
**Files**: Various (detected via data flow analysis)

**Analysis**:
The ext-analyzer detected data flows where postMessage data reaches innerHTML assignment without sanitization.

**Flow**:
```
message data → *.innerHTML(www.w3.org)
Source: workers/screencast_worker.js
Sink: js/simulator.js
```

**Context**:
The extension's files are heavily minified Vue.js applications. Vue typically escapes template content by default, but direct `innerHTML` assignments bypass this protection.

**Attack Scenario**:
If the postMessage handler passes user-controlled data to innerHTML:
1. Malicious website sends crafted message
2. Extension processes message without origin check
3. Data inserted via innerHTML with malicious HTML/JS
4. XSS executes in extension context with elevated privileges

**Mitigating Factors**:
- Vue.js framework may provide some automatic escaping
- Extension runs in isolated context, limiting DOM XSS impact
- Requires specific message format to reach innerHTML sink

**Verdict**: **MEDIUM RISK** - Potential XSS vector, severity depends on actual code path

---

### 4. Extensive Network Endpoints (INFORMATIONAL)
**Severity**: INFORMATIONAL
**Analysis**:
The extension communicates with multiple backend services for legitimate functionality.

**Endpoints Identified**:
1. **AWS API Gateway** (subscription/video processing):
   - `jth7w9hc3m.execute-api.eu-west-3.amazonaws.com`
   - `y13qoxjas8.execute-api.eu-west-3.amazonaws.com`
   
   **Usage**: 
   - Pricing API: `/prices/subscription?plan=personal`
   - Video upload: `/extension/upload-video`
   - Presigned URL generation: `/extension/get-presigned-url?filename=...`
   - Video conversion trigger: `/extension/trigger-video-conversion`

2. **Heroku Admin Panel**:
   - `mobile-first-admin.herokuapp.com/users/me`
   
   **Usage**: User authentication and subscription management
   - Sends Authorization token from `chrome.storage.sync`
   - Validates PRO subscriptions

3. **Supabase Database**:
   - `bixsctseziswsruplxzm.supabase.co`

4. **AWS S3** (video storage):
   - `webmobilefirst-screencasts.s3.eu-west-3.amazonaws.com`
   - `mobile-first-extension-temp-webm-video-captures.s3.eu-west-3.amazonaws.com`

5. **Analytics/Telemetry**:
   - `us.i.posthog.com` (PostHog)
   - `www.google-analytics.com`

6. **IP Geolocation**:
   - `pro.ip-api.com`

**Code Evidence** (video upload flow):
```javascript
// Fetch presigned URL for S3 upload
h = await fetch(`https://jth7w9hc3m.execute-api.eu-west-3.amazonaws.com/extension/get-presigned-url?filename=${d}&filetype=${u}`)

// Upload video to S3
// (upload occurs)

// Trigger video conversion
await fetch(`https://jth7w9hc3m.execute-api.eu-west-3.amazonaws.com/extension/trigger-video-conversion?input_file_name=${d}&output_file_name=...`)

// Notify backend of upload completion
await fetch("https://jth7w9hc3m.execute-api.eu-west-3.amazonaws.com/extension/upload-video", {
  method: "POST",
  body: JSON.stringify({url: r, key: o})
})
```

**Privacy Impact**:
- Screen recordings uploaded to developer's S3 buckets (with user consent - PRO feature)
- IP geolocation may reveal user location
- Multiple tracking services can correlate user activity

**Verdict**: **INFORMATIONAL** - Extensive backend infrastructure, normal for feature-rich extension

---

### 5. Obfuscated Code (INFORMATIONAL)
**Severity**: INFORMATIONAL
**Analysis**:
The ext-analyzer flagged the extension as containing obfuscated code. Investigation reveals this is primarily due to Vue.js minification/bundling, not intentional malicious obfuscation.

**Observations**:
- Minified Vue.js 2.7.14 and Vuex 3.6.2 bundles
- Standard webpack/rollup production build artifacts
- License headers present for open-source libraries (Vue, Vuex, buffer, ieee754)

**Verdict**: **NOT MALICIOUS** - Standard production build minification

---

## Permissions Analysis

### High-Risk Permissions
1. **`<all_urls>`** - Access to all websites
   - **Justification**: Required for device simulator to inject into any webpage
   - **Usage**: Content script injection for mobile device spoofing

2. **`webRequest`** + **`declarativeNetRequest`**
   - **Justification**: Modifies user agent and headers to simulate mobile devices
   - **Potential for Abuse**: Could intercept/modify all web traffic

3. **`tabCapture`**
   - **Justification**: Screen recording feature
   - **Usage**: Captures tab content for video generation

4. **`scripting`**
   - **Justification**: Injects device emulation scripts
   - **File**: `spoofer.js` (web-accessible resource)

### Standard Permissions
- `tabs`, `activeTab` - Tab management for simulator
- `storage` - Settings persistence
- `contextMenus` - Right-click menu integration
- `offscreen` - Background processing for video encoding
- `commands` - Keyboard shortcuts for screenshots

**Verdict**: Permissions are appropriate for stated functionality, but broad access creates large attack surface.

---

## Web Accessible Resources
The extension exposes multiple resources to web pages:

```json
{
  "resources": [
    "spoofer.js",
    "assets/**/*",
    "fonts/icomoon.ttf",
    "fonts/avenir.otf",
    "css/**/*",
    "icons/**/*",
    "workers/*.js",
    "pages/permission/micro.html",
    "pages/permission/camera.html",
    "pages/permission/requestMicroPermission.ts",
    "pages/permission/requestCameraPermission.ts"
  ],
  "matches": ["<all_urls>"]
}
```

**Security Implications**:
- `spoofer.js` is injectable by any website (required for device spoofing)
- Workers exposed to all sites (used for video processing)
- Permission request pages accessible
- Broad wildcard exposure increases fingerprinting risk

**Verdict**: **INFORMATIONAL** - Standard pattern for device emulation extensions

---

## Data Flow Analysis

### Sensitive Data Flows

1. **User Authentication Token**:
   ```
   chrome.storage.sync.get(["auth.token"]) → Authorization header → 
   mobile-first-admin.herokuapp.com/users/me
   ```
   - Stored in sync storage (backed up to Google account)
   - Sent to third-party Heroku backend

2. **Screen Recordings**:
   ```
   tabCapture → VideoFrame processing → canvas → S3 presigned upload →
   AWS S3 buckets
   ```
   - User-initiated (PRO feature)
   - Uploaded to developer-controlled S3 buckets
   - Potentially contains sensitive information from captured tabs

3. **Analytics Events**:
   ```
   User actions → PostHog capture endpoint
   Browser/device info → us.i.posthog.com
   ```
   - Includes device fingerprinting
   - User can opt-out via settings

---

## Recommendations

### For Developer (François Duprat)

1. **CRITICAL**: Add origin validation to all postMessage handlers
2. **HIGH**: Sanitize any data before innerHTML assignment
3. **MEDIUM**: Rotate hardcoded PostHog API key, use environment-based injection
4. **MEDIUM**: Implement Content Security Policy strict-dynamic for better XSS protection
5. **LOW**: Add integrity checks for web-accessible resources
6. **LOW**: Document data collection practices in privacy policy

### For Users

1. **Use with caution** on pages containing sensitive information
2. **Review permissions** - extension has broad access to all websites
3. **Disable analytics** in settings if privacy is a concern
4. **Be aware** that screen recordings are uploaded to third-party servers (PRO feature)
5. **Monitor** for unexpected behavior given the postMessage vulnerabilities

---

## Conclusion

Mobile simulator is a **legitimate extension with security flaws**. The core functionality (device emulation, screenshots, screen recording) appears to work as advertised without malicious behavior. However, multiple security vulnerabilities create real attack surface:

- Missing origin validation could allow malicious websites to send commands to the extension
- innerHTML injection vectors could enable XSS in extension context
- Hardcoded API keys violate security best practices
- Extensive permissions and network access create privacy concerns

**Risk Level: LOW** - The extension serves its intended purpose, but security improvements are needed to protect users from potential exploitation.

**Recommendation**: Safe for use in development/testing environments. Exercise caution when using on websites with sensitive data. Developer should address security vulnerabilities in future updates.
