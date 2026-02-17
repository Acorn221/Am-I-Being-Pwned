# Vulnerability Assessment: Fathom AI Note Taker for Google Meet

## Extension Overview

- **Extension ID**: nhocmlminaplaendbabmoemehbpgdemn
- **Name**: Fathom AI Note Taker for Google Meet
- **Version**: 0.0.37
- **Users**: 400,000+
- **Rating**: 5.0/5.0
- **Manifest Version**: 3
- **Risk Level**: MEDIUM

## Executive Summary

Fathom AI Note Taker is a legitimate enterprise-grade meeting assistant that records, transcribes, and summarizes meetings. The extension collects Chrome user identity information (email and user ID) and sends it to fathom.video servers along with meeting metadata. While the data collection is disclosed and appears appropriate for the stated functionality, the extension employs several privacy-sensitive techniques including identity collection, meeting URL interception, and broad externally_connectable permissions that warrant a MEDIUM risk classification.

## Key Findings

### MEDIUM Severity Issues (2)

#### 1. Chrome Identity Collection and Transmission
**Location**: `service-worker.js` - Functions `ka()`, `Gn()`, `Da()`

The extension collects and transmits Chrome user identity information to fathom.video servers:

```javascript
async function ka(){
  if(kt==="")return;
  Hn({dsn:kt,integrations:[yt(),$n()],environment:U,debug:!1});
  let e=await chrome.identity.getProfileUserInfo({accountStatus:chrome.identity.AccountStatus.ANY}),
      t=await chrome.runtime.getPlatformInfo();
  dt({
    chromeExtUserId:e.id,
    chromeExtUserEmail:e.email,
    chromeExtVersion:chrome.runtime.getManifest().version,
    chromeOs:t.os,
    chromeArch:t.arch
  })
}
```

**Data Collected**:
- Chrome user email (`chrome.identity.email` permission)
- Chrome user ID (unique identifier)
- Extension version
- OS type and architecture

**Transmission Context**: This data is sent via custom headers on all API requests:
```javascript
headers:{
  "X-FATHOM-OS-VERSION":`${i.os} ${i.arch}`,
  "X-FATHOM-CHROME-EXT-VERSION":chrome.runtime.getManifest().version,
  "X-FATHOM-CHROME-EXT-USER-EMAIL":s.email,
  "X-FATHOM-CHROME-EXT-USER-ID":s.id,
  "Content-Type":"application/json",
  Authorization:"Bearer "+o.access_token
}
```

**Assessment**: While identity collection is necessary for user account management and appears disclosed, sending email addresses and persistent IDs in API headers creates a comprehensive user tracking profile. This is appropriate for an enterprise tool but represents significant data collection.

#### 2. Meeting URL Interception
**Location**: `service-worker.js` - `webRequest.onBeforeRequest` listener

The extension intercepts all meeting URLs before page load:

```javascript
chrome.webRequest.onBeforeRequest.addListener(e=>{
  Ma(e.url)  // Sends URL to fathom.video API
},{
  urls:zn,  // All Zoom, Google Meet, Teams URLs
  types:["main_frame"]
});

function Ma(e){
  Gn("/v1/calls/from_intercepted_uri?"+new URLSearchParams({uri:e,startable:"1"}),"GET",null)
    .then(t=>{console.log("intercept",e)})
    .catch(t=>{console.warn(t,t.cause)})
}
```

**Intercepted URLs**:
- `https://*.zoom.us/s/*`, `https://*.zoom.us/j/*`
- `https://*.zoomdev.us/s/*`, `https://*.zoomgov.com/s/*`
- `https://meet.google.com/*-*-*`
- `https://teams.live.com/meet/*`, `https://teams.microsoft.com/l/meetup-join/*`

**Assessment**: The extension sends every meeting URL the user joins to fathom.video servers. While this is likely necessary for the meeting bot to join and record, it creates a complete log of all meetings attended by the user. The `startable:"1"` parameter suggests automated recording initiation.

### LOW Severity Issues (1)

#### 3. Broad externally_connectable Configuration
**Location**: `manifest.json`

The extension allows external websites to communicate with it:

```json
"externally_connectable": {
  "matches": [
    "https://zoom.us/", "https://*.zoom.us/s/*", "https://*.zoom.us/j/*",
    "https://zoomdev.us/", "https://*.zoomdev.us/s/*", "https://*.zoomdev.us/j/*",
    "https://zoomgov.com/", "https://*.zoomgov.com/s/*", "https://*.zoomgov.com/j/*",
    "https://meet.google.com/", "https://meet.google.com/?*", "https://meet.google.com/*-*-*",
    "https://teams.live.com/dl/launcher/*", "https://teams.microsoft.com/dl/launcher/*"
  ]
}
```

**Assessment**: While scoped to meeting platforms, this allows those websites to send messages to the extension. The attack surface identified by ext-analyzer confirms "message data → fetch(${U})" flows from popup.js and onboarding.js. However, this appears to be standard functionality for coordinating with web-based meeting interfaces.

## Technical Analysis

### Data Flow Analysis

The ext-analyzer identified one exfiltration flow:
```
[HIGH] chrome.storage.local.get → fetch(${U})    service-worker.js
```

This flow represents the OAuth token being retrieved from storage and sent to fathom.video servers for authenticated API requests. The domain variable `U="fathom.video"` is defined at the top of the service-worker.

### OAuth Implementation

The extension implements OAuth 2.0 with PKCE (Proof Key for Code Exchange):

```javascript
async function La(){
  let e=To(crypto.randomUUID()),
      t=To(await Pa(e));  // SHA-256 hash
  await chrome.storage.session.set({code_verifier:e,code_challenge:t}),
  await fetch(`https://${U}/api/chrome/v1/oauth2/authorize`,{
    method:"POST",
    headers:{"Content-Type":"application/x-www-form-urlencoded"},
    body:new URLSearchParams({
      client_id:He,
      redirect_uri:`https://${U}/chrome/onboarding/token_callback`,
      response_type:"code",
      scope:"chrome",
      code_challenge:t,
      code_challenge_method:"S256"
    })
  })
}
```

**Assessment**: The OAuth implementation follows security best practices with PKCE, secure token storage, and refresh token rotation. Client ID `He="Ttg_quLK-Q1ylFy9uEJR3rdqWILIoTd2lltJ4qZzfBI"` is hardcoded but this is standard for OAuth public clients.

### Error Tracking

The extension integrates Sentry for error reporting:
- **DSN**: `https://ff7286eeaff2e44d06e6c0c9ce9d4262@o439626.ingest.us.sentry.io/4508281827164160`
- **Environment**: `U="fathom.video"`

This sends error reports to Sentry's US ingestion endpoint, which may include stack traces and user context.

### WASM Detection

The ext-analyzer flagged WASM presence. Analysis shows references to `WebAssembly.Exception` in error handling code, but no actual WASM module was found in the extension package. The flag appears to be a false positive from the Sentry SDK's error handling for WebAssembly exceptions.

## API Endpoints

All endpoints communicate with `fathom.video`:

1. **OAuth Endpoints**:
   - `https://fathom.video/api/chrome/v1/oauth2/authorize` - Authorization initiation
   - `https://fathom.video/api/chrome/v1/oauth2/token` - Token exchange and refresh

2. **Meeting Endpoints**:
   - `https://fathom.video/api/chrome/v1/calls/from_intercepted_uri` - Meeting URL processing

3. **Onboarding**:
   - `https://fathom.video/chrome/onboarding/connect` - Initial connection flow
   - `https://fathom.video/chrome/onboarding/token_callback` - OAuth callback

4. **Error Tracking**:
   - `https://o439626.ingest.us.sentry.io/4508281827164160` - Sentry error ingestion

## Permissions Analysis

### Declared Permissions
- `identity` - Used for `getProfileUserInfo()` to collect email and user ID
- `identity.email` - Grants access to user's email address
- `storage` - Stores OAuth tokens, user preferences
- `webRequest` - Intercepts meeting URLs before page load

### Host Permissions
Broad access to meeting platforms:
- fathom.video (API communication)
- Zoom (all variants: commercial, dev, gov)
- Google Meet
- Microsoft Teams

**Assessment**: Permissions are appropriate for stated functionality but represent significant access to user's meeting activity and identity.

## Privacy Considerations

### Disclosed Data Collection
According to web research, Fathom's privacy policy states:
- HIPAA, GDPR, and SOC2 Type II compliant
- Does not use customer data for AI model training
- Enterprise-grade security practices

### Actual Data Collected (from code analysis)
1. **Identity Data**: Chrome email, Chrome user ID, platform info
2. **Meeting Metadata**: All meeting URLs (Zoom, Meet, Teams)
3. **Usage Telemetry**: Extension version, OS type, architecture
4. **Error Data**: Stack traces and context sent to Sentry

### Data Retention
The code implements token refresh and local storage clearing, but server-side retention of meeting URLs and identity data is not visible in the client code.

## Comparison to Similar Extensions

Meeting assistant extensions typically collect:
- Meeting metadata (URLs, participants) - STANDARD
- User identity for account management - STANDARD
- Audio/video recording access - NOT OBSERVED in this extension

Fathom's approach of URL interception rather than direct media capture suggests it may use a bot-based recording method (joining meetings as a participant) rather than client-side capture.

## Business Model Transparency

The extension's business model is transparent:
- Free tier: Unlimited recordings, 5 AI summaries/month
- Premium: $15-19/user/month
- Enterprise features with CRM integration

The legitimate freemium model explains why data collection is necessary and disclosed.

## Recommendations

### For Users
1. **Understand Data Collection**: This extension sends your email, Chrome ID, and all meeting URLs to Fathom's servers
2. **Review Privacy Policy**: Ensure your organization's compliance requirements align with Fathom's data practices
3. **Meeting Privacy**: Other meeting participants may not know recordings are occurring if Fathom joins as a background bot
4. **Enterprise Use**: Appropriate for disclosed enterprise use; verify compliance requirements (HIPAA, GDPR)

### For Developers
1. **Transparency**: The extension would benefit from more visible privacy notices before first use
2. **Minimize Data**: Consider whether OS/architecture data is necessary for core functionality
3. **Scope Reduction**: The webRequest permission could potentially be scoped more narrowly
4. **Third-party Services**: Document Sentry integration in privacy policy if not already disclosed

## Conclusion

Fathom AI Note Taker is a **legitimate enterprise tool** with appropriate functionality for its stated purpose. The MEDIUM risk classification reflects:

1. **Legitimate Business Purpose**: Meeting recording and transcription
2. **Disclosed Data Collection**: Privacy policy claims compliance with HIPAA/GDPR/SOC2
3. **Significant Data Access**: Collects identity and comprehensive meeting activity logs
4. **Enterprise Context**: Appropriate for business use where data collection is disclosed

**Not Malware**: This is not a malicious extension. The data collection appears necessary for the service and is disclosed in the privacy policy.

**Risk Classification**: MEDIUM due to the scope of personal data collection (email, meeting history) combined with third-party data sharing (Sentry), even though the collection appears disclosed and legitimate.

## Evidence Summary

- **Identity Collection**: ✓ Confirmed (email, Chrome ID sent in every API request)
- **Meeting Monitoring**: ✓ Confirmed (all meeting URLs intercepted and sent to server)
- **OAuth Security**: ✓ Good (PKCE implementation, secure token handling)
- **Data Exfiltration**: ⚠️ Disclosed (meeting URLs sent to fathom.video with user consent)
- **Malicious Intent**: ✗ No evidence (legitimate business model)
- **WASM**: ✗ False positive (Sentry SDK references, no actual WASM module)

## Flag Categories

1. **identity_collection** - Chrome identity API used to collect email and user ID
2. **meeting_monitoring** - webRequest used to intercept all meeting URLs
3. **external_communication** - Data sent to fathom.video and Sentry.io

---

**Analysis Date**: 2026-02-15
**Analyzer Version**: ext-analyzer + manual code review
**Risk Score**: 45/100 (MEDIUM)
