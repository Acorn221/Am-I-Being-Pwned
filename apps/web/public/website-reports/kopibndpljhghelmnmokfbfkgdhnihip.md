# Vulnerability Report: Record to Slides

## Metadata
- **Extension ID**: kopibndpljhghelmnmokfbfkgdhnihip
- **Extension Name**: Record to Slides
- **Version**: 1.0.21
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Record to Slides is a legitimate Google Workspace extension that allows users to record video and audio content and automatically embed it into Google Slides, Forms, or Google Classroom. The extension uses proper OAuth2 authentication with Google's identity APIs and uploads recordings to Google Drive using resumable upload protocols. The extension's core functionality is aligned with its stated purpose, and data flows are appropriate for a productivity tool in the Google Workspace ecosystem.

One minor privacy concern exists: the extension sends user email addresses to an external service (`us-central1-claycodes.cloudfunctions.net`) to check subscription status. This behavior is disclosed in the context of a premium/subscription feature toggle but represents external data collection beyond Google's services.

## Vulnerability Details

### 1. LOW: External Subscription Service Data Collection

**Severity**: LOW
**Files**: background.js (lines 302-314), contentscript.js (line 57)
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension collects user email addresses and sends them to an external Firebase Cloud Function endpoint to verify subscription status. While this is for legitimate functionality (premium feature access), it represents data exfiltration to a third party beyond Google's ecosystem.

**Evidence**:
```javascript
// background.js lines 302-314
async function subscription(request) {
    request.body = { email: request.email, subscription: request.subscription }
    let options = {
        method: 'POST',
        headers: {
            'Access-Control-Allow-Headers': '*'
        },
        body: JSON.stringify(request.body)
    }
    let url = `https://us-central1-claycodes.cloudfunctions.net/usersubscription`
    var sub = await fetchRetry(url, options)
    return sub
}
```

```javascript
// contentscript.js line 57
$.get("https://ipinfo.io", function (res) {
    var data = { type: 'categories', country: res.country }
    chrome.runtime.sendMessage(data);
}, "json");
```

**Verdict**: This is a legitimate premium feature implementation. The extension collects email to validate subscription status with a backend service, which is standard practice for subscription-based extensions. The ipinfo.io call is used to fetch country codes for YouTube category localization, which is reasonable for a tool that can upload to YouTube. The data collection is relatively minimal and purpose-appropriate.

## False Positives Analysis

The static analyzer flagged an "exfiltration flow" from `chrome.storage.sync.get → fetch`, which is actually the legitimate subscription check described above. This is not malicious data exfiltration but rather a documented premium feature mechanism.

The analyzer also flagged "obfuscated" code, but examination of the deobfuscated files shows this is standard minified library code (jQuery, Materialize CSS, adapter.js for WebRTC) rather than deliberately malicious obfuscation.

The "message data → fetch" attack surface finding refers to the content script sending recording data to the background script, which then uploads to Google Drive - this is the core intended functionality of the extension.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.googleapis.com | Google Drive API, OAuth, About API | OAuth tokens, file metadata, recordings | Low - legitimate Google API usage |
| script.googleapis.com | Google Apps Script execution | Video metadata, slide URLs, user domain | Low - executes Apps Script to embed videos |
| us-central1-claycodes.cloudfunctions.net | Subscription verification | User email, subscription product ID | Low - premium feature validation |
| ipinfo.io | Geolocation for YouTube categories | IP address (implicit) | Low - country code for localization |
| fonts.googleapis.com | Material Icons font | None | None - static resource |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
This extension performs its stated function (recording and uploading video to Google Workspace apps) using appropriate Google APIs with proper OAuth scopes. The OAuth scopes requested (Drive, Presentations, YouTube, Forms, Classroom) directly correspond to the advertised features. The resumable upload implementation is a standard open-source library (tanaikech/ResumableUploadForGoogleDrive_js).

The only concern is the external subscription service, but this is:
1. Limited to email addresses and subscription status
2. Used for a clear purpose (premium feature gating)
3. Relatively standard for freemium extensions
4. Not hidden or obfuscated

The extension does not exhibit credential harvesting, hidden data exfiltration, session hijacking, or other malicious behaviors. The user count of 100,000+ users and presence in the Chrome Web Store suggests this is a legitimate productivity tool with a sustainable business model (freemium subscription).

**Recommendation**: CLEAN for core functionality, LOW risk due to minor external data sharing for subscription management.
