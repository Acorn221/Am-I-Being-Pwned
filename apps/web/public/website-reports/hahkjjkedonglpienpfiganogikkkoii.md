# Vulnerability Report: Play HLS

## Metadata
- **Extension ID**: hahkjjkedonglpienpfiganogikkkoii
- **Extension Name**: Play HLS
- **Version**: 1.7
- **Users**: Unknown
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

Play HLS is an extension that allows users to play HLS (HTTP Live Streaming) video content directly in the browser. The extension intercepts .m3u8 playlist URLs and redirects them to a custom player page. However, the extension includes functionality to fetch authentication tokens from a third-party server (totsacademy.in) and manipulate HTTP headers to bypass DRM protections on streaming services like Hotstar and JioTV. This constitutes a MEDIUM risk due to unauthorized access mechanisms and potential terms of service violations.

The extension modifies request headers (User-Agent, X-Forwarded-For, Origin, Referer) to circumvent geo-restrictions and authentication checks. While not malicious in the traditional sense, this behavior facilitates unauthorized access to premium content and may expose users to legal risks.

## Vulnerability Details

### 1. MEDIUM: Third-Party Authentication Token Fetching

**Severity**: MEDIUM
**Files**: h0t.js
**CWE**: CWE-912 (Hidden Functionality)
**Description**: The extension fetches authentication tokens from an external third-party server (totsacademy.in) to access Hotstar's API. This enables users to bypass Hotstar's authentication and access premium content without proper authorization.

**Evidence**:
```javascript
fetch("https://www.totsacademy.in/hotstarauth.php")
  .then(r => r.text())
  .then(token => {
    fetch(
      `https://api.hotstar.com/h/v2/play/us/contents/${contentId}?...`,
      {
        headers: {
          hotstarauth: token
        }
      }
    )
```

**Verdict**: This functionality is designed to circumvent Hotstar's authentication system. The use of third-party tokens violates Hotstar's terms of service and potentially copyright laws. Users may unknowingly participate in content piracy.

### 2. MEDIUM: HTTP Header Manipulation for DRM Bypass

**Severity**: MEDIUM
**Files**: event.js
**CWE**: CWE-441 (Unintended Proxy or Intermediary)
**Description**: The extension uses webRequest API to modify HTTP headers on requests to streaming services, including User-Agent spoofing, X-Forwarded-For injection, and Referer manipulation. This is specifically designed to bypass geo-restrictions and DRM checks.

**Evidence**:
```javascript
if (info.url.indexOf("jio.com") > -1) {
  info.requestHeaders = info.requestHeaders.map((i) => {
    if (i.name.toLowerCase() == "user-agent") {
      i.value = "JioTV/537.36 (KAIOS, like Gecko) ExoPlayer";
    }
    return i;
  });
  info.requestHeaders.push({
    name: "X-Forwarded-For",
    value: "49.40.8.179",
  });
}
```

**Verdict**: The extension actively spoofs device identifiers and IP addresses to bypass JioTV's platform restrictions. This violates the service's terms of use and potentially copyright laws. The hardcoded IP address suggests specific geographic targeting to bypass regional restrictions.

### 3. LOW: Overly Broad URL Pattern Matching

**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-272 (Least Privilege Violation)
**Description**: The extension uses very broad URL patterns (`*://*/*m3u8*`, `*://*/*.ts*`) that match more than necessary for its core functionality.

**Evidence**:
```json
"permissions": [
  "*://*/*m3u8*",
  "*://*/*.ts*",
  "webRequest",
  "webRequestBlocking"
]
```

**Verdict**: While these patterns are reasonable for an HLS player, the TypeScript file pattern (`*.ts*`) is overly broad and could match unintended files. However, this is a minor issue since the extension only intercepts main_frame requests for m3u8 files.

## False Positives Analysis

The static analyzer flagged the extension as "obfuscated" - this appears to be due to the minified hls.min.js library (hls.js video player library), which is a standard legitimate dependency and not actual obfuscation. The core extension code (event.js, content.js, h0t.js, player.js) is clean and readable.

The "remote_config" flag is appropriate here since the extension fetches authentication tokens from a remote server, though this is the problematic behavior rather than a false positive.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.totsacademy.in/hotstarauth.php | Fetch authentication token | None (GET request) | HIGH - Third-party authentication bypass |
| api.hotstar.com/h/v2/play/us/contents/{id} | Retrieve video stream URLs | Content ID, device fingerprint | MEDIUM - Uses unauthorized tokens |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

While this extension is not traditional malware, it facilitates unauthorized access to premium streaming content through two mechanisms:

1. **Third-party authentication token fetching** - The extension relies on an external server to provide valid Hotstar authentication tokens, enabling users to access content without proper subscription.

2. **Header manipulation for DRM bypass** - Active spoofing of device identifiers and IP addresses to circumvent platform restrictions on JioTV and Hotstar.

The extension does not exfiltrate user data, install backdoors, or perform malicious actions against the user. However, it does:
- Violate streaming services' terms of service
- Potentially facilitate copyright infringement
- Expose users to legal risks
- Rely on third-party infrastructure that could be compromised

This constitutes a MEDIUM risk rather than HIGH because:
- The functionality is disclosed in the extension name/description (HLS player)
- No user data is harvested or exfiltrated
- No credential theft or account compromise mechanisms
- The DRM bypass is targeted at specific services the user is already accessing

However, users should be aware they may be violating terms of service and potentially copyright laws by using this extension.
