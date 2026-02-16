# Vulnerability Report: Toolbox for Google Play Store™

## Metadata
- **Extension ID**: fepaalfjfchbdianlgginbmpeeacahoo
- **Extension Name**: Toolbox for Google Play Store™
- **Version**: 3.0.2
- **Users**: Unknown (not available from CWS API)
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Toolbox for Google Play Store™ is a legitimate browser extension developed by APKMirror that enhances the Google Play Store interface with various features. The extension adds buttons to navigate to third-party app information sites (APKMirror, AppBrain, Android Police), provides beta program information, and includes UI enhancements like improved screenshot galleries and language/region switching dropdowns.

The extension has been thoroughly analyzed using static code analysis and manual code review. While ext-analyzer flagged one exfiltration flow involving chrome.storage.sync.get → fetch(www.apkmirror.com), this is a legitimate and documented feature: the extension sends app package names to APKMirror's API to check if apps are available on their platform. This behavior is clearly disclosed in the extension's privacy policy within the settings page, and users can disable it entirely. No security or privacy vulnerabilities were identified.

## Vulnerability Details

No vulnerabilities found.

## False Positives Analysis

### APKMirror API Communication (Flagged by ext-analyzer)

**Files**: js/background.js, js/toolbox.js

**Why it was flagged**: The static analyzer detected a data flow from chrome.storage.sync.get (which could contain sensitive data) to a fetch() call to www.apkmirror.com. This pattern matches typical data exfiltration behavior.

**Why it's a false positive**:

1. **Limited scope**: The extension only sends app package names (e.g., "com.google.android.apps.maps") to APKMirror's API endpoint at https://www.apkmirror.com/wp-json/apkm/v1/app_exists/. No user data, browsing history, or cookies are transmitted.

2. **Documented behavior**: The privacy policy in settings.html explicitly states: "The only time Toolbox communicates with another service is when checking if a given app has been uploaded to APKMirror.com. Only the app's package name (e.g., com.google.android.apps.maps) is sent to the site."

3. **User control**: Users can completely disable this feature by turning off the "APKMirror button" setting, which stops all communication with external services.

4. **Legitimate use case**: The extension's stated purpose includes providing quick links to APKMirror for app downloads. Checking whether apps exist on APKMirror is core functionality, not malicious data collection.

5. **Code review confirms**: Manual inspection of background.js lines 74-110 shows the extension only sends the app package names in a POST request with hardcoded API credentials. The response is used solely to display whether an app is available on APKMirror.

### Cookie Access

**Why it's legitimate**: The extension checks for the APKMirror login cookie (wordpress_logged_in_2fa_auth_time) only to determine whether to show an "app listing" button feature for logged-in APKMirror users. The cookie value is not transmitted anywhere - it's used only for local feature toggling (background.js lines 11-40).

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.apkmirror.com/wp-json/apkm/v1/app_exists/ | Check if apps exist on APKMirror | App package names (array) | None - documented, legitimate, user-controllable |
| play.google.com/apps/testing/* | Check beta program status | None (GET request) | None - standard Play Store functionality |

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:

This extension exhibits no security or privacy vulnerabilities. All network communications are limited to the extension's documented functionality:

1. **Transparent data handling**: The extension clearly discloses what data it sends (only app package names) and to whom (APKMirror.com) in its privacy policy.

2. **Minimal permissions**: The extension requests only the permissions necessary for its features:
   - `storage`: For user preferences and API response caching
   - `cookies`: Only to check if user is logged into APKMirror (value not transmitted)
   - Host permissions limited to play.google.com and www.apkmirror.com

3. **No hidden behavior**: All code is straightforward and matches the extension's stated purpose. No obfuscation, no hidden data collection, no undisclosed third-party services.

4. **User control**: All features can be toggled on/off in settings, including the APKMirror integration that involves external communication.

5. **Open source**: The extension links to its public GitHub repository (https://github.com/android-police/toolbox-for-google-play-store-public/issues) for bug reports and feature requests, demonstrating transparency.

6. **Reputable developer**: Published by APKMirror, a well-known Android app repository site owned by Android Police, a established technology news outlet.

The extension serves its stated purpose as a Play Store enhancement tool without engaging in any data collection or privacy-invasive practices beyond what is necessary and disclosed. The ext-analyzer flag was a false positive resulting from legitimate API communication patterns.
