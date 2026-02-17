# Vulnerability Report: e-Dnevnik Plus

## Metadata
- **Extension ID**: bcnccmamhmcabokipgjechdeealcmdbe
- **Extension Name**: e-Dnevnik Plus
- **Version**: 5.2.0.1
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

e-Dnevnik Plus is an educational extension for Croatian students and parents that enhances the official e-Dnevnik (e-Diary) school platform. The extension provides two modes: a "Plus App" that redirects users to an enhanced interface, and a "Plus Classic" mode that augments the original platform. It includes features like grade calculators, auto-login, and displays targeted ads fetched from Firebase.

The extension uses Google Analytics for telemetry collection and Firebase Realtime Database for remote ad configuration. While the static analyzer flagged potential exfiltration flows, analysis confirms these are legitimate: Google Analytics telemetry and requests to www.carnet.hr (the official Croatian education network). The extension has overly broad host permissions (`*://*/*`) but only operates on ocjene.skole.hr domains and performs its stated educational functions without undisclosed data collection.

## Vulnerability Details

### 1. LOW: Overly Broad Host Permissions
**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension requests `*://*/*` host permissions but only operates on `ocjene.skole.hr` domains. This violates the principle of least privilege.

**Evidence**:
```json
"host_permissions": [
  "*://*/*"
]
```

Content scripts only run on specific domains:
```json
"content_scripts": [
  {
    "matches": ["*://ocjene.skole.hr/*"]
  }
]
```

**Verdict**: The broad permissions are unnecessary but not actively exploited. The extension only injects content scripts on the education platform domains. This is a poor practice but poses limited security risk since the actual functionality is properly scoped.

## False Positives Analysis

### Static Analyzer Exfiltration Flows
The ext-analyzer flagged two HIGH severity exfiltration flows involving `fetch(www.carnet.hr)`:

1. **chrome.storage.sync.get → fetch(www.carnet.hr)**: This is a false positive. Analysis shows no actual requests to www.carnet.hr in the codebase. The only reference is a static link to the official Carnet documentation page:
```javascript
href: "https://www.carnet.hr/usluga/e-dnevnik-za-ucenike-i-roditelje/"
```

2. **document.getElementById → fetch(www.carnet.hr)**: Also a false positive from the same static link reference.

### Google Analytics Telemetry
The extension implements Google Analytics 4 Measurement Protocol for usage tracking. This is disclosed in the privacy policy and is standard practice:

```javascript
const GA_ENDPOINT = "https://www.google-analytics.com/mp/collect";
const MEASUREMENT_ID = "G-YM0ZN005N7";
```

Events tracked include:
- Extension install/update events
- Page views with school name and class year
- Ad view and click events
- Error events

Data collected is limited to:
- Hashed user ID (SHA-256 of username without domain)
- Session data (timing, engagement)
- Page URLs and event parameters
- School type (elementary vs secondary) and class year

### Remote Ad Configuration
The extension fetches ad configuration from Firebase Realtime Database:
```javascript
const ADS_SOURCE_ENDPOINT = "https://e-dnevnik-plus.firebaseio.com/";
const ADS_FILE = "ogl-classic.json";
```

Ads are targeted based on:
- User type (elementary vs secondary school student)
- Class year
- School name
- Previous grades
- Subject grades

This is a legitimate feature for an education-focused extension and ads are displayed transparently in the UI.

### Auto-Login Feature
The extension offers an opt-in "stay logged in" feature that stores credentials in `chrome.storage.sync`:

```javascript
const login = {
  username: usernameEl.value.trim(),
  password: passwordEl.value,
};
const userId = await getSHA256Hash(login.username.replace(/@.*/, ""));
chrome.storage.sync.set({ login, userId });
```

While storing passwords in sync storage is not ideal security practice, this is:
1. User-initiated via checkbox consent
2. Encrypted in transit by Chrome's sync mechanism
3. Only accessible to the extension itself
4. Standard practice for auto-login extensions

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.google-analytics.com | Usage telemetry | Hashed user ID, events, page views, school metadata | Low - disclosed analytics |
| e-dnevnik-plus.firebaseio.com | Fetch ad configuration | None (GET request) | Low - remote config only |
| ocjene.skole.hr | Official school platform | Login credentials (user-initiated), platform interaction | Low - legitimate platform |
| ednevnik.plus | Extension website | Uninstall tracking, install/update notifications | Low - informational |
| www.carnet.hr | Documentation link | None (static href only) | None - not actually contacted |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

e-Dnevnik Plus is a legitimate educational tool that enhances the Croatian e-Dnevnik platform with grade calculators, auto-login, and a modernized interface. The extension operates transparently within its stated purpose.

**Positives**:
- Clean, well-structured code (TypeScript compiled to JavaScript)
- Implements standard Google Analytics following official Chrome extension guidelines
- Remote ad configuration is targeted but transparent
- Only operates on the intended education platform domains
- No credential theft or hidden exfiltration
- Hashes usernames before analytics collection (privacy-preserving)

**Concerns**:
- Overly broad `*://*/*` host permissions (should be scoped to `*://ocjene.skole.hr/*`)
- Stores plaintext passwords in sync storage for auto-login feature (not ideal but common practice)
- Remote ad configuration could theoretically be abused if Firebase account compromised

**Overall**: The extension performs its stated educational functions without malicious behavior. The LOW risk rating reflects the overly broad permissions and password storage practice, but these do not constitute active security vulnerabilities. The static analyzer's exfiltration warnings are false positives from legitimate analytics and static documentation links.
