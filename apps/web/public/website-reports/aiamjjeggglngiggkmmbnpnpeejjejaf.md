# Vulnerability Report: Read AI

## Metadata
- **Extension ID**: aiamjjeggglngiggkmmbnpnpeejjejaf
- **Extension Name**: Read AI
- **Version**: 0.12.1
- **Users**: ~300,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-14

## Executive Summary

Read AI is a legitimate meeting productivity extension that provides AI-powered meeting summaries, calendar integration, and transcript analysis for Google Meet, Zoom, Microsoft Teams, and other video conferencing platforms. The extension integrates with read.ai's cloud service to provide meeting intelligence features.

The extension uses standard analytics tracking (Google Analytics 4 and Mixpanel) to monitor usage patterns, employs Statsig for A/B testing and feature flags, and uses Sentry for error reporting. All data flows are proportionate to the extension's stated functionality as a meeting AI assistant. The three exfiltration flows flagged by static analysis represent legitimate API communications: syncing user preferences to read.ai servers and sending anonymized analytics data.

**Overall Assessment**: The extension follows Chrome extension best practices with MV3 architecture, uses optional permissions appropriately (requesting only when features are activated), and maintains data collection practices typical of modern SaaS meeting tools. No malicious behavior, credential harvesting, or unauthorized data exfiltration was detected.

## Vulnerability Details

### 1. LOW: Extensive Analytics Tracking Without Explicit Consent UI
**Severity**: LOW
**Files**: background.js (lines 16483, 43167-43193, 43240-43258), content-main.js
**CWE**: CWE-359 (Exposure of Private Information)

**Description**: The extension collects usage analytics through three services (Google Analytics, Mixpanel, Statsig) without presenting an explicit consent dialog on first install. While this is common practice for productivity extensions and the data collection appears limited to usage telemetry, users may not be fully aware of the tracking scope.

**Evidence**:
```javascript
// background.js:16483 - Google Analytics
return fetch(`https://www.google-analytics.com/mp/collect?measurement_id=${Config$2.ga.ID}&api_secret=${Config$2.ga.API_ID}`, {
  method: "POST",
  body: JSON.stringify({
    client_id: clientId,
    user_id: `${userId}`,
    events: [{
      name: eventName,
      params: params ? snakeKeys(params) : {}
    }]
  })
});

// background.js:43193 - Mixpanel tracking
fetch(`${this.apiHost ?? Config$2.tracking.MIXPANEL_HOST}/track`, options);

// background.js:43258 - Mixpanel user properties
fetch(`${this.apiHost ?? Config$2.tracking.MIXPANEL_HOST}/engage`, options);
```

**Analysis**:
- Google Analytics uses a randomly-generated client ID stored in `chrome.storage.sync` (not personally identifiable without user ID linkage)
- Mixpanel uses a device ID (`crypto.randomUUID()`) stored in `chrome.storage.local`
- The extension calls `backgroundTracker.event()` for actions like permission grants, API host changes, and feature usage
- Data sent includes event names, timestamps, extension version, and context parameters (e.g., `chrome.runtime.getManifest().version`)
- No evidence of sensitive data (passwords, email content, browsing history outside meetings) being transmitted
- Tracking can be disabled via browser Do Not Track settings (code checks `navigator.doNotTrack`)

**Verdict**: Standard practice for productivity SaaS extensions. The analytics serve legitimate product improvement purposes and don't collect sensitive personal data beyond what users voluntarily provide through the Read AI service. Privacy policy disclosure (referenced in code: `releaseDates.privacyPolicy: "03/26/2024"`) should cover this tracking.

## False Positives Analysis

| Pattern | Static Analysis Flag | Actual Behavior | Risk Level |
|---------|---------------------|-----------------|------------|
| `chrome.storage.sync.get` → `fetch` | HIGH (Exfiltration) | Syncing user preferences (API host, settings) to read.ai backend for cross-device consistency | **False Positive** - Expected SaaS behavior |
| `chrome.storage.local.get` → `fetch(www.google-analytics.com)` | HIGH (Exfiltration) | Retrieving anonymized analytics IDs to track usage events | **False Positive** - Standard analytics |
| WASM flag | WASM presence | No WASM files found in extension package; flag is incorrect | **False Positive** - Misdetection |
| Obfuscation flag | Code complexity | React/Babel bundled production build, not malicious obfuscation | **False Positive** - Normal toolchain output |
| `chrome.scripting.registerContentScripts` | Dynamic injection | Registering content scripts only after user grants `<all_urls>` + `scripting` optional permissions | **False Positive** - Permission-gated feature |

## API Endpoints Analysis

| Endpoint | Purpose | Data Transmitted | Risk Assessment |
|----------|---------|------------------|-----------------|
| `api.read.ai` | Primary API | Meeting metadata, user settings, calendar events, authentication tokens | **LOW** - Required for core functionality |
| `recordings.read.ai` | Meeting recordings | Audio/video from meetings user has joined with bot | **LOW** - User-initiated feature |
| `app.read.ai` | Web app frontend | Session cookies, redirect URLs | **LOW** - Legitimate service domain |
| `moxy.read.ai` | Mixpanel proxy | Usage analytics events (event names, timestamps, user IDs) | **LOW** - Standard product analytics |
| `www.google-analytics.com` | GA4 analytics | Page views, events, client ID, session data | **LOW** - Industry-standard tracking |
| `api.statsigcdn.com` | Feature flags | User ID, A/B test assignments | **LOW** - Experimentation platform |
| `o992397.ingest.sentry.io` | Error reporting | Stack traces, error messages, browser metadata | **LOW** - Debugging/monitoring |
| `app-backend.infra.read.ai` | Internal API | Same as primary API | **LOW** - Infrastructure routing |

## Data Flow Summary

1. **Authentication Flow**: Extension checks for `readAccessToken` cookie on `*.read.ai` domains, uses it to authenticate API requests (background.js:43799-43836)

2. **Settings Sync**: User preferences stored in `chrome.storage.sync` are periodically synced to read.ai backend to maintain consistency across devices (background.js:39588, chunks/package-BIwlnbC4.js:63840)

3. **Analytics Flow**:
   - User actions trigger `backgroundTracker.event()` calls
   - Events batched and sent to Mixpanel proxy (moxy.read.ai)
   - GA4 events sent for install/uninstall tracking
   - Device IDs generated locally, never linked to PII without user login

4. **Meeting Data**: When user joins meeting with Read AI bot, extension facilitates communication between web conferencing UI and read.ai backend to retrieve/display summaries

5. **Content Script Injection**: After user grants `<all_urls>` optional permission, extension registers content scripts to inject meeting controls on all pages (background.js:43545-43552, 43838-43859)

6. **Optional Permission Usage**:
   - `history`: Only accessed during internal testing (evaluateHistory function, never called in production)
   - `tabs`: Query active tab URL to detect meeting pages
   - `scripting`: Inject content scripts after explicit permission grant
   - `contextMenus`: Add Read AI actions to right-click menu
   - `notifications`: Display meeting reminders/summaries

## Manifest Analysis

### Required Permissions
- **`cookies`**: Read read.ai authentication tokens to maintain login state. Legitimate use for session management.
- **`storage`**: Store user preferences, API configuration, analytics IDs. Standard practice.
- **`alarms`**: Schedule periodic tasks (e.g., checking for upcoming meetings). Appropriate for calendar integration.

### Host Permissions
- **`*://*.read.ai/*`**: Access read.ai web app domains for authentication and API calls. Required for core functionality.

### Optional Permissions (Requested on Demand)
- **`<all_urls>`**: Inject content scripts on meeting platforms beyond Google Meet/Calendar. Only activated when user enables "all-sites" mode.
- **`activeTab`**: Access current tab when user clicks extension icon. Standard popup interaction.
- **`contextMenus`**: Add right-click menu items for quick actions.
- **`history`**: **UNUSED IN PRODUCTION** - Only appears in test code (evaluateHistory function at line 43616-43630 is never invoked).
- **`notifications`**: Show meeting reminders. Gated behind permission check (43638-43646).
- **`scripting`**: Dynamically inject content scripts after permission grant. Used responsibly with explicit user action.
- **`tabs`**: Query active tabs to detect meeting URLs. Minimal permission for feature detection.

### Content Scripts
Runs on `calendar.google.com`, `meet.google.com`, and `read.ai` domains at `document_start`. Loads main React app (content-main.js) which provides meeting controls UI.

### Web Accessible Resources
Exposes fonts, CSS, tutorial images, and main content script to web pages. Standard for injected UI components. No executable code exposed beyond necessary content scripts.

## Hardcoded Credentials Analysis

**No sensitive hardcoded credentials found.** The following keys are present but not security concerns:

- **Google Analytics ID** (`G-2Y1H5ZJMBK`) + API Secret: Public tracking IDs, not authentication credentials. Standard practice to embed in client code.
- **Mixpanel Project ID** (`68e743b21f2eb5cbbfd12657136457ad`): Public project token, not a secret key. Mixpanel projects are designed for client-side use.
- **Statsig Client Key** (`client-5rDNQDOcT7Yt6ZTWHVfNzpkY1kHdmfijSlRx83EYj9e`): Prefixed with `client-` indicating it's a client-side SDK key (not server secret). Safe to expose.
- **Sentry DSN** (`https://db61230961b34c97bb5e811a937e0625@o992397.ingest.sentry.io/...`): Public error reporting endpoint. DSN is intended to be client-accessible.
- **Zendesk Key** (`11845bde-7c74-4711-9e4f-60ced041f56b`): Support widget identifier, not an API key.

All API keys follow best practices: client SDKs use public keys, server-side secrets are never exposed.

## Code Execution Risks

**No dynamic code execution vulnerabilities detected:**

- `eval()`: Not used
- `new Function()`: Not used
- `chrome.scripting.executeScript()`: Not used
- Content scripts are static (pre-packaged .js files), not dynamically generated
- CSP (Content Security Policy) not weakened in manifest

The extension uses `chrome.scripting.registerContentScripts()` (line 43545) to inject pre-built content scripts, which is a safe MV3 pattern. Scripts are only injected after user grants `<all_urls>` permission.

## Third-Party Dependencies

All third-party code is bundled and vendored (React, Luxon date library, Statsig SDK, Mixpanel SDK). No runtime loading of external scripts. Dependencies appear to be standard npm packages compiled into production bundles.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
1. **Legitimate Business Purpose**: Extension provides documented meeting AI features that require cloud processing
2. **Proportionate Data Collection**: Only collects data necessary for meeting summaries, calendar integration, and product analytics
3. **Transparent Permissions**: Uses MV3 optional permissions pattern, requesting broad access only when user activates advanced features
4. **No Malicious Patterns**: No credential harvesting, no unauthorized data exfiltration, no code execution vulnerabilities
5. **Standard Analytics**: GA/Mixpanel usage is typical for SaaS products; anonymized IDs used before user login
6. **Secure Architecture**: Follows Chrome extension best practices (MV3, CSP, no eval, service worker background)

**Recommendations for Users**:
- Review optional permissions before granting `<all_urls>` access
- Be aware that usage analytics are collected (can disable via browser Do Not Track settings)
- Understand that meeting transcripts/summaries are processed on read.ai servers (cloud AI service)

**Recommendations for Developers**:
- Add explicit analytics consent UI on first install
- Document data retention policies for meeting recordings
- Consider removing unused `history` permission from manifest
- Provide user-facing toggle to disable analytics in extension settings
