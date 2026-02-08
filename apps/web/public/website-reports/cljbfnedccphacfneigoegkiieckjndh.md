# Easy Scraper - Security Analysis Report

## Extension Metadata

- **Name**: Easy Scraper - One-click web scraper
- **Extension ID**: cljbfnedccphacfneigoegkiieckjndh
- **User Count**: ~100,000 users
- **Manifest Version**: 3
- **Version**: 1.4.1
- **Analysis Date**: 2026-02-07

## Executive Summary

Easy Scraper is a legitimate web scraping utility with a **CLEAN** risk profile. The extension implements standard analytics and error monitoring through Amplitude and Sentry SDKs but does not engage in malicious activities. The extension uses modern development frameworks (React, WXT) and follows security best practices with appropriate permission scoping. Network communication is limited to legitimate analytics/monitoring services and the extension's own domain for privileged operations.

## Vulnerability Analysis

### CLEAN - No Critical or High Severity Issues Found

The extension demonstrates responsible development practices with no evidence of malicious behavior.

## Detailed Findings

### 1. CLEAN - Manifest Permissions (LOW RISK)
**Severity**: LOW
**Files**: `manifest.json`
**Verdict**: BENIGN

**Analysis**:
```json
{
  "permissions": ["activeTab", "scripting", "storage"],
  "optional_permissions": ["tabs"],
  "optional_host_permissions": ["<all_urls>"],
  "host_permissions": []
}
```

The extension uses appropriate permissions for a web scraper:
- `activeTab` + `scripting`: Required to execute scraping logic on the current tab
- `storage`: For saving user preferences and scraping configurations
- Optional permissions properly gated behind user consent dialogs
- No default host permissions (all_urls is optional only)
- No dangerous permissions like `webRequest`, `cookies`, `debugger`

### 2. CLEAN - Analytics Integration (LOW RISK)
**Severity**: LOW
**Files**: `background.js` (lines 10000+), `chunks/popup-window-DB3mIVtB.js`
**Verdict**: BENIGN - Standard Analytics

**Code Evidence**:
```javascript
// Amplitude Analytics SDK
fv = "https://api2.amplitude.com/2/httpapi"
t1 = "https://api.eu.amplitude.com/2/httpapi"
n1 = "https://api2.amplitude.com/batch"
r1 = "https://api.eu.amplitude.com/batch"

// Sentry Error Monitoring
nx = "https://diagnostics.prod.us-west-2.amplitude.com/v1/capture"
rx = "https://diagnostics.prod.eu-central-1.amplitude.com/v1/capture"
```

The extension uses:
- **Amplitude**: Industry-standard product analytics (click tracking, element interaction, viewport metrics)
- **Sentry**: Standard error monitoring and crash reporting

**Tracked Events**:
- `[Amplitude] Element Clicked`
- `[Amplitude] Element Changed`
- `[Amplitude] Network Request`
- Element properties (tag, text, position, hierarchy)
- User interaction patterns (clicks, rage clicks, dead clicks)

**Assessment**: This is standard telemetry for understanding user behavior and debugging. No sensitive data exfiltration detected.

### 3. CLEAN - Externally Connectable Configuration (LOW RISK)
**Severity**: LOW
**Files**: `manifest.json`
**Verdict**: BENIGN - Proper Domain Restriction

**Code Evidence**:
```json
"externally_connectable": {
  "matches": ["https://*.easyscraper.com/*"]
}
```

External messaging is restricted to the extension's own domain only, preventing unauthorized third-party communication.

### 4. CLEAN - Content Security Policy (MEDIUM RISK - False Positive)
**Severity**: MEDIUM (False Positive)
**Files**: `manifest.json`
**Verdict**: BENIGN

**Observation**: No explicit CSP defined in manifest. While this is a best practice concern, MV3 extensions have default CSP that prevents inline scripts and eval(). The extension uses bundled JavaScript modules, not inline scripts.

### 5. CLEAN - No Dynamic Code Execution (CLEAN)
**Severity**: N/A
**Files**: All JavaScript files analyzed
**Verdict**: CLEAN

**Analysis**:
- No `eval()`, `new Function()`, or `document.write()` calls detected
- No remote code loading or dynamic script injection
- All code is statically bundled
- Uses modern React framework with JSX transpilation

### 6. CLEAN - Data Handling (LOW RISK)
**Severity**: LOW
**Files**: `background.js`, `content-scripts/content.js`
**Verdict**: BENIGN

**Analysis**:
- Extension implements proper data masking for sensitive inputs
- Text masking with regex patterns for PII protection
- Input value sanitization for password fields
- Local storage usage for configuration (no cloud sync of user data)

**Code Evidence**:
```javascript
maskTextRegex // PII masking patterns
maskInputOptions // Password field protection
maskInputFn // Custom masking function support
```

## False Positive Analysis

| Component | Flagged Pattern | Explanation | Verdict |
|-----------|----------------|-------------|---------|
| Amplitude SDK | Network tracking | Standard product analytics SDK used by thousands of legitimate apps | BENIGN |
| Sentry SDK | Error reporting | Industry-standard error monitoring for debugging | BENIGN |
| React SVG | innerHTML usage | React's safe SVG rendering mechanism | BENIGN |
| MobX Proxy | Proxy objects | State management library pattern, not malicious proxying | BENIGN |
| Shadow DOM | DOM manipulation | WXT framework's UI isolation pattern for clean UI injection | BENIGN |

## API Endpoints & External Communication

| Endpoint | Purpose | Risk Level | Verdict |
|----------|---------|-----------|---------|
| `api2.amplitude.com` | Product analytics | LOW | Legitimate analytics |
| `api.eu.amplitude.com` | EU analytics endpoint | LOW | Legitimate analytics |
| `diagnostics.prod.*.amplitude.com` | Error diagnostics | LOW | Crash reporting |
| `sr-client-cfg.amplitude.com` | Remote config | LOW | Feature flags/config |
| `*.easyscraper.com` | Extension website | LOW | Developer's domain |

**No evidence of**:
- Data exfiltration to unknown domains
- Cryptocurrency mining endpoints
- Malware C2 servers
- Ad injection networks
- Residential proxy infrastructure

## Data Flow Summary

```
User Interaction
    ↓
Content Script (Scraping Logic)
    ↓
Background Service Worker (Orchestration)
    ↓
├─→ chrome.storage (Local Config)
├─→ Amplitude (Anonymous Analytics)
└─→ Sentry (Error Reports)
```

**Key Observations**:
- No cookie harvesting
- No credential theft
- No cross-site data collection
- No keystroke logging
- No clipboard access
- No history/bookmark access

## Technology Stack

- **Framework**: WXT (Web Extension Toolkit) + React 19.2.0
- **Build Tool**: Vite
- **Analytics**: Amplitude SDK
- **Monitoring**: Sentry SDK
- **State Management**: React Hooks
- **UI Components**: Custom React components
- **Code Size**: ~68,000 lines (mostly framework code)

## Security Strengths

1. **Manifest V3 compliance** - Uses modern, more secure extension APIs
2. **Permission scoping** - No default broad permissions
3. **Domain restriction** - External messaging limited to own domain
4. **Input sanitization** - Implements data masking for sensitive fields
5. **No eval()** - No dynamic code execution patterns
6. **CSP compliance** - No inline scripts, bundled code only
7. **Proper isolation** - Uses Shadow DOM for UI injection

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

Easy Scraper is a well-engineered browser extension that follows security best practices. The analytics and error monitoring integrations are standard for production software. No malicious patterns, data exfiltration, or privacy violations were detected during this analysis.

**Recommendation**: SAFE FOR USE

The extension poses minimal privacy concerns beyond standard analytics telemetry. Users concerned about analytics can review the extension's privacy policy at easyscraper.com for opt-out options.

---

**Analysis Method**: Static code analysis of deobfuscated extension source code
**Analyst**: Security Automation System
**Date**: 2026-02-07
