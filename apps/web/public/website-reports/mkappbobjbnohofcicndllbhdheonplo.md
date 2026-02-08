# Security Analysis Report: Vpn Test

## Extension Metadata
- **Extension ID**: mkappbobjbnohofcicndllbhdheonplo
- **Name**: Vpn Test
- **Version**: 2.0.0
- **Manifest Version**: 3
- **User Count**: ~0 users
- **Analysis Date**: 2026-02-08

## Executive Summary

**Vpn Test** is a legitimate IP geolocation checker tool that monitors the user's public IP address and displays country information. Despite its name, this extension does **NOT** provide actual VPN functionality. The extension is minimal, uses limited permissions, and shows no signs of malicious behavior.

**Overall Risk Assessment: LOW**

The extension performs its stated functionality (IP geolocation lookup) without collecting sensitive data, injecting ads, or engaging in deceptive practices. However, the misleading name "VPN Test" could confuse users into thinking it provides VPN services when it only checks IP geolocation.

## Key Findings

### Positive Indicators
- Minimal permissions (only `notifications`, `alarms`)
- No host permissions requested
- No use of dynamic code execution (eval, Function)
- No cookie harvesting or keylogging
- No ad injection or affiliate fraud mechanisms
- Uses reputable third-party geolocation APIs
- Clean manifest with proper CSP defaults

### Concerns
- **Misleading naming**: "VPN Test" implies VPN functionality but only provides IP lookups
- **Third-party API dependencies**: Relies on external services (ipwhois.app, api.extractip.com)
- **Automatic clipboard access**: Copies IP address to clipboard without explicit user action (minor privacy concern)

## Detailed Analysis

### 1. Manifest Analysis

**File**: `/deobfuscated/manifest.json`

**Permissions**:
- `notifications` - Used to notify users when IP is copied to clipboard
- `alarms` - Used to periodically check IP address changes (every 1 minute)

**Content Scripts**:
- Runs on `<all_urls>` but only provides IP lookup widget functionality
- Injects `content.js` and `style.css`

**Content Security Policy**: Default MV3 CSP (secure)

**Web Accessible Resources**: Flag images and VPN icons (benign)

**Verdict**: ✅ CLEAN - Minimal permissions appropriate for stated functionality

---

### 2. Background Script Analysis

**File**: `/deobfuscated/background.js`

**Network Endpoints**:
- `https://ipwhois.app/json/` - Primary IP geolocation API
- `https://api.extractip.com/geolocate` - Fallback geolocation API
- `https://vpn-test.ovh/welcome/welcome.html` - Install page
- `https://vpn-test.ovh/delete/delete.html` - Uninstall page

**Behavior**:
1. **Periodic IP Checking**: Sets up 1-minute alarm to check IP geolocation
2. **Country Change Detection**: Monitors for country code changes and displays warning badge
3. **API Calls**: Fetches IP data from ipwhois.app (primary) with extractip.com fallback
4. **Install/Uninstall Handlers**: Opens welcome/delete pages on extension lifecycle events

**Chrome API Usage**:
- `chrome.alarms` - Periodic IP checking
- `chrome.action.setBadgeText/setBadgeBackgroundColor` - Visual warnings
- `chrome.tabs.create` - Opens welcome page on install
- `chrome.runtime.setUninstallURL` - Sets uninstall survey
- `chrome.runtime.onMessage` - Message handling for popup/content script

**Verdict**: ✅ CLEAN - Standard utility extension behavior, no malicious patterns

---

### 3. Content Script Analysis

**File**: `/deobfuscated/content.js`

**Functionality**:
1. **IP Selection Detection**: Listens for text selection and validates if it's an IP address
2. **Lookup Widget Injection**: Shows "Lookup" button near selected IP addresses
3. **IP Resolution**: Sends selected IP to background script for geolocation lookup
4. **Result Display**: Shows country and flag for resolved IP

**DOM Manipulation**:
- Creates lookup widget dynamically (`div#lookup-widget`)
- Injects flag images and country names
- No modification of existing page content

**Data Collection**: None - only processes user-selected text locally

**Verdict**: ✅ CLEAN - Legitimate IP lookup tool, no privacy violations

---

### 4. Popup Analysis

**Files**: `/deobfuscated/popup.html`, `/deobfuscated/popup.js`

**Functionality**:
1. **Auto IP Detection**: Automatically fetches user's current IP on popup open
2. **Clipboard Copy**: Copies IP address to clipboard and shows notification
3. **Geolocation Alert**: Displays warning if country has changed
4. **Rating System**: Links to Chrome Web Store reviews and feedback form

**External Dependencies**:
- `https://cdn.jsdelivr.net/gh/lipis/flag-icons@7.0.0/css/flag-icons.min.css` - Flag icon CSS

**Potential Issues**:
- **Automatic Clipboard Write**: Copies IP to clipboard without explicit user action (line 9 in popup.js)
- This could be considered intrusive but is likely intended as a convenience feature

**Verdict**: ⚠️ MINOR CONCERN - Auto clipboard copy is slightly intrusive but not malicious

---

### 5. Privacy Analysis

**Data Collection**:
- No personal data collection
- No tracking pixels or analytics
- No cookies accessed

**Third-Party Data Sharing**:
- IP address sent to ipwhois.app and api.extractip.com for geolocation
- This is inherent to the extension's functionality
- Both are legitimate geolocation services

**User Consent**: Users implicitly consent by installing an IP lookup tool

**Verdict**: ✅ ACCEPTABLE - Minimal data sharing necessary for functionality

---

### 6. Network Traffic Analysis

**Outbound Requests**:
1. `GET https://ipwhois.app/json/{ip}` - IP geolocation lookup
2. `GET https://api.extractip.com/geolocate/{ip}` - Fallback geolocation
3. `GET https://cdn.jsdelivr.net/gh/lipis/flag-icons@7.0.0/css/flag-icons.min.css` - Flag icons

**Request Headers**: Standard fetch() requests, no custom authentication or tracking headers

**Frequency**: Every 60 seconds via alarm for background checks

**Verdict**: ✅ CLEAN - Legitimate API calls, no data exfiltration

---

### 7. Code Quality & Obfuscation

**Obfuscation Level**: Minified but not intentionally obfuscated
- Variable names shortened (e.g., `a`, `e`, `n`)
- Likely output from bundler/minifier (webpack, rollup, etc.)

**Dynamic Code**: None detected
- No `eval()`
- No `Function()` constructor
- No `setTimeout/setInterval` with string arguments

**Verdict**: ✅ CLEAN - Standard production build minification

---

## Vulnerability Assessment

### Critical Vulnerabilities
**Count**: 0

None identified.

---

### High Vulnerabilities
**Count**: 0

None identified.

---

### Medium Vulnerabilities
**Count**: 0

None identified.

---

### Low Vulnerabilities
**Count**: 1

#### L1: Automatic Clipboard Write Without Explicit User Action
- **Severity**: LOW
- **File**: `popup.js` (lines 9-15)
- **Description**: When the popup is opened, the extension automatically copies the user's IP address to the clipboard and shows a notification. While this is likely intended as a convenience feature, it modifies the clipboard without an explicit user action (like clicking a "Copy" button).
- **Impact**: Minor privacy concern - users may not expect their clipboard to be overwritten automatically
- **Recommendation**: Require explicit user click on a "Copy IP" button
- **Verdict**: MINOR ISSUE - Not malicious, just poor UX practice

---

## False Positive Analysis

| Pattern Detected | Context | False Positive? | Explanation |
|-----------------|---------|-----------------|-------------|
| `<all_urls>` content script | IP lookup widget | ✅ YES | Required to detect IP addresses on any page user visits |
| `fetch()` calls to external APIs | Geolocation services | ✅ YES | Core functionality requires external IP lookup APIs |
| `navigator.clipboard.writeText()` | Auto-copy IP | ⚠️ BORDERLINE | Functional but intrusive UX pattern |
| Minified variable names | Build output | ✅ YES | Standard production bundling, not intentional obfuscation |
| Third-party CDN (jsdelivr) | Flag icon CSS | ✅ YES | Reputable CDN for open-source resources |

---

## API Endpoints Summary

| Endpoint | Purpose | Data Sent | Risk Level |
|----------|---------|-----------|------------|
| `ipwhois.app/json/{ip}` | IP geolocation (primary) | IP address | LOW |
| `api.extractip.com/geolocate/{ip}` | IP geolocation (fallback) | IP address | LOW |
| `vpn-test.ovh/welcome/welcome.html` | Install page | None | MINIMAL |
| `vpn-test.ovh/delete/delete.html` | Uninstall survey | None | MINIMAL |
| `forms.gle/2VLA7RnAuu48uKVd8` | Feedback form | User-submitted data | MINIMAL |
| `cdn.jsdelivr.net` | Flag icon CSS | None | MINIMAL |

---

## Data Flow Summary

```
User Opens Popup
    ↓
Background Script: Fetch IP from ipwhois.app (or extractip.com)
    ↓
Response: { ip, country_code, country, ... }
    ↓
Popup: Display country + flag, auto-copy IP to clipboard
    ↓
Notification: "Your IP address (X.X.X.X) copied to clipboard"

---

Content Script: User selects IP on webpage
    ↓
Validation: Check if selected text is valid IP
    ↓
Show "Lookup" button near selection
    ↓
User clicks: Send IP to background script
    ↓
Background: Fetch geolocation
    ↓
Content Script: Display country + flag inline
```

**Sensitive Data Handling**: IP addresses are sent to third-party APIs but this is inherent to the extension's purpose. No other sensitive data (cookies, passwords, browsing history) is accessed or transmitted.

---

## Overall Risk Assessment

**Risk Level**: **LOW**

### Justification
1. **Minimal Permissions**: Only requests `notifications` and `alarms` - no dangerous permissions
2. **Transparent Functionality**: Extension does exactly what it claims (IP geolocation lookup)
3. **No Malicious Patterns**: No code obfuscation, ad injection, tracking, keylogging, or data theft
4. **Legitimate APIs**: Uses reputable third-party geolocation services
5. **No Dynamic Code**: No eval(), Function(), or remote code loading

### Areas of Concern
1. **Misleading Name**: "VPN Test" suggests VPN functionality but extension only checks IP geolocation
2. **Auto-Clipboard Copy**: Intrusive UX pattern that modifies clipboard without explicit user click
3. **Low User Count**: 0 users suggests either new extension or unpopular - limited community vetting

### Recommendations
1. Rename extension to "IP Geolocation Checker" or similar to avoid confusion
2. Change clipboard copy to require explicit user button click
3. Add privacy policy explaining data sent to ipwhois.app and extractip.com
4. Consider self-hosting geolocation API to reduce third-party dependencies

---

## Comparison to Known Malicious Patterns

| Malicious Pattern | Present in Extension? | Evidence |
|-------------------|----------------------|----------|
| Extension Enumeration | ❌ NO | No queries to `chrome.management` or extension IDs |
| Proxy Infrastructure | ❌ NO | No `chrome.proxy` API usage |
| Cookie Harvesting | ❌ NO | No `document.cookie` or cookie API access |
| Keylogging | ❌ NO | No keyboard event listeners |
| Ad Injection | ❌ NO | No DOM manipulation to insert ads/links |
| Remote Config/Kill Switch | ❌ NO | No remote code loading or feature toggles |
| Market Intelligence SDKs | ❌ NO | No third-party tracking SDKs detected |
| Obfuscation | ❌ NO | Only standard minification |
| Data Exfiltration | ❌ NO | Only sends IP to geolocation APIs (functional) |

---

## Conclusion

**Vpn Test** is a legitimate utility extension that provides IP geolocation lookup functionality. Despite the misleading name suggesting VPN capabilities, the extension performs only benign IP lookups using third-party APIs. The code is clean, permissions are minimal, and no malicious behavior was detected.

The main issues are UX-related (auto clipboard copy, confusing name) rather than security concerns. The extension is safe for users but could benefit from improved naming and opt-in clipboard functionality.

**Final Verdict**: CLEAN with minor UX concerns

**Risk Level**: LOW
