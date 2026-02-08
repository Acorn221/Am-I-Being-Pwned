# LeechBlock NG - Security Analysis Report

## Extension Metadata
- **Extension Name:** LeechBlock NG
- **Extension ID:** blaaajhemilngeeffpbfkdjjoefldkok
- **Version:** 1.7.2
- **User Count:** ~100,000
- **Author:** James Anderson
- **Homepage:** https://www.proginosko.com/leechblock/

## Executive Summary

LeechBlock NG is a productivity-focused website blocking extension with a clean security profile. This is a legitimate, open-source productivity tool designed to help users block time-wasting websites. The extension operates entirely locally with minimal permissions, no external network calls, and transparent functionality. **No security vulnerabilities or malicious behavior were identified.**

**Overall Risk Assessment: CLEAN**

## Detailed Analysis

### 1. Manifest Analysis

**Permissions Requested:**
- `alarms` - Used for background script lifecycle management
- `contextMenus` - Right-click menu integration
- `offscreen` - Ticker/timer functionality
- `storage` - Local storage of blocking rules and time data
- `tabs` - Tab management for blocking functionality
- `unlimitedStorage` - Storing extensive blocking data
- `webNavigation` - Monitoring page navigation for blocking

**Optional Permissions:**
- `history` - Optional, for adding blocked pages to history

**Host Permissions:**
- `<all_urls>` - Required for website blocking functionality

**Content Security Policy:** Not explicitly defined (uses Manifest V3 defaults)

**Verdict:** Permissions are appropriate and necessary for website blocking functionality. The extension follows the principle of least privilege by making history permission optional.

### 2. Background Script Analysis (`background.js`)

**Key Functionality:**
- Local site blocking based on user-configured rules (regex patterns, time limits, schedules)
- Time tracking for site usage stored in `chrome.storage.local` or `chrome.storage.sync`
- Tab state management (tracking focused tabs, time spent, blocking states)
- Lockdown and override functionality with password protection
- Alarm-based ticker for periodic processing (every 1-10 seconds configurable)

**Network Activity:**
- **Site List Fetching:** Lines 245-297 - Optional feature allowing users to specify URLs for remote blocklists via `fetch(sitesURL)`. User-controlled, transparent, sanitizes input.
  ```javascript
  let sitesURL = gOptions[`sitesURL${set}`];
  if (sitesURL) {
      sitesURL = sitesURL.replace(/\$S/, set).replace(/\$T/, time);
      fetch(sitesURL).then(...)
  }
  ```
- No telemetry, analytics, or unauthorized data transmission
- Only hardcoded external URL: `https://www.proginosko.com/leechblock/` (documentation, allowlisted by default)

**Chrome API Usage:**
- `chrome.storage.local/sync` - Settings and time data persistence
- `chrome.tabs.*` - Tab management, blocking page redirects, state tracking
- `chrome.webNavigation.onBeforeNavigate` - Pre-navigation blocking checks
- `chrome.contextMenus` - User-facing menu options
- `chrome.alarms` - Background script keepalive (6 alarms, 1-minute periods)
- `chrome.offscreen` - Creates ticker document for periodic processing

**Dynamic Code/Eval:**
- RegExp construction from user-provided blocking patterns (lines 64-81) - Proper use case
- No `eval()`, `Function()`, or remote code execution

**Verdict:** Clean implementation. All functionality serves the stated purpose. Remote blocklist fetching is user-controlled and transparent.

### 3. Content Script Analysis (`content.js`)

**Injection Scope:**
- Injected into `<all_urls>` at `document_start`
- Excludes own blocking pages (`*://*/*lb-custom*`)

**Functionality:**
- Notifies background script when page loads
- Sends referrer information for blocking rule evaluation
- Displays timer overlay showing time remaining before block
- Shows warning alerts before blocking
- Checks page content for keyword-based blocking (searches document.title and body.innerText)
- Applies visual filters (blur, grayscale, etc.) when configured

**DOM Manipulation:**
- Creates timer div (`leechblock-timer`) - minimal, styled via CSS
- Creates alert container for warnings - removable by user click
- `innerText` usage for display only (no XSS risk)

**Message Passing:**
- Bidirectional messages with background script (load notifications, timer updates, keyword checks)
- No external postMessage or cross-origin communication

**Verdict:** Benign content script with minimal DOM footprint. All operations support core blocking functionality.

### 4. Data Privacy & Storage

**Data Collected:**
- Website blocking rules (user-configured site lists, time limits, schedules)
- Time tracking data (time spent on blocked sites per block set)
- User preferences (passwords, override settings, display options)
- Tab state (current URL, focus state, load times) - ephemeral, not persisted

**Data Storage:**
- All data stored locally via `chrome.storage.local` or optionally `chrome.storage.sync`
- No transmission to remote servers
- Export/import functionality for user data backup (local files only)

**Third-Party Connections:**
- None (except optional user-configured remote blocklists)

**Verdict:** Excellent privacy profile. All data remains local, no telemetry or tracking.

### 5. Security Features

**Password Protection:**
- Options page access control with password/code
- Override functionality requires password
- Set-specific passwords for delayed access
- Passwords hashed using `hashCode32()` (32-bit hash) - **Note:** Not cryptographically secure but adequate for productivity tool use case

**Access Controls:**
- Prevents access to extension settings during configured time periods
- Lockdown mode for enforcing blocks
- Override limits (count-based, time-based)

**Verdict:** Security controls appropriate for productivity tool. Hash function is weak by cryptographic standards but acceptable given threat model (self-imposed productivity constraints, not security-critical).

### 6. Blocking & Filtering Mechanisms

**Blocking Logic:**
- Regex-based URL matching (user-configured patterns)
- Time-based blocking (schedules, daily limits, time periods)
- Keyword-based blocking (searches page title/body for keywords)
- Referrer-based blocking
- Incognito mode handling
- Active tab vs. all tabs modes

**Block Pages:**
- Three types: blocked.html, delayed.html (countdown), password.html
- All local HTML pages within extension
- Customizable block messages
- Optional auto-reload after specified time

**Visual Filters:**
- CSS filters (blur, opacity, grayscale, invert, sepia, custom)
- Applied via `document.documentElement.style.filter`
- Non-invasive, user-controlled

**Verdict:** Sophisticated blocking system with extensive user customization. No vulnerabilities detected.

### 7. Code Quality & Licensing

**License:** Mozilla Public License 2.0 (MPL-2.0) - Open source
**Code Style:** Clean, well-commented, consistent naming conventions
**Error Handling:** Appropriate try-catch and promise rejection handling
**Dependencies:** jQuery UI (for options page UI) - legitimate, no security concerns

**Verdict:** High-quality, maintainable codebase. Open-source licensing promotes transparency.

## False Positives

| Item | Location | Reason for False Positive |
|------|----------|---------------------------|
| `fetch()` call | `background.js:255` | Optional user-configured remote blocklist feature, transparent and documented |
| RegExp construction | `background.js:64-81` | Legitimate pattern matching for site blocking, user-controlled input |
| `innerText` access | `content.js:120` | Read-only operation for keyword search, no XSS risk |
| `document.documentElement.style.filter` | `content.js:150` | Benign CSS filter application for visual blocking effects |
| `<all_urls>` permission | `manifest.json:70-72` | Required for website blocking functionality across all sites |

## API Endpoints & External Connections

| URL | Purpose | Risk Level |
|-----|---------|------------|
| `https://www.proginosko.com/leechblock/` | Documentation/homepage (optional, allowlisted) | None |
| User-configured `sitesURL` | Optional remote blocklist fetching | Low (user-controlled, transparent) |

## Data Flow Summary

```
User Configuration (Options Page)
    ↓
chrome.storage.local/sync (Persistent Settings)
    ↓
Background Script (Processing Engine)
    ├─→ Tab Monitoring (chrome.tabs, chrome.webNavigation)
    ├─→ Time Tracking (Local Storage)
    ├─→ Block Evaluation (Regex Matching)
    └─→ Content Scripts (Timer, Alerts, Filters)
         ↓
    Visual Feedback to User
```

**No external data transmission** - All processing occurs locally within the browser.

## Vulnerability Assessment

### Critical Vulnerabilities
**None identified.**

### High Severity Vulnerabilities
**None identified.**

### Medium Severity Vulnerabilities
**None identified.**

### Low Severity Issues
**None identified.**

### Informational Findings

1. **Weak Password Hashing (INFO)**
   - **Finding:** `hashCode32()` uses a simple 32-bit non-cryptographic hash for passwords
   - **Location:** `common.js:609-615`, `blocked.js:13-19`
   - **Impact:** Passwords could theoretically be brute-forced offline if storage is compromised
   - **Verdict:** Acceptable for productivity tool use case. Not designed for security-critical scenarios. Hash collisions are unlikely to be exploited in typical usage.

2. **Unlimited Storage Permission (INFO)**
   - **Finding:** Extension requests `unlimitedStorage` permission
   - **Location:** `manifest.json:104`
   - **Impact:** Could store large amounts of data, but only user-configured blocking rules and time data
   - **Verdict:** Appropriate given extensive blocking rules and long-term time tracking requirements.

## Overall Risk Assessment

**Risk Level: CLEAN**

**Rationale:**
LeechBlock NG is a well-designed, privacy-respecting productivity tool with no security vulnerabilities or malicious behavior. The extension:
- Operates entirely locally with no telemetry or tracking
- Uses permissions appropriately for stated functionality
- Follows secure coding practices
- Is open source with active maintenance
- Has clear documentation and user controls
- Contains no obfuscation or suspicious patterns

The weak password hashing is acceptable given the tool's purpose (self-imposed productivity constraints) rather than security-critical access control. Users should understand this is a productivity tool, not a security mechanism.

**Recommendation:** Safe for use. Extension operates as advertised with excellent privacy practices.

## Technical Notes

- **Manifest Version:** V3 (modern, secure API model)
- **Service Worker:** Proper implementation with alarm-based keepalive
- **Offscreen Document:** Used for ticker functionality (correct MV3 pattern)
- **Storage:** Supports both local and sync storage with user control
- **Obfuscation:** None - source code is readable and well-structured
- **Open Source:** Available at https://github.com/proginosko/LeechBlockNG

## Conclusion

LeechBlock NG represents a best-practice example of a privacy-respecting browser extension. The codebase is clean, transparent, and serves only its stated purpose of helping users manage their time and avoid distracting websites. No security concerns warrant further investigation.

---

**Analysis Date:** 2026-02-07
**Analyst:** Claude Sonnet 4.5
**Analysis Duration:** Comprehensive review of all components
