# Vulnerability Report: Proctor360

## Metadata
- **Extension ID**: hkegehhbmbongohpgmdadkbkmnfokicn
- **Extension Name**: Proctor360
- **Version**: 5.1
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Proctor360 is a legitimate online exam proctoring extension used by educational institutions to monitor students during remote testing. The extension has highly privileged permissions including `<all_urls>`, `management`, `system.display`, and broad navigation/tab access which are necessary for its stated purpose of preventing cheating during exams.

The extension continuously monitors browser activity when a proctoring session is active, tracking tab switches, window focus changes, navigation events, screen configuration, and extension management activities. All collected data is sent to proctor360.com API endpoints. While this represents extensive data collection and monitoring, it is consistent with the extension's disclosed purpose as an exam proctoring tool and is only active during proctored exam sessions.

## Vulnerability Details

### 1. MEDIUM: Extensive Browser Activity Monitoring

**Severity**: MEDIUM
**Files**: background.js, tabCheck.js, content.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension collects comprehensive browser activity data during exam sessions, including:
- All tab creation, switching, and closure events
- Window focus changes and minimization
- Navigation history across all tabs
- Screen/display configuration changes
- Extension management activities (installation/uninstallation of other extensions)
- Full URL access across all domains

**Evidence**:
```javascript
// From background.js - Monitors all browser activities
chrome.tabs.onUpdated.addListener(beforeStartListener);
chrome.tabs.onCreated.addListener(OnCreateListener);
chrome.tabs.onRemoved.addListener(removeExtensionListener);
chrome.tabs.onActivated.addListener(TabSwitchEventListener);
chrome.windows.onFocusChanged.addListener(windowSwitchEventListener);
chrome.webNavigation.onCommitted.addListener(webNavigationListener);

// Data sent to server
await fetch(`${api_base}/browser-activities`, {
    method: 'POST',
    headers: {
        "Content-Type": "application/json",
    },
    body: JSON.stringify({
        session_link: sessionId,
        activity_name: activityName,
        event: activityEvent,
        name: name,
        url: url
    })
})
```

**Verdict**: This is expected behavior for an exam proctoring tool. The monitoring only occurs during active proctoring sessions (when `startSession` flag is true) and is disclosed in the extension's purpose "Secure Testing Anywhere". Educational institutions explicitly install this for exam integrity.

## False Positives Analysis

The static analyzer flagged two HIGH severity exfiltration flows:
1. `chrome.storage.local.get → fetch` - This is legitimate session configuration retrieval
2. `chrome.tabs.get → fetch` - This is expected tab activity monitoring for proctoring

These are not vulnerabilities but core functionality of a proctoring tool. The extension:
- Only monitors when explicitly in a proctoring session
- Sends data only to official proctor360.com API endpoints
- Has a clear disclosed purpose as an exam monitoring tool
- Implements error queuing to ensure exam integrity events aren't lost

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| prod1studentapi.proctor360.com/api/student-sessions/{sessionID} | Fetch session configuration | Session ID (GET) | Low - legitimate auth |
| prod1studentapi.proctor360.com/api/browser-activities | Report browser events | Session ID, activity name, event type, tab URLs, timestamps | Medium - disclosed monitoring |
| prod1studentapi.proctor360.com/api/exam-pass | Retrieve exam credentials | Exam session data | Low - legitimate exam setup |

All endpoints are on the official proctor360.com domain and use HTTPS. No third-party analytics or ad networks detected.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: While Proctor360 has extensive permissions and collects detailed browsing data, this is entirely consistent with its disclosed purpose as an exam proctoring tool. The extension:

**Mitigating Factors:**
- Only activates monitoring during explicit exam sessions
- All data goes to first-party proctor360.com servers
- Clear stated purpose ("Secure Testing Anywhere")
- Typically deployed by educational IT departments, not end-user installed
- Uses session-based activation (requires explicit exam session start)
- No evidence of data collection outside of proctoring sessions

**Concerns:**
- Very broad permissions (`<all_urls>`, `management`, `system.display`)
- Monitors all browser activity during active sessions
- Can enforce fullscreen mode and prevent tab switching
- Access to extension management (can detect/interfere with other extensions)

**Recommendation**: MEDIUM risk is appropriate. This is a legitimate enterprise monitoring tool operating within its disclosed scope. Users should only install when required by their educational institution for proctored exams, and should uninstall when no longer needed. Educational institutions should ensure students are fully informed about the extent of monitoring.
