# Vulnerability Report: iboss Classroom Management for Students

## Metadata
- **Extension ID**: ldomopmamhliggalnecdlinphjjkalhp
- **Extension Name**: iboss Classroom Management for Students
- **Version**: 1.0.20
- **Users**: ~80,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

iboss Classroom Management for Students is a legitimate educational monitoring extension designed for classroom environments. The extension collects comprehensive browsing data including active tab lists, user activity, and screenshots, sending this information to a localhost server (http://127.0.0.1:27556) for teacher monitoring. While the extension performs extensive data collection, this behavior is consistent with its stated purpose as a classroom management tool. The primary privacy concerns stem from the scope of monitoring (all tabs, screenshots) and external connectivity allowing other extensions to trigger screenshot capture. However, these features are disclosed and expected for this type of educational monitoring software.

The extension is rated MEDIUM risk due to privacy considerations rather than malicious intent. The data collection is extensive but appropriate for its stated educational monitoring purpose, and the extension appears to be a legitimate product from iboss, a known cybersecurity company.

## Vulnerability Details

### 1. MEDIUM: Extensive Browsing Data Collection and Transmission

**Severity**: MEDIUM
**Files**: background.js (lines 3735-3763)
**CWE**: CWE-359 (Exposure of Private Personal Information)

**Description**:
The extension continuously collects comprehensive browsing activity data and sends it to a localhost server. Every 500ms (when a class is active) or 30s (when inactive), the extension transmits:
- Complete list of all open tabs via `chrome.tabs.query({})`
- Tab metadata including URLs and titles
- User authentication status
- Class session information
- Raise hand events and timing

**Evidence**:
```javascript
const Vs = async () => {
  try {
    const e = {
      tabList: await U.tabs.query({}),
      lastEventCompleteId: de,
      raiseHandStartTimeMillis: fe
    };
    let t;
    rt ? t = await Hs(e) : t = await Us.post(`/studentPing?extensionId=${se}`, e), qs(t.data)
  } catch (e) {
    Me = !1, I = null, Z = null, Q = "", ct = 1e4, console.error(e)
  }
}
```

The studentPing endpoint at `http://127.0.0.1:27556/studentPing` receives all tab information:
```javascript
Us = M.create({
  baseURL: "http://127.0.0.1:27556",
  timeout: 1e4
});
```

**Verdict**:
This is MEDIUM severity because while the data collection is extensive, it is:
1. Disclosed functionality for a classroom management tool
2. Sent to localhost, not directly to remote servers
3. Appropriate for the stated educational monitoring purpose
4. Likely requires accompanying teacher software to be running locally

However, students should be aware that ALL browsing activity is monitored when this extension is active.

### 2. MEDIUM: Screenshot Capture via External Extension Communication

**Severity**: MEDIUM
**Files**: background.js (lines 3854-3896)
**CWE**: CWE-285 (Improper Authorization)

**Description**:
The extension exposes screenshot capture functionality to two specific external extensions via `externally_connectable`. Any of the whitelisted extensions can request a screenshot of the active tab at any time:

**Evidence**:
```json
"externally_connectable": {
  "ids": [
    "mkhjobnjhllkhekbbedlkmgcglgaeidc",
    "liidnnhljokidffhahaifiplkcaaohjm"
  ]
}
```

Screenshot capture implementation:
```javascript
U.runtime.onMessageExternal.addListener(async (e, t, n) => {
  if ((e == null ? void 0 : e.type) !== "CAPTURE_TAB_IMAGE") return;
  const r = await U.windows.getAll({
      populate: !0
    }),
    o = r.find(m => m.focused) || r[0];
  // ... finds active tab ...
  const m = await U.tabs.captureVisibleTab(a.windowId, {
    format: "jpeg",
    quality: 20
  });
  n(m ? {
    ok: !0,
    base64ImageWithPrefix: m
  } : {
    ok: !1,
    error: "image creation failure"
  })
})
```

**Verdict**:
This is MEDIUM severity because:
1. Screenshot capture is limited to specific whitelisted extension IDs (likely teacher-side extensions)
2. Quality is reduced to 20% (likely for bandwidth considerations)
3. This is expected functionality for classroom monitoring software
4. No evidence the screenshots are sent to unintended recipients

However, this represents significant privacy exposure as teachers can capture screenshots of student screens at any time.

## False Positives Analysis

Several patterns that might appear suspicious are actually legitimate for this extension type:

1. **Tab Blocking/Closing**: The extension can close tabs (`CLOSE_TAB`, `await Le(e.info.id)`) based on teacher-defined allow/block lists. This is standard classroom management functionality, not malicious behavior.

2. **Constant Localhost Communication**: The frequent pings to `http://127.0.0.1:27556` are not malicious - this is the local communication channel with teacher monitoring software.

3. **Extension Enumeration**: The `externally_connectable` configuration is not extension enumeration for malicious purposes - it's explicit API access for companion teacher extensions.

4. **Webpack Bundling**: The code uses Vite/webpack bundling which creates minified variable names (e.g., `U`, `I`, `Z`). This is normal build tooling, not obfuscation to hide malicious code.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| http://127.0.0.1:27556/studentPing | Student activity monitoring | Complete tab list, user info, class session data, raise hand events | Medium - extensive monitoring but localhost only |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
This extension is a legitimate educational monitoring tool from iboss, a known cybersecurity vendor. While it collects extensive browsing data and enables screenshot capture, these features are:

1. **Disclosed**: The extension name clearly identifies it as classroom management software
2. **Appropriate**: The monitoring capabilities match the stated educational purpose
3. **Limited Scope**: Data is sent to localhost server, requiring local teacher software
4. **Common Pattern**: Similar to other classroom management tools (GoGuardian, Securly, etc.)

The MEDIUM risk rating reflects privacy concerns inherent to this category of software rather than malicious behavior. Students and parents should understand:

- All browsing activity is monitored and sent to teachers when active
- Teachers can capture screenshots of student screens
- The extension can block or close tabs based on classroom policies
- Tab blocking enforces teacher-configured allow/block lists

The extension does not exhibit malicious characteristics such as:
- Hidden data exfiltration to unauthorized servers
- Credential theft
- Ad injection or affiliate fraud
- Malware/botnet behavior

For educational environments where monitoring is expected and disclosed, this represents appropriate functionality. The MEDIUM rating acknowledges the significant privacy implications while recognizing the legitimate use case.
