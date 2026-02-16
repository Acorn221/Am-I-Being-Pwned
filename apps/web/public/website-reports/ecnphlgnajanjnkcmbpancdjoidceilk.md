# Vulnerability Report: Kami for Google Chrome™

## Metadata
- **Extension Name**: Kami for Google Chrome™
- **Extension ID**: ecnphlgnajanjnkcmbpancdjoidceilk
- **User Count**: ~19,000,000
- **Version**: 2.0.22152
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-08

## Executive Summary

Kami is a legitimate educational PDF and document annotation tool designed to integrate with learning management systems (Google Classroom, Canvas, Schoology, etc.). The extension demonstrates **CLEAN** security posture with no malicious behavior detected. All extensive permissions are justified for its core functionality as an educational platform integration tool. The extension only communicates with its own official domains and educational platform APIs, implements proper analytics tracking, and follows secure coding practices.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

This extension requires extensive permissions and is highly invasive by necessity, but serves its stated educational purpose without evidence of malicious behavior or key vulnerabilities. All data collection and network communication aligns with expected functionality for a comprehensive educational document annotation and classroom management tool.

## Vulnerability Details

### 1. Extensive Permission Scope - INFORMATIONAL
**Severity**: INFORMATIONAL
**Files**: manifest.json
**Verdict**: JUSTIFIED - Required for educational platform integration

**Description**:
The extension requests extremely broad permissions:
- `<all_urls>` host permissions
- `webRequest`, `tabs`, `webNavigation`, `contextMenus`
- `storage`, `declarativeNetRequest`, `scripting`
- `offscreen`, `printerProvider`
- OAuth2 access to Google Drive and Classroom APIs

**Code Evidence**:
```json
"permissions": [
  "webRequest", "tabs", "webNavigation", "contextMenus",
  "storage", "declarativeNetRequest", "scripting",
  "offscreen", "printerProvider"
],
"host_permissions": ["<all_urls>"],
"oauth2": {
  "client_id": "185741998891-boet3ik0ho58mic9ttbhbtl75bjekic5.apps.googleusercontent.com",
  "scopes": [
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/classroom.courses",
    "https://www.googleapis.com/auth/classroom.coursework.students"
  ]
}
```

**Analysis**: All permissions are necessary for:
- Document annotation across educational platforms
- Google Classroom/Drive integration
- Canvas, Schoology, and other LMS integrations
- PDF rendering and manipulation
- Assignment management and grading workflows

### 2. Educational Platform Data Collection - INFORMATIONAL
**Severity**: INFORMATIONAL
**Files**: content-scripts/google_classroom.js, content-scripts/canvas.js, content-scripts/schoology.js
**Verdict**: EXPECTED - Part of core educational functionality

**Description**:
The extension collects detailed academic data including:
- Student grades and assignment scores
- Course information and enrollment data
- Assignment submission details
- Google Classroom coursework metadata

**Code Evidence (Schoology grading data collection)**:
```javascript
function sn(e,t,n,r){
  const o=cn(e);
  if(!(o.assignments.size>0||o.students.size>0||o.grades.size>0))return;
  const u={...dn(o),course_id:t,course_name:n,
    schoology_origin:c,scan_duration:i,schoology_user_id:a};
  N("Schoology Grade Book Detected",u)
}
```

**Analysis**: This data collection is clearly part of the intended "Class View" feature that allows teachers to track student progress. The extension is transparent about this functionality in its description: "enhancing the way teachers teach, feedback, and assess."

### 3. Analytics and Telemetry - INFORMATIONAL
**Severity**: INFORMATIONAL
**Files**: content-scripts/global.js, content-scripts/google_classroom.js
**Verdict**: EXPECTED - Standard product analytics

**Description**:
The extension implements comprehensive event tracking to Kami's servers.

**Code Evidence**:
```javascript
async function gt(e,t={},n="extension"){
  const o=ae(),i=await ht(e,t,n,o);
  return o==="service_worker"||o==="page_script"?
    await wt(i):await chrome.runtime.sendMessage({type:"trackEvent",payload:i}),i
}

async function wt(e){
  console.debug(`Event: ${e.name}`,e),
  await(await fetch(h.webHost+"/api/events",{
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify(e)
  })).text()
}
```

**Analysis**: Events tracked include:
- Button clicks (e.g., "Canvas Open In New Tab Button Click")
- Assignment creation/editing actions
- Platform navigation events
- Extension usage patterns

All analytics data is sent only to official Kami domains (`*.kamihq.com`, `*.kamipdf.com`, `*.kami.systems`).

### 4. Header Modification for Google Classroom - INFORMATIONAL
**Severity**: INFORMATIONAL
**Files**: rules_global.json
**Verdict**: JUSTIFIED - Required for iframe embedding

**Description**:
Uses declarativeNetRequest to remove Cross-Origin-Opener-Policy header on Google Classroom attachment pages.

**Code Evidence**:
```json
{
  "id": 1,
  "action": {
    "type": "modifyHeaders",
    "responseHeaders": [
      {"header": "cross-origin-opener-policy", "operation": "remove"}
    ]
  },
  "condition": {
    "urlFilter": "https://classroom.google.com/*c/*a/*attachFileId*",
    "resourceTypes": ["main_frame"]
  }
}
```

**Analysis**: This is necessary for the extension's file attachment workflow in Google Classroom. The modification is narrowly scoped to specific attachment URLs only.

### 5. OAuth Token Management - INFORMATIONAL
**Severity**: INFORMATIONAL
**Files**: manifest.json
**Verdict**: STANDARD - Google OAuth best practices

**Description**:
The extension uses Google OAuth2 with standard Drive and Classroom scopes.

**Analysis**:
- Uses official Google OAuth client ID
- Scopes are appropriate for document annotation in educational contexts
- No evidence of token exfiltration or misuse
- Follows standard OAuth flow patterns

## False Positives

| Pattern | Location | Explanation |
|---------|----------|-------------|
| `fetch()` calls to Kami domains | Multiple content scripts | Legitimate API communication with official Kami infrastructure |
| `chrome.storage` extensive usage | content-scripts/global.js | Required for caching user preferences and assignment metadata |
| `postMessage` usage | content-scripts/google_classroom.js | Inter-frame communication for Google Classroom picker integration |
| Grade data extraction | content-scripts/schoology.js | Core "Class View" feature for teachers to monitor student progress |
| `sessionStorage` for assignment data | content-scripts/global.js | Temporary storage for Google Classroom assignment creation workflow |

## API Endpoints

All network communication is restricted to official Kami infrastructure:

| Domain | Purpose | Evidence |
|--------|---------|----------|
| `https://web.kamihq.com` | Main web application and viewer | background.js, all content scripts |
| `https://api.kamihq.com` | API backend for analytics and data | content-scripts/global.js |
| `https://tools.kamihq.com` | Supporting tools and utilities | content-scripts/google_drive.js |
| `https://www.kamiapp.com/library` | Educational content library | manifest.json |
| `https://classroom.google.com` | Google Classroom integration | content-scripts/google_classroom.js |
| `https://*.instructure.com` | Canvas LMS integration | content-scripts/canvas.js |
| `https://*.schoology.com` | Schoology LMS integration | content-scripts/schoology.js |

## Data Flow Summary

### Inbound Data
1. **Google Classroom**: Course data, assignment metadata, student submissions, grades
2. **Canvas LMS**: Assignment forms, course information, student work
3. **Schoology**: Gradebook data, course materials, assignment details
4. **Google Drive**: File metadata for document annotation
5. **User Storage**: Cached preferences, device IDs, user authentication tokens

### Outbound Data
1. **Analytics Events**: User actions, feature usage, error tracking → `api.kamihq.com/api/events`
2. **Assignment Data**: Course/assignment metadata for Class View feature → Kami backend
3. **Grade Information**: Student progress data for teacher dashboards → Kami backend
4. **Document Access**: File IDs and authorization for annotation workflow → Kami viewer

### Data Processing
- All sensitive educational data is processed for legitimate features (Class View, grading, assignment tracking)
- No evidence of data exfiltration to third parties
- No advertising or market intelligence SDKs detected
- Analytics is limited to product usage telemetry

## Security Observations

### Positive Security Practices
1. **Manifest V3 compliance**: Uses modern extension architecture
2. **CSP implementation**: Restricts script execution with Content Security Policy
3. **Domain restrictions**: `externally_connectable` limits communication to official Kami domains
4. **No dynamic code execution**: No `eval()`, `new Function()`, or similar patterns detected
5. **No cookie harvesting**: No access to `chrome.cookies` API
6. **No keylogging**: No keyboard event listeners for credential capture
7. **Proper OAuth**: Uses Google's official OAuth flow for authentication

### Areas of Invasiveness (Justified)
1. **All-URL content scripts**: Required to integrate with diverse educational platforms
2. **Extensive DOM manipulation**: Necessary for injecting UI elements into LMS interfaces
3. **Grade data collection**: Core feature for teacher dashboards and Class View
4. **Cross-origin communication**: Needed for Google Classroom picker and file selection workflows

## Conclusion

Kami for Google Chrome™ is a **CLEAN** extension that serves its stated purpose as an educational document annotation and classroom management tool. While it requires extensive permissions and collects significant educational data, all functionality aligns with its legitimate use case. The extension:

- Only communicates with official Kami infrastructure and educational platform APIs
- Implements proper security practices (Manifest V3, CSP, OAuth)
- Contains no malicious code patterns (keyloggers, credential theft, ad injection)
- Does not use market intelligence SDKs or third-party analytics beyond its own system
- Transparently provides educational features (annotation, grading, assignment management)

The invasive nature of the extension is a necessary consequence of its deep integration with multiple learning management systems. Teachers and administrators should be aware that the extension has broad access to educational data, but this access is used for the advertised functionality of the product.

**Recommendation**: APPROVED for educational use with understanding of data access scope.
