# Vulnerability Analysis Report: Canvas Quiz Loader

## Extension Metadata
- **Extension Name**: Canvas Quiz Loader
- **Extension ID**: pfagnepdndhkmilceinbebdfbmiddagl
- **Version**: 0.5.4
- **Estimated Users**: ~50,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

Canvas Quiz Loader is an educational tool designed to automatically load correct answers from previous Canvas quiz attempts. The extension operates within Canvas LMS (Learning Management System) environments hosted on instructure.com and .edu domains.

**Overall Risk Assessment**: MEDIUM

The extension exhibits potentially concerning behavior for an academic integrity tool, including:
1. External data exfiltration to third-party services (Datadog telemetry, remote debug server)
2. Access and extraction of complete quiz submission history via Canvas API
3. Automatic answer population that facilitates academic dishonesty
4. Collection of full page HTML and sensitive academic data for debug purposes

While the extension appears to function as advertised without malicious intent, it poses academic integrity risks and transmits sensitive educational data to external services without clear user consent.

## Vulnerability Details

### 1. MEDIUM SEVERITY: Unauthorized External Data Transmission

**File**: `quiz-loader/index.js` (lines 2986-2998, 2947)

**Description**: The extension transmits error telemetry and debug data to external third-party services:
- Datadog telemetry service (us3.datadoghq.com) with client token: `pub1b40d87cd5789b981aad8bd37e4e01a4`
- Custom debug server at `https://quiz-loader-production.fly.dev`

**Code Evidence**:
```javascript
Wn.init({
  clientToken: "pub1b40d87cd5789b981aad8bd37e4e01a4",
  site: "us3.datadoghq.com",
  forwardErrorsToLogs: !1,
  sessionSampleRate: 100,
  version: "0.5.4",
  service: "canvas-quiz-loader",
  env: "production",
  beforeSend: e => {
    for (const t of this.debugConfig.excludeErrorPattern)
      if (e.message.includes(t)) return !1;
    return !0
  }
})
```

```javascript
const Vn = new class {
  constructor(e) {
    this.baseUrl = e
  }
  // ...
}("https://quiz-loader-production.fly.dev");
```

**Impact**:
- User browsing behavior, error messages, and session data sent to Datadog
- Debug bundles containing full page HTML, Canvas ENV objects, and logs sent to fly.dev server
- Potential exposure of student PII, quiz content, and academic records
- No explicit user consent or privacy disclosure for this data collection

**Verdict**: MEDIUM RISK - Telemetry is common in modern extensions but sending academic data (including full HTML snapshots and Canvas environment data) to external servers without clear disclosure is concerning, especially given the sensitive educational context.

---

### 2. MEDIUM SEVERITY: Comprehensive Canvas API Data Harvesting

**File**: `quiz-loader/index.js` (lines 3342-3378)

**Description**: Extension fetches complete quiz submission history for all previous attempts via Canvas API endpoints.

**Code Evidence**:
```javascript
const o = `${n}api/v1/courses/${e}/quizzes/${t}/`,
  r = o + "submissions",
  [s, i] = yield Promise.all([fetch(o), fetch(r)]),
  [a, c] = yield Promise.all([s.text(), i.text()]),
  [u, l] = [JSON.parse(a), JSON.parse(c).quiz_submissions];
// ...
return fetch(`${n}api/v1/courses/${e}/assignments/${d}/submissions/${f}?include[]=submission_history`)
  .then((e => e.text()))
  .then((e => JSON.parse(e).submission_history))
```

**Impact**:
- Accesses full submission history including all previous quiz attempts
- Retrieves quiz questions, answers, scores, and student performance data
- Data includes assignment IDs, user IDs, and course information
- Stored locally and potentially sent in debug bundles to external servers

**Verdict**: MEDIUM RISK - While necessary for the extension's functionality, the comprehensive nature of data collection combined with external transmission creates privacy concerns.

---

### 3. LOW SEVERITY: Debug Bundle Exfiltration

**File**: `quiz-loader/index.js` (lines 3025-3030, 3077-3082)

**Description**: Extension collects comprehensive debug bundles including full page HTML, Canvas environment variables, and all logged messages, then sends them to a remote server.

**Code Evidence**:
```javascript
getLogBungle() {
  return Qn(this, void 0, void 0, (function*() {
    const e = [];
    e.push("--------------- HTML SECTION START ---------------\n"),
    e.push(document.documentElement.outerHTML),
    e.push("\n--------------- HTML SECTION END ---------------\n\n"),
    e.push("--------------- CANVAS ENV SECTION START ---------------\n"),
    e.push(JSON.stringify(yield this.getQuizEnv(), null, 2)),
    e.push("\n--------------- CANVAS ENV SECTION END ---------------\n\n"),
    e.push("--------------- LOGS SECTION START ---------------\n"),
    e.push(JSON.stringify(this.getLogs(), null, 2)),
    e.push("\n--------------- LOGS SECTION END ---------------\n\n"),
    return e.join("")
  }))
}
```

```javascript
Vn.postDebugBundle(this.getLogBungle()).then((t => e = t))
  .catch((e => {
    console.error(e),
    this._storeLog("error", t(e)),
    Wn.logger.error(e.message, null, e)
  }))
```

**Impact**:
- Captures complete DOM including quiz questions, answers, and student information
- Sends Canvas internal environment variables (window.ENV)
- Transmits all console logs and error messages
- User can also manually trigger debug log download via popup menu

**Verdict**: LOW RISK - Debug functionality appears legitimate for troubleshooting, but the extent of data collection and automatic transmission on certain errors is concerning.

---

### 4. LOW SEVERITY: Academic Integrity Violation Tool

**File**: `quiz-loader/index.js` (lines 3204-3330), `manifest.json` (line 8)

**Description**: The extension's core purpose is to automatically populate quiz answers from previous attempts, directly facilitating academic dishonesty.

**Code Evidence**:
```javascript
displayMultipleChoise(e, t) {
  // ... marks incorrect answers
  const r = `question_${t}_answer_${e.bestAnswer.text}`,
    s = document.getElementById(r);
  s && (function(e) {
    return e.parentElement.nextElementSibling.className.includes("incorrect-answer")
  }(s) || (s.checked = !0, s.dispatchEvent(new Event("change", {
    bubbles: !0
  }))))
}
```

Manifest description: `"Automatically load correct answers from previous quiz attempts."`

**Impact**:
- Automatically selects correct answers on quizzes
- Fills in text fields, dropdowns, and multiple-choice questions
- Marks point values and shows which answers are correct/incorrect
- Enables students to cheat on Canvas quizzes

**Verdict**: LOW RISK (Security) - While ethically problematic and violating academic integrity policies, this is the extension's stated purpose rather than hidden malicious behavior. Security-wise, the risk is that institutions may not be aware students are using such tools.

---

## False Positive Analysis

| Pattern | Location | Reason for False Positive | Verdict |
|---------|----------|---------------------------|---------|
| Datadog SDK | quiz-loader/index.js (lines 1-2500) | Standard telemetry library bundled with application | Known FP - Legitimate monitoring SDK |
| browser-polyfill.min.js | quiz-loader/ and popup/ | WebExtension API polyfill for cross-browser compatibility | Known FP - Standard Mozilla polyfill |
| Error stack parsing | quiz-loader/index.js (lines 469-476) | Datadog SDK error processing and stack trace parsing | Known FP - SDK functionality |
| Cookie access | quiz-loader/index.js (lines 1000-1018) | Datadog session management cookies (_dd_s) | Known FP - SDK session tracking |

## API Endpoints & External Services

| Endpoint | Purpose | Data Sent | Risk Level |
|----------|---------|-----------|------------|
| https://us3.datadoghq.com | Telemetry/Error tracking | Session data, errors, user actions, browser telemetry | MEDIUM |
| https://quiz-loader-production.fly.dev/api/v1/debug/config | Fetch debug configuration | None (GET request) | LOW |
| https://quiz-loader-production.fly.dev/api/v1/debug/bundle | Submit debug bundle | Full HTML, Canvas ENV, logs, errors | MEDIUM |
| https://quiz-loader-production.fly.dev/health/ping | Health check | None | NONE |
| [institution].instructure.com/api/v1/* | Canvas LMS API | Course/quiz IDs (authenticated with user's session) | LOW |
| https://discord.gg/npNySzNZ | Discord community link | None (external link only) | NONE |
| https://cdnjs.cloudflare.com/ajax/libs/simple-icons/3.13.0/discord.svg | Discord icon CDN | None (image resource) | NONE |

## Data Flow Summary

```
1. User accesses Canvas quiz (*.instructure.com/courses/*/quizzes/*/take*)
   ↓
2. Extension injects content script (quiz-loader/index.js)
   ↓
3. Extension fetches Canvas API:
   - GET /api/v1/courses/{id}/quizzes/{id}/
   - GET /api/v1/courses/{id}/quizzes/{id}/submissions
   - GET /api/v1/courses/{id}/assignments/{id}/submissions/{id}?include[]=submission_history
   ↓
4. Processes submission history to identify best answers
   ↓
5. Automatically populates quiz form fields with correct answers
   ↓
6. Sends telemetry to Datadog (errors, sessions, telemetry)
   ↓
7. On certain errors: Sends debug bundle to fly.dev
   (includes: full HTML, Canvas ENV object, logs)
```

## Permissions Analysis

The extension requests NO explicit permissions in manifest.json, but operates with:
- **Content script injection**: Limited to Canvas domains (*.instructure.com, *.edu)
- **Web accessible resources**: Injectable script to access window.ENV
- **Host permissions**: Implicitly inherits Canvas session cookies/auth

**Assessment**: Minimal permission model is good security practice. Extension properly scopes itself to relevant domains.

## Privacy & Compliance Concerns

1. **FERPA Compliance**: Extension may violate FERPA (Family Educational Rights and Privacy Act) by transmitting student educational records to third-party services without institutional consent
2. **No Privacy Policy**: No visible privacy policy or data handling disclosure
3. **Third-party Services**: Use of Datadog and custom debug server not disclosed to users
4. **Academic Integrity**: Violates most institutions' academic honesty policies

## Recommendations

**For Users**:
- Be aware this extension transmits academic data to external servers
- Understand using this violates academic integrity policies and could result in disciplinary action
- Consider privacy implications of telemetry collection

**For Institutions**:
- Block extension ID via Chrome Web Store policy
- Monitor Canvas API usage for submission history patterns
- Implement Canvas LMS security controls to limit API access

**For Developer**:
- Add clear privacy policy and data collection disclosure
- Make telemetry opt-in rather than automatic
- Remove automatic debug bundle transmission or require explicit user consent
- Consider FERPA implications of collecting educational records

## Overall Risk Assessment

**Risk Level**: MEDIUM

**Justification**:
The Canvas Quiz Loader extension functions as advertised and does not exhibit overtly malicious behavior. However, it poses medium security and privacy risks due to:

1. **Undisclosed data collection**: Sends academic data to external services (Datadog, fly.dev) without clear user consent
2. **Sensitive data exposure**: Debug bundles contain full page HTML with student PII, quiz content, and academic records
3. **Academic integrity violation**: Core functionality facilitates cheating, though this is its stated purpose
4. **FERPA concerns**: May violate educational privacy regulations

The extension is not malware and serves its intended (albeit ethically questionable) purpose. The primary concerns are privacy/compliance related rather than technical security vulnerabilities. Institutions should block this extension, and users should be aware of the academic and privacy implications of its use.

## Technical Notes

- Large bundled Datadog Logs SDK (~2500 lines) comprises majority of code
- No dynamic code execution (eval, Function constructor)
- No credential theft or keylogging
- Uses legitimate WebExtension APIs appropriately
- Manifest v3 compliance indicates recent development/updates
