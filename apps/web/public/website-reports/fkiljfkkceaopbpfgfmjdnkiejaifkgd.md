# Security Analysis Report: Jobalytics - Resume Keyword Analyzer

## Extension Metadata
- **Extension ID**: fkiljfkkceaopbpfgfmjdnkiejaifkgd
- **Name**: Jobalytics - Resume Keyword Analyzer
- **Version**: 6.4.7
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-06

## Executive Summary

Jobalytics is a resume optimization tool that analyzes job descriptions and compares them against uploaded resumes to identify keyword matches. The extension operates primarily on job board websites (LinkedIn, Indeed, Glassdoor, Workday, Handshake) and provides resume-job matching scores.

**Overall Risk Assessment: LOW**

The extension exhibits legitimate functionality consistent with its stated purpose. While it collects and uploads resume data to Firebase storage, this aligns with its core resume analysis features. No malicious behavior patterns were detected.

## Permissions Analysis

### Declared Permissions
- `activeTab` - Access to current tab for job description scraping
- `storage` - Local storage for resume data and match scores
- `tabs` - Tab monitoring for job board navigation
- `webNavigation` - Navigation event monitoring for job page detection
- `webRequest` - Request monitoring (limited scope)
- `scripting` - Content script injection

### Host Permissions
- `http://*/*` - Broad access pattern
- `https://*/*` - Broad access pattern
- `https://www.google-analytics.com/*` - Analytics tracking

**Assessment**: Permissions are overly broad (`http://*/*`, `https://*/*`) but functionally limited to job board sites in practice. The extension only activates on supported job platforms.

### Content Security Policy
```
script-src 'self'; object-src 'self'
```
**Assessment**: Solid CSP. No unsafe-eval, no unsafe-inline, restricts to extension resources only.

## Vulnerability Findings

### 1. Resume Data Upload to Firebase Storage
**Severity**: LOW
**Category**: Privacy Concern (Legitimate Feature)

**Files**:
- `/js/full_page_uploader.js` (lines 261-276)
- `/firebase-init.js` (lines 7-14)

**Description**:
The extension uploads user resumes (PDF/DOCX) to Firebase Storage at `jobalytics.appspot.com`. Resume parsing happens client-side using pdf.js and mammoth.js libraries, but the raw resume file is uploaded to cloud storage.

**Code Evidence**:
```javascript
// full_page_uploader.js
function storeResume(file, path, then) {
   if (path == null || path == "") {
      path = "no_email_" + generate_uuid();
   }
   const storageRef = ref(storage, "resumes/" + path);
   uploadBytes(storageRef, file)
      .then(() => { then(); })
      .catch((error) => {
         trackEvent("resume_save_error", "error", error);
         then();
      });
}
```

**Firebase Configuration** (Public API Keys - Expected for Frontend):
```javascript
const firebaseConfig = {
   apiKey: "AIzaSyAcAaHbimH9lfJ9nx3ma3OCEDKDI2URlIo",
   authDomain: "jobalytics.firebaseapp.com",
   projectId: "jobalytics",
   storageBucket: "jobalytics.appspot.com",
   messagingSenderId: "351217594342",
   appId: "1:351217594342:web:3d299befebae6864f07027",
   measurementId: "G-N7E5N8SE44"
};
```

**Verdict**: **Not a vulnerability**. Resume upload is an intentional feature for cloud-based resume management. Firebase API keys are public by design in web/extension apps. Security depends on Firebase Storage Rules (not visible in extension code).

**Recommendation**: Users should be aware their resumes are uploaded to cloud storage. Privacy policy link is provided (`jobalytics.co/privacy-policy`).

---

### 2. Job Data Collection to Firestore
**Severity**: LOW
**Category**: Data Collection (Legitimate Feature)

**Files**:
- `/js/background.js` (lines 304-371)
- `/js/createPersistentScore.js` (lines 232-251)

**Description**:
The extension saves analyzed job descriptions to Firestore database including job title, location, employer, source, and full job description text.

**Code Evidence**:
```javascript
// background.js
function storeJob(job_data) {
   var job = job_data.job;
   var url = job_data.url;

   if (job != "") {
      var title = job_data.job_title;
      var loc = job_data.job_loc;
      var employer = job_data.job_employer;
      var source = job_data.source;

      jobs_collection
         .doc(doc_id)
         .set({
            version: 2,
            job: job,
            url: url,
            timestamp: new Date().getTime(),
            title: title,
            location: loc,
            employer: employer,
            source: source,
         })
   }
}
```

**Verdict**: **Not a vulnerability**. Job data collection enables features like job history and match tracking. Users trigger this by scanning job descriptions.

---

### 3. Third-Party Job Recommendation API (Neuvoo.com)
**Severity**: LOW
**Category**: Third-Party Data Sharing

**Files**:
- `/js/background.js` (lines 436-488)

**Description**:
The extension fetches job recommendations from `neuvoo.com` API, passing job search parameters, user's resume text, and navigator.userAgent.

**Code Evidence**:
```javascript
// background.js
function get_job_recs(search_title, loc, last_page_fetched, last_num_recs_fetched, cb) {
   var rec_url = new URL("https://neuvoo.com/services/api-new/search");
   rec_url.searchParams.append("publisher", "13761a14");
   rec_url.searchParams.append("chnl1", "chrome_extension");
   rec_url.searchParams.append("format", "json");
   rec_url.searchParams.append("k", search_title);
   rec_url.searchParams.append("l", loc);
   rec_url.searchParams.append("radius", 64);
   rec_url.searchParams.append("country", "us");
   rec_url.searchParams.append("jobdesc", 1);
   rec_url.searchParams.append("contenttype", "all");
   rec_url.searchParams.append("ip", "1.1.1.1");
   rec_url.searchParams.append("useragent", navigator.userAgent);
   rec_url.searchParams.append("limit", 25);

   fetch(rec_url.href)
      .then((res) => res.json())
      .then((result) => {
         if ("results" in result) {
            cb(default_to(result["results"], []), page_fetched);
         }
      })
}
```

**Triggered Conditions**:
- User is on a job search page (LinkedIn/Indeed)
- Extension has stored resume
- At least 5 jobs have been scanned for baseline scoring
- Time thresholds met (15s between attempts, 3-12 hour refresh cycles)

**Data Shared**:
- Job search title and location
- User's browser user-agent
- Publisher ID: "13761a14"

**Verdict**: **Not a vulnerability**. This is an affiliate job recommendation system. Resume text is NOT sent to Neuvoo - only used locally for match filtering. However, users should be aware of third-party job API integration.

---

### 4. Google Analytics Tracking
**Severity**: LOW
**Category**: Standard Analytics

**Files**:
- `/js/background.js` (lines 40-78)
- `/js/full_page_uploader.js` (lines 4-40)
- Multiple UI pages

**Description**:
Extension uses Google Analytics 4 (GA4) for event tracking. Two measurement IDs found:
- `G-NB84M0TM7E` (primary)
- `G-GW4YJG7SK9` (uploader page)

**Events Tracked**:
- `resume_upload` - Resume upload actions
- `scan_job_desc` - Job description scans
- `job_recommendation` - Job rec fetch/save events
- `persistent_score` - Score display events
- `page_view` - Page navigation

**Client ID Generation**:
```javascript
chrome.storage.local.get("ga_client_id", (data) => {
   const clientId = data.ga_client_id || `GA1.1.${crypto.randomUUID().replace(/-/g, "")}`;
   if (!data.ga_client_id) {
      chrome.storage.local.set({ ga_client_id: clientId });
   }
});
```

**Verdict**: **Not a vulnerability**. Standard analytics implementation. Uses anonymized client IDs, no PII in events.

---

### 5. Glassdoor "stags.bluekai.com" Domain Reference
**Severity**: INFORMATIONAL
**Category**: Legacy Code or Tracking Domain

**Files**:
- `/js/background.js` (lines 130, 195, 397)

**Description**:
Extension checks for `stags.bluekai.com` as a supported job board domain in three locations. BlueKai was Oracle's data management platform (acquired 2014, sunset ~2024).

**Code Evidence**:
```javascript
function is_persistent_score_supported(url) {
   return (
      // ... other job boards ...
      url.hostname == "stags.bluekai.com" ||
      url.hostname.endsWith("joinhandshake.com")
   );
}
```

**Verdict**: **Not a vulnerability**. Likely outdated code for Glassdoor's former tracking domain. No active data collection to this domain. Could be removed in future versions.

---

## False Positive Analysis

| Pattern | Location | Explanation | Verdict |
|---------|----------|-------------|---------|
| Firebase Public API Keys | `firebase-init.js`, `background.js` | Firebase web SDK requires public-facing API keys. Security enforced via Firebase Rules (server-side). | **FP - Expected** |
| `innerHTML` usage | `createPersistentScore.js:296` | Setting match score HTML from local template file via `chrome.runtime.getURL()`. No user input. | **FP - Safe** |
| `eval`/`Function()` in vendors | `pdf.min.js`, `mammoth.browser.js` | Third-party libraries (PDF.js, Mammoth) for document parsing. Standard library code. | **FP - Library Code** |
| Broad host permissions | `manifest.json` | `http://*/*` and `https://*/*` declared but unused. Extension only operates on job board sites. | **FP - Over-permission** |
| `.send()` patterns in libraries | jQuery, PDF.js, Mammoth | XMLHttpRequest usage in vendor libraries for internal operations (not network). | **FP - Library Internal** |

## API Endpoints & Data Flow

| Endpoint | Purpose | Data Sent | Frequency |
|----------|---------|-----------|-----------|
| `neuvoo.com/services/api-new/search` | Job recommendations | Job title, location, user-agent, publisher ID | Conditional (job search pages, 15s throttle) |
| `google-analytics.com/debug/mp/collect` | Event tracking | Event names, anonymized client ID, timestamps | Per user action |
| `jobalytics.firebaseapp.com` (Firestore) | Job data storage | Job title, employer, location, description, URL | Per job scan |
| `jobalytics.appspot.com` (Storage) | Resume file storage | Resume PDF/DOCX file | Per resume upload |
| `jobalytics.co/*` | Redirect/landing pages | User ID (UUID), UTM parameters | Install, uninstall, links |

### Data Flow Summary

1. **User uploads resume** → Client-side parsing (PDF.js/Mammoth) → Local storage + Firebase Storage upload
2. **User scans job description** → DOM scraping (job boards) → Keyword matching (local) → Match score display → Firestore save
3. **Job recommendations** → Resume keywords (local) + search params → Neuvoo API → Filtered results (local matching)
4. **Persistent score** → Resume (local storage) + Job description (DOM) → Match calculation → Injected UI element

## Malicious Behavior Assessment

### ❌ Not Found (Good)
- XHR/Fetch hooking or interception
- Extension enumeration or killing
- Keylogging or input monitoring
- Cookie harvesting
- Credential theft
- Ad injection or search manipulation
- Remote code execution capabilities
- Residential proxy infrastructure
- WebRTC IP leak exploitation
- Market intelligence SDKs (Sensor Tower, etc.)
- AI conversation scraping
- Screen capture outside stated functionality
- Dynamic permission requests
- Obfuscated or packed code (beyond vendor libraries)

### ✅ Present (Expected)
- Resume text extraction (stated purpose)
- Job description DOM scraping (stated purpose)
- Firebase data uploads (cloud resume storage)
- Google Analytics tracking (standard telemetry)
- Third-party job API (affiliate recommendations)

## Security Best Practices Observed

1. **Manifest V3** - Using modern extension platform
2. **Strong CSP** - No `unsafe-eval` or `unsafe-inline`
3. **Module-based architecture** - ES6 imports, clean code structure
4. **No eval/Function usage** (in extension code, only vendor libs)
5. **UUID-based anonymization** - GA client IDs use crypto.randomUUID()
6. **Error handling** - Try-catch blocks around DOM parsing
7. **Scoped content injection** - Only on supported job board pages

## Privacy Concerns (Transparent)

1. **Resume Cloud Storage**: Users should understand their resumes are uploaded to Firebase. Privacy policy accessible via UI.
2. **Job Description Collection**: Full job post text saved to Firestore for history/matching.
3. **Third-Party Job API**: Neuvoo.com receives job search queries and user-agent (no resume content).
4. **Analytics Tracking**: Standard GA4 event tracking of user actions within extension.

## Recommendations

### For Users
- Review privacy policy at `jobalytics.co/privacy-policy` before uploading resume
- Understand resume files are stored in cloud (Firebase)
- Job history is saved for match tracking features
- Third-party job recommendations involve Neuvoo.com API

### For Developers
1. **Reduce Permission Scope**: Replace `http://*/*` and `https://*/*` with explicit job board domains:
   ```json
   "host_permissions": [
     "https://www.linkedin.com/*",
     "https://www.indeed.com/*",
     "https://www.glassdoor.com/*",
     "https://*.myworkdayjobs.com/*",
     "https://*.joinhandshake.com/*"
   ]
   ```
2. **Remove Legacy Code**: Delete `stags.bluekai.com` references (Oracle BlueKai sunset)
3. **Privacy Transparency**: Add prominent notice about resume cloud upload in UI
4. **Firebase Rules Audit**: Ensure Firebase Storage/Firestore rules properly restrict access to user data
5. **API Key Rotation**: Consider using Firebase App Check to prevent API abuse

## Overall Risk Rating: **LOW** ✅

### Justification
- Functionality aligns with stated purpose (resume-job keyword matching)
- No malicious patterns detected (no XHR hooks, extension killing, keyloggers, etc.)
- Data collection is transparent and necessary for core features
- Code quality is good (MV3, strong CSP, modular structure)
- Third-party integrations are legitimate (Neuvoo job API, Firebase backend, GA4)
- No obfuscation or anti-analysis techniques

### Risk Breakdown
- **Malware Risk**: CLEAN (0/10)
- **Privacy Risk**: LOW (3/10) - Resume upload, job history collection
- **Security Risk**: LOW (2/10) - Overly broad permissions, third-party API
- **Transparency**: MEDIUM-HIGH (7/10) - Privacy policy provided, but in-app notices could be clearer

## Conclusion

Jobalytics is a **CLEAN** extension that performs legitimate resume optimization functionality. While it collects resume and job data for cloud-based features, this aligns with its stated purpose. No malicious behavior patterns were identified. The primary concerns are privacy-related (resume cloud storage) rather than security-based, and these are disclosed via privacy policy.

Users seeking resume-job matching tools can use this extension with confidence, provided they accept the privacy trade-offs of cloud resume storage and job history tracking.

---

**Analysis Completed**: 2026-02-06
**Analyst**: Claude Opus 4.6 (Automated Security Analysis)
**Files Analyzed**: 32 JavaScript files, manifest.json, 13 HTML pages
**Code Review Depth**: Full deobfuscated source code inspection
