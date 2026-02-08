# Security Analysis Report: Email Finder for LinkedIn - LeadLeaper

## Extension Metadata
- **Extension Name:** Email Finder for LinkedIn - LeadLeaper
- **Extension ID:** iojojcfflmfcejodomoafimdiianbgfe
- **Version:** 7.3.19
- **Users:** ~100,000
- **Manifest Version:** 3
- **Analysis Date:** 2026-02-07

---

## Executive Summary

LeadLeaper is a legitimate LinkedIn lead generation tool that scrapes user profiles, company data, and contact information from LinkedIn to provide email discovery and lead management services. The extension operates as intended - collecting extensive personal and professional data from LinkedIn profiles and transmitting it to the vendor's backend infrastructure.

**Overall Risk Level: MEDIUM**

While the extension performs invasive data collection, it does so transparently as part of its core business model. The primary concerns are:
1. **Extensive data harvesting** from LinkedIn (names, titles, companies, profile URLs, images)
2. **PII transmission** to remote servers without encryption of the payload
3. **Broad permissions** that enable comprehensive LinkedIn tracking
4. **Limited obfuscation** making the data exfiltration patterns clear
5. **No evidence of malicious intent**, but significant privacy implications for LinkedIn users

---

## Vulnerability Details

### 1. MEDIUM: Mass Personal Data Harvesting from LinkedIn
**Severity:** MEDIUM
**Files:** `lbg.js` (lines 358-550), `js/lcs.js` (lines 328-500), `js/lcss.js`
**Category:** Privacy/Data Collection

**Description:**
The extension systematically scrapes comprehensive personal and professional information from LinkedIn profiles and search results, including:

**Data Harvested:**
- Full names, titles, locations
- Company names, websites, employee counts, industries
- Profile URLs (LinkedIn URNs and public profile URLs)
- Profile images
- Contact information discovery (emails, phone numbers)
- Company size, location, phone numbers
- Employment history

**Evidence from Code:**
```javascript
// lbg.js:405-550 - captureLead3 endpoint collects:
{
  gVer: extVer,
  aID: user.aID,
  aN: user.aN,
  ufN: user.ufN,
  ulN: user.ulN,
  uID: user.uID,
  glc: user.glc,
  ucc: user.ucc,
  llglp: user.llglp,
  fn: e,
  ccwF: c.ccwF,
  pID: c.pspo.pID,
  pscF: c.pscF,
  addBtnF: t,
  pspo: c.pspo  // Profile/company data object
}
```

```javascript
// lcs.js:373-482 - Sales Navigator list scraping:
j = {
  urn: l,
  msUPN: i,
  snF: salesNavFlag,
  n: p,        // Full name
  nm: p,       // Full name
  loc: h,      // Location
  emp: g,      // Employer
  ttl: o,      // Title
  iurl: c,     // Image URL
  ifn: s,      // Image filename
  incID: n,    // Company ID
  cwpu: e      // Company website URL
}
```

**Verdict:** This is **legitimate business functionality** for a lead generation tool, but the scale and automation of LinkedIn data collection raises privacy concerns. LinkedIn's Terms of Service prohibit automated scraping.

---

### 2. MEDIUM: Unencrypted PII Transmission
**Severity:** MEDIUM
**Files:** `lbg.js` (lines 104-137, 405-550)
**Category:** Data Security

**Description:**
The extension transmits collected profile data to `https://aws.leadleaper.net/` via HTTPS POST requests. While the transport uses HTTPS, the request bodies are encoded but not encrypted:

```javascript
// lbg.js:104-125
function postDataNoReply(e, r, c, s) {
  fetch(gURLs + a, {  // gURLs = "https://aws.leadleaper.net/"
    method: "POST",
    headers: {
      "Content-Type": o ? "application/x-www-form-urlencoded" : "application/json"
    },
    body: o ? getEncodedData(n) : encodeURIComponent(JSON.stringify(n))
  })
}
```

**Data Endpoints:**
- `captureLead3` - Profile data collection
- `captureLeadUpdt3` - Profile updates
- `captureCompany3` - Company data collection
- `ComChk3` - Company verification
- `AJAX_LeadsCAP` - Bulk lead capture
- `AJAX_Login` - User authentication
- `edc` - Discovery credit checks

**Verdict:** Standard HTTPS transport is used, but JSON payloads containing PII are only URL-encoded, not additionally encrypted. This is **common practice** for web extensions but exposes data to potential interception at the application layer.

---

### 3. LOW: Extensive LinkedIn Monitoring
**Severity:** LOW
**Files:** `manifest.json`, `js/lcss.js`, `js/lcs.js`
**Category:** Tracking/Monitoring

**Description:**
Content scripts inject into all LinkedIn pages (`*://*.linkedin.com/*`) at both `document_start` and `document_end`, enabling comprehensive monitoring:

**Manifest Permissions:**
```json
"content_scripts": [
  {
    "matches": ["*://*.linkedin.com/*"],
    "js": ["js/jquery-3.5.1.min.js", "js/lcss.js"],
    "run_at": "document_start",
    "all_frames": false
  },
  {
    "matches": ["*://*.linkedin.com/*"],
    "js": ["js/jquery-3.5.1.min.js", "js/lcs.js"],
    "run_at": "document_end",
    "all_frames": false
  }
]
```

**Monitoring Capabilities:**
- Profile page visits (`/in/`, `/sales/lead/`, `/sales/profile/`)
- Company pages (`/company/`, `/school/`)
- Search results (`/search/results/people`, `/sales/search`)
- Recruiter profiles (`/recruiter/profile/`)
- Sales Navigator lists (`/sales/lists/people/`)

**Verdict:** Required for core functionality. Extension legitimately needs to monitor LinkedIn navigation to trigger data collection workflows.

---

### 4. LOW: Automated Lead Capture Workflows
**Severity:** LOW
**Files:** `lbg.js` (lines 675-904, 1178-1283)
**Category:** Automation

**Description:**
The extension implements automated workflows to process LinkedIn search results pages sequentially:

```javascript
// lbg.js:1178-1283 - LeadsCAPnxtPg: Auto-navigate to next search page
function LeadsCAPnxtPg(e, r) {
  if (bckGrnd.LeadsCAPo.LeadsCAPcntr < bckGrnd.LeadsCAPo.LeadsCAPpgs) {
    edcChk({  // Check discovery credits
      gVer: extVer,
      uID: user.uID,
      glc: user.glc,
      dcm: user.dcm,
      fn: e + ".LeadsCAPnxtPg",
      restartFlag: r.restartFlag,
      CAPaddPgF: r.CAPaddPgF
    })
  }
}
```

```javascript
// lbg.js:675-833 - Queue processing for bulk lead extraction
function SrchResultsProc(e, c) {
  bckGrnd.SrchResCWarray.length ?
    (n = bckGrnd.SrchResCWarray.shift()) :
  bckGrnd.SrchResCWempIDarray.length ?
    (n = bckGrnd.SrchResCWempIDarray.shift()) :
  bckGrnd.SrchResSNarray.length &&
    (n = bckGrnd.SrchResSNarray.shift())
}
```

**Verdict:** Automation violates LinkedIn's Terms of Service but is **expected behavior** for a commercial lead generation tool. Not malware.

---

### 5. LOW: Chrome Tab Manipulation
**Severity:** LOW
**Files:** `lbg.js` (lines 785-822)
**Category:** User Experience

**Description:**
The extension creates and controls background tabs to process LinkedIn profiles:

```javascript
// lbg.js:785-822
chrome.tabs.get(bckGrnd.SrchTabID, function(e) {
  chrome.tabs.update(bckGrnd.SrchTabID, {
    url: d  // Navigate to next profile
  }, function() {})
})
```

**Verdict:** Legitimate functionality for processing queued profiles. User-initiated action triggers the workflow.

---

## False Positives

| Pattern | Location | Reason for Exclusion |
|---------|----------|---------------------|
| jQuery 3.5.1 | `js/jquery-3.5.1.min.js` | Legitimate library, not malicious |
| `innerHTML` usage | Throughout content scripts | Standard DOM manipulation for UI rendering |
| `chrome.tabs` API | `lbg.js` | Required for multi-tab lead processing workflows |
| `chrome.storage.local` | `lbg.js`, `js/lcs.js` | Legitimate local state persistence |
| Error reporting to server | `lbg.js:139-186` | Standard telemetry (`js_er` endpoint) |

---

## API Endpoints

| Endpoint | Purpose | Data Transmitted |
|----------|---------|-----------------|
| `https://aws.leadleaper.net/captureLead3` | Profile data collection | User ID, profile name, title, company, location, URLs, image URLs |
| `https://aws.leadleaper.net/captureLeadUpdt3` | Profile updates | Contact info updates (emails, phone numbers) |
| `https://aws.leadleaper.net/captureCompany3` | Company data | Company name, website, size, industry, location |
| `https://aws.leadleaper.net/ComChk3` | Company verification | Company domain validation |
| `https://aws.leadleaper.net/AJAX_LeadsCAP` | Bulk capture status | Lead counts, processing status |
| `https://aws.leadleaper.net/AJAX_Login` | Authentication | User credentials, extension ID, version |
| `https://aws.leadleaper.net/edc` | Credit checks | Discovery credit balance queries |
| `https://aws.leadleaper.net/js_er` | Error reporting | Extension errors, stack traces, user context |
| `https://aws.leadleaper.net/debug` | Debug logging | Debug messages (only if `devFlag=true`) |
| `https://aws.leadleaper.net/watoken` | Web app token | SSO token generation for web dashboard |
| `https://aws.leadleaper.net/signlog` | Installation tracking | Extension install/login redirection |

---

## Data Flow Summary

### 1. Profile Collection Flow
```
LinkedIn Profile Page → Content Script (lcs.js) →
Background Script (lbg.js) → captureLead3 API →
Backend Database → User's LeadLeaper Account
```

**Data Collected:**
- Profile: Name, title, location, profile URL, profile image
- Company: Name, website, size, industry
- Contact: Email (discovered), phone number

### 2. Search Results Flow
```
LinkedIn Search Results → Content Script (lcs.js) →
Queue in Background (bckGrnd.SrchResCWarray) →
Sequential Tab Processing → Individual Profile Collection →
AJAX_LeadsCAP batch status updates
```

**Automation:** Extension can process 10-100+ search results automatically based on user's plan.

### 3. Company Data Flow
```
LinkedIn Company Page → Content Script (lcs.js) →
ComChk3 API (domain validation) →
captureCompany3 API → Backend Storage
```

---

## Privacy Implications

### For LinkedIn Users (Targets)
- **Profile scraping:** Names, titles, companies, images collected without consent
- **Contact discovery:** Extension attempts to find/verify email addresses
- **Tracking:** All profile views by LeadLeaper users are logged
- **Third-party storage:** Data stored on LeadLeaper servers indefinitely

### For Extension Users
- **Account linking:** LinkedIn activity tied to LeadLeaper account ID
- **Usage tracking:** All searches, profile views, captures logged
- **Quota enforcement:** "Discovery credits" system tracks/limits usage

---

## Overall Risk Assessment

**Risk Level: MEDIUM**

### Rationale:
1. **Not Malware:** Extension performs as advertised - lead generation from LinkedIn
2. **Privacy Concerns:** Extensive automated scraping of PII from third-party site
3. **ToS Violations:** Likely violates LinkedIn Terms of Service (automated scraping)
4. **Data Security:** Standard HTTPS transport but no additional payload encryption
5. **Transparency:** Users knowingly install for lead generation purposes
6. **Business Model:** Legitimate SaaS product with paid tiers

### Comparison to Malware:
- ❌ No credential theft
- ❌ No ad injection
- ❌ No cryptocurrency mining
- ❌ No keylogging
- ❌ No cookie harvesting for other sites
- ✅ Data collection is core advertised functionality
- ✅ Requests appropriate permissions
- ✅ No obfuscation or anti-analysis techniques

### Risk Factors:
- ⚠️ Mass PII collection from third-party platform
- ⚠️ Automated workflows that violate LinkedIn ToS
- ⚠️ Potential for abuse if credentials compromised
- ⚠️ No user consent from scraped LinkedIn profiles

---

## Recommendations

### For Users:
1. Be aware extension tracks **all LinkedIn browsing** when active
2. Collected data is stored on LeadLeaper's servers
3. LinkedIn may ban accounts using automated scraping tools
4. Review LeadLeaper's privacy policy for data retention

### For Security Analysts:
1. **Not malware** - legitimate business tool with privacy implications
2. Monitor for updates that expand data collection scope
3. Verify backend endpoints remain limited to `leadleaper.net` domain
4. Check for credential handling changes (currently uses OAuth-like tokens)

---

## Conclusion

Email Finder for LinkedIn - LeadLeaper is a **legitimate commercial extension** that performs extensive automated data collection from LinkedIn. While it raises significant privacy concerns and likely violates LinkedIn's Terms of Service, it operates transparently within its stated purpose as a lead generation tool. The extension does not exhibit malicious behaviors typical of malware (credential theft, ad injection, cryptocurrency mining, etc.).

**Classification:** Commercial SaaS tool with aggressive data collection practices
**Threat Level:** Low to users who install it; Medium to LinkedIn users being scraped
**Recommendation:** Monitor but do not flag as malware
