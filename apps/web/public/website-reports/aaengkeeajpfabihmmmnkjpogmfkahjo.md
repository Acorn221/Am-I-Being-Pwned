# Security Analysis: TxtAnalyser (aaengkeeajpfabihmmmnkjpogmfkahjo)

## Extension Metadata
- **Name**: TxtAnalyser
- **Extension ID**: aaengkeeajpfabihmmmnkjpogmfkahjo
- **Version**: 2.3.0
- **Manifest Version**: 3
- **Estimated Users**: ~300,000
- **Developer**: Texthelp / Wizkids (wizkids.dk, texthelp.com)
- **Analysis Date**: 2026-02-14

## Executive Summary
TxtAnalyser is a **legitimate educational writing assistant tool** with **LOW risk**. This Danish educational technology product from Wizkids/Texthelp provides grammar checking, translation, and writing assistance for students and teachers, primarily in Nordic countries. The extension collects usage analytics including tab URLs and grammar statistics, sending them to `stats.appwriterlog.wizkids.dk` and Google Analytics. While this data collection is disclosed and serves legitimate educational product improvement purposes, privacy-conscious users should be aware of its scope.

**Overall Risk Assessment: LOW**

## Vulnerability Assessment

### 1. Tab URL Collection for Analytics
**Severity**: LOW
**Files**:
- `/js/BYvr-Lff5.js` (lines 910-911, 922, 929, 940-944)
- `/js/uL4DV9aYcl.js` (line 520)

**Analysis**:
The extension collects active tab URLs and sends them to two analytics endpoints:

#### Flow 1: Google Analytics (GA4)
```javascript
// Line 910-911: Extracts website context from tab URL
var Pc=async(a,b,c,d,e={})=>{
  a=new Ac(Hc,{...Oc,F:{width:d.F.width,height:d.F.height},G:d.G},a,b,c);
  a.C=d.C;  // d.C is the website URL
  if(d.C)try{
    const g=new URL(d.C);
    var f=g.host.match(/word-edit\.officeapps\.live\.com$/)&&g.pathname.match(/^\/we\/wordeditorframe\.aspx/)?"Microsoft Word":
    "docs.google.com"===g.host&&g.pathname.match(/^(\/a\/[^/]+)?\/document\/(d|u)\//i)?"Google Docs":
    "docs.google.com"===g.host&&g.pathname.match(/^(\/a\/[^/]+)?\/presentation\/d\//i)?"Google Slides":"Page"
  }
  // ... sends to google-analytics.com/mp/collect with measurement ID G-HTCHM7E0L4
}
```

**Data Transmitted to Google Analytics**:
- Full tab URL (website parameter)
- Screen type ("Google Docs", "Microsoft Word", "Google Slides", or "Page")
- User email (SHA-256 hashed)
- System info: timezone, platform, device type, OS, browser version, screen resolution, DPI
- Event name, category, feature
- Session ID and engagement time

**Code Evidence** (Line 903):
```javascript
a=await fetch(`${"https://www.google-analytics.com/mp/collect"}?measurement_id=${encodeURIComponent("G-HTCHM7E0L4")}&api_secret=${encodeURIComponent("4kDeRvRkR1en-N7tTzXCUA")}`,
  {method:"POST",body:JSON.stringify(a)});
```

#### Flow 2: Wizkids Statistics Server
```javascript
// Line 63: Lb() function sends stats to Wizkids
async function Lb(a,b){
  b=b||{};
  b.product="TxtAnalyser Chrome";
  b={data:JSON.stringify(b)};
  const c=await w(x),d=[];
  for(const e in b)d.push(encodeURIComponent(e)+"="+encodeURIComponent(b[e]));
  a=await (new q).request("POST","https://stats.appwriterlog.wizkids.dk"+a,{
    body:d.join("&"),
    headers:{
      "LingApps-Application":"txtanalyser_chrome",
      "LingApps-User-Session-ID":c&&c.session?c.session.sessionId:null,
      "Content-type":"application/x-www-form-urlencoded"
    }
  });
}
```

**Usage Statistics Collected** (Lines 917-918):
```javascript
"TextAnalyzer.stats.sentenceCompleted":async function(a,b,c){
  a={time:Date.now(),data:{language:c,tokens:a,characters:b}};
  try{await Lb("/txtAnalyser/sentenceCompleted",a)}
  catch(d){throw"USER_SID_INVALID"===d.name&&await z(),d;}
},
"TextAnalyzer.stats.grammarError":async function(a){
  a={time:Date.now(),data:a};
  try{await Lb("/txtAnalyser/grammarError",a)}
  catch(b){throw"USER_SID_INVALID"===b.name&&await z(),b;}
}
```

**Data Sent to stats.appwriterlog.wizkids.dk**:
- Sentence completion events: timestamp, language, token count, character count
- Grammar error events: timestamp, full error details (type, corrections, context)
- User session ID (when logged in)

#### Flow 3: Tab URL Access for Domain Detection
```javascript
// Line 929, 46-47: getCurrentTabURL implementation
var J=async()=>{
  var a=await chrome.tabs.query({active:!0,currentWindow:!0});
  a=0<a.length?a[0]:null;
  if(!a)return null;
  const b="number"===typeof a.id?
    await chrome.webNavigation.getAllFrames({tabId:a.id})||[]:[];
  return{windowId:a.windowId,tabId:"number"===typeof a.id?a.id:null,
    url:a.url||null,frames:b}
};

"getCurrentTabURL":async function(){
  const a=await J();
  return a?a.url:null
}
```

**Purpose**:
- Content script checks current tab URL to determine if it's a supported document editor
- Badge updates based on domain (enabled/disabled/not supported)
- Grammar checking only activates on whitelisted domains (Google Docs, Word Online, etc.)

**Privacy Implications**:
- **Tab URLs are sent to external servers** during analytics events
- Only URLs of pages where the extension is active (Google Docs, Word Online, etc.)
- For logged-in users, URLs are linked to hashed email addresses
- Data helps Wizkids/Texthelp track which document platforms students use

**Justification**:
This is **standard analytics behavior** for educational SaaS products. Teachers and administrators using Wizkids typically have agreements covering student data collection. However, **users should be aware** that:
1. Document URLs (not content) are tracked
2. Analytics link URL usage to user accounts
3. Data flows to both Wizkids (Denmark) and Google Analytics (USA)

**Verdict**: **LOW RISK** - Disclosed analytics for educational product; typical for edtech SaaS.

---

### 2. Obfuscated Code
**Severity**: N/A (Standard Build Process)
**Files**: All JavaScript files in `/js/` directory

**Analysis**:
The ext-analyzer flagged the extension as "obfuscated". Analysis confirms this is **standard minification**, not deliberate malicious obfuscation:

**Evidence**:
- Variable names minified to single letters (a, b, c, x, I, J, etc.)
- Google Closure Compiler copyright notices present
- Logic is straightforward and readable after deobfuscation
- No string encoding, eval(), or anti-debugging techniques
- API endpoints and measurement IDs visible in plaintext

**Verdict**: **NOT MALICIOUS** - Standard production build optimization.

---

## Network Activity Analysis

### External Endpoints

| Domain | Purpose | Data Transmitted | Frequency |
|--------|---------|------------------|-----------|
| `txtanalyser-ecs.texthelp.com` | Grammar/translation API (Texthelp ECS) | Text content, language, grammar requests | Per grammar check |
| `services.lingapps.dk` | User authentication & profile sync | Login credentials, session tokens, user profiles | On login/sync |
| `stats.appwriterlog.wizkids.dk` | Educational usage analytics | Sentence stats, grammar errors, timestamps, session ID | Per writing event |
| `www.google-analytics.com` | Product analytics (GA4) | Event tracking, website URLs, hashed user email, system info | Per feature use |
| `account.wizkids.dk` | Account management | User account data | User-initiated |
| `akademi.wizkids.dk` | Wizkids learning platform | Unknown (likely course integration) | Unknown |

### Data Flow Summary

**Data Collection**: Extensive analytics for educational product improvement
**User Data Transmitted**: Tab URLs, grammar statistics, hashed email, system info, session IDs
**Tracking/Analytics**: Google Analytics (GA4) + Wizkids internal stats
**Third-Party Services**: Google Analytics, Texthelp ECS

**Sensitive Data Handling**:
- Text content sent to `txtanalyser-ecs.texthelp.com` for grammar checking (expected)
- User emails are SHA-256 hashed before sending to Google Analytics
- Session IDs link analytics events to logged-in users
- Tab URLs collected when extension is active on documents

**Educational Context**:
This is a **school-deployed extension** where data collection typically falls under:
1. Student data privacy agreements between schools and Wizkids
2. GDPR compliance for EU/Nordic users
3. Educational technology data handling standards

**No evidence of**:
- Selling user data to third parties
- Cross-site tracking beyond documented analytics
- Residential proxy infrastructure
- Ad injection or affiliate fraud

---

## Permission Analysis

| Permission | Justification | Risk Level |
|------------|---------------|------------|
| `tabs` | Access current tab URL for domain detection and analytics | Medium (enables URL tracking) |
| `webNavigation` | Inject content scripts in Google Docs/Word Online frames | Low (functional) |
| `webRequest` | OAuth redirect handling during login | Low (authentication flow) |
| `declarativeNetRequest` | Block unwanted OAuth redirects during login | Low (security measure) |
| `storage` | Store user settings, session tokens, analytics queue | Low (local data) |
| `scripting` | Inject grammar checking UI into documents | Low (core feature) |
| `alarms` | Periodic service health checks | Low (maintenance) |
| `host_permissions: <educational domains>` | Access Google Docs, Word Online, uni-login, etc. | Medium (broad but scoped to education platforms) |

**Assessment**: All permissions are justified for declared functionality. The `tabs` permission combined with analytics endpoints enables URL tracking, which is the primary privacy concern.

---

## Content Security Policy
```json
"extension_pages": "script-src 'self'; object-src 'self'"
```
**Note**: Strong CSP prevents inline script execution and external script loading. No violations detected.

---

## Code Quality Observations

### Positive Indicators
1. No dynamic code execution (`eval()`, `Function()`)
2. No remote code loading
3. No XHR/fetch hooking or prototype pollution
4. No extension enumeration or killing
5. No residential proxy infrastructure
6. Strong authentication flows with multiple providers (Google, UNI-Login, Microsoft, Feide)
7. License validation for paid features (not circumventable)
8. Session validation and automatic logout on service unavailability
9. Clean separation of concerns (background, content, popup scripts)

### Privacy Concerns
1. **Tab URLs sent to analytics** - Disclosed behavior, but extensive
2. **Google Analytics tracking** - Standard for SaaS, but includes hashed user IDs
3. **Grammar error details tracked** - Teachers may review student writing patterns
4. **No obvious opt-out** - Analytics appear always-on for logged-in users

---

## Comparison to Known Malicious Patterns

| Malicious Pattern | Present? | Evidence |
|-------------------|----------|----------|
| Extension enumeration/killing | ✗ No | No `chrome.management` API usage |
| XHR/fetch hooking | ✗ No | No prototype modifications |
| Residential proxy infrastructure | ✗ No | No proxy configuration |
| AI conversation scraping | ✗ No | No ChatGPT/Claude interception |
| Market intelligence SDKs | ✗ No | No Sensor Tower, Pathmatics, etc. |
| Ad/coupon injection | ✗ No | No DOM manipulation for ads |
| Remote config/kill switches | ✗ No | Only remote API endpoints for core features |
| Cookie harvesting | ✗ No | No cookie access |
| Hidden data exfiltration | ✗ No | All endpoints documented and legitimate |
| Keylogging | ✗ No | No keypress capture |

---

## Educational Technology Context

### Wizkids Background
- **Company**: Wizkids ApS (Denmark) / Texthelp Ltd (UK/Ireland)
- **Product**: Educational writing assistant for Nordic schools
- **Target Users**: Students and teachers in Denmark, Sweden, Norway
- **Integration**: Works with UNI-Login (Danish national school SSO), Google Workspace, Microsoft 365
- **Business Model**: School/district licenses, not consumer-facing

### Typical Deployment
Schools deploy TxtAnalyser as part of a managed Chrome environment where:
1. IT administrators pre-configure the extension
2. Students log in with school credentials (UNI-Login, Google, Microsoft)
3. Teachers review aggregate writing statistics via Wizkids dashboards
4. Data processing agreements exist between schools and Wizkids

### Data Collection Rationale
Educational product analytics serve legitimate purposes:
- **Sentence completion stats**: Measure student writing productivity
- **Grammar error tracking**: Identify common mistakes for curriculum planning
- **Platform usage**: Understand if students write in Google Docs vs Word Online
- **Feature adoption**: Track which grammar layers students enable/disable

**This is standard edtech behavior**, comparable to:
- Google Classroom tracking assignment submissions
- Kahoot tracking quiz performance
- Duolingo tracking lesson progress

---

## Privacy Recommendations for Users

### For Students/Parents
1. **Understand school policies**: Review data processing agreements between your school and Wizkids
2. **GDPR rights**: EU users can request data deletion via account.wizkids.dk
3. **Browser profiles**: Use separate Chrome profiles for school vs personal use to isolate tracking

### For School IT Administrators
1. **Review data flows**: Tab URLs are sent to Google Analytics and Wizkids servers
2. **Consider DPA coverage**: Ensure data processing agreements cover cross-border transfers (Denmark → USA via Google Analytics)
3. **Evaluate alternatives**: If URL tracking is unacceptable, consider on-premise grammar tools
4. **User training**: Inform teachers/students that document URLs are tracked for analytics

### For Privacy-Conscious Users
If you **installed this personally** (not school-managed):
1. **Be aware**: All tab URLs on supported domains are sent to analytics
2. **Logout when not needed**: Analytics appear tied to logged-in sessions
3. **Use privacy-focused alternatives**: Grammarly has similar privacy concerns; consider LanguageTool (self-hosted option available)

---

## Overall Risk Assessment

### Risk Level: **LOW**

**Justification**:
1. **Legitimate educational product** from established edtech companies (Wizkids/Texthelp)
2. **No malicious behavior** - No data theft, no ad injection, no proxy abuse
3. **Disclosed analytics** - Tab URL tracking is typical for educational SaaS products
4. **Scoped permissions** - Only active on whitelisted educational domains
5. **Standard for edtech** - Similar to Google Classroom, Canvas, Schoology data collection
6. **Target audience awareness** - Schools deploying this are aware of data flows

**Privacy Concerns** (factored into LOW rating):
1. Tab URLs sent to analytics servers
2. Grammar error details tracked and potentially reviewed by teachers
3. Google Analytics tracking with hashed user IDs
4. No obvious analytics opt-out for end users

### User Privacy Impact
**MODERATE** - The extension collects more data than a typical consumer grammar checker, but this is **expected and disclosed behavior** for educational technology products deployed in schools.

---

## Recommendations

### For the Extension Developer (Wizkids/Texthelp)
1. **Add privacy controls**: Allow students to opt-out of non-essential analytics
2. **Transparency improvements**: Add in-extension privacy notice explaining what data is collected
3. **Minimize URL logging**: Consider logging only domain (not full URL) for privacy
4. **Data retention policy**: Publish clear retention timelines for analytics data

### For Users
- **No action required** if deployed by your school under existing data agreements
- **Review privacy policy** at wizkids.dk if you installed this personally
- **Consider alternatives** if tab URL tracking is unacceptable for your use case

---

## Technical Summary

**Lines of Code**: 945 (background service worker, deobfuscated)
**External Dependencies**: Google Closure Library (minified)
**Third-Party Libraries**: Material Design Components (MDC) for UI
**Remote Code Loading**: None
**Dynamic Code Execution**: None

---

## Conclusion

TxtAnalyser is a **clean, legitimate educational technology extension** with **LOW risk**. The primary privacy consideration is **tab URL collection** for analytics purposes, which is disclosed behavior and standard for educational SaaS products. Schools deploying this extension should ensure their data processing agreements with Wizkids cover:
1. Cross-border data transfers (Denmark → USA via Google Analytics)
2. Student data retention policies
3. Access controls for teacher analytics dashboards

For the ~300,000 users (primarily Nordic students), this extension operates as advertised with **no malicious behavior detected**. Privacy-conscious personal users should be aware of the analytics scope before installation.

**Final Verdict: LOW RISK** - Safe for use in educational environments with appropriate data processing agreements.
