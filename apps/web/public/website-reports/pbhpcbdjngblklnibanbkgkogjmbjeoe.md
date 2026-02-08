# Vulnerability Assessment Report: Image Translator - Comics Translator | Manga Translator

## Extension Metadata
- **Extension ID**: pbhpcbdjngblklnibanbkgkogjmbjeoe
- **Name**: Image Translator - Comics Translator | Manga Translator
- **Version**: 6.7.7
- **User Count**: ~60,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

Image Translator is a legitimate image translation extension with **privacy concerns** due to third-party telemetry integration and excessive permissions. The extension uses Alibaba Cloud ARMS (Application Real-time Monitoring Service) SDK for error tracking and analytics, sending user data to Chinese cloud infrastructure. While the core translation functionality appears legitimate, the combination of broad permissions, screenshot capture capabilities, and external telemetry creates a significant privacy risk profile.

**Overall Risk Level**: **MEDIUM**

The extension is not malware but exhibits privacy-invasive telemetry practices that warrant user awareness.

---

## Vulnerability Details

### 1. Third-Party Telemetry to Chinese Infrastructure (MEDIUM)

**Severity**: MEDIUM
**File**: `assets/contentLogger.js-TDUqHSu2.js` (lines 32-44, 2032-2098)
**Verdict**: Privacy Concern

**Description**:
The extension integrates Alibaba Cloud ARMS SDK (`BrowserLogger`) which sends error reports, usage metrics, and user identifiers to Alibaba Cloud infrastructure in China.

**Evidence**:
```javascript
// contentLogger.js-TDUqHSu2.js:2032-2044
const se = e => _t.singleton({
  pid: "aa9hucpddy@f07435a50fe14e0",
  uid: e,  // User email from chrome.identity
  appType: "web",
  disableHook: !0,
  behavior: !1,
  enableLinkTrace: !1,
  autoSendPerf: !1,
  disableApiPerf: !0,
  disableResourcePerf: !0,
  disableError: !0,
  imgUrl: "https://arms-retcode.aliyuncs.com/r.png?"
});

// Telemetry endpoints (lines 36-45)
regionMap: {
  cn: "https://arms-retcode.aliyuncs.com/r.png?",
  sg: "https://arms-retcode-sg.aliyuncs.com/r.png?",
  us: "https://retcode-us-west-1.arms.aliyuncs.com/r.png?",
  // ... other regions
}

// Usage tracking (lines 2046-2094)
function Et(e) {
  chrome.storage.sync.get(["g_user_info"]).then(({g_user_info: t}) => {
    const r = t.email,
      n = se(r);
    n.sum("bgTranslate", 1), n.error(new Error(JSON.stringify(e)), {
      filename: "点击图标开始翻译",
      lineno: 384,
      colno: 18
    })
  })
}
```

**Impact**:
- User email addresses (from `chrome.identity.email`) are sent to Alibaba Cloud as unique identifiers
- Translation usage events, errors, and metadata are tracked and transmitted
- Data flows to Chinese cloud infrastructure (`aliyuncs.com`), raising jurisdiction concerns
- While error tracking is disabled (`disableError: true`), custom error logging still occurs

**Mitigation**: This is legitimate telemetry for product analytics, but users should be aware their email and usage patterns are shared with Alibaba Cloud.

---

### 2. Screenshot Capture with Broad Scope (MEDIUM)

**Severity**: MEDIUM
**File**: `assets/background.js-CMDT0ex2.js` (line 159), `assets/popup-Ckes4y4W.js` (line 22333)
**Verdict**: Functional but Privacy-Invasive

**Description**:
The extension uses `chrome.tabs.captureVisibleTab` to capture screenshots of the active tab for translation purposes.

**Evidence**:
```javascript
// background.js-CMDT0ex2.js:159
chrome.tabs.captureVisibleTab(n=>{
  console.log("发送了截屏数据",n),
  chrome.tabs.sendMessage(s.id,{type:"base64",data:n})
})

// popup-Ckes4y4W.js:22333
chrome.tabs.captureVisibleTab(X => {
  // Processes screenshot for translation
})
```

**Impact**:
- Extension can capture full visible tab screenshots on demand
- Combined with `<all_urls>` host permissions, this works on any website
- Screenshots are uploaded to third-party services (`ai.imgkits.com`, `video.deletetweets.ai`) for translation
- No explicit user consent flow shown for screenshot capture beyond initial translation request

**Mitigation**: Screenshot capture is necessary for the translation feature, but the broad scope creates privacy risk if the extension were compromised.

---

### 3. Excessive Host Permissions (LOW)

**Severity**: LOW
**File**: `manifest.json` (lines 49-52)
**Verdict**: Over-Permissioned

**Description**:
The extension requests `http://*/*` and `https://*/*` host permissions, granting access to all websites.

**Evidence**:
```json
"host_permissions": [
  "http://*/*",
  "https://*/*"
]
```

**Impact**:
- Content scripts run on `<all_urls>` with `all_frames: true` and `match_about_blank: true`
- Extension can interact with any website the user visits
- Increases attack surface if extension were compromised

**Mitigation**: This is common for image translation extensions that need to work on any site, but represents a large permission scope.

---

### 4. User Email Collection via Identity API (MEDIUM)

**Severity**: MEDIUM
**File**: `assets/background.js-CMDT0ex2.js` (lines 158+)
**Verdict**: Privacy Concern

**Description**:
The extension uses `chrome.identity.getProfileUserInfo` to collect user email addresses without explicit consent dialog.

**Evidence**:
```javascript
// background.js:158+
function V(){
  return new Promise(async(t,e)=>{
    let r=await chrome.storage.sync.get(["g_user_info"]);
    r.g_user_info?t(r.g_user_info):
    chrome.identity.getProfileUserInfo({accountStatus:"ANY"},i=>{
      console.log("userInfo",i),
      t(i),
      chrome.storage.sync.set({g_user_info:i})
    })
  })
}

// Sent to backend (line 158+)
async function S(t){
  let e=await V();
  let r=e.id;
  const s=await he({
    url:`https://www.livepolls.app/image_translator/api/user/status?email=${e.email}`,
    method:"POST",
    data:{email:e.email,app_type:"chrome_addon",uuid:r}
  });
  return chrome.storage.sync.set({jwt:s.jwt,user:s,getUserDateNow:Date.now()}),s
}
```

**Impact**:
- User's Google account email is collected automatically
- Email is used as telemetry UID and sent to both `livepolls.app` and Alibaba Cloud ARMS
- Persistent identifier enables long-term user tracking
- Permission declared in manifest (`identity.email`) but no explicit consent shown to user

**Mitigation**: Email collection should require explicit opt-in consent dialog.

---

### 5. Remote Image Upload to Third-Party CDN (LOW)

**Severity**: LOW
**File**: `assets/background.js-CMDT0ex2.js` (lines 1+)
**Verdict**: Functional but Noteworthy

**Description**:
Images are uploaded to third-party services for translation processing.

**Evidence**:
```javascript
// Multipart upload to ai.imgkits.com
async function f(o,u,l,a){
  const p="https://video.deletetweets.ai",
  const E=(await(await fetch("https://ai.imgkits.com/upload/initiate-upload",{
    method:"POST",
    headers:{"Content-Type":"application/json",Channel:"node-nauth"},
    body:JSON.stringify({bucketName:l,objectName:m,contentType:o.type})
  })).json()).UploadId
  // ... multipart upload logic
}

// Translation API calls
const c=async(o,u,l,a="1",p,m="noto")=>
  fetch("https://ai.imgkits.com/img-translate/create",{
    method:"POST",
    headers:{"Content-Type":"application/json",authorization:"Bearer "+r,channel:"ai"},
    body:JSON.stringify({imgs:o,from:u,to:l,paste:a,userId:p,font:m})
  })
```

**Impact**:
- User-selected images and screenshots are uploaded to `ai.imgkits.com` and `video.deletetweets.ai`
- No privacy policy link visible in manifest or code
- Images may contain sensitive information (emails, documents, personal photos)
- JWT bearer token authentication used

**Mitigation**: This is expected behavior for cloud-based translation, but users should be aware images leave their device.

---

## False Positives

| Pattern | Location | Reason for Exclusion |
|---------|----------|---------------------|
| Alibaba Cloud ARMS SDK | `contentLogger.js` | Legitimate telemetry SDK, not malware (but privacy-invasive) |
| `captureVisibleTab` | `background.js`, `popup.js` | Required for screenshot translation feature |
| Image upload to CDN | `background.js` | Necessary for cloud-based OCR/translation processing |
| JWT tokens in storage | `background.js` | Standard authentication pattern |
| Chinese language comments | `background.js` (e.g., "上传成功结果") | Developer comments, not obfuscation |

---

## API Endpoints and Data Flows

| Endpoint | Purpose | Data Sent | Risk Level |
|----------|---------|-----------|------------|
| `https://arms-retcode.aliyuncs.com/r.png?` | Alibaba Cloud ARMS telemetry | User email, error logs, usage counters | **MEDIUM** |
| `https://ai.imgkits.com/api/generate-presigned-url` | R2/S3 upload token generation | Bucket name, object name | LOW |
| `https://ai.imgkits.com/upload/initiate-upload` | Multipart upload initialization | Image metadata, content type | LOW |
| `https://ai.imgkits.com/img-translate/create` | Translation job creation | Image URLs, source/target languages, user ID | LOW |
| `https://ai.imgkits.com/img-translate/status` | Poll translation job status | Job ID | LOW |
| `https://www.livepolls.app/image_translator/api/user/status` | User authentication | Email, UUID, app type | **MEDIUM** |
| `https://www.livepolls.app/image_translator/api/order/download` | Usage counter decrement | Translation count | LOW |
| `https://video.deletetweets.ai/{filename}` | Translated image CDN | (Response only) | LOW |

---

## Data Flow Summary

1. **User Authentication**:
   - Extension collects Google account email via `chrome.identity.email`
   - Email sent to `livepolls.app` backend for authentication
   - JWT token returned and stored in `chrome.storage.sync`

2. **Image Translation**:
   - User right-clicks image or uses popup interface
   - Image uploaded to `ai.imgkits.com` via multipart upload
   - Translation job created with user ID, language preferences
   - Translated image URL returned from `video.deletetweets.ai` CDN

3. **Telemetry**:
   - User email used as Alibaba Cloud ARMS UID
   - Translation events, errors tracked: `bgTranslate`, `popupTranslate`
   - Data sent to `arms-retcode.aliyuncs.com` (Chinese infrastructure)

4. **Content Script Behavior**:
   - Hover icon injected on images >200px
   - Click triggers translation flow via background script
   - Translated images replace original `src` attribute

---

## Chrome API Usage

| API | Purpose | Risk Level |
|-----|---------|------------|
| `chrome.identity.email` | Collect user email address | **MEDIUM** - Persistent identifier |
| `chrome.storage.sync` | Store user data, JWT, preferences | LOW - Standard practice |
| `chrome.contextMenus` | Right-click "Translate Image" option | LOW - Functional |
| `chrome.scripting.executeScript` | Inject translation UI dialogs | LOW - Functional |
| `chrome.tabs.captureVisibleTab` | Screenshot capture | **MEDIUM** - Privacy-sensitive |
| `chrome.tabs.query` | Find active tab | LOW - Functional |
| `chrome.tabs.sendMessage` | Content script communication | LOW - Functional |
| `chrome.runtime.sendMessage` | Background script messaging | LOW - Functional |
| `chrome.sidePanel` | Display panel UI | LOW - Functional |

---

## Security Observations

### Positive Security Practices:
1. **Manifest V3**: Uses modern manifest version with service workers
2. **No Dynamic Code Execution**: No `eval()`, `Function()`, or `document.write()`
3. **No Cookie Harvesting**: No access to `document.cookie` or `chrome.cookies` API
4. **No Keylogging**: No input field monitoring detected
5. **No Extension Enumeration**: Does not query or kill competing extensions
6. **No XHR/Fetch Hooking**: Does not intercept network requests globally
7. **JWT Authentication**: Uses industry-standard bearer tokens
8. **HTTPS Only**: All network requests use secure connections

### Privacy Concerns:
1. **Email Collection Without Consent**: Automatic collection of Google account email
2. **Third-Party Telemetry**: Alibaba Cloud ARMS SDK with Chinese infrastructure
3. **Broad Permissions**: `<all_urls>` host permissions and screenshot access
4. **No Privacy Policy Link**: No visible privacy policy in manifest or extension pages
5. **Screenshot Upload**: User images/screenshots uploaded to third-party CDN

### No Evidence Of:
- Ad injection or coupon replacement
- Market intelligence SDKs (Sensor Tower, Pathmatics)
- Residential proxy infrastructure
- AI conversation scraping
- Remote kill switches or config fetching
- Extension fingerprinting/killing
- Cryptocurrency mining
- Credential harvesting

---

## Recommendations

### For Users:
1. **Be Aware**: Your email and translation usage are tracked by Alibaba Cloud
2. **Sensitive Content**: Avoid translating images with sensitive/private information
3. **Review Permissions**: Understand the extension can access all websites and capture screenshots
4. **Consider Alternatives**: If privacy is a concern, use local OCR/translation tools

### For Developers:
1. **Add Privacy Policy**: Include clear privacy policy link in manifest and welcome page
2. **Explicit Consent**: Show consent dialog before collecting email via `chrome.identity`
3. **Reduce Permissions**: Consider using `activeTab` instead of `<all_urls>` where possible
4. **Telemetry Opt-Out**: Provide user option to disable Alibaba Cloud ARMS telemetry
5. **Data Retention**: Document how long images/data are retained on servers

---

## Overall Risk Assessment

**Risk Level**: **MEDIUM**

### Justification:
The extension is **not malware** but exhibits **privacy-invasive practices** that users should be aware of. The combination of:
- Automatic email collection without explicit consent
- Third-party telemetry to Chinese cloud infrastructure (Alibaba Cloud ARMS)
- Broad host permissions (`<all_urls>`)
- Screenshot capture capabilities
- Lack of transparent privacy policy

...creates a **medium-risk privacy profile**. The core functionality (image translation) is legitimate and the code contains no overtly malicious behavior. However, the data collection and telemetry practices exceed what many users would expect from an image translation tool.

### Not Classified as HIGH/CRITICAL Because:
- No malware, credential theft, or ad injection detected
- No residential proxy or botnet infrastructure
- Telemetry is for legitimate product analytics (not data exfiltration)
- Image upload is necessary for cloud-based translation
- No evidence of selling user data or secondary monetization

### Classified as MEDIUM Because:
- Alibaba Cloud ARMS telemetry to Chinese infrastructure
- Email collection without explicit user consent
- Excessive permissions create attack surface
- Lack of transparency around data practices

---

## Conclusion

Image Translator is a functional, legitimate extension with privacy concerns stemming from third-party telemetry integration and broad permission requests. Users concerned about privacy should be aware their email and usage patterns are tracked by Alibaba Cloud. The extension would benefit from improved transparency through a visible privacy policy and user consent mechanisms.

**Verdict**: **Privacy-Invasive but Not Malicious**
