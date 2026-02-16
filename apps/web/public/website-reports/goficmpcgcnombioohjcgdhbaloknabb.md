# Security Analysis Report: Note Board - Sticky Notes App

## Extension Metadata
- **Extension ID**: goficmpcgcnombioohjcgdhbaloknabb
- **Name**: Note Board - Sticky Notes App
- **Version**: 9.0.33
- **Users**: ~200,000
- **Author**: Oscar de Dios
- **Homepage**: https://www.noteboardapp.com
- **Manifest Version**: 3

## Executive Summary

Note Board is a sticky notes/note-taking extension with a **MEDIUM risk** profile. The extension contains **Amazon affiliate link injection** that automatically modifies user-created Amazon links to include the developer's affiliate tags. Additionally, it uses broad optional permissions that could enable content scraping, though these require explicit user consent. The extension collects user data through an account system and syncs notes via Firebase Realtime Database for premium users. While the monetization via affiliate injection is undisclosed and potentially deceptive, there is no evidence of malicious data exfiltration, XHR/fetch hooking, or extension enumeration/killing behavior.

**Key Concerns:**
1. **Amazon affiliate link injection** - Silently modifies user content for revenue
2. **Broad optional permissions** - Could enable content scraping if granted
3. **User tracking** - Login system with user data collection
4. **Firebase integration** - Real-time sync of note content to third-party database
5. **OAuth credentials** - Google OAuth client ID embedded in manifest

## Vulnerability Details

### 1. Amazon Affiliate Link Injection
**Severity**: MEDIUM
**Type**: Undisclosed Monetization / Content Manipulation
**Scope**: User-created notes containing Amazon links

**Technical Details**:
The extension automatically injects affiliate tags into Amazon links created by users in their notes. The `convert_Amazon()` function scans note content for Amazon URLs and appends affiliate parameters:

**File**: `sw/backgroundSw.js`, `popupMin.js`, `popup2Min.js`, `backgroundMin.js`, `backgroundBuild.js`

**Affected Code (backgroundSw.js:3096-3098)**:
```javascript
function convert_Amazon(e) {
  for (var a, t = 0, o = 0, n = 0; e.indexOf('<a href="https://www.amazon.com', n) > -1 && -1 == e.indexOf("tag=", n + 10) && t < 10;) t++, o = e.indexOf('<a href="https://www.amazon.com', n), n = e.indexOf('"', o + 27), a = e.substring(o, n), e = a.indexOf("?") > -1 ? e.substring(0, n) + "&tag=notboa-20" + e.substring(n) : e.substring(0, n) + "?tag=notboa-20" + e.substring(n);
  for (t = 0, n = 0; e.indexOf('<a href="https://www.amazon.es', n) > -1 && -1 == e.indexOf("tag=", n + 10) && t < 10;) t++, o = e.indexOf('<a href="https://www.amazon.es', n), n = e.indexOf('"', o + 27), a = e.substring(o, n), e = a.indexOf("?") > -1 ? e.substring(0, n) + "&tag=notboa-21" + e.substring(n) : e.substring(0, n) + "?tag=notboa-21" + e.substring(n);
  for (t = 0, n = 0; e.indexOf('<a href="https://www.amazon.co.uk', n) > -1 && -1 == e.indexOf("tag=", n + 10) && t < 10;) t++, o = e.indexOf('<a href="https://www.amazon.co.uk', n), n = e.indexOf('"', o + 27), a = e.substring(o, n), e = a.indexOf("?") > -1 ? e.substring(0, n) + "&tag=wwwnoteboarda-21" + e.substring(n) : e.substring(0, n) + "?tag=wwwnoteboarda-21" + e.substring(n);
  return e
}
```

**Affiliate Tags Injected**:
- amazon.com → `tag=notboa-20`
- amazon.es → `tag=notboa-21`
- amazon.co.uk → `tag=wwwnoteboarda-21`

**Behavior**:
- Triggered when notes are processed through `compruebaVideos()` function
- Only modifies links that don't already have an affiliate tag
- Affects up to 10 Amazon links per note
- Works on Amazon.com, Amazon.es, and Amazon.co.uk
- Not disclosed in Chrome Web Store description or privacy policy

**Verdict**: This is undisclosed monetization that manipulates user content. While the extension skips links that already have affiliate tags (avoiding conflicts with users' own affiliate programs), the behavior is not transparent and could be considered deceptive.

---

### 2. Broad Optional Permissions
**Severity**: MEDIUM
**Type**: Over-Permissioning
**Scope**: Requires user consent

**Manifest Permissions**:
```json
"optional_permissions": [
  "tabs",
  "background",
  "clipboardRead",
  "desktopCapture",
  "identity",
  "identity.email"
],
"optional_host_permissions": [
  "https://www.noteboardapp.com/",
  "http://*/*",
  "https://*/*"
]
```

**Required Permissions** (granted on install):
```json
"permissions": [
  "contextMenus",
  "unlimitedStorage",
  "activeTab",
  "storage",
  "scripting",
  "alarms",
  "offscreen"
]
```

**Analysis**:
- The `http://*/*` and `https://*/*` optional host permissions allow the extension to inject content scripts on any webpage (with user consent)
- Used for legitimate features like web clipping and page capture
- Context menu entries request these permissions when triggered (`chrome.permissions.request()`)
- Desktop capture permission enables screen recording/capture features
- Identity permissions used for OAuth login (Google, Facebook)

**Code Example** (background.js:333-338):
```javascript
function creaNotaWeb(e, a) {
  chrome.permissions.request({
    permissions: ["tabs"],
    origins: ["http://*/*", "https://*/*"]
  }, (async function(t) {
    t && (await recoverChromeStorage(), creaPopupNota(...))
  }))
}
```

**Verdict**: Permissions are optional and require explicit user consent. The extension properly prompts users before accessing broad web content. However, the breadth of access (all websites) creates risk if permissions are granted carelessly.

---

### 3. User Data Collection & Backend Communication
**Severity**: LOW
**Type**: User Tracking / Data Sync
**Scope**: Logged-in users

**Backend Endpoints**:
| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| https://www.noteboardapp.com/api/login2.php | User login | username, password, reCAPTCHA token |
| https://www.noteboardapp.com/api/loginFb.php | Facebook OAuth login | Facebook ID, token, name |
| https://www.noteboardapp.com/api/loginGoogle2.php | Google OAuth login | Google ID token |
| https://www.noteboardapp.com/api/registraUsuarioApi.php | User registration | username, password, email |
| https://www.noteboardapp.com/api/subirAwsCaptura.php | Screenshot upload | user ID, base64 image data |
| https://www.noteboardapp.com/api/subirAwsVideo.php | Video upload | user ID, video blob |
| https://www.noteboardapp.com/api/getUserSubscription.php | Premium subscription data | user ID, auth token |
| https://www.noteboardapp.com/creditcard/createCustomerPortal.php | Stripe customer portal | user ID, auth token |
| https://www.noteboardapp.com/api/getUserFilesSpace.php | Calculate storage usage | list of all notes |

**OAuth Configuration**:
```json
"oauth2": {
  "client_id": "409932428860-djmrl7hfsuk4fo55s474bt48l3p37o0h.apps.googleusercontent.com",
  "scopes": [
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/userinfo.email"
  ]
}
```

**Data Synced**:
- Complete note content (text, images, attachments)
- Note positions, sizes, colors, metadata
- User credentials (hashed/token-based)
- Screenshots and videos uploaded to AWS S3 (`noteboardapp.s3.amazonaws.com`)
- Board sharing configurations

**Storage**:
- AWS S3 for media files
- Firebase Realtime Database for real-time sync (premium users)
- Backend server at noteboardapp.com for user accounts

**Verdict**: Standard SaaS architecture with user accounts and cloud sync. Data collection is expected for a note-sync service. Privacy policy should clearly describe data handling. No evidence of covert data exfiltration.

---

### 4. Firebase Realtime Database Integration
**Severity**: LOW
**Type**: Third-Party Data Sync
**Scope**: Premium users with shared boards

**Firebase Configuration** (backgroundSw.js:4164-4170):
```javascript
firebase.initializeApp({
  apiKey: "AIzaSyAX48wcrExFdN--o728Pdrc8CPED_SdQ0E",
  authDomain: "note-board-web.firebaseapp.com",
  databaseURL: "https://note-board-web.firebaseio.com",
  projectId: "note-board-web",
  storageBucket: "note-board-web.appspot.com",
  messagingSenderId: "1053127044847"
})
```

**Behavior**:
- Firebase used only for real-time board collaboration (premium feature)
- Syncs note changes between users sharing a board
- Data path: `users/{userId}/board/{boardId}/treeId/{noteId}`
- Enabled when user shares a board or accesses shared board
- Automatically goes offline when not viewing shared boards

**Code** (backgroundSw.js:4184-4217):
```javascript
function sendRealTime(e, a, t = tablonActual) {
  if ("undefined" != typeof firebase && isPremiumUser() && isUserConnected() && esTablonCompartido(t) && localStorage["treeId" + e]) {
    // Constructs note data object
    var r = {
      postit: o,
      tipoA: localStorage["tipoA" + e],
      X: localStorage["X" + e],
      Y: localStorage["Y" + e],
      width: localStorage["width" + e] || 0,
      height: localStorage["height" + e] || 0,
      treeId: localStorage["treeId" + e] || 0,
      // ... more fields
    }
    firebase.database().ref("users/" + n[i].id_usuarioComp + "/board/" + n[i].tabCompRemoto + "/treeId/" + localStorage["treeId" + e]).set(r)
  }
}
```

**Verdict**: Firebase is used appropriately for real-time collaboration features. The API key is client-side (normal for Firebase Web SDK) and should have proper security rules configured server-side. Data exposure risk depends on Firebase security rules, which cannot be audited from extension code.

---

### 5. Content Script Injection (Optional Permission)
**Severity**: LOW
**Type**: Web Content Access
**Scope**: User-initiated, requires permission grant

**Content Scripts**:
- `inject.js` - Displays sticky notes on web pages
- `injectSelect.js` - Text selection capture
- `injectReadability.js` - Readable text extraction

**Inject Script** (inject.js:158-203):
The extension injects jQuery and jQuery UI to display notes on web pages. Notes are retrieved via `chrome.runtime.sendMessage` and rendered as draggable/resizable elements.

**Behavior**:
- Only injected when user has notes saved for specific URLs
- Notes are attached to specific web pages ("web notes")
- Uses `chrome.tabs.onUpdated` listener to auto-inject when user visits page with notes
- Users can create web notes via context menu (requires permission prompt)

**Verdict**: Legitimate feature for attaching notes to web pages. Requires user permission for broad host access. No evidence of covert content scraping or data harvesting from web pages.

---

### 6. Screen Capture & Recording
**Severity**: LOW
**Type**: Sensitive Data Capture
**Scope**: User-initiated

**Features**:
- Screenshot capture (`chrome.tabs.captureVisibleTab`)
- Desktop capture (`desktopCapture` permission, requires user consent)
- Video recording (`recordScreen.js`)

**Upload to AWS** (background.js:238-254):
```javascript
function subeCaptura(e, a, t) {
  var o = "id_usuario=" + localStorageP.id_usuario;
  o += "&captura=" + encodeURIComponent(a), $.ajax({
    type: "POST",
    url: "https://www.noteboardapp.com/api/subirAwsCaptura.php",
    data: o,
    cache: !1,
    success: function(a) {
      var o = JSON.parse(a);
      o.isSuccess && guardaPostitBackground('<a href="' + e + '" target="_blank" >' + e.split("?")[0] + '</a><br><a href="' + e + '" target="_blank" ><img src="https://noteboardapp.s3.amazonaws.com/users/screenshots/' + o.url + '" width="100%"/></a>', {
        menuItemId: t
      })
    }
  })
}
```

**Verdict**: Screen capture features are user-initiated and clearly labeled in context menus. Uploaded screenshots are stored on AWS S3 under user's account. No evidence of covert screen capture.

---

## False Positives

| Pattern | Context | Verdict |
|---------|---------|---------|
| `eval()` / `Function()` in TinyMCE | Third-party rich text editor library | **FALSE POSITIVE** - Standard TinyMCE behavior |
| `eval()` / `atob()` in jQuery libraries | Minified jQuery, jQuery UI, date picker libraries | **FALSE POSITIVE** - Legitimate library code |
| `document.cookie` in emoji libraries | TinyMCE emoticons plugin data structures | **FALSE POSITIVE** - Not actual cookie access |
| Firebase API key exposed | Client-side Firebase Web SDK config | **FALSE POSITIVE** - Normal Firebase pattern, security via backend rules |
| OAuth client ID in manifest | Standard OAuth 2.0 configuration | **FALSE POSITIVE** - Public OAuth client ID (normal) |
| `XMLHttpRequest` in TinyMCE | Image upload/proxy feature in rich text editor | **FALSE POSITIVE** - Legitimate editor functionality |

---

## API Endpoints Summary

| Domain | Purpose | Data Flow |
|--------|---------|-----------|
| www.noteboardapp.com | Backend API server | User auth, note sync, subscription management |
| noteboardapp.s3.amazonaws.com | AWS S3 storage | Screenshot/video uploads |
| note-board-web.firebaseio.com | Firebase Realtime Database | Real-time board collaboration |
| accounts.google.com | Google OAuth | User authentication |
| graph.facebook.com | Facebook Graph API | User authentication |
| www.paypal.com | PayPal subscriptions | Premium subscription payments |
| fonts.googleapis.com | Google Fonts | Font loading for notes |

---

## Data Flow Summary

1. **User Registration/Login**:
   - User credentials → `www.noteboardapp.com/api/` → Server database
   - OAuth tokens → Google/Facebook APIs → Backend verification
   - Session tokens stored in `chrome.storage.local` + `localStorage`

2. **Note Creation/Editing**:
   - Notes stored in `localStorage` (local-first)
   - Logged-in users: Notes uploaded to backend API
   - Premium users: Real-time sync via Firebase
   - Amazon links modified to include affiliate tags

3. **Media Uploads**:
   - Screenshots/videos → `www.noteboardapp.com/api/` → AWS S3 bucket
   - Media URLs embedded in note content
   - Storage quota tracked per user

4. **Board Sharing**:
   - Sharing invitations → Backend API → Recipient notification
   - Shared board updates → Firebase Realtime Database → All collaborators
   - Access control enforced via backend

---

## Privacy & Security Concerns

### Concerns
1. **Amazon affiliate injection not disclosed** in Chrome Web Store listing or visible privacy policy
2. **All note content uploaded to backend** when user logs in (expected for sync service, but should be clearly disclosed)
3. **Firebase API key exposed in code** (requires proper security rules configuration, cannot verify from client)
4. **Broad optional permissions** (`http://*/*`, `https://*/*`) - risk if users grant without understanding scope
5. **OAuth client ID public** (normal for OAuth, but can be used to impersonate extension if backend doesn't validate)

### Positive Security Practices
✓ Permissions properly gated with `chrome.permissions.request()`
✓ No XHR/fetch prototype manipulation
✓ No extension enumeration or killing
✓ No residential proxy infrastructure
✓ No AI conversation scraping
✓ No cookie harvesting from arbitrary websites
✓ Uses Manifest V3 service worker architecture
✓ CSP configured in manifest (sandbox policy)
✓ Uninstall survey URL set (`https://www.noteboardapp.com/uninstallext`)

---

## Overall Risk Assessment

**Risk Level**: **MEDIUM**

### Risk Breakdown
- **Data Exfiltration**: LOW - Standard cloud sync for note-taking app
- **Content Manipulation**: MEDIUM - Amazon affiliate injection without disclosure
- **Permission Abuse**: LOW - Optional permissions properly gated
- **Third-Party SDKs**: LOW - Firebase used appropriately for collaboration
- **User Tracking**: LOW-MEDIUM - Standard account system with cloud sync

### Recommendations

**For Users**:
1. Be aware that Amazon links in your notes will be modified to include developer affiliate tags
2. Only grant optional permissions if you use web clipping features
3. Understand that logged-in accounts sync all note content to developer's servers
4. Review sharing settings if collaborating on boards with others
5. Consider privacy implications of uploading screenshots/videos to AWS S3

**For Developer**:
1. **Disclose Amazon affiliate injection** in Chrome Web Store description and privacy policy
2. Clarify data retention and storage policies for user notes
3. Document Firebase security rules configuration
4. Implement end-to-end encryption option for privacy-conscious users
5. Add user opt-out for Amazon affiliate injection
6. Reduce scope of optional permissions where possible

**For Chrome Web Store Review**:
1. Review Amazon affiliate injection for compliance with monetization policies
2. Verify privacy policy adequately describes data collection
3. Ensure OAuth implementation follows best practices
4. Check Firebase security rules prevent unauthorized access

---

## Conclusion

Note Board is a legitimate sticky notes extension with cloud sync capabilities. The primary concern is **undisclosed Amazon affiliate link injection**, which modifies user content for developer revenue without transparency. While this doesn't constitute data theft or malware, it represents deceptive behavior that should be disclosed to users. The extension's broad optional permissions and user data sync are appropriate for its functionality but require careful user consideration before granting access. There is no evidence of malicious data harvesting, remote code execution, or other severe security vulnerabilities.

**Verdict**: MEDIUM risk due to undisclosed monetization. Core functionality is legitimate, but transparency improvements needed.
