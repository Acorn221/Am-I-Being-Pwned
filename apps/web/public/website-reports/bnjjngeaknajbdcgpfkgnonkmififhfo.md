# Security Analysis: Fake Filler

**Extension ID:** bnjjngeaknajbdcgpfkgnonkmififhfo
**Version:** 4.1.0
**Users:** ~400,000
**Risk Level:** LOW

## Executive Summary

Fake Filler is a legitimate developer tool for automatically filling forms with randomized test data. Despite the static analyzer flagging 15 "exfiltration flows," detailed code analysis reveals these are all false positives — they represent Firebase SDK operations for syncing user preferences to the cloud, not exfiltration of actual form data. The extension generates dummy data locally and never transmits it off the page.

## Core Functionality

The extension provides three primary functions:
1. Fill all inputs on a page with random dummy data
2. Fill a specific form
3. Fill a single input field

Data generation is entirely local using predefined templates for emails, names, phone numbers, addresses, etc. The generated values (e.g., "jack@mailinator.com", "Pa$$w0rd!") are injected directly into form fields and never leave the webpage.

## Static Analysis Findings Investigation

### Cookie Harvesting Flag — FALSE POSITIVE

**Finding:** `document.cookie` access detected
**Reality:** Firebase Authentication SDK reads `__FIREBASE_DEFAULTS__` cookie to configure emulator settings
**Code location:** `rl=()=>{if(typeof document>"u")return;let n;try{n=document.cookie.match(/__FIREBASE_DEFAULTS__=([^;]+)/)}catch{return}const t=n&&Bs(n[1]);return t&&JSON.parse(t)}`

**Analysis:** This is standard Firebase SDK behavior for development/testing configurations. Not harvesting user cookies. The extension does not access or transmit any cookies related to user browsing data.

### PostMessage No Origin Flag — FALSE POSITIVE

**Finding:** `postMessage` without origin validation
**Reality:** Internal React component communication in bundled UI
**Analysis:** The postMessage calls are part of the React/Redux state management system within the extension's options page (index.html). These are internal to the extension popup/options UI, not cross-origin communication with external sites.

### Remote Config Flag — LEGITIMATE BUT SAFE

**Finding:** Firebase Firestore remote configuration
**Code:** `async function qm(n){if(yn&&br&&br.subscribed){const t=Fm();return await Mm(es(as,"settings",yn.uid),{options:JSON.stringify(n),updatedAt:t},{merge:!0}),t}return null}`

**Analysis:** This is a **premium feature** that syncs extension configuration (field templates, custom fill rules) to Firebase for authenticated users. Key points:
- Only saves user's custom settings (field match patterns, templates, ignored domains)
- Requires Firebase Authentication (uid-gated)
- Only available to paid subscribers (`br.subscribed` check)
- Stores: `{options: JSON.stringify(config), updatedAt: timestamp}`
- Does NOT transmit filled form data

### 15 Exfiltration Flows — FALSE POSITIVES

**Static analyzer detected:**
- `chrome.storage.local.get → fetch/Image` (15 instances)
- `document.getElementById → fetch/Image`
- `document.querySelectorAll → fetch/Image`

**Reality:** These are Firebase SDK network operations. Breaking down the data flow:

1. **Source:** `chrome.storage.local.get("options")` retrieves user's extension configuration
2. **Data:** Field templates like `{type:"email", emailHostnameList:["mailinator.com"], match:["email"]}`
3. **Sink:** Firebase Firestore `setDoc()` for cloud sync (premium users only)
4. **Image constructor:** Part of Firebase's network transport layer (beacon fallback)

**Critical distinction:** The "options" object contains **configuration metadata** (how to generate fake data), not actual form field values. Example options data:
```javascript
{
  version: 1,
  fields: [{type:"email", emailHostnameList:["mailinator.com"]}],
  passwordSettings: {mode:"defined", password:"Pa$$w0rd!"},
  ignoreDomains: []
}
```

This is analogous to a text editor syncing user preferences (font size, theme) — not the document content.

## Verified Behavior

**Form data generation flow:**
1. User clicks extension icon or context menu
2. Extension executes `fillAllInputs()` in page context
3. `generateDummyDataForCustomField()` creates random values locally:
   - Emails: `scrambledWord().toLowerCase() + "@mailinator.com"`
   - Names: Random selection from hardcoded lists (Jl, Xl arrays)
   - Numbers: `Math.random()` within specified ranges
4. Values injected via `element.value = generatedValue`
5. **No network transmission of generated form data**

**Chrome storage usage:**
- Saves only: user's custom field templates, ignored domains, UI preferences
- Does NOT save: actual form data entered on websites

**Firebase usage:**
- Authentication: Optional sign-in for premium features
- Firestore: Syncs extension settings (templates/rules) for authenticated users
- No form data transmitted

## Security Assessment

### Permissions Review
- `activeTab`: Required to inject form-filling logic into current page ✓
- `storage`: Stores user preferences locally ✓
- `scripting`: Executes form-filling functions ✓
- `contextMenus`: Adds right-click menu options ✓

All permissions justified for stated functionality.

### Network Communication
- **Firebase Auth:** `fake-filler.firebaseapp.com` (authentication only)
- **Firestore:** `firestore.googleapis.com` (user settings sync for premium)
- **No third-party analytics or tracking detected**

### Code Quality
- Open-source React/TypeScript codebase
- Uses standard Firebase SDK (v4.6.5)
- Minified/bundled but legitimate build output
- No obfuscation beyond standard webpack bundling

## Privacy Analysis

**Data the extension CAN access:**
- Form fields on active tab (only when user triggers fill action)
- User's custom field configuration (templates, domains to ignore)

**Data the extension DOES collect:**
- For authenticated users: extension settings/preferences
- Authentication state (if user signs in for premium)

**Data the extension DOES NOT collect:**
- Actual form data generated or filled
- Browsing history
- Cookies (except Firebase's own auth cookie)
- Personal information from forms

## Risk Assessment

**Overall Risk: LOW**

### Strengths
1. Clear, legitimate functionality (developer testing tool)
2. No actual form data exfiltration
3. Firebase usage limited to settings sync (premium feature)
4. Standard permissions for form-filling use case
5. Large user base (400K) with positive reviews (4.4/5)

### Weaknesses
1. Bundled code makes audit more difficult (but not suspicious)
2. Firebase API key exposed in client code (normal for Firebase, but worth noting)
3. Premium feature requires cloud account (some users may prefer fully offline)

### False Positive Analysis
The ext-analyzer's high risk score (62) and 15 exfil flows are misleading because:
- Firebase SDK network calls are flagged as "Image constructor exfiltration"
- Settings sync (configuration data) classified as data exfiltration
- The analyzer cannot distinguish Firebase SDK from malicious beaconing

This is a known limitation of static analysis on legitimate cloud-integrated extensions.

## Recommendations

**For Users:**
- Safe to use for its intended purpose (form testing)
- Premium features require Firebase account (optional)
- Free tier works entirely offline

**For Developers:**
- Consider adding privacy policy link in manifest
- Document Firebase usage in extension description
- Offer fully offline mode for privacy-conscious users

## Conclusion

Fake Filler is a legitimate, safe developer tool. The flagged "vulnerabilities" are false positives caused by the static analyzer misidentifying Firebase SDK operations as malicious exfiltration. The extension's actual behavior — generating random test data locally and optionally syncing user preferences to Firebase — poses no security risk to users.

**Verdict:** CLEAN — No vulnerabilities or malicious behavior detected.
