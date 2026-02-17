# Security Analysis Report: My Doodle

## Extension Metadata

- **Extension ID**: acnonhmkejidodnppipkffhfjbfiogha
- **Name**: My Doodle
- **Version**: 1.1.6
- **Author**: Lovenish Goyal
- **User Count**: 1,000,000+
- **Rating**: 4.1/5
- **Manifest Version**: 3
- **Last Updated**: 2026-02-09

## Executive Summary

**Risk Level: MEDIUM**

My Doodle is a Chrome extension that allows users to customize the Google homepage logo (doodle) with custom text, images, or an animated clock. The extension uses DOM manipulation to replace Google's logo elements on all Google domain homepages and search pages.

While the extension's core functionality is benign (cosmetic customization), it contains a **medium-severity DOM-based XSS vulnerability** due to unsafe use of `innerHTML` with user-controlled data from chrome.storage.local. If an attacker could compromise the user's extension storage (e.g., through a malicious extension, local file access, or browser exploit), they could inject malicious scripts that execute in the context of Google domains.

The extension does not exfiltrate data, contact external servers for analytics/tracking, or perform any overtly malicious behavior. The security risk is primarily defensive - the extension's architecture creates an attack surface that could be exploited by other threats.

## Vulnerability Details

### 1. DOM-Based XSS via innerHTML (MEDIUM Severity)

**Location**: `contentScript.bundle.js` - Multiple injection points in the `c()` function

**Description**: The extension constructs HTML strings containing user-controlled data and injects them directly into the page using `innerHTML` without proper sanitization.

**Code Evidence**:
```javascript
const a = ({pageType:o,doodleText:n,doodleScale:s,doodleMT:r})=>{
    // ... code truncated ...
    const p=g(0,c);  // g() wraps text in colored spans, but doesn't sanitize
    switch(o){
        case e:
            return"<h1  SPLIT style='font-size: "+a+";text-transform: capitalize;;transform:scale("+s/100+");margin-top:"+r+"px;'>"+p+"</h1>";
        // ... more cases
    }
}
```

The `g()` function wraps each character in colored `<span>` elements but doesn't escape HTML:
```javascript
const g=(t,e)=>{
    for(var o="",l=["#4285F4","#EA4335","#FBBC05","#4285F4","#34A853","#ED5F54"],w=0,n=0;n<e.length;n++)
        o=o+"<span style='color:"+l[w++]+";background:none !important;'>",
        o+=e[n],  // Direct concatenation without HTML escaping
        o+="</span>",
        w>=l.length&&(w=0);
    return o
}
```

Injection occurs in the `c()` function:
```javascript
const c=(t,o,r)=>{
    switch(t){
        case e:
            if(null!==document.getElementById("hplogo")){
                // ...
                e.innerHTML=t  // Direct innerHTML assignment
            }
            // ... more injection points via innerHTML
    }
}
```

**Attack Scenario**:
1. Attacker gains write access to chrome.storage.local (via malicious extension, local file manipulation, or browser bug)
2. Attacker sets `doodleText` to: `<img src=x onerror=alert(document.cookie)>`
3. When user visits Google.com, the payload executes in Google's origin
4. Attacker can steal cookies, session tokens, perform actions as the user on Google services

**Impact**:
- **Confidentiality**: HIGH - Can access all data on Google domains (Gmail, Drive, etc.)
- **Integrity**: HIGH - Can modify Google pages, submit forms, change settings
- **Availability**: LOW - Could deface Google pages for the user

**Likelihood**: LOW - Requires compromising chrome.storage.local first, which is non-trivial but possible

**Overall Severity**: MEDIUM (High impact × Low likelihood)

**Recommendation**: Use `textContent` or `innerText` for text-based doodles, or implement proper HTML sanitization using DOMPurify or similar library. For image URLs, validate and sanitize the URL before insertion.

### 2. Unrestricted Image URL Loading (LOW Severity)

**Location**: `contentScript.bundle.js` - Image URL mode

**Description**: Users can specify arbitrary image URLs to display as the Google logo. The default is `https://i.pinimg.com/originals/cd/6a/87/cd6a872ae86e48ee0bd70a6a26818ee5.png`, but users can change this to any URL.

**Code Evidence**:
```javascript
case"IMAGE_URL":
    v=(({pageType:o,doodleImageUrl:n,doodleScale:s,doodleMT:r})=>{
        switch(o){
            case e:
                return"<img  SPLIT style='height:115px;max-height:135px;transform:scale("+s/100+");margin-top:"+r+"px;' alt='Image not loaded' src='"+n+"'/>";
```

**Attack Scenario**:
1. User sets a malicious image URL or attacker modifies storage
2. Image could track user activity (1x1 tracking pixel with user ID in URL)
3. Image could attempt to exploit browser image rendering vulnerabilities
4. Over HTTP, could leak referer information about Google searches

**Impact**:
- **Privacy**: Can track when user visits Google.com
- **Security**: Potential browser exploit surface (though mitigated by modern browser sandboxing)

**Likelihood**: LOW - Requires user cooperation or storage compromise

**Overall Severity**: LOW

**Recommendation**:
- Implement URL whitelist or validate image URLs are HTTPS
- Consider hosting approved images in the extension package
- Use Content Security Policy to restrict image sources

## Network Analysis

**External Domains Contacted**:
1. **i.pinimg.com** (Pinterest CDN)
   - Default doodle image: `https://i.pinimg.com/originals/cd/6a/87/cd6a872ae86e48ee0bd70a6a26818ee5.png`
   - Purpose: Default custom logo image
   - Data transmitted: None (simple image GET request)
   - Risk: LOW - Standard CDN usage, no tracking observed

**No Analytics or Tracking**: The extension does not contain any analytics libraries, tracking pixels, or telemetry endpoints. It operates entirely locally.

**No Data Exfiltration**: The extension does not send user data, browsing history, or any other information to external servers.

## Permission Analysis

**Declared Permissions**:
- `storage` - Used to persist user preferences (doodle text, image URL, type, scale, formatting)

**Content Script Injection**:
- Matches: All Google TLDs (200+ domains including google.com, google.co.uk, google.co.in, etc.)
- Files: `contentScript.bundle.js`, `content.styles.css`
- Purpose: Replace Google logo on homepage and search pages

**Potential Over-Reach**:
The extension runs on ALL Google domains globally (200+ TLDs). While necessary for the advertised functionality, this broad access creates a large attack surface. If the extension were compromised or contained malicious code, it would have access to all Google properties for millions of users.

**Permission Risk Assessment**:
- `storage`: APPROPRIATE - Needed for saving user customization settings
- Content script access: EXCESSIVE SCOPE - While functionally necessary, the broad Google domain access (including regional TLDs) amplifies the impact of any security vulnerability

## Code Quality & Architecture

**Positive Observations**:
1. Manifest V3 compliance (modern security model)
2. Minimal permissions (only `storage`)
3. No remote code execution capabilities
4. No network requests for analytics or data collection
5. Open-source React framework usage

**Concerning Patterns**:
1. **Unsafe innerHTML usage** - Primary security concern
2. **Minified React bundles** - Makes code review difficult (though React itself is trusted)
3. **No input validation** - User settings are used directly without sanitization
4. **Broad domain matching** - Runs on 200+ Google TLDs

**Obfuscation Analysis**:
The extension bundles use webpack minification, which is standard for React applications. The actual extension logic (not React framework code) is relatively straightforward:
- Reads settings from chrome.storage.local
- Generates colored HTML for text-based doodles
- Injects HTML into Google's logo elements using innerHTML
- Supports three modes: text, image URL, or clock display

## Background Script Analysis

**File**: `background.bundle.js`

**Functionality**:
```javascript
chrome.action.onClicked.addListener((e=>{
    chrome.tabs.query({active:!0,currentWindow:!0},(e=>{
        var r=e[0];
        chrome.tabs.sendMessage(r.id,{message:"clicked_browser_action"})
    }))
}))

chrome.runtime.onMessage.addListener((function(e,r,a){
    "open_new_tab"===e.message?chrome.tabs.create({url:e.url}):
    "reload_current_tab"==e.message&&chrome.tabs.query({active:!0,currentWindow:!0},(e=>{
        chrome.tabs.reload(e[0].id)
    }))
}))
```

**Risk Assessment**:
- **LOW RISK** - Standard message passing between popup and content script
- Opens new tabs based on messages (could be abused if message source isn't validated, but limited to extension context)
- Reloads current tab on demand (benign functionality)
- No network requests or suspicious behavior

## Static Analysis Summary (ext-analyzer)

**Flags Detected**:
- `obfuscated`: TRUE (webpack-bundled React code)

**Data Flows**:
1. **EXFILTRATION Flow** (False Positive):
   - Source: `chrome.tabs.query` (retrieves active tab info)
   - Sink: `*.src` assignment (for image mode, sets img src to `i.pinimg.com`)
   - **Analysis**: This is NOT data exfiltration. The tab query is used to send messages to the content script, not to read tab data. The `src` assignment is for displaying a user-chosen image, not sending data externally.

2. **ATTACK SURFACE - innerHTML**:
   - Multiple message handlers inject content via `innerHTML`
   - Source: chrome.storage.local user settings
   - Sink: DOM manipulation on Google pages
   - **Confirmed vulnerability** - See detailed analysis above

**Risk Score Calibration**:
The ext-analyzer flagged an "exfiltration" flow, but manual review confirms this is a false positive. The actual risk is the innerHTML-based DOM manipulation vulnerability.

## Comparison with Similar Extensions

My Doodle is one of many "Google logo customizer" extensions. Common patterns in this category:
- DOM manipulation of Google homepage
- Local storage for user preferences
- No backend services or data collection

Security-wise, My Doodle is **average** for this category:
- ✅ No tracking/analytics (better than many)
- ✅ Minimal permissions (better than many)
- ❌ Unsafe innerHTML usage (common vulnerability in this category)
- ❌ No input sanitization (common issue)

## Final Verdict

**Overall Risk Rating: MEDIUM**

**Summary**: My Doodle is a legitimate cosmetic extension with a defensive security vulnerability. It does not engage in malicious behavior, data collection, or tracking. However, its use of `innerHTML` with user-controlled data creates a DOM-based XSS risk that could be exploited if an attacker compromises the user's extension storage.

**For Users**:
- SAFE to use for cosmetic customization
- Avoid installing other untrusted extensions that could modify storage
- Risk is theoretical and requires chained attacks

**For Developers**:
- FIX: Replace `innerHTML` with safe DOM manipulation methods
- FIX: Implement HTML sanitization for user inputs
- IMPROVE: Validate and whitelist image URLs
- CONSIDER: Reduce content script scope if possible

**Key Metrics**:
- Malicious Intent: NONE DETECTED
- Privacy Violations: NONE
- Data Exfiltration: NONE
- Defensive Vulnerabilities: 1 MEDIUM, 1 LOW
- Code Quality: AVERAGE (standard webpack bundling, minimal custom code)

**Recommendation**: The extension is generally safe for users but should be updated to fix the innerHTML vulnerability. The risk to end-users is low unless they have other compromised extensions or malware on their system.
