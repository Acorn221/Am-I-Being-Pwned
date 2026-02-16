# Vulnerability Report: Click&Clean

## Metadata
- **Extension ID**: ghgabhipcejejjmhhchfonmamedcbeod
- **Extension Name**: Click&Clean
- **Version**: 9.8.2.0
- **Users**: ~1,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Click&Clean is a privacy and cleaning tool with 1 million users that provides functionality to clear browsing history, cache, cookies, and other private data. While the extension's core functionality appears legitimate, it collects and transmits undisclosed usage telemetry to api64.com, including browsing history counts and detailed usage metrics. The extension also receives remote configuration updates from this endpoint that can modify its behavior. The privacy policy and Chrome Web Store listing do not adequately disclose this data collection, which is concerning for a tool marketed as privacy-focused.

## Vulnerability Details

### 1. MEDIUM: Undisclosed Telemetry Collection
**Severity**: MEDIUM
**Files**: esw901.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension sends detailed usage telemetry to api64.com/upd2 including browsing history count, timezone, language, browser version, user ID, and various usage flags. This occurs without clear disclosure to users.

**Evidence**:
```javascript
// Line 14 in esw901.js - Xa function sends telemetry
const [c,e,f,h]=await Xb(),m=await U({text:"",maxResults:1E3,startTime:1}),n=A(),Q=m&&m.length||0,
x=z((n-(d.ai||0))/6E4),B=z((n-(d.md||0))/6E4),
R={a:1,b:9820,c:x,d:d.au,e:f,f:c,g:e[0],h:e[1],i:e[2],j:e[3],k:h[0],l:h[1],m:h[2],n:h[3],
o:(new na).getTimezoneOffset()/60,p:S.language||"",q:Q,r:d.mc||0,s:B,t:d.ma||0,u:d.p33||0,
v:d.mr,w:d.mt||0,x:d.dc||0,y:d.ms||0,z:d.ml||0};

// Posts to https://api64.com/upd2
let [ia,Wa]=await H(g(9)+g(11)+g(0)+"/upd2",{method:"POST",cache:"no-store",
body:Ba(R),headers:{"Content-Type":"application/json"}},"json");
```

The telemetry includes:
- `q:Q` - Total browsing history count (searches for all history with maxResults:1000)
- `o` - Timezone offset
- `p` - Browser language
- `f,c,g,h,i,j,k,l,m,n` - Browser brand/version details
- `uid` - Persistent user identifier
- Multiple usage flags and metrics

**Verdict**: This represents undisclosed data collection for a privacy-focused extension. While the data sent is primarily usage metrics, the browsing history count and persistent user ID create privacy concerns without adequate disclosure.

### 2. MEDIUM: Remote Configuration Control
**Severity**: MEDIUM
**Files**: esw901.js
**CWE**: CWE-912 (Hidden Functionality)
**Description**: The extension accepts remote configuration updates from api64.com that can modify its runtime behavior, including blocking lists, user interface settings, and feature flags.

**Evidence**:
```javascript
// Line 13-14 in esw901.js - cc function processes remote config
let [ia,Wa]=await H(g(9)+g(11)+g(0)+"/upd2",{method:"POST",...},"json");
0==Wa&&await cc(ia);  // Process remote config response

// cc function updates extension settings from remote response
cc=async function(a){"sf"in a&&("gg"in a&&(d.gg=a.gg),"gf"in a&&(d.gf=a.gf),
"goc"in a&&(d.go.length=0),"gpc"in a&&(d.gp.length=0),"gor"in a&&Ua(d.go,a.gor),
"gpr"in a&&Ua(d.gp,a.gpr),"goa"in a&&Ta(d.go,a.goa),"gpa"in a&&Ta(d.gp,a.gpa));
"dc"in a&&(d.dc=a.dc);"sm"in a&&("mr"in a&&(d.mr=a.mr),"ma"in a&&(d.ma=a.ma),
"ml"in a&&(d.ml=a.ml),"mt"in a&&d.mt!=a.mt&&(d.mt&&t(sa,wa),d.mt=a.mt,
d.mt&&p(sa,wa)));"rtc"in a&&await M({origins:[g(9)+g(10)+g(6)]},{cookies:!0,
cache:!0,localStorage:!0});"op"in a&&await bc(a.op);await I()}
```

**Verdict**: Remote configuration allows the extension developer to modify behavior post-installation. While not inherently malicious, this capability is not clearly disclosed and could be abused to add unwanted functionality.

## False Positives Analysis

**Obfuscation**: The code uses Closure Compiler minification with string array obfuscation (Vb array with g() accessor function). This is a standard optimization technique but makes analysis more difficult. The deobfuscated code shows this is legitimate build artifact obfuscation, not malicious intent to hide functionality.

**Localhost endpoint**: CSP allows http://localhost:27077 which appears to be for local development/debugging. This is not a security issue in production.

**Content script on hotcleaner.com**: The extension has a content script that only runs on hotcleaner.com to provide enhanced UI features for the developer's website. This is legitimate integration with their own domain.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api64.com/upd2 | Telemetry & remote config | History count, user ID, usage metrics, browser details | MEDIUM - Undisclosed collection |
| hotcleaner.com | Developer website | None (UI only) | LOW - Legitimate |
| clients2.google.com | Chrome update service | Standard CRX update | NONE |
| appn.center/apiv1/csp | CSP violation reporting | CSP violations | LOW - Standard reporting |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: Click&Clean provides legitimate privacy cleaning functionality but undermines user trust by collecting undisclosed telemetry from a privacy-focused tool. The extension sends browsing history counts and persistent user identifiers to api64.com without clear disclosure in its privacy policy or Chrome Web Store listing. Additionally, the remote configuration capability allows the developer to modify extension behavior post-installation.

While there is no evidence of malicious activity, the lack of transparency around data collection for a privacy tool represents a significant privacy concern that warrants a MEDIUM risk rating. The extension would be rated LOW if adequate disclosure were provided about the telemetry and remote configuration features.

**Recommendations**:
1. Add clear disclosure of telemetry collection to the Chrome Web Store listing
2. Provide opt-out mechanism for telemetry
3. Document what data is sent to api64.com
4. Clarify the purpose and scope of remote configuration updates
5. Consider removing browsing history count from telemetry data

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
