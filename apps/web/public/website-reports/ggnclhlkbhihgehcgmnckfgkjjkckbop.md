# Security Analysis Report: Não Seguidores

## Extension Metadata
- **Name**: Não Seguidores
- **Extension ID**: ggnclhlkbhihgehcgmnckfgkjjkckbop
- **Version**: 1.3.15
- **User Count**: 1,000,000+
- **Manifest Version**: 3
- **Risk Level**: MEDIUM

## Executive Summary

Não Seguidores is a Brazilian Instagram follower management tool that helps users identify accounts that don't follow them back. The extension extracts sensitive authentication credentials (CSRF tokens, session identifiers, and app IDs) directly from Instagram's page source and uses them to make authenticated API requests to Instagram's internal GraphQL and REST APIs. While the extension appears to function as advertised without exfiltrating user data to third-party servers, it employs security-sensitive practices that could expose users to risks if the extension were compromised or maliciously modified in future updates.

**Key Concerns:**
1. Extraction of CSRF tokens, session identifiers, and Instagram app credentials from page source
2. Client-side rate limiting that can be easily bypassed
3. Hardcoded Instagram API endpoints with minimal error handling
4. Direct manipulation of Instagram's internal APIs using extracted credentials

## Vulnerability Analysis

### 1. Credential Extraction from Page Source (MEDIUM)

**Location**: `contentScript.js`, lines matching regex patterns

**Description**: The extension extracts multiple sensitive authentication tokens and identifiers directly from Instagram's page HTML source:

```javascript
const m=document.body.innerHTML,
n=m.match(/\\?"viewerId\\?":\\?"(\w+)\\?"/i),
o=m.match(/\\?"appScopedIdentity\\?":\\?"(\w+)\\?"/i),
p=m.match(/(?<="csrf_token":").+?(?=")/i),
q=m.match(/(?<="X-IG-App-ID":").+?(?=")/i),
r=m.match(/(?<="rollout_hash":").+?(?=")/i);
let s=n?n[1]:null;
s||(s=o?o[1]:null);
```

These extracted values include:
- **viewerId/appScopedIdentity**: User's Instagram account identifier
- **csrf_token**: Cross-Site Request Forgery protection token
- **X-IG-App-ID**: Instagram's internal application identifier
- **rollout_hash**: Instagram's deployment version identifier

The extracted credentials are then used in authenticated API requests:

```javascript
const t={},u={"Content-Type":"application/x-www-form-urlencoded","X-Requested-With":"XMLHttpRequest","X-Asbd-Id":129477};
sessionStorage.getItem("www-claim-v2")&&(u["X-Ig-Www-Claim"]=sessionStorage.getItem("www-claim-v2")),
p&&(t["X-Csrftoken"]=p[0],u["X-Csrftoken"]=p[0]),
q&&(t["X-Ig-App-Id"]=q[0],u["X-Ig-App-Id"]=q[0]),
r&&(u["X-Instagram-Ajax"]=r[0])
```

**Risk**: If the extension is compromised, these credentials could be used to perform unauthorized actions on behalf of the user, including posting content, sending messages, or modifying account settings.

**Severity**: MEDIUM - The credentials are used solely for Instagram API requests and not exfiltrated to third parties, but the extraction method creates a blueprint for potential abuse.

---

### 2. Insufficient Rate Limiting (MEDIUM)

**Location**: `contentScript.js`, unfollow rate limiting logic

**Description**: The extension implements client-side rate limiting for unfollow operations:

```javascript
let k={minute:0,hour:0}

function g(a){
    if(5<=k.minute)return void alert("Limitado a 5 unfollows por minuto para evitar bloqueio do Instagram.");
    if(60<=k.hour)return void alert("Limitado a 60 unfollows por hora para evitar bloqueio do Instagram.");
    // ... perform unfollow ...
    k.minute++,k.hour++
}

setInterval(function(){k.minute=0},60000),
setInterval(function(){k.hour=0},3600000)
```

**Weaknesses**:
1. Rate limits are enforced client-side and can be trivially bypassed by:
   - Opening developer console and modifying the `k` object
   - Disabling JavaScript and re-enabling it to reset counters
   - Modifying the extension code directly
2. The limits (5/minute, 60/hour) may still be aggressive enough to trigger Instagram's anti-automation systems
3. No server-side validation or token bucket algorithm

**Risk**: Users who bypass these limits (intentionally or through modified versions) could trigger Instagram's automated abuse detection, leading to temporary or permanent account restrictions.

**Severity**: MEDIUM - While the limits exist to protect users, their client-side nature provides minimal actual protection.

---

### 3. Hardcoded Instagram API Endpoints (MEDIUM)

**Location**: `contentScript.js`, GraphQL and REST API calls

**Description**: The extension makes direct calls to Instagram's internal, undocumented APIs:

**GraphQL Follower Query**:
```javascript
fetch("https://www.instagram.com/graphql/query/?query_hash=3dec7e2c57367ef3da3d987d89f9dbc8&variables={\"id\":\""+s+"\",\"include_reel\":false,\"fetch_mutual\":false,\"first\":50,\"after\":\""+b+"\"}",{headers:t})
```

**Unfollow API Request**:
```javascript
fetch("https://i.instagram.com/api/v1/web/friendships/"+b+"/unfollow/",{method:"POST",headers:u,credentials:"include",mode:"cors"})
```

**Issues**:
1. Hardcoded query hash (`3dec7e2c57367ef3da3d987d89f9dbc8`) that may become invalid if Instagram updates their API
2. Reliance on undocumented internal endpoints that could change without notice
3. Minimal error handling - only checks for HTTP 200 status or `.ok` property
4. Direct use of user credentials without additional validation

**Risk**:
- Users may experience extension breakage if Instagram changes their API structure
- Instagram could potentially flag accounts using these patterns as automated/bot activity
- The extension creates a dependency on internal API structures not intended for third-party use

**Severity**: MEDIUM - While not directly exploitable, this practice violates Instagram's Terms of Service and could lead to account restrictions.

## Network Analysis

### Outbound Connections

The extension communicates exclusively with Instagram domains:

| Domain | Purpose | Protocol |
|--------|---------|----------|
| `www.instagram.com` | GraphQL follower queries | HTTPS |
| `i.instagram.com` | Unfollow API requests | HTTPS |
| `invertexto.com` | Developer website link (no actual requests) | N/A |

### Data Flow

**Follower Enumeration Flow**:
1. Extract user ID and CSRF token from Instagram page source
2. Make paginated GraphQL requests to enumerate following list
3. Filter users who don't follow back
4. Display results in injected modal UI

**Unfollow Operation Flow**:
1. User clicks "unfollow" button on displayed result
2. Extension sends POST request to `i.instagram.com/api/v1/web/friendships/{id}/unfollow/`
3. Request includes extracted CSRF token and session cookies
4. Response updates UI to show "Removido" (Removed) status

### Privacy Assessment

**No Third-Party Data Exfiltration**: The extension does not send any user data to servers outside Instagram's infrastructure. All API calls use Instagram's official domains with the user's own credentials.

**Local Processing**: Follower comparison logic runs entirely in the browser - no external processing or analytics.

**Session Storage**: The extension reads `www-claim-v2` from sessionStorage but does not persist any data long-term.

## Permission Analysis

### Declared Permissions

| Permission | Justification | Risk |
|------------|---------------|------|
| `scripting` | Required to inject content script and CSS into Instagram tabs | LOW - Scoped to host permissions |
| `https://*.instagram.com/*` | Host permission for accessing Instagram pages and APIs | MEDIUM - Broad access to Instagram |

### Permission Usage Assessment

**Appropriate**: The permissions requested align with the extension's stated functionality. The `scripting` permission is used to inject the follower analysis UI, and Instagram host permissions are necessary for API access.

**Concerns**:
- The wildcard host permission (`*.instagram.com`) grants access to all Instagram subdomains
- No additional permissions are requested, which is positive from a privacy standpoint

## Code Quality and Security Practices

### Positive Aspects
1. **No external dependencies**: Extension uses vanilla JavaScript without third-party libraries
2. **User feedback**: Clear error messages and loading states inform users of operation status
3. **Basic rate limiting**: Attempts to prevent account flagging through client-side throttling
4. **No data persistence**: Doesn't store user data in extension storage

### Negative Aspects
1. **Minified/obfuscated code**: The content script appears to be minified with single-character variable names, making security auditing difficult
2. **No input validation**: User IDs and API responses are used without sanitization
3. **Regex-based credential extraction**: Fragile parsing method that could break or be exploited
4. **Client-side security controls**: Rate limits and other protections can be bypassed trivially

## Risk Assessment

### Overall Risk Level: MEDIUM

The extension functions as advertised and does not appear to exfiltrate user data to third-party servers. However, several factors contribute to a MEDIUM risk classification:

**Mitigating Factors**:
- No evidence of malicious data collection
- Communications limited to Instagram domains
- Transparent functionality (shows which users are unfollowed)
- Large user base (1M+) suggests legitimate use case

**Aggravating Factors**:
- Extraction and use of sensitive authentication tokens
- Violation of Instagram's Terms of Service (automated actions)
- Client-side security controls that provide false sense of protection
- Reliance on undocumented internal APIs
- Potential for account restrictions if Instagram detects automated behavior

### Recommendations

**For Users**:
1. Be aware that using this extension violates Instagram's Terms of Service and could result in account restrictions
2. Use sparingly - even with rate limiting, bulk unfollowing may trigger anti-automation systems
3. Understand that the extension has access to your session credentials while active on Instagram
4. Consider using Instagram's native follower management features instead

**For Developers**:
1. Implement server-side rate limiting to provide genuine protection against abuse
2. Add input validation and sanitization for all user-controlled data
3. Provide clearer warnings about Terms of Service violations
4. Consider using official Instagram APIs (if available) rather than undocumented endpoints
5. Add error recovery mechanisms for API changes
6. Unminify code for transparency and easier security auditing

**For Extension Reviewers**:
1. Monitor for updates that might introduce data exfiltration
2. Verify that API endpoints remain limited to Instagram domains
3. Check for any new permissions in future versions

## Conclusion

Não Seguidores is a functional Instagram follower management tool that operates within the technical constraints of a browser extension. While it doesn't exhibit overtly malicious behavior, it employs security-sensitive practices (credential extraction, undocumented API usage) that could expose users to risks if the extension were compromised or if Instagram implements stricter anti-automation measures. The extension's primary risk stems from potential Instagram account restrictions rather than direct security vulnerabilities, though the credential extraction pattern warrants ongoing monitoring.

Users should weigh the convenience of automated follower management against the risks of Terms of Service violations and potential account restrictions.
