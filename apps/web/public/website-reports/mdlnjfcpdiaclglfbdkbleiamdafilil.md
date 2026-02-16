# Vulnerability Report: PhantomBuster

## Metadata
- **Extension ID**: mdlnjfcpdiaclglfbdkbleiamdafilil
- **Extension Name**: PhantomBuster
- **Version**: 1.3.8
- **Users**: ~300,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

PhantomBuster is a legitimate LinkedIn prospecting and automation tool with ~300,000 users. The extension harvests session cookies (including LinkedIn's `li_at` and `JSESSIONID`) from multiple social media platforms and transmits them to PhantomBuster's API servers. While this cookie collection is disclosed in the extension's description ("Retrieve session cookies and boost LinkedIn prospecting"), it represents significant privacy exposure. The extension monitors cookie changes across 15+ platforms and sends authentication credentials to third-party servers for automation purposes.

The extension's stated purpose is to enhance LinkedIn prospecting workflows by capturing contact information, saving leads, and syncing with CRMs like HubSpot. The cookie harvesting behavior is core to its functionality (enabling automation via PhantomBuster.com), making this a disclosed data collection practice rather than hidden malware. However, users may not fully understand the security implications of sharing session cookies with a third-party service.

## Vulnerability Details

### 1. MEDIUM: Session Cookie Harvesting and Exfiltration
**Severity**: MEDIUM
**Files**: src/background/background.ts, src/shared/linkedin.ts
**CWE**: CWE-522 (Insufficiently Protected Credentials)
**Description**: The extension harvests authentication session cookies from LinkedIn and up to 15 other platforms, then transmits them to api.phantombuster.com. Key cookies include LinkedIn's `li_at` (authentication token) and `JSESSIONID` (session identifier), along with CSRF tokens (`csrf-token`). The background service worker monitors all cookie changes via `browser.cookies.onChanged` listeners and stores matching cookies when detected.

**Evidence**:
```typescript
// background.ts - Cookie harvesting function
const getCookies = async (websiteName: WebsiteName, senderTab: Tabs.Tab) => {
    if (senderTab.id) {
        const cookiesList = getWebsiteFromName(websiteName)?.cookies
        if (cookiesList) {
            const cookies = await browser.cookies.getAll({})
            const matchingCookies = cookiesList.map(
                (cookie) => cookies.filter((c) => c.name === cookie.name && c.domain === cookie.domain)[0],
            )
            await sendMessage(senderTab.id, {
                cookies: {
                    websiteName,
                    cookies: matchingCookies,
                },
            })
        }
    }
}

// Cookie change monitoring
browser.cookies.onChanged.addListener(async (changeInfo) =>
    cookieChangedListeners[listenerKey].fn(changeInfo).catch(handleError),
)
```

**Verdict**: This is disclosed behavior per the extension description, making it MEDIUM severity rather than HIGH/CRITICAL. The extension description explicitly states "Retrieve session cookies," and the functionality is core to PhantomBuster's automation service. However, the broad scope (15+ platforms) and sensitive nature of session tokens still represents significant privacy exposure.

### 2. MEDIUM: LinkedIn Profile Data Enrichment via Voyager API
**Severity**: MEDIUM
**Files**: src/shared/linkedin.ts, LinkedinProfileRoute.js
**CWE**: CWE-359 (Exposure of Private Personal Information)
**Description**: The extension makes authenticated requests to LinkedIn's private Voyager API (`/voyager/api/me`, `/discover-email`) using harvested session cookies and CSRF tokens. It extracts detailed profile information including names, headlines, subscription status, profile IDs, and attempts to discover email addresses and phone numbers via PhantomBuster's API endpoint `/api/v1/discover-email`.

**Evidence**:
```typescript
// linkedin.ts - Authenticated API requests with harvested credentials
export async function fetchApiResponse(url: string, csrfToken: string, referrer: string): Promise<Response> {
    return fetch(url, {
        headers: {
            accept: "application/vnd.linkedin.normalized+json+2.1",
            "csrf-token": csrfToken,
            "x-restli-protocol-version": "2.0.0",
        },
        method: "GET",
        mode: "cors",
        credentials: "include",
    })
}

// LinkedinProfileRoute.js - Email discovery via PhantomBuster API
async function ne(t,s,a){
    const r=await re.POST("/discover-email",{
        body:Object(s),
        headers:{"X-Phantombuster-Org-Name":t},
        signal:a==null?void 0:a.signal
    });
    if(r.err)throw console.error(r.err),r.err;
    return r.data.data
}
```

**Verdict**: This is expected functionality for a LinkedIn prospecting tool. The data enrichment is part of the disclosed feature set ("displays detailed contact information in the browser's side panel"). However, the use of LinkedIn's private APIs with harvested credentials could violate LinkedIn's Terms of Service.

### 3. LOW: Broad Host Permissions Across 15+ Platforms
**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension requests host permissions for 15+ social media and professional platforms (LinkedIn, Facebook, Instagram, Twitter/X, GitHub, Medium, Slack, YouTube, Quora, Pinterest, TikTok, ProductHunt, Uber, Intercom), despite primarily focusing on LinkedIn prospecting. While these permissions may support PhantomBuster's broader automation platform, they represent an unnecessarily large attack surface.

**Evidence**:
```json
"host_permissions": [
    "*://*.phantombuster.com/*",
    "*://*.facebook.com/*",
    "*://*.github.com/*",
    "*://*.instagram.com/*",
    "*://*.linkedin.com/*",
    "*://*.twitter.com/*",
    "*://*.tiktok.com/*"
    // ... 8 more platforms
]
```

**Verdict**: Overly broad permissions are common in multi-platform tools. The extension description mentions LinkedIn specifically but doesn't clearly communicate that it harvests cookies from all 15+ platforms. This represents poor security hygiene but aligns with PhantomBuster's multi-platform automation service.

## False Positives Analysis

1. **Webpack/Vite Bundling**: The extension uses modern build tooling (Vite, React, TypeScript). The bundled/minified code is not malicious obfuscation but standard development practice. Source maps are included for debugging.

2. **Sentry Error Tracking**: The extension includes Sentry SDK for error monitoring, which sends crash reports to Sentry servers. This is standard development practice and not data exfiltration.

3. **Browser Polyfill**: The webextension-polyfill library provides Firefox compatibility and is not suspicious code.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.phantombuster.com | Session cookie storage, email discovery | Session cookies (li_at, JSESSIONID), CSRF tokens, LinkedIn profile data | MEDIUM - Credentials sent to third party |
| www.linkedin.com/voyager/api | Profile data extraction | Authenticated requests with user's session | MEDIUM - Private API usage may violate ToS |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: PhantomBuster is a legitimate commercial tool (300,000 users) that performs disclosed session cookie harvesting for LinkedIn automation and prospecting. The cookie collection behavior is explicitly mentioned in the extension description ("Retrieve session cookies"), making this a disclosed privacy practice rather than hidden malware.

However, the extension still warrants MEDIUM risk due to:
- **Broad credential exposure**: Session cookies for 15+ platforms are harvested and sent to third-party servers
- **Session hijacking potential**: If PhantomBuster's servers were compromised, attackers would gain access to users' authenticated sessions across multiple platforms
- **Terms of Service violations**: Using harvested credentials to automate LinkedIn interactions likely violates LinkedIn's ToS
- **Limited user understanding**: While disclosed, many users may not fully comprehend the security implications of sharing session cookies

This is NOT malware but represents a legitimate tool with significant privacy and security tradeoffs. Users should be aware they are granting PhantomBuster full access to their authenticated sessions across major social platforms.
