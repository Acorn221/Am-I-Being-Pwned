# Security Analysis: ResumeGPT : AI Job Autofill & Best Resume Builder (jlbkfkcopgimfccacnelllnkohhpdpgo)

## Extension Metadata
- **Name**: ResumeGPT : AI Job Autofill & Best Resume Builder
- **Extension ID**: jlbkfkcopgimfccacnelllnkohhpdpgo
- **Version**: 1.0.5
- **Manifest Version**: 3
- **Estimated Users**: ~100,000
- **Developer**: resumedone.co
- **Analysis Date**: 2026-02-14

## Executive Summary
ResumeGPT is a job application autofill extension with **MEDIUM** risk due to excessive data collection practices. While the core functionality (autofilling job applications on Indeed, LinkedIn, and other job boards) appears legitimate, the extension collects significantly more data than necessary for its stated purpose. It harvests session cookies from 40+ competitor resume builder domains, tracks user IP addresses for geolocation, and sends extensive browsing analytics to PostHog/Indicative. The combination of `<all_urls>` + `cookies` permissions with aggressive cross-domain cookie harvesting and IP tracking represents privacy overreach.

**Overall Risk Assessment: MEDIUM**

**Key Concerns**:
1. Cookie harvesting from 40+ resume builder competitor domains (not just job sites)
2. IP address collection via api.ipify.org + geolocation lookup
3. Extensive PostHog analytics tracking including user sessions, browsing behavior, and LinkedIn profiles
4. Hardcoded API keys exposed in code (PostHog, Indicative, Airtable)

---

## Vulnerability Assessment

### 1. Excessive Cookie Harvesting (Cross-Domain Session Theft)
**Severity**: MEDIUM
**Files**:
- `/service_worker.js` (lines 408-457)
- `/src/scripts/vars.mjs` (lines 50-97)

**Analysis**:
The extension systematically harvests cookies from 40+ resume builder domains, including direct competitors. While the stated purpose is to sync user sessions across the developer's own multi-domain resume builder network, this creates privacy and security risks.

**Code Evidence** (`service_worker.js`):
```javascript
async function getCookies(domain) {
    return new Promise((resolve, reject) => {
        try {
            chrome.cookies.getAll(
                { domain: domain.replace('https://', '') },
                function (cookies) {
                    const res = cookies.map((c) => ({
                        domain: c.domain,
                        name: c.name,
                        path: c.path,
                        value: c.value,
                    }));
                    resolve({ domain: domain, cookies: res });
                }
            );
        } catch (e) {
            resolve({ domain: domain, cookies: null });
        }
    });
}

async function getAllHostCookie(cookieName) {
    let promises = [];
    for (let i = 0; i < domains.length; i++) {
        const _domain = new URL(domains[i]).hostname.match(/(.+)\.(\w+)$/)[0];
        promises.push(getHostCookie(_domain, cookieName));
    }
    const result = await Promise.all(promises);
    return result;
}
```

**Targeted Domains** (from `vars.mjs`):
```javascript
export const domains = [
    'https://resumedone.co',
    'https://bestonlineresume.com',
    'https://elegantcv.app',
    'https://mysmartcv.co',
    'https://buildmycv.io',
    // ... 40+ resume builder domains
    'https://cvdeboss.com',
    'https://chinese-cv.com',
    'https://cv-in-persian.com',
];
```

**Cookies Harvested**:
- `token` - Authentication tokens
- `session_id` - Session identifiers
- `storeRedirect` - Tracking cookie
- `fromWhichCampaign` - Marketing attribution
- All cookies from each domain (via `getCookies()`)

**Attack Vector**:
1. Extension requests `cookies` permission + `<all_urls>`
2. On install/update, calls `getOwnHostWithCookie('token')` to scan all 40+ domains
3. Extracts session tokens and sends to backend for "verification"
4. Uses tokens to auto-login users across the network

**Privacy Implications**:
- Users browsing ANY of the 40+ resume builder sites have their session tokens harvested
- Tokens are transmitted to `api.resumedone.co/auth/verify-login` for validation
- Creates cross-site tracking network across competitor domains
- Session tokens could be used to access user accounts on those platforms

**Verdict**: **MEDIUM RISK** - While likely used for legitimate multi-domain SSO, this violates user privacy expectations and could enable account hijacking if tokens are compromised. Users are unaware their sessions on competitor sites are being monitored.

---

### 2. IP Address Tracking and Geolocation
**Severity**: MEDIUM
**Files**:
- `/src/scripts/service-worker/utils.js` (lines 266-276)
- `/src/scripts/service-worker/utils.js` (lines 235-264)

**Analysis**:
The extension collects user IP addresses via third-party service (api.ipify.org) and performs geolocation lookups to determine user country. This data is stored locally and sent to analytics.

**Code Evidence** (`service-worker/utils.js`):
```javascript
async function getClientIP() {
    const response = await fetch('https://api.ipify.org?format=json');
    const data = await response.json();
    return data.ip;
}

async function getLocation(ip) {
    const { success, token } = await loadToken();
    if (!success) {
        return { countryCode: '', countryName: '' };
    }
    if (!ip) {
        console.warn('No IP address provided');
        return { countryCode: '', countryName: '' };
    }

    const endpoint = `/meta/geolocation/${ip}`;
    const fetchOptions = mkFetchOption('GET', endpoint, token);

    try {
        const response = await fetch(`${BASE_URL}${endpoint}`, {
            ...fetchOptions,
        });
        const res = await response.json();
        return {
            countryCode: res.location?.country?.code || '',
            countryName: res.location?.country?.name || '',
        };
    } catch (e) {
        console.error(e.message, e.stack);
        return { countryCode: '', countryName: '' };
    }
}

export async function postInstallation(flow = 'install') {
    const countryName = await setUserCountry();
    flow == 'install' && setFreeAccess();
    setExtensionUser(countryName);
}
```

**Data Flow**:
1. Extension fetches user's public IP from `api.ipify.org`
2. Sends IP to `api.resumedone.co/meta/geolocation/{ip}` for reverse lookup
3. Stores `CountryCode` and `CountryName` in `chrome.storage.local`
4. Includes country data in PostHog/Indicative analytics events

**Privacy Implications**:
- IP addresses can identify users and approximate location
- Sent to third-party service (ipify.org) without user consent
- Geolocation data enriches analytics tracking profile
- No opt-out mechanism provided

**Justification**:
The extension claims this is for "localizing resume templates" and determining user region, but this could be achieved via `chrome.i18n.getUILanguage()` or browser locale without IP tracking.

**Verdict**: **MEDIUM RISK** - IP tracking is privacy-invasive and disproportionate to stated functionality. Users expect autofill extensions to fill forms, not track their geographic location.

---

### 3. Extensive Analytics Data Exfiltration
**Severity**: LOW (Legitimate but Excessive)
**Files**:
- `/service_worker.js` (lines 138-313, PostHog/Indicative integration)
- `/src/scripts/track.js` (lines 86-187, frontend tracking)

**Analysis**:
The extension sends comprehensive analytics to PostHog (us.i.posthog.com) and Indicative tracking every user action, including browsing behavior, job searches, application flows, and LinkedIn profile data.

**Code Evidence** (`service_worker.js`):
```javascript
const Indicative = {
    identifyUser: '$identify',
    pluginInstalled: 'plugin_installed',
    pluginFirstLaunch: 'plugin_first_launch',
    pluginLaunched: 'plugin_launched',
    pluginApply: 'plugin_apply_redirection',
    pluginLinkedinRedirect: 'plugin_linkedin_redirect',
    contactCollection: 'plugin_contact_collection',
    jobOfferSearch: 'plugin_job_offer_search',

    track: async function (evtName = ctaSavedJob, property = {}) {
        // ... throttling logic ...
        const USER_ID = getContext('USER_ID');
        let eventUniqueId = RD_SESSION_ID || USER_ID || 'UNKNOWN_USER';

        try {
            if (eventUniqueId == 'UNKNOWN_USER') {
                const _ = await chrome.storage.local.get(['userid']);
                eventUniqueId = 'userid' in _ ? _.userid : 'UNKNOWN_USER';
            }
        } catch (error) {}

        const apiKeyPosthog = 'phc_f8ZORiyxMeTrhHXuofTNcdVkgyqKxwEIbmNvXDBjeSW';
        const urlPosthog = 'https://us.i.posthog.com/i/v0/e/';

        let requestParams = {
            apiKey: apiKeyIndicative,
            eventName: evtName,
            eventUniqueId: eventUniqueId,
            properties: property,
        };
        requestParams.properties['plugin_version'] =
            chrome.runtime.getManifest().version;

        // Add A/B variant tracking
        if (!RD_VARIANTS) {
            RD_VARIANTS = await mkABVariant();
        }
        for (const key in RD_VARIANTS) {
            if (RD_VARIANTS[key].value && RD_VARIANTS[key].track) {
                requestParams.properties[key] = RD_VARIANTS[key].value;
            }
        }

        if (usePostHog) {
            requestParams['distinct_id'] = requestParams.eventUniqueId;
            requestParams['api_key'] = apiKeyPosthog;
            requestParams['event'] = requestParams.eventName;
        }

        fetch(usePostHog ? urlPosthog : urlIndicative, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestParams),
        }).then((response) => log(evtName, response.status));
    },
};
```

**Tracked Events** (from `track.js`):
```javascript
export const pluginInstalled = 'plugin_installed';
export const pluginLaunched = 'plugin_launched';
export const pluginButtonClicked = 'plugin_button_clicked';
export const pluginLinkedinRedirect = 'plugin_linkedin_redirect';
export const jobSearch = 'web_job_search';
export const viewJob = 'web_job_view';
export const applyJobCtaClick = 'apply_job_cta_click';
export const applyFlowCtaSubmitStep1 = 'apply_flow_cta_submit_step1';
// ... 40+ event types
```

**Data Transmitted to PostHog**:
- User ID / Session ID (persistent identifier)
- Plugin version
- Browser language / locale
- Viewport size
- Current domain / URL
- Job search queries (title, location, salary)
- Company names
- Application steps and form fields filled
- LinkedIn profile URL (if scraped: `window.RD_LINKEDIN_URL`)
- LinkedIn avatar URL
- A/B test variant assignments
- Tab activity and automation status

**Code Evidence** (`track.js`, lines 150-162):
```javascript
if (window.RD_LINKEDIN_AVATAR) {
    requestParams.properties['linkedin_avatar'] = window.RD_LINKEDIN_AVATAR;
}
if (window.RD_LINKEDIN_URL) {
    requestParams.properties['linkedin_url'] = window.RD_LINKEDIN_URL;
    if (window.RD_LINKEDIN_URL_VALUE) {
        requestParams.properties['linkedin_url_value'] =
            `https://www.linkedin.com/in/${window.RD_LINKEDIN_URL_VALUE}`;
    }
}
requestParams.properties['viewport_size'] =
    `${window.innerWidth || 0}x${window.innerHeight || 0}`;
```

**Privacy Implications**:
- Creates detailed behavioral profile of job search activity
- Links user identity across domains via persistent session ID
- Tracks every click, form submission, and navigation
- No granular opt-out controls (analytics is always-on)
- Data sent to third-party service (PostHog) with unknown retention

**Verdict**: **LOW RISK (Privacy Concern)** - While analytics tracking is common in extensions, the scope here is excessive. Users installing a "job autofill" tool likely don't expect their entire job search journey (including LinkedIn profiles and salary expectations) to be tracked and sent to analytics platforms.

---

### 4. Hardcoded API Keys Exposure
**Severity**: LOW
**Files**:
- `/service_worker.js` (lines 179-184, 253-254)
- `/src/scripts/track.js` (lines 86-90)
- `/src/scripts/service-worker/utils.js` (line 296)

**Analysis**:
Multiple API keys are hardcoded in the extension's JavaScript files, accessible to anyone who inspects the code.

**Exposed Credentials**:
```javascript
// PostHog (Analytics)
const apiKeyPosthog = 'phc_f8ZORiyxMeTrhHXuofTNcdVkgyqKxwEIbmNvXDBjeSW';
const urlPosthog = 'https://us.i.posthog.com/i/v0/e/';

// Indicative (Analytics)
const apiKeyIndicative = '9d40710f-8616-421d-a563-de27df915aaa';
const urlIndicative = 'https://api.indicative.com/service/event';

// Airtable (Content/Tips)
Authorization: `Bearer ${AIRTABLE_PUBLIC_TOKEN}` // from env.mjs
```

**Risk Assessment**:
- **PostHog/Indicative**: Read-only tracking keys, limited abuse potential
- **Airtable**: Public read-only token for fetching "tips" content
- Keys could be extracted and used to spam analytics or pollute datasets
- No sensitive write operations exposed

**Verdict**: **LOW RISK** - While poor security practice, these are client-side analytics keys designed for public use. The impact of exposure is limited to analytics pollution rather than data theft.

---

## Data Flow Summary

### Chrome Storage Data Collected:
```javascript
// From chrome.storage.local
- userid (persistent identifier)
- session_id (PostHog tracking ID)
- token (authentication token for resumedone.co backend)
- origin (user's associated resume builder domain)
- CountryCode, CountryName (from IP geolocation)
- rd_selected_resume (resume ID being used)
- sa_selected_user (for automation features)
- automation_queue (queued job applications)
- linkedin_get_profile, LINKEDIN_TAB_ID
- rd_variants (A/B test assignments)
- tips (fetched from Airtable)
```

### Network Endpoints and Data Sent:

1. **api.ipify.org** (IP Lookup)
   - Request: GET `https://api.ipify.org?format=json`
   - Response: User's public IP address
   - Frequency: On install

2. **api.resumedone.co** (Backend API)
   - `/auth/sign-up` - Creates guest user account
   - `/auth/verify-login` - Validates harvested session tokens
   - `/auth/refresh-token` - Refreshes expired tokens
   - `/user/info` - Fetches user profile
   - `/meta/geolocation/{ip}` - IP geolocation lookup
   - Data sent: User IP, session tokens, authentication credentials

3. **us.i.posthog.com** (Analytics)
   - POST `https://us.i.posthog.com/i/v0/e/` - Event tracking
   - POST `https://us.i.posthog.com/batch/` - Batch events
   - Data sent: User ID, session ID, browsing events, job search queries, LinkedIn profiles, viewport size, plugin version, A/B variants

4. **api.indicative.com** (Analytics - Fallback)
   - POST `https://api.indicative.com/service/event`
   - Data sent: Same as PostHog (legacy endpoint)

5. **api.airtable.com** (Content Delivery)
   - GET `https://api.airtable.com/v0/appXLbUca6EDplqo4/tbleRmDCT7afyhCwi`
   - Purpose: Fetch "tips" and onboarding content
   - Frequency: Daily (cached for 24 hours)

### Exfiltration Flow Diagram:
```
[User Browsing]
    ↓
[Chrome Storage] → userid, session_id, tokens, resume data
    ↓
[Cookie Harvesting] → chrome.cookies.getAll(resumedone.co + 40 domains)
    ↓
[IP Collection] → api.ipify.org → user IP address
    ↓
[Geolocation] → api.resumedone.co/meta/geolocation/{ip} → country
    ↓
[Analytics] → us.i.posthog.com
    - User ID (persistent)
    - Session ID
    - Job search queries
    - LinkedIn profile URLs
    - Browsing events (40+ event types)
    - Country/locale data
    - A/B test variants
```

---

## Permissions Analysis

### Requested Permissions:
```json
{
  "permissions": [
    "storage",        // Store user data, tokens, session IDs
    "tabs",           // Monitor active tabs for job sites
    "cookies",        // CRITICAL: Harvest cookies from 40+ domains
    "notifications",  // Show notifications
    "scripting",      // Inject content scripts
    "activeTab",      // Access current tab content
    "<all_urls>"      // CRITICAL: Access all websites
  ]
}
```

### Risk Analysis:
- **`cookies` + `<all_urls>`**: Allows reading cookies from ANY website user visits, not just job sites. Used to harvest session tokens from 40+ resume builder competitor domains.
- **`tabs`**: Monitors all tab activity, used for job search tracking and analytics.
- **`scripting`**: Injects autofill scripts on job application pages (legitimate use).
- **`storage`**: Stores sensitive data (tokens, user IDs, resume content) in unencrypted local storage.

### Over-Permissioned Concerns:
- **`<all_urls>` abuse**: Extension only needs access to specific job sites (Indeed, LinkedIn, Monster, etc.) but requests broad access. This enables:
  - Cookie harvesting from unrelated resume builder sites
  - Tracking user browsing across all domains
  - Potential for future scope creep (e.g., ad injection)

- **`cookies` abuse**: Needed for autofilling forms with saved data, but actively used to harvest competitor session tokens for cross-domain SSO.

**Recommendation**: Extension should request host permissions only for job sites where autofill is needed:
```json
"host_permissions": [
  "https://www.indeed.com/*",
  "https://www.linkedin.com/*",
  "https://www.monster.com/*",
  // ... other job sites
]
```

---

## Legitimate Functionality vs. Privacy Overreach

### Legitimate Features:
1. **Job Application Autofill**: Injects saved resume data into Indeed, LinkedIn, and 80+ job board application forms
2. **Resume Builder Integration**: Syncs with developer's resumedone.co platform
3. **Multi-Domain SSO**: Allows users logged into one resume builder domain to seamlessly access others in the network
4. **Job Search Tracking**: Helps users track which jobs they've applied to
5. **A/B Testing**: Tests UI variants to improve user experience

### Privacy Overreach:
1. **Competitor Cookie Harvesting**: No legitimate reason to harvest session tokens from 40+ competitor resume builder sites (bestonlineresume.com, elegantcv.app, etc.). This is surveillance of user activity on competing platforms.

2. **IP Geolocation Tracking**: Could use browser locale (`navigator.language`) instead of IP address for region detection. IP tracking enables precise location monitoring.

3. **Excessive Analytics**: Tracking every click, form field, job title, company name, salary range, and LinkedIn profile URL goes beyond operational needs. This creates comprehensive dossiers on users' job search activities.

4. **No Granular Consent**: Users are not informed about:
   - Cross-domain cookie harvesting
   - IP address collection and geolocation
   - Detailed analytics tracking (LinkedIn profiles, job searches)
   - Data sharing with PostHog (third-party analytics provider)

---

## Recommendations

### For Users:
1. **Avoid Installation**: The privacy trade-offs outweigh the convenience unless you're comfortable with:
   - Your IP address and location being tracked
   - Your job search activity (queries, applications, salaries) being logged
   - Session cookies from ANY resume builder site you visit being harvested

2. **Alternative Extensions**: Use job-specific autofill tools that don't request `<all_urls>` or `cookies` permissions.

3. **If Already Installed**:
   - Revoke `<all_urls>` permission in Chrome settings (will break functionality)
   - Clear browsing data and cookies regularly
   - Use extension only in private browsing mode
   - Review PostHog privacy policy to understand data retention

### For Developer:
1. **Reduce Host Permissions**: Limit to specific job boards, not `<all_urls>`
2. **Remove IP Tracking**: Use `chrome.i18n.getUILanguage()` for locale detection
3. **Granular Cookie Access**: Only access cookies on developer-owned domains, not competitors
4. **Privacy Controls**: Add opt-out for analytics, clear disclosure of data collection
5. **Encrypt Storage**: Use `chrome.storage.session` for sensitive tokens, not `local`
6. **Rotate API Keys**: Don't hardcode PostHog/Indicative keys in source

### For Reviewers:
- This extension falls into a gray area: legitimate functionality with excessive surveillance
- Not malware, but privacy-invasive beyond reasonable expectations
- Users deserve transparency about cross-domain tracking and IP collection
- Consider flagging for privacy policy review or requiring granular permission scoping

---

## Conclusion

ResumeGPT provides genuine value (job autofill, resume management) but undermines user privacy through:
- **Aggressive cookie harvesting** from 40+ competitor domains
- **IP-based geolocation tracking**
- **Comprehensive analytics surveillance** of job search activities

The extension is **MEDIUM risk** - not malicious, but privacy-invasive. Users should be aware their browsing behavior, location, and session tokens on unrelated resume builder sites are being collected and analyzed.

**Final Verdict**: **MEDIUM RISK** - Legitimate functionality with significant privacy overreach. Recommend transparency improvements and permission scoping.
