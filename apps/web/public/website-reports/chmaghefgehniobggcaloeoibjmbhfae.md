# Vulnerability Report: GetEmail.io for Gmail/Outlook/Salesforce

## Metadata
- **Extension ID**: chmaghefgehniobggcaloeoibjmbhfae
- **Extension Name**: GetEmail.io for Gmail/Outlook/Salesforce
- **Version**: 0.0.141
- **Users**: ~70,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

GetEmail.io is an email discovery tool that helps users find contact information for people viewed in Gmail, Outlook, and Salesforce. The extension provides legitimate functionality for B2B sales and recruiting use cases. However, it collects extensive user data including email content, browsing behavior, and contact information, which is sent to the getemail.io backend for processing. While the extension's privacy policy likely discloses this data collection, the scope of data access is broad and includes sensitive information from email communications.

The extension shows indicators of obfuscation in the static analyzer output, though much of this appears to be from webpack bundling rather than intentional code hiding. The main privacy concerns stem from the breadth of data collection rather than hidden malicious behavior.

## Vulnerability Details

### 1. MEDIUM: Broad Email Content and Contact Data Collection

**Severity**: MEDIUM
**Files**: cplx-cb02bcec.js, cplx-b4c67ebc.js, cplx-21b3ba3a.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**: The extension extracts email addresses, names, company information, and message content from Gmail, Outlook, and Salesforce interfaces and transmits this data to api.getemail.io for email discovery processing.

**Evidence**:

From `cplx-cb02bcec.js` (lines 42-73), the extension defines multiple API endpoints:
```javascript
const ae = "https://api.getemail.io",
  p = `${ae}/extension`,
  pe = `${p}/ext/people-search`,
  q = `${p}/ext/start-search-email-quick-response`,
  we = `${p}/view-email-user-multi`,
  be = `${p}/get-company-info/`,
  xe = `${p}/tracking-email-v2`,
  Be = `${p}/store-google-mail-info`,
  ke = `${p}/store-google-mail-list`,
```

Email search functionality (lines 1278-1304):
```javascript
oe = async o => {
  try {
    o.profileImage = o && o.profileImage ? o.profileImage.replace(/&amp;/g, "&") : void 0,
    t = { emailList: [], bad_emails: [] },
    n = await f.post(q, o), // Sends search data to getemail.io
    t = te(n, t), t
  }
}
```

DOM scraping of email content from Gmail:
```javascript
let s = await document.querySelectorAll("div[data-message-id]");
s = s.length > 0 ? s[s.length - 1].querySelectorAll(r) :
    document.querySelectorAll(r)
```

**Verdict**: This is expected behavior for an email discovery tool, but the breadth of data access (email content, contacts, browsing patterns) represents a medium privacy risk. Users installing this extension should be aware that their email interactions are being analyzed and transmitted to a third-party service.

### 2. MEDIUM: Comprehensive User Tracking and Analytics

**Severity**: MEDIUM
**Files**: cplx-cb02bcec.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**: The extension implements detailed analytics tracking using Snowplow and custom tracking, collecting screen resolution, viewport size, timezone, language, user behavior events, and page navigation patterns.

**Evidence**:

From lines 486-520:
```javascript
w = async (o, { variation: t, pageTitle: n }, s = !1) => {
  const M = {
    experiment: "track_ge_gmail_extension",
    variation: t,
    e: E,
    p: "web",
    tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
    page: n,
    lang: navigator.language || navigator.userLanguage,
    res: `${window.screen.width}x${window.screen.height}`,
    vp: `${window.innerWidth}x${window.innerHeight}`,
    ds: `${document.body.clientWidth}x${document.body.clientHeight}`,
    duid: _,
    sid: c,
    extension_version: chrome.runtime.getManifest().version,
    referrer: document.referrer,
    pathname: i.pathname,
    url: window.location.href
  };
  window.snowplow && (a || s) && (o === "trackPageView" ?
    window.snowplow(`${o}:sp2`, n, [{
      schema: "iglu:io.getemail/custom_track/jsonschema/1-0-0",
      data: M
    }]) : console.info("Not getting appropriate track type"))
}
```

The extension loads Snowplow tracker from web-accessible resources and tracks various user actions including page views, email searches, and feature usage.

**Verdict**: While analytics are common in modern extensions, the detailed nature of tracking (including full URLs and screen dimensions) combined with email context creates a privacy concern. This is disclosed functionality but represents a medium risk due to the combination with email access.

### 3. MEDIUM: AI/LLM Integration with Email Content

**Severity**: MEDIUM
**Files**: cplx-cb02bcec.js, cplx-96d6a401.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**: The extension includes AI-powered email assistance features that send email content to Claude (Anthropic) via the getemail.io backend for processing, including reply generation, summarization, and translation.

**Evidence**:

From lines 1352-1397:
```javascript
Qt = async (o, t, n) => {
  const i = (l => {
    const _ = [];
    l.forEach((c, E) => {
      _.push({
        role: c.role,
        content: [{ type: "text", text: c.content || "ok" }]
      })
    }), _
  })(o == null ? void 0 : o.conversionArray),
  u = "https://api.getemail.io/extension/llm-prompt",
  r = {
    model: "anthropic.claude-3-sonnet-20240229-v1:0",
    options: {
      anthropic_version: "bedrock-2023-05-31",
      max_tokens: 1024,
      messages: i
    },
    request_type: s
  };
  fetch(u, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(r),
    signal: n.signal
  })
}
```

AI prompts are pre-configured during installation (from cplx-21b3ba3a.js, lines 94-102):
```javascript
await _("Reply or Archive ?", "what to do with this email, reply or archive ? please reply with only one word.", void 0, !1),
await _("Give short summary of email", "Give short summary of email in maximum give me only summary 20 words.", void 0, !1),
await _("Translate email to french", "Translate email to french", void 0, !1),
await _("Give me ideas for how to reply", "Give me ideas for how to reply", void 0, !1),
await _("Give me senders name, company", "Give me senders name, company", void 0, !1),
```

**Verdict**: Sending email content to AI services (even through the vendor's proxy) represents a medium privacy risk. While these are optional features that users can activate, the integration means potentially sensitive email content is being transmitted to third-party AI providers. This should be clearly disclosed to users.

### 4. LOW: Externally Connectable Configuration

**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-923 (Improper Restriction of Communication Channel to Intended Endpoints)

**Description**: The extension declares externally_connectable for *.getemail.io, allowing web pages on that domain to communicate with the extension. This is a standard practice for vendor websites but increases attack surface.

**Evidence**:

From manifest.json (lines 113-117):
```json
"externally_connectable": {
  "matches": [
    "*://*.getemail.io/*"
  ]
}
```

**Verdict**: This is legitimate functionality allowing the vendor's website to interact with the extension. The risk is low as the domain is controlled by the extension author, but it does create an additional attack vector if the website were compromised.

## False Positives Analysis

1. **Obfuscation Flag**: The static analyzer flagged this extension as obfuscated. However, examination of the code reveals this is primarily webpack/rollup bundling with module imports and variable name minification, which is standard practice for modern JavaScript projects. There's no evidence of intentional code obfuscation to hide malicious behavior.

2. **OAuth2 and Google API Access**: The extension requests OAuth2 scopes for Google Sheets and user profile. This is legitimate functionality for the product's features (exporting contacts to spreadsheets, user authentication). The OAuth flow is properly implemented through Google's authorization servers.

3. **DeclarativeNetRequest Usage**: The extension uses declarativeNetRequest to block tracking pixels (`https://api.getemail.io/extension/track-mail`). This appears to be for controlling their own tracking functionality, likely related to email open tracking features.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.getemail.io/extension/ext/people-search | Contact discovery | Email addresses, names, domains | MEDIUM |
| api.getemail.io/extension/ext/start-search-email-quick-response | Email search | Contact info, profile images | MEDIUM |
| api.getemail.io/extension/llm-prompt | AI processing | Email content, conversation history | MEDIUM |
| api.getemail.io/extension/view-email-user-multi | User enrichment | Email addresses, view events | MEDIUM |
| api.getemail.io/extension/tracking-email-v2 | Email tracking | Tracking IDs, email metadata | MEDIUM |
| api.getemail.io/extension/store-google-mail-info | Gmail data sync | Email metadata, sender info | MEDIUM |
| app.getemail.io/register | User registration | User credentials, installation ID | LOW |
| fidelity.getemail.io/mypage.php | Loyalty/rewards | User ID | LOW |
| logo.clearbit.com | Company logos | Domain names | LOW |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

GetEmail.io provides legitimate B2B sales and recruiting functionality but collects extensive data from users' email communications. The extension is transparent about its purpose (finding email addresses), and the data collection is necessary for its core functionality. However, several factors elevate this to a MEDIUM risk:

1. **Broad Data Collection**: The extension accesses email content, contacts, browsing patterns, and user behavior across Gmail, Outlook, and Salesforce.

2. **Third-Party AI Processing**: Email content is sent to Claude/Anthropic for AI features, adding an additional party with access to potentially sensitive communications.

3. **Extensive Analytics**: Detailed tracking of user behavior, screen dimensions, and navigation patterns combined with email context.

4. **Large User Base**: With 70,000+ users, any privacy concerns have broad impact.

The extension does not exhibit malicious behavior and appears to operate as advertised. The MEDIUM rating reflects legitimate privacy concerns inherent to email discovery tools rather than hidden malware. Users should understand that installing this extension grants broad access to their email communications and contact information, which will be transmitted to and processed by getemail.io's servers.

**Recommendations for Users**:
- Review the privacy policy before installation
- Understand that email content and contacts will be transmitted to third-party services
- Consider using on a dedicated business email account rather than personal email
- Be aware that AI features send email content to external AI providers
- Regularly review and delete stored data through the extension's settings if available
