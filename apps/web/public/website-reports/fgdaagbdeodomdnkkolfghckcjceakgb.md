# Vulnerability Report: CRM para Vendas por WhatsApp

## Metadata
- **Extension ID**: fgdaagbdeodomdnkkolfghckcjceakgb
- **Extension Name**: CRM para Vendas por WhatsApp
- **Version**: 2.0.13
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This is a legitimate CRM (Customer Relationship Management) extension developed by RD Station, a well-known Brazilian marketing automation and CRM platform. The extension integrates WhatsApp Web with the RD Station CRM system, allowing sales teams to manage customer conversations and sync contact information directly from WhatsApp to their CRM database.

The extension collects contact information including names, phone numbers, and email addresses from WhatsApp conversations and transmits this data to crm.rdstation.com. While this data collection is consistent with the extension's stated purpose as a sales CRM tool, users should be aware that their WhatsApp contact data is being synchronized to an external service. The extension requires user authentication and is designed for business/enterprise use.

## Vulnerability Details

### 1. MEDIUM: WhatsApp Contact Data Exfiltration
**Severity**: MEDIUM
**Files**: static/js/index.91be51e7.js, extension/content.js, extension/interceptor.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: The extension extracts contact information from WhatsApp Web conversations and transmits it to RD Station's CRM servers. This includes:
- Contact names
- Phone numbers
- Email addresses
- WhatsApp conversation metadata
- Chat activity events

**Evidence**:
```javascript
// From static/js/index.91be51e7.js line 2092-2129
function create(name, phoneNumber, organizationId, title, email, legal_bases, custom_fields) {
    let body = {
        contact: {
            name: name,
            emails: [],
            phones: [
                {
                    phone: phoneNumber,
                    type: 'work'
                }
            ],
            organization_id: organizationId,
            legal_bases: [
                legal_bases
            ],
            contact_custom_fields: custom_fields
        }
    };
    // ...
    axios_default().post("".concat(API_URI, "/contacts"), body, {
        headers: authHeader()
    })
}

// Phone number search function (line 2160-2194)
function searchByPhoneNumber(phoneNumber) {
    const body = {
        filters: [
            {
                nested: {
                    path: 'phones',
                    query: {
                        bool: {
                            should: [
                                {
                                    match_phrase_prefix: {
                                        'phones.phone': phoneNumber
                                    }
                                }
                            ]
                        }
                    }
                }
            }
        ],
        size: 100
    };
    return axios_default().post("".concat(API_URI, "/contacts/list"), body, {
        headers: authHeader()
    })
}
```

**Verdict**: This behavior is EXPECTED for a CRM extension and is disclosed in the extension's purpose ("CRM for WhatsApp Sales"). However, users should be aware that their WhatsApp contact data is being collected and stored on third-party servers. The extension requires authentication and appears to implement proper authorization checks.

### 2. MEDIUM: Third-Party Analytics Tracking
**Severity**: MEDIUM
**Files**: static/js/index.91be51e7.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: The extension sends user activity data to Segment.io for analytics purposes, including user IDs and instance IDs.

**Evidence**:
```javascript
// Line 1458-1463
_public.track = (args)=>{
    axios_default().post('https://api.segment.io/v1/track', (0,esm_object_spread_props._)((0,esm_object_spread._)({}, args), {
        writeKey: SEGMENT_TOKEN
    }));
};

// Line 1474-1485
helpers_segment_segment.track = function(event) {
    let properties = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : {};
    const { id: userId } = storage.getUserInfo();
    const { id: instance_id } = storage.getActiveInstance();
    segment_segment.track({
        event,
        userId,
        properties: (0,esm_object_spread._)({
            instance_id
        }, properties)
    });
};
```

**Verdict**: Standard analytics implementation for a commercial SaaS product. The tracking appears to be for product usage analytics rather than privacy-invasive surveillance.

### 3. LOW: Broad Content Script Injection
**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension injects content scripts into multiple domains including plugcrm.net and rdstation.com with all_frames: true, which increases the attack surface.

**Evidence**:
```json
"content_scripts": [
  {
    "js": ["extension/content.js"],
    "matches": [
      "https://web.whatsapp.com/*",
      "*://*.plugcrm.net/*",
      "*://*.rdstation.com/*"
    ],
    "all_frames": true
  }
]
```

**Verdict**: This appears necessary for the extension's functionality to communicate between WhatsApp Web and the RD Station CRM interface. The all_frames permission is likely needed to inject the CRM sidebar iframe.

## False Positives Analysis

1. **User-Agent Detection**: The ext-analyzer flagged navigator.userAgent access as potential exfiltration. However, review of the code shows this is only used for browser compatibility checks (detecting Internet Explorer and Firefox):
   ```javascript
   var isIE = typeof window !== 'undefined' && window.navigator ? /MSIE |Trident\/|Edge\//.test(window.navigator.userAgent) : false;
   var isFirefox = isBrowser && /Firefox/i.test(navigator.userAgent);
   ```

2. **window.open() Override**: The interceptor.js file overrides window.open(), but this is to detect when WhatsApp Web attempts to open new windows with deal/contact parameters, not for malicious purposes.

3. **Obfuscation Flag**: The extension uses webpack bundling which appears as obfuscation to static analysis, but the deobfuscated code is readable and the patterns are consistent with a React-based application.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| crm.rdstation.com/api/v3/* | Main CRM API | Contact data (names, phones, emails), user auth tokens, deal information | MEDIUM - Disclosed but extensive data collection |
| api.segment.io/v1/track | Analytics | User IDs, event data, instance IDs | LOW - Standard analytics |
| crm.rdstation.com/oauth/token | Authentication | Credentials, refresh tokens | LOW - Standard OAuth flow |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
This is a legitimate enterprise CRM tool from a reputable Brazilian SaaS company (RD Station). The extension functions exactly as advertised - it integrates WhatsApp Web with a CRM system to help sales teams manage customer relationships.

The MEDIUM risk rating is appropriate because:
1. **Disclosed Data Collection**: While extensive contact data is collected from WhatsApp, this is the core functionality and is disclosed in the extension's name and description
2. **Requires Authentication**: Users must actively sign in to use the extension, indicating they are aware of the service
3. **Business/Enterprise Context**: This is clearly a B2B tool, not a consumer extension trying to covertly harvest data
4. **No Evidence of Malicious Behavior**: The code shows standard CRM operations without hidden tracking, credential theft, or other malicious patterns

**Recommendation**: Users should install this extension only if they are RD Station customers and understand that their WhatsApp contact information will be synchronized to the RD Station CRM platform. Personal users looking for simple WhatsApp utilities should avoid this extension as it's designed for business sales teams.
