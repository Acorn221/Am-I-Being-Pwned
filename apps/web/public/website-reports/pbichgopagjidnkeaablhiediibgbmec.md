# Vulnerability Report: Comparador EscolhaSegura

## Metadata
- **Extension ID**: pbichgopagjidnkeaablhiediibgbmec
- **Extension Name**: Comparador EscolhaSegura
- **Version**: 14.35.0
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Comparador EscolhaSegura is a Brazilian shopping comparison extension that helps users find better prices and discount coupons. While the extension appears to serve its stated purpose legitimately, it employs several intrusive techniques that raise privacy concerns. The extension intercepts XMLHttpRequest calls, harvests cookies, manipulates DOM elements programmatically, and collects detailed product browsing data that is transmitted to escolhasegura.com.br and third-party services including Carrefour's API gateway.

The extension runs on all HTTP/HTTPS sites (`<all_urls>`) and injects sophisticated scripts that hook into the browser's navigation APIs (pushState, replaceState) and XMLHttpRequest prototype to monitor and intercept web traffic. While these behaviors appear designed to facilitate price comparison and coupon application on e-commerce sites, the broad scope of access and data collection capabilities warrant a MEDIUM risk classification.

## Vulnerability Details

### 1. MEDIUM: XMLHttpRequest Prototype Hooking
**Severity**: MEDIUM
**Files**: injection/injection.js (lines 331-356)
**CWE**: CWE-940 (Improper Verification of Source of a Communication Channel)
**Description**: The extension hooks the XMLHttpRequest prototype to intercept all AJAX requests made by visited websites. This allows it to monitor and capture HTTP request data including URLs and request bodies.

**Evidence**:
```javascript
var esg_embuti = XMLHttpRequest[esg_edemas][esg_barra];
var esg_jorrai = XMLHttpRequest[esg_edemas][esg_tombou];

window.esg_descre = {};

XMLHttpRequest[esg_edemas][esg_barra] = function(esg_elidas, esg_aguca) {
    this.esg_opiai = esg_aguca;
    esg_embuti.apply(this, arguments);
};

XMLHttpRequest[esg_edemas][esg_tombou] = function(esg_podao) {
    if (esg_podao) {
        window.esg_descre[this.esg_opiai] = esg_podao;
    }
    esg_jorrai.apply(this, arguments);
}
```

**Verdict**: This technique enables the extension to monitor all AJAX traffic on visited pages. While potentially used for legitimate price comparison functionality, it represents a significant privacy risk as it can intercept sensitive data transmitted by other web applications.

### 2. MEDIUM: Cookie Harvesting
**Severity**: MEDIUM
**Files**: injection/injection.js (lines 130-136)
**CWE**: CWE-539 (Use of Persistent Cookies Containing Sensitive Information)
**Description**: The extension implements functionality to read cookies from visited websites, which could include session tokens and authentication credentials.

**Evidence**:
```javascript
function esg_destoo(esg_nanou) {
    return new Promise(esg_findas => {
        const esg_apeais = `; ${document.cookie}`;
        const esg_isolo = esg_apeais.split(`; ${esg_nanou.esg_apinha}=`);
        const esg_varri = (esg_isolo.length == 2) ? esg_isolo.pop().split(';').shift() : null;
        esg_findas(esg_varri ? {esg_varri} : null);
    });
}
```

**Verdict**: The cookie reading functionality appears designed to extract specific cookie values, likely for coupon application flows on e-commerce sites. However, the extension runs on all URLs, creating risk that it could access authentication cookies on non-shopping sites.

### 3. MEDIUM: Data Exfiltration to External Services
**Severity**: MEDIUM
**Files**: background.js (lines 48, 52, 55, 58), index.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: The extension collects and transmits data to multiple endpoints including escolhasegura.com.br and apigw.cloud.carrefour.com.br. The static analyzer detected exfiltration flows where DOM-scraped content is sent to external servers.

**Evidence**:
```javascript
// Product search with user data
(0,_bg_listeners__WEBPACK_IMPORTED_MODULE_0__.sQ)('bg_searchProduct', (esg_goeles, esg_logrei, esg_vianes) => __awaiter(void 0, void 0, void 0, function* () {
    (0,_tools_bg_esg_marido.rh)(_tools_bg_esg_marido.Ay.esg_mirra, 'actions/json/product', esg_goeles, esg_vianes, { ttl: _tools_bg_esg_marido.ns });
}));

// Monitoring/tracking data
(0,_bg_listeners__WEBPACK_IMPORTED_MODULE_0__.sQ)('bg_sendMonitoring', (esg_goeles, esg_logrei, esg_vianes) => __awaiter(void 0, void 0, void 0, function* () {
    esg_goeles.new_button = yield (0,_bg_stats__WEBPACK_IMPORTED_MODULE_1__.stats_getBewButton)();
    (0,_tools_bg_esg_marido.rh)(_tools_bg_esg_marido.Ay.esg_zurzem, 'comparador/monitoraProduto', esg_goeles, esg_vianes, { ttl: _tools_bg_esg_marido.LP });
}));
```

**Verdict**: The extension collects product data and user behavior metrics from visited e-commerce sites and transmits them to backend servers. This appears to be disclosed functionality for price comparison services, but the extent of data collection and third-party sharing (Carrefour API) is concerning.

### 4. LOW: History API Hijacking
**Severity**: LOW
**Files**: injection/injection.js (lines 5-126)
**CWE**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
**Description**: The extension overrides window.history.pushState and window.history.replaceState to monitor single-page application navigation events.

**Evidence**:
```javascript
const esg_soltas = window.history.pushState;
const esg_ovadas = window.history.replaceState;

function esg_pareis() {
    esg_racoes();
    window.dispatchEvent(esg_amiudo('pushstate'));
    return esg_soltas.apply(window.history, arguments);
}

window.history.pushState = esg_pareis;
window.history.replaceState = esg_feixes;
```

**Verdict**: This allows the extension to detect navigation on single-page applications, likely to refresh price comparison data when users navigate to different products. The implementation appears benign but represents modification of core browser APIs.

## False Positives Analysis

- **Webpack Bundling**: The extension uses webpack bundling which creates some visual complexity but is not obfuscation. React libraries are included for UI rendering.
- **Sizzle/jQuery**: The extension includes Sizzle and references jQuery for DOM manipulation on e-commerce sites to apply coupons and extract product information. This is standard for extensions that need robust selector support.
- **GraphQL Queries**: Some GraphQL query strings were detected in the bundled code, likely for querying the escolhasegura.com.br backend API.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| comparador.escolhasegura.com.br | Primary backend service | Product searches, user activity tracking, error reports | Medium - Disclosed functionality but extensive tracking |
| apigw.cloud.carrefour.com.br | Carrefour API Gateway | Product/price data queries | Medium - Third-party data sharing not clearly disclosed |
| www.girafa.com.br | Unknown service | Unknown | Low - Minimal evidence of usage |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
Comparador EscolhaSegura is a legitimate shopping comparison tool that employs intrusive technical methods to achieve its stated functionality. The extension uses XHR hooking, cookie access, and DOM manipulation to extract product information and apply coupons on e-commerce sites. While these behaviors align with the extension's disclosed purpose, several factors elevate the risk:

1. **Broad Scope**: The extension runs on all HTTP/HTTPS URLs with `<all_urls>` content script access, not just shopping sites
2. **Intrusive Techniques**: XHR prototype hooking and cookie harvesting are powerful techniques that could be abused
3. **Data Collection**: Extensive monitoring and transmission of user browsing behavior to remote servers
4. **Third-Party Sharing**: Integration with Carrefour's API suggests data sharing with third parties
5. **Obfuscated Variable Names**: While not malicious obfuscation, the nonsensical variable names (esg_*) make code review difficult

The extension does not appear to be overtly malicious, but users should be aware that it monitors their e-commerce browsing activities extensively and shares this data with the service provider and potentially third parties. The privacy implications are significant despite the legitimate use case.

**Recommendation**: Users should only install this extension if they trust EscolhaSegura with their shopping behavior data and understand that it operates on all websites they visit, not just shopping sites.
