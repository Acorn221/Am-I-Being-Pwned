# Vulnerability Report: Ghelper

## Metadata
- **Extension ID**: nonmafimegllfoonjgplbabhmgfanaka
- **Extension Name**: Ghelper
- **Version**: 2.8.18
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Ghelper is a VPN/proxy extension marketed as a "browser plugin for developers, cross-border workers, and research institutes to secure and speed Internet surfing." The extension exhibits **highly problematic behavior** that constitutes a significant security and privacy risk. Most critically, it automatically disables competing proxy extensions without user consent, receives remote proxy configuration from multiple backend domains, and implements undisclosed remote testing/monitoring capabilities. The extension connects to multiple suspicious API endpoints and receives Base64-encoded PAC (Proxy Auto-Config) scripts from remote servers with double-encoding obfuscation. While proxy extensions legitimately need proxy permissions, the aggressive extension-killing behavior, remote configuration control, and lack of transparency about backend infrastructure represent serious concerns.

## Vulnerability Details

### 1. HIGH: Aggressive Competitive Extension Elimination

**Severity**: HIGH
**Files**: sw.min.js
**CWE**: CWE-284 (Improper Access Control)
**Description**: The extension automatically disables any other extension with "proxy" permissions without user consent, except for a hardcoded whitelist containing only "IDM Integration Module". This is done silently in the background on installation/startup.

**Evidence**:
```javascript
const pass_apps=["IDM Integration Module"];

function remove_other_apps(){
    var myid=chrome.runtime.id;
    chrome.management.getAll(function(apps){
        for(i in apps){
            var app=apps[i];
            if(pass_apps.includes(app.name)){continue;}
            if(myid==app.id||!app.enabled){continue;}
            for(i2 in app.permissions){
                if(app.permissions[i2]=='proxy'){
                    chrome.management.setEnabled(app.id,false);
                    console.log('remove app:',app.name);
                }
            }
        }
    });
}

remove_other_apps();  // Executed on startup
```

**Verdict**: This behavior is explicitly hostile to users and other extensions. While VPN extensions may legitimately want to prevent conflicts, completely disabling competitors without user knowledge or consent is unacceptable. The extension also provides UI warnings about proxy conflicts in check.html, but takes unilateral action rather than letting users decide.

### 2. HIGH: Remote Proxy Configuration with Double Base64 Encoding

**Severity**: HIGH
**Files**: sw.min.js
**CWE**: CWE-494 (Download of Code Without Integrity Check)
**Description**: The extension fetches PAC (Proxy Auto-Config) scripts from remote servers with double Base64 encoding obfuscation. These scripts control all browser traffic routing and are received without apparent integrity verification.

**Evidence**:
```javascript
function build_pac_script(conf){
    if(!conf.hasOwnProperty('pac')){return conf;}
    pac=conf.pac.value.pacScript.data;
    if(conf.hasOwnProperty('pac_encode')&&conf.pac_encode=="base64"){
        pac=atob(atob(pac));  // DOUBLE Base64 decoding
    }
    pac=pac.replace(/<cnips>/g,geoips);
    conf['pac']['value']['pacScript']['data']=pac;
    return conf;
}
```

All fetch requests include a `Pac-Encode: base64` header, suggesting the backend returns encoded PAC scripts. The double encoding is particularly suspicious as it serves no legitimate technical purpose beyond obfuscation.

**Verdict**: Double encoding of remote executable code (PAC scripts control all traffic) is a significant red flag. This prevents casual inspection and suggests intentional obfuscation.

### 3. MEDIUM: Multiple Suspicious Backend Domains with Wildcard Subdomain Rotation

**Severity**: MEDIUM
**Files**: sw.min.js
**CWE**: CWE-912 (Hidden Functionality)
**Description**: The extension communicates with multiple backend API domains using wildcard subdomain generation, suggesting infrastructure designed to evade takedowns or monitoring.

**Evidence**:
```javascript
var default_api=[];
default_api.push('https://*.broapi.com/api2');
default_api.push('https://*.apihuawei.com/api2');
default_api.push('http://*.broapi.com/api2');  // Note: HTTP fallback
default_api.push('https://*.gheapi.com/api2');
default_api.push('http://*.plebvps.com/api2');

function make_tmp_url(host){
    host=host.replace("*",get_uuid());  // Generate random UUID subdomain
    return host;
}
```

The extension also uses DNS-over-HTTPS (DoH) to resolve additional API endpoints:
```javascript
const doh_servers=["https://223.5.5.5/resolve","https://223.6.6.6/resolve"];  // Alibaba Cloud DNS

function async_api_from_doh(domain){
    // Fetches TXT records for v2.ghelper.net and v4.ghelper.net
    // to discover additional API endpoints
}
```

**Verdict**: The combination of wildcard subdomains with UUID generation, HTTP fallbacks, and DoH-based dynamic endpoint discovery suggests infrastructure designed for resilience against blocking. The domain "apihuawei.com" is particularly suspicious as it appears designed to impersonate Huawei.

### 4. MEDIUM: Undisclosed Remote Performance Monitoring System

**Severity**: MEDIUM
**Files**: sw.min.js
**CWE**: CWE-359 (Exposure of Private Personal Information)
**Description**: The extension implements a remote "tester" system that pings arbitrary URLs provided by the backend and reports timing data back to the server.

**Evidence**:
```javascript
function run_one_tester(row){
    var st=get_time();
    fetchWithTimeout(row.ping_url,{mode:"cors"},3000).then(function(req){
        var ping_time=get_time()-st;
        tester[row.id]={
            id:row.id,
            ping_time:ping_time,
            poster:row.poster,
            ping_adjust:row.ping_adjust
        };
        chrome.storage.local.set({tester:tester});
    }).catch(console.log);
}

// Tester results are sent back in session requests
query["body"]=JSON.stringify({tester:data.tester});
```

**Verdict**: This appears to be a network measurement/testing system. While potentially benign (measuring proxy performance), it's completely undisclosed and allows the backend to probe arbitrary URLs from users' browsers. The purpose of "poster" and "ping_adjust" fields is unclear.

### 5. MEDIUM: Session Token System with 3-Hour Refresh Cycle

**Severity**: MEDIUM
**Files**: sw.min.js
**CWE**: CWE-319 (Cleartext Transmission of Sensitive Information)
**Description**: The extension maintains persistent session tokens that are transmitted to backend servers every 3 hours. Some API endpoints use HTTP (not HTTPS).

**Evidence**:
```javascript
function cron_chrome_session(){
    var delayInMinutes=180;  // 3 hours
    chrome.alarms.clear();
    chrome.alarms.create({delayInMinutes:delayInMinutes});
    async_session(set_chrome_settings);
}

// Token sent in both headers and query params
query["headers"]["token"]=data.token;
default_query["token"]=data.token;
```

**Verdict**: While session management is standard for services, the use of HTTP fallback endpoints means tokens could be transmitted in cleartext. The 3-hour refresh suggests ongoing tracking of active users.

### 6. LOW: Language Information Disclosure

**Severity**: LOW
**Files**: popup.min.js, options.min.js, check.min.js
**CWE**: CWE-359 (Exposure of Private Personal Information)
**Description**: All API requests include the user's browser language setting.

**Evidence**:
```javascript
msg['query']["lang"]=window.navigator.language;
```

**Verdict**: Minor privacy disclosure, could be used for fingerprinting or user profiling, but typical for internationalized services.

## False Positives Analysis

1. **Proxy permission usage**: Proxy extensions legitimately need the "proxy" permission to function. This is not suspicious.

2. **Management permission for conflict detection**: Using `chrome.management` to detect proxy conflicts is reasonable, but the automatic disabling behavior crosses the line.

3. **Remote configuration**: VPN/proxy services often use remote configuration for server lists and routing rules. However, the double encoding and lack of integrity checks are problematic.

4. **DoH usage**: Using DNS-over-HTTPS can be a privacy feature, but here it appears to be used primarily for censorship evasion to discover additional API endpoints.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| *.broapi.com/api2 | Primary API (UUID subdomains) | Token, version, tester results, language | HIGH - Wildcard subdomain rotation |
| *.apihuawei.com/api2 | Secondary API | Token, version, tester results, language | HIGH - Impersonation domain |
| *.gheapi.com/api2 | Tertiary API | Token, version, tester results, language | MEDIUM - Related to ghelper.net |
| *.plebvps.com/api2 | Quaternary API | Token, version, tester results, language | MEDIUM - VPS provider name |
| 223.5.5.5/resolve | Alibaba DoH DNS | TXT record queries for ghelper.net | LOW - DNS resolution |
| 223.6.6.6/resolve | Alibaba DoH DNS | TXT record queries for ghelper.net | LOW - DNS resolution |
| ghelper.net | Homepage/branding | N/A | LOW - Legitimate homepage |

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**:

While Ghelper is a legitimate VPN/proxy service, it employs several practices that are deceptive, privacy-invasive, and potentially malicious:

1. **Aggressive anti-competitive behavior**: Automatically disabling competing extensions without user consent is unacceptable and violates Chrome Web Store policies.

2. **Infrastructure obfuscation**: The use of double Base64 encoding, wildcard subdomain rotation with UUIDs, HTTP fallbacks, and DoH-based endpoint discovery suggests an infrastructure designed to evade monitoring and blocking rather than legitimate technical requirements.

3. **Suspicious domain names**: "apihuawei.com" appears designed to impersonate Huawei, which is deceptive.

4. **Undisclosed functionality**: The remote "tester" system that pings arbitrary URLs and reports timing data is completely undisclosed in the extension description.

5. **Lack of code transparency**: For a security tool with 200,000 users, the obfuscated code and double-encoded remote configuration represent significant trust issues.

The extension's stated purpose (VPN/proxy service) is legitimate, and the core functionality aligns with that purpose. However, the implementation choices consistently favor obfuscation, evasion, and anti-competitive behavior over transparency and user control. The extension appears designed for markets with internet censorship (evidenced by Chinese default locale and DoH usage for censorship evasion), but the aggressive tactics and infrastructure design raise substantial concerns.

**Recommendation**: This extension should be flagged for policy review regarding the extension-killing behavior. Users should be aware that installing this extension will automatically disable other VPN/proxy extensions. The lack of transparency around backend infrastructure and the double-encoded remote configuration are significant red flags that warrant deeper investigation.
