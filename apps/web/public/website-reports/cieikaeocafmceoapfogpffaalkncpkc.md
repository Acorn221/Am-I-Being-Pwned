# Vulnerability Report: 谷歌上网助手 开发 (Ghelper)

## Metadata
- **Extension ID**: cieikaeocafmceoapfogpffaalkncpkc
- **Extension Name**: 谷歌上网助手 开发 (Ghelper)
- **Version**: 2.8.18
- **Users**: ~400,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This is a Chinese proxy/VPN extension ("Google Internet Assistant") that provides proxy functionality to help users access blocked websites. While the core proxy functionality is legitimate for this extension type, it exhibits aggressive anti-competitive behavior by automatically disabling ALL other extensions with proxy permissions without user consent or notification. The extension uses the `management` permission to enumerate and forcibly disable competing proxy/VPN extensions, which violates user choice and Chrome Web Store policies.

Additionally, the extension uses remote configuration to dynamically receive proxy PAC scripts from multiple backend servers, with Base64 double-encoding that could obscure the actual proxy behavior from users and reviewers.

## Vulnerability Details

### 1. HIGH: Forced Disabling of Competing Extensions

**Severity**: HIGH
**Files**: sw.min.js (lines 52-54), assets/js/check.min.js (line 20)
**CWE**: CWE-912 (Hidden Functionality)
**Description**: The extension automatically disables all other extensions that have the `proxy` permission, with only a hardcoded whitelist for "IDM Integration Module". This is done silently without user consent or notification.

**Evidence**:
```javascript
// sw.min.js line 52-54
function remove_other_apps(){
  var myid=chrome.runtime.id;
  chrome.management.getAll(function(apps){
    for(i in apps){
      var app=apps[i];
      if(pass_apps.includes(app.name)){continue;}  // Only whitelists "IDM Integration Module"
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
remove_other_apps();  // Executed on extension startup
```

**Verdict**: This behavior is deceptive and anti-competitive. While VPN/proxy extensions may legitimately need to check for conflicts, forcibly disabling competing extensions without user consent violates user autonomy and Chrome Web Store policies. The extension presents itself as a "helper" but behaves like malware in monopolizing proxy control.

### 2. MEDIUM: Remote Configuration with Double Base64 Encoding

**Severity**: MEDIUM
**Files**: sw.min.js (lines 1, 19, 31-37)
**CWE**: CWE-494 (Download of Code Without Integrity Check)
**Description**: The extension receives PAC (Proxy Auto-Config) scripts from remote servers with double Base64 encoding, which obscures the actual proxy behavior.

**Evidence**:
```javascript
// sw.min.js line 19
pac=conf.pac.value.pacScript.data;
if(conf.hasOwnProperty('pac_encode')&&conf.pac_encode=="base64"){
  pac=atob(atob(pac));  // Double Base64 decode
}
```

Remote API endpoints:
```javascript
default_api.push('https://*.chrapi.com/api2');
default_api.push('https://*.apikuaishou.com/api2');
default_api.push('http://*.chrapi.com/api2');  // Note: HTTP, not HTTPS
default_api.push('http://*.gheapi.com/api2');
default_api.push('https://*.gheapi.com/api2');
```

The extension also uses DNS-over-HTTPS (DoH) queries to Chinese DNS servers (223.5.5.5, 223.6.6.6) to discover additional API endpoints dynamically.

**Verdict**: While remote configuration is common for proxy extensions, the double Base64 encoding is suspicious and could be used to hide malicious proxy rules from static analysis. The use of HTTP (not HTTPS) for some API endpoints also exposes users to MITM attacks. However, this appears to be a legitimate technique for a proxy service that needs to update server configurations.

## False Positives Analysis

**Proxy Permission Usage**: The core use of `chrome.proxy` API is legitimate for a VPN/proxy extension. The extension sets PAC scripts to route traffic through proxy servers, which is its stated purpose.

**Alarm Permission**: Used for periodic session renewal (every 180 minutes) to refresh proxy configuration from backend servers - this is normal for proxy services that need to maintain fresh server lists.

**Storage Permission**: Used to cache proxy configuration, API endpoints, and user tokens - legitimate for offline functionality.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| chrapi.com/api2 | Proxy configuration API | User token, version, tester results | Medium - HTTP variant exists |
| apikuaishou.com/api2 | Backup proxy config API | User token, version, tester results | Medium |
| gheapi.com/api2 | Backup proxy config API | User token, version, tester results | Medium - HTTP variant exists |
| ghelper.net | Homepage/documentation | N/A | Low |
| 223.5.5.5/resolve | DoH DNS queries | Domain names for TXT records | Low |
| 223.6.6.6/resolve | DoH DNS queries | Domain names for TXT records | Low |

**Data Collection**: The extension sends "tester results" (ping times to various servers) back to the API, which appears to be for server performance monitoring. User tokens are sent for authentication but no other PII appears to be transmitted.

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**: While this extension provides legitimate proxy functionality for its 400,000 users (primarily in China for accessing blocked websites), it crosses the line into malicious behavior by forcibly disabling ALL competing proxy/VPN extensions without user consent. This is:

1. **Deceptive**: No disclosure in privacy policy or extension description about disabling other extensions
2. **Anti-competitive**: Monopolizes proxy control by eliminating user choice
3. **Violates Chrome policies**: Extensions should not manipulate other extensions without explicit user action

The remote configuration with double Base64 encoding and HTTP endpoints is concerning but appears to be for legitimate proxy service management rather than malware distribution.

**Recommendation**: The extension should be flagged for policy violation. The `management` permission abuse makes this HIGH risk despite the otherwise legitimate proxy functionality. Users should be warned that installing this extension will disable their other VPN/proxy tools.
