# Vulnerability Report: iGuge Helper

## Metadata
- **Extension ID**: ncldcbhpeplkfijdhnoepdgdnmjkckij
- **Extension Name**: iGuge Helper
- **Version**: 2.3.9
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

iGuge Helper is a VPN/proxy extension from China with approximately 200,000 users. While the extension provides legitimate proxy functionality, it exhibits HIGH-RISK behavior by actively disabling competing browser extensions without explicit user consent. The extension uses the `chrome.management` API to detect and forcibly disable any other extensions with proxy permissions (except those on an allowlist controlled by the remote server), and specifically targets "Tampermonkey" for disablement. This anti-competitive behavior represents a significant violation of user autonomy and Chrome Web Store policies. The extension implements authenticated proxy routing with PAC (Proxy Auto-Config) scripts fetched from remote servers and communicates with multiple backend domains in encrypted format.

## Vulnerability Details

### 1. HIGH: Unauthorized Extension Disablement (Anti-Competitive Behavior)

**Severity**: HIGH
**Files**: js/iggservice.js (lines 446-462), js/main.js (lines 161-174), helper/js/tracket.js (lines 63-73)
**CWE**: CWE-284 (Improper Access Control)
**Description**: The extension systematically enumerates all installed extensions and forcibly disables competing proxy extensions and specifically targets Tampermonkey.

**Evidence**:
```javascript
// iggservice.js lines 458-461
function check_clash_app(ExtensionInfo) {
    if (ExtensionInfo.id != chrome.runtime.id && typeof ExtensionInfo.permissions !== "undefined"
        && ExtensionInfo.permissions.indexOf('proxy') !== -1 && ExtensionInfo.enabled === true
        && ExtensionInfo.id !== chrome.runtime.id) {
        if (!iggcfg.mzk_config.proxy_permissions_namewhilelist.includes(ExtensionInfo.name))
            chrome.management.setEnabled(ExtensionInfo.id, false);
    }
}

// main.js lines 167-172 - Even more aggressive disablement
function disable_clash_app(ExtensionInfo) {
    if (typeof ExtensionInfo.permissions !== "undefined" && ExtensionInfo.permissions.indexOf('proxy') !== -1
        && ExtensionInfo.enabled === true && ExtensionInfo.id !== chrome.runtime.id) {
        chrome.management.setEnabled(ExtensionInfo.id, false);
    } else if (ExtensionInfo.name == "Tampermonkey") {
        chrome.management.setEnabled(ExtensionInfo.id, false);
    }
}
```

**Verdict**: This is a clear violation of user autonomy. While VPN extensions disabling other VPNs to avoid conflicts is defensible, the whitelist is controlled remotely (`data.proxy_namewhilelist` from server), and the specific targeting of Tampermonkey (which isn't a proxy extension) indicates anti-competitive behavior rather than technical necessity.

### 2. MEDIUM: Remote Code Configuration with Encrypted Communication

**Severity**: MEDIUM
**Files**: js/iggservice.js (lines 291-379, 813-841)
**CWE**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
**Description**: The extension fetches PAC (Proxy Auto-Config) scripts from remote servers with encrypted communication and applies them to the browser's proxy settings. The remote server can control which domains are proxied through their infrastructure.

**Evidence**:
```javascript
// Lines 820-826 - Remote PAC script fetching
MZK_getJSON_DATA("chromeext/pac/show", { sid: iggcfg.mzk_select_server_info.line_sn,
    gpd: 1, geoip: iggcfg.mzk_pac_config.geoip_switch.toString(), top_server: top_server },
    function (data) {
        if (typeof data.result !== "undefined" && data.result == 'ok') {
            load_default_data(function () {
                var browser_proxy = new Mzk_Chrome_proxy();
                data.tpl = data.tpl.replace('__GEOIP_LIST__', iggcfg.mzk_pac_config.geoip_data);
                var config = browser_proxy.generateProxyConfig(mode, data.tpl);
                browser_proxy.applyChanges(config, cb);
            });
        }
    });
```

**Verdict**: While remote PAC configuration is standard for legitimate VPN services, the ability for the remote server to arbitrarily change routing rules combined with encrypted communication makes verification difficult. This is expected behavior for a proxy service but represents a trust boundary issue.

### 3. MEDIUM: Extension Enumeration and Data Exfiltration

**Severity**: MEDIUM
**Files**: helper/js/tracket.js (lines 63-73)
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension collects detailed information about all installed extensions with proxy permissions and includes this in feedback/tracking submissions to remote servers.

**Evidence**:
```javascript
// tracket.js lines 64-72
function get_otherproxylist() {
    chrome.management.getAll(function (ExtensionInfo) {
        ExtensionInfo.forEach(getappdetails);
    });
}

function getappdetails(ExtensionInfo) {
    if (typeof ExtensionInfo.permissions !== "undefined"
        && ExtensionInfo.permissions.indexOf('proxy') !== -1
        && ExtensionInfo.enabled === true && ExtensionInfo.id !== chrome.runtime.id) {
        other_app_list.push(JSON.stringify(ExtensionInfo));
    }
}
```

**Verdict**: While the extension uses this data ostensibly for debugging/support purposes, collecting and transmitting full extension metadata (names, IDs, permissions) to remote servers represents privacy overreach and potential competitive intelligence gathering.

### 4. LOW: Multiple Fallback API Domains

**Severity**: LOW
**Files**: js/iggservice.js (lines 57-69)
**CWE**: CWE-710 (Improper Adherence to Coding Standards)
**Description**: The extension maintains multiple backup API domains and dynamically switches between them, which is common for censorship circumvention but can complicate security analysis.

**Evidence**:
```javascript
iggcfg.mzk_backup_server = [
    "https://$udomain$.igsync.net/",
    "https://igg.imsfast.net/E20j19RdYi6hlOKW8v/",
    "http://$udomain$.igg-sync.com/",
    "http://$udomain$.igg-sync.net/",
    "http://$udomain$.imsfast.org/93f83938/",
    "http://igg.fyi/",
    "https://$udomain$.dingdingsync.com/",
];
```

**Verdict**: This is expected behavior for proxy services operating in restrictive network environments, but the HTTP (non-HTTPS) fallback domains and hash-based subdomain generation add complexity that could hide malicious updates.

## False Positives Analysis

- **Proxy Permission Usage**: Expected for a VPN/proxy extension - NOT A VULNERABILITY
- **Host Permissions `*://*/*`**: Required for routing all traffic through proxy - NOT A VULNERABILITY
- **webRequest Permission**: Needed for proxy authentication handling - NOT A VULNERABILITY
- **Storage Permission**: Normal for saving user preferences and session data - NOT A VULNERABILITY
- **Management Permission Usage**: Would be acceptable if ONLY used for conflict detection and warning users, but actual disablement crosses the line

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| asia.igugehelperapi.com | Primary API server | User token, device info, runtime ID, server selection | MEDIUM |
| *.igsync.net | Backup API domains | Same as primary | MEDIUM |
| igg.imsfast.net | Backup API | Same as primary | MEDIUM |
| *.igg-sync.com | Backup API (HTTP) | Same as primary | HIGH (unencrypted) |
| *.igg-sync.net | Backup API (HTTP) | Same as primary | HIGH (unencrypted) |
| api.igg.fyi | VIP API endpoint | Same as primary | MEDIUM |
| *.dingdingsync.com | Backup API | Same as primary | MEDIUM |

**Transmitted Data Includes**:
- User authentication token
- Selected server ID
- Browser version and type
- Extension version
- Runtime ID (extension instance identifier)
- Language preference
- Current server configuration
- Installed extension details (for proxy extensions)

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**: While iGuge Helper provides legitimate VPN/proxy functionality, it exhibits HIGH-RISK behavior through unauthorized extension disablement. The extension uses the `chrome.management` API to forcibly disable competing proxy extensions and specifically targets Tampermonkey without explicit user consent. This anti-competitive behavior represents a serious violation of user autonomy and browser extension ecosystem integrity.

The remote-controlled whitelist (`proxy_permissions_namewhilelist` fetched from server) means the operator can arbitrarily decide which extensions to allow, and the specific targeting of Tampermonkey (not a proxy extension) suggests malicious intent beyond technical necessity.

Additional concerns include:
- Extension enumeration and metadata exfiltration to remote servers
- Remote PAC script configuration with encrypted communication
- Multiple fallback domains including insecure HTTP endpoints
- User traffic routing through operator-controlled proxy infrastructure

**Recommendation**: This extension violates Chrome Web Store policies against interfering with other extensions and should be flagged for review. Users should be warned about the extension's behavior of disabling other extensions without permission.
