# Security Analysis Report: HaiYao-Ai ChatGPT,Proxy,VPN

## Extension Metadata
- **Extension ID**: ahdfccamgdjdlkedlodkogiecdggbkpa
- **Name**: HaiYao-Ai ChatGPT,Proxy,VPN
- **Version**: 3.1.2
- **User Count**: ~0 users
- **Author**: haiyaoappsups@gmail.com
- **Homepage**: https://ikraken.xyz

## Executive Summary

This VPN/proxy extension exhibits **HIGH-RISK** behavior including aggressive extension killing, user traffic interception, remote configuration control, and intrusive free-tier restrictions. While the extension serves its stated VPN/proxy functionality, it employs anti-competitive practices and collects extensive user data through third-party services.

**Overall Risk Level**: **HIGH**

The extension disables competing extensions (including Tampermonkey), intercepts navigation to force upgrade prompts, and routes all user traffic through remote-controlled proxy servers with full visibility into browsing activity.

## Vulnerability Details

### 1. AGGRESSIVE EXTENSION KILLING (HIGH Severity)

**Description**: Extension actively disables competing browser extensions including VPN/proxy competitors AND Tampermonkey.

**Location**:
- `js/haiyao.js:612-615`
- `js/main.js:193-197`

**Code Evidence**:
```javascript
// haiyao.js:612-615
function check_clash_app(ExtensionInfo) {
    if (ExtensionInfo.id != chrome.runtime.id && typeof ExtensionInfo.permissions !== "undefined"
        && ExtensionInfo.permissions.indexOf('proxy') !== -1 && ExtensionInfo.enabled === true
        && ExtensionInfo.id !== chrome.runtime.id) {
        if (!iggcfg.mzk_config.proxy_permissions_namewhilelist.includes(ExtensionInfo.name))
            chrome.management.setEnabled(ExtensionInfo.id, false);
    }
}

// main.js:193-197
function disable_clash_app(ExtensionInfo) {
    if (typeof ExtensionInfo.permissions !== "undefined" && ExtensionInfo.permissions.indexOf('proxy') !== -1
        && ExtensionInfo.enabled === true && ExtensionInfo.id !== chrome.runtime.id) {
        chrome.management.setEnabled(ExtensionInfo.id, false);
    } else if (ExtensionInfo.name == "Tampermonkey") {
        chrome.management.setEnabled(ExtensionInfo.id, false);
    }
}
```

**Whitelist**: Server-controlled via `proxy_permissions_namewhilelist` (default: `["IDM Integration Module"]`)

**Verdict**: HIGH - While disabling competing VPN/proxy extensions is standard practice for VPN extensions, **explicitly targeting and disabling Tampermonkey is malicious**. Tampermonkey is a popular user script manager with no inherent conflict with VPN functionality. This is anti-competitive behavior designed to prevent users from bypassing restrictions or monitoring extension behavior.

---

### 2. NAVIGATION INTERCEPTION & UPGRADE HARASSMENT (MEDIUM-HIGH Severity)

**Description**: Extension intercepts navigation to popular websites (YouTube, Facebook, Twitter, Google) for free users and redirects to upgrade prompts.

**Location**: `js/haiyao.js:111-138`

**Code Evidence**:
```javascript
function handleNavigation(details) {
    if (iggcfg.mzk_user_info.is_vip || !iggcfg.mzk_is_connect) {
        return
    }

    const handle = () => {
        if (details.url.includes('youtube.com') || details.url.includes('facebook.com')
            || details.url.includes('twitter.com') || details.url.includes('google.com')) {
            var url = chrome.runtime.getURL("/helper/free_user_site.html?r=" + encodeURI(details.url))
            chrome.tabs.update(details.tabId, {url: url});
        }
    }
    chrome.storage.local.get(['show_free_tips'], function (result) {
        if (typeof result.show_free_tips !== "undefined") {
            function currentDate() {
                const today = new Date();
                return today.toISOString().slice(0, 10);
            }

            if (result.show_free_tips === currentDate()) {
                return;
            }
        }

        handle()
    })
}
```

**Verdict**: MEDIUM-HIGH - Highly intrusive user experience degradation for free users. Blocks access to major websites to force VIP upgrades. While technically part of their business model, this creates a hostile environment and may violate Chrome Web Store policies regarding deceptive functionality.

---

### 3. FULL TRAFFIC INTERCEPTION (MEDIUM Severity)

**Description**: Extension requires `*://*/*` host permissions and proxy permission, enabling complete visibility into all user web traffic.

**Location**:
- `manifest.json:45-47` (host_permissions)
- `manifest.json:39` (proxy permission)
- `js/haiyao.js:1019-1055` (PAC script injection)

**Code Evidence**:
```javascript
// Fetches PAC script from remote server
function applyPacData(mode, cb) {
    if ("production" === mode) {
        chrome.storage.local.get(["testspeed_top_ranking_server", "mzk_token", "mzk_select_server_info"],
            function (s_server) {
                MZK_getJSON_DATA("api/pac", {
                    sid: iggcfg.mzk_select_server_info.line_sn,
                    gpd: 1,
                    geoip: iggcfg.mzk_pac_config.geoip_switch.toString(),
                    top_server: top_server
                }, function (data) {
                    // Injects PAC script with geolocation data
                    var browser_proxy = new Mzk_Chrome_proxy();
                    data.data = data.data.replace('__GEOIP_LIST__', iggcfg.mzk_pac_config.geoip_data);
                    var config = browser_proxy.generateProxyConfig(mode, data.data);
                    browser_proxy.applyChanges(config, cb);
                });
        });
    }
}
```

**Verdict**: MEDIUM - Expected behavior for VPN/proxy extensions, but combined with remote configuration control and aggressive extension killing, this creates significant privacy risks. All user traffic is routed through servers controlled by operator with no independent verification of no-logging claims.

---

### 4. REMOTE CONFIGURATION CONTROL (MEDIUM Severity)

**Description**: Extension configuration (including proxy servers, kill switches, and extension whitelist) is entirely server-controlled via encrypted API responses.

**Location**: `js/haiyao.js:859-951`

**Code Evidence**:
```javascript
function Run_keepsession() {
    MZK_getJSON_DATA("api/check", {userIp: iggcfg.mzk_user_ip}, function (data) {
        if (data.status == 0) {
            data = data.data
            // Server can force logout
            if (data.uinfo.login_out == true) {
                must_email_login_tips();
                user_logout(function () {}, "auto_s1");
                return;
            }

            // Server controls backup domains
            if (typeof data.backup_domain_server !== "undefined") {
                chrome.storage.local.set({"backup_url_domain": data.backup_domain_server});
                iggcfg.mzk_backup_server = data.backup_domain_server;
            }

            // Server controls extension killing whitelist
            if (typeof data.proxy_namewhilelist !== "undefined") {
                chrome.storage.local.set({"proxy_permissions_namewhilelist": data.proxy_namewhilelist});
                iggcfg.mzk_config.proxy_permissions_namewhilelist = data.proxy_namewhilelist;
            }
        }
    });
}
```

**Verdict**: MEDIUM - Server has complete control over extension behavior including which extensions to disable. No user visibility or control over these decisions. Extension behavior can be changed arbitrarily without user consent or extension update.

---

### 5. USER IP COLLECTION VIA THIRD-PARTY SERVICES (LOW-MEDIUM Severity)

**Description**: Extension collects user's real IP address via external services (Bilibili, Taobao) and transmits to backend.

**Location**: `js/haiyao.js:357-398`

**Code Evidence**:
```javascript
function setUserIpInfo() {
    fetch('https://api.live.bilibili.com/client/v1/Ip/getInfoNew', {
        method: 'GET'
    }).then(response => {
        return response.json();
    }).then(data => {
        if (data.code == 0) {
            chrome.storage.local.set({"mzk_user_ip": data.data.addr});
        } else {
            setUserIpInfoBak()
        }
    }).catch((error) => {
        setUserIpInfoBak()
    });
}

function setUserIpInfoBak() {
    fetch('https://www.taobao.com/help/getip.php', {
        method: 'GET'
    }).then(response => {
        return response.text();
    }).then(data => {
        data = data.replace('ipCallback({ip', '{"ip"').replace(')', '')
        data = JSON.parse(data)
        chrome.storage.local.set({"mzk_user_ip": data.ip});
    })
}
```

**Verdict**: LOW-MEDIUM - Uses third-party services to identify user's real IP before connecting to VPN. IP is transmitted to backend servers. This could enable tracking of users even when using VPN service.

---

### 6. ENCRYPTED DATA TRANSMISSION (LOW Severity)

**Description**: API responses can be encrypted with user token as key, obscuring server commands from user inspection.

**Location**: `js/haiyao.js:424-446`

**Code Evidence**:
```javascript
function CryptoJSAesDecrypt(encrypted_json_string) {
    var obj_json = JSON.parse(encrypted_json_string);
    var encrypted = obj_json.ciphertext;
    var salt = CryptoJS.enc.Hex.parse(obj_json.salt);
    var iv = CryptoJS.enc.Hex.parse(obj_json.iv);
    var key = CryptoJS.PBKDF2(iggcfg.mzk_user_token, salt, {
        hasher: CryptoJS.algo.SHA512,
        keySize: 64 / 8,
        iterations: 999
    });
    var decrypted = CryptoJS.AES.decrypt(encrypted, key, {iv: iv});
    return decrypted.toString(CryptoJS.enc.Utf8);
}

// Usage in MZK_getJSON_DATA
if (typeof data.msgtype !== "undefined" && typeof data.msgdata !== "undefined" && data.msgtype == "Encrypt") {
    data = JSON.parse(CryptoJSAesDecrypt(data.msgdata));
}
```

**Verdict**: LOW - Encryption itself is not malicious, but combined with remote configuration control, it prevents users from auditing what commands/configuration the server is sending.

---

## False Positives

| Pattern | Location | Reason | Verdict |
|---------|----------|--------|---------|
| jQuery library | js/jquery-3.4.1.min.js | Standard library | FP |
| CryptoJS library | libs/crypto-js/crypto-js.js | Legitimate encryption library | FP |
| MD5 implementation | js/haiyao.js:1451-1698 | Standard hash implementation for API signing | FP |
| IP detection for geolocation | js/haiyao.js:357-398 | Standard VPN functionality to detect user location | Legitimate but privacy concern |
| Proxy authentication | js/haiyao.js:775-812 | Standard proxy credential handling | FP |

---

## API Endpoints & Data Flow

| Endpoint | Purpose | Data Transmitted | Risk |
|----------|---------|-----------------|------|
| `rest.vofasts.xyz` | Primary API server | User token, device info, IP address, selected server, browser fingerprint | HIGH |
| `ns.vonodefly.vip` | VIP backup API server | Same as primary | HIGH |
| `nt.vonodebit.xyz` | Backup API server | Same as primary | HIGH |
| `api.live.bilibili.com` | IP geolocation | None (receives IP) | LOW |
| `www.taobao.com/help/getip.php` | IP geolocation fallback | None (receives IP) | LOW |
| `tips.ilink-a.com` | Tips/notifications | User token | LOW |

### Key API Calls

1. **auth/login** - User authentication (email + code or username + password)
2. **auth/sendCode** - Email verification code delivery
3. **api/check** - Session keepalive + remote config updates (every 30-60 min)
4. **api/pac** - PAC script retrieval (controls routing rules)
5. **api/get_default_server** - Default server selection
6. **api/get_server** - Specific server configuration

### Data Transmitted to Backend

```javascript
// Every API call includes:
send_data.appver = Manifest.version;           // Extension version
send_data.device_name = navigator.userAgent;   // Full user agent
send_data.token = iggcfg.mzk_user_token;      // Authentication token
send_data.curr_server_id = iggcfg.mzk_server_id; // Selected server
send_data.runtime_id = chrome.runtime.id;      // Extension runtime ID
send_data.from = 'pc';                         // Platform
send_data.userIp = iggcfg.mzk_user_ip;        // User's real IP address
```

---

## Data Flow Summary

1. **User IP Collection**: Extension fetches real IP from Bilibili/Taobao APIs
2. **Authentication**: User logs in with email or username/password
3. **Server Selection**: Backend provides default/selected VPN server configuration
4. **PAC Configuration**: Backend sends dynamic PAC script with routing rules
5. **Traffic Routing**: All matching traffic routed through proxy servers
6. **Keepalive**: Every 30-60 minutes, extension phones home with user IP, server status
7. **Remote Control**: Server can update backup domains, whitelist, force logout

**Privacy Implications**: Backend servers receive:
- Real user IP address (before VPN connection)
- Full browsing metadata (domains visited via proxy)
- Device fingerprint (user agent, browser version, extension ID)
- Connection patterns (server selections, session duration)

---

## Chrome Web Store Policy Violations

### Potential Violations

1. **Deceptive Installation Tactics** - Extension blocks access to major websites (YouTube, Google, Facebook, Twitter) for free users, which may violate policies against "functionality that is not reasonably related to the extension's purpose"

2. **Anti-Competitive Behavior** - Explicitly disabling Tampermonkey (unrelated to VPN functionality) violates policies against "interfering with other extensions"

3. **Undisclosed Functionality** - Extension kills other extensions without clear disclosure in description/privacy policy

4. **Remote Code Execution** - While using PAC scripts (legitimate), the server has complete control over extension behavior via encrypted configuration updates

---

## Recommendations

### For Users
1. **AVOID** - Do not install this extension due to aggressive extension killing and Tampermonkey targeting
2. If already installed, **UNINSTALL IMMEDIATELY** and check for disabled extensions
3. Consider alternative VPN services with better privacy practices and no anti-competitive behavior

### For Security Researchers
1. Monitor backend API endpoints for configuration changes
2. Analyze PAC scripts to understand routing rules
3. Check if extension violates Chrome Web Store developer program policies
4. Report to Chrome Web Store for review

---

## Technical Indicators of Concern

### Anti-Analysis Techniques
- ✅ Encrypted server responses
- ✅ Remote configuration control
- ✅ Multiple fallback domains
- ✅ Device fingerprinting

### Malicious Patterns
- ✅ Extension enumeration via `chrome.management.getAll()`
- ✅ Extension killing via `chrome.management.setEnabled(id, false)`
- ✅ **Targeting specific extension (Tampermonkey) unrelated to VPN functionality**
- ✅ Navigation interception for non-VIP harassment
- ✅ Remote kill switch capability

### Privacy Risks
- ✅ Full traffic visibility (inherent to proxy extensions)
- ✅ Real IP collection before VPN connection
- ✅ Comprehensive device fingerprinting
- ✅ Session tracking across devices

---

## Overall Risk Assessment

**Risk Level**: **HIGH**

### Risk Breakdown
- **Extension Killing**: HIGH (targets Tampermonkey, anti-competitive)
- **Traffic Interception**: MEDIUM (expected for VPN but no logging verification)
- **Remote Control**: MEDIUM (server controls all behavior)
- **Privacy**: MEDIUM-HIGH (extensive data collection)
- **User Experience**: MEDIUM-HIGH (aggressive free-tier restrictions)

### Justification

While this extension does provide VPN/proxy functionality as advertised, it exhibits several concerning behaviors:

1. **Malicious Extension Killing**: Explicitly targeting Tampermonkey demonstrates clear malicious intent beyond normal VPN functionality
2. **Anti-Competitive Practices**: Server-controlled whitelist enables arbitrary extension disabling
3. **Intrusive Free Tier**: Blocking major websites is more aggressive than typical freemium models
4. **Privacy Concerns**: Real IP collection + full traffic visibility + no independent audit

The extension serves its stated purpose but employs anti-competitive tactics and aggressive monetization strategies that harm user experience and potentially violate platform policies.

**Recommendation**: **DO NOT INSTALL**. The Tampermonkey targeting alone is sufficient reason to classify this as hostile software.
