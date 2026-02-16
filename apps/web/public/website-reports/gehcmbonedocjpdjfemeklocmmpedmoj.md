# Vulnerability Report: Netsweeper Workstation Agent

## Metadata
- **Extension ID**: gehcmbonedocjpdjfemeklocmmpedmoj
- **Extension Name**: Netsweeper Workstation Agent
- **Version**: 4.55.53.53
- **Users**: ~300,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Netsweeper Workstation Agent is an enterprise content filtering and monitoring solution designed for managed Chrome OS and ChromeOS environments. The extension collects comprehensive user identity information (email, username, domain, group membership, device serial numbers, device asset IDs) and periodically transmits this data along with IP address information to Netsweeper cloud servers (cloud.netsweeper.com) for authentication and policy enforcement purposes.

This is a disclosed enterprise monitoring tool intended for corporate/educational deployments. While the extension's behavior is appropriate for its stated purpose as a network filtering agent, it raises significant privacy concerns due to the extensive data collection and transmission. The extension requires enterprise.deviceAttributes permission, indicating it is designed for enterprise-managed devices, and uses Chrome's managed storage API for policy configuration. The extension tracks user session states, network changes, and screen lock/unlock events to maintain filtering enforcement.

## Vulnerability Details

### 1. MEDIUM: Comprehensive User and Device Profiling
**Severity**: MEDIUM
**Files**: service.js (sinfo module, lines showing system_dug, libnscf_get_asset, libnscf_get_serial)
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: The extension systematically collects and transmits extensive user and device information including:
- User email address via chrome.identity.getProfileUserInfo
- Username and domain (parsed from email or UPN)
- Google Groups membership via Google Admin Directory API (requires OAuth token)
- Device serial number via chrome.enterprise.deviceAttributes.getDeviceSerialNumber
- Device asset ID via chrome.enterprise.deviceAttributes.getDeviceAssetId
- Chrome OS platform information
- User session state (active/locked via chrome.idle.onStateChanged)
- Network change events

**Evidence**:
```javascript
// From service.js - sinfo module
system_dug(){
  var e=new o.dug_str(null);
  yield(0,o.libnscf_dug_get_domain)(this.agent.nscf_conf,e),
  this.system_domainname=e.s,
  this.agent.log("sinfo: domain: "+this.system_domainname);

  var t=new o.dug_str(null);
  yield(0,o.libnscf_dug_get_user)(this.agent.nscf_conf,t,this.system_domainname),
  this.system_user=t.s,

  // Retrieves device identifiers
  this.system_wuid=yield(0,a.libnscf_get_asset)(),
  ""==this.system_wuid&&(this.system_wuid=yield(0,a.libnscf_get_serial)())
}

// Chrome identity collection
function o(){
  return new Promise((function(e,t){
    try{
      chrome.identity.getProfileUserInfo((function(t){e(t.email)}))
    }catch(t){e("")}
  }))
}

// Google Groups collection
t.libnscf_dug_get_groups=function(){
  var e=yield new Promise((function(e,t){
    try{
      chrome.identity.getAuthToken({interactive:!0},(function(n){
        return null!=n?(e(n),n):(t(null),null)
      }))
    }
  }));
  var n=yield fetch("https://www.googleapis.com/admin/directory/v1/groups?&userKey=testuser@netsweeper.com",{headers:t});
}
```

**Verdict**: This constitutes extensive device and user fingerprinting. While disclosed for enterprise monitoring, the scope of data collection (including Google Groups via Admin API) exceeds typical filtering requirements. The hardcoded test user email in the Groups API call suggests incomplete implementation.

### 2. MEDIUM: Periodic Data Transmission to External Server
**Severity**: MEDIUM
**Files**: service.js (wagent module, agentauthorization_send function)
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: Collected user/device information is base64-encoded and transmitted via POST request to cloud.netsweeper.com every hour (configurable via -t flag, default 3600 seconds). The extension also re-transmits on IP address changes (-i flag) and screen unlock events (-l flag).

**Evidence**:
```javascript
// Default configuration
n.NS_WAGENT_ARGS="-w cloud.netsweeper.com -t 3600 -i -l -v"

// Data encoding
encode(){
  var e=this.configline_whatismyfilteredip_reported_ip+
        this.configline_whatismyfilteredip_peer_ip+
        this.configline_agentauthorization_peer_ip;
  this.configline_system_domainname&&(e+=this.configline_system_domainname),
  this.configline_system_groupname&&(e+=this.configline_system_groupname),
  e+=this.configline_system_workstationname+
      this.configline_system_wuid+
      this.configline_system_username+
      this.configline_system_username_upn+
      this.configline_netsweeper_env_username+
      this.configline_netsweeper_env_groupname,
  this.encoded_buffer=btoa(e)
}

// Transmission to remote server
agentauthorization_send(e){
  var o="stateinfo="+e.encoded_buffer+"&guid="+n.opt_guid+"&apiversion=2.0",
  l=_.scheme+"://"+_.host+":"+_.port+_.path; // cloud.netsweeper.com

  var u={method:"POST",
         headers:{"Content-Type":"application/x-www-form-urlencoded",
                  [t.WAGENT_USER_AGENT_HEADER]:r.WAgentArgs.NS_WAGENT_VERSION_STRING},
         body:o,
         signal:h.signal};
  return fetch(l,u)
}
```

**Verdict**: Regular automated transmission of user identity and device information to third-party servers. While this is the extension's intended purpose for network filtering enforcement, it represents continuous monitoring and data exfiltration that users should be aware of. The extension is designed for enterprise-managed deployments where this behavior is disclosed and expected.

### 3. LOW: Overly Permissive Host Permissions
**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension requests `<all_urls>` host permissions, which grants access to all websites. While the code review shows these permissions are not actively exploited for content injection or manipulation, the broad scope exceeds the minimal permissions needed for an authentication agent.

**Evidence**:
```json
"host_permissions": [
  "<all_urls>"
]
```

**Verdict**: The extension does not inject content scripts or manipulate web page content. The <all_urls> permission appears unnecessary for its authentication/filtering coordination function, which only requires communication with Netsweeper servers and Google APIs. This represents potential over-privileging but not active abuse.

## False Positives Analysis

1. **Enterprise Device Management**: The use of `enterprise.deviceAttributes` permission and serial number collection is standard for enterprise device management and filtering enforcement.

2. **Managed Storage**: Configuration via `chrome.storage.managed` with schema.json is the correct approach for enterprise-deployed extensions controlled by admin policy.

3. **Session Monitoring**: Tracking screen lock/unlock and network changes is necessary for the extension's purpose of maintaining filtering enforcement across session states.

4. **OAuth Token Request**: The Google Admin Directory API call for group membership is a legitimate enterprise authentication pattern, though the hardcoded test email suggests this feature may not be fully implemented.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| cloud.netsweeper.com | Agent authorization | User email, username, domain, group, device serial, device asset ID, IP address, workstation name | MEDIUM - Comprehensive PII transmission for filtering enforcement |
| www.googleapis.com/admin/directory/v1/groups | Google Groups lookup | OAuth token, test user email | LOW - Admin API access for group-based policies, appears incomplete |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

This is a legitimate enterprise content filtering and monitoring agent, not malware. However, it warrants a MEDIUM risk rating due to:

1. **Extensive Data Collection**: The extension collects comprehensive user identity and device information including email addresses, domain/username, group membership, device serial numbers, and asset IDs.

2. **Regular Data Transmission**: User and device data is transmitted to Netsweeper cloud servers hourly, on IP changes, and on screen unlock events.

3. **Privacy Implications**: While disclosed as an enterprise monitoring tool, the breadth of data collection (especially Google Groups enumeration via Admin API) raises privacy concerns even in managed environments.

4. **Enterprise Context**: The extension is designed for enterprise/educational deployments on managed Chrome OS devices. In this context, the behavior is disclosed and expected. However, if installed on personal devices or without proper disclosure, it would constitute significant privacy violation.

5. **Intended Deployment**: The requirement for `enterprise.deviceAttributes` and use of managed storage indicates this extension should only function on enterprise-managed devices, providing some protection against misuse on personal devices.

The extension is functioning as designed for its stated purpose of network filtering enforcement. The MEDIUM rating reflects the privacy-invasive nature of comprehensive user/device monitoring, even when disclosed. Organizations deploying this extension should ensure users are informed about the extent of monitoring and data collection.
