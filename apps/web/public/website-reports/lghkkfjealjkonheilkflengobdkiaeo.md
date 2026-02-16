# Vulnerability Report: max PayBack Reminder - מקס פייבק

## Metadata
- **Extension ID**: lghkkfjealjkonheilkflengobdkiaeo
- **Extension Name**: max PayBack Reminder - מקס פייבק
- **Version**: 2.2310.01.44
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

max PayBack is an Israeli cashback and coupon extension for the pay-back.co.il service. While it provides legitimate cashback functionality, it exhibits concerning privacy behaviors that are not clearly disclosed to users. The extension collects a comprehensive list of all installed browser extensions and transmits this data to its remote server. Additionally, it has the capability to programmatically enable or disable other extensions in the user's browser. These behaviors represent significant privacy overreach beyond what would be expected from a cashback extension.

The extension also fetches remote configurations and maintains extensive user tracking through "snitching" mechanisms that report user actions back to the server. While the core cashback functionality appears legitimate, the additional data collection and extension control capabilities elevate this to a HIGH risk classification.

## Vulnerability Details

### 1. HIGH: Extension Enumeration and Exfiltration

**Severity**: HIGH
**Files**: utils/Api.js (lines 64-76), utils/ExtensionApi.js (line 74-76)
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension collects a complete list of all installed browser extensions and sends this information to a remote server without explicit user consent or clear disclosure.

**Evidence**:
```javascript
// utils/Api.js - snitchExtensionsList function
async snitchExtensionsList() {
  let t = BASE_URL + "/hooks/browserext/v2/?action=snitching_ext_list",
    e = await chrome.management.getAll(),
    a = {};
  for (let t = 0; t < e.length; t++) a[e[t].id] = e[t].shortName;
  let o = await fetch(t, {
    method: "POST",
    body: JSON.stringify({
      exts_list: a
    })
  });
  await o.json()
}

// utils/ExtensionApi.js - getAllExtentions function
async getAllExtentions() {
  return chrome.management.getAll()
}
```

The extension calls this function daily via `dailySnitch()` in background.js during initialization.

**Verdict**: This is a clear privacy violation. Browser extension lists can be used for fingerprinting and reveal sensitive information about user behavior, interests, and potentially security tools. This data is transmitted to `www.pay-back.co.il/hooks/browserext/v2/?action=snitching_ext_list` without explicit user consent.

### 2. HIGH: Unauthorized Extension Control

**Severity**: HIGH
**Files**: utils/ExtensionApi.js (lines 185-189)
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension can programmatically enable or disable other browser extensions through the `onOffExtention` function.

**Evidence**:
```javascript
// utils/ExtensionApi.js
async onOffExtention(e) {
  return chrome.management.setEnabled(e.ext_id, e.state, (() => {})), {
    req: e
  }
}
```

**Verdict**: While this could theoretically be used for legitimate purposes (e.g., disabling competing cashback extensions to avoid conflicts), granting an extension the ability to control other extensions without clear user understanding represents a significant security concern. This capability could be abused to disable security extensions or competing services.

### 3. MEDIUM: User Action Tracking and Remote Configuration

**Severity**: MEDIUM
**Files**: utils/Api.js (lines 82-93, 21-42), utils/ExtensionApi.js (lines 119-121)
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension implements comprehensive user tracking through "snitching" functions that report user actions to the remote server, and fetches remote configuration that could change extension behavior post-installation.

**Evidence**:
```javascript
// utils/Api.js - Action tracking
async snitchAction(t, e) {
  let a = BASE_URL + "/hooks/browserext/v2/?action=snitching_action",
    o = {
      user_action: t,
      action_value: e
    },
    s = await fetch(a, {
      method: "POST",
      body: JSON.stringify(o)
    });
  await s.json()
}

// Remote configuration fetching
async updateConfig() {
  let t = BASE_URL + "/hooks/browserext/v2/?action=get_ext_config",
    e = await fetch(t),
    a = {
      data: await e.json(),
      lastUpdate: Date.now()
    };
  return trace("CONFIG UPDATED IN LOCAL STORAGE"), chrome.storage.local.set({
    config: a
  }), a
}
```

**Verdict**: While analytics are common in extensions, the lack of transparency about what specific user actions are being tracked is concerning. The remote configuration capability also allows the extension behavior to be modified after installation without user awareness.

## False Positives Analysis

**Legitimate Cashback Functionality**: The core functionality of tracking retailer websites, displaying cashback opportunities, and activating cashback through affiliate links is expected behavior for a cashback extension and is NOT malicious.

**Webpack Bundling**: The extension uses some bundled JavaScript (static/js/main.js), which is standard practice for React applications and is not obfuscation.

**Tab Permissions**: The `<all_urls>` host permission is required for a cashback extension to detect when users visit supported retailers and inject the cashback widget.

**Storage API**: Storing retailer lists, user preferences, and cashback status locally is expected behavior.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.pay-back.co.il/hooks/browserext/v2/?action=update_retailers | Fetch retailer list | None | Low |
| www.pay-back.co.il/hooks/browserext/v2/?action=get_dictionary | Fetch translations | None | Low |
| www.pay-back.co.il/hooks/browserext/v2/?action=get_ext_config | Fetch remote config | None | Medium |
| www.pay-back.co.il/hooks/browserext/v2/?action=get_logged_user | Fetch user account info | None | Low |
| www.pay-back.co.il/hooks/browserext/v2/?action=snitching_ext_list | Extension enumeration | **Complete list of installed extensions** | **HIGH** |
| www.pay-back.co.il/hooks/browserext/v2/?action=snitching_action | User action tracking | User actions and values | Medium |
| www.pay-back.co.il/hooks/browserext/v2/?action=recommend_a_shop | Shop recommendation | Shop URL | Low |
| www.cashyo.co.il/hooks/goshop/booking.php | Booking integration | App name | Low |

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**: While max PayBack provides legitimate cashback functionality for Israeli users, it exhibits significant privacy overreach that is not clearly disclosed:

1. **Extension Enumeration**: The systematic collection and transmission of all installed browser extensions is a severe privacy violation that enables user fingerprinting and surveillance.

2. **Extension Control**: The ability to enable/disable other extensions represents a security risk, as it could be used to disable security tools or competing services without user awareness.

3. **Insufficient Disclosure**: The privacy policy and permission requests do not adequately explain these invasive capabilities to users.

4. **Remote Configuration**: The ability to change extension behavior post-installation through remote configuration reduces user control and transparency.

The extension should be classified as HIGH risk due to these privacy violations. Users should be fully informed about extension enumeration and control capabilities before installation. The extension developer should consider removing or clearly justifying these capabilities, and providing explicit opt-in consent for such data collection.

**Recommendation**: Users concerned about privacy should avoid this extension until these issues are addressed. Alternative cashback extensions that do not implement extension enumeration should be preferred.
