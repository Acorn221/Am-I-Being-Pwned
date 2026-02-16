# Vulnerability Report: Youtube Pop Out Player

## Metadata
- **Extension ID**: jbagkfehijlbpamidikhgjcfijjdcbib
- **Extension Name**: Youtube Pop Out Player
- **Version**: 3.1
- **Users**: ~60,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Youtube Pop Out Player is a Chrome extension that enables YouTube videos to be played in picture-in-picture mode. While the core functionality is legitimate, the extension implements an undisclosed device tracking and license validation system that raises privacy concerns. The extension generates unique device identifiers, transmits them to remote servers, and implements a freemium monetization model with activation checks that are not disclosed in the extension's description. The static analysis detected 4 high-severity data exfiltration flows where user data reaches external endpoints.

## Vulnerability Details

### 1. MEDIUM: Undisclosed Device Tracking and Registration

**Severity**: MEDIUM
**Files**: background.js, content.js, popup.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**: The extension generates a unique device identifier (UUID) upon installation and registers it with a remote server without user disclosure or consent. This identifier is persistent and used to track device activation status across multiple API endpoints.

**Evidence**:

```javascript
// background.js lines 24-34
if (!existingDeviceId) {
  const newDeviceId = crypto.randomUUID();
  chrome.storage.local.set({
    device_id: newDeviceId
  });
  if (urls.welcomeURL) {
    chrome.tabs.create({
      url: urls.welcomeURL
    })
  }
  await registerDevice(newDeviceId)
}

// background.js lines 51-74
async function registerDevice(deviceId) {
  try {
    const response = await fetch("https://api.youtube-popout-player.cresotech.com/device-register", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        device_id: deviceId
      })
    });
```

**Verdict**: The device tracking system is not mentioned in the extension's store description. While device IDs are commonly used for license management, users should be informed about this data collection practice. The persistent nature of the UUID enables cross-session tracking.

### 2. MEDIUM: Remote Configuration and Feature Gating

**Severity**: MEDIUM
**Files**: content.js, popup.js
**CWE**: CWE-912 (Hidden Functionality)

**Description**: The extension implements server-side feature gating that controls access to core functionality based on activation status retrieved from remote servers. The extension makes multiple API calls to check license status and can remotely disable features.

**Evidence**:

```javascript
// content.js lines 43-67
async function checkLicense() {
  try {
    const {
      device_id: e
    } = await getStoredData();
    if (!e) return console.warn("📛 device_id not found in chrome.storage"), !1;
    const t = await fetch(`https://api.youtube-popout-player.cresotech.com/check-activation-new?device_id=${e}`),
      o = await t.json(),
      {
        activated: n = !1,
        tempActivated: a = !1,
        countryAllowed: r = !1
      } = o;
    return n || a ? (console.log("✅ Activation confirmed from the server"), chrome.storage.local.set({
      activated: n,
      tempActivated: a,
      countryAllowed: r
    }), !0) : (chrome.storage.local.set({
      activated: !1,
      tempActivated: !1,
      countryAllowed: r
    }), console.warn("⛔ The server did not confirm activation."), !1)
  }
}

// popup.js lines 13-26
const e = await fetch(`https://api.youtube-popout-player.cresotech.com/data-check?device_id=${a}`),
  o = await e.json();
chrome.storage.local.set({
  activated: o.activated,
  tempActivated: o.tempActivated,
  countryAllowed: o.countryAllowed,
  monthlyPlan: o.monthlyPlan,
  yearlyPlan: o.yearlyPlan,
  lifetimePlan: o.lifetimePlan
})
```

**Verdict**: The extension's core PiP functionality requires server validation on each use. The `countryAllowed` flag suggests geolocation-based feature restriction. This remote control mechanism is not disclosed and could potentially be used to modify extension behavior without user consent.

## False Positives Analysis

1. **LemonSqueezy Checkout Links**: The extension uses LemonSqueezy (lines 30-33 in popup.js) for payment processing, which is a legitimate payment platform. The links to `cresotech.lemonsqueezy.com` are for purchasing subscriptions and are not malicious.

2. **Rating Prompts**: The extension implements a rating request system that opens URLs based on user ratings (rate123URL, rate45URL). This is a common practice for soliciting user feedback and is not inherently malicious.

3. **Multi-language Support**: The extension fetches translation files based on user language preferences, which is standard i18n functionality.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.youtube-popout-player.cresotech.com/device-register | Device registration on install | device_id (UUID) | MEDIUM - Persistent tracking identifier |
| api.youtube-popout-player.cresotech.com/check-activation-new | License validation | device_id | MEDIUM - Every feature use |
| api.youtube-popout-player.cresotech.com/data-check | Get subscription status | device_id | MEDIUM - On popup open |
| api.youtube-popout-player.cresotech.com/authorize | Email-based license restore | email, deviceId | MEDIUM - PII transmission |
| app.cresotech.com/* | Welcome/removal/rating pages | None (page visits) | LOW - Analytics tracking |
| cresotech.lemonsqueezy.com/buy/* | Payment checkout | device_id, billing info | LOW - Legitimate payment processor |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: The extension provides legitimate picture-in-picture functionality for YouTube videos, which aligns with its stated purpose. However, it implements an undisclosed device tracking system and remote activation checks that are not mentioned in the Chrome Web Store description. The extension:

1. Generates and transmits unique device identifiers without explicit user consent
2. Performs server-side license validation on every feature use
3. Implements geo-restriction capabilities (`countryAllowed` flag)
4. Collects email addresses for license recovery

While these practices are common in freemium software, the lack of disclosure in the extension's description represents a transparency issue. The data collection is focused on license management rather than user behavior tracking, which mitigates some privacy concerns. The extension does not appear to exfiltrate browsing history, cookies, or other sensitive user data beyond the device identifier used for activation.

The risk is elevated from LOW to MEDIUM due to the undisclosed tracking mechanism and the remote control capabilities that could potentially be misused, though there is no evidence of current malicious behavior.
