# Vulnerability Report: Rewards Search Automator

## Metadata
- **Extension ID**: eanofdhdfbcalhflpbdipkjjkoimeeod
- **Extension Name**: Rewards Search Automator
- **Version**: 1.6.5
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Rewards Search Automator is a sophisticated automation bot designed to manipulate Microsoft Rewards searches on Bing. The extension employs the Chrome Debugger Protocol (CDP) to programmatically control browser behavior, simulate mobile devices, inject search queries with human-like typing patterns, and deploy anti-fingerprinting techniques to evade bot detection. While marketed as a productivity tool for earning Microsoft Rewards points, the extension fundamentally violates Microsoft's Terms of Service, Chrome Web Store Developer Program Policies, and engages in deceptive practices by masking automated activity as human behavior.

The extension uses powerful debugging APIs (`chrome.debugger`) with `<all_urls>` host permissions to manipulate DOM elements, spoof user-agent headers and device metrics, inject canvas/WebGL fingerprint noise, and clear browsing data to cover tracks. It implements humanization algorithms including randomized typing delays, mouse movement paths, and search query typos. The extension gates premium features behind a Gumroad license key verification system and includes scheduled automation modes that run without user interaction.

## Vulnerability Details

### 1. HIGH: Chrome Debugger Protocol Abuse for Automated Bot Activity

**Severity**: HIGH
**Files**: service.js (lines 326-789), content.js (lines 2-73)
**CWE**: CWE-506 (Embedded Malicious Code), CWE-912 (Hidden Functionality)
**Description**: The extension extensively uses `chrome.debugger` API to programmatically control browser tabs, simulate user interactions, and manipulate page content to automate Bing searches for Microsoft Rewards points.

**Evidence**:
```javascript
// service.js lines 366-409 - Attaching debugger and setting auto-attach
await chrome.debugger.attach({ tabId }, "1.3");
await chrome.debugger.sendCommand({ tabId }, "Target.setAutoAttach", {
    autoAttach: true,
    waitForDebuggerOnStart: false,
    flatten: true,
});

// service.js lines 509-646 - Mobile device simulation via CDP
await chrome.debugger.sendCommand({ tabId }, "Emulation.setDeviceMetricsOverride", deviceMetrics);
await chrome.debugger.sendCommand({ tabId }, "Network.setUserAgentOverride", uaOverride);
await chrome.debugger.sendCommand({ tabId }, "Emulation.setTouchEmulationEnabled", {
    enabled: true,
    maxTouchPoints: maxTouchPoints,
    configuration: "mobile",
});

// service.js lines 1160-1201 - Automated query typing via CDP Input.insertText
for (const char of searchQuery) {
    await chrome.debugger.sendCommand({ tabId }, "Input.insertText", { text: char });
    await delay(typingDelay, interruptible);
}

// service.js lines 867-1119 - Automated clicking with humanized mouse paths
const path = generateMousePath(lastMouseX, lastMouseY, x, y);
for (const point of path) {
    await chrome.debugger.sendCommand({ tabId }, "Input.dispatchMouseEvent", {
        type: "mouseMoved",
        x: point.x,
        y: point.y,
    });
}
```

**Verdict**: This represents undisclosed automation that violates both Microsoft Rewards ToS (which prohibit automated point accumulation) and Chrome Web Store policies against deceptive practices. The extension is specifically designed to game a rewards program through bot activity while mimicking human behavior to evade detection.

### 2. HIGH: Anti-Fingerprinting Code to Evade Bot Detection

**Severity**: HIGH
**Files**: content.js (lines 2-73)
**CWE**: CWE-506 (Embedded Malicious Code), CWE-330 (Use of Insufficiently Random Values)
**Description**: The extension implements sophisticated anti-fingerprinting techniques to mask automated activity, including masking `navigator.webdriver`, spoofing navigator properties, adding canvas fingerprint noise, and randomizing WebGL parameters.

**Evidence**:
```javascript
// content.js lines 3-11 - Masking navigator.webdriver (primary bot detection vector)
Object.defineProperty(navigator, "webdriver", {
    get: () => undefined,
    configurable: true,
});

// content.js lines 14-33 - Spoofing navigator properties
const spoofNavigator = {
    plugins: { length: 5 },
    languages: ["en-US", "en"],
    deviceMemory: 8,
    hardwareConcurrency: 8,
};

// content.js lines 36-50 - Canvas fingerprint noise injection
HTMLCanvasElement.prototype.toDataURL = function (type) {
    const ctx = this.getContext("2d");
    if (ctx) {
        const imageData = ctx.getImageData(0, 0, this.width, this.height);
        for (let i = 0; i < 10; i++) {
            const idx = Math.floor((Math.random() * imageData.data.length) / 4) * 4;
            imageData.data[idx] = (imageData.data[idx] + 1) % 256;
        }
        ctx.putImageData(imageData, 0, 0);
    }
    return originalToDataURL.apply(this, arguments);
};

// content.js lines 53-72 - WebGL fingerprint randomization
WebGLRenderingContext.prototype.getParameter = function (parameter) {
    if (parameter === 37445) return "Google Inc. (Intel)";
    if (parameter === 37446)
        return "ANGLE (Intel, Intel(R) UHD Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)";
    return getParameterProto.apply(this, arguments);
};
```

**Verdict**: These techniques are specifically designed to circumvent bot detection systems. The masking of `navigator.webdriver` is a red flag indicating malicious intent to hide automated behavior from anti-bot systems.

### 3. HIGH: Browsing Data Manipulation and Privacy Violation

**Severity**: HIGH
**Files**: service.js (lines 197-250, 217-236)
**CWE**: CWE-359 (Exposure of Private Information), CWE-732 (Incorrect Permission Assignment)
**Description**: The extension clears browsing data for Bing.com to reset session state and evade detection, and accesses/downloads user's Bing search history without adequate disclosure.

**Evidence**:
```javascript
// service.js lines 217-236 - Clearing browsing data for bing.com
await chrome.browsingData.remove(
    {
        origins: [bing],
        since: 0,
    },
    {
        cacheStorage: true,
        cookies: true,
        serviceWorkers: true,
        localStorage: true,
        pluginData: true,
    }
);

// popup.js lines 873-895 - Downloading Bing search history
const results = await new Promise((resolve) => {
    chrome.history.search(
        {
            text: "bing.com",
            startTime: oneDayAgo,
            maxResults: 1000,
        },
        resolve,
    );
});
const blob = new Blob([JSON.stringify(results, null, 2)], { type: "application/json" });
```

**Verdict**: Clearing browsing data is used to cover tracks and reset cookies/sessions to avoid detection. The history download feature, while gated behind a "pro" license, accesses potentially sensitive search history data.

### 4. MEDIUM: Undisclosed External License Verification and Monetization

**Severity**: MEDIUM
**Files**: utils.js (lines 115-201), popup.js (lines 721-759)
**CWE**: CWE-912 (Hidden Functionality)
**Description**: The extension implements a license verification system via Gumroad API that gates features and collects usage metrics without clear disclosure in the extension description.

**Evidence**:
```javascript
// utils.js lines 122-193 - Gumroad license verification
const res = await fetch(gumroad_api + "/verify", {
    method: "POST",
    headers: {
        "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
        product_id: product_id,
        license_key: key,
        increment_uses_count: increment,
    }),
});

// utils.js lines 146-153 - Blocking test purchases on production extension
if (purchase.test && chrome.runtime.id === ext_id) {
    await resetPro(config);
    log(`[VERIFY] Test purchase detected. Resetting Pro membership.`, "error");
    return false;
}
```

**Verdict**: While monetization is not inherently malicious, the extension's primary purpose (automated bot activity) combined with paid premium features creates a business model built on violating third-party terms of service. The test purchase blocking suggests awareness of policy violations.

### 5. MEDIUM: Scheduled Autonomous Operation Without User Interaction

**Severity**: MEDIUM
**Files**: service.js (lines 1940-1977, 2013-2046)
**CWE**: CWE-912 (Hidden Functionality)
**Description**: The extension implements scheduled automation modes (m3, m4) that run searches automatically at randomized intervals without requiring user action, including on browser startup.

**Evidence**:
```javascript
// service.js lines 1940-1976 - Alarm-triggered scheduled automation
chrome.alarms.onAlarm.addListener(async (alarm) => {
    if (alarm.name === "schedule") {
        if (
            config?.control?.consent &&
            config?.pro?.key &&
            !["m1", "m2"].includes(config?.schedule?.mode) &&
            (config?.schedule?.desk !== 0 || config?.schedule?.mob !== 0)
        ) {
            await initialise(config?.schedule);
        }
    }
});

// service.js lines 2026-2034 - Auto-start on browser startup
chrome.runtime.onStartup.addListener(async () => {
    if (
        config?.control?.consent &&
        config?.pro?.key &&
        config?.schedule?.mode !== "m1"
    ) {
        await delay(longestDelay, false);
        await initialise(config?.schedule);
    }
});

// popup.js lines 583-619 - Setting randomized alarm schedules
const randomDelay = Math.floor(Math.random() * 150) + 300; // 5-7.5 minutes
await chrome.alarms.create("schedule", {
    when: Date.now() + randomDelay * 1000,
});
```

**Verdict**: Autonomous scheduled operation reduces user awareness and control, particularly when triggered on browser startup. This amplifies the deceptive nature of the automation.

### 6. LOW: Excessive Permissions for Stated Functionality

**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension requests `<all_urls>` host permissions despite only needing access to `*.bing.com` and `*.microsoft.com` domains.

**Evidence**:
```json
"permissions": [
    "tabs",
    "storage",
    "alarms",
    "browsingData",
    "webNavigation",
    "history",
    "debugger"
],
"host_permissions": ["<all_urls>"]
```

**Verdict**: While the debugger permission technically requires broad host permissions to function, the extension only operates on Bing/Microsoft domains. The overly broad permissions create unnecessary privacy and security exposure.

## False Positives Analysis

**Humanization Algorithms**: The typing delay randomization (lines 845-861, 225-241), mouse path generation (lines 830-843), and search query typo injection (lines 1278-1355) might appear as legitimate UI enhancement features. However, in this context they are explicitly designed to evade bot detection systems, not to improve user experience.

**Device Simulation**: Mobile device emulation via CDP could be legitimate for testing purposes, but the extension's pattern of simulating mobile devices to earn additional mobile search rewards is clearly for gaming the rewards system.

**Consent Mechanism**: The extension does implement a consent mechanism (lines 364-376 in popup.js, 2056-2063 in service.js), but this consent is for using the automation features, not for disclosing the violation of third-party ToS.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| rewards.bing.com | Microsoft Rewards dashboard and API | Automated search queries, account interactions | HIGH - Primary target of automation abuse |
| api.gumroad.com/v2/licenses/verify | License key verification | License key, product ID, usage increment | MEDIUM - Tracks paid users, enables premium features |
| buildwithkt.dev | Developer homepage | None (navigation only) | LOW - Informational |
| getprojects.notion.site | Privacy policy / terms | None (navigation only) | LOW - Informational |
| getprojects.gumroad.com | Purchase page for premium features | None (navigation only) | LOW - Commercial |

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**: Rewards Search Automator is a sophisticated automation bot that violates Microsoft's Terms of Service, Chrome Web Store Developer Program Policies (specifically the deceptive practices and abuse policies), and employs anti-detection techniques to masquerade automated activity as human behavior. While the extension implements some user-facing features (manual search triggers, configuration UI, consent mechanism), the core functionality is explicitly designed to automate earning Microsoft Rewards points through programmatic browser control.

Key concerns:
1. **Policy Violations**: The extension's stated purpose is to automate a rewards program, which Microsoft explicitly prohibits
2. **Deceptive Practices**: Anti-fingerprinting code and humanization algorithms are designed to deceive bot detection systems
3. **Abuse of Powerful APIs**: Chrome Debugger Protocol is used for automation rather than legitimate debugging purposes
4. **Privacy Concerns**: Accesses and manipulates browsing history and session data
5. **Monetization of Abuse**: Paid "pro" features create a business model built on violating third-party ToS
6. **Autonomous Operation**: Scheduled modes reduce user awareness and control

**Recommendation**: This extension should be removed from the Chrome Web Store for violating developer program policies prohibiting deceptive practices, abuse of platform features, and extensions designed to facilitate violations of third-party terms of service.
