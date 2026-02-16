# Vulnerability Report: Unblocker for YouTube

## Metadata
- **Extension ID**: gpnebajhkedajplkepiafghcfoljbgmk
- **Extension Name**: Unblocker for YouTube
- **Version**: 4.0.1
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

"Unblocker for YouTube" is a legitimate commercial proxy/VPN service designed to unblock YouTube content blocked by ISPs or network administrators. The extension routes YouTube traffic through a proxy server (yt.d3.routeme.me:3129) and implements a freemium business model with a 20-minute-per-hour usage limit for free users and unlimited access for premium subscribers.

The extension collects user behavior analytics via Amplitude and requires email-based authentication for premium features. While it does exfiltrate user data (email addresses, connection status, usage patterns) to remote servers, this data collection is consistent with the extension's stated functionality as a commercial proxy service with subscription management. No malicious behavior, credential theft, or deceptive practices were identified.

## Vulnerability Details

### 1. LOW: User Analytics Collection via Amplitude

**Severity**: LOW
**Files**: popup/amplitude.js, popup/popup.js, popup/countdown.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension sends detailed user behavior analytics to Amplitude (api2.amplitude.com), including extension opens, button clicks, connection status changes, authentication events, and premium feature usage.

**Evidence**:
```javascript
// popup/amplitude.js
const AMPLITUDE_API_KEY = '680812b42b998d072fd8d2ddf1f2aa70';
const AMPLITUDE_SECRET_KEY = '36c8e4734f7608aacca72929bd21dd9a';

async trackEvent(eventType, eventProperties = {}) {
    const event = {
        event_type: eventType,
        user_id: this.userId || this.deviceId,
        device_id: this.deviceId,
        session_id: this.sessionId,
        time: Date.now(),
        event_properties: eventProperties,
        user_properties: this.userProperties,
        platform: 'Chrome Extension',
        app_version: '4.0.0'
    };

    const response = await fetch('https://api2.amplitude.com/2/httpapi', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        },
        body: JSON.stringify({
            api_key: AMPLITUDE_API_KEY,
            events: [event]
        })
    });
}
```

**Verdict**: This is standard commercial analytics tracking. Amplitude is a widely-used analytics platform, and the data collected (user interactions, feature usage) is typical for commercial software. While privacy-conscious users may object to this tracking, it is not inherently malicious and appears to be used for product analytics rather than surveillance.

## False Positives Analysis

1. **Proxy Configuration**: The extension's use of `chrome.proxy.settings.set()` to route YouTube traffic through a proxy server is the core functionality of the extension and matches its stated purpose as a YouTube unblocker.

2. **Email-Based Authentication**: The authentication flow that sends email addresses to `api.ytu.routeme.me` is part of the legitimate premium subscription system. The extension uses Basic Auth with a weak password derivation (`pass_of_word` function extracts 4 characters from base64-encoded email), but this appears to be for low-security verification code delivery rather than primary authentication.

3. **Storage Access**: The extension reads/writes to `chrome.storage.local` to maintain connection state, remaining time, and premium status. This is expected behavior for a session-based proxy service.

4. **Content Script Injection**: The countdown timer injected into YouTube pages displays remaining free usage time. This is transparent to users (visible UI element) and serves a functional purpose.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.ytu.routeme.me/sendCode | Send verification code to user's email | Email address, Basic Auth header | LOW - Standard email verification |
| api.ytu.routeme.me/login | Verify login code | Email, verification code, Basic Auth | LOW - Expected authentication flow |
| api.ytu.routeme.me/getInfo | Retrieve user subscription info | Email, Basic Auth | LOW - Subscription management |
| api.ytu.routeme.me/unsubscribe | Cancel premium subscription | Email, Basic Auth | LOW - Subscription management |
| api2.amplitude.com/2/httpapi | Send usage analytics | User events, device ID, timestamps | LOW - Standard analytics |
| buy.stripe.com | Payment processing | None (external link) | CLEAN - Legitimate payment provider |
| yt.d3.routeme.me:3129 | Proxy server | YouTube traffic | LOW - Core functionality |

## Security Observations

### Positive Findings:
- Clean, readable code with no obfuscation
- Uses Manifest V3 (modern security model)
- Proxy configuration limited to YouTube domains only (not a full system proxy)
- Premium authentication requires email verification codes (prevents casual account sharing)
- Subscription management through Stripe (reputable payment processor)

### Minor Concerns:
- Weak password derivation in `pass_of_word()` function (extracts 4 chars from base64-encoded email) for Basic Auth
- Hardcoded API keys for Amplitude (standard practice but exposes keys in extension code)
- No Content Security Policy defined in manifest
- Analytics tracking may concern privacy-focused users

### Code Quality:
The codebase is well-structured with clear separation of concerns (auth.js, amplitude.js, countdown.js, etc.). No signs of malicious intent or deceptive practices. The extension appears to be professionally developed commercial software.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
This is a legitimate commercial proxy service with a freemium business model. While it does collect user analytics and authentication data, this data collection is proportional to its stated functionality and consistent with standard commercial software practices. The extension operates transparently (visible UI elements, clear premium upgrade prompts), uses reputable third-party services (Stripe for payments, Amplitude for analytics), and limits its proxy scope to YouTube domains only.

The analytics collection via Amplitude and the authentication flow constitute minor privacy considerations rather than security vulnerabilities. Users who install a "YouTube Unblocker" service would reasonably expect that the service needs to authenticate premium users and may collect usage analytics.

No evidence of credential theft, malicious data exfiltration, hidden network activity, or deceptive practices was found. The extension does what it claims to do and does not appear to engage in any activities beyond its stated purpose.

**Recommendation**: Safe for use with the understanding that it sends usage analytics to Amplitude and requires email authentication for premium features. Privacy-conscious users may want to review the extension's privacy policy regarding data collection.
