# Vulnerability Report: TTV LOL PRO

## Metadata
- **Extension ID**: bpaoeijjlplfjbagceilcgbkcdjbomjd
- **Extension Name**: TTV LOL PRO
- **Version**: 2.6.1
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

TTV LOL PRO is a Twitch ad blocker that removes livestream ads from Twitch using a combination of proxy routing, DNS-over-HTTPS, and fetch interception. The extension is open source (available on GitHub at https://github.com/younesaassila/ttv-lol-pro) and implements transparent ad-blocking functionality through user-configured proxies.

The extension requests powerful permissions including `proxy`, `webRequest`, `webRequestAuthProvider`, and broad host permissions for Twitch domains. However, all functionality is directly related to its stated purpose of blocking Twitch ads. The extension uses Cloudflare DNS-over-HTTPS for DNS resolution and sends anonymized telemetry about detected ads to perfprod.com for analytics. No security vulnerabilities or privacy violations were identified beyond the extension's disclosed functionality.

## Vulnerability Details

No vulnerabilities identified. This extension operates as designed for its stated purpose.

## False Positives Analysis

### Proxy Configuration and DNS Resolution
The extension uses `chrome.proxy.onRequest` to dynamically configure proxies for Twitch video streams. This is the core mechanism for bypassing ads and is not malicious. User-configured proxies are stored in extension storage and applied via PAC scripts.

The extension performs DNS-over-HTTPS lookups to `cloudflare-dns.com/dns-query` to resolve proxy hostnames to IP addresses. This is a legitimate privacy-enhancing feature and not data exfiltration.

### Fetch Hooking
The page script (injected into MAIN world) hooks `window.fetch` to intercept Twitch API calls and modify video manifest requests. This interception is necessary to detect ads and switch to ad-free streams. The hooking mechanism checks for conflicts with other Twitch extensions and reports errors if fetch replacement fails.

### Telemetry Endpoint
The extension sends anonymized ad detection logs to `https://perfprod.com/ttvlolpro/telemetry` with header `X-Ad-Log-Version: 2`. The payload contains:
- Channel name
- Timestamp
- Video weaver URL hash (not the full URL)
- Parsed ad metadata (advertiser ID, campaign ID)

This telemetry is used for analytics to track ad blocking effectiveness. No personally identifiable information or browsing data is sent. Users can inspect this in the source code.

### BroadcastChannel Communication
The extension uses BroadcastChannel API to communicate between content script, page script, and worker scripts. A random channel name is generated (`TLP_${randomString(32)}`) and embedded in the page via `data-tlpParams`. This is standard practice for isolated script communication and not a security risk.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| gql.twitch.tv | Twitch GraphQL API queries | Standard Twitch API requests for channel subscription status and ad identity resolution | None - legitimate Twitch API usage |
| perfprod.com/ttvlolpro/telemetry | Ad detection telemetry | Anonymized ad logs (channel name, timestamp, hashed URL, ad metadata) | Low - telemetry is disclosed in privacy policy |
| cloudflare-dns.com/dns-query | DNS-over-HTTPS resolution | Proxy hostnames for DNS A/AAAA record lookups | None - standard DoH usage |
| github.com/younesaassila/ttv-lol-pro | Homepage/source code | None | None - documentation link |
| discord.ttvlolpro.com | Support community | None | None - external link |
| donate.perfprod.com | Donation page | None | None - external link |

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**: TTV LOL PRO is a transparent, open-source ad blocker for Twitch that operates exactly as described. The extension requires powerful permissions (proxy, webRequest, host permissions) but uses them solely for ad blocking functionality. Key points:

1. **Open Source**: Full source code available on GitHub, allowing independent verification
2. **Transparent Functionality**: All proxy configuration, fetch hooking, and DNS resolution directly supports ad blocking
3. **Minimal Telemetry**: Ad detection logs sent to perfprod.com are anonymized and documented in the privacy policy
4. **No Data Exfiltration**: No browsing history, cookies, or personal data is collected beyond what's necessary for functionality
5. **No Hidden Behavior**: All network requests are for legitimate purposes (Twitch API, DoH, telemetry)
6. **User Control**: Proxies are user-configured, and the extension provides detailed settings

The extension uses declarativeNetRequest to block Twitch's ad tracking scripts (`*.twitch.tv/r/s/*` and `*.twitch.tv/r/c/*`), which is a standard ad-blocking technique. The code is Parcel-bundled (not obfuscated) and readable in deobfuscated form.

No security vulnerabilities or privacy violations were found. This is a legitimate utility extension for Twitch users.
