# Vulnerability Report: Обход блокировок Рунета

## Metadata
- **Extension ID**: npgcnondjocldhldegnakemclmfkngch
- **Extension Name**: Обход блокировок Рунета (Russian Internet Censorship Bypass)
- **Version**: 0.0.1.63
- **Users**: ~600,000
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

This is a legitimate censorship circumvention extension designed for Russian users to bypass internet censorship (Runet blocking). The extension name translates to "Russian Internet Censorship Bypass" and is associated with the anticensority/runet-censorship-bypass GitHub project.

The extension uses PAC (Proxy Auto-Configuration) scripts to selectively route blocked websites through proxy servers while allowing direct connections to non-blocked sites. It supports multiple PAC script providers (Antizapret, Anticensority) and allows users to configure their own proxy servers including local Tor. The code is well-structured, contains no malicious functionality, and operates transparently for its stated purpose. All network requests are legitimate and related to downloading PAC scripts, resolving proxy server IPs, and managing proxy configurations.

## Vulnerability Details

### No Vulnerabilities Found

After thorough code analysis, no security vulnerabilities or privacy concerns were identified. All functionality aligns with the extension's stated purpose of bypassing censorship.

## False Positives Analysis

### 1. Broad Permissions
The extension requests `<all_urls>`, `webRequest`, `webRequestBlocking`, and `proxy` permissions. These are **legitimate** for a proxy/censorship circumvention tool:
- **proxy**: Required to configure PAC scripts and manage proxy settings
- **webRequest/webRequestBlocking**: Used to monitor which resources are being proxied and display notifications to the user
- **<all_urls>**: Necessary to monitor and proxy any blocked website

### 2. External Network Requests
The extension makes requests to several external domains:
- **dns.google.com**: Used for DNS-over-HTTPS to resolve proxy server IP addresses (helps detect when proxy is active)
- **e.cen.rodeo, antizapret.prostovpn.org**: Official Antizapret PAC script hosting servers
- **anticensority.github.io, raw.githubusercontent.com**: Alternative PAC script providers from the extension author

All these requests are transparent and documented in the UI/code. No hidden data exfiltration occurs.

### 3. PAC Script Modification ("Dynamic Code")
The extension dynamically modifies PAC scripts in `35-pac-kitchen-api.js`. This is **expected behavior** - it allows users to:
- Add custom proxies
- Configure exceptions (whitelist/blacklist)
- Enable security options (HTTPS-only proxying, secure proxies only)
- Use local Tor or WARP as proxy

The modifications are applied client-side and are based on user configuration choices.

### 4. Proxy Authentication Handler
The extension intercepts proxy authentication requests (`chrome.webRequest.onAuthRequired`) to automatically provide credentials for password-protected proxies. This is **legitimate** - users can configure custom proxies with credentials, and the extension handles authentication transparently.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| dns.google.com/resolve | DNS-over-HTTPS queries for proxy server IPs | Hostname queries (proxy servers), random padding | Low - Standard DoH, legitimate use |
| e.cen.rodeo:8443/proxy.pac | Download Antizapret PAC script | None (HTTP GET) | Low - Official PAC provider |
| antizapret.prostovpn.org | Download Antizapret PAC script (fallback) | None (HTTP GET) | Low - Official PAC provider |
| anticensority.github.io | Download Anticensority PAC script | None (HTTP GET) | Low - GitHub Pages, public repository |
| raw.githubusercontent.com | Download Anticensority PAC script (fallback) | None (HTTP GET) | Low - GitHub raw content |

## Code Quality and Transparency

### Positive Security Indicators
1. **Open Source**: Code references GitHub repository (anticensority/runet-censorship-bypass)
2. **Well-documented**: Extensive comments in Russian explaining functionality
3. **Error Handling**: Robust error handling and user notifications
4. **No Obfuscation**: Clean, readable code (webpack bundled but not obfuscated)
5. **User Control**: All features require explicit user configuration
6. **Privacy-Conscious**: Option to use only local Tor, HTTPS-only proxying, secure proxies only

### Key Functionality
- **PAC Script Management** (`37-sync-pac-script-with-pac-provider-api.js`): Downloads and installs PAC scripts from configured providers, updates every 12 hours
- **IP-to-Host Mapping** (`20-ip-to-host-api.js`): Resolves proxy server IPs to display notification icons when sites are being proxied
- **Block Informer** (`85-block-informer.js`): Shows browser action badge when a site is being proxied through censorship bypass
- **Custom Proxy Support** (`35-pac-kitchen-api.js`): Allows users to configure their own proxy servers in various formats (HTTPS, SOCKS5, with authentication)

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**: This is a legitimate, well-maintained censorship circumvention tool with no malicious functionality. All permissions are justified by its stated purpose. The extension operates transparently, allows extensive user configuration, and contains no hidden data collection or exfiltration. The code quality is high with proper error handling and user notifications. While it has broad permissions, this is necessary and appropriate for a proxy management extension designed to bypass internet censorship.

The extension is specifically designed for users in Russia who face internet censorship, and it fulfills this purpose without introducing security or privacy risks beyond what users would expect from such a tool.
