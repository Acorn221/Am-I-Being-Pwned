# Vulnerability Report: Giftful

## Metadata
- **Extension ID**: mbcfbddbppaccljmahnakpbafnoogmgi
- **Extension Name**: Giftful
- **Version**: 2.17.0
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Giftful is a wishlist management browser extension that allows users to add products from any website to their personal wishlists. The extension uses legitimate scraping techniques to extract product information (title, price, images) from the active tab and sends this data to Giftful's servers for storage and management. All observed data flows are appropriate for the extension's stated purpose.

The extension has minimal permissions (activeTab, scripting) and only communicates with first-party Giftful domains. No security or privacy concerns were identified during this analysis.

## Vulnerability Details

No vulnerabilities were identified in this extension.

## False Positives Analysis

The static analyzer flagged two exfiltration flows involving `chrome.tabs.query` and external network requests:

1. **Tab HTML extraction to link.giftful.co**: The extension reads the HTML of the active tab using `chrome.scripting.executeScript` and sends structured product data (extracted from the HTML) to `link.giftful.co` for scraping rule retrieval and storage. This is the core functionality of a wishlist extension.

2. **Tab data to api.giftful.com**: The extension communicates with Giftful's GraphQL API at `api.giftful.com` to manage user accounts, wishlists, and saved items. This is expected behavior for a cloud-synced wishlist service.

Both flows are:
- Clearly disclosed in the extension description ("add wishes from any shop")
- Essential to the extension's core purpose
- Limited to first-party Giftful domains (not third-party tracking)
- Initiated by explicit user action (clicking the extension icon)

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| link.giftful.co | Product scraping service | Hostname, product metadata (title, price, images, URL) | Low - first-party service, user-initiated |
| api.giftful.com | GraphQL API | User authentication, wishlist data, product items | Low - first-party service, encrypted HTTPS |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

This extension performs exactly as expected for a wishlist management tool. It scrapes product information from web pages (with user consent via clicking the extension) and stores it in the user's Giftful account. The permissions are appropriate and minimal:

- **activeTab**: Required to read product information from the current page
- **scripting**: Required to inject scraping logic into the active tab
- **Host permissions**: Limited to Giftful's own domains only

The extension uses standard web scraping techniques (DOM parsing, metadata extraction) and communicates exclusively with first-party Giftful services. There is no evidence of:
- Hidden data collection
- Third-party tracking
- Credential theft
- Excessive permissions
- Malicious code injection
- Undisclosed behavior

The "obfuscated" flag from the static analyzer refers to webpack bundling, which is standard for modern JavaScript applications and not indicative of malicious intent.

**Recommendation**: CLEAN - No security or privacy concerns identified.
