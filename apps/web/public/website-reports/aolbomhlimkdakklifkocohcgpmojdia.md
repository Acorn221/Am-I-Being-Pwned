# Vulnerability Report: ExCITATION journal ranking in Google Scholar™

## Metadata
- **Extension ID**: aolbomhlimkdakklifkocohcgpmojdia
- **Extension Name**: ExCITATION journal ranking in Google Scholar™
- **Version**: 1.2.7
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

ExCITATION is a legitimate academic research tool that enhances Google Scholar search results by adding journal ranking information (SJR, ABS, ABDC) and abstract previews. The extension runs only on Google Scholar domains and fetches journal metadata from CrossRef's public API and the developer's own service at excitation.tech. Despite static analyzer flags for data flows to external endpoints, all network requests are for legitimate academic data enrichment purposes that align with the extension's stated functionality. The extension includes premium features requiring user authentication via email/key validation stored in chrome.storage.sync. No privacy violations, malicious data exfiltration, or security vulnerabilities were identified.

## Vulnerability Details

No vulnerabilities were identified. The static analyzer flagged several data flows to external endpoints, but all are false positives for this extension type.

## False Positives Analysis

### Static Analyzer Exfiltration Flags
The ext-analyzer tool reported 4 HIGH-severity exfiltration flows from DOM elements and chrome.storage to excitation.tech endpoints. Analysis confirms these are false positives:

1. **CrossRef API Integration**: The extension queries `api.crossref.org/works` with journal bibliographic information extracted from Google Scholar pages to retrieve journal metadata (title, ISSN, container-title, type). This is standard academic data enrichment.

2. **Abstract Preview Feature**: Fetches academic paper abstracts from `excitation.tech` API using paper identifiers extracted from the page. The data sent is publication identifiers already visible on the page, not user data.

3. **Premium Feature Authentication**: The extension stores user email and a validation key in chrome.storage.sync for premium features (predatory journal detection). The authentication mechanism uses checksums to validate the key matches the email, but does not transmit credentials to remote servers during normal operation.

4. **Journal Ranking Data**: Fetches journal ranking information (SJR quartiles, ABS ratings, ABDC classifications) from the developer's API to display alongside search results. The queries contain journal names already visible on the page.

All network requests are contextually appropriate for an academic research enhancement tool. The extension explicitly runs only on scholar.google.* domains (96+ regional variants listed in manifest), limiting its scope to academic search contexts.

### Attack Surface: Message Handlers
The static analyzer flagged message handlers that can trigger fetch requests. These handlers are part of the extension's architecture:
- Background worker handles requests from content script to fetch page headers and data
- Used for retrieving journal metadata from external sources
- No origin validation issues as handlers only process specific message types from the extension's own content script

### Host Permissions
The extension requests `*://*/*` host permissions. This is broader than strictly necessary but used for:
- Fetching journal metadata from various academic sources (CrossRef API, etc.)
- Not used for content script injection (content scripts only run on scholar.google.* domains)

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.crossref.org/works | Fetch journal metadata | Bibliographic queries (journal names, ISSNs from page) | None - public API |
| excitation.tech | Journal rankings, abstracts, premium features | Journal identifiers, paper IDs from page | None - legitimate service |

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**: ExCITATION is a well-designed academic tool that performs exactly as described. The extension enhances Google Scholar with valuable metadata (journal rankings, abstract previews) from legitimate academic sources. All flagged "exfiltration" flows are contextually appropriate data lookups using information already visible on the page. The extension follows MV3 best practices, has appropriate permission scoping to academic domains, and includes transparent premium feature monetization. No security vulnerabilities, privacy violations, or deceptive practices were identified.
