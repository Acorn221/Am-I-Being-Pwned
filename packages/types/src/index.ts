/** Risk level assigned to an extension after analysis */
export type RiskLevel =
  | "clean"
  | "low"
  | "medium-low"
  | "medium"
  | "medium-high"
  | "high"
  | "critical";

/**
 * Triage flag severity tiers:
 * - 1: Critical (RCE, dynamic eval with external input)
 * - 2: Dangerous patterns (proxy SDKs, XHR hooking)
 * - 3: Suspicious (excessive permissions, analytics)
 */
export type FlagTier = 1 | 2 | 3;

/** Categories of suspicious behaviour detected during triage */
export type FlagCategory =
  | "residential_proxy_vendor"
  | "dynamic_eval"
  | "dynamic_function"
  | "dynamic_import"
  | "xss"
  | "keylogging"
  | "cookie_harvesting"
  | "xhr_hooking"
  | "fetch_hooking"
  | "remote_config"
  | "ad_injection"
  | "affiliate_fraud"
  | "data_exfiltration"
  | "extension_enumeration"
  | "war_js_html_all_urls"
  | "csp_unsafe_inline"
  | "dynamic_tab_url"
  | "postmessage_no_origin"
  | "dynamic_window_open"
  | "wasm_binary"
  | "document_write";

/** A specific vulnerability found during deep analysis */
export interface Vulnerability {
  /** e.g. "VULN-01" */
  id: string;
  severity: RiskLevel;
  title: string;
  description: string;
  /** CVSS score if available, e.g. "7.5" */
  cvssScore?: string;
}

/** A triage flag — a pattern detected during automated scanning */
export interface Flag {
  tier: FlagTier;
  category: FlagCategory;
  description: string;
  /** Source file where the pattern was detected */
  file?: string;
  /** Line number in the source file */
  line?: number;
  /** Code snippet showing the flagged pattern */
  snippet?: string;
}

/** Full security report for a single Chrome extension */
export interface ExtensionReport {
  name: string;
  risk: RiskLevel;
  version?: string;
  publisher?: string;
  userCount: number;
  rating: number;
  /** Chrome API permissions (e.g. "tabs", "storage") */
  permissions: string[];
  /** Host permissions (e.g. "<all_urls>", "https://*.example.com/*") */
  hostPermissions?: string[];
  /** Permissions that can be granted post-install */
  optionalPermissions?: string[];
  /** One-line human-readable summary of the risk */
  summary: string;
  vulnerabilities: Vulnerability[];
  flags: Flag[];
  /** External domains/endpoints the extension communicates with */
  endpoints: string[];
  /** ISO 8601 timestamp of when this report was last updated */
  updatedAt: string;
}

/** The static JSON database — keyed by Chrome Web Store extension ID */
export type ExtensionDatabase = Record<string, ExtensionReport>;

// ---------------------------------------------------------------------------
// Extension ↔ Web App messaging protocol (externally_connectable)
// ---------------------------------------------------------------------------

/** Minimal info about an installed extension — no icons, versions, descriptions */
export interface InstalledExtensionInfo {
  id: string;
  name: string;
  enabled: boolean;
}

/** Messages the web page can send to the extension */
export type ExtRequest =
  | { type: "PING"; version: 1 }
  | { type: "GET_EXTENSIONS"; version: 1 };

/** Messages the extension sends back */
export type ExtResponse =
  | { type: "PONG"; version: 1 }
  | { type: "EXTENSIONS_RESULT"; version: 1; extensions: InstalledExtensionInfo[] }
  | { type: "ERROR"; version: 1; code: string; message: string };
