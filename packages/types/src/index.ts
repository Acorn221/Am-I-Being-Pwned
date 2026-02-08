/** Risk level assigned to an extension after analysis */
export type RiskLevel =
  | "clean"
  | "low"
  | "medium-low"
  | "medium"
  | "medium-high"
  | "high"
  | "critical"
  | "unavailable";

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

/** Vulnerability counts by severity */
export interface VulnerabilityCount {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

/** Whether this report was AI-generated or manually reviewed by a human */
export type ReviewSource = "ai" | "manual";

/** Full security report for a single Chrome extension */
export interface ExtensionReport {
  name: string;
  extensionId: string;
  risk: RiskLevel;
  /** How this report was produced — "ai" or "manual" (human-reviewed) */
  reviewedBy?: ReviewSource;
  version: string;
  publisher: string;
  userCount: number;
  rating: number;
  /** Chrome API permissions (e.g. "tabs", "storage") */
  permissions: string[];
  /** Host permissions (e.g. "<all_urls>", "https://*.example.com/*") */
  hostPermissions: string[];
  /** Permissions that can be granted post-install */
  optionalPermissions: string[];
  /** One-line human-readable summary of the risk */
  summary: string;
  /** Flag categories detected during triage */
  flagCategories: string[];
  /** Vulnerability counts by severity */
  vulnerabilityCount: VulnerabilityCount;
  /** External domains/endpoints the extension communicates with */
  endpoints: string[];
  /** Web-accessible resource paths that can be probed to detect installation */
  webAccessibleResources: string[];
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
