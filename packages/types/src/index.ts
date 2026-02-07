/** Risk level assigned to an extension after analysis */
export type RiskLevel = "clean" | "low" | "medium" | "high" | "critical";

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
  | "extension_enumeration";

/** A specific vulnerability found during deep analysis */
export interface Vulnerability {
  /** e.g. "VULN-01" */
  id: string;
  severity: RiskLevel;
  title: string;
  description: string;
}

/** A triage flag — a pattern detected during automated scanning */
export interface Flag {
  tier: FlagTier;
  category: FlagCategory;
  description: string;
}

/** Full security report for a single Chrome extension */
export interface ExtensionReport {
  name: string;
  risk: RiskLevel;
  userCount: number;
  rating: number;
  permissions: string[];
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
