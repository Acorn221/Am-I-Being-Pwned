import type { RiskLevel } from "@amibeingpwned/types";

export interface PermAnnotation {
  /** Matches the permission chip text, e.g. "cookies" */
  permission: string;
  /** Short label, e.g. "Cookie Theft" */
  title: string;
  /** Brief explanation, e.g. "Reads & exfiltrates session cookies" */
  description: string;
}

export interface HeroSlide {
  /** Typing phrase shown in the hero headline */
  phrase: string;
  /** Anonymised display name (we can't name real extensions yet) */
  name: string;
  risk: RiskLevel;
  userCount: number;
  permissions: string[];
  hostPermissions: string[];
  annotations?: PermAnnotation[];
}

/**
 * Self-contained hero slide data - no extension IDs or database lookups.
 * All data sourced from our vulnerability reports; names are anonymised.
 *
 * Annotations focus on what the extension ACTUALLY DOES to the user - concrete,
 * verifiable behaviours. We never speculate about intent (e.g. "sold") - only
 * state what the code does and where data goes.
 *
 * Ordered to lead with the most shocking examples and highest user counts.
 */
export const HERO_SLIDES: HeroSlide[] = [
  {
    phrase: "Browser extensions",
    name: "Ad Block Plus Pro",
    risk: "critical",
    userCount: 700000,
    permissions: ["declarativeNetRequest", "declarativeNetRequestFeedback", "storage", "tabs"],
    hostPermissions: ["<all_urls>"],
    annotations: [
      { permission: "tabs", title: "Every URL Uploaded", description: "Every page you visit is sent to a remote server with a persistent tracking UUID" },
      { permission: "<all_urls>", title: "Cross-Device Tracking", description: "Your tracking ID syncs across all your devices via chrome.storage.sync" },
    ],
  },
  {
    phrase: "Free VPN extensions",
    name: "Free VPN Unlimited",
    risk: "critical",
    userCount: 600000,
    permissions: ["tabs", "webRequest", "webRequestAuthProvider", "management", "webNavigation", "storage", "alarms", "unlimitedStorage", "proxy", "notifications", "privacy", "cookies", "scripting", "declarativeNetRequest", "declarativeNetRequestWithHostAccess", "declarativeNetRequestFeedback"],
    hostPermissions: ["<all_urls>"],
    annotations: [
      { permission: "proxy", title: "You're an Exit Node", description: "Unknown traffic is routed through your home connection as a residential proxy" },
      { permission: "management", title: "Kills Other Extensions", description: "Silently disables every other VPN so you can't switch away" },
      { permission: "cookies", title: "Shopping Hijacked", description: "Injects affiliate codes into your purchases via a third-party ad network" },
    ],
  },
  {
    phrase: "Unvetted search tools",
    name: "Similar Sites Finder",
    risk: "high",
    userCount: 300000,
    permissions: ["tabs", "webRequest", "webNavigation", "storage", "scripting", "contextMenus"],
    hostPermissions: ["*://*/*"],
    annotations: [
      { permission: "webRequest", title: "File Uploads Intercepted", description: "Documents you upload can be silently forwarded to a server-configured domain" },
      { permission: "tabs", title: "Encrypted Exfiltration", description: "Collected data is RSA+AES encrypted before being sent to a remote server" },
    ],
  },
  {
    phrase: "Employee ad blockers",
    name: "Ad Speedup & Skipper",
    risk: "critical",
    userCount: 200000,
    permissions: ["storage", "activeTab", "tabs", "offscreen"],
    hostPermissions: ["*://*/*"],
    annotations: [
      { permission: "tabs", title: "ChatGPT Sessions Stolen", description: "Creates hidden ChatGPT tabs to hijack your access tokens and prompts" },
      { permission: "*://*/*", title: "Residential Proxy Botnet", description: "Your browser becomes a proxy node via a remote command server" },
    ],
  },
  {
    phrase: "Productivity extensions",
    name: "Screen Time Tracker",
    risk: "critical",
    userCount: 200000,
    permissions: ["alarms", "tabs", "storage", "notifications", "webNavigation", "scripting", "favicon", "search"],
    hostPermissions: ["*://*/*"],
    annotations: [
      { permission: "*://*/*", title: "Ad Intelligence Sensor", description: "Embeds a data broker's SDK to scrape ads from every page you visit" },
      { permission: "tabs", title: "AI Chats Uploaded", description: "Your ChatGPT, Gemini & Copilot prompts are sent to a data broker's servers" },
    ],
  },
  {
    phrase: "Social media tools",
    name: "Tweet Manager Pro",
    risk: "critical",
    userCount: 40000,
    permissions: ["webRequest", "storage", "cookies"],
    hostPermissions: ["https://x.com/", "https://api.x.com/"],
    annotations: [
      { permission: "cookies", title: "Session Stolen", description: "Reads your auth cookies to make API calls as you" },
      { permission: "webRequest", title: "Credential Harvesting", description: "Intercepts login requests to capture your credentials" },
    ],
  },
  {
    phrase: "VPN extensions",
    name: "1-Click VPN Free",
    risk: "high",
    userCount: 8000000,
    permissions: ["alarms", "webRequest", "proxy", "storage", "unlimitedStorage", "webRequestAuthProvider"],
    hostPermissions: ["*://*/*"],
    annotations: [
      { permission: "proxy", title: "You Are the VPN", description: "Your home internet is used as a proxy to route strangers' traffic" },
      { permission: "webRequest", title: "Ads Injected", description: "Injects ads into pages you visit to generate revenue" },
    ],
  },
  {
    phrase: "Unmanaged media tools",
    name: "Movie Maker Studio",
    risk: "critical",
    userCount: 100000,
    permissions: ["storage", "tabs"],
    hostPermissions: [],
    annotations: [
      { permission: "tabs", title: "Every Site Reported", description: "Every URL you visit is hex-encoded and sent to a remote tracking server" },
      { permission: "storage", title: "Permanent Tracking ID", description: "A unique ID stored in chrome.storage.sync follows you across devices" },
    ],
  },
  {
    phrase: "New tab extensions",
    name: "Infinite New Tab",
    risk: "high",
    userCount: 100000,
    permissions: ["tabs", "storage", "search", "unlimitedStorage", "topSites", "scripting", "contextMenus"],
    hostPermissions: ["<all_urls>"],
    annotations: [
      { permission: "topSites", title: "Top Sites Harvested", description: "Your most-visited sites are collected and sent to a remote server" },
      { permission: "<all_urls>", title: "ChatGPT Cookies Extracted", description: "Reads all your ChatGPT cookies to make API calls on your behalf" },
    ],
  },
  {
    phrase: "Notepad extensions",
    name: "Notepad Online",
    risk: "high",
    userCount: 100000,
    permissions: ["unlimitedStorage", "contextMenus", "storage"],
    hostPermissions: [],
    annotations: [
      { permission: "unlimitedStorage", title: "All Local Data Sent", description: "Your entire localStorage is dumped and uploaded to a remote server" },
      { permission: "storage", title: "Tracked Until 2033", description: "A tracking cookie is set to expire in 10+ years" },
    ],
  },
  {
    phrase: "Document editors",
    name: "Office Online Suite",
    risk: "critical",
    userCount: 90000,
    permissions: ["storage", "tabs"],
    hostPermissions: [],
    annotations: [
      { permission: "tabs", title: "Browsing History Uploaded", description: "Every URL you visit is hex-encoded and sent to a remote tracking server" },
      { permission: "storage", title: "Remote Tab Redirect", description: "The server can force your active tab to navigate to a different URL" },
    ],
  },
  {
    phrase: "Unvetted audio tools",
    name: "Audio Editor Studio",
    risk: "critical",
    userCount: 80000,
    permissions: ["storage", "tabs"],
    hostPermissions: [],
    annotations: [
      { permission: "tabs", title: "Full Surveillance", description: "Every page you visit is reported to a remote server in real time" },
      { permission: "storage", title: "Remote Tab Redirect", description: "Server responses can force your active tab to navigate elsewhere" },
    ],
  },
  {
    phrase: "Video extensions",
    name: "Auto Ad Skipper",
    risk: "high",
    userCount: 100000,
    permissions: ["storage", "unlimitedStorage", "declarativeNetRequest", "declarativeNetRequestWithHostAccess", "declarativeNetRequestFeedback"],
    hostPermissions: ["<all_urls>"],
    annotations: [
      { permission: "declarativeNetRequest", title: "Remote Control Server", description: "Receives commands from a remote server to execute on your browser" },
      { permission: "<all_urls>", title: "Runs on Every Site", description: "Injected into all websites - far beyond its stated purpose" },
    ],
  },
  {
    phrase: "Video downloaders",
    name: "Video Downloader HD",
    risk: "high",
    userCount: 100000,
    permissions: ["tabs", "storage", "downloads", "declarativeNetRequest", "alarms"],
    hostPermissions: ["<all_urls>"],
    annotations: [
      { permission: "<all_urls>", title: "Keylogging Code Found", description: "Contains keylogging and XHR hooking code in its source" },
      { permission: "tabs", title: "Ads Injected", description: "Injects ads and affiliate links across sites you visit" },
    ],
  },
];
