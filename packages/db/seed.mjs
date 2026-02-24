/**
 * Dev seed — populates the DB with realistic-looking test data.
 * Run with: pnpm --filter @amibeingpwned/db with-env node seed.mjs
 */
import { neon } from "@neondatabase/serverless";

const sql = neon(process.env.POSTGRES_URL);

// ---------------------------------------------------------------------------
// Known IDs (already in the DB)
// ---------------------------------------------------------------------------
const ORG_ID = "b26f7c41-cd28-4b49-ae5a-b69ba9928650";
const USER_ID = "HyeQWYR3okndZdzOmakrRm9D6O0gDCsv";
const now = new Date();
const ago = (days) => new Date(now - days * 86_400_000).toISOString();

// ---------------------------------------------------------------------------
// Extensions — global registry
// ---------------------------------------------------------------------------
const extensions = [
  { id: "cjpalhdlnbpafiamejdnhcphjbkeiagm", name: "uBlock Origin",          riskScore: 5,  isFlagged: false },
  { id: "kbfnbcaeplbcioakkpcpgfkobkghlhen", name: "Grammarly",               riskScore: 38, isFlagged: false },
  { id: "hdokiejnpimakedhajhdlcegeplioahd", name: "LastPass",                 riskScore: 52, isFlagged: false },
  { id: "bmnlcjabgnpnenekpadlanbbkooimhnj", name: "Honey",                   riskScore: 61, isFlagged: false },
  { id: "cfhdojbkjhnklbpkdaibdccddilifddb", name: "Adblock Plus",             riskScore: 9,  isFlagged: false },
  { id: "eimadpbcbfnmbkopoojfekhnkhdbieeh", name: "Privacy Badger",           riskScore: 7,  isFlagged: false },
  { id: "enamippconapkdmohfbamkmbhncnncnn", name: "Dark Reader",              riskScore: 14, isFlagged: false },
  { id: "fmkadmapgofadopljbjfkapdkoienihi", name: "React DevTools",           riskScore: 3,  isFlagged: false },
  { id: "aaaaaaaaaabbbbbbbbbbccccccccccdd", name: "DataSpii Collector",        riskScore: 88, isFlagged: true,  flaggedReason: "Harvests full browsing history and exfiltrates to third-party servers" },
  { id: "aaaaaaaaaabbbbbbbbbbcccccccccce1", name: "CryptoMiner Pro",          riskScore: 96, isFlagged: true,  flaggedReason: "Executes covert cryptocurrency mining using visitor CPU resources" },
  { id: "aaaaaaaaaabbbbbbbbbbcccccccccce2", name: "Session Hijacker",         riskScore: 91, isFlagged: true,  flaggedReason: "Captures session cookies and forwards to remote C2 server" },
  { id: "ghbmnnjooekpmoecnnnilnnbdlolhkhi", name: "Google Docs Offline",      riskScore: 4,  isFlagged: false },
  { id: "nmmhkkegccagdldgiimedpiccmgmieda", name: "Google Pay",               riskScore: 6,  isFlagged: false },
];

// ---------------------------------------------------------------------------
// Devices — all linked to the org
// ---------------------------------------------------------------------------
const devices = [
  { fingerprint: "fp-alpha-001",   platform: "chrome", version: "3.1.2", lastSeen: ago(0),  label: "Alice's MacBook" },
  { fingerprint: "fp-beta-002",    platform: "chrome", version: "3.1.2", lastSeen: ago(1),  label: "Bob's Windows PC" },
  { fingerprint: "fp-gamma-003",   platform: "chrome", version: "3.0.9", lastSeen: ago(3),  label: "Carol's Linux box" },
  { fingerprint: "fp-delta-004",   platform: "edge",   version: "3.1.2", lastSeen: ago(0),  label: "Dave's Surface" },
  { fingerprint: "fp-epsilon-005", platform: "chrome", version: "2.9.0", lastSeen: ago(14), label: "Old laptop (stale)" },
];

// Which extensions are installed on each device (by index into `extensions`)
const deviceExtensions = {
  "fp-alpha-001":   [0, 1, 2, 5, 6, 7, 11, 12],     // Alice — clean
  "fp-beta-002":    [0, 3, 4, 8],                     // Bob — has DataSpii
  "fp-gamma-003":   [0, 1, 4, 9, 10],                // Carol — has two malicious
  "fp-delta-004":   [0, 2, 3, 6, 11],                // Dave — clean
  "fp-epsilon-005": [0, 1, 8],                        // Old laptop — has DataSpii
};

// ---------------------------------------------------------------------------
// Seed
// ---------------------------------------------------------------------------

console.log("Seeding extensions...");
for (const ext of extensions) {
  await sql`
    INSERT INTO extension (id, chrome_extension_id, name, risk_score, is_flagged, flagged_reason, last_updated_at, created_at, updated_at)
    VALUES (
      gen_random_uuid(),
      ${ext.id},
      ${ext.name},
      ${ext.riskScore},
      ${ext.isFlagged},
      ${ext.flaggedReason ?? null},
      ${now.toISOString()},
      ${now.toISOString()},
      ${now.toISOString()}
    )
    ON CONFLICT (chrome_extension_id) DO UPDATE
      SET name = EXCLUDED.name,
          risk_score = EXCLUDED.risk_score,
          is_flagged = EXCLUDED.is_flagged,
          flagged_reason = EXCLUDED.flagged_reason
  `;
}
console.log(`  ${extensions.length} extensions upserted`);

console.log("Seeding devices + user_extension rows...");
let deviceCount = 0;
let ueCount = 0;

for (const dev of devices) {
  const devId = crypto.randomUUID();
  const tokenHash = Array.from(crypto.getRandomValues(new Uint8Array(32)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const tokenExpires = new Date(now.getTime() + 7 * 86_400_000).toISOString();

  await sql`
    INSERT INTO device (id, org_id, token_hash, token_expires_at, device_fingerprint, extension_version, platform, last_seen_at, created_at, updated_at)
    VALUES (
      ${devId},
      ${ORG_ID},
      ${tokenHash},
      ${tokenExpires},
      ${dev.fingerprint},
      ${dev.version},
      ${dev.platform},
      ${dev.lastSeen},
      ${dev.lastSeen},
      ${dev.lastSeen}
    )
    ON CONFLICT DO NOTHING
  `;
  deviceCount++;

  const extIndices = deviceExtensions[dev.fingerprint] ?? [];
  for (const idx of extIndices) {
    const ext = extensions[idx];
    await sql`
      INSERT INTO user_extension (id, device_id, chrome_extension_id, version_at_last_sync, enabled, disabled_by_aibp, last_seen_at, created_at, updated_at)
      VALUES (
        gen_random_uuid(),
        ${devId},
        ${ext.id},
        ${ext.id === "aaaaaaaaaabbbbbbbbbbcccccccccce1" ? "2.4.1" : "latest"},
        true,
        false,
        ${dev.lastSeen},
        ${dev.lastSeen},
        ${dev.lastSeen}
      )
      ON CONFLICT DO NOTHING
    `;
    ueCount++;
  }
}
console.log(`  ${deviceCount} devices, ${ueCount} user_extension rows inserted`);

console.log("Seeding alerts...");
const alerts = [
  {
    type: "threat_detected",
    severity: "critical",
    title: "Malicious extension detected on Bob's PC",
    body:  "DataSpii Collector (cjpalhdlnbpafiamejdnhcphjbkeiagm) has been flagged as malicious. It harvests browsing history and sends it to third-party servers. Immediate removal is recommended.",
    read: false,
  },
  {
    type: "threat_detected",
    severity: "critical",
    title: "Two threats found on Carol's Linux box",
    body:  "CryptoMiner Pro and Session Hijacker were detected. Both extensions are known malware. Device has been flagged for review.",
    read: false,
  },
  {
    type: "new_permissions",
    severity: "warning",
    title: "LastPass requested new permissions",
    body:  "LastPass updated to v4.119.0 and added the 'nativeMessaging' permission. Review before re-enabling.",
    read: false,
  },
  {
    type: "scan_complete",
    severity: "info",
    title: "Weekly fleet scan complete",
    body:  "Scan finished: 13 extensions analysed across 5 devices. 3 threats found, 10 clean.",
    read: true,
  },
  {
    type: "update_disabled",
    severity: "warning",
    title: "Honey auto-disabled on Dave's Surface",
    body:  "Honey updated to v16.2.1 which has not yet been scanned. Extension quarantined pending analysis.",
    read: true,
  },
];

for (const alert of alerts) {
  await sql`
    INSERT INTO user_alert (id, user_id, alert_type, severity, title, body, read, dismissed, created_at, updated_at)
    VALUES (
      gen_random_uuid(),
      ${USER_ID},
      ${alert.type},
      ${alert.severity},
      ${alert.title},
      ${alert.body},
      ${alert.read},
      false,
      ${ago(Math.floor(Math.random() * 5))},
      ${now.toISOString()}
    )
  `;
}
console.log(`  ${alerts.length} alerts inserted`);

console.log("Seeding org API key...");
const keyHash = Array.from(crypto.getRandomValues(new Uint8Array(32)))
  .map((b) => b.toString(16).padStart(2, "0"))
  .join("");
await sql`
  INSERT INTO org_api_key (id, org_id, name, key_hash, created_by, last_used_at, created_at, updated_at)
  VALUES (
    gen_random_uuid(),
    ${ORG_ID},
    'Production fleet key',
    ${keyHash},
    ${USER_ID},
    ${ago(1)},
    ${ago(30)},
    ${ago(30)}
  )
  ON CONFLICT DO NOTHING
`;
console.log("  1 API key inserted");

console.log("\nDone! Summary:");
console.log(`  ${extensions.length} extensions in global registry`);
console.log(`  ${devices.length} devices (4 active, 1 stale)`);
console.log(`  3 flagged extensions across the fleet`);
console.log(`  ${alerts.length} alerts (3 unread)`);
