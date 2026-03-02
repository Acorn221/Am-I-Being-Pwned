/**
 * Ingest analyzed extension data from the local cws_scraper database
 * into the Neon B2B SaaS database.
 *
 * Run:
 *   cd packages/db
 *   pnpm with-env tsx scripts/ingest-cws.ts
 *
 * Flags:
 *   --only-flagged   Only ingest extensions with risk_level IN (CRITICAL, HIGH)
 *   --dry-run        Print counts but do not write to the target DB
 */

import pg from "pg";
import { neon } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-http";
import { sql } from "drizzle-orm";

import * as schema from "../src/schema";
import {
  Extension,
  ExtensionAnalysisReport,
  ExtensionStaticAnalysis,
  ExtensionVersion,
  ExtensionVtResult,
} from "../src/schema";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const CHUNK = 100;
const ONLY_FLAGGED = process.argv.includes("--only-flagged");
const DRY_RUN = process.argv.includes("--dry-run");

// ---------------------------------------------------------------------------
// Types matching cws_scraper rows
// ---------------------------------------------------------------------------

interface SrcExtension {
  id: string;
  name: string | null;
  author: string | null;
  risk_level: string | null;
  version: string | null;
  isFlagged: boolean;
}

interface SrcReport {
  extension_id: string;
  report_type: string;
  content: string;
  risk_level: string | null;
  analyzed_at: Date | null;
  extension_version: string;
  summary: string | null;
  flag_categories: string[] | null;
  vuln_count_low: number | null;
  vuln_count_medium: number | null;
  vuln_count_high: number | null;
  vuln_count_critical: number | null;
  endpoints: string[] | null;
  can_publish: boolean | null;
}

interface SrcStaticAnalysis {
  extension_id: string;
  ext_version: string | null;
  analyzer_version: string;
  risk_score: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  exfil_flows: number;
  code_exec_flows: number;
  total_flow_paths: number;
  open_message_handlers: number;
  has_wasm: boolean;
  has_obfuscation: boolean;
  files_analyzed: number;
  analysis_time_ms: number | null;
  raw_report: Record<string, unknown> | null;
  analyzed_at: Date | null;
}

interface SrcVtResult {
  extension_id: string;
  ext_version: string | null;
  sha256: string;
  malicious: number;
  suspicious: number;
  undetected: number;
  harmless: number;
  total_engines: number;
  detection_ratio: number;
  status: string;
  raw_response: Record<string, unknown> | null;
  scanned_at: Date | null;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type RiskLevel = "unknown" | "clean" | "low" | "medium" | "high" | "critical";

function mapRisk(level: string | null | undefined): RiskLevel {
  if (!level) return "unknown";
  const l = level.toLowerCase();
  if (
    l === "critical" ||
    l === "high" ||
    l === "medium" ||
    l === "low" ||
    l === "clean"
  )
    return l as RiskLevel;
  return "unknown";
}

/** Map source report_type to the target enum value (or null to skip). */
function mapReportType(
  rt: string,
): "llm_analysis" | "vuln_report" | null {
  if (rt === "llm_analysis") return "llm_analysis";
  if (rt === "VULN_REPORT") return "vuln_report";
  return null;
}

function chunks<T>(arr: T[], size: number): T[][] {
  const result: T[][] = [];
  for (let i = 0; i < arr.length; i += size) result.push(arr.slice(i, i + size));
  return result;
}

function log(msg: string) {
  process.stdout.write(`${msg}\n`);
}

function progress(done: number, total: number, label: string) {
  const pct = total === 0 ? 100 : Math.round((done / total) * 100);
  process.stdout.write(`\r  ${label}: ${done}/${total} (${pct}%)`);
  if (done === total) process.stdout.write("\n");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  // --- Source DB (local cws_scraper) ---
  const src = new pg.Client({ database: "cws_scraper", user: "acorn221" });
  await src.connect();
  log("Connected to cws_scraper");

  // --- Target DB (Neon) ---
  const neonUrl = process.env.POSTGRES_URL;
  if (!neonUrl) throw new Error("POSTGRES_URL not set - run via: pnpm with-env tsx scripts/ingest-cws.ts");
  const db = drizzle(neon(neonUrl), { schema, casing: "snake_case" });
  log("Connected to Neon target DB");

  if (DRY_RUN) log("DRY RUN - no writes will occur");

  // -------------------------------------------------------------------------
  // Step 1: Fetch and upsert extensions
  // -------------------------------------------------------------------------

  const riskFilter = ONLY_FLAGGED
    ? `WHERE e.risk_level IN ('CRITICAL', 'HIGH')`
    : `WHERE e.risk_level IS NOT NULL`;

  const { rows: srcExts } = await src.query<SrcExtension>(`
    SELECT
      e.id,
      e.name,
      e.author,
      e.risk_level,
      e.version,
      COALESCE(e.triage_verdict = 'FLAGGED', false) AS "isFlagged"
    FROM extensions e
    ${riskFilter}
  `);

  log(`\nStep 1: ${srcExts.length} extensions to upsert`);

  if (!DRY_RUN) {
    let done = 0;
    for (const batch of chunks(srcExts, CHUNK)) {
      await db
        .insert(Extension)
        .values(
          batch.map((e) => ({
            chromeExtensionId: e.id,
            name: e.name ?? null,
            publisher: e.author ?? null,
            riskLevel: mapRisk(e.risk_level),
          })),
        )
        .onConflictDoUpdate({
          target: Extension.chromeExtensionId,
          set: {
            name: sql`excluded.name`,
            publisher: sql`excluded.publisher`,
            riskLevel: sql`excluded.risk_level`,
            lastUpdatedAt: sql`now()`,
          },
        });
      done += batch.length;
      progress(done, srcExts.length, "extensions");
    }
  }

  // Build chromeExtensionId -> internal UUID lookup
  const extRows = await db
    .select({ id: Extension.id, chromeExtensionId: Extension.chromeExtensionId })
    .from(Extension);
  const extIdMap = new Map(extRows.map((r) => [r.chromeExtensionId, r.id]));
  log(`  Loaded ${extIdMap.size} extension IDs from target`);

  // -------------------------------------------------------------------------
  // Step 2: Collect all unique (extensionId, version) pairs needed
  // -------------------------------------------------------------------------

  log("\nStep 2: Collecting unique extension versions...");

  // From analysis_reports
  const { rows: reportVersions } = await src.query<{
    extension_id: string;
    extension_version: string;
  }>(`
    SELECT DISTINCT extension_id, extension_version
    FROM analysis_reports
    WHERE extension_version IS NOT NULL
      AND report_type IN ('llm_analysis', 'VULN_REPORT')
      AND extension_id = ANY($1::text[])
  `, [srcExts.map((e) => e.id)]);

  // From static_analysis_results (use extensions.version)
  const { rows: staticVersions } = await src.query<{
    extension_id: string;
    extension_version: string;
  }>(`
    SELECT DISTINCT s.extension_id, e.version AS extension_version
    FROM static_analysis_results s
    JOIN extensions e ON e.id = s.extension_id
    WHERE e.version IS NOT NULL
      AND s.extension_id = ANY($1::text[])
  `, [srcExts.map((e) => e.id)]);

  // From vt_results (use extensions.version)
  const { rows: vtVersions } = await src.query<{
    extension_id: string;
    extension_version: string;
  }>(`
    SELECT DISTINCT v.extension_id, e.version AS extension_version
    FROM vt_results v
    JOIN extensions e ON e.id = v.extension_id
    WHERE e.version IS NOT NULL
      AND v.extension_id = ANY($1::text[])
  `, [srcExts.map((e) => e.id)]);

  // Deduplicate (extensionId, version) pairs across all three sources
  const versionPairsSet = new Map<string, { extChromeId: string; version: string }>();
  for (const { extension_id, extension_version } of [
    ...reportVersions,
    ...staticVersions,
    ...vtVersions,
  ]) {
    const key = `${extension_id}:${extension_version}`;
    if (!versionPairsSet.has(key)) {
      versionPairsSet.set(key, { extChromeId: extension_id, version: extension_version });
    }
  }

  const versionPairs = [...versionPairsSet.values()].filter(
    ({ extChromeId }) => extIdMap.has(extChromeId),
  );

  log(`  Found ${versionPairs.length} unique (extension, version) pairs`);

  // Upsert all ExtensionVersions
  if (!DRY_RUN) {
    let done = 0;
    for (const batch of chunks(versionPairs, CHUNK)) {
      await db
        .insert(ExtensionVersion)
        .values(
          batch.map(({ extChromeId, version }) => ({
            extensionId: extIdMap.get(extChromeId)!,
            version,
          })),
        )
        .onConflictDoNothing();
      done += batch.length;
      progress(done, versionPairs.length, "extension versions");
    }
  }

  // Build (extensionInternalId:version) -> extensionVersionId lookup
  const evRows = await db
    .select({
      id: ExtensionVersion.id,
      extensionId: ExtensionVersion.extensionId,
      version: ExtensionVersion.version,
    })
    .from(ExtensionVersion);
  const evIdMap = new Map(evRows.map((r) => [`${r.extensionId}:${r.version}`, r.id]));
  log(`  Loaded ${evIdMap.size} extension version IDs from target`);

  function getEvId(chromeId: string, version: string): string | undefined {
    const internalId = extIdMap.get(chromeId);
    if (!internalId) return undefined;
    return evIdMap.get(`${internalId}:${version}`);
  }

  // -------------------------------------------------------------------------
  // Step 3: Upsert analysis reports
  // -------------------------------------------------------------------------

  log("\nStep 3: Fetching analysis reports...");

  const { rows: srcReports } = await src.query<SrcReport>(`
    SELECT
      extension_id,
      report_type,
      content,
      risk_level,
      analyzed_at,
      extension_version,
      summary,
      flag_categories,
      vuln_count_low,
      vuln_count_medium,
      vuln_count_high,
      vuln_count_critical,
      endpoints,
      can_publish
    FROM analysis_reports
    WHERE report_type IN ('llm_analysis', 'VULN_REPORT')
      AND extension_version IS NOT NULL
      AND extension_id = ANY($1::text[])
    ORDER BY extension_id, analyzed_at DESC
  `, [srcExts.map((e) => e.id)]);

  log(`  ${srcReports.length} reports to upsert`);

  const reportValues = srcReports.flatMap((r) => {
    const rt = mapReportType(r.report_type);
    if (!rt) return [];
    const evId = getEvId(r.extension_id, r.extension_version);
    if (!evId) return [];
    return [{
      extensionVersionId: evId,
      reportType: rt,
      content: r.content,
      summary: r.summary ?? null,
      riskLevel: mapRisk(r.risk_level),
      flagCategories: r.flag_categories ?? [],
      vulnCountLow: r.vuln_count_low ?? 0,
      vulnCountMedium: r.vuln_count_medium ?? 0,
      vulnCountHigh: r.vuln_count_high ?? 0,
      vulnCountCritical: r.vuln_count_critical ?? 0,
      endpoints: r.endpoints ?? [],
      canPublish: r.can_publish ?? true,
      analyzedAt: r.analyzed_at ?? new Date(),
    }];
  });

  if (!DRY_RUN) {
    let done = 0;
    for (const batch of chunks(reportValues, CHUNK)) {
      await db
        .insert(ExtensionAnalysisReport)
        .values(batch)
        .onConflictDoUpdate({
          target: [
            ExtensionAnalysisReport.extensionVersionId,
            ExtensionAnalysisReport.reportType,
          ],
          set: {
            content: sql`excluded.content`,
            summary: sql`excluded.summary`,
            riskLevel: sql`excluded.risk_level`,
            flagCategories: sql`excluded.flag_categories`,
            vulnCountLow: sql`excluded.vuln_count_low`,
            vulnCountMedium: sql`excluded.vuln_count_medium`,
            vulnCountHigh: sql`excluded.vuln_count_high`,
            vulnCountCritical: sql`excluded.vuln_count_critical`,
            endpoints: sql`excluded.endpoints`,
            canPublish: sql`excluded.can_publish`,
            analyzedAt: sql`excluded.analyzed_at`,
          },
        });
      done += batch.length;
      progress(done, reportValues.length, "analysis reports");
    }
  } else {
    log(`  Would upsert ${reportValues.length} analysis reports`);
  }

  // Roll up riskLevel + summary to ExtensionVersion from the primary llm_analysis report
  if (!DRY_RUN) {
    log("  Rolling up risk levels to ExtensionVersion...");
    await db.execute(sql`
      UPDATE extension_version ev
      SET
        risk_level = ear.risk_level,
        summary = ear.summary,
        flag_categories = ear.flag_categories,
        analyzed_at = ear.analyzed_at,
        updated_at = now()
      FROM extension_analysis_report ear
      WHERE ear.extension_version_id = ev.id
        AND ear.report_type = 'llm_analysis'
    `);
    log("  Done");
  }

  // -------------------------------------------------------------------------
  // Step 4: Upsert static analysis results
  // -------------------------------------------------------------------------

  log("\nStep 4: Fetching static analysis results...");

  const { rows: srcStatic } = await src.query<SrcStaticAnalysis>(`
    SELECT
      s.extension_id,
      e.version AS ext_version,
      s.analyzer_version,
      s.risk_score,
      s.critical_count,
      s.high_count,
      s.medium_count,
      s.low_count,
      s.exfil_flows,
      s.code_exec_flows,
      s.total_flow_paths,
      s.open_message_handlers,
      s.has_wasm,
      s.has_obfuscation,
      s.files_analyzed,
      s.analysis_time_ms,
      s.raw_report,
      s.analyzed_at
    FROM static_analysis_results s
    JOIN extensions e ON e.id = s.extension_id
    WHERE e.version IS NOT NULL
      AND s.extension_id = ANY($1::text[])
  `, [srcExts.map((e) => e.id)]);

  log(`  ${srcStatic.length} static analyses to upsert`);

  const staticValues = srcStatic.flatMap((s) => {
    if (!s.ext_version) return [];
    const evId = getEvId(s.extension_id, s.ext_version);
    if (!evId) return [];
    return [{
      extensionVersionId: evId,
      analyzerVersion: s.analyzer_version,
      riskScore: s.risk_score,
      criticalCount: s.critical_count,
      highCount: s.high_count,
      mediumCount: s.medium_count,
      lowCount: s.low_count,
      exfilFlows: s.exfil_flows,
      codeExecFlows: s.code_exec_flows,
      totalFlowPaths: s.total_flow_paths,
      openMessageHandlers: s.open_message_handlers,
      hasWasm: s.has_wasm,
      hasObfuscation: s.has_obfuscation,
      filesAnalyzed: s.files_analyzed,
      analysisTimeMs: s.analysis_time_ms ?? null,
      rawReport: s.raw_report ?? null,
      analyzedAt: s.analyzed_at ?? new Date(),
    }];
  });

  if (!DRY_RUN) {
    let done = 0;
    for (const batch of chunks(staticValues, CHUNK)) {
      await db
        .insert(ExtensionStaticAnalysis)
        .values(batch)
        .onConflictDoUpdate({
          target: [
            ExtensionStaticAnalysis.extensionVersionId,
            ExtensionStaticAnalysis.analyzerVersion,
          ],
          set: {
            riskScore: sql`excluded.risk_score`,
            criticalCount: sql`excluded.critical_count`,
            highCount: sql`excluded.high_count`,
            mediumCount: sql`excluded.medium_count`,
            lowCount: sql`excluded.low_count`,
            exfilFlows: sql`excluded.exfil_flows`,
            codeExecFlows: sql`excluded.code_exec_flows`,
            totalFlowPaths: sql`excluded.total_flow_paths`,
            openMessageHandlers: sql`excluded.open_message_handlers`,
            hasWasm: sql`excluded.has_wasm`,
            hasObfuscation: sql`excluded.has_obfuscation`,
            filesAnalyzed: sql`excluded.files_analyzed`,
            analysisTimeMs: sql`excluded.analysis_time_ms`,
            rawReport: sql`excluded.raw_report`,
            analyzedAt: sql`excluded.analyzed_at`,
          },
        });
      done += batch.length;
      progress(done, staticValues.length, "static analyses");
    }
  } else {
    log(`  Would upsert ${staticValues.length} static analyses`);
  }

  // -------------------------------------------------------------------------
  // Step 5: Upsert VirusTotal results
  // -------------------------------------------------------------------------

  log("\nStep 5: Fetching VirusTotal results...");

  const { rows: srcVt } = await src.query<SrcVtResult>(`
    SELECT
      v.extension_id,
      e.version AS ext_version,
      v.sha256,
      v.malicious,
      v.suspicious,
      v.undetected,
      v.harmless,
      v.total_engines,
      v.detection_ratio,
      v.status,
      v.raw_response,
      v.scanned_at
    FROM vt_results v
    JOIN extensions e ON e.id = v.extension_id
    WHERE e.version IS NOT NULL
      AND v.extension_id = ANY($1::text[])
  `, [srcExts.map((e) => e.id)]);

  log(`  ${srcVt.length} VT results to upsert`);

  const vtValues = srcVt.flatMap((v) => {
    if (!v.ext_version) return [];
    const evId = getEvId(v.extension_id, v.ext_version);
    if (!evId) return [];
    const status = v.status === "found" || v.status === "not_found"
      ? v.status
      : "unknown" as const;
    return [{
      extensionVersionId: evId,
      sha256: v.sha256,
      malicious: v.malicious,
      suspicious: v.suspicious,
      undetected: v.undetected,
      harmless: v.harmless,
      totalEngines: v.total_engines,
      detectionRatio: v.detection_ratio,
      status,
      rawResponse: v.raw_response ?? null,
      scannedAt: v.scanned_at ?? new Date(),
    }];
  });

  if (!DRY_RUN) {
    let done = 0;
    for (const batch of chunks(vtValues, CHUNK)) {
      await db
        .insert(ExtensionVtResult)
        .values(batch)
        .onConflictDoUpdate({
          target: [ExtensionVtResult.extensionVersionId, ExtensionVtResult.sha256],
          set: {
            malicious: sql`excluded.malicious`,
            suspicious: sql`excluded.suspicious`,
            undetected: sql`excluded.undetected`,
            harmless: sql`excluded.harmless`,
            totalEngines: sql`excluded.total_engines`,
            detectionRatio: sql`excluded.detection_ratio`,
            status: sql`excluded.status`,
            rawResponse: sql`excluded.raw_response`,
            scannedAt: sql`excluded.scanned_at`,
          },
        });
      done += batch.length;
      progress(done, vtValues.length, "VT results");
    }
  } else {
    log(`  Would upsert ${vtValues.length} VT results`);
  }

  // -------------------------------------------------------------------------
  // Done
  // -------------------------------------------------------------------------

  await src.end();

  log(`
Done.
  Extensions:       ${srcExts.length}
  Version pairs:    ${versionPairs.length}
  Analysis reports: ${reportValues.length}
  Static analyses:  ${staticValues.length}
  VT results:       ${vtValues.length}
`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
