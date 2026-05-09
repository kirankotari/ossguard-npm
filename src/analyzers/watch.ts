/**
 * Post-deployment vulnerability monitoring — watches SBOMs for new CVEs.
 */

import { OSVClient, type VulnInfo } from "../apis/osv.js";
import { parseSBOM } from "../parsers/sbom.js";

export interface WatchAlert {
  packageName: string;
  packageVersion: string;
  ecosystem: string;
  vulns: VulnInfo[];
  maxSeverity: string;
}

export interface WatchReport {
  sbomPath: string;
  sbomName: string;
  scanTime: string;
  alerts: WatchAlert[];
  totalComponents: number;
  affectedComponents: number;
  totalVulns: number;
  isClean: boolean;
}

export async function watchSbom(sbomPath: string): Promise<WatchReport> {
  const sbom = parseSBOM(sbomPath);
  const packages = sbom.dependencies
    .filter((d) => d.ecosystem)
    .map((d) => ({ name: d.name, version: d.version, ecosystem: d.ecosystem }));

  const osv = new OSVClient();
  const vulnMap = await osv.queryBatch(packages);

  const alerts: WatchAlert[] = [];
  let totalVulns = 0;
  const severityOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };

  for (const dep of sbom.dependencies) {
    const vulns = vulnMap.get(dep.name) ?? [];
    if (vulns.length > 0) {
      const maxSev = vulns.reduce(
        (best, v) => ((severityOrder[v.severity] ?? 99) < (severityOrder[best] ?? 99) ? v.severity : best),
        "UNKNOWN",
      );
      alerts.push({ packageName: dep.name, packageVersion: dep.version, ecosystem: dep.ecosystem, vulns, maxSeverity: maxSev });
      totalVulns += vulns.length;
    }
  }

  alerts.sort((a, b) => (severityOrder[a.maxSeverity] ?? 99) - (severityOrder[b.maxSeverity] ?? 99));

  return {
    sbomPath,
    sbomName: sbom.name,
    scanTime: new Date().toISOString(),
    alerts,
    totalComponents: sbom.dependencies.length,
    affectedComponents: alerts.length,
    totalVulns,
    isClean: alerts.length === 0,
  };
}

export async function sendWebhook(report: WatchReport, webhookUrl: string): Promise<boolean> {
  try {
    const resp = await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(report),
      signal: AbortSignal.timeout(10000),
    });
    return resp.ok;
  } catch {
    return false;
  }
}
