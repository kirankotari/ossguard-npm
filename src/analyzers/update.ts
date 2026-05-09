/**
 * Security-aware dependency updater — suggest updates prioritized by security impact.
 */

import { analyzeDependencies, type DepHealthResult } from "./dep-health.js";
import { DepsDevClient } from "../apis/deps-dev.js";
import { parseDependencies } from "../parsers/dependencies.js";

export interface UpdateCandidate {
  name: string;
  currentVersion: string;
  latestVersion: string;
  ecosystem: string;
  sourceFile: string;
  vulnCount: number;
  criticalVulns: number;
  highVulns: number;
  hasSecurityFix: boolean;
  priority: string;
  reason: string;
}

export interface UpdateReport {
  candidates: UpdateCandidate[];
  securityUpdates: number;
  totalUpdates: number;
  upToDate: number;
}

export async function checkUpdates(projectPath: string, securityOnly = false): Promise<UpdateReport> {
  const deps = parseDependencies(projectPath);
  if (!deps.length) return { candidates: [], securityUpdates: 0, totalUpdates: 0, upToDate: 0 };

  const depReport = await analyzeDependencies(deps, false);
  const resultMap = new Map<string, DepHealthResult>();
  for (const r of depReport.results) resultMap.set(r.dep.name, r);

  const candidates: UpdateCandidate[] = [];
  let upToDate = 0, securityCount = 0;
  const client = new DepsDevClient();

  for (const dep of deps) {
    if (dep.isDev) continue;
    const pkgInfo = await client.getPackage(dep.name, dep.ecosystem);
    if (!pkgInfo?.latestVersion) continue;

    const latest = pkgInfo.latestVersion;
    const current = dep.version || "";
    if (current === latest) { upToDate++; continue; }

    const result = resultMap.get(dep.name);
    const vulnCount = result?.vulns.length ?? 0;
    const critical = result?.vulns.filter((v) => v.severity === "CRITICAL").length ?? 0;
    const high = result?.vulns.filter((v) => v.severity === "HIGH").length ?? 0;
    const hasFix = result?.vulns.some((v) => v.fixedVersion) ?? false;

    let priority = "low", reason = "Newer version available";
    if (critical > 0) { priority = "critical"; reason = `${critical} critical vulnerability(ies) — update immediately`; }
    else if (high > 0) { priority = "high"; reason = `${high} high vulnerability(ies)`; }
    else if (vulnCount > 0) { priority = "medium"; reason = `${vulnCount} vulnerability(ies) with fixes available`; }
    else if (hasFix) { priority = "medium"; reason = "Security fix available"; }

    if (securityOnly && vulnCount === 0 && !hasFix) continue;
    if (vulnCount > 0 || hasFix) securityCount++;

    candidates.push({ name: dep.name, currentVersion: current, latestVersion: latest, ecosystem: dep.ecosystem, sourceFile: dep.sourceFile, vulnCount, criticalVulns: critical, highVulns: high, hasSecurityFix: hasFix, priority, reason });
  }

  const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  candidates.sort((a, b) => (order[a.priority] ?? 4) - (order[b.priority] ?? 4));

  return { candidates, securityUpdates: securityCount, totalUpdates: candidates.length, upToDate };
}
