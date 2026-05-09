/**
 * Dependency health analysis — combines OSV vulns, deps.dev metadata, and Scorecard.
 */

import { DepsDevClient, type PackageInfo } from "../apis/deps-dev.js";
import { OSVClient, type VulnInfo } from "../apis/osv.js";
import type { Dependency } from "../parsers/dependencies.js";

export interface DepHealthResult {
  dep: Dependency;
  vulns: VulnInfo[];
  packageInfo: PackageInfo | null;
  healthScore: number; // 0-10
  vulnCount: number;
  criticalCount: number;
  highCount: number;
  license: string;
  latestVersion: string;
  isOutdated: boolean;
  riskLevel: string;
}

export interface DepHealthReport {
  results: DepHealthResult[];
  totalDeps: number;
  totalVulns: number;
  criticalVulns: number;
  highVulns: number;
  mediumVulns: number;
  outdatedCount: number;
  aggregateScore: number; // 0-10
  riskSummary: string;
}

function computeRiskLevel(r: DepHealthResult): string {
  if (r.criticalCount > 0) return "CRITICAL";
  if (r.highCount > 0) return "HIGH";
  if (r.vulnCount > 0) return "MEDIUM";
  if (r.isOutdated) return "LOW";
  return "OK";
}

function calculateHealthScore(
  dep: Dependency,
  vulns: VulnInfo[],
  pkgInfo: PackageInfo | null,
): number {
  let score = 10.0;
  for (const v of vulns) {
    if (v.severity === "CRITICAL") score -= 3.0;
    else if (v.severity === "HIGH") score -= 2.0;
    else if (v.severity === "MEDIUM") score -= 1.0;
    else score -= 0.5;
  }
  if (pkgInfo && dep.version && pkgInfo.latestVersion && dep.version !== pkgInfo.latestVersion) {
    score -= 0.5;
  }
  return Math.round(Math.max(0, Math.min(10, score)) * 10) / 10;
}

export async function analyzeDependencies(
  deps: Dependency[],
  includeDev = false,
): Promise<DepHealthReport> {
  const targetDeps = includeDev ? deps : deps.filter((d) => !d.isDev);
  if (targetDeps.length === 0) {
    return {
      results: [],
      totalDeps: 0,
      totalVulns: 0,
      criticalVulns: 0,
      highVulns: 0,
      mediumVulns: 0,
      outdatedCount: 0,
      aggregateScore: 10,
      riskSummary: "HEALTHY",
    };
  }

  const osv = new OSVClient();
  const vulnMap = await osv.queryBatch(
    targetDeps.map((d) => ({ name: d.name, version: d.version, ecosystem: d.ecosystem })),
  );

  const ddc = new DepsDevClient();
  const pkgInfoMap = new Map<string, PackageInfo>();
  for (const dep of targetDeps) {
    const info = dep.version
      ? await ddc.getVersion(dep.name, dep.version, dep.ecosystem)
      : await ddc.getPackage(dep.name, dep.ecosystem);
    if (info) pkgInfoMap.set(dep.name, info);
  }

  let totalVulns = 0;
  let critical = 0;
  let high = 0;
  let medium = 0;
  let outdated = 0;

  const results: DepHealthResult[] = targetDeps.map((dep) => {
    const vulns = vulnMap.get(dep.name) ?? [];
    const pkgInfo = pkgInfoMap.get(dep.name) ?? null;
    const healthScore = calculateHealthScore(dep, vulns, pkgInfo);
    const criticalCount = vulns.filter((v) => v.severity === "CRITICAL").length;
    const highCount = vulns.filter((v) => v.severity === "HIGH").length;
    const isOutdated =
      !!(dep.version && pkgInfo?.latestVersion && dep.version !== pkgInfo.latestVersion);

    totalVulns += vulns.length;
    critical += criticalCount;
    high += highCount;
    medium += vulns.filter((v) => v.severity === "MEDIUM").length;
    if (isOutdated) outdated++;

    const result: DepHealthResult = {
      dep,
      vulns,
      packageInfo: pkgInfo,
      healthScore,
      vulnCount: vulns.length,
      criticalCount,
      highCount,
      license: pkgInfo?.license ?? "",
      latestVersion: pkgInfo?.latestVersion ?? "",
      isOutdated,
      riskLevel: "",
    };
    result.riskLevel = computeRiskLevel(result);
    return result;
  });

  results.sort((a, b) => a.healthScore - b.healthScore);

  const avgScore =
    results.length > 0
      ? Math.round((results.reduce((s, r) => s + r.healthScore, 0) / results.length) * 10) / 10
      : 10;

  let riskSummary = "HEALTHY";
  if (critical > 0) riskSummary = "CRITICAL";
  else if (high > 0) riskSummary = "HIGH";
  else if (totalVulns > 0) riskSummary = "MEDIUM";
  else if (outdated > 0) riskSummary = "LOW";

  return {
    results,
    totalDeps: targetDeps.length,
    totalVulns,
    criticalVulns: critical,
    highVulns: high,
    mediumVulns: medium,
    outdatedCount: outdated,
    aggregateScore: avgScore,
    riskSummary,
  };
}
