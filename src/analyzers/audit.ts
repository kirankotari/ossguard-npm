/**
 * Comprehensive security audit — combines scan + deps + reach into one report.
 */

import { detectProject, type ProjectInfo } from "../detector.js";
import { parseDependencies } from "../parsers/dependencies.js";
import { analyzeDependencies, type DepHealthReport } from "./dep-health.js";
import { analyzeReachability, type ReachReport } from "./reach.js";

export interface AuditReport {
  projectInfo: ProjectInfo | null;
  depHealth: DepHealthReport | null;
  reachability: ReachReport | null;
  configScore: number;
  configTotal: number;
  configPct: number;
  overallGrade: string;
  findings: string[];
  recommendations: string[];
  auditTime: string;
}

function calculateGrade(report: AuditReport): string {
  let score = 100.0;
  const configPct = report.configTotal > 0 ? (report.configScore / report.configTotal) * 100 : 0;
  score -= (100 - configPct) * 0.3;

  if (report.depHealth) {
    if (report.depHealth.criticalVulns > 0) score -= 30;
    if (report.depHealth.highVulns > 0) score -= 15;
    if (report.depHealth.totalVulns > 5) score -= 5;
    score -= (10 - report.depHealth.aggregateScore) * 2;
  }

  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

export async function runAudit(projectPath: string): Promise<AuditReport> {
  const info = detectProject(projectPath);
  const findings: string[] = [];
  const recommendations: string[] = [];

  const checks = [
    info.hasSecurityMd,
    info.hasScorecard,
    info.hasDependabot,
    info.hasCodeql,
    info.hasSbomWorkflow,
    info.hasSigstore,
  ];

  if (!info.hasSecurityMd) { findings.push("Missing SECURITY.md — no vulnerability disclosure policy"); recommendations.push("Run `ossguard init` to add SECURITY.md"); }
  if (!info.hasScorecard) { findings.push("Missing Scorecard workflow — no automated security scoring"); recommendations.push("Run `ossguard init` to add Scorecard CI"); }
  if (!info.hasDependabot) { findings.push("Missing Dependabot — no automated dependency updates"); recommendations.push("Run `ossguard init` to add Dependabot config"); }
  if (!info.hasCodeql) { findings.push("Missing CodeQL — no automated code scanning"); recommendations.push("Run `ossguard init` to add CodeQL workflow"); }
  if (!info.hasSbomWorkflow) { findings.push("Missing SBOM workflow — no bill of materials generation"); recommendations.push("Run `ossguard init` to add SBOM workflow"); }
  if (!info.hasSigstore) { findings.push("Missing Sigstore — releases are not cryptographically signed"); recommendations.push("Run `ossguard init` to add Sigstore signing"); }

  let depHealth: DepHealthReport | null = null;
  let reachability: ReachReport | null = null;

  const deps = parseDependencies(projectPath);
  if (deps.length > 0) {
    depHealth = await analyzeDependencies(deps, false);

    if (depHealth.criticalVulns > 0) { findings.push(`${depHealth.criticalVulns} CRITICAL vulnerabilities in dependencies`); recommendations.push("Immediately update packages with critical vulns"); }
    if (depHealth.highVulns > 0) { findings.push(`${depHealth.highVulns} HIGH severity vulnerabilities`); recommendations.push("Run `ossguard deps` for details and remediation"); }
    if (depHealth.outdatedCount > 0) { findings.push(`${depHealth.outdatedCount} outdated dependencies`); recommendations.push("Update outdated packages to latest versions"); }

    reachability = await analyzeReachability(deps, projectPath);
    if (reachability.filteredVulns > 0) findings.push(`${reachability.filteredVulns} vulnerabilities filtered (not imported)`);
  } else {
    findings.push("No dependencies detected — skipping dependency analysis");
  }

  const report: AuditReport = {
    projectInfo: info,
    depHealth,
    reachability,
    configScore: checks.filter(Boolean).length,
    configTotal: checks.length,
    configPct: checks.length > 0 ? Math.round((checks.filter(Boolean).length / checks.length) * 100) : 0,
    overallGrade: "F",
    findings,
    recommendations,
    auditTime: new Date().toISOString(),
  };

  report.overallGrade = calculateGrade(report);
  return report;
}
