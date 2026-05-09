/**
 * Generate and validate SECURITY-INSIGHTS.yml per the OpenSSF Security Insights spec.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { detectProject, type ProjectInfo } from "../detector.js";

export interface InsightsReport {
  generated: boolean;
  valid: boolean;
  filePath: string;
  errors: string[];
  warnings: string[];
}

export function generateInsights(projectPath: string): string {
  const resolved = path.resolve(projectPath);
  const info = detectProject(resolved);
  const now = new Date().toISOString().replace(/\.\d+Z$/, "Z");
  const expiry = oneYearFromNow();
  const commitHash = getGitHead(resolved);

  const lines: string[] = [
    "header:",
    `  schema-version: '1.0.0'`,
    `  expiry-date: '${expiry}'`,
    `  last-updated: '${now}'`,
    `  last-reviewed: '${now}'`,
  ];
  if (commitHash) lines.push(`  commit-hash: '${commitHash}'`);
  if (info.repoName !== path.basename(resolved)) lines.push(`  project-url: 'https://github.com/${info.repoName}'`);

  const changelog = findFile(resolved, ["CHANGELOG.md", "CHANGES.md", "HISTORY.md"]);
  if (changelog) lines.push(`  changelog: '${changelog}'`);

  lines.push("project-lifecycle:", "  status: active", "  bug-fixes-only: false");
  lines.push("contribution-policy:", "  accepts-pull-requests: true", `  accepts-automated-pull-requests: ${info.hasDependabot}`);
  const contributing = findFile(resolved, ["CONTRIBUTING.md", ".github/CONTRIBUTING.md"]);
  if (contributing) lines.push(`  contributing-policy: '${contributing}'`);

  const readme = findFile(resolved, ["README.md"]);
  if (readme) lines.push("documentation:", `  README: '${readme}'`);

  lines.push("vulnerability-reporting:", `  accepts-vulnerability-reports: ${info.hasSecurityMd}`);
  const secPol = findFile(resolved, ["SECURITY.md", ".github/SECURITY.md"]);
  if (secPol) lines.push(`  security-policy: '${secPol}'`);

  if (info.hasCodeql || info.hasScorecard) {
    lines.push("security-testing:");
    if (info.hasCodeql) lines.push("  - tool-type: sast", "    tool-name: CodeQL", "    tool-url: 'https://codeql.github.com/'", "    integration:", "      ci: true");
    if (info.hasScorecard) lines.push("  - tool-type: scorecard", "    tool-name: OpenSSF Scorecard", "    tool-url: 'https://securityscorecards.dev/'", "    integration:", "      ci: true");
  }

  if (info.hasSigstore) lines.push("security-artifacts:", "  signing:", "    enabled: true", "    tool: Sigstore");

  lines.push("dependencies:", "  third-party-packages: true", `  automated-dependency-management:`, `    enabled: ${info.hasDependabot}`);
  if (info.hasSbomWorkflow) lines.push("  sbom:", "    - sbom-type: build", "      sbom-format: spdx");

  return lines.join("\n") + "\n";
}

export function validateInsights(projectPath: string): InsightsReport {
  const resolved = path.resolve(projectPath);
  const report: InsightsReport = { generated: false, valid: false, filePath: "", errors: [], warnings: [] };

  const candidates = ["SECURITY-INSIGHTS.yml", "security-insights.yml", ".github/SECURITY-INSIGHTS.yml", ".github/security-insights.yml"];
  let content = "";
  for (const name of candidates) {
    const full = path.join(resolved, name);
    if (fs.existsSync(full)) { content = fs.readFileSync(full, "utf-8"); report.filePath = name; break; }
  }
  if (!content) { report.errors.push("No SECURITY-INSIGHTS.yml file found"); return report; }

  if (!content.includes("header:")) report.errors.push("Missing required section: header");
  if (!content.includes("project-lifecycle:")) report.errors.push("Missing required section: project-lifecycle");
  if (!content.includes("vulnerability-reporting:")) report.errors.push("Missing required section: vulnerability-reporting");
  if (!content.includes("schema-version")) report.errors.push("Missing header.schema-version");
  if (!content.includes("expiry-date")) report.warnings.push("Missing header.expiry-date");
  if (!content.includes("last-updated")) report.warnings.push("Missing header.last-updated");
  if (!content.includes("accepts-vulnerability-reports")) report.errors.push("Missing vulnerability-reporting.accepts-vulnerability-reports");
  if (!content.includes("status")) report.warnings.push("Missing project-lifecycle.status");

  report.valid = report.errors.length === 0;
  return report;
}

function oneYearFromNow(): string {
  const d = new Date();
  d.setFullYear(d.getFullYear() + 1);
  return d.toISOString().replace(/\.\d+Z$/, "Z");
}

function getGitHead(p: string): string {
  try {
    const head = fs.readFileSync(path.join(p, ".git", "HEAD"), "utf-8").trim();
    if (head.startsWith("ref:")) {
      const refPath = path.join(p, ".git", head.slice(5).trim());
      if (fs.existsSync(refPath)) return fs.readFileSync(refPath, "utf-8").trim().slice(0, 40);
    } else if (head.length === 40) return head;
  } catch { /* */ }
  return "";
}

function findFile(base: string, candidates: string[]): string {
  for (const name of candidates) if (fs.existsSync(path.join(base, name))) return name;
  return "";
}
