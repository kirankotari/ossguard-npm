/**
 * Export HTML/JSON compliance reports from audit data.
 */

import type { AuditReport } from "./audit.js";

export function generateReport(audit: AuditReport, format: "html" | "json" = "html"): string {
  if (format === "json") return generateJsonReport(audit);
  return generateHtmlReport(audit);
}

function generateJsonReport(audit: AuditReport): string {
  return JSON.stringify({
    auditTime: audit.auditTime,
    overallGrade: audit.overallGrade,
    configScore: `${audit.configScore}/${audit.configTotal}`,
    depHealthScore: audit.depHealth?.aggregateScore ?? null,
    totalVulns: audit.depHealth?.totalVulns ?? 0,
    reachableVulns: audit.reachability?.reachableVulns ?? 0,
    noiseReduction: audit.reachability?.noiseReductionPct ?? 0,
    findings: audit.findings,
    recommendations: audit.recommendations,
  }, null, 2);
}

function generateHtmlReport(audit: AuditReport): string {
  const gradeColor: Record<string, string> = { A: "#22c55e", B: "#84cc16", C: "#eab308", D: "#f97316", F: "#ef4444" };
  const color = gradeColor[audit.overallGrade] || "#ef4444";
  const repoName = audit.projectInfo?.repoName ?? "Unknown";

  const findingsHtml = audit.findings.map((f) => `<li>${esc(f)}</li>`).join("\n          ");
  const recsHtml = audit.recommendations.map((r) => `<li>${esc(r)}</li>`).join("\n          ");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Security Report — ${esc(repoName)}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 900px; margin: 0 auto; padding: 2rem; background: #0d1117; color: #c9d1d9; }
    h1 { color: #58a6ff; } h2 { color: #79c0ff; }
    .grade { font-size: 4rem; font-weight: bold; color: ${color}; text-align: center; padding: 1rem; border: 3px solid ${color}; border-radius: 1rem; display: inline-block; min-width: 5rem; }
    .header { text-align: center; margin-bottom: 2rem; }
    .section { background: #161b22; padding: 1.5rem; border-radius: 0.5rem; margin: 1rem 0; border: 1px solid #30363d; }
    ul { padding-left: 1.5rem; }
    .meta { color: #8b949e; font-size: 0.9rem; }
  </style>
</head>
<body>
  <div class="header">
    <h1>Security Compliance Report</h1>
    <p class="meta">${esc(repoName)} — ${esc(audit.auditTime)}</p>
    <div class="grade">${esc(audit.overallGrade)}</div>
  </div>
  <div class="section">
    <h2>Configuration</h2>
    <p>Score: ${audit.configScore}/${audit.configTotal} (${audit.configPct}%)</p>
  </div>
  ${audit.depHealth ? `<div class="section">
    <h2>Dependency Health</h2>
    <p>Score: ${audit.depHealth.aggregateScore}/10 | Vulnerabilities: ${audit.depHealth.totalVulns} (${audit.depHealth.criticalVulns} critical, ${audit.depHealth.highVulns} high)</p>
  </div>` : ""}
  ${audit.reachability ? `<div class="section">
    <h2>Reachability</h2>
    <p>Reachable: ${audit.reachability.reachableVulns} | Filtered: ${audit.reachability.filteredVulns} | Noise reduction: ${audit.reachability.noiseReductionPct}%</p>
  </div>` : ""}
  <div class="section">
    <h2>Findings</h2>
    <ul>${findingsHtml}</ul>
  </div>
  <div class="section">
    <h2>Recommendations</h2>
    <ul>${recsHtml}</ul>
  </div>
</body>
</html>`;
}

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
