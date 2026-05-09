/**
 * Organization-wide security policy enforcement.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { detectProject } from "../detector.js";

export interface PolicyRule {
  id: string;
  description: string;
  category: string;
  severity: string;
  passed: boolean;
  evidence: string;
  recommendation: string;
}

export interface PolicyReport {
  rules: PolicyRule[];
  passedCount: number;
  failedCount: number;
  totalCount: number;
  compliant: boolean;
}

interface PolicyConfig { rules: Array<{ id: string; description: string; category: string; severity: string; check: string }> }

const DEFAULT_RULES = [
  { id: "POL-001", description: "SECURITY.md must exist", category: "documentation", severity: "high", check: "has_security_md" },
  { id: "POL-002", description: "Dependabot must be configured", category: "dependencies", severity: "high", check: "has_dependabot" },
  { id: "POL-003", description: "CodeQL or SAST must be configured", category: "analysis", severity: "high", check: "has_codeql" },
  { id: "POL-004", description: "Scorecard must be configured", category: "scoring", severity: "medium", check: "has_scorecard" },
  { id: "POL-005", description: "SBOM workflow must exist", category: "supply_chain", severity: "medium", check: "has_sbom_workflow" },
  { id: "POL-006", description: "Sigstore signing must be configured", category: "signing", severity: "medium", check: "has_sigstore" },
  { id: "POL-007", description: "LICENSE file must exist", category: "legal", severity: "high", check: "has_license" },
  { id: "POL-008", description: "README.md must exist", category: "documentation", severity: "low", check: "has_readme" },
];

export function checkPolicy(
  projectPath: string,
  policyFile?: string,
): PolicyReport {
  const resolved = path.resolve(projectPath);
  const info = detectProject(resolved);

  let rules = DEFAULT_RULES;
  if (policyFile && fs.existsSync(policyFile)) {
    try {
      const custom = JSON.parse(fs.readFileSync(policyFile, "utf-8")) as PolicyConfig;
      if (custom.rules?.length) rules = custom.rules;
    } catch { /* use defaults */ }
  }

  const results: PolicyRule[] = rules.map((rule) => {
    const passed = evaluateCheck(rule.check, info, resolved);
    return {
      id: rule.id,
      description: rule.description,
      category: rule.category,
      severity: rule.severity,
      passed,
      evidence: passed ? "Present" : "Missing",
      recommendation: passed ? "" : `Fix: ensure ${rule.description.toLowerCase()}`,
    };
  });

  const passedCount = results.filter((r) => r.passed).length;
  return {
    rules: results,
    passedCount,
    failedCount: results.length - passedCount,
    totalCount: results.length,
    compliant: results.every((r) => r.passed),
  };
}

function evaluateCheck(check: string, info: ReturnType<typeof detectProject>, projectPath: string): boolean {
  switch (check) {
    case "has_security_md": return info.hasSecurityMd;
    case "has_dependabot": return info.hasDependabot;
    case "has_codeql": return info.hasCodeql;
    case "has_scorecard": return info.hasScorecard;
    case "has_sbom_workflow": return info.hasSbomWorkflow;
    case "has_sigstore": return info.hasSigstore;
    case "has_license": return ["LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"].some((f) => fs.existsSync(path.join(projectPath, f)));
    case "has_readme": return fs.existsSync(path.join(projectPath, "README.md"));
    default: return false;
  }
}

export function generatePolicyTemplate(): string {
  return JSON.stringify({ rules: DEFAULT_RULES }, null, 2);
}
