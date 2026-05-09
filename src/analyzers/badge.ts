/**
 * OpenSSF Best Practices Badge readiness assessment.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { detectProject } from "../detector.js";

export interface BadgeCriterion {
  id: string;
  description: string;
  met: boolean;
  suggestion: string;
}

export interface BadgeReport {
  criteria: BadgeCriterion[];
  metCount: number;
  totalCount: number;
  percentage: number;
  passingLevel: string;
}

export function assessBadgeReadiness(projectPath: string): BadgeReport {
  const resolved = path.resolve(projectPath);
  const info = detectProject(resolved);

  const criteria: BadgeCriterion[] = [];

  const check = (id: string, desc: string, met: boolean, suggestion: string) =>
    criteria.push({ id, description: desc, met, suggestion: met ? "" : suggestion });

  check("readme", "Project has a README", fs.existsSync(path.join(resolved, "README.md")), "Create a README.md");
  check("contributing", "Project has contribution guide",
    ["CONTRIBUTING.md", ".github/CONTRIBUTING.md"].some((f) => fs.existsSync(path.join(resolved, f))),
    "Create CONTRIBUTING.md");
  check("license", "Project has a license",
    ["LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"].some((f) => fs.existsSync(path.join(resolved, f))),
    "Add a LICENSE file");
  check("security_md", "Project has SECURITY.md", info.hasSecurityMd, "Run `ossguard init` to add SECURITY.md");
  check("ci", "Project uses CI", info.hasGithubActions, "Set up CI with GitHub Actions — run `ossguard ci`");
  check("codeql", "Project uses CodeQL or SAST", info.hasCodeql, "Run `ossguard init` to add CodeQL");
  check("dependabot", "Project uses Dependabot or Renovate", info.hasDependabot, "Run `ossguard init` to add Dependabot");
  check("scorecard", "Project uses OpenSSF Scorecard", info.hasScorecard, "Run `ossguard init` to add Scorecard");
  check("sbom", "Project generates SBOMs", info.hasSbomWorkflow, "Run `ossguard init` to add SBOM workflow");
  check("sigstore", "Project signs releases with Sigstore", info.hasSigstore, "Run `ossguard init` to add Sigstore");
  check("test_suite", "Project has tests",
    ["tests", "test", "spec", "__tests__"].some((d) => {
      try { return fs.statSync(path.join(resolved, d)).isDirectory(); } catch { return false; }
    }),
    "Add automated tests");
  check("changelog", "Project has a change log",
    ["CHANGELOG.md", "CHANGES.md", "HISTORY.md"].some((f) => fs.existsSync(path.join(resolved, f))),
    "Create a CHANGELOG.md");

  const metCount = criteria.filter((c) => c.met).length;
  const total = criteria.length;
  const pct = total > 0 ? Math.round((metCount / total) * 100) : 0;
  let passingLevel = "not passing";
  if (pct >= 90) passingLevel = "passing";
  else if (pct >= 60) passingLevel = "in progress";

  return { criteria, metCount, totalCount: total, percentage: pct, passingLevel };
}
