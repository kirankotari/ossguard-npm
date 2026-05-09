/**
 * OSPS Baseline compliance checker — assess against OpenSSF Security Baseline levels.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { detectProject, type ProjectInfo } from "../detector.js";

export interface BaselineControl {
  id: string;
  family: string;
  title: string;
  level: number;
  status: string;
  evidence: string;
  recommendation: string;
}

export interface BaselineReport {
  controls: BaselineControl[];
  level1Pass: number;
  level1Total: number;
  level2Pass: number;
  level2Total: number;
  level3Pass: number;
  level3Total: number;
  achievedLevel: number;
  level1Pct: number;
  level2Pct: number;
  level3Pct: number;
}

const CONTROLS: Array<[string, string, string, number]> = [
  ["OSPS-AC-01", "Access Control", "Version control system MUST require MFA for collaborators", 1],
  ["OSPS-AC-02", "Access Control", "Version control system MUST restrict who can push to release branches", 1],
  ["OSPS-BR-01", "Build & Release", "Project MUST publish build/install instructions", 1],
  ["OSPS-BR-02", "Build & Release", "Project MUST use an automated build system", 1],
  ["OSPS-DO-01", "Documentation", "Project MUST have a README with description", 1],
  ["OSPS-DO-02", "Documentation", "Project MUST document how to report security issues", 1],
  ["OSPS-DO-03", "Documentation", "Project MUST have a contribution guide", 1],
  ["OSPS-GV-01", "Governance", "Project MUST have a defined governance model or maintainer list", 1],
  ["OSPS-LE-01", "Legal", "Project MUST have an OSI-approved license", 1],
  ["OSPS-LE-02", "Legal", "All source files SHOULD contain a license header or SPDX identifier", 1],
  ["OSPS-QA-01", "Quality", "Project MUST have an automated test suite", 1],
  ["OSPS-QA-02", "Quality", "Project MUST use CI to run tests on each change", 1],
  ["OSPS-SA-01", "Security Assessment", "Project MUST use a static analysis tool", 1],
  ["OSPS-VM-01", "Vulnerability Management", "Project MUST monitor dependencies for known vulnerabilities", 1],
  ["OSPS-VM-02", "Vulnerability Management", "Project MUST have a process to address reported vulnerabilities", 1],
  ["OSPS-AC-03", "Access Control", "Project MUST enforce branch protection on default branch", 2],
  ["OSPS-BR-03", "Build & Release", "Project MUST produce provenance metadata for releases", 2],
  ["OSPS-BR-04", "Build & Release", "Project MUST pin dependencies in build configuration", 2],
  ["OSPS-DO-04", "Documentation", "Project MUST have a change log", 2],
  ["OSPS-DO-05", "Documentation", "Project MUST publish a security-insights.yml", 2],
  ["OSPS-QA-03", "Quality", "Project MUST achieve adequate test coverage", 2],
  ["OSPS-SA-02", "Security Assessment", "Project MUST run SAST on each change (e.g., CodeQL)", 2],
  ["OSPS-SA-03", "Security Assessment", "Project MUST generate SBOMs for releases", 2],
  ["OSPS-VM-03", "Vulnerability Management", "Project MUST fix critical/high vulns within defined SLAs", 2],
  ["OSPS-LE-03", "Legal", "Project MUST include a NOTICE or attribution file for third-party code", 2],
  ["OSPS-AC-04", "Access Control", "Project MUST require signed commits on release branches", 3],
  ["OSPS-BR-05", "Build & Release", "Project MUST sign releases with Sigstore or equivalent", 3],
  ["OSPS-BR-06", "Build & Release", "Project MUST achieve SLSA Build Level 2+", 3],
  ["OSPS-SA-04", "Security Assessment", "Project MUST have a fuzz testing framework configured", 3],
  ["OSPS-SA-05", "Security Assessment", "Project MUST run dependency review on PRs", 3],
  ["OSPS-QA-04", "Quality", "Project MUST have reproducible builds", 3],
  ["OSPS-VM-04", "Vulnerability Management", "Project MUST publish security advisories via GitHub/OSV", 3],
];

export function checkBaseline(projectPath: string, targetLevel = 3): BaselineReport {
  const resolved = path.resolve(projectPath);
  const info = detectProject(resolved);

  const controls: BaselineControl[] = [];
  for (const [id, family, title, level] of CONTROLS) {
    if (level > targetLevel) continue;
    const [status, evidence, rec] = checkControl(id, info, resolved);
    controls.push({ id, family, title, level, status, evidence, recommendation: rec });
  }

  const count = (lvl: number, pass: boolean) => controls.filter((c) => c.level === lvl && (!pass || c.status === "pass")).length;
  const l1p = count(1, true), l1t = count(1, false), l2p = count(2, true), l2t = count(2, false), l3p = count(3, true), l3t = count(3, false);

  let achieved = 0;
  if (l1t > 0 && l1p === l1t) { achieved = 1; if (l2t > 0 && l2p === l2t) { achieved = 2; if (l3t > 0 && l3p === l3t) achieved = 3; } }

  return {
    controls, level1Pass: l1p, level1Total: l1t, level2Pass: l2p, level2Total: l2t, level3Pass: l3p, level3Total: l3t, achievedLevel: achieved,
    level1Pct: l1t ? Math.round((l1p / l1t) * 1000) / 10 : 0,
    level2Pct: l2t ? Math.round((l2p / l2t) * 1000) / 10 : 0,
    level3Pct: l3t ? Math.round((l3p / l3t) * 1000) / 10 : 0,
  };
}

function exists(base: string, ...names: string[]): boolean { return names.some((n) => fs.existsSync(path.join(base, n))); }

function readWorkflows(base: string): Array<{ name: string; content: string }> {
  const wfDir = path.join(base, ".github", "workflows");
  if (!fs.existsSync(wfDir)) return [];
  return fs.readdirSync(wfDir).filter((f: string) => f.endsWith(".yml") || f.endsWith(".yaml")).map((f: string) => ({ name: f, content: fs.readFileSync(path.join(wfDir, f), "utf-8") }));
}

function checkControl(id: string, info: ProjectInfo, p: string): [string, string, string] {
  const wfs = () => readWorkflows(p);

  if (id === "OSPS-AC-01") { return (exists(p, "BRANCH_PROTECTION.md") || info.hasScorecard) ? ["pass", "Branch protection guide or Scorecard found", ""] : ["unknown", "", "Enable MFA for all collaborators and run Scorecard to verify"]; }
  if (id === "OSPS-AC-02") { return (exists(p, "BRANCH_PROTECTION.md") || info.hasScorecard) ? ["pass", "Branch protection documentation found", ""] : ["unknown", "", "Configure branch protection — run `ossguard init`"]; }
  if (id === "OSPS-AC-03") { return (exists(p, "BRANCH_PROTECTION.md") || info.hasScorecard) ? ["pass", "Branch protection documentation found", ""] : ["fail", "", "Enable branch protection on default branch"]; }
  if (id === "OSPS-AC-04") { if (exists(p, "BRANCH_PROTECTION.md")) { try { if (fs.readFileSync(path.join(p, "BRANCH_PROTECTION.md"), "utf-8").toLowerCase().includes("signed")) return ["pass", "Signed commit requirement documented", ""]; } catch {} } return ["fail", "", "Require signed commits on release branches"]; }

  if (id === "OSPS-BR-01") { if (exists(p, "README.md")) { try { const c = fs.readFileSync(path.join(p, "README.md"), "utf-8").toLowerCase(); if (["install", "build", "getting started", "setup", "usage"].some((k) => c.includes(k))) return ["pass", "Build/install instructions found in README", ""]; } catch {} } return ["fail", "", "Add build/install instructions to README.md"]; }
  if (id === "OSPS-BR-02") { if (info.hasGithubActions) return ["pass", "GitHub Actions workflows found", ""]; if ([".travis.yml", ".circleci/config.yml", "Jenkinsfile", ".gitlab-ci.yml"].some((f) => exists(p, f))) return ["pass", "CI config found", ""]; return ["fail", "", "Set up automated builds — run `ossguard ci`"]; }
  if (id === "OSPS-BR-03") { for (const wf of wfs()) { const c = wf.content.toLowerCase(); if (["slsa", "provenance", "attest"].some((k) => c.includes(k))) return ["pass", `Provenance generation found in ${wf.name}`, ""]; } return ["fail", "", "Add SLSA provenance generation to your release workflow"]; }
  if (id === "OSPS-BR-04") { for (const wf of wfs()) { if (wf.content.includes("@") && /[0-9a-f]{40}/.test(wf.content)) return ["pass", "Some actions pinned to commit SHAs", ""]; } return ["fail", "", "Pin GitHub Actions to commit SHAs — run `ossguard pin`"]; }
  if (id === "OSPS-BR-05") { return info.hasSigstore ? ["pass", "Sigstore signing workflow found", ""] : ["fail", "", "Add release signing — run `ossguard init`"]; }
  if (id === "OSPS-BR-06") { for (const wf of wfs()) { const c = wf.content.toLowerCase(); if (c.includes("slsa") && (c.includes("level") || c.includes("l2") || c.includes("l3"))) return ["pass", "SLSA build level configuration found", ""]; } return ["fail", "", "Achieve SLSA Build Level 2+ for your release pipeline"]; }

  if (id === "OSPS-DO-01") { if (exists(p, "README.md")) { try { if (fs.statSync(path.join(p, "README.md")).size > 100) return ["pass", "README.md found with content", ""]; } catch {} } return ["fail", "", "Create a detailed README.md"]; }
  if (id === "OSPS-DO-02") { return info.hasSecurityMd ? ["pass", "SECURITY.md found", ""] : ["fail", "", "Add SECURITY.md — run `ossguard init`"]; }
  if (id === "OSPS-DO-03") { return exists(p, "CONTRIBUTING.md", ".github/CONTRIBUTING.md") ? ["pass", "Contributing guide found", ""] : ["fail", "", "Create a CONTRIBUTING.md with contribution guidelines"]; }
  if (id === "OSPS-DO-04") { return exists(p, "CHANGELOG.md", "CHANGES.md", "HISTORY.md", "NEWS.md") ? ["pass", "Changelog found", ""] : ["fail", "", "Create a CHANGELOG.md documenting changes"]; }
  if (id === "OSPS-DO-05") { return exists(p, "SECURITY-INSIGHTS.yml", "security-insights.yml", ".github/SECURITY-INSIGHTS.yml", ".github/security-insights.yml") ? ["pass", "Security insights found", ""] : ["fail", "", "Generate security-insights.yml — run `ossguard insights`"]; }

  if (id === "OSPS-GV-01") { return exists(p, "GOVERNANCE.md", "MAINTAINERS.md", "CODEOWNERS", ".github/CODEOWNERS") ? ["pass", "Governance file found", ""] : ["fail", "", "Add GOVERNANCE.md or CODEOWNERS file"]; }
  if (id === "OSPS-LE-01") { return exists(p, "LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING") ? ["pass", "License found", ""] : ["fail", "", "Add a LICENSE file with an OSI-approved license"]; }
  if (id === "OSPS-LE-02") { return ["unknown", "", "Check SPDX headers in source files"]; }
  if (id === "OSPS-LE-03") { return exists(p, "NOTICE", "NOTICE.md", "THIRD-PARTY-NOTICES.txt", "THIRD_PARTY_NOTICES", "ThirdPartyNotices.txt") ? ["pass", "Third-party notice found", ""] : ["fail", "", "Generate third-party notices — run `ossguard tpn`"]; }

  if (id === "OSPS-QA-01") { if (["tests", "test", "spec", "__tests__"].some((d) => { try { return fs.statSync(path.join(p, d)).isDirectory(); } catch { return false; } })) return ["pass", "Test directory found", ""]; return ["fail", "", "Add an automated test suite"]; }
  if (id === "OSPS-QA-02") { if (info.hasGithubActions) { for (const wf of wfs()) { const c = wf.content.toLowerCase(); if (["test", "pytest", "jest"].some((k) => c.includes(k))) return ["pass", "CI test workflow found", ""]; } return ["pass", "GitHub Actions found", ""]; } return ["fail", "", "Configure CI to run tests — run `ossguard ci`"]; }
  if (id === "OSPS-QA-03") { return exists(p, ".coveragerc", "codecov.yml", ".codecov.yml", "coverage.xml", "jest.config.js", "tox.ini", "setup.cfg") ? ["pass", "Coverage configuration found", ""] : ["unknown", "", "Configure and measure test coverage"]; }
  if (id === "OSPS-QA-04") { return ["unknown", "", "Verify builds are reproducible"]; }

  if (id === "OSPS-SA-01") { if (info.hasCodeql) return ["pass", "CodeQL workflow found", ""]; for (const wf of wfs()) { const c = wf.content.toLowerCase(); if (["semgrep", "bandit", "eslint", "clippy", "gosec", "sonar"].some((k) => c.includes(k))) return ["pass", `Static analysis found in ${wf.name}`, ""]; } return ["fail", "", "Add static analysis — run `ossguard init` for CodeQL"]; }
  if (id === "OSPS-SA-02") { return info.hasCodeql ? ["pass", "CodeQL SAST workflow found", ""] : ["fail", "", "Configure SAST to run on each change — run `ossguard init`"]; }
  if (id === "OSPS-SA-03") { return info.hasSbomWorkflow ? ["pass", "SBOM generation workflow found", ""] : ["fail", "", "Add SBOM generation — run `ossguard init`"]; }
  if (id === "OSPS-SA-04") { const markers = ["fuzz", "oss-fuzz", ".clusterfuzzlite", "cargo-fuzz"]; if (markers.some((m) => exists(p, m))) return ["pass", "Fuzz config found", ""]; for (const wf of wfs()) if (wf.content.toLowerCase().includes("fuzz")) return ["pass", `Fuzz workflow found: ${wf.name}`, ""]; return ["fail", "", "Set up fuzz testing — run `ossguard fuzz`"]; }
  if (id === "OSPS-SA-05") { for (const wf of wfs()) { const c = wf.content.toLowerCase(); if (c.includes("dependency-review") || c.includes("dependency_review")) return ["pass", `Dependency review found: ${wf.name}`, ""]; } return ["fail", "", "Add dependency review action for PRs"]; }

  if (id === "OSPS-VM-01") { return info.hasDependabot ? ["pass", "Dependabot configured", ""] : ["fail", "", "Enable Dependabot — run `ossguard init`"]; }
  if (id === "OSPS-VM-02") { return info.hasSecurityMd ? ["pass", "SECURITY.md defines vulnerability process", ""] : ["fail", "", "Add SECURITY.md with vulnerability handling process"]; }
  if (id === "OSPS-VM-03") { return (info.hasDependabot && info.hasSecurityMd) ? ["pass", "Automated updates + vulnerability process in place", ""] : ["unknown", "", "Define SLAs for fixing critical/high vulnerabilities"]; }
  if (id === "OSPS-VM-04") { return exists(p, ".github/advisories") ? ["pass", "Security advisories directory found", ""] : ["unknown", "", "Publish security advisories via GitHub Security Advisories"]; }

  return ["unknown", "", ""];
}
