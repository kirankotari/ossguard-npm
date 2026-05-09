/**
 * S2C2F maturity assessment — Secure Supply Chain Consumption Framework levels.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { detectProject, type ProjectInfo } from "../detector.js";

export interface S2C2FPractice {
  id: string;
  level: number;
  category: string;
  description: string;
  status: string;
  evidence: string;
  recommendation: string;
}

export interface MaturityReport {
  practices: S2C2FPractice[];
  achievedLevel: number;
  level1Pct: number;
  level2Pct: number;
  level3Pct: number;
  level4Pct: number;
}

const PRACTICES: Array<[string, number, string, string]> = [
  ["S2C2F-ING-1", 1, "Ingest", "Use package managers to consume OSS (not copy-paste)"],
  ["S2C2F-ING-2", 1, "Ingest", "Track all OSS dependencies in a manifest file"],
  ["S2C2F-ING-3", 1, "Ingest", "Use an automated dependency update tool"],
  ["S2C2F-SCN-1", 1, "Scan", "Scan OSS for known vulnerabilities"],
  ["S2C2F-SCN-2", 1, "Scan", "Scan OSS for license compliance"],
  ["S2C2F-INV-1", 2, "Inventory", "Maintain an inventory (SBOM) of all OSS consumed"],
  ["S2C2F-INV-2", 2, "Inventory", "Track transitive dependencies"],
  ["S2C2F-UPD-1", 2, "Update", "Apply security patches within defined SLAs"],
  ["S2C2F-UPD-2", 2, "Update", "Automate dependency updates for security fixes"],
  ["S2C2F-ENF-1", 2, "Enforce", "Block known-vulnerable components from being used"],
  ["S2C2F-ENF-2", 2, "Enforce", "Enforce license compliance policies"],
  ["S2C2F-AUD-1", 3, "Audit", "Perform security audit of critical OSS dependencies"],
  ["S2C2F-AUD-2", 3, "Audit", "Verify provenance of OSS packages"],
  ["S2C2F-FIX-1", 3, "Fix", "Ability to privately patch critical OSS vulnerabilities"],
  ["S2C2F-FIX-2", 3, "Fix", "Contribute security fixes upstream"],
  ["S2C2F-VER-1", 3, "Verify", "Verify signatures on consumed OSS packages"],
  ["S2C2F-VER-2", 3, "Verify", "Validate SBOM accuracy"],
  ["S2C2F-REB-1", 4, "Rebuild", "Rebuild OSS from source in a controlled environment"],
  ["S2C2F-REB-2", 4, "Rebuild", "Verify reproducibility of builds"],
  ["S2C2F-SEC-1", 4, "Secure", "Run OSS in sandboxed environments"],
  ["S2C2F-SEC-2", 4, "Secure", "Apply runtime protection and monitoring"],
];

export function assessMaturity(projectPath: string): MaturityReport {
  const resolved = path.resolve(projectPath);
  const info = detectProject(resolved);

  const practices: S2C2FPractice[] = PRACTICES.map(([id, level, category, description]) => {
    const [status, evidence, rec] = checkPractice(id, info, resolved);
    return { id, level, category, description, status, evidence, recommendation: rec };
  });

  const pctForLevel = (lvl: number) => {
    const pracs = practices.filter((p) => p.level === lvl);
    const met = pracs.filter((p) => p.status === "met").length;
    return pracs.length ? Math.round((met / pracs.length) * 1000) / 10 : 0;
  };

  let achieved = 0;
  for (let lvl = 1; lvl <= 4; lvl++) {
    const pracs = practices.filter((p) => p.level === lvl);
    if (pracs.length && pracs.every((p) => p.status === "met")) achieved = lvl;
    else break;
  }

  return { practices, achievedLevel: achieved, level1Pct: pctForLevel(1), level2Pct: pctForLevel(2), level3Pct: pctForLevel(3), level4Pct: pctForLevel(4) };
}

function exists(base: string, ...names: string[]): boolean { return names.some((n) => fs.existsSync(path.join(base, n))); }

function readWorkflows(base: string): Array<{ name: string; content: string }> {
  const wfDir = path.join(base, ".github", "workflows");
  if (!fs.existsSync(wfDir)) return [];
  return fs.readdirSync(wfDir).filter((f: string) => f.endsWith(".yml") || f.endsWith(".yaml")).map((f: string) => ({ name: f, content: fs.readFileSync(path.join(wfDir, f), "utf-8") }));
}

function checkPractice(id: string, info: ProjectInfo, p: string): [string, string, string] {
  const manifests = ["package.json", "requirements.txt", "pyproject.toml", "go.mod", "Cargo.toml", "pom.xml", "composer.json", "Gemfile"];
  const lockFiles = ["package-lock.json", "yarn.lock", "poetry.lock", "Cargo.lock", "go.sum", "Gemfile.lock", "composer.lock"];

  if (id === "S2C2F-ING-1") { for (const m of manifests) if (exists(p, m)) return ["met", `Package manifest found: ${m}`, ""]; return ["unmet", "", "Use a package manager with a manifest file"]; }
  if (id === "S2C2F-ING-2") { const found = manifests.filter((m) => exists(p, m)); return found.length ? ["met", `Dependency manifests: ${found.join(", ")}`, ""] : ["unmet", "", "Track dependencies in a manifest file"]; }
  if (id === "S2C2F-ING-3") { if (info.hasDependabot) return ["met", "Dependabot configured", ""]; if (exists(p, "renovate.json", ".renovaterc", ".renovaterc.json")) return ["met", "Renovate configured", ""]; return ["unmet", "", "Enable Dependabot or Renovate — run `ossguard init`"]; }

  if (id === "S2C2F-SCN-1") { return (info.hasDependabot || info.hasCodeql) ? ["met", "Vulnerability scanning configured", ""] : ["unmet", "", "Enable vulnerability scanning — run `ossguard deps`"]; }
  if (id === "S2C2F-SCN-2") { for (const wf of readWorkflows(p)) if (wf.content.toLowerCase().includes("license")) return ["met", `License scanning found in ${wf.name}`, ""]; return ["unknown", "", "Add license compliance scanning — run `ossguard license`"]; }

  if (id === "S2C2F-INV-1") { if (info.hasSbomWorkflow) return ["met", "SBOM generation workflow found", ""]; if (exists(p, "sbom.json", "sbom.spdx.json", "bom.json")) return ["met", "SBOM found", ""]; return ["unmet", "", "Generate SBOMs — run `ossguard sbom`"]; }
  if (id === "S2C2F-INV-2") { for (const lf of lockFiles) if (exists(p, lf)) return ["met", `Lock file tracks transitive deps: ${lf}`, ""]; return ["unmet", "", "Use lock files to track transitive dependencies"]; }

  if (id === "S2C2F-UPD-1") { return info.hasDependabot ? ["met", "Automated dependency updates configured", ""] : ["unknown", "", "Define and enforce SLAs for security patches"]; }
  if (id === "S2C2F-UPD-2") { return info.hasDependabot ? ["met", "Dependabot automates security updates", ""] : ["unmet", "", "Enable automated security updates"]; }

  if (id === "S2C2F-ENF-1") { for (const wf of readWorkflows(p)) { const c = wf.content.toLowerCase(); if (c.includes("dependency-review") || c.includes("audit")) return ["met", `Dependency enforcement found in ${wf.name}`, ""]; } return ["unmet", "", "Add dependency review to CI — run `ossguard ci`"]; }
  if (id === "S2C2F-ENF-2") return ["unknown", "", "Implement license compliance enforcement"];

  if (id === "S2C2F-AUD-1") return ["unknown", "", "Perform security audits of critical dependencies"];
  if (id === "S2C2F-AUD-2") { return info.hasSigstore ? ["met", "Sigstore verification available", ""] : ["unmet", "", "Verify provenance of consumed packages"]; }

  if (id === "S2C2F-FIX-1") return ["unknown", "", "Establish process for privately patching critical vulnerabilities"];
  if (id === "S2C2F-FIX-2") { return info.hasSecurityMd ? ["met", "Security policy encourages upstream contributions", ""] : ["unknown", "", "Document process for contributing security fixes upstream"]; }

  if (id === "S2C2F-VER-1") { for (const wf of readWorkflows(p)) { const c = wf.content.toLowerCase(); if (c.includes("cosign verify") || c.includes("sigstore")) return ["met", "Signature verification configured", ""]; } return ["unmet", "", "Add package signature verification"]; }
  if (id === "S2C2F-VER-2") return ["unknown", "", "Implement SBOM validation processes"];

  if (["S2C2F-REB-1", "S2C2F-REB-2", "S2C2F-SEC-1", "S2C2F-SEC-2"].includes(id)) return ["unknown", "", "Advanced practice — requires organizational process"];

  return ["unknown", "", ""];
}
