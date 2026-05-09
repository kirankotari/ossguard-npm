/**
 * Malicious package detection — check deps against known malicious packages and typosquatting.
 */

import { OSVClient } from "../apis/osv.js";
import { parseDependencies, type Dependency } from "../parsers/dependencies.js";

export interface SupplyChainFinding {
  package: string;
  version: string;
  ecosystem: string;
  findingType: string;
  severity: string;
  description: string;
  evidence: string;
}

export interface SupplyChainReport {
  findings: SupplyChainFinding[];
  totalDeps: number;
  maliciousCount: number;
  typosquatCount: number;
  riskCount: number;
  clean: boolean;
}

const POPULAR_PACKAGES: Record<string, string[]> = {
  npm: ["lodash", "express", "react", "vue", "angular", "axios", "moment", "webpack", "babel", "eslint", "prettier", "typescript", "jquery", "commander", "chalk", "inquirer", "minimist", "yargs", "debug", "uuid", "dotenv", "cors", "helmet", "jsonwebtoken", "bcrypt", "mongoose", "sequelize", "next", "nuxt", "gatsby", "svelte"],
  pypi: ["requests", "flask", "django", "numpy", "pandas", "scipy", "matplotlib", "tensorflow", "torch", "scikit-learn", "boto3", "pillow", "sqlalchemy", "celery", "redis", "fastapi", "uvicorn", "pydantic", "pytest", "black", "mypy", "ruff", "httpx", "cryptography", "paramiko", "beautifulsoup4", "scrapy"],
};

const MALICIOUS_PATTERNS: Array<[RegExp, string]> = [
  [/^@[a-z]+-pay(?:ment)?s?\//, "Suspicious scoped payment package"],
  [/-exec$/, "Package name ending in -exec (common malicious pattern)"],
  [/colors?\d+/, "Suspicious color package variant"],
];

export async function checkSupplyChain(projectPath: string, checkTyposquats = true, checkMalicious = true): Promise<SupplyChainReport> {
  const deps = parseDependencies(projectPath);
  if (!deps.length) return { findings: [], totalDeps: 0, maliciousCount: 0, typosquatCount: 0, riskCount: 0, clean: true };

  const findings: SupplyChainFinding[] = [];
  if (checkMalicious) await checkOsvMalicious(deps, findings);
  if (checkTyposquats) checkTyposquatRisks(deps, findings);
  checkSuspiciousPatterns(deps, findings);
  checkEmptyPackages(deps, findings);

  const malicious = findings.filter((f) => f.findingType === "malicious").length;
  const typosquat = findings.filter((f) => f.findingType === "typosquat").length;
  const risk = findings.filter((f) => !["malicious", "typosquat"].includes(f.findingType)).length;

  return { findings, totalDeps: deps.length, maliciousCount: malicious, typosquatCount: typosquat, riskCount: risk, clean: findings.length === 0 };
}

async function checkOsvMalicious(deps: Dependency[], findings: SupplyChainFinding[]): Promise<void> {
  const client = new OSVClient();
  for (const dep of deps) {
    const vulns = await client.query(dep.name, dep.version || "", dep.ecosystem);
    for (const vuln of vulns) {
      if (vuln.id.startsWith("MAL-") || (vuln.id.startsWith("PYSEC-") && vuln.summary.toLowerCase().includes("malicious"))) {
        findings.push({ package: dep.name, version: dep.version, ecosystem: dep.ecosystem, findingType: "malicious", severity: "critical", description: `Known malicious package: ${vuln.summary}`, evidence: `OSV: ${vuln.id}` });
      }
    }
  }
}

function checkTyposquatRisks(deps: Dependency[], findings: SupplyChainFinding[]): void {
  for (const dep of deps) {
    const popular = POPULAR_PACKAGES[dep.ecosystem] ?? [];
    for (const popName of popular) {
      if (dep.name === popName) continue;
      const dist = levenshtein(dep.name.toLowerCase(), popName.toLowerCase());
      if (dist > 0 && dist <= 1 && dep.name.length > 4) {
        findings.push({ package: dep.name, version: dep.version, ecosystem: dep.ecosystem, findingType: "typosquat", severity: "high", description: `Name is similar to popular package '${popName}' (edit distance: ${dist})`, evidence: `Levenshtein distance to '${popName}': ${dist}` });
        break;
      }
    }
  }
}

function checkSuspiciousPatterns(deps: Dependency[], findings: SupplyChainFinding[]): void {
  for (const dep of deps) {
    for (const [pattern, desc] of MALICIOUS_PATTERNS) {
      if (pattern.test(dep.name)) {
        findings.push({ package: dep.name, version: dep.version, ecosystem: dep.ecosystem, findingType: "suspicious", severity: "medium", description: desc, evidence: `Matched pattern: ${pattern.source}` });
      }
    }
  }
}

function checkEmptyPackages(deps: Dependency[], findings: SupplyChainFinding[]): void {
  for (const dep of deps) {
    if (dep.ecosystem === "npm" && dep.name.startsWith("@")) {
      const org = dep.name.split("/")[0];
      if (org.length <= 3) {
        findings.push({ package: dep.name, version: dep.version, ecosystem: dep.ecosystem, findingType: "suspicious", severity: "low", description: `Very short scoped package org name: ${org}`, evidence: "Short org names may indicate placeholder squatting" });
      }
    }
  }
}

function levenshtein(s1: string, s2: string): number {
  if (s1.length < s2.length) return levenshtein(s2, s1);
  if (s2.length === 0) return s1.length;
  let prev = Array.from({ length: s2.length + 1 }, (_, i) => i);
  for (let i = 0; i < s1.length; i++) {
    const curr = [i + 1];
    for (let j = 0; j < s2.length; j++) {
      curr.push(Math.min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (s1[i] !== s2[j] ? 1 : 0)));
    }
    prev = curr;
  }
  return prev[s2.length];
}
