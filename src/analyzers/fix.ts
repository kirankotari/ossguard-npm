/**
 * Auto-remediation — fix common security issues automatically.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { detectProject } from "../detector.js";
import { generateSecurityMd } from "../generators/security-md.js";
import { generateDependabotConfig } from "../generators/dependabot.js";
import { generateScorecardWorkflow } from "../generators/scorecard.js";
import { parseDependencies, type Dependency } from "../parsers/dependencies.js";
import { analyzeDependencies } from "./dep-health.js";

export interface FixAction {
  description: string;
  filePath: string;
  actionType: string;
  applied: boolean;
  details: string;
}

export interface FixReport {
  actions: FixAction[];
  appliedCount: number;
  skippedCount: number;
  failedCount: number;
  total: number;
}

export async function autoFix(
  projectPath: string,
  dryRun = false,
  fixDeps = true,
  fixConfigs = true,
): Promise<FixReport> {
  const resolved = path.resolve(projectPath);
  const actions: FixAction[] = [];

  if (fixDeps) {
    const deps = parseDependencies(resolved);
    if (deps.length > 0) {
      const depReport = await analyzeDependencies(deps, false);
      for (const result of depReport.results) {
        for (const vuln of result.vulns) {
          if (vuln.fixedVersion) {
            const action: FixAction = {
              description: `Bump ${result.dep.name} to ${vuln.fixedVersion} (fixes ${vuln.id})`,
              filePath: result.dep.sourceFile,
              actionType: "update_dep",
              applied: false,
              details: `${result.dep.version} → ${vuln.fixedVersion}`,
            };
            if (!dryRun) {
              action.applied = bumpDependency(resolved, result.dep, vuln.fixedVersion);
            }
            actions.push(action);
          }
        }
      }
    }
  }

  if (fixConfigs) {
    const info = detectProject(resolved);
    if (!info.hasSecurityMd) {
      const action: FixAction = { description: "Add SECURITY.md vulnerability disclosure policy", filePath: "SECURITY.md", actionType: "add_file", applied: false, details: "" };
      if (!dryRun) {
        fs.writeFileSync(path.join(resolved, "SECURITY.md"), generateSecurityMd(info.repoName));
        action.applied = true;
      }
      actions.push(action);
    }
    if (!info.hasDependabot) {
      const action: FixAction = { description: "Add Dependabot configuration", filePath: ".github/dependabot.yml", actionType: "add_file", applied: false, details: "" };
      if (!dryRun) {
        const depDir = path.join(resolved, ".github");
        fs.mkdirSync(depDir, { recursive: true });
        fs.writeFileSync(path.join(depDir, "dependabot.yml"), generateDependabotConfig(info.packageManagers));
        action.applied = true;
      }
      actions.push(action);
    }
    if (!info.hasScorecard) {
      const action: FixAction = { description: "Add Scorecard workflow", filePath: ".github/workflows/scorecard.yml", actionType: "add_file", applied: false, details: "" };
      if (!dryRun) {
        const wfDir = path.join(resolved, ".github", "workflows");
        fs.mkdirSync(wfDir, { recursive: true });
        fs.writeFileSync(path.join(wfDir, "scorecard.yml"), generateScorecardWorkflow());
        action.applied = true;
      }
      actions.push(action);
    }
    checkAndFixNpmScripts(resolved, actions, dryRun);
  }

  const applied = actions.filter((a) => a.applied).length;
  const skipped = dryRun ? actions.length : actions.filter((a) => !a.applied).length;
  return { actions, appliedCount: applied, skippedCount: skipped, failedCount: 0, total: actions.length };
}

function bumpDependency(projectPath: string, dep: Dependency, newVersion: string): boolean {
  try {
    if (dep.sourceFile === "package.json") return bumpPackageJson(path.join(projectPath, "package.json"), dep.name, newVersion);
    if (dep.sourceFile === "requirements.txt") return bumpRequirementsTxt(path.join(projectPath, "requirements.txt"), dep.name, newVersion);
  } catch { /* */ }
  return false;
}

function bumpPackageJson(filePath: string, name: string, newVersion: string): boolean {
  if (!fs.existsSync(filePath)) return false;
  try {
    const data = JSON.parse(fs.readFileSync(filePath, "utf-8"));
    let updated = false;
    for (const section of ["dependencies", "devDependencies"]) {
      if (data[section]?.[name]) {
        const old: string = data[section][name];
        const prefix = ["^", "~", ">=", ">"].find((p) => old.startsWith(p)) ?? "";
        data[section][name] = `${prefix}${newVersion}`;
        updated = true;
      }
    }
    if (updated) { fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + "\n"); return true; }
  } catch { /* */ }
  return false;
}

function bumpRequirementsTxt(filePath: string, name: string, newVersion: string): boolean {
  if (!fs.existsSync(filePath)) return false;
  try {
    const lines = fs.readFileSync(filePath, "utf-8").split("\n");
    let updated = false;
    const re = new RegExp(`^(${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")})\\s*([><=~!]+)\\s*[\\d.*]+`, "i");
    const newLines = lines.map((line: string) => {
      const m = re.exec(line);
      if (m) { updated = true; return `${m[1]}${m[2]}${newVersion}`; }
      return line;
    });
    if (updated) { fs.writeFileSync(filePath, newLines.join("\n")); return true; }
  } catch { /* */ }
  return false;
}

function checkAndFixNpmScripts(projectPath: string, actions: FixAction[], dryRun: boolean): void {
  const npmrc = path.join(projectPath, ".npmrc");
  if (fs.existsSync(path.join(projectPath, "package.json")) && !fs.existsSync(npmrc)) {
    const action: FixAction = { description: "Add .npmrc with security-hardened defaults", filePath: ".npmrc", actionType: "patch_config", applied: false, details: "" };
    if (!dryRun) {
      fs.writeFileSync(npmrc, "# Security: prevent lifecycle script execution on install\nignore-scripts=true\n");
      action.applied = true;
    }
    actions.push(action);
  }
}
