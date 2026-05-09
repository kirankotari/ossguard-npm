/**
 * ossguard CLI — One command to guard any OSS project with OpenSSF security best practices.
 */

import { Command } from "commander";
import { VERSION } from "./index.js";
import { detectProject } from "./detector.js";
import { parseDependencies } from "./parsers/dependencies.js";
import { runAudit } from "./analyzers/audit.js";
import { autoFix } from "./analyzers/fix.js";
import { assessBadgeReadiness } from "./analyzers/badge.js";
import { generateCiPipeline } from "./analyzers/ci.js";
import { generateReport } from "./analyzers/report.js";
import { checkPolicy } from "./analyzers/policy.js";
import { checkLicenses } from "./analyzers/license-check.js";
import { checkBaseline } from "./analyzers/baseline.js";
import { generateInsights, validateInsights } from "./analyzers/insights.js";
import { scanActions, pinActions } from "./analyzers/pin.js";
import { scanSecrets } from "./analyzers/secrets.js";
import { checkSlsa } from "./analyzers/slsa.js";
import { generateSbom } from "./analyzers/sbom-gen.js";
import { checkSupplyChain } from "./analyzers/supply-chain.js";
import { scanContainers } from "./analyzers/container.js";
import { compareProjects } from "./analyzers/compare.js";
import { checkUpdates } from "./analyzers/update.js";
import { assessMaturity } from "./analyzers/maturity.js";
import { checkFuzzReadiness } from "./analyzers/fuzz.js";
import { analyzeDependencies } from "./analyzers/dep-health.js";
import { analyzeDrift } from "./analyzers/drift.js";
import { generateTpn, tpnToText } from "./analyzers/tpn.js";
import { analyzeReachability } from "./analyzers/reach.js";
import {
  generateSecurityMd, generateScorecardWorkflow, generateDependabotConfig,
  generateCodeqlWorkflow, generateSbomWorkflow, generateSigstoreWorkflow,
} from "./generators/index.js";

const program = new Command();

program
  .name("ossguard")
  .description("One CLI to guard any OSS project with OpenSSF security best practices")
  .version(VERSION);

function getPath(cmd: Command): string {
  return cmd.optsWithGlobals().path || ".";
}

function isJson(cmd: Command): boolean {
  return cmd.optsWithGlobals().json === true;
}

function jsonOut(cmd: Command, data: unknown): void {
  if (isJson(cmd)) {
    process.stdout.write(JSON.stringify(data, null, 2) + "\n");
  }
}

program.option("-p, --path <path>", "Project path", ".");
program.option("-j, --json", "Output as JSON");

// --- version ---
program.command("version").description("Show version").action(() => {
  process.stdout.write(`ossguard ${VERSION}\n`);
});

// --- init ---
program.command("init").description("Bootstrap security configs for a project").action((_opts: unknown, cmd: Command) => {
  const p = getPath(cmd);
  const info = detectProject(p);
  process.stdout.write(`Initializing security configs for ${info.repoName}...\n`);
  const generated: Record<string, string | null> = {
    "SECURITY.md": generateSecurityMd(info.repoName),
    "scorecard.yml": generateScorecardWorkflow(),
    "dependabot.yml": generateDependabotConfig(info.packageManagers),
    "codeql.yml": generateCodeqlWorkflow(info.languages),
    "sbom.yml": generateSbomWorkflow(),
    "sigstore.yml": generateSigstoreWorkflow(info.primaryLanguage),
  };
  if (isJson(cmd)) { jsonOut(cmd, generated); return; }
  for (const file of Object.keys(generated)) {
    process.stdout.write(`  ✓ ${file}\n`);
  }
});

// --- scan ---
program.command("scan").description("Quick security configuration scan").action((_opts: unknown, cmd: Command) => {
  const p = getPath(cmd);
  const info = detectProject(p);
  if (isJson(cmd)) { jsonOut(cmd, info); return; }
  process.stdout.write(`Project: ${info.repoName}\nLanguage: ${info.primaryLanguage}\n`);
  const checks: [string, boolean][] = [
    ["SECURITY.md", info.hasSecurityMd], ["Scorecard", info.hasScorecard],
    ["Dependabot", info.hasDependabot], ["CodeQL", info.hasCodeql],
    ["SBOM workflow", info.hasSbomWorkflow], ["Sigstore", info.hasSigstore],
  ];
  for (const [name, ok] of checks) {
    process.stdout.write(`  ${ok ? "✓" : "✗"} ${name}\n`);
  }
});

// --- audit ---
program.command("audit").description("Comprehensive security audit").action(async (_opts: unknown, cmd: Command) => {
  const report = await runAudit(getPath(cmd));
  if (isJson(cmd)) { jsonOut(cmd, report); return; }
  const name = report.projectInfo?.repoName ?? "unknown";
  process.stdout.write(`Audit: ${name} — Grade: ${report.overallGrade} (${report.configScore}/${report.configTotal} config checks)\n`);
  for (const f of report.findings) process.stdout.write(`  ⚠ ${f}\n`);
  for (const r of report.recommendations) process.stdout.write(`  → ${r}\n`);
});

// --- deps ---
program.command("deps").description("Analyze dependency health and vulnerabilities").action(async (_opts: unknown, cmd: Command) => {
  const deps = parseDependencies(getPath(cmd));
  const report = await analyzeDependencies(deps);
  if (isJson(cmd)) { jsonOut(cmd, report); return; }
  process.stdout.write(`Dependencies: ${report.totalDeps} total, ${report.totalVulns} vulnerable\n`);
});

// --- drift ---
program.command("drift").description("Detect dependency drift from lock files")
  .option("--old <path>", "Old SBOM path")
  .option("--new <path>", "New SBOM path")
  .action(async (opts: { old?: string; new?: string }, cmd: Command) => {
    if (!opts.old || !opts.new) { process.stdout.write("Usage: ossguard drift --old <sbom1> --new <sbom2>\n"); return; }
    const report = await analyzeDrift(opts.old, opts.new);
    if (isJson(cmd)) { jsonOut(cmd, report); return; }
    process.stdout.write(`Drift: ${report.entries.length} changes detected\n`);
  });

// --- watch ---
program.command("watch").description("Monitor dependencies for new vulnerabilities").action(async (_opts: unknown, cmd: Command) => {
  const deps = parseDependencies(getPath(cmd));
  const report = await analyzeDependencies(deps);
  if (isJson(cmd)) { jsonOut(cmd, report); return; }
  process.stdout.write(`Watching ${report.totalDeps} deps — ${report.totalVulns} known vulns\n`);
});

// --- tpn ---
program.command("tpn").description("Generate third-party notices").action(async (_opts: unknown, cmd: Command) => {
  const p = getPath(cmd);
  const deps = parseDependencies(p);
  const info = detectProject(p);
  const report = await generateTpn(deps, info.repoName);
  if (isJson(cmd)) { jsonOut(cmd, report); return; }
  process.stdout.write(tpnToText(report) + "\n");
});

// --- reach ---
program.command("reach").description("Reachability-filtered vulnerability analysis").action(async (_opts: unknown, cmd: Command) => {
  const p = getPath(cmd);
  const deps = parseDependencies(p);
  const report = await analyzeReachability(deps, p);
  if (isJson(cmd)) { jsonOut(cmd, report); return; }
  process.stdout.write(`Reachability: ${report.reachableDeps} reachable, ${report.totalDeps - report.reachableDeps} unreachable of ${report.totalDeps} deps\n`);
});

// --- fix ---
program.command("fix").description("Auto-remediate common security issues")
  .option("--dry-run", "Preview changes without applying")
  .action(async (opts: { dryRun?: boolean }, cmd: Command) => {
    const report = await autoFix(getPath(cmd), opts.dryRun);
    if (isJson(cmd)) { jsonOut(cmd, report); return; }
    for (const a of report.actions) process.stdout.write(`  ${a.applied ? "✓" : "–"} ${a.description}\n`);
    process.stdout.write(`\nApplied ${report.appliedCount}/${report.actions.length}\n`);
  });

// --- badge ---
program.command("badge").description("OpenSSF Best Practices Badge readiness").action((_opts: unknown, cmd: Command) => {
  const report = assessBadgeReadiness(getPath(cmd));
  if (isJson(cmd)) { jsonOut(cmd, report); return; }
  const pct = report.totalCount > 0 ? ((report.metCount / report.totalCount) * 100).toFixed(0) : "0";
  process.stdout.write(`Badge: ${report.passingLevel} (${pct}% — ${report.metCount}/${report.totalCount})\n`);
});

// --- ci ---
program.command("ci").description("Generate unified security CI pipeline").action((_opts: unknown, cmd: Command) => {
  const content = generateCiPipeline(getPath(cmd));
  if (isJson(cmd)) { jsonOut(cmd, { content }); return; }
  process.stdout.write(content + "\n");
});

// --- report ---
program.command("report").description("Export HTML/JSON compliance report")
  .option("--format <format>", "Output format: html or json", "html")
  .action(async (opts: { format: "html" | "json" }, cmd: Command) => {
    const audit = await runAudit(getPath(cmd));
    process.stdout.write(generateReport(audit, opts.format) + "\n");
  });

// --- policy ---
program.command("policy").description("Organization-wide security policy enforcement").action((_opts: unknown, cmd: Command) => {
  const report = checkPolicy(getPath(cmd));
  if (isJson(cmd)) { jsonOut(cmd, report); return; }
  process.stdout.write(`Policy: ${report.passedCount}/${report.passedCount + report.failedCount} passed — compliant: ${report.compliant}\n`);
});

// --- license ---
program.command("license").description("License compliance checking").action(async (_opts: unknown, cmd: Command) => {
  const deps = parseDependencies(getPath(cmd));
  const report = await checkLicenses(deps);
  if (isJson(cmd)) { jsonOut(cmd, report); return; }
  process.stdout.write(`Licenses: ${report.licenses.length} deps, ${report.unknownCount} unknown, ${report.conflicts.length} conflicts\n`);
});

// --- baseline ---
program.command("baseline").description("OSPS Baseline compliance").action((_opts: unknown, cmd: Command) => {
  const report = checkBaseline(getPath(cmd));
  if (isJson(cmd)) { jsonOut(cmd, report); return; }
  process.stdout.write(`Baseline Level ${report.achievedLevel} — L1: ${report.level1Pct.toFixed(0)}%, L2: ${report.level2Pct.toFixed(0)}%, L3: ${report.level3Pct.toFixed(0)}%\n`);
});

// --- insights ---
program.command("insights").description("Generate/validate SECURITY-INSIGHTS.yml")
  .option("--validate", "Validate existing file")
  .action((opts: { validate?: boolean }, cmd: Command) => {
    if (opts.validate) {
      const report = validateInsights(getPath(cmd));
      if (isJson(cmd)) { jsonOut(cmd, report); return; }
      if (report.valid) process.stdout.write("SECURITY-INSIGHTS.yml is valid\n");
      else process.stdout.write(`Validation errors: ${report.errors.join(", ")}\n`);
    } else {
      const content = generateInsights(getPath(cmd));
      process.stdout.write(content + "\n");
    }
  });

// --- pin ---
program.command("pin").description("Pin GitHub Actions to commit SHAs")
  .option("--apply", "Apply pinning changes")
  .action(async (opts: { apply?: boolean }, cmd: Command) => {
    const report = opts.apply ? await pinActions(getPath(cmd)) : scanActions(getPath(cmd));
    if (isJson(cmd)) { jsonOut(cmd, report); return; }
    process.stdout.write(`Actions: ${report.totalRefs} total, ${report.alreadyPinnedCount} pinned, ${report.totalRefs - report.alreadyPinnedCount} unpinned\n`);
  });

// --- secrets ---
program.command("secrets").description("Scan for leaked credentials and secrets").action((_opts: unknown, cmd: Command) => {
  const report = scanSecrets(getPath(cmd));
  if (isJson(cmd)) { jsonOut(cmd, report); return; }
  process.stdout.write(`Secrets scan: ${report.filesScanned} files, ${report.findings.length} findings\n`);
  for (const f of report.findings) process.stdout.write(`  ${f.file}:${f.lineNumber} [${f.severity}] ${f.ruleId}\n`);
});

// --- slsa ---
program.command("slsa").description("SLSA provenance level assessment").action((_opts: unknown, cmd: Command) => {
  const report = checkSlsa(getPath(cmd));
  if (isJson(cmd)) { jsonOut(cmd, report); return; }
  process.stdout.write(`${report.levelLabel} — ${report.metCount}/${report.totalCount} met\n`);
});

// --- sbom-gen ---
program.command("sbom-gen").description("Generate SPDX or CycloneDX SBOMs")
  .option("--format <format>", "SBOM format: spdx or cyclonedx", "spdx")
  .action((opts: { format: "spdx" | "cyclonedx" }, cmd: Command) => {
    process.stdout.write(generateSbom(getPath(cmd), opts.format) + "\n");
  });

// --- supply-chain ---
program.command("supply-chain").description("Malicious package and typosquatting detection").action(async (_opts: unknown, cmd: Command) => {
  const report = await checkSupplyChain(getPath(cmd));
  if (isJson(cmd)) { jsonOut(cmd, report); return; }
  process.stdout.write(`Supply chain: ${report.totalDeps} deps, ${report.maliciousCount} malicious, ${report.typosquatCount} typosquat, clean: ${report.clean}\n`);
});

// --- container ---
program.command("container").description("Dockerfile security linting").action((_opts: unknown, cmd: Command) => {
  const report = scanContainers(getPath(cmd));
  if (isJson(cmd)) { jsonOut(cmd, report); return; }
  process.stdout.write(`Container scan: ${report.filesScanned} files, ${report.findings.length} findings\n`);
});

// --- compare ---
program.command("compare").description("Compare security posture of two projects")
  .argument("<pathA>", "First project path")
  .argument("<pathB>", "Second project path")
  .action(async (pathA: string, pathB: string, cmd: Command) => {
    const report = await compareProjects(pathA, pathB);
    if (isJson(cmd)) { jsonOut(cmd, report); return; }
    const a = report.auditA?.projectInfo?.repoName ?? "A";
    const b = report.auditB?.projectInfo?.repoName ?? "B";
    process.stdout.write(`${a} (${report.auditA?.overallGrade}) vs ${b} (${report.auditB?.overallGrade}) — winner: ${report.winner}\n`);
  });

// --- update ---
program.command("update").description("Security-prioritized dependency updates")
  .option("--security-only", "Show only security updates")
  .action(async (opts: { securityOnly?: boolean }, cmd: Command) => {
    const report = await checkUpdates(getPath(cmd), opts.securityOnly);
    if (isJson(cmd)) { jsonOut(cmd, report); return; }
    process.stdout.write(`Updates: ${report.totalUpdates} available, ${report.securityUpdates} security, ${report.upToDate} up-to-date\n`);
  });

// --- maturity ---
program.command("maturity").description("S2C2F maturity assessment").action((_opts: unknown, cmd: Command) => {
  const report = assessMaturity(getPath(cmd));
  if (isJson(cmd)) { jsonOut(cmd, report); return; }
  process.stdout.write(`S2C2F Level ${report.achievedLevel} — L1: ${report.level1Pct.toFixed(0)}%, L2: ${report.level2Pct.toFixed(0)}%, L3: ${report.level3Pct.toFixed(0)}%, L4: ${report.level4Pct.toFixed(0)}%\n`);
});

// --- fuzz ---
program.command("fuzz").description("Fuzzing readiness check").action((_opts: unknown, cmd: Command) => {
  const report = checkFuzzReadiness(getPath(cmd));
  if (isJson(cmd)) { jsonOut(cmd, report); return; }
  process.stdout.write(`Fuzz: ${report.language}, framework: ${report.framework || "none"}, score: ${report.readinessScore}/100\n`);
  for (const f of report.findings) process.stdout.write(`  [${f.category}] ${f.description}\n`);
});

program.parse();
