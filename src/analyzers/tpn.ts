/**
 * Third-party notice generation from dependencies or SBOMs.
 */

import { DepsDevClient } from "../apis/deps-dev.js";
import type { Dependency } from "../parsers/dependencies.js";

export interface ThirdPartyEntry {
  name: string;
  version: string;
  license: string;
  homepage: string;
  repoUrl: string;
  ecosystem: string;
}

export interface TPNReport {
  projectName: string;
  entries: ThirdPartyEntry[];
  unknownLicenses: string[];
  conflicts: string[];
}

const COPYLEFT_LICENSES = new Set(["GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.1", "LGPL-3.0", "MPL-2.0"]);
const PERMISSIVE_LICENSES = new Set(["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD"]);

export function tpnToText(report: TPNReport): string {
  const lines = [
    "THIRD-PARTY SOFTWARE NOTICES AND INFORMATION",
    `Project: ${report.projectName}`,
    "",
    "This project incorporates components from the projects listed below.",
    "=".repeat(72),
    "",
  ];
  const sorted = [...report.entries].sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()));
  sorted.forEach((e, i) => {
    lines.push(`${i + 1}. ${e.name} (${e.version})`);
    lines.push(`   License: ${e.license || "UNKNOWN"}`);
    if (e.homepage) lines.push(`   Homepage: ${e.homepage}`);
    if (e.repoUrl) lines.push(`   Source: ${e.repoUrl}`);
    lines.push("");
  });
  if (report.unknownLicenses.length > 0) {
    lines.push("=".repeat(72), "WARNING: The following packages have unknown licenses:");
    for (const n of report.unknownLicenses) lines.push(`  - ${n}`);
    lines.push("");
  }
  if (report.conflicts.length > 0) {
    lines.push("=".repeat(72), "WARNING: Potential license conflicts detected:");
    for (const c of report.conflicts) lines.push(`  - ${c}`);
    lines.push("");
  }
  return lines.join("\n");
}

export function tpnToHtml(report: TPNReport): string {
  const sorted = [...report.entries].sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()));
  const rows = sorted.map((e) => {
    const link = e.homepage ? `<a href="${e.homepage}">${e.homepage}</a>` : e.repoUrl ? `<a href="${e.repoUrl}">${e.repoUrl}</a>` : "";
    return `<tr><td><strong>${e.name}</strong></td><td>${e.version}</td><td>${e.license || '<span style="color:red">UNKNOWN</span>'}</td><td>${link}</td></tr>`;
  }).join("\n");

  return `<!DOCTYPE html><html><head><title>Third-Party Notices — ${report.projectName}</title>
<style>body{font-family:sans-serif;max-width:960px;margin:2rem auto}table{width:100%;border-collapse:collapse}th,td{border:1px solid #ddd;padding:8px;text-align:left}th{background:#f5f5f5}</style>
</head><body><h1>Third-Party Notices</h1><p>Project: <strong>${report.projectName}</strong></p>
<table><thead><tr><th>Package</th><th>Version</th><th>License</th><th>Link</th></tr></thead><tbody>${rows}</tbody></table></body></html>`;
}

export async function generateTpn(deps: Dependency[], projectName = ""): Promise<TPNReport> {
  const entries: ThirdPartyEntry[] = [];
  const unknown: string[] = [];
  const foundLicenses: Record<string, string> = {};

  const client = new DepsDevClient();
  for (const dep of deps) {
    if (dep.isDev) continue;
    let info = dep.version ? await client.getVersion(dep.name, dep.version, dep.ecosystem) : null;
    if (!info) info = await client.getPackage(dep.name, dep.ecosystem);

    const license = info?.license ?? "";
    entries.push({ name: dep.name, version: dep.version, license, homepage: info?.homepage ?? "", repoUrl: info?.repoUrl ?? "", ecosystem: dep.ecosystem });
    if (!license) unknown.push(dep.name);
    else foundLicenses[dep.name] = license;
  }

  return { projectName, entries, unknownLicenses: unknown, conflicts: detectConflicts(foundLicenses) };
}

function detectConflicts(licenses: Record<string, string>): string[] {
  const conflicts: string[] = [];
  const hasCopyleft: Array<[string, string]> = [];
  const hasPermissive: Array<[string, string]> = [];

  for (const [name, lic] of Object.entries(licenses)) {
    const upper = lic.toUpperCase().trim();
    for (const c of COPYLEFT_LICENSES) { if (upper.includes(c.toUpperCase())) { hasCopyleft.push([name, lic]); break; } }
    for (const p of PERMISSIVE_LICENSES) { if (upper.includes(p.toUpperCase())) { hasPermissive.push([name, lic]); break; } }
  }

  if (hasCopyleft.length > 0 && hasPermissive.length > 0) {
    const names = hasCopyleft.slice(0, 3).map(([n, l]) => `${n} (${l})`).join(", ");
    conflicts.push(`Copyleft licenses detected alongside permissive: ${names}. Review compatibility with your project license.`);
  }
  return conflicts;
}
