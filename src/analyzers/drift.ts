/**
 * SBOM drift detection — diff two SBOMs and compute risk delta.
 */

import { OSVClient, type VulnInfo } from "../apis/osv.js";
import type { Dependency } from "../parsers/dependencies.js";
import { parseSBOM } from "../parsers/sbom.js";

export interface DriftEntry {
  changeType: "added" | "removed" | "upgraded" | "downgraded";
  dep: Dependency;
  oldVersion: string;
  newVersion: string;
  vulns: VulnInfo[];
  riskLevel: string;
}

export interface DriftReport {
  oldName: string;
  newName: string;
  entries: DriftEntry[];
  added: number;
  removed: number;
  upgraded: number;
  downgraded: number;
  newVulns: number;
  totalChanges: number;
  riskDelta: string;
}

function classifyVersionChange(oldVer: string, newVer: string): "upgraded" | "downgraded" {
  const toTuple = (v: string) => (v.match(/\d+/g) ?? ["0"]).map(Number);
  const o = toTuple(oldVer);
  const n = toTuple(newVer);
  for (let i = 0; i < Math.max(o.length, n.length); i++) {
    const a = o[i] ?? 0;
    const b = n[i] ?? 0;
    if (b > a) return "upgraded";
    if (b < a) return "downgraded";
  }
  return "upgraded";
}

function computeRiskLevel(entry: DriftEntry): string {
  if (entry.vulns.some((v) => v.severity === "CRITICAL")) return "CRITICAL";
  if (entry.vulns.some((v) => v.severity === "HIGH")) return "HIGH";
  if (entry.vulns.length > 0) return "MEDIUM";
  if (entry.changeType === "added") return "NEW";
  if (entry.changeType === "downgraded") return "WARN";
  return "OK";
}

export async function analyzeDrift(
  oldSbomPath: string,
  newSbomPath: string,
  checkVulns = true,
): Promise<DriftReport> {
  const oldSbom = parseSBOM(oldSbomPath);
  const newSbom = parseSBOM(newSbomPath);

  const oldMap = new Map(oldSbom.dependencies.map((d) => [`${d.name}|${d.ecosystem}`, d]));
  const newMap = new Map(newSbom.dependencies.map((d) => [`${d.name}|${d.ecosystem}`, d]));

  const entries: DriftEntry[] = [];
  const depsToCheck: Array<{ name: string; version: string; ecosystem: string }> = [];

  for (const [key, newDep] of newMap) {
    const oldDep = oldMap.get(key);
    if (!oldDep) {
      const entry: DriftEntry = {
        changeType: "added",
        dep: newDep,
        oldVersion: "",
        newVersion: newDep.version,
        vulns: [],
        riskLevel: "",
      };
      entries.push(entry);
      if (newDep.version && newDep.ecosystem)
        depsToCheck.push({ name: newDep.name, version: newDep.version, ecosystem: newDep.ecosystem });
    } else if (oldDep.version !== newDep.version) {
      const change = classifyVersionChange(oldDep.version, newDep.version);
      const entry: DriftEntry = {
        changeType: change,
        dep: newDep,
        oldVersion: oldDep.version,
        newVersion: newDep.version,
        vulns: [],
        riskLevel: "",
      };
      entries.push(entry);
      if (newDep.version && newDep.ecosystem)
        depsToCheck.push({ name: newDep.name, version: newDep.version, ecosystem: newDep.ecosystem });
    }
  }

  for (const [key, oldDep] of oldMap) {
    if (!newMap.has(key)) {
      entries.push({
        changeType: "removed",
        dep: oldDep,
        oldVersion: oldDep.version,
        newVersion: "",
        vulns: [],
        riskLevel: "OK",
      });
    }
  }

  let newVulnCount = 0;
  if (checkVulns && depsToCheck.length > 0) {
    const osv = new OSVClient();
    const vulnMap = await osv.queryBatch(depsToCheck);
    for (const entry of entries) {
      if (["added", "upgraded", "downgraded"].includes(entry.changeType)) {
        entry.vulns = vulnMap.get(entry.dep.name) ?? [];
        newVulnCount += entry.vulns.length;
      }
    }
  }

  for (const entry of entries) entry.riskLevel = computeRiskLevel(entry);

  const riskOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, WARN: 3, NEW: 4, OK: 5 };
  entries.sort((a, b) => (riskOrder[a.riskLevel] ?? 99) - (riskOrder[b.riskLevel] ?? 99));

  const added = entries.filter((e) => e.changeType === "added").length;
  const removed = entries.filter((e) => e.changeType === "removed").length;
  const upgraded = entries.filter((e) => e.changeType === "upgraded").length;
  const downgraded = entries.filter((e) => e.changeType === "downgraded").length;

  let riskDelta = "UNCHANGED";
  if (entries.some((e) => e.riskLevel === "CRITICAL")) riskDelta = "CRITICAL INCREASE";
  else if (entries.some((e) => e.riskLevel === "HIGH")) riskDelta = "HIGH INCREASE";
  else if (newVulnCount > 0) riskDelta = "MODERATE INCREASE";
  else if (added > removed) riskDelta = "SLIGHT INCREASE";
  else if (removed > added) riskDelta = "DECREASED";

  return {
    oldName: oldSbom.name,
    newName: newSbom.name,
    entries,
    added,
    removed,
    upgraded,
    downgraded,
    newVulns: newVulnCount,
    totalChanges: added + removed + upgraded + downgraded,
    riskDelta,
  };
}
