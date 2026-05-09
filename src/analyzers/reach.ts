/**
 * Reachability analysis — filter vulnerabilities by actual import/usage.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { OSVClient, type VulnInfo } from "../apis/osv.js";
import type { Dependency } from "../parsers/dependencies.js";

export interface ReachResult {
  dep: Dependency;
  isReachable: boolean;
  importLocations: string[];
  vulns: VulnInfo[];
  vulnCount: number;
}

export interface ReachReport {
  results: ReachResult[];
  totalDeps: number;
  reachableDeps: number;
  totalVulns: number;
  reachableVulns: number;
  filteredVulns: number;
  noiseReductionPct: number;
}

const SKIP_DIRS = new Set(["node_modules", ".git", "__pycache__", "venv", ".venv", "env", "dist", "build", ".tox", ".mypy_cache", "target", "vendor"]);

const IMPORT_PATTERNS: Record<string, RegExp[]> = {
  ".py": [/^import\s+(\w+)/, /^from\s+(\w+)/],
  ".js": [/require\s*\(\s*['"]([^'"./][^'"]*)['"]\s*\)/, /from\s+['"]([^'"./][^'"]*)['"]\s*/, /import\s+['"]([^'"./][^'"]*)['"]\s*/],
  ".ts": [/from\s+['"]([^'"./][^'"]*)['"]\s*/, /import\s+['"]([^'"./][^'"]*)['"]\s*/],
  ".go": [/"([a-zA-Z0-9._/-]+)"/],
  ".rs": [/^use\s+(\w+)/, /^extern\s+crate\s+(\w+)/],
  ".rb": [/^require\s+['"]([^'"]+)['"]/, /^gem\s+['"]([^'"]+)['"]/],
  ".java": [/^import\s+(?:static\s+)?([a-zA-Z0-9_.]+)/],
};
IMPORT_PATTERNS[".tsx"] = IMPORT_PATTERNS[".ts"];
IMPORT_PATTERNS[".jsx"] = IMPORT_PATTERNS[".js"];
IMPORT_PATTERNS[".mjs"] = IMPORT_PATTERNS[".js"];

function normalizeImportName(name: string, ext: string): string {
  if (!name) return "";
  if (ext === ".py") return name.split(".")[0].replace(/_/g, "-");
  if ([".js", ".ts", ".tsx", ".jsx", ".mjs"].includes(ext)) {
    if (name.startsWith("@")) { const p = name.split("/"); return p.length >= 2 ? `${p[0]}/${p[1]}` : name; }
    return name.split("/")[0];
  }
  if (ext === ".go") return name;
  if (ext === ".rs") return name.replace(/_/g, "-");
  return name.split(".")[0];
}

function* walkFiles(root: string, skip: Set<string>): Generator<string> {
  try {
    for (const item of fs.readdirSync(root, { withFileTypes: true })) {
      const full = path.join(root, item.name);
      if (item.isDirectory() && !skip.has(item.name)) yield* walkFiles(full, skip);
      else if (item.isFile()) yield full;
    }
  } catch { /* permission errors */ }
}

function scanImports(projectPath: string): Map<string, string[]> {
  const imports = new Map<string, string[]>();
  for (const filePath of walkFiles(projectPath, SKIP_DIRS)) {
    const ext = path.extname(filePath).toLowerCase();
    const patterns = IMPORT_PATTERNS[ext];
    if (!patterns) continue;
    try {
      const content = fs.readFileSync(filePath, "utf-8");
      for (const line of content.split("\n")) {
        const stripped = line.trim();
        for (const pattern of patterns) {
          const match = pattern.exec(stripped);
          if (match) {
            const pkgName = normalizeImportName(match[1], ext);
            if (pkgName) {
              const relPath = path.relative(projectPath, filePath);
              const list = imports.get(pkgName) ?? [];
              if (!list.includes(relPath)) list.push(relPath);
              imports.set(pkgName, list);
            }
          }
        }
      }
    } catch { continue; }
  }
  return imports;
}

function isDepImported(dep: Dependency, imports: Map<string, string[]>): boolean {
  const name = dep.name.toLowerCase();
  const keys = [...imports.keys()].map((k) => k.toLowerCase());
  if (keys.includes(name)) return true;
  if (keys.includes(name.replace(/-/g, "_"))) return true;
  if (keys.includes(name.replace(/_/g, "-"))) return true;
  return false;
}

function findImportLocations(dep: Dependency, imports: Map<string, string[]>): string[] {
  const name = dep.name.toLowerCase();
  for (const [key, locs] of imports) {
    if (key.toLowerCase() === name || key.toLowerCase().replace(/-/g, "_") === name.replace(/-/g, "_")) return locs;
  }
  return [];
}

export async function analyzeReachability(deps: Dependency[], projectPath: string): Promise<ReachReport> {
  const resolved = path.resolve(projectPath);
  const importedPackages = scanImports(resolved);
  const nonDev = deps.filter((d) => !d.isDev);

  const reachable: Array<[Dependency, string[]]> = [];
  const unreachable: Dependency[] = [];

  for (const dep of nonDev) {
    if (isDepImported(dep, importedPackages)) {
      reachable.push([dep, findImportLocations(dep, importedPackages)]);
    } else {
      unreachable.push(dep);
    }
  }

  const osv = new OSVClient();
  const vulnMap = await osv.queryBatch(nonDev.map((d) => ({ name: d.name, version: d.version, ecosystem: d.ecosystem })));

  const results: ReachResult[] = [];
  let totalVulns = 0;
  let reachableVulns = 0;

  for (const [dep, locations] of reachable) {
    const vulns = vulnMap.get(dep.name) ?? [];
    totalVulns += vulns.length;
    reachableVulns += vulns.length;
    results.push({ dep, isReachable: true, importLocations: locations, vulns, vulnCount: vulns.length });
  }
  for (const dep of unreachable) {
    const vulns = vulnMap.get(dep.name) ?? [];
    totalVulns += vulns.length;
    results.push({ dep, isReachable: false, importLocations: [], vulns, vulnCount: vulns.length });
  }

  results.sort((a, b) => (a.isReachable === b.isReachable ? b.vulnCount - a.vulnCount : a.isReachable ? -1 : 1));

  const filteredVulns = totalVulns - reachableVulns;
  return {
    results,
    totalDeps: nonDev.length,
    reachableDeps: reachable.length,
    totalVulns,
    reachableVulns,
    filteredVulns,
    noiseReductionPct: totalVulns > 0 ? Math.round((filteredVulns / totalVulns) * 1000) / 10 : 0,
  };
}
