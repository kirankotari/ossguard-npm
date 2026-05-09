/**
 * Client for the OSV (Open Source Vulnerabilities) API.
 */

const OSV_API_BASE = "https://api.osv.dev/v1";

const ECOSYSTEM_MAP: Record<string, string> = {
  npm: "npm",
  pypi: "PyPI",
  go: "Go",
  "crates.io": "crates.io",
  maven: "Maven",
  rubygems: "RubyGems",
  nuget: "NuGet",
  packagist: "Packagist",
  pub: "Pub",
};

export interface VulnInfo {
  id: string;
  summary: string;
  severity: string; // CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
  aliases: string[];
  fixedVersion: string;
  url: string;
}

export class OSVClient {
  private timeout: number;

  constructor(timeout = 30000) {
    this.timeout = timeout;
  }

  async query(name: string, version: string, ecosystem: string): Promise<VulnInfo[]> {
    const osvEcosystem = ECOSYSTEM_MAP[ecosystem] ?? ecosystem;
    if (!osvEcosystem) return [];

    const payload: Record<string, unknown> = {
      package: { name, ecosystem: osvEcosystem },
    };
    if (version) payload.version = version;

    try {
      const resp = await fetch(`${OSV_API_BASE}/query`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(this.timeout),
      });
      if (!resp.ok) return [];
      const data = (await resp.json()) as Record<string, unknown>;
      return parseVulns((data.vulns as Record<string, unknown>[]) ?? []);
    } catch {
      return [];
    }
  }

  async queryBatch(
    packages: Array<{ name: string; version: string; ecosystem: string }>,
  ): Promise<Map<string, VulnInfo[]>> {
    const queries = packages.map(({ name, version, ecosystem }) => {
      const osvEcosystem = ECOSYSTEM_MAP[ecosystem] ?? ecosystem;
      if (!osvEcosystem) return {};
      const q: Record<string, unknown> = {
        package: { name, ecosystem: osvEcosystem },
      };
      if (version) q.version = version;
      return q;
    });

    if (queries.length === 0) return new Map();

    try {
      const resp = await fetch(`${OSV_API_BASE}/querybatch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ queries }),
        signal: AbortSignal.timeout(this.timeout),
      });
      if (!resp.ok) return new Map();
      const data = (await resp.json()) as Record<string, unknown>;
      const results = new Map<string, VulnInfo[]>();

      for (const [i, result] of ((data.results as Record<string, unknown>[]) ?? []).entries()) {
        const name = packages[i].name;
        const vulns = parseVulns((result.vulns as Record<string, unknown>[]) ?? []);
        if (vulns.length > 0) results.set(name, vulns);
      }
      return results;
    } catch {
      return new Map();
    }
  }
}

function parseVulns(vulns: Record<string, unknown>[]): VulnInfo[] {
  return vulns.map((v) => ({
    id: (v.id as string) ?? "",
    summary: ((v.summary as string) ?? "").slice(0, 120),
    severity: extractSeverity(v),
    aliases: (v.aliases as string[]) ?? [],
    fixedVersion: extractFixedVersion(v),
    url: `https://osv.dev/vulnerability/${(v.id as string) ?? ""}`,
  }));
}

function extractSeverity(vuln: Record<string, unknown>): string {
  for (const sev of (vuln.severity as Record<string, string>[]) ?? []) {
    const scoreStr = sev.score ?? "";
    if (scoreStr) {
      const score = parseFloat(scoreStr);
      if (!isNaN(score)) {
        if (score >= 9.0) return "CRITICAL";
        if (score >= 7.0) return "HIGH";
        if (score >= 4.0) return "MEDIUM";
        return "LOW";
      }
    }
  }

  const dbSpecific = (vuln.database_specific as Record<string, unknown>) ?? {};
  const severity = dbSpecific.severity;
  if (
    typeof severity === "string" &&
    ["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(severity.toUpperCase())
  ) {
    return severity.toUpperCase();
  }

  return "UNKNOWN";
}

function extractFixedVersion(vuln: Record<string, unknown>): string {
  for (const affected of (vuln.affected as Record<string, unknown>[]) ?? []) {
    for (const rng of (affected.ranges as Record<string, unknown>[]) ?? []) {
      for (const event of (rng.events as Record<string, string>[]) ?? []) {
        if (event.fixed) return event.fixed;
      }
    }
  }
  return "";
}
