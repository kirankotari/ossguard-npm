/**
 * Client for the deps.dev API (dependency metadata, Scorecard, licenses).
 */

const DEPS_DEV_API_BASE = "https://api.deps.dev/v3alpha";

const SYSTEM_MAP: Record<string, string> = {
  npm: "npm",
  pypi: "pypi",
  go: "go",
  "crates.io": "cargo",
  maven: "maven",
  rubygems: "rubygems",
  nuget: "nuget",
  packagist: "packagist",
};

export interface ScorecardResult {
  overallScore: number;
  checks: Record<string, number>;
  date: string;
  repoUrl: string;
}

export interface PackageInfo {
  name: string;
  ecosystem: string;
  latestVersion: string;
  license: string;
  description: string;
  homepage: string;
  repoUrl: string;
  scorecard: ScorecardResult | null;
  isDeprecated: boolean;
  stars: number;
}

function createPackageInfo(partial: Partial<PackageInfo> & { name: string }): PackageInfo {
  return {
    name: partial.name,
    ecosystem: partial.ecosystem ?? "",
    latestVersion: partial.latestVersion ?? "",
    license: partial.license ?? "",
    description: partial.description ?? "",
    homepage: partial.homepage ?? "",
    repoUrl: partial.repoUrl ?? "",
    scorecard: partial.scorecard ?? null,
    isDeprecated: partial.isDeprecated ?? false,
    stars: partial.stars ?? 0,
  };
}

export class DepsDevClient {
  private timeout: number;

  constructor(timeout = 30000) {
    this.timeout = timeout;
  }

  async getPackage(name: string, ecosystem: string): Promise<PackageInfo | null> {
    const system = SYSTEM_MAP[ecosystem];
    if (!system) return null;

    const encodedName = encodeURIComponent(name);
    try {
      const resp = await fetch(
        `${DEPS_DEV_API_BASE}/systems/${system}/packages/${encodedName}`,
        { signal: AbortSignal.timeout(this.timeout) },
      );
      if (!resp.ok) return null;
      const data = (await resp.json()) as Record<string, unknown>;

      const versions = (data.versions as Record<string, unknown>[]) ?? [];
      let latestVersion = "";
      for (let i = versions.length - 1; i >= 0; i--) {
        const vk = (versions[i].versionKey as Record<string, string>) ?? {};
        if (!isPrerelease(vk.version ?? "")) {
          latestVersion = vk.version ?? "";
          break;
        }
      }
      if (!latestVersion && versions.length > 0) {
        const vk = (versions[versions.length - 1].versionKey as Record<string, string>) ?? {};
        latestVersion = vk.version ?? "";
      }

      return createPackageInfo({ name, ecosystem, latestVersion });
    } catch {
      return null;
    }
  }

  async getVersion(
    name: string,
    version: string,
    ecosystem: string,
  ): Promise<PackageInfo | null> {
    const system = SYSTEM_MAP[ecosystem];
    if (!system) return null;

    const encodedName = encodeURIComponent(name);
    const encodedVersion = encodeURIComponent(version);

    try {
      const resp = await fetch(
        `${DEPS_DEV_API_BASE}/systems/${system}/packages/${encodedName}/versions/${encodedVersion}`,
        { signal: AbortSignal.timeout(this.timeout) },
      );
      if (!resp.ok) return null;
      const data = (await resp.json()) as Record<string, unknown>;

      const licenses = (data.licenses as string[]) ?? [];
      const licenseStr = licenses.join(", ");

      const links: Record<string, string> = {};
      for (const lnk of (data.links as Record<string, string>[]) ?? []) {
        links[lnk.label ?? ""] = lnk.url ?? "";
      }

      return createPackageInfo({
        name,
        ecosystem,
        latestVersion: version,
        license: licenseStr,
        homepage: links.HOMEPAGE ?? "",
        repoUrl: links.SOURCE_REPO ?? "",
      });
    } catch {
      return null;
    }
  }

  async getScorecard(repoUrl: string): Promise<ScorecardResult | null> {
    if (!repoUrl) return null;

    const projectId = normalizeRepoUrl(repoUrl);
    if (!projectId) return null;

    try {
      const encodedId = encodeURIComponent(projectId);
      const resp = await fetch(`${DEPS_DEV_API_BASE}/projects/${encodedId}`, {
        signal: AbortSignal.timeout(this.timeout),
      });
      if (!resp.ok) return null;
      const data = (await resp.json()) as Record<string, unknown>;

      const scorecardData =
        (data.scorecardV2 as Record<string, unknown>) ??
        (data.scorecard as Record<string, unknown>) ??
        {};
      if (!scorecardData) return null;

      const overall = (scorecardData.overallScore as number) ?? 0;
      const checks: Record<string, number> = {};
      for (const check of (scorecardData.checks as Record<string, unknown>[]) ??
        (scorecardData.check as Record<string, unknown>[]) ??
        []) {
        const checkName = (check.name as string) ?? "";
        const checkScore = (check.score as number) ?? 0;
        if (checkName) checks[checkName] = checkScore;
      }

      return {
        overallScore: overall,
        checks,
        date: (scorecardData.date as string) ?? "",
        repoUrl,
      };
    } catch {
      return null;
    }
  }

  async getPackageBatch(
    packages: Array<{ name: string; version: string; ecosystem: string }>,
  ): Promise<Map<string, PackageInfo>> {
    const results = new Map<string, PackageInfo>();
    for (const { name, version, ecosystem } of packages) {
      const info = version
        ? await this.getVersion(name, version, ecosystem)
        : await this.getPackage(name, ecosystem);
      if (info) results.set(name, info);
    }
    return results;
  }
}

function normalizeRepoUrl(url: string): string {
  let u = url.replace(/\/+$/, "");
  for (const prefix of ["https://", "http://", "git://", "ssh://git@"]) {
    if (u.startsWith(prefix)) {
      u = u.slice(prefix.length);
      break;
    }
  }
  if (u.endsWith(".git")) u = u.slice(0, -4);

  const parts = u.split("/");
  if (
    parts.length >= 3 &&
    ["github.com", "gitlab.com", "bitbucket.org"].includes(parts[0])
  ) {
    return `${parts[0]}/${parts[1]}/${parts[2]}`;
  }
  return "";
}

function isPrerelease(version: string): boolean {
  const markers = ["alpha", "beta", "rc", "dev", "pre", "snapshot", "canary", "nightly"];
  const v = version.toLowerCase();
  return markers.some((m) => v.includes(m));
}
