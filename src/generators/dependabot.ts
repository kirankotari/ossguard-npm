/**
 * Generate Dependabot configuration for automated dependency updates.
 */

const ECOSYSTEM_MAP: Record<string, string> = {
  npm: "npm",
  yarn: "npm",
  pnpm: "npm",
  pip: "pip",
  pipenv: "pip",
  poetry: "pip",
  "go-modules": "gomod",
  cargo: "cargo",
  bundler: "bundler",
  maven: "maven",
  gradle: "gradle",
  composer: "composer",
  pub: "pub",
};

export function generateDependabotConfig(packageManagers: string[]): string {
  const ecosystems = new Set<string>();
  for (const pm of packageManagers) {
    const eco = ECOSYSTEM_MAP[pm];
    if (eco) ecosystems.add(eco);
  }
  // Always include github-actions
  ecosystems.add("github-actions");

  const entries = [...ecosystems].sort().map(
    (eco) => `  - package-ecosystem: "${eco}"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    labels:
      - "dependencies"
      - "security"`,
  );

  return `# Dependabot configuration
# https://docs.github.com/en/code-security/dependabot/dependabot-version-updates
# Keeps your dependencies up to date and patches known vulnerabilities.

version: 2

updates:
${entries.join("\n\n")}
`;
}
