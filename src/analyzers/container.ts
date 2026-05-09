/**
 * Dockerfile security linting — detect insecure patterns in container builds.
 */

import * as fs from "node:fs";
import * as path from "node:path";

export interface ContainerFinding {
  file: string;
  lineNumber: number;
  ruleId: string;
  severity: string;
  description: string;
  recommendation: string;
}

export interface ContainerReport {
  findings: ContainerFinding[];
  filesScanned: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  clean: boolean;
}

const RULES: Array<[string, string, string | null, string, string]> = [
  ["DL-001", "high", "^FROM\\s+\\S+:latest\\b", "Using ':latest' tag — image not pinned to specific version", "Pin base image to a specific version or SHA digest"],
  ["DL-002", "medium", "^FROM\\s+\\S+\\s*$", "FROM without tag — image defaults to :latest", "Specify a version tag (e.g., FROM python:3.12-slim)"],
  ["DL-010", "high", "^\\s*USER\\s+root\\s*$", "Container runs as root user", "Use a non-root user: USER nonroot or USER 1000"],
  ["DL-020", "critical", "(?:ARG|ENV)\\s+\\w*(?:SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY)\\w*\\s*=", "Secret value hardcoded in build argument or environment variable", "Use Docker secrets or mount secrets at runtime"],
  ["DL-021", "high", "(?:ARG|ENV)\\s+\\w*(?:AWS_ACCESS|AWS_SECRET|DATABASE_URL|REDIS_URL)\\w*\\s*=", "Cloud credentials or connection string in Dockerfile", "Pass credentials at runtime via environment variables or secrets manager"],
  ["DL-030", "medium", "RUN\\s+.*apt-get\\s+.*install.*(?!--no-install-recommends)", "apt-get install without --no-install-recommends", "Use --no-install-recommends to minimize attack surface"],
  ["DL-031", "medium", "RUN\\s+.*pip\\s+install\\s+(?!.*--no-cache-dir)", "pip install without --no-cache-dir", "Use --no-cache-dir to avoid caching packages in the image"],
  ["DL-032", "high", "RUN\\s+.*curl\\s+.*\\|\\s*(?:sh|bash)", "Piping curl output to shell — insecure remote code execution", "Download scripts first, verify checksums, then execute"],
  ["DL-033", "high", "RUN\\s+.*wget\\s+.*\\|\\s*(?:sh|bash)", "Piping wget output to shell — insecure remote code execution", "Download scripts first, verify checksums, then execute"],
  ["DL-034", "medium", "RUN\\s+.*chmod\\s+777\\b", "Setting world-writable permissions (777)", "Use least-privilege permissions (e.g., 755 or 644)"],
  ["DL-040", "medium", "^\\s*ADD\\s+(?!https?://)\\S", "Using ADD for local files — COPY is preferred", "Use COPY instead of ADD for local files"],
  ["DL-050", "low", null, "No HEALTHCHECK instruction found", "Add HEALTHCHECK to enable container health monitoring"],
  ["DL-060", "medium", null, "No .dockerignore file found", "Create .dockerignore to exclude .git, node_modules, secrets, etc."],
];

export function scanContainers(projectPath: string): ContainerReport {
  const resolved = path.resolve(projectPath);
  const findings: ContainerFinding[] = [];
  let filesScanned = 0;

  const dockerfiles = findDockerfiles(resolved);
  for (const df of dockerfiles) {
    filesScanned++;
    const rel = path.relative(resolved, df);
    const content = fs.readFileSync(df, "utf-8");
    const lines = content.split("\n");

    for (const [ruleId, severity, pattern, desc, rec] of RULES) {
      if (!pattern) continue;
      const re = new RegExp(pattern, "i");
      for (let i = 0; i < lines.length; i++) {
        if (re.test(lines[i])) findings.push({ file: rel, lineNumber: i + 1, ruleId, severity, description: desc, recommendation: rec });
      }
    }

    if (!/^\s*HEALTHCHECK\b/m.test(content)) findings.push({ file: rel, lineNumber: 0, ruleId: "DL-050", severity: "low", description: "No HEALTHCHECK instruction found", recommendation: "Add HEALTHCHECK to enable container health monitoring" });
    if (!/^\s*USER\b/m.test(content)) findings.push({ file: rel, lineNumber: 0, ruleId: "DL-010", severity: "high", description: "No USER instruction — container runs as root by default", recommendation: "Add USER nonroot or USER 1000 before CMD/ENTRYPOINT" });
    if ((content.match(/^\s*FROM\b/gm) || []).length === 1) findings.push({ file: rel, lineNumber: 0, ruleId: "DL-070", severity: "low", description: "Single-stage build — consider multi-stage for smaller images", recommendation: "Use multi-stage builds to separate build and runtime stages" });
  }

  if (filesScanned > 0 && !fs.existsSync(path.join(resolved, ".dockerignore"))) {
    findings.push({ file: ".dockerignore", lineNumber: 0, ruleId: "DL-060", severity: "medium", description: "No .dockerignore file found", recommendation: "Create .dockerignore to exclude .git, node_modules, secrets, etc." });
  }

  return {
    findings, filesScanned,
    criticalCount: findings.filter((f) => f.severity === "critical").length,
    highCount: findings.filter((f) => f.severity === "high").length,
    mediumCount: findings.filter((f) => f.severity === "medium").length,
    lowCount: findings.filter((f) => f.severity === "low").length,
    clean: findings.length === 0,
  };
}

function findDockerfiles(p: string): string[] {
  const found: string[] = [];
  const candidates = ["Dockerfile", "Dockerfile.dev", "Dockerfile.prod", "Dockerfile.build", "Dockerfile.test", "docker/Dockerfile", "build/Dockerfile", "Containerfile"];
  for (const name of candidates) { const full = path.join(p, name); if (fs.existsSync(full)) found.push(full); }
  try { for (const f of fs.readdirSync(p)) { const full = path.join(p, f); if (fs.statSync(full).isFile() && f.startsWith("Dockerfile") && !found.includes(full)) found.push(full); } } catch { /* */ }
  return found.sort();
}
