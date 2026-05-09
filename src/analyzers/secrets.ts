/**
 * Credential and secret scanner — detect leaked secrets in project files.
 */

import * as fs from "node:fs";
import * as path from "node:path";

export interface SecretFinding {
  file: string;
  lineNumber: number;
  ruleId: string;
  description: string;
  severity: string;
  matchPreview: string;
}

export interface SecretsReport {
  findings: SecretFinding[];
  filesScanned: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  total: number;
  clean: boolean;
}

const RULES: Array<[string, string, string, string]> = [
  ["aws-access-key", "AWS Access Key ID", "(?:AKIA)[0-9A-Z]{16}", "critical"],
  ["aws-secret-key", "AWS Secret Access Key", '(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\\s*[=:]\\s*["\']?([A-Za-z0-9/+=]{40})', "critical"],
  ["gcp-api-key", "Google Cloud API Key", "AIza[0-9A-Za-z\\-_]{35}", "critical"],
  ["gcp-service-account", "Google Cloud Service Account Key", '"type"\\s*:\\s*"service_account"', "critical"],
  ["github-token", "GitHub Personal Access Token", "gh[ps]_[A-Za-z0-9_]{36,}", "critical"],
  ["github-fine-grained", "GitHub Fine-Grained Token", "github_pat_[A-Za-z0-9_]{22,}", "critical"],
  ["gitlab-token", "GitLab Token", "glpat-[A-Za-z0-9\\-_]{20,}", "high"],
  ["slack-token", "Slack Token", "xox[bpors]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}", "high"],
  ["npm-token", "npm Access Token", "npm_[A-Za-z0-9]{36}", "critical"],
  ["pypi-token", "PyPI API Token", "pypi-[A-Za-z0-9_\\-]{100,}", "critical"],
  ["private-key-rsa", "RSA Private Key", "-----BEGIN RSA PRIVATE KEY-----", "critical"],
  ["private-key-openssh", "OpenSSH Private Key", "-----BEGIN OPENSSH PRIVATE KEY-----", "critical"],
  ["private-key-ec", "EC Private Key", "-----BEGIN EC PRIVATE KEY-----", "critical"],
  ["database-url", "Database Connection String with Credentials", "(?:postgres|mysql|mongodb|redis)://[^:]+:[^@]+@[^/\\s]+", "high"],
  ["generic-secret-assignment", "Hardcoded Secret Assignment", '(?:secret|password|passwd|token|api_key|apikey|api-key|access_key|auth_token|credentials)\\s*[=:]\\s*["\'][A-Za-z0-9+/=_\\-]{16,}["\']', "medium"],
  ["stripe-key", "Stripe API Key", "(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}", "critical"],
  ["sendgrid-api-key", "SendGrid API Key", "SG\\.[A-Za-z0-9\\-_]{22}\\.[A-Za-z0-9\\-_]{43}", "high"],
];

const SKIP_EXTENSIONS = new Set([".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp", ".woff", ".woff2", ".ttf", ".eot", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".exe", ".dll", ".so", ".dylib", ".bin", ".pdf", ".pyc", ".class", ".o", ".obj", ".lock"]);
const SKIP_DIRS = new Set([".git", "node_modules", "vendor", "venv", ".venv", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", "dist", "build", ".eggs", "target", ".gradle"]);
const SKIP_FILES = new Set(["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock", "go.sum", "poetry.lock", "Gemfile.lock", "composer.lock"]);

export function scanSecrets(projectPath: string, includeLow = false): SecretsReport {
  const resolved = path.resolve(projectPath);
  const findings: SecretFinding[] = [];
  let filesScanned = 0;

  const compiled = RULES.filter(([, , , sev]) => includeLow || sev !== "low").map(([id, desc, pattern, sev]) => ({ id, desc, re: new RegExp(pattern), sev }));
  const ignorePatterns = loadIgnoreFile(resolved);

  for (const filePath of walkFiles(resolved)) {
    if (SKIP_FILES.has(path.basename(filePath))) continue;
    const ext = path.extname(filePath).toLowerCase();
    if (SKIP_EXTENSIONS.has(ext)) continue;
    const rel = path.relative(resolved, filePath);
    if (ignorePatterns.some((p) => new RegExp(p).test(rel))) continue;

    let content: string;
    try { content = fs.readFileSync(filePath, "utf-8"); } catch { continue; }
    filesScanned++;

    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      for (const rule of compiled) {
        if (rule.re.test(lines[i])) {
          findings.push({ file: rel, lineNumber: i + 1, ruleId: rule.id, description: rule.desc, severity: rule.sev, matchPreview: redactLine(lines[i].trim()) });
        }
      }
    }
  }

  const seen = new Set<string>();
  const deduped = findings.filter((f) => { const k = `${f.file}:${f.lineNumber}:${f.ruleId}`; if (seen.has(k)) return false; seen.add(k); return true; });

  return {
    findings: deduped, filesScanned,
    criticalCount: deduped.filter((f) => f.severity === "critical").length,
    highCount: deduped.filter((f) => f.severity === "high").length,
    mediumCount: deduped.filter((f) => f.severity === "medium").length,
    lowCount: deduped.filter((f) => f.severity === "low").length,
    total: deduped.length, clean: deduped.length === 0,
  };
}

function walkFiles(dir: string): string[] {
  const results: string[] = [];
  try {
    for (const entry of fs.readdirSync(dir).sort()) {
      if (SKIP_DIRS.has(entry) || (entry.startsWith(".") && ![".github", ".env", ".npmrc"].includes(entry))) continue;
      const full = path.join(dir, entry);
      const stat = fs.statSync(full);
      if (stat.isFile()) results.push(full);
      else if (stat.isDirectory() && !SKIP_DIRS.has(entry)) results.push(...walkFiles(full));
    }
  } catch { /* permission error */ }
  return results;
}

function redactLine(line: string, maxLen = 80): string {
  if (line.length > maxLen) line = line.slice(0, maxLen) + "...";
  return line.replace(/[A-Za-z0-9+/=_\-]{16,}/g, (m) => m.length > 8 ? m.slice(0, 4) + "*".repeat(m.length - 8) + m.slice(-4) : m);
}

function loadIgnoreFile(p: string): string[] {
  const f = path.join(p, ".ossguard-secrets-ignore");
  if (!fs.existsSync(f)) return [];
  return fs.readFileSync(f, "utf-8").split("\n").map((l: string) => l.trim()).filter((l: string) => l && !l.startsWith("#"));
}
