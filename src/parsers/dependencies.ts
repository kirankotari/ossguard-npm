/**
 * Parse dependency files to extract package names and versions.
 */

import * as fs from "node:fs";
import * as path from "node:path";

export interface Dependency {
  name: string;
  version: string;
  ecosystem: string; // npm, pypi, go, crates.io, maven, rubygems, nuget, packagist
  sourceFile: string;
  isDev: boolean;
}

export function createDependency(partial: Partial<Dependency> & { name: string }): Dependency {
  return {
    name: partial.name,
    version: partial.version ?? "",
    ecosystem: partial.ecosystem ?? "",
    sourceFile: partial.sourceFile ?? "",
    isDev: partial.isDev ?? false,
  };
}

export function displayName(dep: Dependency): string {
  return dep.version ? `${dep.name}@${dep.version}` : dep.name;
}

export function parseDependencies(projectPath: string): Dependency[] {
  const resolved = path.resolve(projectPath);
  if (!fs.existsSync(resolved) || !fs.statSync(resolved).isDirectory()) return [];

  const deps: Dependency[] = [];
  parsePackageJson(resolved, deps);
  parseRequirementsTxt(resolved, deps);
  parsePyprojectToml(resolved, deps);
  parseGoMod(resolved, deps);
  parseCargoToml(resolved, deps);
  parseGemfileLock(resolved, deps);
  parsePomXml(resolved, deps);
  parseComposerJson(resolved, deps);

  // Deduplicate
  const seen = new Set<string>();
  return deps.filter((dep) => {
    const key = `${dep.name}|${dep.ecosystem}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function cleanVersion(version: string): string {
  return version.replace(/^[\^~>=<!\s*]+/, "").trim();
}

function parsePackageJson(projectPath: string, deps: Dependency[]): void {
  const pkgFile = path.join(projectPath, "package.json");
  if (!fs.existsSync(pkgFile)) return;

  try {
    const pkg = JSON.parse(fs.readFileSync(pkgFile, "utf-8"));
    for (const [name, version] of Object.entries(pkg.dependencies ?? {})) {
      deps.push(
        createDependency({
          name,
          version: cleanVersion(version as string),
          ecosystem: "npm",
          sourceFile: "package.json",
          isDev: false,
        }),
      );
    }
    for (const [name, version] of Object.entries(pkg.devDependencies ?? {})) {
      deps.push(
        createDependency({
          name,
          version: cleanVersion(version as string),
          ecosystem: "npm",
          sourceFile: "package.json",
          isDev: true,
        }),
      );
    }
  } catch {
    // ignore
  }
}

function parseRequirementsTxt(projectPath: string, deps: Dependency[]): void {
  for (const reqFile of ["requirements.txt", "requirements-dev.txt", "requirements_dev.txt"]) {
    const reqPath = path.join(projectPath, reqFile);
    if (!fs.existsSync(reqPath)) continue;

    const isDev = reqFile.includes("dev");
    try {
      const content = fs.readFileSync(reqPath, "utf-8");
      for (const raw of content.split("\n")) {
        const line = raw.trim();
        if (!line || line.startsWith("#") || line.startsWith("-")) continue;

        const match = line.match(/^([a-zA-Z0-9_.-]+)\s*([><=~!]+\s*[\d.*]+)?/);
        if (match) {
          const name = match[1];
          const versionSpec = match[2] ?? "";
          const version = versionSpec.replace(/[><=~!]+\s*/g, "").trim();
          deps.push(
            createDependency({ name, version, ecosystem: "pypi", sourceFile: reqFile, isDev }),
          );
        }
      }
    } catch {
      // ignore
    }
  }
}

function parsePyprojectToml(projectPath: string, deps: Dependency[]): void {
  const tomlPath = path.join(projectPath, "pyproject.toml");
  if (!fs.existsSync(tomlPath)) return;

  try {
    const content = fs.readFileSync(tomlPath, "utf-8");
    let inProject = false;
    let inDeps = false;
    let bracketDepth = 0;

    for (const line of content.split("\n")) {
      const stripped = line.trim();

      if (stripped === "[project]") {
        inProject = true;
        continue;
      } else if (stripped.startsWith("[") && stripped !== "[project]") {
        if (inProject && !stripped.startsWith("[project.")) {
          inProject = false;
          inDeps = false;
        }
        continue;
      }

      if (inProject && stripped.startsWith("dependencies")) {
        inDeps = true;
        bracketDepth = (stripped.match(/\[/g) ?? []).length - (stripped.match(/]/g) ?? []).length;
        extractPyprojectDeps(stripped, deps);
        if (bracketDepth <= 0 && stripped.includes("[")) inDeps = false;
        continue;
      }

      if (inDeps) {
        bracketDepth += (stripped.match(/\[/g) ?? []).length - (stripped.match(/]/g) ?? []).length;
        extractPyprojectDeps(stripped, deps);
        if (bracketDepth <= 0) inDeps = false;
      }
    }
  } catch {
    // ignore
  }
}

function extractPyprojectDeps(line: string, deps: Dependency[]): void {
  const re = /"([a-zA-Z0-9_.-]+)(?:\[.*?])?(?:\s*([><=~!]+\s*[\d.*]+))?/g;
  let match;
  while ((match = re.exec(line)) !== null) {
    const name = match[1];
    const versionSpec = match[2] ?? "";
    const version = versionSpec.replace(/[><=~!]+\s*/g, "").trim();
    deps.push(
      createDependency({
        name,
        version,
        ecosystem: "pypi",
        sourceFile: "pyproject.toml",
      }),
    );
  }
}

function parseGoMod(projectPath: string, deps: Dependency[]): void {
  const goMod = path.join(projectPath, "go.mod");
  if (!fs.existsSync(goMod)) return;

  try {
    const content = fs.readFileSync(goMod, "utf-8");
    let inRequire = false;

    for (const line of content.split("\n")) {
      const stripped = line.trim();
      if (stripped.startsWith("require (")) {
        inRequire = true;
        continue;
      } else if (stripped === ")" && inRequire) {
        inRequire = false;
        continue;
      }

      if (inRequire || stripped.startsWith("require ")) {
        const match = stripped.match(/^(?:require\s+)?([a-zA-Z0-9_./-]+)\s+(v[\d.]+)/);
        if (match) {
          deps.push(
            createDependency({
              name: match[1],
              version: match[2],
              ecosystem: "go",
              sourceFile: "go.mod",
            }),
          );
        }
      }
    }
  } catch {
    // ignore
  }
}

function parseCargoToml(projectPath: string, deps: Dependency[]): void {
  const cargoPath = path.join(projectPath, "Cargo.toml");
  if (!fs.existsSync(cargoPath)) return;

  try {
    const content = fs.readFileSync(cargoPath, "utf-8");
    let inDeps = false;
    let isDev = false;

    for (const line of content.split("\n")) {
      const stripped = line.trim();
      if (stripped === "[dependencies]") {
        inDeps = true;
        isDev = false;
        continue;
      } else if (stripped === "[dev-dependencies]") {
        inDeps = true;
        isDev = true;
        continue;
      } else if (stripped.startsWith("[")) {
        inDeps = false;
        continue;
      }

      if (inDeps) {
        let match = stripped.match(/^([a-zA-Z0-9_-]+)\s*=\s*"([\d.*^~]+)"/);
        if (!match) {
          match = stripped.match(/^([a-zA-Z0-9_-]+)\s*=\s*\{.*version\s*=\s*"([\d.*^~]+)"/);
        }
        if (match) {
          deps.push(
            createDependency({
              name: match[1],
              version: cleanVersion(match[2]),
              ecosystem: "crates.io",
              sourceFile: "Cargo.toml",
              isDev,
            }),
          );
        }
      }
    }
  } catch {
    // ignore
  }
}

function parseGemfileLock(projectPath: string, deps: Dependency[]): void {
  const lockPath = path.join(projectPath, "Gemfile.lock");
  if (!fs.existsSync(lockPath)) return;

  try {
    const content = fs.readFileSync(lockPath, "utf-8");
    let inSpecs = false;

    for (const line of content.split("\n")) {
      if (line.trim() === "specs:") {
        inSpecs = true;
        continue;
      } else if (!line.startsWith(" ") && inSpecs) {
        inSpecs = false;
        continue;
      }

      if (inSpecs) {
        const match = line.match(/^\s{4}([a-zA-Z0-9_.-]+)\s+\(([\d.]+)/);
        if (match) {
          deps.push(
            createDependency({
              name: match[1],
              version: match[2],
              ecosystem: "rubygems",
              sourceFile: "Gemfile.lock",
            }),
          );
        }
      }
    }
  } catch {
    // ignore
  }
}

function parsePomXml(projectPath: string, deps: Dependency[]): void {
  const pomPath = path.join(projectPath, "pom.xml");
  if (!fs.existsSync(pomPath)) return;

  try {
    const content = fs.readFileSync(pomPath, "utf-8");
    const re =
      /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*(?:<version>([^<]+)<\/version>)?/gs;
    let match;
    while ((match = re.exec(content)) !== null) {
      const groupId = match[1].trim();
      const artifactId = match[2].trim();
      const version = (match[3] ?? "").trim();
      deps.push(
        createDependency({
          name: `${groupId}:${artifactId}`,
          version,
          ecosystem: "maven",
          sourceFile: "pom.xml",
        }),
      );
    }
  } catch {
    // ignore
  }
}

function parseComposerJson(projectPath: string, deps: Dependency[]): void {
  const composerPath = path.join(projectPath, "composer.json");
  if (!fs.existsSync(composerPath)) return;

  try {
    const data = JSON.parse(fs.readFileSync(composerPath, "utf-8"));
    for (const [name, version] of Object.entries(data.require ?? {})) {
      if (name === "php" || name.startsWith("ext-")) continue;
      deps.push(
        createDependency({
          name,
          version: cleanVersion(version as string),
          ecosystem: "packagist",
          sourceFile: "composer.json",
        }),
      );
    }
    for (const [name, version] of Object.entries(data["require-dev"] ?? {})) {
      if (name === "php" || name.startsWith("ext-")) continue;
      deps.push(
        createDependency({
          name,
          version: cleanVersion(version as string),
          ecosystem: "packagist",
          sourceFile: "composer.json",
          isDev: true,
        }),
      );
    }
  } catch {
    // ignore
  }
}
