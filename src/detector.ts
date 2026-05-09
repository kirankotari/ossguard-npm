/**
 * Auto-detect project language, framework, and package manager.
 */

import * as fs from "node:fs";
import * as path from "node:path";

export interface ProjectInfo {
  path: string;
  languages: string[];
  frameworks: string[];
  packageManagers: string[];
  hasGithubActions: boolean;
  hasGit: boolean;
  hasSecurityMd: boolean;
  hasScorecard: boolean;
  hasDependabot: boolean;
  hasCodeql: boolean;
  hasSbomWorkflow: boolean;
  hasSigstore: boolean;
  repoName: string;
  primaryLanguage: string;
}

export function createProjectInfo(projectPath: string): ProjectInfo {
  return {
    path: projectPath,
    languages: [],
    frameworks: [],
    packageManagers: [],
    hasGithubActions: false,
    hasGit: false,
    hasSecurityMd: false,
    hasScorecard: false,
    hasDependabot: false,
    hasCodeql: false,
    hasSbomWorkflow: false,
    hasSigstore: false,
    repoName: "",
    primaryLanguage: "",
  };
}

const LANGUAGE_MARKERS: Record<string, string> = {
  "package.json": "javascript",
  "tsconfig.json": "typescript",
  "pyproject.toml": "python",
  "setup.py": "python",
  "setup.cfg": "python",
  "requirements.txt": "python",
  Pipfile: "python",
  "go.mod": "go",
  "go.sum": "go",
  "Cargo.toml": "rust",
  Gemfile: "ruby",
  "pom.xml": "java",
  "build.gradle": "java",
  "build.gradle.kts": "kotlin",
  "composer.json": "php",
  "mix.exs": "elixir",
  "pubspec.yaml": "dart",
  "CMakeLists.txt": "c/c++",
  Makefile: "c/c++",
  "meson.build": "c/c++",
};

const PACKAGE_MANAGER_MARKERS: Record<string, string> = {
  "package.json": "npm",
  "yarn.lock": "yarn",
  "pnpm-lock.yaml": "pnpm",
  "pyproject.toml": "pip",
  Pipfile: "pipenv",
  "poetry.lock": "poetry",
  "requirements.txt": "pip",
  "go.mod": "go-modules",
  "Cargo.toml": "cargo",
  Gemfile: "bundler",
  "pom.xml": "maven",
  "build.gradle": "gradle",
  "build.gradle.kts": "gradle",
  "composer.json": "composer",
  "pubspec.yaml": "pub",
};

const FRAMEWORK_MARKERS: Record<string, string> = {
  "next.config.js": "Next.js",
  "next.config.mjs": "Next.js",
  "next.config.ts": "Next.js",
  "nuxt.config.ts": "Nuxt",
  "angular.json": "Angular",
  "svelte.config.js": "Svelte",
  "astro.config.mjs": "Astro",
  "vite.config.ts": "Vite",
  "vite.config.js": "Vite",
  "webpack.config.js": "Webpack",
  "manage.py": "Django",
};

function addUnique(arr: string[], value: string): void {
  if (!arr.includes(value)) arr.push(value);
}

export function detectProject(projectPath: string): ProjectInfo {
  const resolved = path.resolve(projectPath);
  const info = createProjectInfo(resolved);

  if (!fs.existsSync(resolved) || !fs.statSync(resolved).isDirectory()) {
    return info;
  }

  info.repoName = path.basename(resolved);
  info.hasGit = fs.existsSync(path.join(resolved, ".git"));

  const filesInRoot = new Set<string>();
  for (const item of fs.readdirSync(resolved)) {
    filesInRoot.add(item);
  }

  // Detect languages
  for (const [marker, lang] of Object.entries(LANGUAGE_MARKERS)) {
    if (marker.startsWith("*")) {
      const ext = marker.slice(1);
      for (const f of filesInRoot) {
        if (f.endsWith(ext)) {
          addUnique(info.languages, lang);
          break;
        }
      }
    } else if (filesInRoot.has(marker)) {
      addUnique(info.languages, lang);
    }
  }

  // Detect package managers
  for (const [marker, pm] of Object.entries(PACKAGE_MANAGER_MARKERS)) {
    if (filesInRoot.has(marker)) addUnique(info.packageManagers, pm);
  }

  // Detect frameworks from markers
  for (const [marker, fw] of Object.entries(FRAMEWORK_MARKERS)) {
    if (filesInRoot.has(marker)) addUnique(info.frameworks, fw);
  }

  // Check for framework references inside package.json
  const pkgJsonPath = path.join(resolved, "package.json");
  if (fs.existsSync(pkgJsonPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, "utf-8"));
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      if (deps.react) addUnique(info.frameworks, "React");
      if (deps.vue) addUnique(info.frameworks, "Vue");
      if (deps["@angular/core"]) addUnique(info.frameworks, "Angular");
      if (deps.express) addUnique(info.frameworks, "Express");
      if (deps.fastify) addUnique(info.frameworks, "Fastify");
    } catch {
      // ignore parse errors
    }
  }

  // Set primary language
  if (info.languages.length > 0) {
    info.primaryLanguage = info.languages[0];
  }

  // Check existing security setup
  const githubDir = path.join(resolved, ".github");
  if (fs.existsSync(githubDir) && fs.statSync(githubDir).isDirectory()) {
    const workflowsDir = path.join(githubDir, "workflows");
    info.hasGithubActions =
      fs.existsSync(workflowsDir) && fs.statSync(workflowsDir).isDirectory();

    info.hasSecurityMd = fs.existsSync(path.join(githubDir, "SECURITY.md"));

    info.hasDependabot =
      fs.existsSync(path.join(githubDir, "dependabot.yml")) ||
      fs.existsSync(path.join(githubDir, "dependabot.yaml"));

    // Scan workflows
    if (info.hasGithubActions) {
      try {
        for (const wfFile of fs.readdirSync(workflowsDir)) {
          if (wfFile.endsWith(".yml") || wfFile.endsWith(".yaml")) {
            try {
              const content = fs
                .readFileSync(path.join(workflowsDir, wfFile), "utf-8")
                .toLowerCase();
              if (content.includes("scorecard") || content.includes("ossf/scorecard"))
                info.hasScorecard = true;
              if (content.includes("codeql")) info.hasCodeql = true;
              if (
                content.includes("sbom") ||
                content.includes("cyclonedx") ||
                content.includes("spdx")
              )
                info.hasSbomWorkflow = true;
              if (content.includes("sigstore") || content.includes("cosign"))
                info.hasSigstore = true;
            } catch {
              // ignore read errors
            }
          }
        }
      } catch {
        // ignore readdir errors
      }
    }
  }

  // Also check root for SECURITY.md
  if (!info.hasSecurityMd) {
    info.hasSecurityMd = fs.existsSync(path.join(resolved, "SECURITY.md"));
  }

  return info;
}

export function projectInfoSummary(info: ProjectInfo): Record<string, unknown> {
  return {
    languages: info.languages,
    primaryLanguage: info.primaryLanguage,
    frameworks: info.frameworks,
    packageManagers: info.packageManagers,
    existing: {
      git: info.hasGit,
      githubActions: info.hasGithubActions,
      securityMd: info.hasSecurityMd,
      scorecard: info.hasScorecard,
      dependabot: info.hasDependabot,
      codeql: info.hasCodeql,
      sbomWorkflow: info.hasSbomWorkflow,
      sigstore: info.hasSigstore,
    },
  };
}
