/**
 * Fuzzing readiness check — detect existing fuzz setup and generate starter harnesses.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { detectProject, type ProjectInfo } from "../detector.js";

export interface FuzzFinding {
  category: string;
  description: string;
  file: string;
  details: string;
}

export interface FuzzReport {
  hasFuzzing: boolean;
  framework: string;
  findings: FuzzFinding[];
  readinessScore: number;
  starterHarness: string;
  language: string;
}

export function checkFuzzReadiness(projectPath: string): FuzzReport {
  const resolved = path.resolve(projectPath);
  const info = detectProject(resolved);
  const lang = info.primaryLanguage || "";
  const findings: FuzzFinding[] = [];
  let hasFuzzing = false, framework = "", score = 0;

  const [ef, efr, eff] = detectExistingFuzz(resolved, info);
  hasFuzzing = ef; framework = efr; findings.push(...eff);
  if (hasFuzzing) score += 50;

  const ossFuzz = checkOssFuzz(resolved);
  findings.push(...ossFuzz);
  if (ossFuzz.some((f) => f.category === "existing" && f.description.includes("OSS-Fuzz"))) score += 20;

  const cfl = checkClusterFuzzLite(resolved);
  findings.push(...cfl);
  if (cfl.some((f) => f.category === "existing")) score += 15;

  const ci = checkFuzzCi(resolved);
  findings.push(...ci);
  if (ci.some((f) => f.category === "existing")) score += 15;

  if (!hasFuzzing) findings.push(...generateRecommendations(lang));

  return { hasFuzzing, framework, findings, readinessScore: Math.min(score, 100), starterHarness: generateStarterHarness(lang), language: lang };
}

function detectExistingFuzz(p: string, info: ProjectInfo): [boolean, string, FuzzFinding[]] {
  const findings: FuzzFinding[] = [];
  let found = false, fw = "";
  const lang = (info.primaryLanguage || "").toLowerCase();

  if (lang === "python") {
    for (const f of globPy(p)) {
      try { const c = fs.readFileSync(f, "utf-8").slice(0, 2000); if (c.includes("atheris")) { found = true; fw = "Atheris"; findings.push({ category: "existing", description: `Atheris fuzzer found in ${path.basename(f)}`, file: f, details: "" }); } if (c.includes("hypothesis") && c.includes("@given")) { found = true; fw = fw || "Hypothesis"; findings.push({ category: "existing", description: `Hypothesis property tests in ${path.basename(f)}`, file: f, details: "" }); } } catch {}
    }
  } else if (lang === "go") {
    for (const f of globGo(p)) {
      try { if (fs.readFileSync(f, "utf-8").includes("func Fuzz")) { found = true; fw = "Go native fuzzing"; findings.push({ category: "existing", description: `Go fuzz function found in ${path.basename(f)}`, file: f, details: "" }); } } catch {}
    }
  } else if (lang === "rust") {
    if (fs.existsSync(path.join(p, "fuzz"))) { found = true; fw = "cargo-fuzz"; findings.push({ category: "existing", description: "cargo-fuzz directory found", file: "fuzz/", details: "" }); }
  } else if (["javascript", "typescript"].includes(lang)) {
    const pkg = path.join(p, "package.json");
    if (fs.existsSync(pkg)) { try { const d = JSON.parse(fs.readFileSync(pkg, "utf-8")); const all = { ...d.dependencies, ...d.devDependencies }; if (all["jsfuzz"] || all["@jazzer.js/core"]) { found = true; fw = "jsfuzz/Jazzer.js"; findings.push({ category: "existing", description: "JS fuzzer dependency found", file: "", details: "" }); } if (all["fast-check"]) { found = true; fw = fw || "fast-check"; findings.push({ category: "existing", description: "fast-check property testing found", file: "", details: "" }); } } catch {} }
  } else if (["java", "kotlin"].includes(lang)) {
    for (const f of globJava(p)) {
      try { const c = fs.readFileSync(f, "utf-8").slice(0, 2000); if (c.includes("com.code_intelligence.jazzer") || c.includes("@FuzzTest")) { found = true; fw = "Jazzer"; findings.push({ category: "existing", description: `Jazzer fuzz test in ${path.basename(f)}`, file: f, details: "" }); } } catch {}
    }
  } else if (["c", "c++"].includes(lang)) {
    for (const f of globC(p)) {
      try { if (fs.readFileSync(f, "utf-8").slice(0, 2000).includes("LLVMFuzzerTestOneInput")) { found = true; fw = "libFuzzer"; findings.push({ category: "existing", description: `libFuzzer harness in ${path.basename(f)}`, file: f, details: "" }); } } catch {}
    }
  }
  return [found, fw, findings];
}

function checkOssFuzz(p: string): FuzzFinding[] {
  const findings: FuzzFinding[] = [];
  if (fs.existsSync(path.join(p, ".oss-fuzz"))) findings.push({ category: "existing", description: "OSS-Fuzz integration found", file: ".oss-fuzz/", details: "" });
  for (const n of ["project.yaml", ".clusterfuzzlite/project.yaml"]) if (fs.existsSync(path.join(p, n))) findings.push({ category: "existing", description: `OSS-Fuzz project config found: ${n}`, file: n, details: "" });
  return findings;
}

function checkClusterFuzzLite(p: string): FuzzFinding[] {
  const findings: FuzzFinding[] = [];
  if (fs.existsSync(path.join(p, ".clusterfuzzlite"))) findings.push({ category: "existing", description: "ClusterFuzzLite configuration found", file: ".clusterfuzzlite/", details: "" });
  const wfDir = path.join(p, ".github", "workflows");
  if (fs.existsSync(wfDir)) { for (const f of fs.readdirSync(wfDir)) { if (f.endsWith(".yml") || f.endsWith(".yaml")) { try { if (fs.readFileSync(path.join(wfDir, f), "utf-8").toLowerCase().includes("clusterfuzzlite")) findings.push({ category: "existing", description: `ClusterFuzzLite workflow: ${f}`, file: f, details: "" }); } catch {} } } }
  return findings;
}

function checkFuzzCi(p: string): FuzzFinding[] {
  const findings: FuzzFinding[] = [];
  const wfDir = path.join(p, ".github", "workflows");
  if (fs.existsSync(wfDir)) { for (const f of fs.readdirSync(wfDir)) { if (f.endsWith(".yml") || f.endsWith(".yaml")) { try { const c = fs.readFileSync(path.join(wfDir, f), "utf-8").toLowerCase(); if (c.includes("fuzz") && (c.includes("run:") || c.includes("uses:"))) findings.push({ category: "existing", description: `Fuzz CI workflow: ${f}`, file: f, details: "" }); } catch {} } } }
  return findings;
}

function generateRecommendations(lang: string): FuzzFinding[] {
  const recs: Record<string, string[]> = {
    python: ["Install Atheris for Python fuzzing: pip install atheris", "Consider Hypothesis for property-based testing: pip install hypothesis", "Apply to OSS-Fuzz for continuous fuzzing coverage"],
    go: ["Use native Go fuzzing (Go 1.18+): func FuzzXxx(f *testing.F)", "Run: go test -fuzz=FuzzXxx ./...", "Apply to OSS-Fuzz or set up ClusterFuzzLite"],
    rust: ["Install cargo-fuzz: cargo install cargo-fuzz", "Initialize: cargo fuzz init && cargo fuzz add fuzz_target_1"],
    javascript: ["Install Jazzer.js: npm install --save-dev @jazzer.js/core", "Consider fast-check for property-based testing"],
    typescript: ["Install Jazzer.js: npm install --save-dev @jazzer.js/core", "Consider fast-check for property-based testing"],
    java: ["Use Jazzer for Java fuzzing: add com.code_intelligence:jazzer-junit", "Annotate fuzz test methods with @FuzzTest"],
    c: ["Use libFuzzer: implement LLVMFuzzerTestOneInput", "Compile with: clang -fsanitize=fuzzer,address"],
    "c++": ["Use libFuzzer: implement LLVMFuzzerTestOneInput", "Compile with: clang++ -fsanitize=fuzzer,address"],
  };
  const findings: FuzzFinding[] = (recs[lang.toLowerCase()] ?? []).map((d) => ({ category: "recommendation", description: d, file: "", details: "" }));
  findings.push({ category: "recommendation", description: "Set up ClusterFuzzLite for CI-integrated fuzzing: https://google.github.io/clusterfuzzlite/", file: "", details: "" });
  return findings;
}

function generateStarterHarness(lang: string): string {
  const l = lang.toLowerCase();
  if (l === "python") return `#!/usr/bin/env python3\n"""Fuzz test harness — customize for your project."""\nimport atheris\nimport sys\n\n@atheris.instrument_func\ndef fuzz_target(data: bytes):\n    try:\n        text = data.decode("utf-8", errors="ignore")\n    except (ValueError, KeyError, IndexError):\n        pass\n\nif __name__ == "__main__":\n    atheris.Setup(sys.argv, fuzz_target)\n    atheris.Fuzz()\n`;
  if (l === "go") return `package mypackage\n\nimport "testing"\n\nfunc FuzzParseInput(f *testing.F) {\n\tf.Add([]byte("hello"))\n\tf.Add([]byte(""))\n\tf.Fuzz(func(t *testing.T, data []byte) {\n\t\t// Replace with your function under test\n\t})\n}\n`;
  if (l === "rust") return `#![no_main]\nuse libfuzzer_sys::fuzz_target;\n\nfuzz_target!(|data: &[u8]| {\n    if let Ok(s) = std::str::from_utf8(data) {\n        // Replace with your function under test\n    }\n});\n`;
  if (["javascript", "typescript"].includes(l)) return `const { fuzz } = require("@jazzer.js/core");\n\nfuzz((data) => {\n  const input = data.toString("utf-8");\n  // Replace with your function under test\n});\n`;
  if (["java", "kotlin"].includes(l)) return `import com.code_intelligence.jazzer.api.FuzzedDataProvider;\nimport com.code_intelligence.jazzer.junit.FuzzTest;\n\nclass FuzzTests {\n    @FuzzTest\n    void fuzzParseInput(FuzzedDataProvider data) {\n        String input = data.consumeRemainingAsString();\n    }\n}\n`;
  if (["c", "c++"].includes(l)) return `#include <stdint.h>\n#include <stddef.h>\n\nextern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n    return 0;\n}\n`;
  return "# No starter harness available for this language.\n";
}

// Simple file glob helpers (shallow search, skip common dirs)
const SKIP = new Set([".git", "node_modules", "vendor", "venv", ".venv", "__pycache__", "dist", "build", "target"]);
function walk(dir: string, ext: string[]): string[] {
  const results: string[] = [];
  try { for (const e of fs.readdirSync(dir)) { if (SKIP.has(e)) continue; const f = path.join(dir, e); const s = fs.statSync(f); if (s.isFile() && ext.some((x) => f.endsWith(x))) results.push(f); else if (s.isDirectory()) results.push(...walk(f, ext)); } } catch {}
  return results;
}
function globPy(p: string) { return walk(p, [".py"]); }
function globGo(p: string) { return walk(p, ["_test.go"]); }
function globJava(p: string) { return walk(p, [".java"]); }
function globC(p: string) { return walk(p, [".c", ".cpp", ".cc", ".h"]); }
