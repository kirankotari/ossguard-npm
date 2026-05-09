/**
 * Parse SBOM files (SPDX and CycloneDX JSON formats).
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { type Dependency, createDependency } from "./dependencies.js";

export interface SBOMInfo {
  format: "spdx" | "cyclonedx";
  name: string;
  version: string;
  dependencies: Dependency[];
  raw: Record<string, unknown>;
}

const PURL_ECOSYSTEM_MAP: Record<string, string> = {
  npm: "npm",
  pypi: "pypi",
  golang: "go",
  cargo: "crates.io",
  maven: "maven",
  gem: "rubygems",
  nuget: "nuget",
  composer: "packagist",
  pub: "pub",
};

export function parseSBOM(sbomPath: string): SBOMInfo {
  const resolved = path.resolve(sbomPath);
  const data = JSON.parse(fs.readFileSync(resolved, "utf-8"));

  if (data.bomFormat === "CycloneDX") return parseCycloneDX(data);
  if (data.spdxVersion) return parseSPDX(data);
  throw new Error(`Unrecognized SBOM format in ${resolved}`);
}

function parseCycloneDX(data: Record<string, unknown>): SBOMInfo {
  const deps: Dependency[] = [];
  const metadata = (data.metadata as Record<string, unknown>) ?? {};
  const component = (metadata.component as Record<string, string>) ?? {};

  for (const comp of (data.components as Record<string, unknown>[]) ?? []) {
    const name = (comp.name as string) ?? "";
    const version = (comp.version as string) ?? "";
    let ecosystem = "";
    const purl = (comp.purl as string) ?? "";

    if (purl) ecosystem = ecosystemFromPurl(purl);
    if (!ecosystem && comp.type === "library") ecosystem = guessEcosystem(name);

    deps.push(
      createDependency({ name, version, ecosystem, sourceFile: "sbom (CycloneDX)" }),
    );
  }

  return {
    format: "cyclonedx",
    name: component.name ?? "",
    version: component.version ?? "",
    dependencies: deps,
    raw: data,
  };
}

function parseSPDX(data: Record<string, unknown>): SBOMInfo {
  const deps: Dependency[] = [];
  const docName = (data.name as string) ?? "";

  for (const pkg of (data.packages as Record<string, unknown>[]) ?? []) {
    const name = (pkg.name as string) ?? "";
    const version = (pkg.versionInfo as string) ?? "";
    let ecosystem = "";

    for (const ref of (pkg.externalRefs as Record<string, string>[]) ?? []) {
      if (ref.referenceType === "purl") {
        ecosystem = ecosystemFromPurl(ref.referenceLocator ?? "");
        break;
      }
    }
    if (!ecosystem) ecosystem = guessEcosystem(name);

    const spdxId = (pkg.SPDXID as string) ?? "";
    if (spdxId === "SPDXRef-DOCUMENT") continue;

    deps.push(createDependency({ name, version, ecosystem, sourceFile: "sbom (SPDX)" }));
  }

  return {
    format: "spdx",
    name: docName,
    version: "",
    dependencies: deps,
    raw: data,
  };
}

function ecosystemFromPurl(purl: string): string {
  if (!purl.startsWith("pkg:")) return "";
  const parts = purl.slice(4).split("/", 1);
  const purlType = parts[0].toLowerCase();
  return PURL_ECOSYSTEM_MAP[purlType] ?? purlType;
}

function guessEcosystem(name: string): string {
  const host = name.includes("/") ? name.split("/")[0] : "";
  if (host && host !== "github.com" && host !== "golang.org") return "npm";
  if (host === "github.com" || host === "golang.org") return "go";
  return "";
}
