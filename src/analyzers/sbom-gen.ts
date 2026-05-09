/**
 * Local SBOM generator — produce SPDX or CycloneDX JSON from dependency manifests.
 */

import { randomUUID } from "node:crypto";
import { detectProject } from "../detector.js";
import { parseDependencies, type Dependency } from "../parsers/dependencies.js";

export function generateSbom(projectPath: string, sbomFormat: "spdx" | "cyclonedx" = "spdx"): string {
  const info = detectProject(projectPath);
  const deps = parseDependencies(projectPath);
  return sbomFormat === "cyclonedx" ? generateCyclonedx(info.repoName, deps) : generateSpdx(info.repoName, deps);
}

function generateSpdx(projectName: string, deps: Dependency[]): string {
  const now = new Date().toISOString().replace(/\.\d+Z$/, "Z");
  const rootId = "SPDXRef-RootPackage";
  const packages: Record<string, unknown>[] = [{ SPDXID: rootId, name: projectName, versionInfo: "", downloadLocation: "NOASSERTION", filesAnalyzed: false, supplier: "NOASSERTION", primaryPackagePurpose: "APPLICATION" }];
  const relationships: Record<string, string>[] = [{ spdxElementId: "SPDXRef-DOCUMENT", relatedSpdxElement: rootId, relationshipType: "DESCRIBES" }];

  deps.forEach((dep, i) => {
    const spdxId = `SPDXRef-Package-${i}`;
    const purl = makePurl(dep);
    const pkg: Record<string, unknown> = { SPDXID: spdxId, name: dep.name, versionInfo: dep.version || "NOASSERTION", downloadLocation: "NOASSERTION", filesAnalyzed: false, supplier: "NOASSERTION" };
    if (purl) pkg.externalRefs = [{ referenceCategory: "PACKAGE-MANAGER", referenceType: "purl", referenceLocator: purl }];
    packages.push(pkg);
    relationships.push({ spdxElementId: spdxId, relatedSpdxElement: rootId, relationshipType: dep.isDev ? "DEV_DEPENDENCY_OF" : "DEPENDENCY_OF" });
  });

  return JSON.stringify({
    spdxVersion: "SPDX-2.3", dataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", name: `${projectName}-sbom`,
    documentNamespace: `https://spdx.org/spdxdocs/${projectName}-${randomUUID()}`,
    creationInfo: { created: now, creators: ["Tool: ossguard"], licenseListVersion: "3.22" },
    packages, relationships,
  }, null, 2);
}

function generateCyclonedx(projectName: string, deps: Dependency[]): string {
  const now = new Date().toISOString().replace(/\.\d+Z$/, "Z");
  const components: Record<string, unknown>[] = [];
  const depsList: Record<string, unknown>[] = [];

  for (const dep of deps) {
    const purl = makePurl(dep);
    const bomRef = purl || `${dep.name}@${dep.version}`;
    const comp: Record<string, unknown> = { type: "library", name: dep.name, version: dep.version || "", "bom-ref": bomRef };
    if (purl) comp.purl = purl;
    if (dep.ecosystem) comp.group = dep.ecosystem;
    comp.scope = dep.isDev ? "optional" : "required";
    components.push(comp);
    depsList.push({ ref: bomRef, dependsOn: [] });
  }

  depsList.unshift({ ref: projectName, dependsOn: components.map((c) => c["bom-ref"] as string) });

  return JSON.stringify({
    bomFormat: "CycloneDX", specVersion: "1.5", serialNumber: `urn:uuid:${randomUUID()}`, version: 1,
    metadata: { timestamp: now, tools: [{ vendor: "ossguard", name: "ossguard", version: "0.1.0" }], component: { type: "application", name: projectName, "bom-ref": projectName } },
    components, dependencies: depsList,
  }, null, 2);
}

function makePurl(dep: Dependency): string {
  const ecoMap: Record<string, string> = { npm: "npm", pypi: "pypi", go: "golang", cargo: "cargo", maven: "maven", composer: "composer", rubygems: "gem" };
  const purlType = ecoMap[dep.ecosystem] ?? dep.ecosystem;
  if (!purlType) return "";
  if (dep.ecosystem === "go") return dep.version ? `pkg:${purlType}/${dep.name}@${dep.version}` : `pkg:${purlType}/${dep.name}`;
  if (dep.ecosystem === "maven" && dep.name.includes(":")) { const [g, a] = dep.name.split(":", 2); return dep.version ? `pkg:${purlType}/${g}/${a}@${dep.version}` : ""; }
  const ver = dep.version ? `@${dep.version}` : "";
  return `pkg:${purlType}/${dep.name}${ver}`;
}
