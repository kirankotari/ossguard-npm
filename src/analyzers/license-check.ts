/**
 * License compliance checking — detect conflicts and incompatibilities.
 */

import { DepsDevClient } from "../apis/deps-dev.js";
import type { Dependency } from "../parsers/dependencies.js";

export interface LicenseInfo {
  name: string;
  version: string;
  ecosystem: string;
  license: string;
  category: string;
}

export interface LicenseConflict {
  packageA: string;
  licenseA: string;
  packageB: string;
  licenseB: string;
  reason: string;
}

export interface LicenseReport {
  licenses: LicenseInfo[];
  conflicts: LicenseConflict[];
  permissiveCount: number;
  copyleftCount: number;
  weakCopyleftCount: number;
  unknownCount: number;
  hasConflicts: boolean;
}

const COPYLEFT = new Set(["GPL-2.0", "GPL-3.0", "AGPL-3.0", "GPL-2.0-only", "GPL-3.0-only", "AGPL-3.0-only", "GPL-2.0-or-later", "GPL-3.0-or-later", "AGPL-3.0-or-later"]);
const WEAK_COPYLEFT = new Set(["LGPL-2.1", "LGPL-3.0", "MPL-2.0", "EPL-1.0", "EPL-2.0", "LGPL-2.1-only", "LGPL-3.0-only", "LGPL-2.1-or-later", "LGPL-3.0-or-later"]);
const PERMISSIVE = new Set(["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD", "Unlicense", "CC0-1.0", "Zlib", "BlueOak-1.0.0"]);

function classifyLicense(license: string): string {
  if (COPYLEFT.has(license)) return "copyleft";
  if (WEAK_COPYLEFT.has(license)) return "weak_copyleft";
  if (PERMISSIVE.has(license)) return "permissive";
  return "unknown";
}

export async function checkLicenses(deps: Dependency[]): Promise<LicenseReport> {
  const client = new DepsDevClient();
  const licenses: LicenseInfo[] = [];

  for (const dep of deps) {
    if (dep.isDev) continue;
    const info = await client.getPackage(dep.name, dep.ecosystem);
    const lic = info?.license ?? "Unknown";
    licenses.push({
      name: dep.name,
      version: dep.version,
      ecosystem: dep.ecosystem,
      license: lic,
      category: classifyLicense(lic),
    });
  }

  const conflicts: LicenseConflict[] = [];
  const copyleftPkgs = licenses.filter((l) => l.category === "copyleft");
  const permissivePkgs = licenses.filter((l) => l.category === "permissive");

  for (const cp of copyleftPkgs) {
    for (const pp of permissivePkgs) {
      conflicts.push({
        packageA: cp.name,
        licenseA: cp.license,
        packageB: pp.name,
        licenseB: pp.license,
        reason: `Copyleft license ${cp.license} may impose requirements on ${pp.license}-licensed code`,
      });
    }
  }

  return {
    licenses,
    conflicts,
    permissiveCount: licenses.filter((l) => l.category === "permissive").length,
    copyleftCount: licenses.filter((l) => l.category === "copyleft").length,
    weakCopyleftCount: licenses.filter((l) => l.category === "weak_copyleft").length,
    unknownCount: licenses.filter((l) => l.category === "unknown").length,
    hasConflicts: conflicts.length > 0,
  };
}
