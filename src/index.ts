/**
 * ossguard: One-command CLI to guard OSS projects with OpenSSF security best practices.
 */

export const VERSION = "0.1.4-alpha.2";

export { detectProject, type ProjectInfo } from "./detector.js";
export { parseDependencies, type Dependency } from "./parsers/dependencies.js";
export { parseSBOM, type SBOMInfo } from "./parsers/sbom.js";
export { OSVClient, type VulnInfo } from "./apis/osv.js";
export { DepsDevClient, type PackageInfo } from "./apis/deps-dev.js";
