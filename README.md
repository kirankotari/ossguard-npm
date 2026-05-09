# OSSGuard — Node.js Implementation

**The TypeScript/Node.js implementation of [OSSGuard](https://github.com/kirankotari/ossguard).**

[![npm](https://img.shields.io/npm/v/ossguard)](https://www.npmjs.com/package/ossguard)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Native TypeScript implementation — runs on Node.js 18+, zero-install via `npx`.

> For full documentation, all install methods, and command examples, see the main [ossguard](https://github.com/kirankotari/ossguard) repo.

## Install

```bash
npm install -g ossguard
```

## Quick Start

```bash
# Initialize security configs (SECURITY.md, Scorecard, Dependabot, CodeQL, SBOM, Sigstore)
ossguard init

# Run a full security audit
ossguard audit

# Scan for leaked secrets
ossguard secrets

# Check OSPS Baseline compliance
ossguard baseline

# Pin GitHub Actions to commit SHAs
ossguard pin --apply
```

## Commands

| Command | Description |
|---------|-------------|
| `init` | Bootstrap security configs for a project |
| `scan` | Quick scan for security configuration |
| `version` | Show version |
| **Dependencies** | |
| `deps` | Analyze dependency health and vulnerabilities |
| `drift` | Detect dependency drift from lock files |
| `watch` | Monitor dependencies for new vulnerabilities |
| `tpn` | Generate third-party notices |
| `reach` | Reachability-filtered vulnerability analysis |
| **Audit & Fix** | |
| `audit` | Comprehensive security audit (config + deps + reach) |
| `fix` | Auto-remediate common security issues |
| `badge` | OpenSSF Best Practices Badge readiness |
| `ci` | Generate unified security CI pipeline |
| `report` | Export HTML/JSON compliance reports |
| `policy` | Organization-wide security policy enforcement |
| `license` | License compliance checking |
| **Advanced** | |
| `baseline` | OSPS Baseline compliance (Levels 1–3) |
| `insights` | Generate/validate SECURITY-INSIGHTS.yml |
| `pin` | Pin GitHub Actions to commit SHAs |
| `secrets` | Scan for leaked credentials and secrets |
| `slsa` | SLSA provenance level assessment |
| `sbom-gen` | Generate SPDX or CycloneDX SBOMs |
| `supply-chain` | Malicious package and typosquatting detection |
| `container` | Dockerfile security linting |
| `compare` | Compare security posture of two projects |
| `update` | Security-prioritized dependency updates |
| `maturity` | S2C2F maturity assessment |
| `fuzz` | Fuzzing readiness check and starter harness generation |

## Project Structure

```
src/
├── analyzers/       # 24 security analyzers
├── apis/            # OSV and deps.dev API clients
├── detector.ts      # Project detection and metadata
├── generators/      # Config file generators (security-md, scorecard, etc.)
├── parsers/         # Dependency and SBOM parsers
├── ui.ts            # Terminal output helpers
└── index.ts         # Public API exports
```

## Other Implementations

| Implementation | Install | Best for |
|---------------|---------|----------|
| **[ossguard-python](https://github.com/kirankotari/ossguard-python)** | `pip install ossguard` | Rich UI, developer workstation |
| **[ossguard-go](https://github.com/kirankotari/ossguard-go)** | `brew install kirankotari/tap/ossguard` | CI pipelines, single binary |

## Development

```bash
git clone https://github.com/kirankotari/ossguard-npm.git
cd ossguard-npm
npm install
npm run build
npm test
npm run typecheck
```

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.
