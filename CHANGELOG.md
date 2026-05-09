# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-05-08

### Added

- **Core commands**: `init`, `scan`, `version`
- **Dependency analysis**: `deps`, `drift`, `watch`, `tpn`, `reach`
- **Audit & remediation**: `audit`, `fix`, `update`
- **Compliance**: `baseline`, `badge`, `license`, `policy`
- **Supply chain**: `slsa`, `supply-chain`, `pin`, `maturity`
- **Generation**: `insights`, `sbom-gen`, `ci`, `report`
- **Container security**: `container`
- **Utilities**: `compare`, `fuzz`, `secrets`
- Native TypeScript implementation — no Python required
- Project detection for Python, JavaScript, Go, Rust, Java, C/C++
- OSV and deps.dev API integrations
- SPDX and CycloneDX SBOM generation
- OSPS Baseline compliance checking (Levels 1–3)
- SLSA provenance level assessment (Levels 1–4)
- S2C2F maturity framework assessment
- Secret scanning with 17 regex-based detection rules
- Dockerfile security linting with 13 rules
- GitHub Actions pinning to commit SHAs
- SECURITY-INSIGHTS.yml generation and validation
- Cross-project security posture comparison
- HTML and JSON compliance report export
- Rich CLI output with chalk and cli-table3
- OpenSSF repository standards: LICENSE, CONTRIBUTING.md, CODE_OF_CONDUCT.md, CHANGELOG.md, SECURITY.md
