# ossguard-npm

> npm distribution packages for [ossguard](https://github.com/kirankotari/ossguard) — pre-built binaries, no Python required.

## Install

```bash
npm install -g ossguard
```

npm automatically installs only the pre-built binary for your platform.

## Packages

| Package | Platform |
|---------|----------|
| [`ossguard`](packages/ossguard/) | Main CLI wrapper (all platforms) |
| [`@ossguard/cli-linux-x64`](packages/cli-linux-x64/) | Linux x64 |
| [`@ossguard/cli-linux-arm64`](packages/cli-linux-arm64/) | Linux arm64 |
| [`@ossguard/cli-darwin-x64`](packages/cli-darwin-x64/) | macOS Intel |
| [`@ossguard/cli-darwin-arm64`](packages/cli-darwin-arm64/) | macOS Apple Silicon |
| [`@ossguard/cli-win32-x64`](packages/cli-win32-x64/) | Windows x64 |

Uses the same platform-specific `optionalDependencies` pattern as esbuild, Biome, and Turbo.

## How releases work

1. A new version is tagged in [kirankotari/ossguard](https://github.com/kirankotari/ossguard)
2. The binaries workflow builds standalone executables for all platforms
3. A `repository_dispatch` event triggers this repo's publish workflow
4. Platform packages are published first, then the main `ossguard` package

## License

Apache-2.0
