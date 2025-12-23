# How npm-audit-tree Works

This document explains the architecture and inner workings of npm-audit-tree.

## Overview

npm-audit-tree is a Rust CLI tool distributed via npm. It runs `npm audit` and displays vulnerabilities with their dependency trees, making it easy to see which of your direct dependencies pulls in vulnerable packages.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    npm package                          │
│  ┌──────────────────┐    ┌──────────────────────────┐  │
│  │ bin/npm-audit-tree│───▶│ native/npm-audit-tree   │  │
│  │ (Node.js wrapper) │    │ (Rust binary)           │  │
│  └──────────────────┘    └──────────────────────────┘  │
│           │                         ▲                   │
│           │                         │                   │
│  ┌────────▼─────────┐    ┌─────────┴────────────────┐  │
│  │ package.json     │    │ scripts/install.js       │  │
│  │ (bin entry point)│    │ (postinstall downloader) │  │
│  └──────────────────┘    └──────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Components

### 1. Rust Binary (`src/main.rs`)

The core logic is written in Rust for performance. It:

1. **Checks npm is installed** - Runs `npm --version` to verify npm is available
2. **Runs npm audit** - Executes `npm audit --json` and captures the JSON output
3. **Parses vulnerabilities** - Uses serde to deserialize the audit report, extracting name, severity, and advisory info
4. **Sorts by severity** - Orders vulnerabilities: critical > high > moderate > low
5. **Filters (optional)** - If a severity argument is passed, only shows that severity
6. **Shows advisory info and dependency trees** - For each vulnerability, displays the advisory title/URL and runs `npm ls <package>` to show how it's included

### 2. Node.js Wrapper (`bin/npm-audit-tree`)

A small Node.js script that:
- Locates the native binary in `../native/`
- Spawns the Rust binary with inherited stdio
- Passes through all command-line arguments
- Forwards the exit code

This wrapper is necessary because npm expects bin entries to be JavaScript files or have a shebang. The actual Rust binary lives in `native/` to avoid being overwritten by npm during installation.

### 3. Postinstall Script (`scripts/install.js`)

Downloads the platform-specific binary during `npm install`:

1. **Detects platform** - Checks `process.platform` and `process.arch`
2. **Constructs URL** - Points to GitHub releases: `https://github.com/.../releases/download/v{version}/{binary}`
3. **Downloads with security checks**:
   - Only allows redirects to trusted hosts (github.com, release-assets.githubusercontent.com)
   - Limits redirects to prevent loops
   - Has a 30-second timeout
4. **Saves to `native/`** - This directory is not overwritten by npm
5. **Makes executable** - Sets chmod 755 on Unix systems

### 4. GitHub Actions Workflow (`.github/workflows/release.yml`)

Automates the release process:

1. **Triggers on tag push** - When you push a tag like `v1.0.0`
2. **Builds for 4 platforms** in parallel:
   - macOS ARM64 (Apple Silicon)
   - macOS x64 (Intel)
   - Linux x64
   - Windows x64
3. **Uploads binaries** to the GitHub release
4. **Publishes to npm** using OIDC authentication (no tokens needed)

## Data Flow

```
User runs: npm-audit-tree high

    │
    ▼
┌─────────────────────────────┐
│ bin/npm-audit-tree (Node)   │
│ Spawns native binary        │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ native/npm-audit-tree (Rust)│
│                             │
│  1. Run: npm audit --json   │──────▶ npm registry
│  2. Parse JSON response     │
│  3. Sort by severity        │
│  4. Filter if arg provided  │
│  5. For each vulnerability: │
│     - Print advisory info   │
│     Run: npm ls <package>   │──────▶ local node_modules
│  6. Print colored output    │
└─────────────┬───────────────┘
              │
              ▼
         Terminal output
```

## npm Audit JSON Structure

The Rust code parses npm audit's JSON output:

```json
{
  "vulnerabilities": {
    "lodash": {
      "name": "lodash",
      "severity": "critical",
      "via": [
        {
          "title": "Prototype Pollution in lodash",
          "url": "https://github.com/advisories/GHSA-p6mc-m468-83gw",
          "severity": "critical",
          "range": "<4.17.19"
        }
      ],
      "effects": [...],
      "fixAvailable": true
    }
  }
}
```

The `name`, `severity`, and `via` fields are used from each vulnerability. The `via` field contains advisory information (title and URL) that is displayed for each vulnerability. Note that `via` can also contain strings (package names) when the vulnerability is inherited from a transitive dependency.

## Why This Architecture?

### Why Rust?
- Fast startup time
- Single binary with no runtime dependencies
- Easy cross-compilation

### Why npm distribution?
- Target audience uses npm
- Familiar installation: `npm install -g npm-audit-tree`
- No need to install Rust toolchain

### Why download binary in postinstall?
- Keeps npm package tiny (~2KB)
- Users only download their platform's binary
- Alternative (bundling all binaries) would make package ~2MB

### Why the `native/` directory?
npm overwrites the `bin/` directory after postinstall with the packaged files. By downloading to `native/` and using a wrapper script in `bin/`, the binary survives installation.

## Release Process

1. Update version in `package.json` and `Cargo.toml`
2. Commit changes
3. Create and push a git tag: `git tag v1.0.0 && git push --tags`
4. GitHub Actions automatically:
   - Builds binaries for all platforms
   - Creates/updates GitHub release with binaries
   - Publishes to npm with OIDC provenance

## Security Considerations

- **OIDC Publishing**: No npm tokens stored in GitHub secrets
- **Download Security**: Postinstall only allows redirects to GitHub domains
- **Provenance**: npm packages are published with `--provenance` flag, cryptographically linking the package to its source
