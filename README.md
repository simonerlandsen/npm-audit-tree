# npm-audit-tree

Display npm audit vulnerabilities with their dependency trees, so you can see which of your direct dependencies pulls in vulnerable packages.

## Installation

```bash
npm install -g npm-audit-tree
```

Or with Cargo:

```bash
cargo install npm-audit-tree
```

## Usage

Run in a directory containing a `package.json`:

```bash
npm-audit-tree
```

Filter by severity:

```bash
npm-audit-tree critical   # Show only critical vulnerabilities
npm-audit-tree high       # Show only high severity
npm-audit-tree moderate   # Show only moderate severity
npm-audit-tree low        # Show only low severity
```

## Example Output

```
=== lodash@4.17.15 (critical) ===
my-project@1.0.0
└── some-package@1.2.3
    └── lodash@4.17.15

=== minimatch@3.0.4 (high) ===
my-project@1.0.0
└── glob@7.1.6
    └── minimatch@3.0.4
```

## Building from Source

```bash
cargo build --release
```

## License

MIT
