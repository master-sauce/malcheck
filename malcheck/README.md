# malcheck

A fast, zero-dependency CLI tool written in Go that statically analyzes files and directories for malicious or suspicious behavior patterns.

## Features

- **Recursive directory scanning** with configurable depth
- **50+ detection rules** across 10 categories
- **Multiple output formats**: colored terminal text, JSON, CSV
- **Severity filtering**: only see what matters (low/medium/high/critical)
- **Extension filtering**: limit scans to specific file types
- **Binary file skipping**: automatically ignores non-text files
- **Zero external dependencies**: pure standard library

## Detection Categories

| Category              | Examples                                              |
|-----------------------|-------------------------------------------------------|
| Command Injection     | `eval()`, `exec()`, backticks, `subprocess`           |
| Network/Backdoor      | Reverse shells, `curl \| bash`, bind shells           |
| Credential            | Hardcoded passwords, API keys, AWS keys, SSH privkeys |
| Obfuscation           | base64 decode+exec, encoded PowerShell, shellcode hex |
| Privilege Escalation  | `chmod 777`, `sudo NOPASSWD`, `/etc/passwd` writes    |
| Persistence           | Crontab, systemd, registry Run keys, authorized_keys  |
| Data Exfiltration     | DNS exfil, curl POST, reading shadow/passwd           |
| Destructive           | `rm -rf /`, `dd` to disk, fork bombs, ransomware      |
| Injection             | SQL injection construction, LDAP injection            |
| Defense Evasion       | Disabling TLS, LD_PRELOAD, ptrace, timestomping       |

## Build

```bash
go build -o malcheck .
```

Or install globally:
```bash
go install .
```

## Usage

```
malcheck [flags] <file|directory> [<file|directory>...]

Flags:
  -r, --recursive        Recursively scan directories
  -v, --verbose          Verbose output
      --format string    Output format: text, json, csv (default "text")
      --output string    Write results to file (default: stdout)
      --severity string  Minimum severity: low, medium, high, critical (default "low")
      --depth int        Max directory recursion depth, -1 = unlimited (default -1)
      --ext string       Comma-separated extensions to scan, empty = all
```

## Examples

```bash
# Scan a single file
malcheck suspicious.sh

# Recursively scan a directory
malcheck -r ./project

# Only show high and critical findings
malcheck -r --severity high ./src

# Export JSON report
malcheck -r --format json --output report.json ./downloads

# Only scan Python and shell files
malcheck -r --ext .py,.sh /opt/scripts

# Limit depth and output CSV
malcheck -r --depth 3 --format csv --output findings.csv ./upload
```

## Project Structure

```
malcheck/
├── main.go               # Entry point
├── go.mod
├── cmd/
│   └── root.go           # CLI flag parsing
├── analyzer/
│   ├── analyzer.go       # File walking, scanning engine
│   └── rules.go          # Detection rules (50+)
└── reporter/
    └── reporter.go       # text / JSON / CSV output
```

## Adding Custom Rules

Edit `analyzer/rules.go` and add a new rule using `newRule()`:

```go
newRule(
    "CUSTOM001",           // unique rule ID
    "My custom rule",      // human-readable name
    "My Category",         // category label
    High,                  // severity: Low, Medium, High, Critical
    "Description of why this is dangerous",
    `(?i)dangerous_pattern`, // Go regex
    "keyword1", "keyword2",  // fast pre-filter keywords (optional)
)
```

## Exit Codes

| Code | Meaning                     |
|------|-----------------------------|
| 0    | Success, no findings        |
| 1    | Error (bad args, I/O error) |
| 2    | *(reserved for findings)*   |
