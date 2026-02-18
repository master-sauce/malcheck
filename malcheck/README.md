
# Malcheck - Malware Pattern Analyzer

A fast, rule-based malware pattern analyzer written in Go. Malcheck scans files and directories for suspicious patterns, including command injection, network backdoors, credential harvesting, obfuscation, privilege escalation, and more. It supports both text source code and compiled binary analysis.

## Features

- **Dual-Mode Analysis**: Automatically switches between comprehensive text-based rules and a focused binary-specific rule set.
- **Extensible Rule Engine**: Easy-to-add YAML-like rule definitions with regex patterns and keyword pre-filtering for performance.
- **Binary Scanning**: Uses `strings` to extract readable content from binaries for analysis, avoiding false positives from common Go runtime functions.
- **Recursive Scanning**: Can recursively scan entire directory trees.
- **Configurable Severity Levels**: Filter findings by severity (Low, Medium, High, Critical).
- **Multiple Output Formats**: Clean, colorized console output with detailed findings and a summary report.
- **Cross-Platform**: Works on Windows, Linux, and macOS.

## Installation

### From Source

1.  Ensure you have Go (version 1.21 or later) installed.
2.  Clone the repository:
    ```bash
    git clone https://github.com/your-username/malcheck.git
    cd malcheck
    ```
3.  Build the executable:
    ```bash
    go build -o malcheck .
    ```

The `malcheck` executable will be created in your current directory.

## Usage

### Basic Syntax

```bash
malcheck [flags] <target1> [target2] ...
```

-   `target`: A file or directory to scan.

### Flags

| Flag                 | Description                                                                                              |
| -------------------- | -------------------------------------------------------------------------------------------------------- |
| `-r, --recursive`    | Scan directories recursively.                                                                           |
| `-v, --verbose`      | Enable verbose output.                                                                                   |
| `-d, --max-depth`    | Maximum depth for recursive scanning (default: unlimited).                                               |
| `-e, --extensions`   | Comma-separated list of file extensions to scan (e.g., `.py,.sh,.js`). Scans all if empty.               |
| `-s, --min-severity` | Minimum severity level to report (Low, Medium, High, Critical). Default: `Low`.                          |
| `--bin`              | **Enable binary scanning mode.** Uses a specialized rule set for analyzing compiled executables.          |
| `--help`             | Display help and usage.                                                                                  |

### Examples

#### Scan a single Python script
```bash
malcheck analyze.py
```

#### Recursively scan a directory of shell scripts, showing only High and Critical findings
```bash
malcheck -r -s High /opt/scripts
```

#### Scan a directory for only `.js` and `.html` files
```bash
malcheck -r -e .js,.html /var/www/html
```

#### Scan a compiled executable for malicious patterns
```bash
malcheck --bin suspicious.exe
```

#### Scan a directory containing both source code and binaries
```bash
# This will skip binaries by default
malcheck -r /path/to/mixed/files

# Use --bin to analyze the binaries as well
malcheck -r --bin /path/to/mixed/files
```

## Understanding the Output

Malcheck provides a detailed report for each file scanned.

### Finding Format

Each finding is displayed in the following format:

```
[SEVERITY] L<line_number>    <Rule Name>
         Category: <Category>  |  Rule: <Rule ID>
         <Rule Details>
         › <Matched Content Line>
```

-   **Severity**: `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.
-   **Line Number**: The line in the file where the pattern was found.
-   **Rule Name**: A human-readable name for the detected pattern.
-   **Category**: The type of threat (e.g., "Command Injection", "Network/Backdoor").
-   **Rule ID**: A unique identifier for the rule.
-   **Matched Content Line**: The exact line of text or string from the binary that triggered the rule.

### Scan Summary

At the end of the scan, a summary report is shown:

```
── Scan Summary ──
  Files scanned : 15
  Files skipped : 2
  Errors        : 0
  Total findings: 7
  By severity   : CRITICAL=2  HIGH=3  MEDIUM=2  LOW=0
```

## Rule Categories

Malcheck detects patterns across a wide range of categories:

-   **Command Injection**: `eval()`, `system()`, backticks, etc.
-   **Network/Backdoor**: Reverse shells, bind shells, C2 communication.
-   **Credential Harvesting**: Hardcoded passwords, API keys, private keys.
-   **Obfuscation**: Base64 encoding, shellcode, string construction.
-   **Privilege Escalation**: `chmod 777`, sudo `NOPASSWD`, registry modification.
-   **Persistence**: Cron jobs, scheduled tasks, registry Run keys.
-   **Destructive**: `rm -rf /`, disk wiping, fork bombs, ransomware patterns.
-   **Injection**: SQLi, LDAP injection.
-   **LOLBin (Living Off the Land)**: Abuse of legitimate tools like `powershell`, `wmic`, `rundll32`.
-   **Process Injection**: `CreateRemoteThread`, `WriteProcessMemory`, process hollowing.
-   **DLL Hijacking**: Search order hijacking, COM hijacking.
-   **Evasion**: Anti-debugging, sandbox/VM detection.
-   **Binary Analysis**: Embedded signatures, suspicious API calls, packed binaries.

## Configuration

Malcheck's behavior is controlled entirely by its command-line flags. There are no external configuration files.

### Rule Customization

To add or modify rules, edit the `rules.go` and `binary_rules.go` source files and recompile the tool.

-   **`rules.go`**: Contains rules primarily for source code and text files.
-   **`binary_rules.go`**: Contains rules specifically for analyzing compiled binaries.

Each rule is defined by the `newRule` function:
```go
newRule("ID", "Name", "Category", Severity, "Details", "RegexPattern", "keyword1", "keyword2")
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Areas for Contribution

-   **New Rules**: Add detection patterns for new malware techniques.
-   **Performance**: Improve the speed of the scanning engine.
-   **Output Formats**: Add support for JSON, XML, or SARIF output.
-   **False Positive Reduction**: Help refine rules to be more precise.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

Malcheck is a static analysis tool and may produce false positives or miss sophisticated threats. It is intended to be used as a part of a comprehensive security strategy, not as a sole means of detection. Always verify findings in a safe environment. The authors are not responsible for any damage caused by the use of this software.
