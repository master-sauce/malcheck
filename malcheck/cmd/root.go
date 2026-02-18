package cmd

import (
	"flag"
	"fmt"
	"os"

	"malcheck/analyzer"
	"malcheck/reporter"
)

func Execute() error {
	var (
		recursive    bool
		verbose      bool
		outputFmt    string
		outputFile   string
		minSeverity  string
		maxDepth     int
		extensions   string
		scanBinaries bool
	)

	flag.BoolVar(&recursive, "r", false, "Recursively scan directories")
	flag.BoolVar(&recursive, "recursive", false, "Recursively scan directories")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.BoolVar(&verbose, "verbose", false, "Verbose output")
	flag.StringVar(&outputFmt, "format", "text", "Output format: text, json, csv")
	flag.StringVar(&outputFile, "output", "", "Write results to file instead of stdout")
	flag.StringVar(&minSeverity, "severity", "low", "Minimum severity to report: low, medium, high, critical")
	flag.IntVar(&maxDepth, "depth", -1, "Max recursion depth (-1 = unlimited)")
	flag.StringVar(&extensions, "ext", "", "Comma-separated file extensions to scan (e.g. .py,.sh,.js). Empty = all")
	// Add both long and short versions of the binaries flag
	flag.BoolVar(&scanBinaries, "binaries", false, "Scan binary files using strings command")
	flag.BoolVar(&scanBinaries, "bin", false, "Scan binary files using strings command (shorthand)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
malcheck - Static malicious behavior analyzer

USAGE:
  malcheck [flags] <file|directory> [<file|directory>...]

FLAGS:
  -r, --recursive        Recursively scan directories
  -v, --verbose          Show all matches including context
      --format string    Output format: text, json, csv (default "text")
      --output string    Write results to file (default: stdout)
      --severity string  Minimum severity: low, medium, high, critical (default "low")
      --depth int        Max directory recursion depth, -1 = unlimited (default -1)
      --ext string       Comma-separated extensions to scan, empty = all
      --binaries, --bin  Scan binary files using strings command (default: false)

EXAMPLES:
  malcheck suspicious.sh
  malcheck -r ./project
  malcheck -r --severity high --format json -o report.json ./src
  malcheck --ext .py,.sh -r /opt/scripts
  malcheck --bin suspicious.exe  # Example for binary scanning
  malcheck -r --bin ./directory_with_binaries  # Example with shorthand flag

`)
	}

	flag.Parse()

	targets := flag.Args()
	if len(targets) == 0 {
		flag.Usage()
		return fmt.Errorf("no target files or directories specified")
	}

	cfg := analyzer.Config{
		Recursive:    recursive,
		Verbose:      verbose,
		MaxDepth:     maxDepth,
		Extensions:   extensions,
		MinSeverity:  analyzer.ParseSeverity(minSeverity),
		ScanBinaries: scanBinaries,
	}

	results, err := analyzer.Scan(targets, cfg)
	if err != nil {
		return err
	}

	rep := reporter.New(outputFmt, outputFile, cfg.MinSeverity)
	return rep.Write(results)
}
