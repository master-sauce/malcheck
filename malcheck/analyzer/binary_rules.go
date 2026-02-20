package analyzer




// BinaryRules returns rules specific to binary analysis
func BinaryRules() []Rule {
	return []Rule{
		// Binary-specific rules
		newRule("BIN001", "Embedded PE signature", "Binary Analysis", High,
			"PE executable signature found in binary",
			`(?i)MZ\x90\x00`,
			"mz"),

		newRule("BIN002", "Embedded ELF signature", "Binary Analysis", High,
			"ELF executable signature found in binary",
			`(?i)\x7fELF`,
			"elf"),

		newRule("BIN003", "Suspicious string in binary", "Binary Analysis", Medium,
			"Suspicious string pattern found in binary",
			`(?i)(password|secret|key|token|api)\s*[:=]\s*['"][^'"]{4,}['"]`,
			"password", "secret", "key", "token", "api"),

		newRule("BIN004", "URL in binary", "Binary Analysis", Medium,
			"URL found in binary",
			`(?i)https?://[^\s/$.?#].[^\s]*`,
			"http://", "https://"),

		newRule("BIN005", "IP address in binary", "Binary Analysis", Medium,
			"IPv4 or IPv6 address found in binary",
			`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::ffff:(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3})|(?:(?:[0-9a-fA-F]{1,4}:){1,4}:(?:[0-9]{1,3}\.){3}[0-9]{1,3}))`,
			"192.168", "10.0", "127.0", "2001", "fe80", "::1", "::ffff"),

		newRule("BIN006", "Base64 encoded data", "Binary Analysis", Low,
			"Base64 encoded data found in binary",
			`[A-Za-z0-9+/]{20,}={0,2}`,
			"aGVsbG8", "d29ybGQ="),

		newRule("BIN007", "Registry key path", "Binary Analysis", Medium,
			"Windows registry key path found in binary",
			`(?i)(HKLM|HKCU)\\Software\\Microsoft\\Windows\\CurrentVersion`,
			"hklm", "hkcu", "software\\microsoft\\windows"),

		// More precise Windows API rule
		newRule("BIN008", "Suspicious Windows API pattern", "Binary Analysis", High,
			"Suspicious combination of Windows API calls",
			`(?i)(VirtualAlloc.*WriteProcessMemory|CreateRemoteThread|VirtualProtect.*PAGE_EXECUTE_READWRITE)`,
			"virtualalloc", "writeprocessmemory", "createremotethread", "page_execute_readwrite"),

		// More precise Linux syscall rule
		newRule("BIN009", "Linux syscall", "Binary Analysis", Medium,
			"Direct Linux syscall invocation",
			`(?i)(syscall\.Syscall\s*$$|syscall\.RawSyscall\s*$$|__NR_|SYS_)`,
			"syscall", "syscall.syscall", "rawsyscall"),

		// More precise Suspicious command rule
		newRule("BIN010", "Suspicious command", "Binary Analysis", High,
			"Suspicious command found in binary",
			`(?i)(\bcmd\.exe\b|\bpowershell\.exe\b|\bbash\b\s+|\bsh\b\s+|\b/bin/sh\b\s+|\bsystem\s*$$)`,
			"cmd.exe", "powershell.exe", "bash ", "sh ", "/bin/sh "),

		// False positive filter for Go runtime functions
		newRule("GO001", "Go runtime function", "False Positive Filter", Low,
			"Legitimate Go runtime function (ignore)",
			`(?i)(runtime\.|internal/|syscall\.proc|internal/syscall)`,
			"runtime.", "internal/", "syscall.proc"),
	}
}



// DefaultBinaryRules returns the ruleset specifically for BINARY file analysis.
// It combines base binary rules with other relevant high-level rules.
func DefaultBinaryRules() []Rule {
	// Start with the specific binary rules from binary_rules.go
	binarySpecificRules := BinaryRules()

	// Add any other rules from baseRules() that are also relevant for binaries
	// For example, hardcoded credentials, URLs, etc. are useful in binaries too.
	relevantBaseRules := []Rule{
		// Credentials
		newRule("CRED001", "Hardcoded password", "Credential", High,
			"Password assigned directly in source code",
			`(?i)(password|passwd|pwd|secret)\s*[:=]\s*['"][^'"]{4,}['"]`,
			"password", "passwd", "secret"),

		newRule("CRED002", "Hardcoded API key / token", "Credential", High,
			"API key or bearer token embedded in code",
			`(?i)(api[_-]?key|api[_-]?secret|auth[_-]?token|bearer)\s*[:=]\s*['"][A-Za-z0-9\-_\.]{16,}['"]`,
			"api_key", "api-key", "auth_token", "bearer"),

		newRule("CRED003", "AWS access key", "Credential", Critical,
			"Hardcoded AWS credentials",
			`(?i)AKIA[0-9A-Z]{16}`,
			"akia"),

		// Network
		newRule("NET005", "Download and execute", "Network/Backdoor", High,
			"Fetching remote content and executing it",
			`(?i)(Invoke-WebRequest|Invoke-Expression|iex\s*$$|DownloadString|DownloadFile)`,
			"invoke-webrequest", "invoke-expression", "iex", "downloadstring"),

		// Obfuscation
		newRule("OBF001", "Base64 decode + execute", "Obfuscation", High,
			"Decoding base64 content before execution is a common obfuscation tactic",
			`(?i)(base64[_-]?decode|atob|FromBase64String|from_base64)\s*$$`,
			"base64_decode", "atob", "frombase64"),

		newRule("OBF002", "PowerShell encoded command", "Obfuscation", Critical,
			"-EncodedCommand or -enc used to hide PS payload",
			`(?i)powershell.*(-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{20,}`,
			"-enc", "-encodedcommand"),
	}

	// Combine them
	return append(binarySpecificRules, relevantBaseRules...)
}


