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
			"IP address found in binary",
			`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`,
			"192.168", "10.0", "127.0"),

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
