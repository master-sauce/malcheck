package analyzer

// BinaryRules returns rules for compiled binary analysis via strings output.
// Philosophy: binaries produce a lot of noise from runtime strings, help text,
// and symbol names. Rules here require very specific patterns that are nearly
// impossible to explain as innocent runtime artefacts.
func BinaryRules() []Rule {
	return []Rule{

		newRule("URL001", "URL in file", "url in file", Medium,
			"URL found in file",
			`(?i)https?://[^\s/$.?#].[^\s]*`,
			"http://", "https://"),

		newRule("IP001", "IP address in file", "ip in file", Medium,
			"IPv4 or IPv6 address found in file",
			`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::ffff:(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3})|(?:(?:[0-9a-fA-F]{1,4}:){1,4}:(?:[0-9]{1,3}\.){3}[0-9]{1,3}))`,
			"192.168", "10.0", "127.0", "2001", "fe80", "::1", "::ffff"),

		// ─── C2 / NETWORK ────────────────────────────────────────────────────

		newRule("BNET001", "Reverse shell string", "C2/Backdoor", Critical,
			"Reverse shell command string embedded in binary",
			`(?i)(bash\s+-i\s+>&?\s*/dev/tcp/|/bin/(ba)?sh\s+-i\s+>&|nc\s+.*-e\s+/bin/(ba)?sh)`,
			"/dev/tcp", "-e /bin"),

		newRule("BNET002", "PowerShell download cradle", "C2/Backdoor", Critical,
			"PowerShell download-and-execute cradle embedded in binary",
			`(?i)(IEX|Invoke-Expression)\s*\(?\s*(New-Object\s+Net\.WebClient|Invoke-WebRequest)`,
			"iex", "invoke-expression", "webclient"),

		newRule("BNET003", "PowerShell encoded command", "C2/Backdoor", Critical,
			"PowerShell -EncodedCommand with a payload — hidden execution",
			`(?i)powershell(\.exe)?\s+.*-enc(odedcommand)?\s+[A-Za-z0-9+/=]{40,}`,
			"-enc", "-encodedcommand"),

		newRule("BNET004", "curl/wget pipe to shell", "C2/Backdoor", Critical,
			"Shell command fetching and executing remote code",
			`(?i)(curl|wget)\s+https?://[^\s]+\s*\|\s*(ba)?sh`,
			"curl", "wget"),

		newRule("BNET005", "C2 domain/IP with port", "C2/Backdoor", High,
			"Non-local IP:port or domain:port pattern typical of C2 beacons",
			`(?i)(connect|dial|socket)\s*[\s\S]{0,60}([1-9]\d{1,2}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}|[a-z0-9-]{4,}\.[a-z]{2,}:\d{2,5})`,
			"connect", "dial"),

		newRule("BNET006", "LHOST/LPORT beacon config", "C2/Backdoor", High,
			"Metasploit-style listener config strings in binary",
			`(?i)\b(LHOST|LPORT)\s*=\s*[\d"']`,
			"lhost", "lport"),

		// ─── PERSISTENCE ─────────────────────────────────────────────────────

		newRule("BPER001", "Autorun registry write string", "Persistence", High,
			"Registry Run key path string — binary writing persistence",
			`(?i)(Software\\Microsoft\\Windows\\CurrentVersion\\Run\\|HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)`,
			"currentversion\\run"),

		newRule("BPER002", "Cron write string", "Persistence", High,
			"Cron path string with write intent in binary",
			`(?i)(echo|printf|write|fwrite)\s*[\s\S]{0,100}/etc/cron`,
			"/etc/cron"),

		newRule("BPER003", "SSH authorized_keys path", "Persistence", High,
			"authorized_keys path found — potential SSH backdoor",
			`\.ssh/authorized_keys`,
			"authorized_keys"),

		newRule("BPER004", "LD_PRELOAD injection", "Persistence", High,
			"LD_PRELOAD set to a .so file — library injection",
			`LD_PRELOAD\s*=\s*[^\s]{4,}\.so`,
			"ld_preload"),

		// ─── PROCESS INJECTION ───────────────────────────────────────────────

		newRule("BINJ001", "Process injection API combo", "Process Injection", Critical,
			"VirtualAllocEx + WriteProcessMemory or CreateRemoteThread — injection triad",
			`(?i)(VirtualAllocEx|WriteProcessMemory|CreateRemoteThread)`,
			"virtualallocex", "writeprocessmemory", "createremotethread"),

		newRule("BINJ002", "RWX shellcode allocation", "Process Injection", Critical,
			"PAGE_EXECUTE_READWRITE memory allocation — shellcode staging",
			`(?i)(PAGE_EXECUTE_READWRITE|PROT_READ\|PROT_WRITE\|PROT_EXEC|0x40)[\s\S]{0,100}(VirtualAlloc|mmap)`,
			"page_execute_readwrite", "prot_exec"),

		newRule("BINJ003", "Process hollowing strings", "Process Injection", Critical,
			"CREATE_SUSPENDED + NtUnmapViewOfSection — hollowing pair",
			`(?i)(CREATE_SUSPENDED|NtUnmapViewOfSection|ZwUnmapViewOfSection)`,
			"create_suspended", "ntunmapviewofsection", "zwunmapviewofsection"),

		// ─── EVASION ─────────────────────────────────────────────────────────

		newRule("BEVA001", "Debugger detection API", "Evasion", High,
			"IsDebuggerPresent or PEB.BeingDebugged — anti-debug",
			`(?i)(IsDebuggerPresent|CheckRemoteDebuggerPresent|PEB\.BeingDebugged|NtQueryInformationProcess)`,
			"isdebuggerpresent", "beingdebugged"),

		newRule("BEVA002", "VM artifact strings", "Evasion", High,
			"VMware/VirtualBox/QEMU string checks — sandbox evasion",
			`(?i)(vmware|vbox|virtualbox|qemu|sandboxie|cuckoo|wireshark|procmon|x64dbg|ollydbg)`,
			"vmware", "vbox", "virtualbox", "qemu", "sandboxie"),

		newRule("BEVA003", "Log wipe command", "Evasion", High,
			"Shell command clearing logs or history — covering tracks",
			`(?i)(history\s+-c|unset\s+HISTFILE|HISTSIZE=0|rm\s+-f\s+[^\s]*\.bash_history|>\s*/var/log/)`,
			"histfile", "histsize", "bash_history"),

		// ─── CREDENTIAL THEFT ────────────────────────────────────────────────

		newRule("BCRED001", "LSASS dump string", "Credential Theft", Critical,
			"LSASS dump tooling strings — credential extraction",
			`(?i)(MiniDumpWriteDump|lsass\.exe|comsvcs\.dll[\s\S]{0,50}MiniDump)`,
			"lsass", "minidumpwritedump"),

		newRule("BCRED002", "Hardcoded AWS key", "Credential Theft", Critical,
			"AWS access key ID embedded in binary",
			`AKIA[0-9A-Z]{16}`,
			"akia"),

		newRule("BCRED003", "Shadow/passwd file path", "Credential Theft", High,
			"Accessing /etc/shadow or SAM — credential file theft",
			`(?i)(/etc/shadow|/etc/passwd|\\SAM\b|\\SYSTEM\b|\\SECURITY\b)`,
			"/etc/shadow", "\\sam", "\\system"),

		// ─── LOLBin ──────────────────────────────────────────────────────────

		newRule("BLOL001", "Certutil abuse", "LOLBin", High,
			"certutil with download or decode flags — dropper pattern",
			`(?i)certutil\s+[^\n]*(-urlcache|-decode|-decodehex)`,
			"certutil"),

		newRule("BLOL002", "WMIC process create", "LOLBin", High,
			"WMIC process call create — execution bypass",
			`(?i)wmic\s+[^\n]*process\s+[^\n]*call\s+create`,
			"wmic"),

		newRule("BLOL003", "Regsvr32 scriptlet", "LOLBin", High,
			"regsvr32 /s with scrobj or remote path — AppLocker bypass",
			`(?i)regsvr32\s+[^\n]*/s\s+[^\n]*(scrobj|http|\\\\)`,
			"regsvr32"),

		// ─── DESTRUCTIVE ─────────────────────────────────────────────────────

		newRule("BDST001", "Root deletion command", "Destructive", Critical,
			"rm -rf targeting root or critical directories",
			`(?i)rm\s+-[rRf]+\s+(/\s*$|/\*|/home|/etc|/var|/usr|/boot)`,
			"rm -"),

		newRule("BDST002", "Disk wipe command", "Destructive", Critical,
			"dd writing to raw disk device — disk wipe",
			`(?i)dd\s+[^\n]*of=/dev/(sd[a-z]|nvme\d|vd[a-z])`,
			"dd ", "/dev/sd", "/dev/nvme"),

		newRule("BDST003", "Ransomware known family", "Destructive", Critical,
			"Known ransomware family name string",
			`(?i)\b(WannaCry|Petya|NotPetya|REvil|Conti|LockBit|BlackCat|Ryuk|Maze)\b`,
			"wannacry", "petya", "revil", "conti", "lockbit"),
	}
}
