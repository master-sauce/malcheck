package analyzer

import (
	"regexp"
	"strings"
)

// Rule defines a single detection pattern
type Rule struct {
	ID       string
	Name     string
	Category string
	Severity Severity
	Details  string
	pattern  *regexp.Regexp
	keywords []string // for fast keyword matching (before regex)
}

// Match returns (column, matched) for a line
func (r Rule) Match(line string) (int, bool) {
	lower := strings.ToLower(line)

	// Keyword pre-filter for speed
	if len(r.keywords) > 0 {
		found := false
		for _, kw := range r.keywords {
			if strings.Contains(lower, kw) {
				found = true
				break
			}
		}
		if !found {
			return 0, false
		}
	}

	if r.pattern != nil {
		loc := r.pattern.FindStringIndex(line)
		if loc == nil {
			return 0, false
		}
		return loc[0] + 1, true
	}

	return 0, false
}

func newRule(id, name, category string, sev Severity, details, pattern string, keywords ...string) Rule {
	var re *regexp.Regexp
	if pattern != "" {
		re = regexp.MustCompile(pattern)
	}
	return Rule{
		ID:       id,
		Name:     name,
		Category: category,
		Severity: sev,
		Details:  details,
		pattern:  re,
		keywords: keywords,
	}
}

// DefaultRules returns the full ruleset for TEXT file analysis.
func DefaultRules() []Rule {
	return baseRules()
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

// baseRules returns the foundational rules (command injection, network, credentials, etc.)
func baseRules() []Rule {
	return []Rule{

		// ─── COMMAND INJECTION / EXEC ────────────────────────────────────────
		newRule("CMD001", "Shell execution via eval", "Command Injection", High,
			"eval() with dynamic input can execute arbitrary shell commands",
			`(?i)\beval\s*\(`,
			"eval"),

		newRule("CMD002", "System/exec call", "Command Injection", High,
			"Direct system command execution",
			`(?i)\b(os\.system|subprocess\.(?:call|run|Popen|check_output)|exec\.Command|shell_exec|passthru|popen|proc_open)\s*\(`,
			"system", "subprocess", "exec", "shell_exec", "passthru", "popen"),

		newRule("CMD003", "Backtick shell execution (bash/ruby/perl)", "Command Injection", High,
			"Backtick execution runs shell commands inline",
			"`[^`]{3,}`",
			"`"),

		newRule("CMD004", "Command substitution $(...)", "Command Injection", Medium,
			"Command substitution can lead to injection if input is uncontrolled",
			`\$\([^)]{3,}\)`,
			"$("),

		newRule("CMD005", "Dangerous Python exec()", "Command Injection", High,
			"exec() evaluates arbitrary Python code",
			`(?i)\bexec\s*\(`,
			"exec("),

		// ─── NETWORK / REVERSE SHELL ─────────────────────────────────────────
		newRule("NET001", "Reverse shell pattern", "Network/Backdoor", Critical,
			"Classic reverse shell using bash redirection to a TCP socket",
			`(?i)bash\s+-i\s+>&\s*/dev/tcp/`,
			"/dev/tcp"),

		newRule("NET002", "Netcat listener or reverse shell", "Network/Backdoor", Critical,
			"Netcat used to create a listener or pipe shell",
			`(?i)\bnc\b.*((-e|-c)\s+/bin/(ba)?sh|\d{2,5})`,
			"nc "),

		newRule("NET003", "Python reverse shell", "Network/Backdoor", Critical,
			"Python one-liner often used in reverse shells",
			`(?i)socket\.connect\s*\(.*\)\s*.*os\.(dup2|execve)`,
			"socket.connect", "dup2"),

		newRule("NET004", "curl/wget piped to shell", "Network/Backdoor", Critical,
			"Downloading and executing remote code is a common dropper pattern",
			`(?i)(curl|wget)\s+[^\|]+\|\s*(ba)?sh`,
			"curl", "wget"),

		newRule("NET005", "Download and execute", "Network/Backdoor", High,
			"Fetching remote content and executing it",
			`(?i)(Invoke-WebRequest|Invoke-Expression|iex\s*\(|DownloadString|DownloadFile)`,
			"invoke-webrequest", "invoke-expression", "iex", "downloadstring"),

		newRule("NET006", "Bind shell socket", "Network/Backdoor", Critical,
			"Listening socket bound to 0.0.0.0 piping to shell",
			`(?i)(LHOST|LPORT|bind.*0\.0\.0\.0.*shell|/bin/(ba)?sh.*RHOST)`,
			"lhost", "lport", "0.0.0.0"),

		// ─── CREDENTIAL HARVESTING ───────────────────────────────────────────
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

		newRule("CRED004", "SSH private key header", "Credential", Critical,
			"Private key material embedded in file",
			`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`,
			"private key"),

		newRule("CRED005", "Base64-encoded credentials", "Obfuscation", Medium,
			"Credentials may be base64-encoded to evade detection",
			`(?i)(password|secret|token)\s*[:=]\s*['"][A-Za-z0-9+/]{20,}={0,2}['"]`,
			"password", "secret", "token"),

		// ─── OBFUSCATION ─────────────────────────────────────────────────────
		newRule("OBF001", "Base64 decode + execute", "Obfuscation", High,
			"Decoding base64 content before execution is a common obfuscation tactic",
			`(?i)(base64[_-]?decode|atob|FromBase64String|from_base64)\s*\(`,
			"base64_decode", "atob", "frombase64"),

		newRule("OBF002", "PowerShell encoded command", "Obfuscation", Critical,
			"-EncodedCommand or -enc used to hide PS payload",
			`(?i)powershell.*(-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{20,}`,
			"-enc", "-encodedcommand"),

		newRule("OBF003", "Long hex string (potential shellcode)", "Obfuscation", High,
			"Long hex string could be encoded shellcode",
			`\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){15,}`,
			`\x`),

		newRule("OBF004", "chr()/char() string construction", "Obfuscation", Medium,
			"Building strings from character codes evades string-based detection",
			`(?i)(chr|char)\s*\(\s*\d+\s*\)(\s*[+\.]\s*(chr|char)\s*\(\s*\d+\s*\)){5,}`,
			"chr(", "char("),

		newRule("OBF005", "Python compile/exec with encoded bytes", "Obfuscation", High,
			"Compiling and executing encoded bytecode",
			`(?i)compile\s*\(.*(exec|eval)\s*\(`,
			"compile("),

		// ─── PRIVILEGE ESCALATION ────────────────────────────────────────────
		newRule("PRIV001", "chmod 777 or setuid", "Privilege Escalation", High,
			"Setting world-writable or setuid permissions",
			`(?i)(chmod\s+(777|4755|6755|0777|a\+[rwx])|setuid\s*\(\s*0\s*\))`,
			"chmod", "setuid"),

		newRule("PRIV002", "sudo without password", "Privilege Escalation", Critical,
			"NOPASSWD sudo grants passwordless root",
			`(?i)NOPASSWD\s*:\s*ALL`,
			"nopasswd"),

		newRule("PRIV003", "Writing to /etc/passwd or /etc/shadow", "Privilege Escalation", Critical,
			"Modifying system auth files can create backdoor accounts",
			`(?i)(>>|open|write|echo)\s+.*(/etc/passwd|/etc/shadow)`,
			"/etc/passwd", "/etc/shadow"),

		newRule("PRIV004", "Cron job injection", "Persistence", High,
			"Adding entries to crontab for persistence",
			`(?i)(crontab\s+-[ul]|echo\s+.*>>\s*/etc/cron)`,
			"crontab", "/etc/cron"),

		newRule("PRIV005", "Disabling firewall/SELinux", "Defense Evasion", High,
			"Turning off security controls",
			`(?i)(ufw\s+disable|iptables\s+-F|setenforce\s+0|systemctl\s+(stop|disable)\s+(firewalld|ufw|apparmor))`,
			"ufw disable", "setenforce", "iptables -f"),

		// ─── DATA EXFILTRATION ───────────────────────────────────────────────
		newRule("EXFIL001", "DNS exfiltration pattern", "Data Exfiltration", High,
			"Encoding data into DNS queries to exfiltrate it",
			`(?i)(nslookup|dig|host)\s+.*\$\{?[a-zA-Z_][a-zA-Z0-9_]*\}?`,
			"nslookup", "dig "),

		newRule("EXFIL002", "Sending data to remote host via curl/wget", "Data Exfiltration", High,
			"Posting local data to an external endpoint",
			`(?i)(curl|wget)\s+.*(--data|-d|--upload-file|-T|POST)\s`,
			"curl", "wget"),

		newRule("EXFIL003", "Reading /etc/passwd or /etc/shadow", "Data Exfiltration", High,
			"Accessing credential files",
			`(?i)(cat|open|read|get-content)\s+.*(\/etc\/passwd|\/etc\/shadow|\/etc\/hosts|sam\b|ntds\.dit)`,
			"/etc/passwd", "/etc/shadow", "ntds.dit"),

		// ─── PERSISTENCE ─────────────────────────────────────────────────────
		newRule("PERS001", "Systemd service installation", "Persistence", Medium,
			"Installing a systemd service for persistence",
			`(?i)(systemctl\s+(enable|start)|\.service\s*\[Unit\])`,
			"systemctl enable", ".service"),

		newRule("PERS002", "Registry run key (Windows persistence)", "Persistence", High,
			"Writing to Run/RunOnce registry keys for autostart",
			`(?i)(HKLM|HKCU)\\.*\\Run(Once)?\b`,
			"hklm", "hkcu", "\\run"),

		newRule("PERS003", "SSH authorized_keys manipulation", "Persistence", High,
			"Adding keys to authorized_keys creates persistent access",
			`(?i)(>>|echo|cat|tee)\s+.*authorized_keys`,
			"authorized_keys"),

		// ─── DESTRUCTIVE ─────────────────────────────────────────────────────
		newRule("DEST001", "rm -rf on root or critical path", "Destructive", Critical,
			"Recursive deletion of root or critical directories",
			`(?i)rm\s+(-[rfv]+\s+){0,3}(-[rfv]+\s+)?(/\s|/\*|/home|/etc|/var|/usr)\b`,
			"rm -rf", "rm -r /"),

		newRule("DEST002", "Disk wipe / dd to /dev/sda", "Destructive", Critical,
			"Wiping the disk by writing zeros/random to block device",
			`(?i)dd\s+.*of=/dev/(sd[a-z]|nvme|vd[a-z]|hd[a-z])\b`,
			"dd ", "/dev/sd"),

		newRule("DEST003", "Fork bomb", "Destructive", Critical,
			"Classic fork bomb that exhausts process table",
			`:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;?\s*:`,
			":(){ :|:& };"),

		newRule("DEST004", "Ransomware-like file encryption loop", "Destructive", Critical,
			"Looping over files and encrypting them is a ransomware pattern",
			`(?i)(for\s+.*\s+in\s+.*\*\*\*?.*encrypt|openssl\s+enc.*-pass.*for\s+)`,
			"openssl enc", "encrypt"),

		// ─── INJECTION ───────────────────────────────────────────────────────
		newRule("INJ001", "SQL injection construction", "Injection", High,
			"String-concatenated SQL query — vulnerable to SQLi",
			`(?i)(select|insert|update|delete|drop|union)\s+.*\+\s*(request|params|argv|stdin|input|getenv)`,
			"select", "insert", "update", "delete", "union"),

		newRule("INJ002", "Unsanitized user input in shell command", "Injection", High,
			"User-supplied input directly concatenated into a shell command",
			`(?i)(os\.system|subprocess|exec|shell_exec|passthru)\s*\(.*\+\s*(request|input|argv|params|stdin)`,
			"os.system", "subprocess", "exec", "shell_exec"),

		newRule("INJ003", "LDAP injection pattern", "Injection", Medium,
			"User input in LDAP filter without sanitization",
			`(?i)ldap.*filter.*\+\s*(request|params|input|argv)`,
			"ldap"),

		// ─── MISC SUSPICIOUS ─────────────────────────────────────────────────
		newRule("MISC001", "Disabling TLS/SSL verification", "Security Bypass", High,
			"Skipping certificate verification allows MITM attacks",
			`(?i)(verify\s*=\s*False|InsecureRequestWarning|ssl\._create_unverified_context|--no-check-certificate|skipVerify\s*:\s*true|InsecureSkipVerify)`,
			"verify=false", "insecure", "skipverify", "no-check-certificate"),

		newRule("MISC002", "Environment variable credential exposure", "Credential", Medium,
			"Printing or logging environment variables may leak secrets",
			`(?i)(print|log|echo|fmt\.Print)\s*\(.*os\.environ|os\.getenv`,
			"os.environ", "os.getenv"),

		newRule("MISC003", "Ptrace / process injection", "Evasion", High,
			"ptrace can be used for process injection or anti-debugging bypass",
			`(?i)\bptrace\s*\(`,
			"ptrace"),

		newRule("MISC004", "Dynamic library injection (LD_PRELOAD)", "Evasion", Critical,
			"LD_PRELOAD injection hijacks shared libraries",
			`(?i)LD_PRELOAD\s*=`,
			"ld_preload"),

		newRule("MISC005", "Timestomping (modifying file timestamps)", "Defense Evasion", Medium,
			"Modifying timestamps to cover tracks",
			`(?i)(touch\s+-[acdmr]+\s+-t|SetFileTime|os\.utime)`,
			"touch -t", "setfiletime", "os.utime"),

		// ─── LOW-LEVEL SYSTEM CALLS ───────────────────────────────────────────────
		newRule("LOW001", "Direct syscalls (Linux)", "Low-Level", High,
			"Direct syscall invocation without standard library wrappers",
			`(?i)syscall\s*$$\s*(SYS_\w+|__NR_\w+|\d+)\s*,`,
			"syscall", "sys_"),

		newRule("LOW002", "ptrace process manipulation", "Low-Level", Critical,
			"ptrace used for process injection or anti-debugging",
			`(?i)ptrace\s*$$\s*(PTRACE_.*|0x[0-9a-f]+)`,
			"ptrace", "ptrace_"),

		newRule("LOW003", "mmap with executable permissions", "Low-Level", High,
			"Memory mapping with RWX permissions - suspicious for shellcode",
			`(?i)mmap\s*$$\s*NULL.*PROT_EXEC|PROT_WRITE\s*\|\s*PROT_EXEC`,
			"mmap", "prot_exec"),

		newRule("LOW004", "Direct kernel module loading", "Low-Level", Critical,
			"Loading kernel modules (potential rootkit)",
			`(?i)(init_module|finit_module|create_module)\s*$$`,
			"init_module", "finit_module"),

		newRule("LOW005", "Raw socket manipulation", "Low-Level", High,
			"Raw sockets often used for stealthy communication",
			`(?i)socket\s*$$\s*(AF_PACKET|SOCK_RAW|PF_PACKET)`,
			"socket", "af_packet", "sock_raw"),

		newRule("LOW006", "Assembly shellcode patterns", "Low-Level", Critical,
			"Common shellcode patterns in assembly",
			`(?i)(\x31\xc0\x50\x68|\x6a\x0b\x58\x99|\xeb\xfe|\x90\x90\x90)`,
			"\\x31\\xc0", "\\x6a\\x0b", "\\xeb\\xfe"),

		// ─── JAVASCRIPT MALWARE ───────────────────────────────────────────────────
		newRule("JS001", "Obfuscated JavaScript eval", "JavaScript", High,
			"Obfuscated eval() commonly used in JS malware",
			`(?i)eval\s*$$\s*(String\.fromCharCode|String\.prototype\.charCodeAt|unescape|atob)`,
			"eval", "fromcharcode", "unescape"),

		newRule("JS002", "WScript.Shell execution", "JavaScript", Critical,
			"Windows Script Host shell execution",
			`(?i)(new\s+ActiveXObject\s*$$\s*['"]WScript\.Shell['"]|WScript\.CreateObject\s*$$\s*['"]WScript\.Shell['"])`,
			"wscript.shell", "activexobject"),

		newRule("JS003", "PowerShell execution from JS", "JavaScript", Critical,
			"PowerShell launched from JavaScript",
			`(?i)(powershell\.exe|-enc|-encodedcommand|bypass|noprofile)`,
			"powershell.exe", "-enc"),

		newRule("JS004", "Document Object abuse", "JavaScript", High,
			"DOM manipulation for credential theft",
			`(?i)(document\.getElementsByClassName.*value|document\.forms$$0$$\.password|addEventListener.*keydown)`,
			"document.", "addeventlistener"),

		newRule("JS005", "WebAssembly shellcode", "JavaScript", Critical,
			"WebAssembly used to execute shellcode in browser",
			`(?i)(WebAssembly\.instantiate|new\s+WebAssembly\.Instance|\.buffer\s*\.\s*byteLength)`,
			"webassembly", "instantiate"),

		newRule("JS006", "Cryptojacking patterns", "JavaScript", Medium,
			"Cryptocurrency mining in browser",
			`(?i)(cryptojs\.|\.mine$$|CoinHive|JSEcoin|crypto-looter)`,
			"coinhive", "jsecoin", "cryptojacking"),

		// ─── LOLBIN (LIVING OFF THE LAND) ───────────────────────────────────────────
		newRule("LOL001", "Rundll32.exe abuse", "LOLBin", High,
			"rundll32.exe executing arbitrary code",
			`(?i)rundll32\.exe.*\s+(javascript:|shell32\.dll#|url\.dll|user32\.dll)`,
			"rundll32.exe", "shell32.dll", "user32.dll"),

		newRule("LOL002", "Certutil abuse", "LOLBin", High,
			"certutil used for downloading/encoding files",
			`(?i)certutil\.exe.*(-decode|-encode|-urlcache|-verifyctl)`,
			"certutil.exe", "-decode", "-urlcache"),

		newRule("LOL003", "Bitsadmin abuse", "LOLBin", High,
			"bitsadmin used for file transfer",
			`(?i)bitsadmin\.exe.*(/transfer|/create|/addfile)`,
			"bitsadmin.exe", "/transfer"),

		newRule("LOL004", "WMIC abuse", "LOLBin", High,
			"wmic used for execution/persistence",
			`(?i)wmic.*process.*call.*create|wmic.*path.*win32_process.*create`,
			"wmic", "process call create"),

		newRule("LOL005", "Regsvr32 abuse", "LOLBin", High,
			"regsvr32.exe loading remote COM scriptlets",
			`(?i)regsvr32\.exe.*(/s|/i|scrobj\.dll)`,
			"regsvr32.exe", "scrobj.dll"),

		newRule("LOL006", "Mshta.exe abuse", "LOLBin", High,
			"mshta.exe executing remote HTML applications",
			`(?i)mshta\.exe.*((http|https|ftp)://|javascript:|vbscript:)`,
			"mshta.exe", "javascript:", "vbscript:"),

		newRule("LOL007", "SyncAppvPublishingServer.exe", "LOLBin", High,
			"App-V client used for execution",
			`(?i)SyncAppvPublishingServer\.exe.*(-n|-c)`,
			"syncapppublishingserver.exe"),

		newRule("LOL008", "Register-cimprovider abuse", "LOLBin", High,
			"PowerShell CIM provider registration",
			`(?i)Register-CimProvider.*-Path.*\.dll`,
			"register-cimprovider"),

		newRule("LOL009", "Installutil.exe abuse", "LOLBin", High,
			".NET installer utility executing code",
			`(?i)Installutil\.exe.*(/logfile=|/LogToConsole|/U)`,
			"installutil.exe", "/logfile="),

		newRule("LOL010", "Microsoft.Workflow.Compiler.exe", "LOLBin", High,
			"Workflow compiler executing XOML files",
			`(?i)Microsoft\.Workflow\.Compiler\.exe.*\.xoml`,
			"microsoft.workflow.compiler.exe"),

		// ─── MACOS LOLBIN ────────────────────────────────────────────────────────
		newRule("MAC001", "osascript abuse", "LOLBin", High,
			"osascript executing AppleScript",
			`(?i)osascript.*(-e|-l|do\s+shell\s+script)`,
			"osascript", "do shell script"),

		newRule("MAC002", "launchctl abuse", "LOLBin", High,
			"launchctl manipulating services",
			`(?i)launchctl.*load|-w|start|unload`,
			"launchctl", "load -w"),

		newRule("MAC003", "bash -i via macOS tools", "LOLBin", High,
			"Interactive shell via macOS binaries",
			`(?i)(bash|zsh|sh)\s+-i.*>&\s*/dev/tcp/`,
			"bash -i", "zsh -i"),

		// ─── LINUX LOLBIN ────────────────────────────────────────────────────────
		newRule("LIN001", "awk abuse", "LOLBin", Medium,
			"awk executing shell commands",
			`(?i)awk.*\{.*system$$|BEGIN.*system$$`,
			"awk", "system("),

		newRule("LIN002", "find abuse", "LOLBin", Medium,
			"find executing commands",
			`(?i)find.*-exec.*sh|find.*-exec.*bash`,
			"find", "-exec"),

		newRule("LIN003", "tcpdump abuse", "LOLBin", Medium,
			"tcpdump executing commands",
			`(?i)tcpdump.*-w.*-z.*sh|tcpdump.*-w.*-z.*bash`,
			"tcpdump", "-z"),

		newRule("LIN004", "strace abuse", "LOLBin", Medium,
			"strace executing commands",
			`(?i)strace.*-e.*execve|strace.*-o.*sh`,
			"strace", "execve"),

		newRule("LIN005", "ld.so abuse", "LOLBin", High,
			"Dynamic loader executing code",
			`(?i)(ld\.so|ld\.linux).*--library-path|ld\.so.*--preload`,
			"ld.so", "--library-path"),
		// ─── WINDOWS PROCESS INJECTION ───────────────────────────────────────────
		newRule("WIN001", "CreateRemoteThread injection", "Process Injection", Critical,
			"Classic process injection using CreateRemoteThread",
			`(?i)CreateRemoteThread\s*$$\s*.*\s*,\s*0\s*,\s*0\s*,\s*.*\s*,\s*0\s*,\s*0\s*,\s*0\s*$$`,
			"createremotethread"),

		newRule("WIN002", "WriteProcessMemory injection", "Process Injection", Critical,
			"Writing malicious code to remote process memory",
			`(?i)WriteProcessMemory\s*$$\s*.*\s*,\s*LPVOID\s*.*\s*,\s*.*\s*,\s*SIZE_T\s*.*\s*,\s*SIZE_T\s*.*\s*$$`,
			"writeprocessmemory"),

		newRule("WIN003", "VirtualAllocEx RWX", "Process Injection", Critical,
			"Allocating executable memory in remote process",
			`(?i)VirtualAllocEx\s*$$\s*.*\s*,\s*NULL\s*,\s*.*\s*,\s*(MEM_COMMIT|MEM_RESERVE)\s*\|\s*PAGE_EXECUTE_READWRITE`,
			"virtualallocex", "page_execute_readwrite"),

		newRule("WIN004", "SetWindowsHookEx injection", "Process Injection", High,
			"Global hooking for code injection",
			`(?i)SetWindowsHookEx\s*$$\s*(WH_KEYBOARD|WH_MOUSE|WH_GETMESSAGE)`,
			"setwindowshookex", "wh_keyboard", "wh_mouse"),

		newRule("WIN005", "QueueUserAPC injection", "Process Injection", High,
			"Asynchronous Procedure Call injection",
			`(?i)QueueUserAPC\s*$$\s*PAPCFUNC\s*.*\s*,\s*HANDLE\s*.*\s*,\s*ULONG_PTR\s*.*\s*$$`,
			"queueuserapc"),

		newRule("WIN006", "NtCreateThreadEx injection", "Process Injection", Critical,
			"Direct NT API thread creation for stealth injection",
			`(?i)NtCreateThreadEx\s*$$\s*.*\s*,\s*(THREAD_ALL_ACCESS|0x1F03FF)`,
			"ntcreatethreadex", "thread_all_access"),

		newRule("WIN007", "RtlCreateUserThread injection", "Process Injection", Critical,
			"Undocumented NT thread creation function",
			`(?i)RtlCreateUserThread\s*$$\s*.*\s*,\s*.*\s*,\s*FALSE\s*,\s*0\s*,\s*0\s*,\s*0\s*,\s*.*\s*,\s*0\s*,\s*0\s*,\s*0\s*$$`,
			"rtlcreateuserthread"),

		// ─── DLL HIJACKING ───────────────────────────────────────────────────────
		newRule("DLL001", "DLL Search Order Hijacking", "DLL Hijacking", High,
			"Placing malicious DLL in application search path",
			`(?i)(LoadLibrary\s*$$|LoadLibraryEx\s*$$|__declspec\s*$$dllexport$$|DllMain\s*$$)`,
			"loadlibrary", "dllmain", "dllexport"),

		newRule("DLL002", "COM Hijacking", "DLL Hijacking", High,
			"COM object hijacking for persistence/privilege escalation",
			`(?i)(HKLM\\Software\\Classes\\CLSID|HKCU\\Software\\Classes\\CLSID|InprocServer32)`,
			"clsid", "inprocserver32"),

		newRule("DLL003", "AppInit_DLLs Hijacking", "DLL Hijacking", High,
			"Injecting DLL into all processes using AppInit_DLLs",
			`(?i)(AppInit_DLLs|LoadAppInit_DLLs)`,
			"appinit_dlls", "loadappinit_dlls"),

		newRule("DLL004", "IFEO Hijacking", "DLL Hijacking", High,
			"Image File Execution Options hijacking",
			`(?i)(HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options|Debugger)`,
			"image file execution options", "debugger"),

		newRule("DLL005", "Winsock LSP Hijacking", "DLL Hijacking", High,
			"Layered Service Provider hijacking for network interception",
			`(?i)(Winsock\\LSP|Ws2_32\.dll|SPI\_INSTALL\_PROVIDER)`,
			"winsock lsp", "ws2_32.dll"),

		newRule("DLL006", "Side-loading DLL", "DLL Hijacking", High,
			"Side-loading malicious DLL with same name as legitimate",
			`(?i)(\.dll.*\.exe|Application\.dll|version\.dll|wininet\.dll)`,
			".dll", "application.dll", "version.dll"),

		// ─── WINDOWS MALWARE TECHNIQUES ───────────────────────────────────────────
		newRule("MAL001", "Process Hollowing", "Malware Technique", Critical,
			"Creating process in suspended state and replacing its memory",
			`(?i)(CreateProcess\s*$$\s*.*\s*,\s*.*\s*,\s*.*\s*,\s*.*\s*,\s*TRUE\s*,\s*(CREATE\_SUSPENDED|0x00000004)|NtUnmapViewOfSection)`,
			"createprocess", "create_suspended", "ntunmapviewofsection"),

		newRule("MAL002", "Atom Bombing", "Malware Technique", High,
			"Using atom tables for code injection",
			`(?i)(GlobalAddAtom\s*$$|GlobalGetAtomName\s*$$|NtAddAtom\s*$$)`,
			"globaladdatom", "globalgetatomname", "ntaddatom"),

		newRule("MAL003", "Process Doppelgänging", "Malware Technique", Critical,
			"Creating process from transacted file",
			`(?i)(CreateFileTransacted\s*$$|NtCreateFile\s*$$|NtCreateSection\s*$$|NtCreateProcessEx\s*$$)`,
			"createfiletransacted", "ntcreatefile", "ntcreatesection"),

		newRule("MAL004", "Module Stomping", "Malware Technique", High,
			"Overwriting loaded module memory with malicious code",
			`(?i)(VirtualProtect\s*$$|GetModuleHandle\s*$$|VirtualQueryEx\s*$$)`,
			"virtualprotect", "getmodulehandle", "virtualqueryex"),

		newRule("MAL005", "Thread Execution Hijacking", "Malware Technique", High,
			"Suspend, modify, and resume thread execution",
			`(?i)(SuspendThread\s*$$|GetThreadContext\s*$$|SetThreadContext\s*$$|ResumeThread\s*$$)`,
			"suspendthread", "getthreadcontext", "setthreadcontext", "resumethread"),

		newRule("MAL006", "PE Injection", "Malware Technique", High,
			"Injecting entire PE into remote process",
			`(?i)(IMAGE\_DOS\_HEADER|IMAGE\_NT\_HEADERS|PE\_SIGNATURE|MZ\\x90)`,
			"image_dos_header", "image_nt_headers", "pe_signature", "mz"),

		// ─── WINDOWS API ABUSE ───────────────────────────────────────────────────
		newRule("API001", "Token Manipulation", "Privilege Escalation", Critical,
			"Manipulating process tokens for privilege escalation",
			`(?i)(OpenProcessToken\s*$$|AdjustTokenPrivileges\s*$$|DuplicateTokenEx\s*$$|ImpersonateLoggedOnUser\s*$$)`,
			"openprocesstoken", "adjusttokenprivileges", "duplicatetokenex", "impersonateloggedonuser"),

		newRule("API002", "Service Creation", "Persistence", High,
			"Creating new Windows service for persistence",
			`(?i)(CreateService\s*$$|OpenService\s*$$|StartService\s*$$|ChangeServiceConfig\s*$$)`,
			"createservice", "openservice", "startservice", "changeserviceconfig"),

		newRule("API003", "Scheduled Task Creation", "Persistence", High,
			"Creating scheduled task for persistence",
			`(?i)(SchTasks\.exe.*\/create|NetScheduleJobAdd|ITaskScheduler|CreateWorkItem)`,
			"schtasks.exe", "netschedulejobadd", "taskscheduler"),

		// More precise Registry Persistence rule
		newRule("API004", "Registry Persistence", "Persistence", High,
			"Modifying registry for persistence",
			`(?i)(RegSetValueEx\s*$$|RegCreateKeyEx\s*$$|HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)`,
			"regsetvalueex", "regcreatekeyex", "currentversion\\run"),

		newRule("API005", "WMI Persistence", "Persistence", High,
			"Using WMI for persistence and execution",
			`(?i)(IWbemServices|ExecNotificationQuery|SWbemLocator|__EventFilter|__EventConsumer)`,
			"iwbemservices", "swbemlocator", "__eventfilter"),

		newRule("API006", "Kernel Driver Installation", "Privilege Escalation", Critical,
			"Installing kernel driver for rootkit functionality",
			`(?i)(NtLoadDriver|CreateService.*kernel|DriverEntry|SC\_MANAGER\_CREATE\_SERVICE)`,
			"ntloaddriver", "driverentry", "sc_manager_create_service"),

		// ─── EVASION TECHNIQUES ───────────────────────────────────────────────────
		newRule("EVA001", "Anti-Debugging", "Evasion", High,
			"Techniques to detect and evade debuggers",
			`(?i)(IsDebuggerPresent\s*$$|CheckRemoteDebuggerPresent\s*$$|NtQueryInformationProcess\s*$$|PEB\.BeingDebugged)`,
			"isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess"),

		newRule("EVA002", "Sandbox Detection", "Evasion", High,
			"Detecting sandbox environment",
			`(?i)(GetTickCount\s*$$|QueryPerformanceCounter\s*$$|GetCursorPos\s*$$|GetDriveType\s*$$|CPUID)`,
			"gettickcount", "queryperformancecounter", "getcursorpos"),

		newRule("EVA003", "VM Detection", "Evasion", High,
			"Detecting virtual machine environment",
			`(?i)(VMware|VirtualBox|QEMU|Xen|Red Pill|SIDT|STR|SLDT)`,
			"vmware", "virtualbox", "qemu", "xen"),

		newRule("EVA004", "API Hooking", "Evasion", High,
			"Hooking API functions to hide malicious activity",
			`(?i)(DetourTransactionBegin|IAT Hooking|Inline Hooking|DetourUpdateThread|DetourAttach)`,
			"detourtransactionbegin", "iat hooking", "inline hooking"),

		// newRule("EVA005", "Sleep Obfuscation", "Evasion", High,
		// 	"Obfuscating code during sleep execution with suspicious patterns",
		// 	// Looks for: 1) Sleep with long numeric duration, 2) Sleep in a loop, 3) Sleep combined with other evasion techniques
		// 	`(?i)(sleep\s*$$\s*[1-9]\d{4,}\s*$$|for.*sleep|while.*sleep|sleep.*;\s*sleep|sleep.*&&.*sleep|sleep\s*$$\s*.*\s*$$\s*;\s*(virtualprotect|virtualalloc|writeprocessmemory|getthreadcontext|setthreadcontext))`,
		// 	"sleep", "virtualprotect", "virtualalloc", "writeprocessmemory", "getthreadcontext"),

		// ─── CRYPTO / ENCRYPTION ───────────────────────────────────────────────────
		newRule("CRY001", "Custom Encryption", "Obfuscation", High,
			"Custom encryption algorithms in malware",
			`(?i)(encrypt\s*$$|decrypt\s*$$|AES\s*$$|RC4\s*$$|DES\s*$$|XOR\s*$$)`,
			"encrypt", "decrypt", "aes", "rc4", "des", "xor"),

		newRule("CRY002", "Ransomware Encryption", "Ransomware", Critical,
			"Ransomware file encryption patterns",
			`(?i)(encryptFile\s*$$|encryptFilesInDirectory|CryptoLocker|WannaCry|Petya)`,
			"encryptfile", "cryptolocker", "wannacry", "petya"),

		newRule("CRY003", "C2 Communication Encryption", "Network/Backdoor", High,
			"Encrypted C2 communication",
			`(?i)(SSL\_CONNECT|TLS\_CONNECT|CryptoPP|OpenSSL|CryptoAPI|C2\_SERVER)`,
			"ssl_connect", "tls_connect", "cryptopp", "openssl", "cryptoapi"),

		newRule("CRY004", "Anti-Analysis Encryption", "Obfuscation", High,
			"Anti-analysis encryption techniques",
			`(?i)(packer|protector|obfuscator|UPX|ASPack|PECompact|Themida)`,
			"packer", "protector", "upx", "aspack", "themida"),
	}
}
