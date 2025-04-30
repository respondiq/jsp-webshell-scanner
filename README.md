# JSP Webshell Scanner for SAP CVE-2025-31324

This simple Bash script recursively scans `.jsp` files for suspicious code patterns commonly associated with webshells — including those exploited via the recent SAP NetWeaver vulnerability **CVE-2025-31324**.

## 🚨 What It Detects

The scanner hunts for JSP files that contain patterns like:

- `Runtime.getRuntime()`
- `request.getParameter()`
- Command execution (`exec(`, `cmd=`, `ProcessBuilder`)
- File manipulation (`new File()`, `FileWriter`, `PrintWriter`)
- Base64 obfuscation
- Common webshell markers (`response.getWriter()`, `out.println()`)

> It inspects the file contents — not just filenames — making it suitable for detecting renamed or stealth webshells.

## 🔧 How to Use

1. **Clone the repo** or [download the script](detect_webshells.sh):
   ```bash
   git clone https://github.com/yourusername/jsp-webshell-scanner.git
   cd jsp-webshell-scanner
   chmod +x detect_webshells.sh
