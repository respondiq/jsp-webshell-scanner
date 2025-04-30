# JSP Webshell Scanner for SAP CVE-2025-31324

A lightweight script to scan `.jsp` files for suspicious patterns typically associated with JSP-based webshells, including those observed in attacks exploiting **SAP NetWeaver CVE-2025-31324**.

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

1. Linux: **Clone the repo** or [download the script](detect_webshells.sh):
   ```bash
      chmod +x detect_webshells.sh
      ./detect_webhsells.sh
2. Windows: **Clone the repo** or [download the script](detect_webshells.ps1)
   ```powershell
   ./detect_webshells.ps1

## 📌 Example Output

For Linux:
```bash
🔍 Pattern: Runtime.getRuntime(
/usr/sap/OP1/J31/work/suspicious.jsp:13: out.println(Runtime.getRuntime().exec(cmd));

🔍 Pattern: request.getParameter(
/usr/sap/OP1/J31/work/shell.jsp:9: String cmd = request.getParameter("cmd");
```
For Windows: 

## ⚠️ Disclaimer

This script is provided **as-is**, without any warranties, guarantees, or liability of any kind. It is intended as a **quick triage tool** to assist in the initial identification of suspicious `.jsp` files, especially those that may resemble webshells related to vulnerabilities like **CVE-2025-31324**.

It is **not** a comprehensive detection or forensic solution.

- **False positives are possible**, particularly in legitimate applications that use similar programming constructs.
- **False negatives are also possible**, as attackers may use obfuscation or alternate techniques that bypass the patterns included in this script.
- Use this tool as a **first step** in your investigation process, and follow up with full manual review, logging analysis, and endpoint forensics as required.

**You are solely responsible** for how you interpret and act on the findings. This project is shared in good faith and for community benefit, but **use is entirely at your own risk**.

## 🙌 Contributing

Contributions are welcome and appreciated!

If you'd like to improve this tool — whether by adding new detection patterns, optimizing the scanning logic, or reducing false positives — feel free to open an issue or submit a pull request.

### Ways You Can Contribute:

- 🧠 Add new suspicious code patterns based on observed threats
- 🛠️ Improve search performance or coverage
- 🧪 Share edge cases or test samples that help validate detection logic
- 🐛 Report false positives or bugs 
- 📚 Improve documentation or usage examples

Before submitting a pull request:
- Make sure your code is clear and documented
- Include a description of the change and why it’s helpful

Thank you for supporting open-source security tooling!

