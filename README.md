# JSP Webshell Scanner for SAP CVE-2025-31324 and PeopleSoft IOC Triage

A lightweight script to scan `.jsp` and `.jspx` files for suspicious patterns typically associated with JSP-based webshells, including those observed in attacks exploiting **SAP NetWeaver CVE-2025-31324**.

This scanner has also been expanded with triage checks for **Oracle PeopleSoft / ShinyHunters / UNC6240** indicators associated with **CVE-2026-35273**, including suspicious PeopleSoft paths, filenames, hashes, and C2 strings.

> This is a triage tool. It is intended to help defenders quickly identify suspicious files, paths, and strings that warrant follow-up review.

---

## 🚨 What It Detects

The scanner hunts for JSP/JSPX files and related web-tier artifacts that contain patterns such as:

- `Runtime.getRuntime()`
- `request.getParameter()`
- Command execution indicators such as `exec(`, `cmd=`, `command=`, and `ProcessBuilder`
- File manipulation indicators such as `new File()`, `FileWriter`, `PrintWriter`, and `FileOutputStream`
- Base64 encoding/decoding
- Java reflection and dynamic class loading
- Common webshell markers such as `response.getWriter()` and `out.println()`
- Suspicious shell references such as `cmd.exe`, `powershell`, `/bin/sh`, and `/bin/bash`

> It inspects file contents, not just filenames, making it suitable for detecting renamed or stealth webshells.

---

## 🧭 PeopleSoft / ShinyHunters / UNC6240 IOC Checks

The scanner also includes triage checks for Oracle PeopleSoft indicators associated with the June 2026 ShinyHunters / UNC6240 campaign involving **CVE-2026-35273**.

These checks include:

- Suspicious requests to `/PSEMHUB/hub`
- Suspicious requests to `/PSIGW/HttpListeningConnector`
- References to `/PSEMHUB/`
- Unexpected `.jsp` or `.jspx` files under `PSEMHUB.war`
- Files or directories under `PSEMHUB.war/envmetadata/transactions`
- Suspicious `logs`, `persistantstorage`, `persistentstorage`, or `scratchpad` directories under PSEMHUB paths
- Recent XML files under `envmetadata/data/environment`
- MeshCentral agent filenames
- Known staging/C2 indicators
- Known SHA256 hashes
- Extortion marker file `README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED.TXT`
- Possible fanout scripts matching `*_fanout.sh`
- PeopleSoft reconnaissance strings such as `psappsrv.cfg`, `ps_config`, and `config.xml`

---

## 🧩 Included Network / C2 Indicators

```text
142.11.200.186
142.11.200.187
142.11.200.188
142.11.200.189
142.11.200.190
108.174.202.99
176.120.22.24
azurenetfiles.net
wss://azurenetfiles.net:443/agent.ashx
```

---

## 📁 Included Filename Indicators

```text
README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED.TXT
*_fanout.sh
meshagent
meshagent.exe
meshagent32-azure-ops.exe
meshagent64-azure-ops.exe
meshagent64-v2.exe
meshctrl.js
.bash_history
```

---

## 🔐 Included SHA256 Indicators

```text
2ab684d93c1553fad87041b4dea97188a97e78589deee2a7bacff905564f3a35
f02a924c9ff92a8780ce812511341182c6b509d45bc59f3f7b522e37225d24fc
d83fdb9e53c5ff03c4cb0451ea1bebd79b53f29eadc1e2fa394c7af13a86ce2f
c7e9332731b06644fc73e0046a2a89eaa59b09f54250e9bd622467187351711f
68257a6f9ff196179ec03624e849927f26599eb180a7c82e14ef5bc4e93bc309
```

---

## 🔧 How to Use

### Linux / macOS / Git Bash

Clone the repo or download the Bash script:

```bash
chmod +x detect_webshells.sh
./detect_webshells.sh /path/to/scan
```

Example:

```bash
./detect_webshells.sh .
```

Example SAP path:

```bash
./detect_webshells.sh /usr/sap
```

Example PeopleSoft paths:

```bash
./detect_webshells.sh /u01/app/psoft
./detect_webshells.sh /u01/app/psoft/ps_config_homes
./detect_webshells.sh /opt/oracle/psft
```

---

### Windows PowerShell

Clone the repo or download the PowerShell script:

```powershell
.\detect_webshells.ps1 -Path .
```

Example:

```powershell
.\detect_webshells.ps1 -Path C:\inetpub\wwwroot
```

Example PeopleSoft paths:

```powershell
.\detect_webshells.ps1 -Path D:\PeopleSoft
.\detect_webshells.ps1 -Path D:\Oracle\PeopleSoft
.\detect_webshells.ps1 -Path C:\Oracle\Middleware
```

If PowerShell blocks script execution, run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\detect_webshells.ps1 -Path .
```

This changes the execution policy only for the current PowerShell session.

---

## 📌 Example Output

### Linux / Bash

```bash
==== 1. Suspicious JSP code patterns ====

[HIT] Suspicious JSP pattern: Runtime\.getRuntime\(
/usr/sap/OP1/J31/work/suspicious.jsp:13: out.println(Runtime.getRuntime().exec(cmd));

[HIT] Suspicious JSP pattern: request\.getParameter\(
/usr/sap/OP1/J31/work/shell.jsp:9: String cmd = request.getParameter("cmd");
```

### PeopleSoft IOC Example

```bash
==== 2. PeopleSoft / ShinyHunters HTTP path indicators ====

[HIT] HTTP/path indicator: POST /PSEMHUB/hub
/u01/app/psoft/logs/access.log:1042: 142.11.200.186 - - "POST /PSEMHUB/hub HTTP/1.1" 200

==== 4. Filename indicators ====

[HIT] Suspicious filename: /u01/app/psoft/README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED.TXT
```

### Windows / PowerShell

```powershell
==== 1. Suspicious JSP code patterns ====

[HIT] Suspicious JSP pattern in C:\PeopleSoft\webserv\shell.jsp:9: String cmd = request.getParameter("cmd");

==== 5. Network/C2 indicators in files and logs ====

[HIT] Network/C2 IOC 'azurenetfiles.net' in C:\PeopleSoft\logs\access.log:522: connection to azurenetfiles.net
```

---

## 🔎 Recommended Follow-Up

A scanner hit should be treated as a lead for investigation, not definitive proof of compromise.

For SAP NetWeaver environments, review:

- Internet-facing SAP NetWeaver Java components
- Upload directories
- Recently created or modified JSP/JSPX files
- Web server logs
- SAP application logs
- EDR telemetry
- Unusual child processes spawned by Java
- Suspicious outbound connections

For PeopleSoft environments, review:

- PIA WebLogic access logs
- Reverse proxy logs
- WAF logs
- Requests to `/PSEMHUB/hub`
- Requests to `/PSIGW/HttpListeningConnector`
- Unexpected JSP/JSPX files under `PSEMHUB.war`
- New or modified XML files under environment metadata paths
- Outbound SMB/445 activity from PeopleSoft servers
- Unexpected SSH activity from PeopleSoft servers
- MeshCentral agents or services
- Archive/compression activity
- Large database exports
- Unexpected PeopleSoft administrative changes

---

## ⚠️ Disclaimer

This script is provided **as-is**, without warranties, guarantees, or liability of any kind.

It is intended as a **quick triage tool** to assist in the initial identification of suspicious `.jsp` and `.jspx` files, especially those that may resemble webshells related to vulnerabilities such as **SAP NetWeaver CVE-2025-31324**.

It also includes triage checks for selected **Oracle PeopleSoft / ShinyHunters / UNC6240** indicators, but it is **not** a comprehensive PeopleSoft forensic scanner.

This tool is **not** a replacement for full incident response, forensic review, vendor patch validation, EDR telemetry, or log analysis.

- **False positives are possible**, particularly in legitimate applications that use similar programming constructs.
- **False negatives are possible**, as attackers may use obfuscation, alternate tooling, or modified infrastructure.
- Indicator-based detection is inherently limited because attacker infrastructure and filenames can change.
- Use this tool as a **first step** in your investigation process, and follow up with full manual review, logging analysis, and endpoint forensics as required.

**You are solely responsible** for how you interpret and act on the findings. This project is shared in good faith and for community benefit, but **use is entirely at your own risk**.

---

## 🙌 Contributing

Contributions are welcome and appreciated.

If you'd like to improve this tool — whether by adding new detection patterns, optimizing scanning logic, improving IOC coverage, or reducing false positives — feel free to open an issue or submit a pull request.

### Ways You Can Contribute

- 🧠 Add new suspicious code patterns based on observed threats
- 🛠️ Improve search performance or coverage
- 🧪 Share edge cases or test samples that help validate detection logic
- 🐛 Report false positives or bugs
- 📚 Improve documentation or usage examples
- 🔎 Add new campaign-specific IOC modules
- 🧩 Improve support for SAP, PeopleSoft, WebLogic, Tomcat, and other Java web environments

Before submitting a pull request:

- Make sure your code is clear and documented
- Include a description of the change and why it is helpful
- Clearly distinguish confirmed indicators from experimental or community-reported indicators

Thank you for supporting open-source security tooling.
