<#
.SYNOPSIS
    Quick triage script to detect suspicious patterns in .jsp files (PowerShell version)

.DESCRIPTION
    Scans recursively for .jsp files and searches for patterns commonly used in webshells,
    including those seen in exploitation of SAP CVE-2025-31324.

.PARAMETER Path
    The root directory to scan (defaults to current directory if not specified)
#>

param (
    [string]$Path = "."
)

Write-Host "`nScanning .jsp files in '$Path' for suspicious patterns..." -ForegroundColor Cyan

# Define suspicious patterns
$patterns = @(
    "Runtime\.getRuntime\(",
    "request\.getParameter\(",
    "response\.getWriter\(",
    "new File\(",
    "FileWriter",
    "PrintWriter",
    "ProcessBuilder",
    "exec\(",
    "cmd=",
    "command=",
    "BASE64Decoder",
    "BASE64Encoder",
    "new String\(Base64",
    "InputStreamReader",
    "out\.println\("
)

# Get all .jsp files recursively
$jspFiles = Get-ChildItem -Path $Path -Recurse -Filter *.jsp -ErrorAction SilentlyContinue

foreach ($file in $jspFiles) {
    $lines = Get-Content -Path $file.FullName -ErrorAction SilentlyContinue
    for ($i = 0; $i -lt $lines.Length; $i++) {
        foreach ($pattern in $patterns) {
            if ($lines[$i] -match $pattern) {
                Write-Output "`n[$($file.FullName):$($i + 1)] $($lines[$i].Trim())"
                break
            }
        }
    }
}
