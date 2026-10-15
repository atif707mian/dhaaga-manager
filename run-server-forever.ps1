# Keeps the Dhaaga Manager server running: starts it, and if it ever exits
# (crash, unhandled exception, etc.) waits a few seconds and starts it again,
# indefinitely. Logs to run-server-forever.log for diagnosis.
$ErrorActionPreference = 'Continue'
Set-Location -Path $PSScriptRoot
$logFile = Join-Path $PSScriptRoot 'run-server-forever.log'

function Write-Log($msg) {
  $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $msg"
  Add-Content -Path $logFile -Value $line
}

Write-Log "run-server-forever.ps1 started"

while ($true) {
  Write-Log "Starting: node --watch-path=server.js server.js"
  try {
    # --watch-path (instead of plain --watch) limits the restart trigger to
    # server.js itself. Plain --watch follows the whole require() graph,
    # so any node_modules file touched by Windows (AV scan, indexing,
    # OneDrive) also caused a restart -- a few seconds of downtime during
    # which logins/requests failed with a network error.
    & node --watch-path=server.js server.js 2>&1 | ForEach-Object { Add-Content -Path $logFile -Value $_ }
  } catch {
    Write-Log "Exception launching node: $_"
  }
  Write-Log "server.js process exited - restarting in 5 seconds"
  Start-Sleep -Seconds 5
}
