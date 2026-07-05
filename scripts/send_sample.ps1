# サンプルSSHログを /ingest に投入（Windows / PowerShell）
# 使い方:  ./scripts/send_sample.ps1
$ErrorActionPreference = "Stop"
$body = Get-Content -Raw -Path "$PSScriptRoot/../backend/samples/ssh_sample.json"
$headers = @{ "Content-Type" = "application/json" }
if ($env:INGEST_TOKEN) { $headers["Authorization"] = "Bearer $($env:INGEST_TOKEN)" }
$res = Invoke-RestMethod -Uri "http://localhost:8000/ingest" -Method Post -Body $body -Headers $headers
$res | ConvertTo-Json -Depth 5
