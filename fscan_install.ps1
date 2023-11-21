$outputPath = Join-Path $env:APPDATA "environment"
git clone https://github.com/shadow1ng/fscan.git $outputPath

Set-Location -Path $outputPath
go build -ldflags="-s -w " -trimpath main.go
