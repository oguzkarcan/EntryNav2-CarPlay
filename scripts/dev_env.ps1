# Adds portable w64devkit (g++, gcc, make, ar) and MinGit (git) to the current PowerShell session.
$assetsTools = Resolve-Path (Join-Path $PSScriptRoot "..\..\EntryNav2-CarPlay-Assets\tools")
$w64Bin = Join-Path $assetsTools "w64devkit\bin"
$gitCmd = Join-Path $assetsTools "mingit\cmd"

if (Test-Path $w64Bin) {
    $env:PATH = "$w64Bin;$env:PATH"
}
if (Test-Path $gitCmd) {
    $env:PATH = "$gitCmd;$env:PATH"
}

Write-Host "Toolchain ready:" -ForegroundColor Green
Write-Host "  g++  : $((Get-Command g++ -ErrorAction SilentlyContinue).Source)"
Write-Host "  make : $((Get-Command make -ErrorAction SilentlyContinue).Source)"
Write-Host "  git  : $((Get-Command git -ErrorAction SilentlyContinue).Source)"
